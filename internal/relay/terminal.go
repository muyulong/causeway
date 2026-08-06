package relay

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type termMessage struct {
	Type string `json:"t"`           // "input" | "resize"
	Data string `json:"d,omitempty"` // base64 for input
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func (a *API) handleTerminal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	token := r.URL.Query().Get("token")
	if !constantTimeEqual(token, a.cfg.WebToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("terminal upgrade: %v", err)
		return
	}
	defer ws.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rec.RelayPort))
	client, session, err := dialSSH(a.cfg.WebSSHKey, addr)
	if err != nil {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[连接失败: "+err.Error()+"]\r\n"))
		return
	}
	defer client.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[PTY 请求失败: "+err.Error()+"]\r\n"))
		return
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return
	}
	if err := session.Shell(); err != nil {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[启动 shell 失败: "+err.Error()+"]\r\n"))
		return
	}
	_ = a.cfg.Store.Log(rec.ID, userOf(r), "terminal_session", "opened")

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { // ws -> ssh stdin
		defer wg.Done()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				_ = session.Close()
				return
			}
			var m termMessage
			if json.Unmarshal(msg, &m) != nil {
				continue
			}
			switch m.Type {
			case "input", "i":
				if b, err := base64.StdEncoding.DecodeString(m.Data); err == nil {
					_, _ = stdin.Write(b)
				}
			case "resize", "r":
				if m.Cols > 0 && m.Rows > 0 {
					_ = session.WindowChange(m.Rows, m.Cols)
				}
			}
		}
	}()
	go func() { // ssh stdout -> ws
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				_ = ws.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				break
			}
		}
		_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[会话已结束]\r\n"))
		_ = session.Close()
		_ = client.Close()
		_ = ws.Close()
	}()
	go func() { // ssh stderr -> ws
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				_ = ws.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	wg.Wait()
	_ = a.cfg.Store.Log(rec.ID, userOf(r), "terminal_session", "closed")
}

func dialSSH(keyPath, addr string) (*ssh.Client, *ssh.Session, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            "webterm",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // the relay channel is already authenticated via TLS+token
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return client, session, nil
}
