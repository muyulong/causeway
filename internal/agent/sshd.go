package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	glssh "github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"

	"causeway/internal/tunnel"
)

// Server is the agent's embedded SSH server.
type Server struct {
	*glssh.Server
	authorized *KeyAuthorizer
	cfgMu      sync.Mutex
	cfg        AgentConfig
}

// AgentUser is one platform user in the key registry pushed by the relay.
type AgentUser struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

// AgentConfig is the per-agent configuration pushed by the relay.
type AgentConfig struct {
	DefaultUser string      `json:"default_user"`
	Users       []AgentUser `json:"users"`
}

func (s *Server) ApplyConfig(c AgentConfig) {
	s.cfgMu.Lock()
	s.cfg = c
	s.cfgMu.Unlock()
}

func (s *Server) targetUser() string {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg.DefaultUser
}

func (s *Server) registryAllows(key glssh.PublicKey) bool {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	for _, u := range s.cfg.Users {
		for _, line := range u.Keys {
			if pub, _, _, _, err := glssh.ParseAuthorizedKey([]byte(line)); err == nil {
				if bytes.Equal(pub.Marshal(), key.Marshal()) {
					return true
				}
			}
		}
	}
	return false
}

func New(dataDir, authKeysPath string) (*Server, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	hostSigner, err := loadOrCreateHostKey(filepath.Join(dataDir, "host_key"))
	if err != nil {
		return nil, err
	}
	s := &Server{authorized: newKeyAuthorizer(authKeysPath)}
	srv := &glssh.Server{
		HostSigners: []glssh.Signer{hostSigner},
		PublicKeyHandler: func(ctx glssh.Context, key glssh.PublicKey) bool {
			return s.authorized.Allow(key) || s.registryAllows(key)
		},
		Handler: s.sessionHandler,
	}
	// gliderlabs/ssh only initializes these maps in Serve(); since we hand
	// connections to HandleConn directly, register the defaults ourselves.
	srv.ChannelHandlers = copyMap(glssh.DefaultChannelHandlers)
	srv.RequestHandlers = copyMap(glssh.DefaultRequestHandlers)
	srv.SubsystemHandlers = copyMap(glssh.DefaultSubsystemHandlers)
	srv.SubsystemHandlers["sftp"] = s.sftpHandler
	s.Server = srv
	return s, nil
}

func copyMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// HandleStream serves one SSH connection carried over a tunnel stream.
func (s *Server) HandleStream(stream *tunnel.Stream) {
	conn := &connAdapter{ReadWriteCloser: stream}
	defer conn.Close()
	s.Server.HandleConn(conn)
}

func (s *Server) sessionHandler(sess glssh.Session) {
	ptyReq, winCh, isPty := sess.Pty()
	cmdline := strings.TrimSpace(sess.RawCommand())
	if cmdline == "__relay_list_users" {
		s.handleListUsers(sess)
		return
	}
	if strings.HasPrefix(cmdline, "__relay_upgrade ") {
		// 升级脚本必须以 Agent 自身用户直接执行（不经 sudo），
		// 否则脚本内的 $PPID 是 sudo 而非 Agent，路径发现会出错。
		s.handleUpgradeScript(sess, strings.TrimPrefix(cmdline, "__relay_upgrade "))
		return
	}
	if isPty {
		if cmdline != "" {
			s.handlePTYExec(sess, ptyReq, winCh, cmdline)
		} else {
			s.handlePTY(sess, ptyReq, winCh)
		}
		return
	}
	if cmdline != "" {
		s.handleExec(sess, cmdline)
		return
	}
	s.handlePlainShell(sess)
}

func (s *Server) handlePTYExec(sess glssh.Session, ptyReq glssh.Pty, winCh <-chan glssh.Window, cmdline string) {
	s.runPTY(sess, ptyReq, winCh, func() *exec.Cmd {
		if u := s.targetUser(); u != "" {
			return exec.Command("sudo", "-n", "-u", u, "-i", "--", shellPath(), "-c", cmdline)
		}
		return exec.Command(shellPath(), "-c", cmdline)
	})
}

func (s *Server) handlePTY(sess glssh.Session, ptyReq glssh.Pty, winCh <-chan glssh.Window) {
	s.runPTY(sess, ptyReq, winCh, func() *exec.Cmd {
		if u := s.targetUser(); u != "" {
			return exec.Command("sudo", "-n", "-u", u, "-i")
		}
		return exec.Command(shellPath())
	})
}

func (s *Server) runPTY(sess glssh.Session, ptyReq glssh.Pty, winCh <-chan glssh.Window, makeCmd func() *exec.Cmd) {
	cmd := makeCmd()
	cmd.Env = sessionEnv(sess)
	cmd.Dir = homeDir()
	f, err := pty.Start(cmd)
	if err != nil {
		log.Printf("pty start: %v", err)
		_ = sess.Exit(1)
		return
	}
	defer f.Close()

	if ptyReq.Term != "" {
		_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(ptyReq.Window.Height), Cols: uint16(ptyReq.Window.Width)})
	}
	go func() {
		_, _ = io.Copy(f, sess)
	}()
	go func() {
		for win := range winCh {
			_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)})
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	_, _ = io.Copy(sess, f)
	select {
	case err := <-waitCh:
		_ = sess.Exit(exitCode(err))
	default:
		_ = cmd.Process.Kill()
		<-waitCh
		_ = sess.Exit(1)
	}
}

func (s *Server) handleExec(sess glssh.Session, cmdline string) {
	var cmd *exec.Cmd
	if u := s.targetUser(); u != "" {
		cmd = exec.Command("sudo", "-n", "-u", u, "-H", "--", shellPath(), "-c", cmdline)
	} else {
		cmd = exec.Command(shellPath(), "-c", cmdline)
	}
	cmd.Env = sessionEnv(sess)
	cmd.Dir = homeDir()
	cmd.Stdin = sess
	cmd.Stdout = sess
	cmd.Stderr = extendedStderrWriter{sess}
	err := cmd.Run()
	if err == nil {
		_ = sess.Exit(0)
		return
	}
	_ = sess.Exit(exitCode(err))
}

// handleListUsers is an internal command used by the relay to enumerate OS
// user accounts on the target (uid >= 1000), returning a JSON array.
func (s *Server) handleListUsers(sess glssh.Session) {
	out, err := exec.Command("getent", "passwd").Output()
	if err != nil {
		_, _ = sess.Write([]byte("[]"))
		_ = sess.Exit(1)
		return
	}
	var users []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err == nil && uid >= 1000 {
			users = append(users, f[0])
		}
	}
	b, _ := json.Marshal(users)
	_, _ = sess.Write(b)
	_ = sess.Exit(0)
}

// handleUpgradeScript runs the relay-provided upgrade script as the agent user.
func (s *Server) handleUpgradeScript(sess glssh.Session, script string) {
	cmd := exec.Command(shellPath(), "-c", script)
	cmd.Env = sessionEnv(sess)
	cmd.Dir = homeDir()
	cmd.Stdin = sess
	cmd.Stdout = sess
	cmd.Stderr = extendedStderrWriter{sess}
	if err := cmd.Run(); err != nil {
		_ = sess.Exit(exitCode(err))
		return
	}
	_ = sess.Exit(0)
}

func (s *Server) handlePlainShell(sess glssh.Session) {
	cmd := exec.Command(shellPath())
	cmd.Env = sessionEnv(sess)
	cmd.Dir = homeDir()
	cmd.Stdin = sess
	cmd.Stdout = sess
	cmd.Stderr = extendedStderrWriter{sess}
	_ = cmd.Run()
	_ = sess.Exit(0)
}

// extendedStderrWriter writes to the SSH channel's stderr extended stream
// (RFC 4254 extended data code 1) so protocol tools like git can separate
// stdout from stderr. Falls back to stdout if the channel cannot write
// extended data.
type extendedStderrWriter struct {
	sess glssh.Session
}

func (w extendedStderrWriter) Write(p []byte) (int, error) {
	if ew, ok := w.sess.(interface {
		WriteExtended([]byte, uint32) (int, error)
	}); ok {
		return ew.WriteExtended(p, 1)
	}
	return w.sess.Write(p)
}

func (s *Server) sftpHandler(sess glssh.Session) {
	if u := s.targetUser(); u != "" {
		if path := findSFTPServer(); path != "" {
			cmd := exec.Command("sudo", "-n", "-u", u, path)
			cmd.Env = sessionEnv(sess)
			cmd.Stdin = sess
			cmd.Stdout = sess
			cmd.Stderr = sess
			log.Printf("sftp via sudo user=%s", u)
			if err := cmd.Run(); err != nil {
				log.Printf("sftp-server via sudo failed: %v", err)
			}
			return
		}
		log.Printf("sftp-server binary not found, falling back to in-process sftp (agent user)")
	}
	server, err := sftp.NewServer(sess)
	if err != nil {
		log.Printf("sftp server: %v", err)
		return
	}
	defer server.Close()
	_ = server.Serve()
}

func findSFTPServer() string {
	for _, p := range []string{
		"/usr/lib/openssh/sftp-server",
		"/usr/libexec/openssh/sftp-server",
		"/usr/lib/ssh/sftp-server",
		"/usr/lib/openssh/sftp-server",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func shellPath() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	return "/bin/bash"
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}

func sessionEnv(sess glssh.Session) []string {
	env := os.Environ()
	env = append(env, sess.Environ()...)
	return env
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func loadOrCreateHostKey(path string) (glssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		key, err := xssh.ParsePrivateKey(b)
		if err == nil {
			return glssh.Signer(key), nil
		}
		log.Printf("host key %s unreadable, regenerating: %v", path, err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writePEM(path, "PRIVATE KEY", der, 0o600); err != nil {
		return nil, err
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return glssh.Signer(signer), nil
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

// KeyAuthorizer allows public keys listed in an authorized_keys file.
// The file is reloaded when its mtime changes, so adding keys needs no restart.
type KeyAuthorizer struct {
	mu    sync.Mutex
	path  string
	mtime time.Time
	keys  []glssh.PublicKey
}

func newKeyAuthorizer(path string) *KeyAuthorizer {
	return &KeyAuthorizer{path: path}
}

func (a *KeyAuthorizer) Allow(key glssh.PublicKey) bool {
	a.reload()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range a.keys {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

func (a *KeyAuthorizer) reload() {
	st, err := os.Stat(a.path)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if st.Size() == 0 || (!a.mtime.IsZero() && st.ModTime().Equal(a.mtime)) {
		if st.ModTime().Equal(a.mtime) {
			return
		}
	}
	a.mtime = st.ModTime()
	b, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	var keys []glssh.PublicKey
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, _, _, _, err := glssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		keys = append(keys, pub)
	}
	a.keys = keys
}

// connAdapter adapts a tunnel.Stream to net.Conn for the SSH server.
type connAdapter struct {
	io.ReadWriteCloser
}

func (c *connAdapter) LocalAddr() net.Addr             { return stringAddr("relay") }
func (c *connAdapter) RemoteAddr() net.Addr            { return stringAddr("agent") }
func (c *connAdapter) SetDeadline(time.Time) error     { return nil }
func (c *connAdapter) SetReadDeadline(time.Time) error { return nil }
func (c *connAdapter) SetWriteDeadline(time.Time) error {
	return nil
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

var _ net.Conn = (*connAdapter)(nil)

func (s *Server) String() string { return fmt.Sprintf("agent-sshd(%s)", s.authorized.path) }
