package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"causeway/internal/agent"
	"causeway/internal/tunnel"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "install" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		installCmd()
		return
	}
	runCmd()
}

func installCmd() {
	var cfg agent.Config
	var forceFallback bool
	var noCron bool
	flag.StringVar(&cfg.Relay, "relay", "", "workstation relay address (host:port)")
	flag.StringVar(&cfg.CA, "ca", "", "path to relay CA certificate (pem)")
	flag.StringVar(&cfg.ServerID, "server-id", "", "unique server id (e.g. web-01)")
	flag.StringVar(&cfg.Token, "token", "", "registration token")
	flag.StringVar(&cfg.DataDir, "data-dir", "", "data dir (default ~/.ops/agent)")
	flag.StringVar(&cfg.AuthorizedKeys, "authorized-keys", "", "authorized_keys file")
	flag.StringVar(&cfg.SocksListen, "socks-listen", "127.0.0.1:1080", "local SOCKS5 listen (empty disables)")
	flag.BoolVar(&forceFallback, "force-fallback", false, "skip systemd, use nohup+cron")
	flag.BoolVar(&noCron, "no-cron", false, "do not add crontab @reboot entry")
	flag.Parse()

	if cfg.Relay == "" || cfg.CA == "" || cfg.ServerID == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "usage: agent install -relay host:port -ca ca.pem -server-id NAME -token TOKEN")
		os.Exit(2)
	}
	applyDefaults(&cfg)
	if err := agent.Install(cfg, forceFallback, noCron); err != nil {
		log.Fatalf("install failed: %v", err)
	}
}

func runCmd() {
	var configPath string
	var relayAddr, caFile, serverID, token, dataDir, authKeys, socksListen string
	var showVersion bool
	flag.StringVar(&configPath, "config", "", "path to config.json (optional)")
	flag.StringVar(&relayAddr, "relay", "", "workstation relay address (host:port)")
	flag.StringVar(&caFile, "ca", "", "path to relay CA certificate (pem)")
	flag.StringVar(&serverID, "server-id", "", "unique server id (e.g. web-01)")
	flag.StringVar(&token, "token", "", "registration token")
	flag.StringVar(&dataDir, "data-dir", "", "data dir")
	flag.StringVar(&authKeys, "authorized-keys", "", "authorized_keys file")
	flag.StringVar(&socksListen, "socks-listen", "127.0.0.1:1080", "local SOCKS5 listen (empty disables)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Println("causeway agent", tunnel.Version)
		return
	}

	cfg := agent.Config{SocksListen: "127.0.0.1:1080"}
	if configPath != "" {
		c, err := agent.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		cfg = c
	}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "relay":
			cfg.Relay = relayAddr
		case "ca":
			cfg.CA = caFile
		case "server-id":
			cfg.ServerID = serverID
		case "token":
			cfg.Token = token
		case "data-dir":
			cfg.DataDir = dataDir
		case "authorized-keys":
			cfg.AuthorizedKeys = authKeys
		case "socks-listen":
			cfg.SocksListen = socksListen
		}
	})
	applyDefaults(&cfg)
	if cfg.Relay == "" || cfg.CA == "" || cfg.ServerID == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "usage: agent -relay host:port -ca ca.pem -server-id NAME -token TOKEN")
		os.Exit(2)
	}
	// 记录精确启动参数，供在线升级重启时复用（避免 cmdline 丢失空值参数）
	_ = os.WriteFile(
		filepath.Join(cfg.DataDir, "agent.args"),
		[]byte(agent.ShellQuoteArgs(os.Args[1:])+"\n"),
		0o600,
	)

	sshd, err := agent.New(cfg.DataDir, cfg.AuthorizedKeys)
	if err != nil {
		log.Fatalf("init ssh server: %v", err)
	}
	holder := agent.NewMuxHolder()
	if cfg.SocksListen != "" {
		socks := agent.NewSOCKS5(cfg.SocksListen, holder)
		go func() {
			if err := socks.Serve(); err != nil {
				log.Printf("socks server stopped: %v", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		err := runOnce(ctx, cfg, sshd, holder)
		if ctx.Err() != nil {
			log.Printf("agent exiting: %v", ctx.Err())
			return
		}
		log.Printf("connection ended: %v; retrying in 3s", err)
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func applyDefaults(cfg *agent.Config) {
	home, _ := os.UserHomeDir()
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(home, ".ops", "agent")
	}
	if cfg.AuthorizedKeys == "" {
		cfg.AuthorizedKeys = filepath.Join(home, ".ssh", "authorized_keys")
	}
}

func runOnce(ctx context.Context, cfg agent.Config, sshd *agent.Server, holder *agent.MuxHolder) error {
	host, _, err := net.SplitHostPort(cfg.Relay)
	if err != nil {
		return fmt.Errorf("bad relay address: %w", err)
	}
	tlsCfg, err := tunnel.ClientConfig(cfg.CA, host)
	if err != nil {
		return err
	}
	conn, err := tls.Dial("tcp", cfg.Relay, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	hostname, _ := os.Hostname()
	reg, err := json.Marshal(tunnel.RegisterMsg{
		ServerID: cfg.ServerID,
		Token:    cfg.Token,
		Version:  tunnel.Version,
		Hostname: hostname,
	})
	if err != nil {
		return err
	}
	if err := tunnel.WriteFrame(conn, tunnel.Frame{Type: tunnel.FrameRegister, Payload: reg}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	f, err := tunnel.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("waiting for registration ack: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if f.Type != tunnel.FrameControl {
		return fmt.Errorf("unexpected registration reply type %d", f.Type)
	}
	var ctrl tunnel.ControlMsg
	if err := json.Unmarshal(f.Payload, &ctrl); err != nil || ctrl.Type != tunnel.ControlRegistered {
		return fmt.Errorf("registration rejected: %s", string(f.Payload))
	}
	var ackPayload struct {
		Config json.RawMessage `json:"config"`
	}
	_ = json.Unmarshal(ctrl.Data, &ackPayload)
	if len(ackPayload.Config) > 0 {
		var cfg agent.AgentConfig
		if err := json.Unmarshal(ackPayload.Config, &cfg); err == nil {
			sshd.ApplyConfig(cfg)
			log.Printf("agent config: default_user=%q users=%d", cfg.DefaultUser, len(cfg.Users))
		}
	}
	log.Printf("registered as %q with relay %s", cfg.ServerID, cfg.Relay)

	m := tunnel.NewMux(conn, 1)
	holder.Set(m)
	m.SetHeartbeat(15*time.Second, 60*time.Second, true)
	m.SetControlHandler(func(c tunnel.ControlMsg) {
		log.Printf("control message: %s", c.Type)
		switch c.Type {
		case tunnel.ControlServerUpdate:
			var cfg agent.AgentConfig
			if err := json.Unmarshal(c.Data, &cfg); err == nil {
				sshd.ApplyConfig(cfg)
				log.Printf("agent config updated: default_user=%q users=%d", cfg.DefaultUser, len(cfg.Users))
			}
		}
	})

	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Hand every relayed connection to the embedded SSH server,
	// except upgrade streams which are handled separately.
	go func() {
		for {
			s, err := m.AcceptStream()
			if err != nil {
				cancel()
				return
			}
			go sshd.HandleStream(s)
		}
	}()

	err = m.Serve(srvCtx)
	m.Close()
	return err
}
