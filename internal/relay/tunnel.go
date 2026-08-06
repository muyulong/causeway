package relay

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"time"

	"causeway/internal/tunnel"
)

// HandleAgent accepts one agent connection: validates registration, registers
// the mux and relay port, then serves until the connection dies.
func HandleAgent(conn net.Conn, reg *Registry) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	f, err := tunnel.ReadFrame(conn)
	if err != nil {
		log.Printf("agent handshake failed: %v", err)
		return
	}
	if f.Type != tunnel.FrameRegister {
		log.Printf("agent sent unexpected frame type %d", f.Type)
		return
	}
	var r tunnel.RegisterMsg
	if err := json.Unmarshal(f.Payload, &r); err != nil {
		log.Printf("agent register parse error: %v", err)
		return
	}
	if err := reg.ValidateToken(r.ServerID, r.Token); err != nil {
		log.Printf("agent %q rejected: %v", r.ServerID, err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	m := tunnel.NewMux(conn, 2)
	m.SetHeartbeat(15*time.Second, 60*time.Second, false)
	reg.ServePeerStreams(r.ServerID, m)
	port, err := reg.Register(r.ServerID, r.Hostname, r.Version, m)
	if err != nil {
		log.Printf("agent %q rejected: %v", r.ServerID, err)
		return
	}

	var cfg map[string]any
	if rec, err := reg.store.GetServerByName(r.ServerID); err == nil {
		cfg = reg.AgentConfig(rec)
	}
	ack, err := tunnel.EncodeControl(tunnel.ControlRegistered, map[string]any{
		"version": tunnel.Version,
		"port":    port,
		"config":  cfg,
	})
	if err != nil {
		return
	}
	if err := tunnel.WriteFrame(conn, tunnel.Frame{Type: tunnel.FrameControl, Payload: ack}); err != nil {
		return
	}
	log.Printf("agent %q online (host=%s version=%s) relay port %d", r.ServerID, r.Hostname, r.Version, port)

	m.SetControlHandler(func(c tunnel.ControlMsg) {
		log.Printf("control from agent %q: %s", r.ServerID, c.Type)
	})

	err = m.Serve(context.Background())
	reg.Unregister(r.ServerID, m)
	log.Printf("agent %q offline (%v)", r.ServerID, err)
}

// ValidateToken checks a plaintext token against the stored hash.
func (r *Registry) ValidateToken(name, token string) error {
	rec, err := r.store.GetServerByName(name)
	if err != nil {
		return err
	}
	if !rec.AdminEnabled {
		return errDisabled
	}
	if HashToken(token) != rec.TokenHash {
		return errBadToken
	}
	return nil
}
