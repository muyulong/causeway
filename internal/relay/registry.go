package relay

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"causeway/internal/tunnel"
)

type Registry struct {
	mu        sync.Mutex
	store     *Store
	portStart int
	webPubKey string
	agents    map[string]*agentEntry
	ports     map[int]string
	listeners map[int]*portListener
}

type agentEntry struct {
	id       string
	hostname string
	version  string
	mux      *tunnel.Mux
	port     int
}

func NewRegistry(store *Store, portStart int, webPubKey string) *Registry {
	return &Registry{
		store:     store,
		portStart: portStart,
		webPubKey: webPubKey,
		agents:    make(map[string]*agentEntry),
		ports:     make(map[int]string),
		listeners: make(map[int]*portListener),
	}
}

// AgentConfig builds the per-agent configuration: the server's default OS
// user plus the key registry (platform users -> public keys), including the
// web terminal transport key.
func (r *Registry) AgentConfig(rec ServerRecord) map[string]any {
	byUser := make(map[string][]string)
	keys, err := r.store.AllUserKeys()
	if err == nil {
		for _, k := range keys {
			if u, err := r.store.GetUser(k.UserID); err == nil {
				byUser[u.Username] = append(byUser[u.Username], k.PublicKey)
			}
		}
	}
	if r.webPubKey != "" {
		byUser["webterm"] = append(byUser["webterm"], r.webPubKey)
	}
	users := make([]map[string]any, 0, len(byUser))
	for name, ks := range byUser {
		users = append(users, map[string]any{"name": name, "keys": ks})
	}
	return map[string]any{
		"default_user": rec.DefaultUser,
		"users":        users,
	}
}

// SendControl pushes a control message to a connected agent.
func (r *Registry) SendControl(id, typ string, v any) error {
	r.mu.Lock()
	e, ok := r.agents[id]
	r.mu.Unlock()
	if !ok || e.mux == nil {
		return fmt.Errorf("agent offline")
	}
	return e.mux.SendControl(typ, v)
}

func (r *Registry) Register(id, hostname, version string, m *tunnel.Mux) (int, error) {
	rec, err := r.store.GetServerByName(id)
	if err != nil {
		return 0, fmt.Errorf("unknown server %q", id)
	}
	if !rec.AdminEnabled {
		return 0, fmt.Errorf("server %q is disabled", id)
	}
	_ = r.store.UpdateOnline(rec.ID, hostname, version)

	r.mu.Lock()
	defer r.mu.Unlock()
	port := rec.RelayPort
	if e, ok := r.agents[id]; ok {
		e.mux.Close()
		e.mux = m
		e.hostname = hostname
		e.version = version
		_ = r.store.Log(rec.ID, "", "online", fmt.Sprintf("version=%s hostname=%s", version, hostname))
		return port, nil
	}
	if _, ok := r.listeners[port]; !ok {
		pl := newPortListener(port, r)
		r.listeners[port] = pl
		go pl.serve()
	}
	r.agents[id] = &agentEntry{id: id, hostname: hostname, version: version, mux: m, port: port}
	r.ports[port] = id
	_ = r.store.Log(rec.ID, "", "online", fmt.Sprintf("version=%s hostname=%s", version, hostname))
	return port, nil
}

func (r *Registry) Unregister(id string, m *tunnel.Mux) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.agents[id]; ok && e.mux == m {
		delete(r.agents, id)
		delete(r.ports, e.port)
		if pl, ok := r.listeners[e.port]; ok {
			pl.close()
			delete(r.listeners, e.port)
		}
		if rec, err := r.store.GetServerByName(id); err == nil {
			_ = r.store.Log(rec.ID, "", "offline", "connection closed")
		}
	}
}

func (r *Registry) Online(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.agents[id]
	return ok && e.mux != nil
}

func (r *Registry) CloseByName(id string) {
	r.mu.Lock()
	e, ok := r.agents[id]
	r.mu.Unlock()
	if ok {
		e.mux.Close()
	}
}

// ServePeerStreams handles streams opened by the agent (SOCKS requests).
func (r *Registry) ServePeerStreams(serverName string, m *tunnel.Mux) {
	go func() {
		for {
			s, err := m.AcceptStream()
			if err != nil {
				return
			}
			go r.handlePeerStream(serverName, s)
		}
	}()
}

func (r *Registry) handlePeerStream(serverName string, s *tunnel.Stream) {
	defer s.Close()
	o := s.Open()
	log.Printf("peer stream from %q kind=%s host=%s port=%d", serverName, o.Kind, o.Host, o.Port)
	switch o.Kind {
	case "socks":
		r.handleSOCKS(serverName, s, o)
	}
}

func (r *Registry) handleSOCKS(serverName string, s *tunnel.Stream, o tunnel.StreamOpenMsg) {
	rec, err := r.store.GetServerByName(serverName)
	if err != nil {
		return
	}
	addr := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	if !rec.ProxyEnabled {
		_ = r.store.Log(rec.ID, "", "proxy_denied", addr)
		return
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		_ = r.store.Log(rec.ID, "", "proxy_failed", addr+": "+err.Error())
		return
	}
	defer conn.Close()
	_ = r.store.Log(rec.ID, "", "proxy", "connect "+addr)
	pipe(conn, s)
}

func (r *Registry) NextFreePort() int {
	used, err := r.store.UsedPorts()
	if err != nil {
		used = make(map[int]bool)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for p := range r.ports {
		used[p] = true
	}
	p := r.portStart
	for used[p] {
		p++
	}
	return p
}

func (r *Registry) entryByPort(port int) *agentEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.ports[port]
	if !ok {
		return nil
	}
	return r.agents[id]
}

type portListener struct {
	mu   sync.Mutex
	port int
	reg  *Registry
	ln   net.Listener
	stop chan struct{}
	once sync.Once
}

func newPortListener(port int, reg *Registry) *portListener {
	return &portListener{port: port, reg: reg, stop: make(chan struct{})}
}

func (p *portListener) serve() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
	if err != nil {
		log.Printf("relay port %d listen failed: %v", p.port, err)
		return
	}
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-p.stop:
				return
			default:
			}
			log.Printf("port %d accept: %v", p.port, err)
			continue
		}
		go p.handleConn(c)
	}
}

func (p *portListener) handleConn(c net.Conn) {
	defer c.Close()
	e := p.reg.entryByPort(p.port)
	if e == nil {
		return
	}
	s, err := e.mux.OpenStream("ssh", "", 0)
	if err != nil {
		return
	}
	pipe(c, s)
}

func (p *portListener) close() {
	p.once.Do(func() { close(p.stop) })
	p.mu.Lock()
	if p.ln != nil {
		_ = p.ln.Close()
	}
	p.mu.Unlock()
}

func pipe(a net.Conn, s *tunnel.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(s, a)
		_ = s.Close()
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(a, s)
		_ = a.Close()
		wg.Done()
	}()
	wg.Wait()
}
