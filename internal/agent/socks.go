package agent

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"causeway/internal/tunnel"
)

// MuxHolder exposes the current tunnel mux, which changes on reconnect.
type MuxHolder struct {
	mux atomic.Pointer[tunnel.Mux]
}

func NewMuxHolder() *MuxHolder { return &MuxHolder{} }

func (h *MuxHolder) Set(m *tunnel.Mux) { h.mux.Store(m) }
func (h *MuxHolder) Get() *tunnel.Mux  { return h.mux.Load() }

// SOCKS5Server exposes a local SOCKS5 proxy that tunnels CONNECT requests to
// the workstation gateway, so target-side programs can use the workstation's
// network.
type SOCKS5Server struct {
	listenAddr string
	holder     *MuxHolder
}

func NewSOCKS5(listenAddr string, holder *MuxHolder) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: listenAddr, holder: holder}
}

func (s *SOCKS5Server) Serve() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	log.Printf("socks5 listening on %s", s.listenAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *SOCKS5Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 5 {
		log.Printf("socks: bad version %d", hdr[0])
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // no auth
		return
	}

	var reqHdr [3]byte
	if _, err := io.ReadFull(c, reqHdr[:]); err != nil {
		log.Printf("socks: read request hdr: %v", err)
		return
	}
	if reqHdr[1] != 1 { // CONNECT only
		log.Printf("socks: unsupported cmd %d", reqHdr[1])
		_, _ = c.Write([]byte{5, 0x07})
		return
	}
	var atyp [1]byte
	if _, err := io.ReadFull(c, atyp[:]); err != nil {
		log.Printf("socks: read atyp: %v", err)
		return
	}
	var host string
	switch atyp[0] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		log.Printf("socks: unknown atyp %d", atyp[0])
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb[:]))

	m := s.holder.Get()
	if m == nil {
		_, _ = c.Write([]byte{5, 0x05})
		return
	}
	stream, err := m.OpenStream("socks", host, port)
	if err != nil {
		_, _ = c.Write([]byte{5, 0x05})
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = stream.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	log.Printf("socks connect %s:%d via workstation", host, port)
	pipeSOCKS(c, stream)
}

func pipeSOCKS(a net.Conn, s *tunnel.Stream) {
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
