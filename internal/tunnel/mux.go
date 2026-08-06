package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ErrMuxClosed = errors.New("tunnel: mux closed")

// Stream is one multiplexed bidirectional byte stream.
type Stream struct {
	id           uint32
	mux          *Mux
	mu           sync.Mutex
	cond         *sync.Cond
	buf          []byte
	remoteClosed bool
	localClosed  bool
	open         StreamOpenMsg
}

func newStream(id uint32, m *Mux) *Stream {
	s := &Stream{id: id, mux: m}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 {
		if s.remoteClosed || s.localClosed || s.mux.closed.Load() {
			return 0, io.EOF
		}
		s.cond.Wait()
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.mux.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	s.mu.Lock()
	closed := s.localClosed
	s.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxFrameSize {
			n = MaxFrameSize
		}
		if err := s.mux.writeFrame(Frame{Type: FrameStreamData, StreamID: s.id, Payload: p[:n]}); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	s.mu.Unlock()
	_ = s.mux.writeFrame(Frame{Type: FrameStreamClose, StreamID: s.id})
	return nil
}

func (s *Stream) push(b []byte) {
	s.mu.Lock()
	s.buf = append(s.buf, b...)
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) markRemoteClosed() {
	s.mu.Lock()
	s.remoteClosed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) abort() {
	s.mu.Lock()
	s.remoteClosed = true
	s.localClosed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Open returns the open request that created this stream.
func (s *Stream) Open() StreamOpenMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

// Mux multiplexes streams over one net.Conn using length-prefixed frames.
type Mux struct {
	conn    net.Conn
	writeMu sync.Mutex

	mu       sync.Mutex
	streams  map[uint32]*Stream
	nextID   uint32
	acceptCh chan *Stream

	closed atomic.Bool
	done   chan struct{}
	once   sync.Once

	lastActivity atomic.Int64

	controlHandler func(ControlMsg)

	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	sendHeartbeat     bool
}

// NewMux creates a Mux. idBase must be 1 (agent side) or 2 (relay side);
// stream ids advance by 2 so both sides can open streams without collision.
func NewMux(conn net.Conn, idBase uint32) *Mux {
	m := &Mux{
		conn:     conn,
		streams:  make(map[uint32]*Stream),
		nextID:   idBase,
		acceptCh: make(chan *Stream, 64),
		done:     make(chan struct{}),
	}
	m.lastActivity.Store(time.Now().UnixNano())
	return m
}

func (m *Mux) SetControlHandler(h func(ControlMsg)) { m.controlHandler = h }

// SendControl sends a control message to the peer.
func (m *Mux) SendControl(typ string, v any) error {
	b, err := EncodeControl(typ, v)
	if err != nil {
		return err
	}
	return m.writeFrame(Frame{Type: FrameControl, Payload: b})
}

func (m *Mux) SetHeartbeat(interval, timeout time.Duration, send bool) {
	m.heartbeatInterval = interval
	m.heartbeatTimeout = timeout
	m.sendHeartbeat = send
}

func (m *Mux) Serve(ctx context.Context) error {
	readErr := make(chan error, 1)
	go func() { readErr <- m.readLoop() }()
	if m.sendHeartbeat {
		go m.heartbeatLoop()
	}
	if m.heartbeatTimeout > 0 {
		go m.watchdogLoop()
	}
	select {
	case err := <-readErr:
		m.Close()
		return err
	case <-ctx.Done():
		m.Close()
		return ctx.Err()
	}
}

func (m *Mux) readLoop() error {
	for {
		f, err := ReadFrame(m.conn)
		if err != nil {
			return err
		}
		m.lastActivity.Store(time.Now().UnixNano())
		switch f.Type {
		case FrameStreamOpen:
			var o StreamOpenMsg
			_ = json.Unmarshal(f.Payload, &o)
			m.mu.Lock()
			s, ok := m.streams[f.StreamID]
			if !ok {
				s = newStream(f.StreamID, m)
				s.open = o
				m.streams[f.StreamID] = s
			}
			m.mu.Unlock()
			if !ok {
				select {
				case m.acceptCh <- s:
				default:
					s.abort()
				}
			}
		case FrameStreamData:
			if s := m.getStream(f.StreamID); s != nil {
				s.push(f.Payload)
			}
		case FrameStreamClose:
			if s := m.getStream(f.StreamID); s != nil {
				s.markRemoteClosed()
			}
		case FrameHeartbeat:
			_ = m.writeFrame(Frame{Type: FrameHeartbeatAck})
		case FrameControl:
			if m.controlHandler != nil {
				var c ControlMsg
				if json.Unmarshal(f.Payload, &c) == nil {
					m.controlHandler(c)
				}
			}
		}
	}
}

func (m *Mux) getStream(id uint32) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[id]
}

// OpenStream opens a new stream toward the peer.
func (m *Mux) OpenStream(kind, host string, port int) (*Stream, error) {
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		return nil, ErrMuxClosed
	}
	id := m.nextID
	m.nextID += 2
	s := newStream(id, m)
	s.open = StreamOpenMsg{Kind: kind, Host: host, Port: port}
	m.streams[id] = s
	m.mu.Unlock()

	o, err := json.Marshal(StreamOpenMsg{Kind: kind, Host: host, Port: port})
	if err != nil {
		m.removeStream(id)
		return nil, err
	}
	if err := m.writeFrame(Frame{Type: FrameStreamOpen, StreamID: id, Payload: o}); err != nil {
		m.removeStream(id)
		return nil, err
	}
	return s, nil
}

func (m *Mux) removeStream(id uint32) {
	m.mu.Lock()
	if s, ok := m.streams[id]; ok {
		s.abort()
		delete(m.streams, id)
	}
	m.mu.Unlock()
}

// AcceptStream waits for the peer to open a stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	select {
	case s := <-m.acceptCh:
		return s, nil
	case <-m.done:
		return nil, ErrMuxClosed
	}
}

func (m *Mux) writeFrame(f Frame) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if err := WriteFrame(m.conn, f); err != nil {
		return err
	}
	m.lastActivity.Store(time.Now().UnixNano())
	return nil
}

func (m *Mux) heartbeatLoop() {
	t := time.NewTicker(m.heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := m.writeFrame(Frame{Type: FrameHeartbeat}); err != nil {
				m.Close()
				return
			}
		case <-m.done:
			return
		}
	}
}

func (m *Mux) watchdogLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if time.Since(time.Unix(0, m.lastActivity.Load())) > m.heartbeatTimeout {
				m.Close()
				return
			}
		case <-m.done:
			return
		}
	}
}

func (m *Mux) Close() error {
	m.once.Do(func() {
		m.closed.Store(true)
		close(m.done)
		_ = m.conn.Close()
		m.mu.Lock()
		for _, s := range m.streams {
			s.abort()
		}
		m.mu.Unlock()
	})
	return nil
}
