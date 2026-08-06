package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestFrameRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []Frame{
		{Type: FrameRegister, StreamID: 0, Payload: []byte("hello")},
		{Type: FrameStreamData, StreamID: 7, Payload: make([]byte, MaxFrameSize/2)},
		{Type: FrameHeartbeat, StreamID: 0, Payload: nil},
	}
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for _, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if got.Type != want.Type || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame mismatch: got %+v want %+v", got, want)
		}
	}
}

func TestMuxEcho(t *testing.T) {
	c1, c2 := net.Pipe()
	m1 := NewMux(c1, 1)
	m2 := NewMux(c2, 2)
	defer m1.Close()
	defer m2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go m1.Serve(ctx)
	go m2.Serve(ctx)

	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		for {
			s, err := m2.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(s, s)
				_ = s.Close()
			}()
		}
	}()

	s, err := m1.OpenStream("test", "", 0)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	payload := bytes.Repeat([]byte("ping"), 1000)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch")
	}
	_ = s.Close()
	_ = m1.Close()
	select {
	case <-echoDone:
	case <-time.After(3 * time.Second):
		t.Fatal("echo loop did not stop")
	}
}
