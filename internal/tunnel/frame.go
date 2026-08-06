package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxFrameSize = 1 << 20

var ErrFrameTooLarge = errors.New("tunnel: frame too large")

type FrameType byte

const (
	FrameRegister     FrameType = 1
	FrameControl      FrameType = 2
	FrameStreamOpen   FrameType = 3
	FrameStreamData   FrameType = 4
	FrameStreamClose  FrameType = 5
	FrameHeartbeat    FrameType = 6
	FrameHeartbeatAck FrameType = 7
)

type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

func WriteFrame(w io.Writer, f Frame) error {
	n := len(f.Payload)
	if n > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [9]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(n))
	hdr[4] = byte(f.Type)
	binary.BigEndian.PutUint32(hdr[5:9], f.StreamID)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[0:4])
	if n > MaxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}
	f := Frame{
		Type:     FrameType(hdr[4]),
		StreamID: binary.BigEndian.Uint32(hdr[5:9]),
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}
