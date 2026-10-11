package wgengine

import (
	"errors"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// SimTUN is an in-memory tun.Device implementation for unprivileged testing.
type SimTUN struct {
	name   string
	mtu    int
	events chan tun.Event

	mu     sync.Mutex
	in     chan []byte
	out    chan []byte
	closed bool
}

// NewSimTUN creates a new in-memory TUN device.
func NewSimTUN(name string, mtu int) *SimTUN {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &SimTUN{
		name:   name,
		mtu:    mtu,
		events: make(chan tun.Event, 10),
		in:     make(chan []byte, 1024),
		out:    make(chan []byte, 1024),
	}
}

func (s *SimTUN) File() *os.File { return nil }

func (s *SimTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, os.ErrClosed
	}
	s.mu.Unlock()

	pkt, ok := <-s.in
	if !ok {
		return 0, os.ErrClosed
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	n := copy(bufs[0][offset:], pkt)
	sizes[0] = n
	return 1, nil
}

func (s *SimTUN) Write(bufs [][]byte, offset int) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, os.ErrClosed
	}
	s.mu.Unlock()

	count := 0
	for _, b := range bufs {
		pkt := make([]byte, len(b)-offset)
		copy(pkt, b[offset:])
		select {
		case s.out <- pkt:
			count++
		default:
			// queue full, drop
		}
	}
	return count, nil
}

func (s *SimTUN) MTU() (int, error)   { return s.mtu, nil }
func (s *SimTUN) Name() (string, error) { return s.name, nil }
func (s *SimTUN) Events() <-chan tun.Event { return s.events }
func (s *SimTUN) BatchSize() int { return 1 }

func (s *SimTUN) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.in)
	close(s.events)
	return nil
}

// InjectPacket injects a packet into the TUN device as if received from kernel.
func (s *SimTUN) InjectPacket(pkt []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("closed")
	}
	s.in <- pkt
	return nil
}

// ReadOut reads a packet written to the TUN device.
func (s *SimTUN) ReadOut() ([]byte, bool) {
	pkt, ok := <-s.out
	return pkt, ok
}
