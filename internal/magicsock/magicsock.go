package magicsock

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/peerlink-go/peerlink/internal/relay"
	"github.com/peerlink-go/peerlink/internal/types/key"
)

// MagicEndpoint implements conn.Endpoint for WireGuard.
type MagicEndpoint struct {
	addrPort netip.AddrPort
	peerKey  key.Public
	isRelay  bool
}

func (e *MagicEndpoint) ClearSrc()           {}
func (e *MagicEndpoint) SrcToString() string { return "" }
func (e *MagicEndpoint) DstToString() string {
	if e.isRelay {
		return fmt.Sprintf("relay:%s", e.peerKey.ShortString())
	}
	return e.addrPort.String()
}
func (e *MagicEndpoint) DstToBytes() []byte {
	if e.isRelay {
		return e.peerKey[:]
	}
	b, _ := e.addrPort.MarshalBinary()
	return b
}
func (e *MagicEndpoint) DstIP() netip.Addr { return e.addrPort.Addr() }
func (e *MagicEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// InboundPacket represents a packet received either via UDP or Relay.
type InboundPacket struct {
	data []byte
	ep   conn.Endpoint
}

// Config configures a magicsock Conn.
type Config struct {
	NodeKey  key.Private
	Logf     func(format string, args ...any)
}

// Conn is a magic socket implementing WireGuard's conn.Bind interface.
type Conn struct {
	nodeKey key.Private
	logf    func(format string, args ...any)

	mu        sync.RWMutex
	udpConn   *net.UDPConn
	port      uint16
	closed    bool
	inbound   chan InboundPacket
	closeOnce sync.Once

	// Peers state
	peers       map[key.Public]*peerState
	relayClient *relay.Client
}

type peerState struct {
	pub           key.Public
	directAddr    netip.AddrPort
	directActive  bool
	lastPong      time.Time
	lastPingSent  time.Time
	lastPingTxID  uint64
}

// New creates a new magicsock Conn.
func New(cfg Config) *Conn {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Conn{
		nodeKey: cfg.NodeKey,
		logf:    cfg.Logf,
		inbound: make(chan InboundPacket, 2048),
		peers:   make(map[key.Public]*peerState),
	}
}

// SetRelayClient sets or updates the active relay client connection.
func (c *Conn) SetRelayClient(rc *relay.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.relayClient = rc
}

// SetPeerEndpoint configures known endpoints for a peer from NetMap.
func (c *Conn) SetPeerEndpoint(pub key.Public, ep netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ps, ok := c.peers[pub]
	if !ok {
		ps = &peerState{pub: pub}
		c.peers[pub] = ps
	}
	if ep.IsValid() {
		ps.directAddr = ep
	}
}

// ---- conn.Bind Implementation ----

func (c *Conn) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.udpConn != nil {
		return nil, 0, errors.New("already open")
	}

	udpAddr := &net.UDPAddr{Port: int(port)}
	uconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, 0, err
	}
	c.udpConn = uconn
	c.port = uint16(uconn.LocalAddr().(*net.UDPAddr).Port)

	go c.udpReadLoop()

	rxFunc := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		pkt, ok := <-c.inbound
		if !ok {
			return 0, net.ErrClosed
		}
		if len(bufs) == 0 {
			return 0, nil
		}
		copied := copy(bufs[0], pkt.data)
		sizes[0] = copied
		eps[0] = pkt.ep
		return 1, nil
	}

	return []conn.ReceiveFunc{rxFunc}, c.port, nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	c.closeOnce.Do(func() {
		close(c.inbound)
	})
	return nil
}

func (c *Conn) SetMark(mark uint32) error { return nil }

func (c *Conn) BatchSize() int { return 1 }

func (c *Conn) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err == nil {
		return &MagicEndpoint{addrPort: ap}, nil
	}
	// Maybe hex key
	pk, err := key.ParsePublicHex(s)
	if err == nil {
		return &MagicEndpoint{peerKey: pk, isRelay: true}, nil
	}
	return nil, fmt.Errorf("invalid endpoint: %s", s)
}

func (c *Conn) Send(bufs [][]byte, ep conn.Endpoint) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return net.ErrClosed
	}

	mep, ok := ep.(*MagicEndpoint)
	if !ok {
		// Fallback for default endpoints
		ap, err := netip.ParseAddrPort(ep.DstToString())
		if err == nil {
			mep = &MagicEndpoint{addrPort: ap}
		} else {
			return errors.New("unsupported endpoint type")
		}
	}

	for _, buf := range bufs {
		// If peer has verified direct UDP path, send over UDP
		if mep.addrPort.IsValid() && !mep.isRelay {
			uaddr := net.UDPAddrFromAddrPort(mep.addrPort)
			if _, err := c.udpConn.WriteToUDP(buf, uaddr); err != nil {
				// On direct write error, try relay fallback if peer key known
				if !mep.peerKey.IsZero() && c.relayClient != nil {
					_ = c.relayClient.SendPacket(context.Background(), mep.peerKey, buf)
				}
				return err
			}
			continue
		}

		// Otherwise send over Relay
		if !mep.peerKey.IsZero() && c.relayClient != nil {
			if err := c.relayClient.SendPacket(context.Background(), mep.peerKey, buf); err != nil {
				return err
			}
		}
	}

	return nil
}

// ReceiveFromRelay handles packet incoming from the relay client.
func (c *Conn) ReceiveFromRelay(src key.Public, packet []byte) {
	ep := &MagicEndpoint{
		peerKey: src,
		isRelay: true,
	}

	select {
	case c.inbound <- InboundPacket{data: packet, ep: ep}:
	default:
		// drop on full buffer
	}
}

func (c *Conn) udpReadLoop() {
	buf := make([]byte, 2048)
	for {
		n, from, err := c.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		fromAP, err := netip.ParseAddrPort(from.String())
		if err != nil {
			continue
		}

		// Check if Disco message
		if IsDisco(pkt) {
			c.handleDisco(pkt, fromAP)
			continue
		}

		// WireGuard Packet
		ep := &MagicEndpoint{addrPort: fromAP}
		select {
		case c.inbound <- InboundPacket{data: pkt, ep: ep}:
		default:
			// drop on full
		}
	}
}

func (c *Conn) handleDisco(pkt []byte, from netip.AddrPort) {
	msg, err := ParseDisco(pkt)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ps, ok := c.peers[msg.Sender]
	if !ok {
		ps = &peerState{pub: msg.Sender}
		c.peers[msg.Sender] = ps
	}

	switch msg.Type {
	case DiscoTypePing:
		// Reply with Pong
		pong := BuildDiscoPong(c.nodeKey.Public(), msg.TxID)
		uaddr := net.UDPAddrFromAddrPort(from)
		_, _ = c.udpConn.WriteToUDP(pong, uaddr)

		// Learned direct endpoint
		ps.directAddr = from
		ps.directActive = true

	case DiscoTypePong:
		if msg.TxID == ps.lastPingTxID {
			ps.directActive = true
			ps.lastPong = time.Now()
			ps.directAddr = from
			c.logf("magicsock: doğrudan P2P bağlantı doğrulandı %s -> %s", msg.Sender.ShortString(), from)
		}
	}
}

// PingPeer initiates a Disco NAT hole punch ping to peer's known direct endpoint.
func (c *Conn) PingPeer(pub key.Public) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ps, ok := c.peers[pub]
	if !ok || !ps.directAddr.IsValid() {
		return
	}

	ping, txID := BuildDiscoPing(c.nodeKey.Public())
	ps.lastPingTxID = txID
	ps.lastPingSent = time.Now()

	uaddr := net.UDPAddrFromAddrPort(ps.directAddr)
	_, _ = c.udpConn.WriteToUDP(ping, uaddr)
}
