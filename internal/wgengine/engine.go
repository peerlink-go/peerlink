// Package wgengine wraps wireguard-go device and manages the TUN interface
// and WireGuard peer configuration from the PeerLink NetMap.
package wgengine

import (
	"bufio"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// DefaultMTU is the default WireGuard tunnel MTU.
const DefaultMTU = 1420

// PeerStatus contains runtime statistics about a WireGuard peer.
type PeerStatus struct {
	PublicKey           key.Public
	Endpoint            string
	LastHandshake       time.Time
	RxBytes             int64
	TxBytes             int64
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// Config configures a WireGuard engine.
type Config struct {
	// TunDevice is an existing TUN device. If nil, one will be created.
	TunDevice tun.Device
	// TunName is the preferred TUN interface name (e.g. "peerlink0" or "utun").
	TunName string
	// MTU is the TUN interface MTU (default 1420).
	MTU int
	// ListenPort is the UDP listen port (0 = random).
	ListenPort int
	// Bind is the custom conn.Bind (nil uses default UDP bind).
	Bind conn.Bind
	// Logf is the logger function.
	Logf func(format string, args ...any)
}

// Engine manages a wireguard-go device.
type Engine struct {
	cfg    Config
	tunDev tun.Device
	dev    *device.Device
	logf   func(string, ...any)

	mu        sync.RWMutex
	privKey   key.Private
	listenPort int
	tunName   string
	localIP   netip.Addr
	peers     map[key.Public]proto.Node
	closed    bool
}

// New creates and starts a WireGuard engine.
func New(cfg Config) (*Engine, error) {
	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}

	tunDev := cfg.TunDevice
	tunName := cfg.TunName
	if tunDev == nil {
		var err error
		tunDev, err = tun.CreateTUN(tunName, cfg.MTU)
		if err != nil {
			return nil, fmt.Errorf("tun.CreateTUN(%s): %w", tunName, err)
		}
		if realName, err := tunDev.Name(); err == nil {
			tunName = realName
		}
	} else if realName, err := tunDev.Name(); err == nil {
		tunName = realName
	}

	b := cfg.Bind
	if b == nil {
		b = conn.NewDefaultBind()
	}

	logger := device.NewLogger(device.LogLevelSilent, fmt.Sprintf("[%s] ", tunName))
	dev := device.NewDevice(tunDev, b, logger)

	e := &Engine{
		cfg:        cfg,
		tunDev:     tunDev,
		dev:        dev,
		logf:       cfg.Logf,
		listenPort: cfg.ListenPort,
		tunName:    tunName,
		peers:      make(map[key.Public]proto.Node),
	}

	return e, nil
}

// TunName returns the active TUN interface name.
func (e *Engine) TunName() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tunName
}

// SetPrivateKey configures the WireGuard node's private key.
func (e *Engine) SetPrivateKey(priv key.Private) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return fmt.Errorf("engine closed")
	}
	e.privKey = priv

	ipc := fmt.Sprintf("private_key=%s\n", priv.HexString())
	if e.listenPort > 0 {
		ipc += fmt.Sprintf("listen_port=%d\n", e.listenPort)
	}
	return e.dev.IpcSet(ipc)
}

// UpdateFromNetMap updates WireGuard peers to match the provided NetMap.
func (e *Engine) UpdateFromNetMap(self *proto.Node, peers []proto.Node) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return fmt.Errorf("engine closed")
	}

	if len(self.Addresses) > 0 {
		e.localIP = self.Addresses[0].Addr()
	}

	var sb strings.Builder
	sb.WriteString("replace_peers=true\n")

	newPeerMap := make(map[key.Public]proto.Node, len(peers))
	for _, p := range peers {
		if p.Key.IsZero() || p.Key == self.Key {
			continue
		}
		newPeerMap[p.Key] = p

		sb.WriteString(fmt.Sprintf("public_key=%s\n", p.Key.HexString()))

		// Set endpoint if available
		if len(p.Endpoints) > 0 {
			// Choose first endpoint for now (magicsock will handle dynamic endpoint in Phase 3)
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", p.Endpoints[0].String()))
		}

		// Allowed IPs
		for _, ip := range p.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
		}

		// Keepalive
		sb.WriteString("persistent_keepalive_interval=25\n")
	}

	ipcConfig := sb.String()
	if err := e.dev.IpcSet(ipcConfig); err != nil {
		return fmt.Errorf("wireguard IpcSet: %w", err)
	}

	e.peers = newPeerMap
	return nil
}

// Status returns current WireGuard peer statuses parsed from IpcGet.
func (e *Engine) Status() ([]PeerStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, fmt.Errorf("engine closed")
	}

	ipc, err := e.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("IpcGet: %w", err)
	}

	return parseIpcGet(ipc)
}

func parseIpcGet(ipc string) ([]PeerStatus, error) {
	var peers []PeerStatus
	var current *PeerStatus

	scanner := bufio.NewScanner(strings.NewReader(ipc))
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch k {
		case "public_key":
			if current != nil {
				peers = append(peers, *current)
			}
			pk, err := key.ParsePublicHex(v)
			if err != nil {
				continue
			}
			current = &PeerStatus{PublicKey: pk}

		case "endpoint":
			if current != nil {
				current.Endpoint = v
			}
		case "last_handshake_time_sec":
			if current != nil {
				sec, _ := strconv.ParseInt(v, 10, 64)
				if sec > 0 {
					current.LastHandshake = time.Unix(sec, 0)
				}
			}
		case "rx_bytes":
			if current != nil {
				n, _ := strconv.ParseInt(v, 10, 64)
				current.RxBytes = n
			}
		case "tx_bytes":
			if current != nil {
				n, _ := strconv.ParseInt(v, 10, 64)
				current.TxBytes = n
			}
		case "allowed_ip":
			if current != nil {
				pfx, err := netip.ParsePrefix(v)
				if err == nil {
					current.AllowedIPs = append(current.AllowedIPs, pfx)
				}
			}
		case "persistent_keepalive_interval":
			if current != nil {
				interval, _ := strconv.Atoi(v)
				current.PersistentKeepalive = interval
			}
		}
	}

	if current != nil {
		peers = append(peers, *current)
	}

	return peers, nil
}

// Close closes the WireGuard device and the TUN device.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.dev.Close()
	return e.tunDev.Close()
}
