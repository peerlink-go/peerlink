// Package router manages OS network interface addresses and IP routing tables
// for the PeerLink TUN interface across macOS, Linux, and Windows.
package router

import (
	"fmt"
	"net/netip"
	"os/exec"
	"sync"
)

// Router configures interface IPs and routing table entries.
type Router interface {
	// SetRoutes configures the local interface IP address and active routing table entries.
	SetRoutes(localIP netip.Addr, routes []netip.Prefix) error
	// Close cleans up routes and interface configuration.
	Close() error
}

// Config configures a Router.
type Config struct {
	TunName string
	Logf    func(format string, args ...any)
}

// New creates an OS-appropriate router for tunName.
func New(cfg Config) (Router, error) {
	return newOSRouter(cfg)
}

// DummyRouter is a no-op router used in testing or on unsupported platforms.
type DummyRouter struct {
	cfg    Config
	mu     sync.Mutex
	local  netip.Addr
	routes []netip.Prefix
}

func newDummyRouter(cfg Config) *DummyRouter {
	return &DummyRouter{cfg: cfg}
}

func (r *DummyRouter) SetRoutes(localIP netip.Addr, routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.local = localIP
	r.routes = append([]netip.Prefix(nil), routes...)
	if r.cfg.Logf != nil {
		r.cfg.Logf("dummy router: set IP %s, %d routes", localIP, len(routes))
	}
	return nil
}

func (r *DummyRouter) Close() error {
	return nil
}

// ExecCmd runs an OS command and returns combined output on error.
func ExecCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w (output: %s)", name, args, err, string(out))
	}
	return nil
}
