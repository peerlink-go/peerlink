package router

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
)

type darwinRouter struct {
	cfg    Config
	mu     sync.Mutex
	local  netip.Addr
	routes []netip.Prefix
}

func newOSRouter(cfg Config) (Router, error) {
	return &darwinRouter{cfg: cfg}, nil
}

func (r *darwinRouter) SetRoutes(localIP netip.Addr, routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tun := r.cfg.TunName
	// Set local IP if changed or not set
	if localIP.IsValid() && localIP != r.local {
		// on macOS: ifconfig utunX 100.64.x.y 100.64.x.y up
		ipStr := localIP.String()
		if err := ExecCmd("ifconfig", tun, ipStr, ipStr, "up"); err != nil {
			return fmt.Errorf("ifconfig %s: %w", tun, err)
		}
		r.local = localIP
	}

	// Calculate routes delta
	var toAdd, toDel []netip.Prefix
	for _, rt := range routes {
		if !slices.Contains(r.routes, rt) {
			toAdd = append(toAdd, rt)
		}
	}
	for _, rt := range r.routes {
		if !slices.Contains(routes, rt) {
			toDel = append(toDel, rt)
		}
	}

	// Delete obsolete routes
	for _, rt := range toDel {
		_ = ExecCmd("route", "-q", "-n", "delete", "-net", rt.String(), "-interface", tun)
	}

	// Add new routes
	for _, rt := range toAdd {
		if rt.Bits() == 0 {
			// Default route (Exit node)
			_ = ExecCmd("route", "-q", "-n", "add", "-net", "0.0.0.0/1", "-interface", tun)
			_ = ExecCmd("route", "-q", "-n", "add", "-net", "128.0.0.0/1", "-interface", tun)
		} else {
			_ = ExecCmd("route", "-q", "-n", "add", "-net", rt.String(), "-interface", tun)
		}
	}

	r.routes = append([]netip.Prefix(nil), routes...)
	return nil
}

func (r *darwinRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tun := r.cfg.TunName
	for _, rt := range r.routes {
		if rt.Bits() == 0 {
			_ = ExecCmd("route", "-q", "-n", "delete", "-net", "0.0.0.0/1", "-interface", tun)
			_ = ExecCmd("route", "-q", "-n", "delete", "-net", "128.0.0.0/1", "-interface", tun)
		} else {
			_ = ExecCmd("route", "-q", "-n", "delete", "-net", rt.String(), "-interface", tun)
		}
	}
	r.routes = nil
	_ = ExecCmd("ifconfig", tun, "down")
	return nil
}
