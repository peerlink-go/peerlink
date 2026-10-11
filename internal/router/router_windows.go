package router

import (
	"net/netip"
	"slices"
	"sync"
)

type windowsRouter struct {
	cfg    Config
	mu     sync.Mutex
	local  netip.Addr
	routes []netip.Prefix
}

func newOSRouter(cfg Config) (Router, error) {
	return &windowsRouter{cfg: cfg}, nil
}

func (r *windowsRouter) SetRoutes(localIP netip.Addr, routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tun := r.cfg.TunName
	if localIP.IsValid() && localIP != r.local {
		_ = ExecCmd("netsh", "interface", "ipv4", "set", "address", "name="+tun, "source=static", "address="+localIP.String(), "mask=255.255.255.255")
		r.local = localIP
	}

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

	for _, rt := range toDel {
		_ = ExecCmd("route", "delete", rt.Addr().String())
	}

	for _, rt := range toAdd {
		_ = ExecCmd("route", "add", rt.String(), localIP.String())
	}

	r.routes = append([]netip.Prefix(nil), routes...)
	return nil
}

func (r *windowsRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.routes {
		_ = ExecCmd("route", "delete", rt.Addr().String())
	}
	r.routes = nil
	return nil
}
