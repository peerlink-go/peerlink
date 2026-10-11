package router

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
)

type linuxRouter struct {
	cfg    Config
	mu     sync.Mutex
	local  netip.Addr
	routes []netip.Prefix
}

func newOSRouter(cfg Config) (Router, error) {
	return &linuxRouter{cfg: cfg}, nil
}

func (r *linuxRouter) SetRoutes(localIP netip.Addr, routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tun := r.cfg.TunName
	if localIP.IsValid() && localIP != r.local {
		_ = ExecCmd("ip", "addr", "add", localIP.String()+"/32", "dev", tun)
		_ = ExecCmd("ip", "link", "set", "dev", tun, "up")
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
		if rt.Bits() == 0 {
			_ = ExecCmd("ip", "route", "del", "0.0.0.0/1", "dev", tun)
			_ = ExecCmd("ip", "route", "del", "128.0.0.0/1", "dev", tun)
		} else {
			_ = ExecCmd("ip", "route", "del", rt.String(), "dev", tun)
		}
	}

	for _, rt := range toAdd {
		if rt.Bits() == 0 {
			_ = ExecCmd("ip", "route", "add", "0.0.0.0/1", "dev", tun)
			_ = ExecCmd("ip", "route", "add", "128.0.0.0/1", "dev", tun)
		} else {
			_ = ExecCmd("ip", "route", "add", rt.String(), "dev", tun)
		}
	}

	r.routes = append([]netip.Prefix(nil), routes...)
	return nil
}

func (r *linuxRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tun := r.cfg.TunName
	_ = ExecCmd("ip", "link", "set", "dev", tun, "down")
	r.routes = nil
	return nil
}
