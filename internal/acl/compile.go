package acl

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// NodeInfo is the policy-relevant view of a node.
type NodeInfo struct {
	ID          int64
	IP          netip.Addr
	UserID      int64
	UserEmail   string
	UserIsAdmin bool
	Tags        []string
	// Routes are the node's approved *primary* routes (including 0.0.0.0/0
	// for an approved exit node).
	Routes []netip.Prefix
}

func (n *NodeInfo) tagged() bool { return len(n.Tags) > 0 }

func (n *NodeInfo) isExit() bool {
	for _, r := range n.Routes {
		if r.Bits() == 0 {
			return true
		}
	}
	return false
}

// InternetDst is the NetPortRange.IP value meaning "any non-PeerLink address"
// (traffic forwarded by an exit node).
const InternetDst = "autogroup:internet"

// Result is the compiled policy for a single node.
type Result struct {
	// Peers maps visible peer IDs to the AllowedIPs to route to them.
	Peers map[int64][]netip.Prefix
	// Filter is the inbound packet filter for the node.
	Filter []proto.FilterRule
	// SSH is the node's SSH policy (nil if no rule targets it).
	SSH *proto.SSHPolicy
	// CanUseExitNodes reports whether the node may use exit nodes.
	CanUseExitNodes bool
}

func (p *Policy) userInGroup(email, group string, depth int) bool {
	if depth > 10 {
		return false
	}
	for _, m := range p.Groups[group] {
		if strings.HasPrefix(m, "group:") {
			if p.userInGroup(email, m, depth+1) {
				return true
			}
		} else if strings.EqualFold(m, email) {
			return true
		}
	}
	return false
}

func (p *Policy) selPrefix(sel string) (netip.Prefix, bool) {
	if pfx, ok := p.hosts[sel]; ok {
		return pfx, true
	}
	if strings.ContainsAny(sel, ":@") {
		return netip.Prefix{}, false
	}
	pfx, err := parsePrefix(sel)
	return pfx, err == nil
}

// matches reports whether node n is selected by sel. autogroup:self and
// autogroup:internet never match here; they are handled by the caller.
func (p *Policy) matches(sel string, n *NodeInfo) bool {
	switch {
	case sel == "*":
		return true
	case sel == "autogroup:member":
		return !n.tagged()
	case sel == "autogroup:tagged":
		return n.tagged()
	case sel == "autogroup:admin":
		return !n.tagged() && n.UserIsAdmin
	case sel == "autogroup:self", sel == "autogroup:internet":
		return false
	case strings.HasPrefix(sel, "group:"):
		return !n.tagged() && p.userInGroup(n.UserEmail, sel, 0)
	case strings.HasPrefix(sel, "tag:"):
		return slices.Contains(n.Tags, sel)
	case strings.Contains(sel, "@"):
		return !n.tagged() && strings.EqualFold(sel, n.UserEmail)
	}
	if pfx, ok := p.selPrefix(sel); ok {
		return pfx.Contains(n.IP)
	}
	return false
}

func (p *Policy) matchesAny(sels []string, n *NodeInfo) bool {
	for _, s := range sels {
		if p.matches(s, n) {
			return true
		}
	}
	return false
}

func overlapsRoutes(pfx netip.Prefix, routes []netip.Prefix) bool {
	for _, r := range routes {
		if r.Bits() > 0 && r.Overlaps(pfx) {
			return true
		}
	}
	return false
}

// srcSet returns the nodes selected by srcs plus literal source prefixes.
func (p *Policy) srcSet(srcs []string, all []*NodeInfo) (nodes []*NodeInfo, ips []string) {
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			ips = append(ips, s)
		}
	}
	for _, s := range srcs {
		if s == "*" {
			add("*")
		} else if pfx, ok := p.selPrefix(s); ok {
			add(pfx.String())
		}
	}
	for _, n := range all {
		if p.matchesAny(srcs, n) {
			nodes = append(nodes, n)
			if !seen["*"] {
				add(n.IP.String())
			}
		}
	}
	return nodes, ips
}

func nodeIPs(nodes []*NodeInfo) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.IP.String())
	}
	return out
}

func toPorts(prs []portRange, ip string) []proto.NetPortRange {
	out := make([]proto.NetPortRange, 0, len(prs))
	for _, pr := range prs {
		out = append(out, proto.NetPortRange{IP: ip, Ports: proto.PortRange{First: pr.first, Last: pr.last}})
	}
	return out
}

// Compile computes the netmap view of self given all nodes (self included).
// sshCheckURL is the control URL used for "check" SSH rules.
func (p *Policy) Compile(self *NodeInfo, all []*NodeInfo, sshCheckURL string) *Result {
	res := &Result{Peers: map[int64][]netip.Prefix{}}
	visible := map[int64]bool{}
	selfIP := netip.PrefixFrom(self.IP, 32).String()
	addPeers := func(ns []*NodeInfo) {
		for _, n := range ns {
			if n.ID != self.ID {
				visible[n.ID] = true
			}
		}
	}

	for i := range p.ACLs {
		r := &p.ACLs[i]
		srcNodes, srcIPs := p.srcSet(r.Src, all)
		selfIsSrc := p.matchesAny(r.Src, self)

		for _, ds := range r.dst {
			switch ds.sel {
			case "autogroup:internet":
				if selfIsSrc {
					res.CanUseExitNodes = true
					for _, n := range all {
						if n.ID != self.ID && n.isExit() {
							visible[n.ID] = true
						}
					}
				}
				if self.isExit() && len(srcNodes) > 0 {
					res.Filter = append(res.Filter, proto.FilterRule{
						SrcIPs: nodeIPs(srcNodes), DstPorts: toPorts(ds.ports, InternetDst), IPProto: r.proto})
					addPeers(srcNodes)
				}

			case "autogroup:self":
				if self.tagged() {
					continue
				}
				var mine []*NodeInfo
				for _, n := range srcNodes {
					if !n.tagged() && n.UserID == self.UserID {
						mine = append(mine, n)
					}
				}
				if len(mine) > 0 {
					res.Filter = append(res.Filter, proto.FilterRule{
						SrcIPs: nodeIPs(mine), DstPorts: toPorts(ds.ports, selfIP), IPProto: r.proto})
					addPeers(mine)
				}
				if selfIsSrc {
					for _, n := range all {
						if !n.tagged() && n.UserID == self.UserID {
							addPeers([]*NodeInfo{n})
						}
					}
				}

			default:
				pfx, isPfx := p.selPrefix(ds.sel)
				// Inbound: does this rule allow traffic to self?
				if len(srcIPs) > 0 {
					if p.matches(ds.sel, self) {
						dst := selfIP
						if isPfx {
							dst = pfx.String()
						}
						res.Filter = append(res.Filter, proto.FilterRule{
							SrcIPs: srcIPs, DstPorts: toPorts(ds.ports, dst), IPProto: r.proto})
						addPeers(srcNodes)
					} else if isPfx && overlapsRoutes(pfx, self.Routes) {
						// Self is a subnet router for (part of) this prefix.
						res.Filter = append(res.Filter, proto.FilterRule{
							SrcIPs: srcIPs, DstPorts: toPorts(ds.ports, pfx.String()), IPProto: r.proto})
						addPeers(srcNodes)
					}
				}
				// Outbound: which peers can self reach?
				if selfIsSrc {
					for _, n := range all {
						if n.ID == self.ID {
							continue
						}
						if p.matches(ds.sel, n) || (isPfx && overlapsRoutes(pfx, n.Routes)) {
							visible[n.ID] = true
						}
					}
				}
			}
		}
	}

	// SSH rules: compile policy for self as destination, and grant implicit
	// TCP/22 network access so that SSH rules work without a matching ACL.
	var sshRules []proto.SSHRule
	for i := range p.SSH {
		r := &p.SSH[i]
		srcNodes, _ := p.srcSet(r.Src, all)
		selfIsSrc := p.matchesAny(r.Src, self)

		var principals []*NodeInfo
		for _, d := range r.Dst {
			if d == "autogroup:self" {
				if selfIsSrc {
					for _, n := range all {
						if !n.tagged() && !self.tagged() && n.UserID == self.UserID {
							addPeers([]*NodeInfo{n})
						}
					}
				}
				if self.tagged() {
					continue
				}
				for _, n := range srcNodes {
					if !n.tagged() && n.UserID == self.UserID {
						principals = append(principals, n)
					}
				}
				continue
			}
			if selfIsSrc {
				for _, n := range all {
					if n.ID != self.ID && p.matches(d, n) {
						visible[n.ID] = true
					}
				}
			}
			if p.matches(d, self) {
				principals = append(principals, srcNodes...)
			}
		}
		if len(principals) == 0 {
			continue
		}
		principals = dedupNodes(principals)
		addPeers(principals)
		res.Filter = append(res.Filter, proto.FilterRule{
			SrcIPs:   nodeIPs(principals),
			DstPorts: []proto.NetPortRange{{IP: selfIP, Ports: proto.PortRange{First: 22, Last: 22}}},
			IPProto:  []int{ProtoTCP},
		})

		rule := proto.SSHRule{SSHUsers: sshUserMap(r.Users)}
		for _, n := range principals {
			rule.Principals = append(rule.Principals, proto.SSHPrincipal{NodeIP: n.IP.String()})
		}
		switch r.Action {
		case "accept":
			rule.Action = proto.SSHAction{
				Accept: true, Recorded: r.Recorded,
				AllowAgentForwarding: true, AllowLocalPortForwarding: true, AllowRemotePortForwarding: true,
			}
		case "check":
			rule.Action = proto.SSHAction{
				HoldAndDelegate: fmt.Sprintf("%s?period=%s", sshCheckURL, r.checkPeriod),
				Recorded:        r.Recorded,
			}
		}
		sshRules = append(sshRules, rule)
	}
	if len(sshRules) > 0 {
		res.SSH = &proto.SSHPolicy{Rules: sshRules}
	}

	byID := map[int64]*NodeInfo{}
	for _, n := range all {
		byID[n.ID] = n
	}
	for id := range visible {
		n := byID[id]
		if n == nil {
			continue
		}
		allowed := []netip.Prefix{netip.PrefixFrom(n.IP, 32)}
		for _, r := range n.Routes {
			if r.Bits() == 0 && !res.CanUseExitNodes {
				continue
			}
			allowed = append(allowed, r)
		}
		res.Peers[id] = allowed
	}
	if res.Filter == nil {
		res.Filter = []proto.FilterRule{}
	}
	return res
}

func dedupNodes(ns []*NodeInfo) []*NodeInfo {
	seen := map[int64]bool{}
	out := ns[:0:0]
	for _, n := range ns {
		if !seen[n.ID] {
			seen[n.ID] = true
			out = append(out, n)
		}
	}
	return out
}

// sshUserMap converts policy users into an SSHUsers map.
func sshUserMap(users []string) map[string]string {
	m := map[string]string{}
	for _, u := range users {
		if u == "autogroup:nonroot" {
			m["*"] = "="
			if _, ok := m["root"]; !ok {
				m["root"] = ""
			}
		}
	}
	for _, u := range users {
		if u != "autogroup:nonroot" {
			m[u] = u
		}
	}
	return m
}

// CanOwnTag reports whether the given user may apply tag to a node.
func (p *Policy) CanOwnTag(email string, isAdmin bool, tag string) bool {
	if isAdmin {
		return true
	}
	for _, o := range p.TagOwners[tag] {
		switch {
		case strings.HasPrefix(o, "group:"):
			if p.userInGroup(email, o, 0) {
				return true
			}
		case strings.EqualFold(o, email):
			return true
		}
	}
	return false
}

// AutoApproved reports whether route advertised by n is automatically approved.
func (p *Policy) AutoApproved(n *NodeInfo, route netip.Prefix) bool {
	if p.AutoApprovers == nil {
		return false
	}
	if route.Bits() == 0 {
		return p.matchesAny(p.AutoApprovers.ExitNode, n)
	}
	for r, approvers := range p.AutoApprovers.Routes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		if pfx.Bits() <= route.Bits() && pfx.Contains(route.Addr()) && p.matchesAny(approvers, n) {
			return true
		}
	}
	return false
}
