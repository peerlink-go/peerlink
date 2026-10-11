// Package filter implements user-space packet filtering based on compiled ACL rules.
package filter

import (
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// Filter evaluates whether an inbound IPv4 packet is permitted by ACL rules.
type Filter struct {
	rules []proto.FilterRule
}

// New creates a new packet filter from rules.
func New(rules []proto.FilterRule) *Filter {
	return &Filter{rules: rules}
}

// Verdict is the outcome of packet evaluation.
type Verdict int

const (
	Drop Verdict = iota
	Accept
)

// Match examines an IPv4 packet buffer and reports whether it is allowed.
func (f *Filter) Match(pkt []byte) Verdict {
	if len(f.rules) == 0 {
		return Drop
	}
	if len(pkt) < 20 {
		return Drop
	}

	version := pkt[0] >> 4
	if version != 4 {
		return Drop // IPv4 only for now
	}

	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl {
		return Drop
	}

	ipProto := int(pkt[9])
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))

	var dstPort uint16
	if (ipProto == 6 || ipProto == 17) && len(pkt) >= ihl+4 { // TCP or UDP
		dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}

	for _, r := range f.rules {
		// 1. Protocol check
		if len(r.IPProto) > 0 && !slices.Contains(r.IPProto, ipProto) {
			continue
		}

		// 2. Source IP check
		srcMatches := false
		for _, s := range r.SrcIPs {
			if s == "*" {
				srcMatches = true
				break
			}
			if pfx, err := netip.ParsePrefix(s); err == nil {
				if pfx.Contains(srcIP) {
					srcMatches = true
					break
				}
			} else if addr, err := netip.ParseAddr(s); err == nil {
				if addr == srcIP {
					srcMatches = true
					break
				}
			}
		}
		if !srcMatches {
			continue
		}

		// 3. Destination Port check
		for _, dp := range r.DstPorts {
			// Check if destination IP matches rule
			dstMatches := false
			if dp.IP == "*" || dp.IP == "autogroup:internet" {
				dstMatches = true
			} else if pfx, err := netip.ParsePrefix(dp.IP); err == nil {
				if pfx.Contains(dstIP) {
					dstMatches = true
				}
			} else if addr, err := netip.ParseAddr(dp.IP); err == nil {
				if addr == dstIP {
					dstMatches = true
				}
			}

			if dstMatches {
				// If port matches
				if dstPort >= dp.Ports.First && dstPort <= dp.Ports.Last {
					return Accept
				}
			}
		}
	}

	return Drop
}
