// Package acl parses and compiles PeerLink access control policies.
//
// Policies are HuJSON (JSON with comments and trailing commas), modeled on
// Tailscale's policy file format:
//
//	{
//	  "groups":    {"group:devops": ["alice@example.com"]},
//	  "tagOwners": {"tag:server": ["group:devops"]},
//	  "hosts":     {"nas": "100.64.1.2"},
//	  "acls": [
//	    {"action": "accept", "src": ["group:devops"], "dst": ["tag:server:22,443"]},
//	    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*", "autogroup:internet:*"]},
//	  ],
//	  "ssh": [
//	    {"action": "accept", "src": ["group:devops"], "dst": ["tag:server"], "users": ["root", "autogroup:nonroot"]},
//	    {"action": "check",  "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"], "checkPeriod": "12h"},
//	  ],
//	  "autoApprovers": {"exitNode": ["tag:exit"], "routes": {"10.0.0.0/8": ["tag:router"]}},
//	}
package acl

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// Policy is a parsed access control policy.
type Policy struct {
	Groups        map[string][]string `json:"groups,omitempty"`
	TagOwners     map[string][]string `json:"tagOwners,omitempty"`
	Hosts         map[string]string   `json:"hosts,omitempty"`
	ACLs          []Rule              `json:"acls"`
	SSH           []SSHRule           `json:"ssh,omitempty"`
	AutoApprovers *AutoApprovers      `json:"autoApprovers,omitempty"`

	hosts map[string]netip.Prefix
}

// Rule is a network access rule.
type Rule struct {
	Action string   `json:"action"` // "accept"
	Proto  string   `json:"proto,omitempty"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"` // "selector:ports"

	proto []int
	dst   []dstSpec
}

type dstSpec struct {
	sel   string
	ports []portRange
}

type portRange struct{ first, last uint16 }

// SSHRule is an SSH access rule.
type SSHRule struct {
	Action      string   `json:"action"` // "accept" | "check"
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	CheckPeriod string   `json:"checkPeriod,omitempty"`
	Recorded    bool     `json:"recorded,omitempty"`

	checkPeriod time.Duration
}

// AutoApprovers lists who may have routes approved automatically.
type AutoApprovers struct {
	ExitNode []string            `json:"exitNode,omitempty"`
	Routes   map[string][]string `json:"routes,omitempty"`
}

// DefaultPolicyText is used when no policy has been configured: every device
// can reach every other device, and users can SSH into their own devices.
const DefaultPolicyText = `// PeerLink erişim politikası (HuJSON)
// Varsayılan: tüm cihazlar birbirine erişebilir.
{
  "groups": {},
  "tagOwners": {},
  "hosts": {},
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:internet:*"]},
  ],
  "ssh": [
    // Kullanıcılar kendi cihazlarına SSH yapabilir.
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot", "root"]},
  ],
}
`

// Default returns the default policy.
func Default() *Policy {
	p, err := Parse([]byte(DefaultPolicyText))
	if err != nil {
		panic(err)
	}
	return p
}

// Parse parses and validates a HuJSON policy.
func Parse(b []byte) (*Policy, error) {
	std, err := hujson.Standardize(b)
	if err != nil {
		return nil, fmt.Errorf("syntax error: %w", err)
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(std)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate() error {
	for g, members := range p.Groups {
		if !strings.HasPrefix(g, "group:") {
			return fmt.Errorf("group %q must start with group:", g)
		}
		for _, m := range members {
			if !strings.Contains(m, "@") && !strings.HasPrefix(m, "group:") {
				return fmt.Errorf("group %s: member %q must be a user email or group", g, m)
			}
		}
	}
	for t := range p.TagOwners {
		if !strings.HasPrefix(t, "tag:") {
			return fmt.Errorf("tagOwner %q must start with tag:", t)
		}
	}
	p.hosts = map[string]netip.Prefix{}
	for h, v := range p.Hosts {
		pfx, err := parsePrefix(v)
		if err != nil {
			return fmt.Errorf("host %q: %w", h, err)
		}
		p.hosts[h] = pfx
	}
	for i := range p.ACLs {
		r := &p.ACLs[i]
		if r.Action != "accept" {
			return fmt.Errorf("acls[%d]: action must be \"accept\"", i)
		}
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("acls[%d]: src and dst are required", i)
		}
		for _, s := range r.Src {
			if err := p.checkSelector(s, false); err != nil {
				return fmt.Errorf("acls[%d].src: %w", i, err)
			}
		}
		pr, err := parseProto(r.Proto)
		if err != nil {
			return fmt.Errorf("acls[%d]: %w", i, err)
		}
		r.proto = pr
		r.dst = nil
		for _, d := range r.Dst {
			ds, err := parseDst(d)
			if err != nil {
				return fmt.Errorf("acls[%d].dst: %w", i, err)
			}
			if err := p.checkSelector(ds.sel, true); err != nil {
				return fmt.Errorf("acls[%d].dst: %w", i, err)
			}
			r.dst = append(r.dst, ds)
		}
	}
	for i := range p.SSH {
		r := &p.SSH[i]
		if r.Action != "accept" && r.Action != "check" {
			return fmt.Errorf("ssh[%d]: action must be \"accept\" or \"check\"", i)
		}
		if len(r.Src) == 0 || len(r.Dst) == 0 || len(r.Users) == 0 {
			return fmt.Errorf("ssh[%d]: src, dst and users are required", i)
		}
		for _, s := range r.Src {
			if err := p.checkSelector(s, false); err != nil {
				return fmt.Errorf("ssh[%d].src: %w", i, err)
			}
		}
		for _, d := range r.Dst {
			if d == "autogroup:internet" {
				return fmt.Errorf("ssh[%d].dst: autogroup:internet not allowed", i)
			}
			if err := p.checkSelector(d, true); err != nil {
				return fmt.Errorf("ssh[%d].dst: %w", i, err)
			}
		}
		r.checkPeriod = 12 * time.Hour
		if r.CheckPeriod != "" {
			d, err := time.ParseDuration(r.CheckPeriod)
			if err != nil {
				return fmt.Errorf("ssh[%d].checkPeriod: %w", i, err)
			}
			r.checkPeriod = d
		}
	}
	if p.AutoApprovers != nil {
		for r := range p.AutoApprovers.Routes {
			if _, err := netip.ParsePrefix(r); err != nil {
				return fmt.Errorf("autoApprovers.routes: %w", err)
			}
		}
	}
	return nil
}

func (p *Policy) checkSelector(s string, dst bool) error {
	switch {
	case s == "*":
		return nil
	case s == "autogroup:member", s == "autogroup:tagged", s == "autogroup:admin":
		return nil
	case s == "autogroup:self", s == "autogroup:internet":
		if !dst {
			return fmt.Errorf("%s is only valid in dst", s)
		}
		return nil
	case strings.HasPrefix(s, "autogroup:"):
		return fmt.Errorf("unknown autogroup %q", s)
	case strings.HasPrefix(s, "group:"):
		if _, ok := p.Groups[s]; !ok {
			return fmt.Errorf("undefined group %q", s)
		}
		return nil
	case strings.HasPrefix(s, "tag:"):
		return nil
	case strings.Contains(s, "@"):
		return nil
	}
	if _, ok := p.hosts[s]; ok {
		return nil
	}
	if _, err := parsePrefix(s); err == nil {
		return nil
	}
	return fmt.Errorf("unknown selector %q", s)
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseDst(s string) (dstSpec, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return dstSpec{}, fmt.Errorf("%q: missing :ports", s)
	}
	sel, ports := s[:i], s[i+1:]
	var ds dstSpec
	ds.sel = sel
	for _, part := range strings.Split(ports, ",") {
		part = strings.TrimSpace(part)
		if part == "*" {
			ds.ports = append(ds.ports, portRange{0, 65535})
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return ds, fmt.Errorf("%q: bad port %q", s, part)
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(hi, 10, 16); err != nil || b < a {
				return ds, fmt.Errorf("%q: bad port range %q", s, part)
			}
		}
		ds.ports = append(ds.ports, portRange{uint16(a), uint16(b)})
	}
	return ds, nil
}

// IP protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

func parseProto(s string) ([]int, error) {
	switch strings.ToLower(s) {
	case "":
		return nil, nil
	case "tcp":
		return []int{ProtoTCP}, nil
	case "udp":
		return []int{ProtoUDP}, nil
	case "icmp":
		return []int{ProtoICMP}, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 255 {
		return nil, fmt.Errorf("invalid proto %q", s)
	}
	return []int{n}, nil
}
