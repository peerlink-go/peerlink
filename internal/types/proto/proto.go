// Package proto defines the wire types exchanged between PeerLink nodes
// (peerlinkd) and the coordination server (peerlink-control).
//
// All messages are JSON. Node requests are authenticated with an HMAC derived
// from an X25519 shared secret between the node key and the control key
// (see package controlauth).
package proto

import (
	"net/netip"
	"time"

	"github.com/peerlink-go/peerlink/internal/types/key"
)

// ProtocolVersion is bumped on incompatible protocol changes.
const ProtocolVersion = 1

// Well-known addresses.
var (
	// CGNATRange is the address range nodes are allocated from.
	CGNATRange = netip.MustParsePrefix("100.64.0.0/10")
	// MagicDNSIP is the address of the in-daemon DNS resolver.
	MagicDNSIP = netip.MustParseAddr("100.100.100.100")
)

// Control HTTP endpoints.
const (
	PathKey      = "/peerlink/key"
	PathRegister = "/peerlink/v1/register"
	PathMap      = "/peerlink/v1/map"
	PathSSHCheck = "/peerlink/v1/ssh/check"
	PathSSHAudit = "/peerlink/v1/ssh/audit"
	PathSSHRec   = "/peerlink/v1/ssh/recording"
)

// KeyResponse is returned by GET PathKey.
type KeyResponse struct {
	PublicKey       key.Public `json:"publicKey"`
	ProtocolVersion int        `json:"protocolVersion"`
}

// Hostinfo describes a node's host environment and requested capabilities.
type Hostinfo struct {
	Hostname      string         `json:"hostname"`
	OS            string         `json:"os"`
	OSVersion     string         `json:"osVersion,omitempty"`
	GoArch        string         `json:"goArch,omitempty"`
	ClientVersion string         `json:"clientVersion,omitempty"`
	RoutableIPs   []netip.Prefix `json:"routableIPs,omitempty"` // advertised subnet/exit routes
	RequestTags   []string       `json:"requestTags,omitempty"`
	SSHEnabled    bool           `json:"sshEnabled,omitempty"`
	SSHHostKeys   []string       `json:"sshHostKeys,omitempty"` // authorized_keys format
}

// IsExitNode reports whether h advertises a default route.
func (h *Hostinfo) IsExitNode() bool {
	for _, p := range h.RoutableIPs {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

// RegisterRequest registers (or re-authenticates) a node key.
type RegisterRequest struct {
	Version  int      `json:"version"`
	AuthKey  string   `json:"authKey,omitempty"`
	Hostinfo Hostinfo `json:"hostinfo"`
	// Followup is the AuthURL from a previous response; the server blocks
	// until the interactive login completes or times out.
	Followup string `json:"followup,omitempty"`
	// Logout expires the node key.
	Logout bool `json:"logout,omitempty"`
}

// RegisterResponse is the reply to RegisterRequest.
type RegisterResponse struct {
	NodeID         int64       `json:"nodeID,omitempty"`
	User           UserProfile `json:"user"`
	Authorized     bool        `json:"authorized"`
	NodeKeyExpired bool        `json:"nodeKeyExpired,omitempty"`
	// AuthURL is set when the user must log in through the browser.
	AuthURL string `json:"authURL,omitempty"`
	Error   string `json:"error,omitempty"`
}

// MapRequest opens (or updates) a node's netmap session.
type MapRequest struct {
	Version   int              `json:"version"`
	DiscoKey  key.Public       `json:"discoKey"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
	HomeRelay int              `json:"homeRelay,omitempty"`
	Hostinfo  *Hostinfo        `json:"hostinfo,omitempty"`
	// Stream keeps the response open, sending a new MapResponse on every
	// change and periodic keep-alives. If false, a single response is sent
	// (used for endpoint updates).
	Stream bool `json:"stream"`
}

// MapResponse is one message of the netmap stream (newline-delimited JSON).
type MapResponse struct {
	KeepAlive    bool          `json:"keepAlive,omitempty"`
	Node         *Node         `json:"node,omitempty"`
	Peers        []Node        `json:"peers"`
	UserProfiles []UserProfile `json:"userProfiles,omitempty"`
	DNS          *DNSConfig    `json:"dns,omitempty"`
	PacketFilter []FilterRule  `json:"packetFilter"`
	SSHPolicy    *SSHPolicy    `json:"sshPolicy,omitempty"`
	RelayMap     *RelayMap     `json:"relayMap,omitempty"`
	Domain       string        `json:"domain,omitempty"`
	ControlTime  time.Time     `json:"controlTime"`
}

// Node is a device in the tailnet as seen by other nodes.
type Node struct {
	ID            int64            `json:"id"`
	StableID      string           `json:"stableID"`
	Name          string           `json:"name"` // FQDN with trailing dot, e.g. "laptop.peerlink."
	User          int64            `json:"user"`
	Key           key.Public       `json:"key"`
	KeyExpiry     time.Time        `json:"keyExpiry,omitzero"`
	DiscoKey      key.Public       `json:"discoKey"`
	Addresses     []netip.Prefix   `json:"addresses"`  // node's own addresses (/32)
	AllowedIPs    []netip.Prefix   `json:"allowedIPs"` // addresses + approved routes
	Endpoints     []netip.AddrPort `json:"endpoints,omitempty"`
	HomeRelay     int              `json:"homeRelay,omitempty"`
	Hostinfo      Hostinfo         `json:"hostinfo"`
	Online        bool             `json:"online"`
	LastSeen      *time.Time       `json:"lastSeen,omitempty"`
	Authorized    bool             `json:"authorized"`
	Expired       bool             `json:"expired,omitempty"`
	Tags          []string         `json:"tags,omitempty"`
	PrimaryRoutes []netip.Prefix   `json:"primaryRoutes,omitempty"`
}

// IsExitNode reports whether n has an approved default route.
func (n *Node) IsExitNode() bool {
	for _, p := range n.AllowedIPs {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

// ShortName returns the first label of n.Name.
func (n *Node) ShortName() string {
	for i, c := range n.Name {
		if c == '.' {
			return n.Name[:i]
		}
	}
	return n.Name
}

// UserProfile is public information about a user.
type UserProfile struct {
	ID          int64  `json:"id"`
	LoginName   string `json:"loginName"`
	DisplayName string `json:"displayName"`
}

// DNSConfig configures MagicDNS on nodes.
type DNSConfig struct {
	MagicDNS      bool         `json:"magicDNS"`
	Domain        string       `json:"domain"`
	Nameservers   []netip.Addr `json:"nameservers,omitempty"` // upstream resolvers; empty = OS default
	SearchDomains []string     `json:"searchDomains,omitempty"`
	OverrideLocal bool         `json:"overrideLocal,omitempty"`
}

// FilterRule allows packets from SrcIPs to DstPorts.
// Rules are evaluated on the receiving node; default is deny.
type FilterRule struct {
	SrcIPs   []string       `json:"srcIPs"` // CIDRs, IPs, or "*"
	DstPorts []NetPortRange `json:"dstPorts"`
	// IPProto is the list of IP protocol numbers. Empty means TCP, UDP, ICMP.
	IPProto []int `json:"ipProto,omitempty"`
}

// NetPortRange is an IP range and port range.
type NetPortRange struct {
	IP    string    `json:"ip"` // CIDR, IP or "*"
	Ports PortRange `json:"ports"`
}

// PortRange is an inclusive port range.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// PortRangeAny matches every port.
var PortRangeAny = PortRange{0, 65535}

// SSHPolicy is the compiled SSH policy for a single destination node.
type SSHPolicy struct {
	Rules []SSHRule `json:"rules"`
}

// SSHRule matches a set of principals and maps SSH users to local users.
type SSHRule struct {
	RuleExpires *time.Time      `json:"ruleExpires,omitempty"`
	Principals  []SSHPrincipal  `json:"principals"`
	// SSHUsers maps a requested SSH user to a local user. "*" matches any user;
	// a value of "=" means "same as requested". An empty value rejects.
	SSHUsers map[string]string `json:"sshUsers"`
	Action   SSHAction         `json:"action"`
}

// SSHPrincipal identifies a connecting node or user. Exactly one field is set.
type SSHPrincipal struct {
	NodeIP    string `json:"nodeIP,omitempty"`
	UserLogin string `json:"userLogin,omitempty"`
	Any       bool   `json:"any,omitempty"`
}

// SSHAction is the outcome of a matching SSHRule.
type SSHAction struct {
	Message                  string        `json:"message,omitempty"`
	Reject                   bool          `json:"reject,omitempty"`
	Accept                   bool          `json:"accept,omitempty"`
	SessionDuration          time.Duration `json:"sessionDuration,omitempty"`
	AllowAgentForwarding     bool          `json:"allowAgentForwarding,omitempty"`
	AllowLocalPortForwarding bool          `json:"allowLocalPortForwarding,omitempty"`
	AllowRemotePortForwarding bool         `json:"allowRemotePortForwarding,omitempty"`
	// HoldAndDelegate, if set, is a control URL the node must POST to; the
	// request blocks until the user re-authenticates ("check" mode) and
	// returns the final SSHAction.
	HoldAndDelegate string `json:"holdAndDelegate,omitempty"`
	// Recorded requests that the session be recorded and uploaded.
	Recorded bool `json:"recorded,omitempty"`
}

// SSHCheckRequest is sent to SSHAction.HoldAndDelegate.
type SSHCheckRequest struct {
	SrcNodeID int64  `json:"srcNodeID"`
	SSHUser   string `json:"sshUser"`
	LocalUser string `json:"localUser"`
}

// SSHCheckResponse returns the final action and an optional URL for the user.
type SSHCheckResponse struct {
	Action  *SSHAction `json:"action,omitempty"`
	AuthURL string     `json:"authURL,omitempty"`
}

// SSHAuditEvent records an SSH connection attempt.
type SSHAuditEvent struct {
	Time      time.Time `json:"time"`
	SrcNodeID int64     `json:"srcNodeID"`
	SrcIP     string    `json:"srcIP"`
	SSHUser   string    `json:"sshUser"`
	LocalUser string    `json:"localUser"`
	Accepted  bool      `json:"accepted"`
	Reason    string    `json:"reason,omitempty"`
	SessionID string    `json:"sessionID,omitempty"`
	Command   string    `json:"command,omitempty"`
	Ended     bool      `json:"ended,omitempty"`
}

// RelayMap describes available relay (and STUN) servers.
type RelayMap struct {
	Regions map[int]*RelayRegion `json:"regions"`
}

// RelayRegion is a geographic group of relay servers.
type RelayRegion struct {
	RegionID   int          `json:"regionID"`
	RegionCode string       `json:"regionCode"`
	RegionName string       `json:"regionName"`
	Nodes      []*RelayNode `json:"nodes"`
}

// RelayNode is a single relay server.
type RelayNode struct {
	Name     string `json:"name"`
	RegionID int    `json:"regionID"`
	// URL is the relay base URL, e.g. "https://relay1.example.com".
	URL string `json:"url"`
	// STUNAddr is host:port of the STUN server ("" disables STUN).
	STUNAddr string `json:"stunAddr,omitempty"`
	// InsecureSkipVerify disables TLS verification (tests only).
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}
