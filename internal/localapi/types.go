// Package localapi provides the local IPC protocol between the peerlink CLI
// and the peerlinkd daemon over a Unix domain socket or named pipe.
package localapi

import (
	"net/netip"
	"time"

	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// DefaultSocketPath returns the standard socket location.
const DefaultSocketPath = "/var/run/peerlink/peerlinkd.sock"

// StatusResponse is returned by GET /localapi/v0/status.
type StatusResponse struct {
	BackendState string            `json:"backendState"` // "Running", "Stopped", "NeedsLogin", "Starting"
	Self         *proto.Node       `json:"self,omitempty"`
	Peers        []PeerStatusItem  `json:"peers"`
	ControlURL   string            `json:"controlURL"`
	AuthURL      string            `json:"authURL,omitempty"`
	MagicDNSSuffix string          `json:"magicDNSSuffix,omitempty"`
}

// PeerStatusItem is peer information shown in `peerlink status`.
type PeerStatusItem struct {
	ID             int64               `json:"id"`
	Name           string              `json:"name"`
	IP             netip.Addr          `json:"ip"`
	Online         bool                `json:"online"`
	Active         bool                `json:"active"` // WireGuard handshake in last 5m
	LastHandshake  time.Time           `json:"lastHandshake,omitempty"`
	RxBytes        int64               `json:"rxBytes"`
	TxBytes        int64               `json:"txBytes"`
	Endpoint       string              `json:"endpoint,omitempty"`
	Relay          string              `json:"relay,omitempty"`
	AllowedIPs     []netip.Prefix      `json:"allowedIPs"`
	OS             string              `json:"os"`
	IsExitNode     bool                `json:"isExitNode"`
	SSH            bool                `json:"ssh"`
}

// UpRequest is passed to POST /localapi/v0/up.
type UpRequest struct {
	ControlURL        string   `json:"controlURL,omitempty"`
	AuthKey           string   `json:"authKey,omitempty"`
	Hostname          string   `json:"hostname,omitempty"`
	SSH               bool     `json:"ssh"`
	AdvertiseExitNode bool     `json:"advertiseExitNode"`
	ExitNode          string   `json:"exitNode,omitempty"` // Name or IP of exit node to use
	AdvertiseRoutes   []string `json:"advertiseRoutes,omitempty"`
}

// UpResponse is returned by POST /localapi/v0/up.
type UpResponse struct {
	AuthURL string `json:"authURL,omitempty"`
	Status  string `json:"status"`
}

// PingResponse is returned by POST /localapi/v0/ping.
type PingResponse struct {
	Peer     string        `json:"peer"`
	IP       string        `json:"ip"`
	Direct   bool          `json:"direct"`
	Endpoint string        `json:"endpoint,omitempty"`
	Latency  time.Duration `json:"latency"`
	Error    string        `json:"error,omitempty"`
}
