package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Client talks to a local peerlinkd daemon.
type Client struct {
	http *http.Client
}

// UserSocketPath returns the per-user socket path when not running as root.
func UserSocketPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".peerlink", "peerlinkd.sock")
}

// SocketPath searches for available socket paths (system / user / env).
func SocketPath() string {
	if s := os.Getenv("PEERLINK_SOCKET"); s != "" {
		return s
	}
	if _, err := os.Stat(DefaultSocketPath); err == nil {
		return DefaultSocketPath
	}
	return UserSocketPath()
}

// NewClient returns a Client connecting to socketPath via Unix socket.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = SocketPath()
	}
	return &Client{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
				},
			},
			Timeout: 30 * time.Second,
		},
	}
}

// Status returns daemon status.
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localapi/localapi/v0/status", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peerlinkd çalışmıyor olabilir: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status failed (%d): %s", resp.StatusCode, string(b))
	}
	var res StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Up requests the daemon to connect.
func (c *Client) Up(ctx context.Context, upReq UpRequest) (*UpResponse, error) {
	body, _ := json.Marshal(upReq)
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localapi/localapi/v0/up", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peerlinkd çalışmıyor: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("up hatası: %s", strings.TrimSpace(string(b)))
	}
	var res UpResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Down requests the daemon to disconnect.
func (c *Client) Down(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localapi/localapi/v0/down", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Logout requests the daemon to logout.
func (c *Client) Logout(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localapi/localapi/v0/logout", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// IP returns the node's PeerLink IP.
func (c *Client) IP(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localapi/localapi/v0/ip", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
