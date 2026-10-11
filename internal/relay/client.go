package relay

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/peerlink-go/peerlink/internal/types/key"
)

// PacketHandler is called when a packet arrives from src peer via relay.
type PacketHandler func(src key.Public, packet []byte)

// Client is a connection to a PeerLink relay server.
type Client struct {
	serverURL string
	nodeKey   key.Public
	handler   PacketHandler

	mu     sync.Mutex
	conn   *websocket.Conn
	cancel context.CancelFunc
	closed bool
}

// NewClient connects to serverURL as nodeKey and delivers packets to handler.
func NewClient(ctx context.Context, serverURL string, nodeKey key.Public, handler PacketHandler) (*Client, error) {
	wsURL := serverURL + "/relay?key=" + nodeKey.String()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"X-PeerLink-Node-Key": []string{nodeKey.String()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	loopCtx, cancel := context.WithCancel(context.Background())
	c := &Client{
		serverURL: serverURL,
		nodeKey:   nodeKey,
		handler:   handler,
		conn:      conn,
		cancel:    cancel,
	}

	go c.readLoop(loopCtx)
	return c, nil
}

func (c *Client) readLoop(ctx context.Context) {
	defer c.conn.Close(websocket.StatusNormalClosure, "client closing")
	for {
		_, frame, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
		if len(frame) < 32 {
			continue
		}
		var src key.Public
		copy(src[:], frame[0:32])
		pkt := frame[32:]
		if c.handler != nil {
			c.handler(src, pkt)
		}
	}
}

// SendPacket sends a WireGuard packet to dst via this relay server.
func (c *Client) SendPacket(ctx context.Context, dst key.Public, packet []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.conn == nil {
		return fmt.Errorf("relay client closed")
	}

	frame := make([]byte, 32+len(packet))
	copy(frame[0:32], dst[:])
	copy(frame[32:], packet)

	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return c.conn.Write(writeCtx, websocket.MessageBinary, frame)
}

// Close closes the connection to the relay server.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		return c.conn.Close(websocket.StatusNormalClosure, "closed")
	}
	return nil
}
