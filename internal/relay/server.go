// Package relay implements the PeerLink Relay server and client
// (similar to Tailscale's DERP) over WebSockets.
// WireGuard packets are relayed end-to-end encrypted without the relay
// server possessing decryption keys.
package relay

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/peerlink-go/peerlink/internal/types/key"
)

// Server relays encrypted WireGuard packets between connected peers.
type Server struct {
	mu      sync.RWMutex
	clients map[key.Public]*clientSession
	logf    func(format string, args ...any)
}

type clientSession struct {
	pub  key.Public
	conn *websocket.Conn
	send chan []byte
}

// NewServer creates a new Relay server.
func NewServer(logf func(format string, args ...any)) *Server {
	if logf == nil {
		logf = log.Printf
	}
	return &Server{
		clients: make(map[key.Public]*clientSession),
		logf:    logf,
	}
}

// Handler returns the HTTP handler for relay connections.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", s.handleRelay)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	return mux
}

func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request) {
	nodeKeyStr := r.Header.Get("X-PeerLink-Node-Key")
	if nodeKeyStr == "" {
		nodeKeyStr = r.URL.Query().Get("key")
	}
	nodeKey, err := key.ParsePublic(nodeKeyStr)
	if err != nil || nodeKey.IsZero() {
		http.Error(w, "missing or invalid node key", http.StatusBadRequest)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.logf("websocket.Accept error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "session ended")

	sess := &clientSession{
		pub:  nodeKey,
		conn: conn,
		send: make(chan []byte, 512),
	}

	s.mu.Lock()
	if old, exists := s.clients[nodeKey]; exists {
		old.conn.Close(websocket.StatusNormalClosure, "replaced by new connection")
	}
	s.clients[nodeKey] = sess
	s.mu.Unlock()

	s.logf("Relay: peer bağlandı %s", nodeKey.ShortString())
	defer func() {
		s.mu.Lock()
		if cur, ok := s.clients[nodeKey]; ok && cur == sess {
			delete(s.clients, nodeKey)
		}
		s.mu.Unlock()
		s.logf("Relay: peer ayrıldı %s", nodeKey.ShortString())
	}()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Writer loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-sess.send:
				if !ok {
					return
				}
				writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Write(writeCtx, websocket.MessageBinary, msg)
				writeCancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Reader loop: receives [32-byte dstKey] + [payload]
	for {
		_, payload, err := conn.Read(ctx)
		if err != nil {
			break
		}
		if len(payload) < 32 {
			continue // invalid frame
		}

		var dstKey key.Public
		copy(dstKey[:], payload[0:32])
		pktData := payload[32:]

		// Forward frame: [32-byte srcKey] + [payload]
		outFrame := make([]byte, 32+len(pktData))
		copy(outFrame[0:32], nodeKey[:])
		copy(outFrame[32:], pktData)

		s.mu.RLock()
		target, ok := s.clients[dstKey]
		s.mu.RUnlock()

		if ok {
			select {
			case target.send <- outFrame:
			default:
				// target buffer full, drop packet
			}
		}
	}
}

// ActivePeers returns the count of currently connected peers.
func (s *Server) ActivePeers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}
