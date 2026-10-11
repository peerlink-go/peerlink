// Package control implements the PeerLink coordination server.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/peerlink-go/peerlink/internal/acl"
	"github.com/peerlink-go/peerlink/internal/control/store"
	"github.com/peerlink-go/peerlink/internal/controlauth"
	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// Config configures the control server.
type Config struct {
	// ServerURL is the externally reachable base URL, e.g. https://peerlink.example.com.
	ServerURL string
	// Domain is the MagicDNS domain (default "peerlink").
	Domain string
	// RequireApproval requires an admin to authorize new nodes (unless the auth key is pre-authorized).
	RequireApproval bool
	// NodeKeyExpiry is how long node keys are valid (default 180 days; 0 uses default).
	NodeKeyExpiry time.Duration
	// RelayMap is distributed to all nodes.
	RelayMap *proto.RelayMap
	// SecureCookies sets the Secure flag on session cookies (enable behind HTTPS).
	SecureCookies bool
	// RecordingDir stores SSH session recordings ("" disables uploads).
	RecordingDir string
	// WebHandler serves the admin UI (optional).
	WebHandler http.Handler
	// Logf logs messages (default log.Printf).
	Logf func(format string, args ...any)
}

// Server is the coordination server.
type Server struct {
	cfg      Config
	store    *store.Store
	priv     key.Private
	verifier *controlauth.Verifier
	logf     func(string, ...any)

	policy atomic.Pointer[acl.Policy]
	notify notifier

	mu     sync.Mutex
	online map[int64]int // node ID -> active map streams

	sshMu     sync.Mutex
	sshChecks map[string]chan bool // check ID -> result
}

const (
	settingControlKey = "control_private_key"
	settingPolicy     = "policy"
	settingDNS        = "dns"
)

// New creates a server using st for storage.
func New(ctx context.Context, cfg Config, st *store.Store) (*Server, error) {
	if cfg.Domain == "" {
		cfg.Domain = "peerlink"
	}
	if cfg.NodeKeyExpiry == 0 {
		cfg.NodeKeyExpiry = 180 * 24 * time.Hour
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	s := &Server{
		cfg:       cfg,
		store:     st,
		logf:      cfg.Logf,
		online:    map[int64]int{},
		sshChecks: map[string]chan bool{},
	}
	s.notify.ch = make(chan struct{})

	// Control key: generated on first start, persisted.
	ks, err := st.GetSetting(ctx, settingControlKey)
	if err != nil {
		return nil, err
	}
	if ks == "" {
		s.priv = key.NewPrivate()
		if err := st.SetSetting(ctx, settingControlKey, s.priv.String()); err != nil {
			return nil, err
		}
	} else if err := s.priv.UnmarshalText([]byte(ks)); err != nil {
		return nil, err
	}
	s.verifier = controlauth.NewVerifier(s.priv)

	// Policy.
	pt, err := st.GetSetting(ctx, settingPolicy)
	if err != nil {
		return nil, err
	}
	if pt == "" {
		pt = acl.DefaultPolicyText
		st.SetSetting(ctx, settingPolicy, pt)
	}
	p, err := acl.Parse([]byte(pt))
	if err != nil {
		s.logf("WARNING: stored policy invalid (%v); using default", err)
		p = acl.Default()
	}
	s.policy.Store(p)
	return s, nil
}

// PublicKey returns the control server public key.
func (s *Server) PublicKey() key.Public { return s.priv.Public() }

// Store returns the underlying store.
func (s *Server) Store() *store.Store { return s.store }

// Run runs background maintenance until ctx is done.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.gcEphemeral(ctx)
		}
	}
}

func (s *Server) gcEphemeral(ctx context.Context) {
	nodes, err := s.store.ListNodes(ctx, 0)
	if err != nil {
		return
	}
	changed := false
	for _, n := range nodes {
		if n.Ephemeral && !s.isOnline(n.ID) && time.Since(n.LastSeen) > 10*time.Minute {
			s.logf("deleting offline ephemeral node %s", n.Name)
			s.store.DeleteNode(ctx, n.ID)
			changed = true
		}
	}
	if changed {
		s.notify.notify()
	}
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Node protocol.
	mux.HandleFunc("GET "+proto.PathKey, s.handleKey)
	mux.HandleFunc("POST "+proto.PathRegister, s.handleRegister)
	mux.HandleFunc("POST "+proto.PathMap, s.handleMap)
	mux.HandleFunc("POST "+proto.PathSSHCheck, s.handleSSHCheck)
	mux.HandleFunc("POST "+proto.PathSSHAudit, s.handleSSHAudit)
	mux.HandleFunc("POST "+proto.PathSSHRec, s.handleSSHRecording)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	// Admin API.
	s.registerAdmin(mux)
	// Web UI.
	if s.cfg.WebHandler != nil {
		mux.Handle("/", s.cfg.WebHandler)
	} else {
		mux.HandleFunc("GET /{$}", s.handleEmbeddedAdmin)
	}
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, proto.KeyResponse{PublicKey: s.PublicKey(), ProtocolVersion: proto.ProtocolVersion})
}

// ---- change notification ----

type notifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func (n *notifier) wait() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ch
}

func (n *notifier) notify() {
	n.mu.Lock()
	defer n.mu.Unlock()
	close(n.ch)
	n.ch = make(chan struct{})
}

// Changed signals all connected nodes that the netmap may have changed.
func (s *Server) Changed() { s.notify.notify() }

// ---- online tracking ----

func (s *Server) setOnline(id int64, delta int) {
	s.mu.Lock()
	before := s.online[id] > 0
	s.online[id] += delta
	if s.online[id] <= 0 {
		delete(s.online, id)
	}
	after := s.online[id] > 0
	s.mu.Unlock()
	if before != after {
		s.notify.notify()
	}
}

func (s *Server) isOnline(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online[id] > 0
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apiError{Error: msg})
}

func storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrExists):
		writeErr(w, http.StatusConflict, "already exists")
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}
