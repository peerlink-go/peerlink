package localapi

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

// DaemonBackend is implemented by the peerlinkd daemon to serve local requests.
type DaemonBackend interface {
	Status() (*StatusResponse, error)
	Up(req UpRequest) (*UpResponse, error)
	Down() error
	Logout() error
	IP() (string, error)
}

// Server serves the local control API over a Unix listener.
type Server struct {
	backend DaemonBackend
	mux     *http.ServeMux
}

// NewServer creates a localapi HTTP handler.
func NewServer(backend DaemonBackend) *Server {
	s := &Server{
		backend: backend,
		mux:     http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /localapi/v0/status", s.handleStatus)
	s.mux.HandleFunc("POST /localapi/v0/up", s.handleUp)
	s.mux.HandleFunc("POST /localapi/v0/down", s.handleDown)
	s.mux.HandleFunc("POST /localapi/v0/logout", s.handleLogout)
	s.mux.HandleFunc("GET /localapi/v0/ip", s.handleIP)
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.backend.Status()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func (s *Server) handleUp(w http.ResponseWriter, r *http.Request) {
	var req UpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	res, err := s.backend.Up(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (s *Server) handleDown(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Down(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Logout(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleIP(w http.ResponseWriter, r *http.Request) {
	ip, err := s.backend.IP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(ip + "\n"))
}

// ListenUnix creates a Unix domain socket listener at socketPath.
func ListenUnix(socketPath string) (net.Listener, error) {
	_ = os.MkdirAll(filepath.Dir(socketPath), 0755)
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(socketPath, 0666) // allow unprivileged CLI access
	return l, nil
}
