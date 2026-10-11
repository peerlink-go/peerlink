package control

import (
	_ "embed"
	"net/http"
)

//go:embed admin.html
var adminHTML []byte

func (s *Server) handleEmbeddedAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(adminHTML)
}
