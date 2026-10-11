package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/peerlink-go/peerlink/internal/control/store"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// handleSSHCheck handles node checks when policy action is "check".
// The node queries this endpoint when someone tries to SSH.
func (s *Server) handleSSHCheck(w http.ResponseWriter, r *http.Request) {
	nodeKey, body, err := s.verifier.Verify(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx := r.Context()
	dstNode, err := s.store.GetNodeByKey(ctx, nodeKey)
	if err != nil {
		writeErr(w, http.StatusForbidden, "node not registered")
		return
	}

	var req proto.SSHCheckRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	srcNode, err := s.store.GetNode(ctx, req.SrcNodeID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid src node")
		return
	}

	// Create pending check record
	checkID := store.RandomToken(16)
	ch := make(chan bool, 1)

	s.sshMu.Lock()
	s.sshChecks[checkID] = ch
	s.sshMu.Unlock()

	defer func() {
		s.sshMu.Lock()
		delete(s.sshChecks, checkID)
		s.sshMu.Unlock()
	}()

	authURL := fmt.Sprintf("%s/ssh/check/%s", s.cfg.ServerURL, checkID)

	// In check mode: we can return the authURL immediately to the node,
	// or wait up to 10 seconds if long-polling, or let the node prompt the user.
	// Tailscale SSH returns an action with HoldAndDelegate or returns the challenge.
	select {
	case approved := <-ch:
		if approved {
			writeJSON(w, http.StatusOK, proto.SSHCheckResponse{
				Action: &proto.SSHAction{
					Accept:                   true,
					AllowAgentForwarding:     true,
					AllowLocalPortForwarding: true,
					AllowRemotePortForwarding: true,
				},
			})
			return
		}
		writeJSON(w, http.StatusOK, proto.SSHCheckResponse{
			Action: &proto.SSHAction{Reject: true, Message: "SSH bağlantısı onaylanmadı"},
		})
	case <-time.After(2 * time.Second):
		// If not approved yet, return AuthURL so the client can display it to user
		writeJSON(w, http.StatusOK, proto.SSHCheckResponse{
			AuthURL: authURL,
		})
	case <-ctx.Done():
		return
	}
	_ = srcNode
	_ = dstNode
}

// handleSSHAudit logs SSH connection attempts reported by peerlinkd.
func (s *Server) handleSSHAudit(w http.ResponseWriter, r *http.Request) {
	nodeKey, body, err := s.verifier.Verify(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx := r.Context()
	dstNode, err := s.store.GetNodeByKey(ctx, nodeKey)
	if err != nil {
		writeErr(w, http.StatusForbidden, "node not registered")
		return
	}

	var ev proto.SSHAuditEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	s.logf("SSH event on %s: src=%s sshUser=%s localUser=%s accepted=%v reason=%s",
		dstNode.Name, ev.SrcIP, ev.SSHUser, ev.LocalUser, ev.Accepted, ev.Reason)

	// Save to DB audit
	detail := fmt.Sprintf("src=%s user=%s->%s accepted=%v", ev.SrcIP, ev.SSHUser, ev.LocalUser, ev.Accepted)
	s.store.Audit(ctx, "ssh", "ssh.connect", dstNode.Name, detail)

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleSSHRecording accepts session recordings uploaded by destination nodes.
func (s *Server) handleSSHRecording(w http.ResponseWriter, r *http.Request) {
	nodeKey, _, err := s.verifier.Verify(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx := r.Context()
	dstNode, err := s.store.GetNodeByKey(ctx, nodeKey)
	if err != nil {
		writeErr(w, http.StatusForbidden, "node not registered")
		return
	}

	if s.cfg.RecordingDir == "" {
		writeErr(w, http.StatusNotImplemented, "recording storage disabled")
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeErr(w, http.StatusBadRequest, "missing session query parameter")
		return
	}

	_ = os.MkdirAll(s.cfg.RecordingDir, 0700)
	destPath := filepath.Join(s.cfg.RecordingDir, filepath.Clean(sessionID)+".cast")
	f, err := os.Create(destPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save recording")
		return
	}
	defer f.Close()

	if _, err := io.Copy(f, r.Body); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to write stream")
		return
	}

	s.store.Audit(ctx, "ssh", "ssh.recording_saved", dstNode.Name, sessionID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
