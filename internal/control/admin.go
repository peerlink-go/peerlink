package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/peerlink-go/peerlink/internal/acl"
	"github.com/peerlink-go/peerlink/internal/control/store"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// Session cookie name.
const sessionCookieName = "peerlink_session"

func (s *Server) registerAdmin(mux *http.ServeMux) {
	// Public auth endpoints
	mux.HandleFunc("POST /api/auth/login", s.handleAPILogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAPILogout)
	mux.HandleFunc("GET /api/auth/me", s.handleAPIMe)

	// Interactive device registration approval page helper
	mux.HandleFunc("GET /register/{token}", s.handleWebRegisterPage)
	mux.HandleFunc("POST /api/register/{token}/approve", s.handleApprovePendingLogin)

	// Users API
	mux.HandleFunc("GET /api/users", s.requireAdmin(s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.requireAdmin(s.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", s.requireAdmin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.handleDeleteUser))

	// Auth Keys API
	mux.HandleFunc("GET /api/auth-keys", s.requireAuth(s.handleListAuthKeys))
	mux.HandleFunc("POST /api/auth-keys", s.requireAuth(s.handleCreateAuthKey))
	mux.HandleFunc("DELETE /api/auth-keys/{id}", s.requireAuth(s.handleRevokeAuthKey))

	// Nodes API
	mux.HandleFunc("GET /api/nodes", s.requireAuth(s.handleListNodes))
	mux.HandleFunc("GET /api/nodes/{id}", s.requireAuth(s.handleGetNode))
	mux.HandleFunc("PATCH /api/nodes/{id}", s.requireAuth(s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.requireAuth(s.handleDeleteNode))

	// ACL / Policy API
	mux.HandleFunc("GET /api/policy", s.requireAdmin(s.handleGetPolicy))
	mux.HandleFunc("PUT /api/policy", s.requireAdmin(s.handlePutPolicy))

	// Audit & Settings API
	mux.HandleFunc("GET /api/audit", s.requireAdmin(s.handleListAudit))
	mux.HandleFunc("GET /api/dns", s.requireAdmin(s.handleGetDNS))
	mux.HandleFunc("PUT /api/dns", s.requireAdmin(s.handlePutDNS))
}

// ---- Context & Auth Helpers ----

type contextKey string

const userCtxKey = contextKey("user")

func (s *Server) currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(userCtxKey).(*store.User)
	return u
}

func (s *Server) authenticateRequest(r *http.Request) (*store.User, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, store.ErrNotFound
	}
	sess, err := s.store.GetSession(r.Context(), c.Value)
	if err != nil {
		return nil, err
	}
	return sess.User, nil
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.authenticateRequest(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, u)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.authenticateRequest(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !u.IsAdmin() {
			writeErr(w, http.StatusForbidden, "forbidden: admin required")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, u)
		next(w, r.WithContext(ctx))
	}
}

// ---- Auth Handlers ----

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	u, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil || !u.CheckPassword(req.Password) {
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	tok, err := s.store.CreateSession(r.Context(), u.ID, 30*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * 24 * time.Hour).Seconds()),
	}
	http.SetCookie(w, cookie)
	s.store.Audit(r.Context(), u.Email, "auth.login", "", "")
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		s.store.DeleteSession(r.Context(), c.Value)
	}
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAPIMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.authenticateRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

// ---- Device Interactive Login Handlers ----

func (s *Server) handleWebRegisterPage(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	pl, err := s.store.GetPendingLogin(r.Context(), tok)
	if err != nil {
		http.Error(w, "Geçersiz veya süresi dolmuş kayıt bağlantısı.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PeerLink Cihaz Onayı</title><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family: sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; line-height: 1.5;">
<h2>PeerLink Cihaz Kaydı</h2>
<p>Cihaz adı: <strong>%s</strong> (OS: %s)</p>
<p>Public Key: <code>%s</code></p>
<button onclick="approve()" style="padding: 10px 20px; background: #0066cc; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Bu Cihazı Hesabıma Ekle</button>
<div id="status" style="margin-top: 15px;"></div>
<script>
function approve() {
	document.getElementById('status').innerText = 'Onaylanıyor...';
	fetch('/api/register/%s/approve', {method: 'POST'})
		.then(r => r.json())
		.then(data => {
			if(data.error) { document.getElementById('status').innerText = 'Hata: ' + data.error; }
			else { document.getElementById('status').innerHTML = '<span style="color: green;">Cihaz başarıyla bağlandı! Bu sekmeyi kapatabilirsiniz.</span>'; }
		}).catch(e => { document.getElementById('status').innerText = 'Hata oluştu.'; });
}
</script>
</body>
</html>`, pl.Hostinfo.Hostname, pl.Hostinfo.OS, pl.NodeKey.ShortString(), tok)
}

func (s *Server) handleApprovePendingLogin(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	u, err := s.authenticateRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Lütfen önce admin paneline giriş yapın")
		return
	}
	if err := s.store.CompletePendingLogin(r.Context(), tok, u.ID); err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), u.Email, "node.approve_interactive", tok, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- Users Handlers ----

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

type createUserReq struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Role == "" {
		req.Role = store.RoleMember
	}
	u, err := s.store.CreateUser(r.Context(), req.Email, req.DisplayName, req.Password, req.Role)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), s.currentUser(r).Email, "user.create", u.Email, u.Role)
	writeJSON(w, http.StatusCreated, map[string]any{"user": u})
}

type updateUserReq struct {
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Password    string `json:"password"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req updateUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.store.UpdateUser(r.Context(), id, req.DisplayName, req.Role, req.Password); err != nil {
		storeErr(w, err)
		return
	}
	u, _ := s.store.GetUser(r.Context(), id)
	s.store.Audit(r.Context(), s.currentUser(r).Email, "user.update", u.Email, "")
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	cur := s.currentUser(r)
	if cur.ID == id {
		writeErr(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), cur.Email, "user.delete", u.Email, "")
	s.notify.notify()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- Auth Keys Handlers ----

func (s *Server) handleListAuthKeys(w http.ResponseWriter, r *http.Request) {
	cur := s.currentUser(r)
	uid := cur.ID
	if cur.IsAdmin() {
		uid = 0 // admin can see all
	}
	keys, err := s.store.ListAuthKeys(r.Context(), uid)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

type createAuthKeyReq struct {
	UserID        int64    `json:"userID"`
	Description   string   `json:"description"`
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags"`
	ExpiryDays    int      `json:"expiryDays"`
}

func (s *Server) handleCreateAuthKey(w http.ResponseWriter, r *http.Request) {
	var req createAuthKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	cur := s.currentUser(r)
	targetUID := cur.ID
	if cur.IsAdmin() && req.UserID != 0 {
		targetUID = req.UserID
	}
	exp := 90 * 24 * time.Hour
	if req.ExpiryDays > 0 {
		exp = time.Duration(req.ExpiryDays) * 24 * time.Hour
	}
	secret, k, err := s.store.CreateAuthKey(r.Context(), store.AuthKeyOptions{
		UserID:        targetUID,
		Description:   req.Description,
		Reusable:      req.Reusable,
		Ephemeral:     req.Ephemeral,
		Preauthorized: req.Preauthorized,
		Tags:          req.Tags,
		Expiry:        exp,
	})
	if err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), cur.Email, "auth_key.create", k.Prefix, "")
	writeJSON(w, http.StatusCreated, map[string]any{"key": k, "secret": secret})
}

func (s *Server) handleRevokeAuthKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	k, err := s.store.GetAuthKey(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return
	}
	cur := s.currentUser(r)
	if !cur.IsAdmin() && k.UserID != cur.ID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.store.RevokeAuthKey(r.Context(), id); err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), cur.Email, "auth_key.revoke", k.Prefix, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- Nodes Handlers ----

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	cur := s.currentUser(r)
	uid := cur.ID
	if cur.IsAdmin() {
		uid = 0
	}
	nodes, err := s.store.ListNodes(r.Context(), uid)
	if err != nil {
		storeErr(w, err)
		return
	}
	// Enrich with online state
	type nodeResp struct {
		*store.Node
		Online bool `json:"online"`
	}
	res := make([]nodeResp, len(nodes))
	for i, n := range nodes {
		res[i] = nodeResp{Node: n, Online: s.isOnline(n.ID)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": res})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return
	}
	cur := s.currentUser(r)
	if !cur.IsAdmin() && n.UserID != cur.ID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": n, "online": s.isOnline(n.ID)})
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return
	}
	cur := s.currentUser(r)
	if !cur.IsAdmin() && n.UserID != cur.ID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var u store.NodeUpdate
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Non-admin can only change Name
	if !cur.IsAdmin() {
		u.Authorized = nil
		u.Tags = nil
		u.ApprovedRoutes = nil
		u.ExpiryDisabled = nil
		u.UserID = nil
	}
	if err := s.store.UpdateNode(r.Context(), id, u); err != nil {
		storeErr(w, err)
		return
	}
	updated, _ := s.store.GetNode(r.Context(), id)
	s.store.Audit(r.Context(), cur.Email, "node.update", updated.Name, "")
	s.notify.notify()
	writeJSON(w, http.StatusOK, map[string]any{"node": updated})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return
	}
	cur := s.currentUser(r)
	if !cur.IsAdmin() && n.UserID != cur.ID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), cur.Email, "node.delete", n.Name, "")
	s.notify.notify()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- Policy & Settings Handlers ----

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	text, err := s.store.GetSetting(r.Context(), settingPolicy)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"hujson": text})
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HuJSON string `json:"hujson"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	newPol, err := acl.Parse([]byte(req.HuJSON))
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid policy: %v", err))
		return
	}
	if err := s.store.SetSetting(r.Context(), settingPolicy, req.HuJSON); err != nil {
		storeErr(w, err)
		return
	}
	s.policy.Store(newPol)
	s.store.Audit(r.Context(), s.currentUser(r).Email, "policy.update", "", "")
	s.notify.notify()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	cfg := s.dnsConfig(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"dns": cfg})
}

func (s *Server) handlePutDNS(w http.ResponseWriter, r *http.Request) {
	var cfg proto.DNSConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b, _ := json.Marshal(cfg)
	if err := s.store.SetSetting(r.Context(), settingDNS, string(b)); err != nil {
		storeErr(w, err)
		return
	}
	s.store.Audit(r.Context(), s.currentUser(r).Email, "dns.update", "", "")
	s.notify.notify()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
