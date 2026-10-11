package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/peerlink-go/peerlink/internal/acl"
	"github.com/peerlink-go/peerlink/internal/control/store"
	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	nodeKey, body, err := s.verifier.Verify(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req proto.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	resp, err := s.register(r.Context(), nodeKey, &req)
	if err != nil {
		writeJSON(w, http.StatusOK, proto.RegisterResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) register(ctx context.Context, nodeKey key.Public, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	existing, err := s.store.GetNodeByKey(ctx, nodeKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if req.Logout {
		if existing == nil {
			return &proto.RegisterResponse{NodeKeyExpired: true}, nil
		}
		if existing.Ephemeral {
			s.store.DeleteNode(ctx, existing.ID)
		} else {
			t := time.Now()
			f := false
			s.store.UpdateNode(ctx, existing.ID, store.NodeUpdate{KeyExpiry: &t, ExpiryDisabled: &f})
		}
		s.logf("node %s logged out", existing.Name)
		s.notify.notify()
		return &proto.RegisterResponse{NodeKeyExpired: true}, nil
	}

	// Already registered and valid.
	if existing != nil && !existing.Expired() && req.AuthKey == "" && req.Followup == "" {
		s.updateHostinfo(ctx, existing, &req.Hostinfo)
		return s.registerResponse(ctx, existing)
	}

	// Pre-auth key.
	if req.AuthKey != "" {
		ak, err := s.store.LookupAuthKey(ctx, req.AuthKey)
		if err != nil {
			return nil, errors.New("invalid auth key")
		}
		if err := ak.Valid(); err != nil {
			return nil, err
		}
		if existing != nil {
			// Re-authenticating an expired node.
			if existing.UserID != ak.UserID {
				return nil, errors.New("auth key belongs to a different user")
			}
			if err := s.store.UseAuthKey(ctx, ak.ID); err != nil {
				return nil, err
			}
			s.renewNode(ctx, existing, ak.Preauthorized)
			n, _ := s.store.GetNode(ctx, existing.ID)
			return s.registerResponse(ctx, n)
		}
		if err := s.store.UseAuthKey(ctx, ak.ID); err != nil {
			return nil, err
		}
		n, err := s.createNode(ctx, nodeKey, ak.UserID, req.Hostinfo, ak.Tags, ak.Ephemeral,
			ak.Preauthorized || !s.cfg.RequireApproval, ak.ID)
		if err != nil {
			return nil, err
		}
		return s.registerResponse(ctx, n)
	}

	// Interactive login.
	if req.Followup != "" {
		tok := tokenFromAuthURL(req.Followup)
		deadline := time.Now().Add(2 * time.Minute)
		for {
			pl, err := s.store.GetPendingLogin(ctx, tok)
			if err != nil || pl.NodeKey != nodeKey {
				return nil, errors.New("login expired, please retry")
			}
			if pl.UserID != 0 {
				s.store.DeletePendingLogin(ctx, tok)
				if existing != nil {
					if existing.UserID != pl.UserID {
						return nil, errors.New("node belongs to a different user")
					}
					s.renewNode(ctx, existing, false)
					n, _ := s.store.GetNode(ctx, existing.ID)
					return s.registerResponse(ctx, n)
				}
				n, err := s.createNode(ctx, nodeKey, pl.UserID, req.Hostinfo, nil, false, !s.cfg.RequireApproval, 0)
				if err != nil {
					return nil, err
				}
				return s.registerResponse(ctx, n)
			}
			if time.Now().After(deadline) {
				return &proto.RegisterResponse{AuthURL: req.Followup}, nil
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}

	pl, err := s.store.CreatePendingLogin(ctx, nodeKey, req.Hostinfo)
	if err != nil {
		return nil, err
	}
	resp := &proto.RegisterResponse{AuthURL: s.cfg.ServerURL + "/register/" + pl.Token}
	if existing != nil {
		resp.NodeKeyExpired = existing.Expired()
	}
	return resp, nil
}

func tokenFromAuthURL(u string) string {
	for i := len(u) - 1; i >= 0; i-- {
		if u[i] == '/' {
			return u[i+1:]
		}
	}
	return u
}

func (s *Server) createNode(ctx context.Context, nodeKey key.Public, userID int64, hi proto.Hostinfo,
	tags []string, ephemeral, authorized bool, authKeyID int64) (*store.Node, error) {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	pol := s.policy.Load()
	// Tags requested by the node itself must be owned by the user.
	for _, t := range hi.RequestTags {
		if pol.CanOwnTag(u.Email, u.IsAdmin(), t) && !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	var expiry time.Time
	if len(tags) == 0 {
		expiry = time.Now().Add(s.cfg.NodeKeyExpiry)
	}
	n, err := s.store.CreateNode(ctx, store.NewNode{
		NodeKey: nodeKey, UserID: userID, Hostinfo: hi, Authorized: authorized,
		Ephemeral: ephemeral, Tags: tags, KeyExpiry: expiry, AuthKeyID: authKeyID,
	})
	if err != nil {
		return nil, err
	}
	s.autoApproveRoutes(ctx, n, u)
	s.logf("registered node %s (%s) for %s authorized=%v", n.Name, n.IPv4, u.Email, n.Authorized)
	s.store.Audit(ctx, u.Email, "node.register", n.Name, n.IPv4.String())
	s.notify.notify()
	return s.store.GetNode(ctx, n.ID)
}

func (s *Server) renewNode(ctx context.Context, n *store.Node, authorize bool) {
	var u store.NodeUpdate
	exp := time.Time{}
	if !n.IsTagged() {
		exp = time.Now().Add(s.cfg.NodeKeyExpiry)
	}
	u.KeyExpiry = &exp
	if authorize {
		u.Authorized = &authorize
	}
	s.store.UpdateNode(ctx, n.ID, u)
	s.notify.notify()
}

func (s *Server) registerResponse(ctx context.Context, n *store.Node) (*proto.RegisterResponse, error) {
	u, err := s.store.GetUser(ctx, n.UserID)
	if err != nil {
		return nil, err
	}
	return &proto.RegisterResponse{
		NodeID:         n.ID,
		User:           proto.UserProfile{ID: u.ID, LoginName: u.Email, DisplayName: u.DisplayName},
		Authorized:     n.Authorized,
		NodeKeyExpired: n.Expired(),
	}, nil
}

// updateHostinfo stores new host info if it changed. Returns true if changed.
func (s *Server) updateHostinfo(ctx context.Context, n *store.Node, hi *proto.Hostinfo) bool {
	if hi == nil {
		return false
	}
	a, _ := json.Marshal(n.Hostinfo)
	b, _ := json.Marshal(hi)
	if bytes.Equal(a, b) {
		return false
	}
	s.store.UpdateNodeHostinfo(ctx, n.ID, *hi)
	n.Hostinfo = *hi
	if u, err := s.store.GetUser(ctx, n.UserID); err == nil {
		s.autoApproveRoutes(ctx, n, u)
	}
	s.notify.notify()
	return true
}

func (s *Server) autoApproveRoutes(ctx context.Context, n *store.Node, u *store.User) {
	pol := s.policy.Load()
	ni := &acl.NodeInfo{ID: n.ID, IP: n.IPv4, UserID: n.UserID, UserEmail: u.Email, UserIsAdmin: u.IsAdmin(), Tags: n.Tags}
	approved := slices.Clone(n.ApprovedRoutes)
	changed := false
	for _, r := range n.Hostinfo.RoutableIPs {
		if !slices.Contains(approved, r) && pol.AutoApproved(ni, r) {
			approved = append(approved, r)
			changed = true
		}
	}
	if changed {
		s.store.UpdateNode(ctx, n.ID, store.NodeUpdate{ApprovedRoutes: &approved})
		n.ApprovedRoutes = approved
	}
}

// ---- map ----

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	nodeKey, body, err := s.verifier.Verify(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req proto.MapRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ctx := r.Context()
	n, err := s.store.GetNodeByKey(ctx, nodeKey)
	if err != nil {
		writeErr(w, http.StatusForbidden, "node not registered")
		return
	}
	if n.Expired() {
		writeErr(w, http.StatusForbidden, "node key expired")
		return
	}

	// Record status reported by the node.
	statusChanged := n.DiscoKey != req.DiscoKey || n.HomeRelay != req.HomeRelay ||
		!slices.Equal(n.Endpoints, req.Endpoints)
	if req.Hostinfo != nil && s.updateHostinfo(ctx, n, req.Hostinfo) {
		statusChanged = true
	}
	if err := s.store.UpdateNodeStatus(ctx, n.ID, req.DiscoKey, req.Endpoints, req.HomeRelay, nil); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if statusChanged {
		s.notify.notify()
	}

	if !req.Stream {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	s.setOnline(n.ID, 1)
	defer func() {
		s.setOnline(n.ID, -1)
		s.store.TouchNode(context.Background(), n.ID)
	}()

	enc := json.NewEncoder(w)
	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()
	touch := time.NewTicker(2 * time.Minute)
	defer touch.Stop()

	var lastSent []byte
	for {
		changed := s.notify.wait()
		self, err := s.store.GetNodeByKey(ctx, nodeKey)
		if err != nil {
			return // node deleted
		}
		mr, err := s.buildMap(ctx, self)
		if err != nil {
			s.logf("buildMap(%s): %v", self.Name, err)
			return
		}
		// Only send when something other than the timestamp changed.
		mr.ControlTime = time.Time{}
		cur, _ := json.Marshal(mr)
		if !bytes.Equal(cur, lastSent) {
			mr.ControlTime = time.Now().UTC()
			if err := enc.Encode(mr); err != nil {
				return
			}
			flusher.Flush()
			lastSent = cur
		}
		if self.Expired() {
			return
		}
	wait:
		select {
		case <-ctx.Done():
			return
		case <-changed:
			// Coalesce bursts of changes.
			time.Sleep(50 * time.Millisecond)
		case <-touch.C:
			s.store.TouchNode(ctx, n.ID)
			goto wait
		case <-keepAlive.C:
			if err := enc.Encode(proto.MapResponse{KeepAlive: true}); err != nil {
				return
			}
			flusher.Flush()
			goto wait
		}
	}
}

// buildMap computes the netmap for self.
func (s *Server) buildMap(ctx context.Context, self *store.Node) (*proto.MapResponse, error) {
	nodes, err := s.store.ListNodes(ctx, 0)
	if err != nil {
		return nil, err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	userByID := map[int64]*store.User{}
	for _, u := range users {
		userByID[u.ID] = u
	}

	// Only authorized, unexpired nodes participate.
	active := map[int64]*store.Node{}
	for _, n := range nodes {
		if n.Authorized && !n.Expired() {
			active[n.ID] = n
		}
	}
	primary := s.primaryRoutes(nodes, active)

	var infos []*acl.NodeInfo
	infoByID := map[int64]*acl.NodeInfo{}
	for _, n := range nodes {
		if active[n.ID] == nil {
			continue
		}
		u := userByID[n.UserID]
		ni := &acl.NodeInfo{ID: n.ID, IP: n.IPv4, UserID: n.UserID, Tags: n.Tags, Routes: primary[n.ID]}
		if u != nil {
			ni.UserEmail, ni.UserIsAdmin = u.Email, u.IsAdmin()
		}
		infos = append(infos, ni)
		infoByID[n.ID] = ni
	}

	mr := &proto.MapResponse{
		Domain:       s.cfg.Domain,
		RelayMap:     s.cfg.RelayMap,
		DNS:          s.dnsConfig(ctx),
		Peers:        []proto.Node{},
		PacketFilter: []proto.FilterRule{},
	}
	selfAllowed := []netip.Prefix{netip.PrefixFrom(self.IPv4, 32)}
	selfNode := s.toProtoNode(self, selfAllowed, primary[self.ID])
	mr.Node = &selfNode

	profiles := map[int64]bool{self.UserID: true}
	if si := infoByID[self.ID]; si != nil {
		res := s.policy.Load().Compile(si, infos, s.cfg.ServerURL+proto.PathSSHCheck)
		mr.PacketFilter = res.Filter
		mr.SSHPolicy = res.SSH
		for _, n := range nodes {
			if allowed, ok := res.Peers[n.ID]; ok {
				mr.Peers = append(mr.Peers, s.toProtoNode(n, allowed, primary[n.ID]))
				profiles[n.UserID] = true
			}
		}
	}
	for id := range profiles {
		if u := userByID[id]; u != nil {
			mr.UserProfiles = append(mr.UserProfiles, proto.UserProfile{ID: u.ID, LoginName: u.Email, DisplayName: u.DisplayName})
		}
	}
	slices.SortFunc(mr.UserProfiles, func(a, b proto.UserProfile) int { return int(a.ID - b.ID) })
	return mr, nil
}

// primaryRoutes returns, per node, the approved advertised routes it serves.
// Exit routes are served by every approved exit node; each subnet route is
// served by a single primary router (online preferred, then lowest ID).
func (s *Server) primaryRoutes(all []*store.Node, active map[int64]*store.Node) map[int64][]netip.Prefix {
	out := map[int64][]netip.Prefix{}
	best := map[netip.Prefix]*store.Node{}
	for _, n := range all {
		if active[n.ID] == nil {
			continue
		}
		for _, r := range n.ApprovedRoutes {
			if !slices.Contains(n.Hostinfo.RoutableIPs, r) {
				continue // approved but no longer advertised
			}
			if r.Bits() == 0 {
				out[n.ID] = append(out[n.ID], r)
				continue
			}
			cur := best[r]
			if cur == nil || (!s.isOnline(cur.ID) && s.isOnline(n.ID)) {
				best[r] = n
			}
		}
	}
	for r, n := range best {
		out[n.ID] = append(out[n.ID], r)
	}
	for id := range out {
		slices.SortFunc(out[id], func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	}
	return out
}

func (s *Server) toProtoNode(n *store.Node, allowed, primary []netip.Prefix) proto.Node {
	pn := proto.Node{
		ID:            n.ID,
		StableID:      n.StableID,
		Name:          fmt.Sprintf("%s.%s.", n.Name, s.cfg.Domain),
		User:          n.UserID,
		Key:           n.NodeKey,
		KeyExpiry:     n.KeyExpiry,
		DiscoKey:      n.DiscoKey,
		Addresses:     []netip.Prefix{netip.PrefixFrom(n.IPv4, 32)},
		AllowedIPs:    allowed,
		Endpoints:     n.Endpoints,
		HomeRelay:     n.HomeRelay,
		Hostinfo:      n.Hostinfo,
		Online:        s.isOnline(n.ID),
		Authorized:    n.Authorized,
		Expired:       n.Expired(),
		Tags:          n.Tags,
		PrimaryRoutes: primary,
	}
	if n.ExpiryDisabled {
		pn.KeyExpiry = time.Time{}
	}
	if !n.LastSeen.IsZero() {
		t := n.LastSeen.UTC()
		pn.LastSeen = &t
	}
	return pn
}

func (s *Server) dnsConfig(ctx context.Context) *proto.DNSConfig {
	cfg := &proto.DNSConfig{MagicDNS: true}
	if v, _ := s.store.GetSetting(ctx, settingDNS); v != "" {
		json.Unmarshal([]byte(v), cfg)
	}
	cfg.Domain = s.cfg.Domain
	return cfg
}
