package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// Node is a registered device.
type Node struct {
	ID             int64            `json:"id"`
	StableID       string           `json:"stableID"`
	NodeKey        key.Public       `json:"nodeKey"`
	DiscoKey       key.Public       `json:"discoKey"`
	UserID         int64            `json:"userID"`
	Name           string           `json:"name"`
	IPv4           netip.Addr       `json:"ipv4"`
	Hostinfo       proto.Hostinfo   `json:"hostinfo"`
	Endpoints      []netip.AddrPort `json:"endpoints"`
	HomeRelay      int              `json:"homeRelay"`
	Authorized     bool             `json:"authorized"`
	Ephemeral      bool             `json:"ephemeral"`
	Tags           []string         `json:"tags"`
	ApprovedRoutes []netip.Prefix   `json:"approvedRoutes"`
	KeyExpiry      time.Time        `json:"keyExpiry"`
	ExpiryDisabled bool             `json:"expiryDisabled"`
	LastSeen       time.Time        `json:"lastSeen"`
	AuthKeyID      int64            `json:"authKeyID,omitempty"`
	CreatedAt      time.Time        `json:"createdAt"`
}

// Expired reports whether the node key has expired.
func (n *Node) Expired() bool {
	return !n.ExpiryDisabled && !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry)
}

// IsTagged reports whether the node is owned by tags rather than a user.
func (n *Node) IsTagged() bool { return len(n.Tags) > 0 }

const nodeCols = `id,stable_id,node_key,disco_key,user_id,name,ipv4,hostinfo,endpoints,home_relay,
	authorized,ephemeral,tags,approved_routes,key_expiry,expiry_disabled,last_seen,
	COALESCE(auth_key_id,0),created_at`

func scanNode(sc interface{ Scan(...any) error }) (*Node, error) {
	var n Node
	var nk, dk, ip, hi, eps, tags, routes string
	var exp, seen, created int64
	err := sc.Scan(&n.ID, &n.StableID, &nk, &dk, &n.UserID, &n.Name, &ip, &hi, &eps, &n.HomeRelay,
		&n.Authorized, &n.Ephemeral, &tags, &routes, &exp, &n.ExpiryDisabled, &seen, &n.AuthKeyID, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.NodeKey, _ = key.ParsePublic(nk)
	if dk != "" {
		n.DiscoKey, _ = key.ParsePublic(dk)
	}
	n.IPv4, _ = netip.ParseAddr(ip)
	json.Unmarshal([]byte(hi), &n.Hostinfo)
	json.Unmarshal([]byte(eps), &n.Endpoints)
	json.Unmarshal([]byte(tags), &n.Tags)
	json.Unmarshal([]byte(routes), &n.ApprovedRoutes)
	if n.Tags == nil {
		n.Tags = []string{}
	}
	if n.ApprovedRoutes == nil {
		n.ApprovedRoutes = []netip.Prefix{}
	}
	n.KeyExpiry, n.LastSeen, n.CreatedAt = toTime(exp), toTime(seen), toTime(created)
	return &n, nil
}

// NewNode describes a node to create.
type NewNode struct {
	NodeKey    key.Public
	UserID     int64
	Hostinfo   proto.Hostinfo
	Authorized bool
	Ephemeral  bool
	Tags       []string
	KeyExpiry  time.Time
	AuthKeyID  int64
}

var nonDNS = regexp.MustCompile(`[^a-z0-9-]+`)

// SanitizeName converts a hostname into a valid DNS label.
func SanitizeName(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	h = nonDNS.ReplaceAllString(h, "-")
	h = strings.Trim(h, "-")
	if len(h) > 50 {
		h = strings.Trim(h[:50], "-")
	}
	if h == "" {
		h = "node"
	}
	return h
}

// randomCGNAT returns a random address in 100.64.0.0/10, avoiding reserved ones.
func randomCGNAT() netip.Addr {
	for {
		var b [4]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		v = 0x64400000 | (v & 0x003fffff) // 100.64.0.0/10
		binary.BigEndian.PutUint32(b[:], v)
		a := netip.AddrFrom4(b)
		if b[3] == 0 || b[3] == 255 || a == proto.MagicDNSIP {
			continue
		}
		// Keep 100.100.100.0/24 free for services.
		if b[1] == 100 && b[2] == 100 {
			continue
		}
		return a
	}
}

// CreateNode creates a node, allocating a unique IP and DNS name.
func (s *Store) CreateNode(ctx context.Context, nn NewNode) (*Node, error) {
	base := SanitizeName(nn.Hostinfo.Hostname)
	if nn.Tags == nil {
		nn.Tags = []string{}
	}
	for attempt := 0; attempt < 100; attempt++ {
		name := base
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d", base, attempt)
		}
		ip := randomCGNAT()
		res, err := s.db.ExecContext(ctx, `INSERT INTO nodes
			(stable_id,node_key,user_id,name,ipv4,hostinfo,authorized,ephemeral,tags,key_expiry,auth_key_id,created_at,last_seen)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			"n"+RandomToken(8), nn.NodeKey.String(), nn.UserID, name, ip.String(), jsonStr(nn.Hostinfo),
			b2i(nn.Authorized), b2i(nn.Ephemeral), jsonStr(nn.Tags), fromTime(nn.KeyExpiry),
			sql.NullInt64{Int64: nn.AuthKeyID, Valid: nn.AuthKeyID != 0}, now(), now())
		if isUnique(err) {
			if strings.Contains(err.Error(), "node_key") {
				return nil, ErrExists
			}
			continue // name or IP collision: retry
		}
		if err != nil {
			return nil, err
		}
		id, _ := res.LastInsertId()
		return s.GetNode(ctx, id)
	}
	return nil, errors.New("could not allocate unique name/IP")
}

// GetNode returns a node by ID.
func (s *Store) GetNode(ctx context.Context, id int64) (*Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, "SELECT "+nodeCols+" FROM nodes WHERE id=?", id))
}

// GetNodeByKey returns a node by its node key.
func (s *Store) GetNodeByKey(ctx context.Context, k key.Public) (*Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, "SELECT "+nodeCols+" FROM nodes WHERE node_key=?", k.String()))
}

// ListNodes returns nodes, optionally filtered by user (0 = all).
func (s *Store) ListNodes(ctx context.Context, userID int64) ([]*Node, error) {
	q := "SELECT " + nodeCols + " FROM nodes"
	var args []any
	if userID != 0 {
		q += " WHERE user_id=?"
		args = append(args, userID)
	}
	rows, err := s.db.QueryContext(ctx, q+" ORDER BY name", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNodeStatus records data reported by the node itself.
func (s *Store) UpdateNodeStatus(ctx context.Context, id int64, disco key.Public, eps []netip.AddrPort, homeRelay int, hi *proto.Hostinfo) error {
	if eps == nil {
		eps = []netip.AddrPort{}
	}
	if hi != nil {
		_, err := s.db.ExecContext(ctx,
			"UPDATE nodes SET disco_key=?,endpoints=?,home_relay=?,hostinfo=?,last_seen=? WHERE id=?",
			disco.String(), jsonStr(eps), homeRelay, jsonStr(hi), now(), id)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		"UPDATE nodes SET disco_key=?,endpoints=?,home_relay=?,last_seen=? WHERE id=?",
		disco.String(), jsonStr(eps), homeRelay, now(), id)
	return err
}

// UpdateNodeHostinfo stores new host info.
func (s *Store) UpdateNodeHostinfo(ctx context.Context, id int64, hi proto.Hostinfo) error {
	_, err := s.db.ExecContext(ctx, "UPDATE nodes SET hostinfo=? WHERE id=?", jsonStr(hi), id)
	return err
}

// TouchNode updates last_seen.
func (s *Store) TouchNode(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE nodes SET last_seen=? WHERE id=?", now(), id)
	return err
}

// NodeUpdate holds admin-modifiable node fields; nil fields are unchanged.
type NodeUpdate struct {
	Name           *string
	Authorized     *bool
	Tags           *[]string
	ApprovedRoutes *[]netip.Prefix
	ExpiryDisabled *bool
	KeyExpiry      *time.Time
	UserID         *int64
}

// UpdateNode applies admin changes to a node.
func (s *Store) UpdateNode(ctx context.Context, id int64, u NodeUpdate) error {
	var sets []string
	var args []any
	if u.Name != nil {
		name := SanitizeName(*u.Name)
		sets, args = append(sets, "name=?"), append(args, name)
	}
	if u.Authorized != nil {
		sets, args = append(sets, "authorized=?"), append(args, b2i(*u.Authorized))
	}
	if u.Tags != nil {
		for _, t := range *u.Tags {
			if !strings.HasPrefix(t, "tag:") {
				return fmt.Errorf("invalid tag %q", t)
			}
		}
		sets, args = append(sets, "tags=?"), append(args, jsonStr(*u.Tags))
	}
	if u.ApprovedRoutes != nil {
		sets, args = append(sets, "approved_routes=?"), append(args, jsonStr(*u.ApprovedRoutes))
	}
	if u.ExpiryDisabled != nil {
		sets, args = append(sets, "expiry_disabled=?"), append(args, b2i(*u.ExpiryDisabled))
	}
	if u.KeyExpiry != nil {
		sets, args = append(sets, "key_expiry=?"), append(args, fromTime(*u.KeyExpiry))
	}
	if u.UserID != nil {
		sets, args = append(sets, "user_id=?"), append(args, *u.UserID)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, "UPDATE nodes SET "+strings.Join(sets, ",")+" WHERE id=?", args...)
	if isUnique(err) {
		return ErrExists
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNode deletes a node.
func (s *Store) DeleteNode(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM nodes WHERE id=?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- pending interactive logins ----

// PendingLogin is an in-progress browser login for a node key.
type PendingLogin struct {
	Token     string
	NodeKey   key.Public
	Hostinfo  proto.Hostinfo
	UserID    int64 // 0 until approved
	CreatedAt time.Time
}

// CreatePendingLogin creates (or returns the existing) pending login for k.
func (s *Store) CreatePendingLogin(ctx context.Context, k key.Public, hi proto.Hostinfo) (*PendingLogin, error) {
	s.db.ExecContext(ctx, "DELETE FROM pending_logins WHERE created_at < ?", now()-3600)
	var tok string
	err := s.db.QueryRowContext(ctx, "SELECT token FROM pending_logins WHERE node_key=? AND user_id IS NULL",
		k.String()).Scan(&tok)
	if err == nil {
		return s.GetPendingLogin(ctx, tok)
	}
	tok = RandomToken(16)
	if _, err := s.db.ExecContext(ctx,
		"INSERT INTO pending_logins(token,node_key,hostinfo,created_at) VALUES(?,?,?,?)",
		tok, k.String(), jsonStr(hi), now()); err != nil {
		return nil, err
	}
	return s.GetPendingLogin(ctx, tok)
}

// GetPendingLogin returns a pending login by token.
func (s *Store) GetPendingLogin(ctx context.Context, tok string) (*PendingLogin, error) {
	var p PendingLogin
	var nk, hi string
	var uid sql.NullInt64
	var c int64
	err := s.db.QueryRowContext(ctx,
		"SELECT token,node_key,hostinfo,user_id,created_at FROM pending_logins WHERE token=?", tok).
		Scan(&p.Token, &nk, &hi, &uid, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.NodeKey, _ = key.ParsePublic(nk)
	json.Unmarshal([]byte(hi), &p.Hostinfo)
	p.UserID = uid.Int64
	p.CreatedAt = toTime(c)
	return &p, nil
}

// CompletePendingLogin marks the login as approved by userID.
func (s *Store) CompletePendingLogin(ctx context.Context, tok string, userID int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE pending_logins SET user_id=? WHERE token=?", userID, tok)
	return err
}

// DeletePendingLogin removes a pending login.
func (s *Store) DeletePendingLogin(ctx context.Context, tok string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_logins WHERE token=?", tok)
	return err
}
