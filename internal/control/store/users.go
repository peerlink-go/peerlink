package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Roles.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// User is a PeerLink user account.
type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"displayName"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"createdAt"`
	passwordHash string
}

// IsAdmin reports whether u has the admin role.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// CheckPassword reports whether pw matches the user's password.
func (u *User) CheckPassword(pw string) bool {
	if u.passwordHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(pw)) == nil
}

// ErrExists is returned on uniqueness violations.
var ErrExists = errors.New("already exists")

// CreateUser creates a user. Password must be at least 8 characters.
func (s *Store) CreateUser(ctx context.Context, email, displayName, password, role string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if !strings.Contains(email, "@") {
		return nil, errors.New("invalid email")
	}
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}
	if role != RoleAdmin && role != RoleMember {
		return nil, errors.New("invalid role")
	}
	if displayName == "" {
		displayName = strings.SplitN(email, "@", 2)[0]
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO users(email,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
		email, displayName, string(h), role, now())
	if isUnique(err) {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetUser(ctx, id)
}

const userCols = "id,email,display_name,password_hash,role,created_at"

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	var c int64
	err := sc.Scan(&u.ID, &u.Email, &u.DisplayName, &u.passwordHash, &u.Role, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = toTime(c)
	return &u, nil
}

// GetUser returns the user with the given ID.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id=?", id))
}

// GetUserByEmail returns the user with the given email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE email=?",
		strings.TrimSpace(strings.ToLower(email))))
}

// ListUsers returns all users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// UpdateUser updates mutable user fields. Empty values are left unchanged.
func (s *Store) UpdateUser(ctx context.Context, id int64, displayName, role, password string) error {
	if displayName != "" {
		if _, err := s.db.ExecContext(ctx, "UPDATE users SET display_name=? WHERE id=?", displayName, id); err != nil {
			return err
		}
	}
	if role != "" {
		if role != RoleAdmin && role != RoleMember {
			return errors.New("invalid role")
		}
		if _, err := s.db.ExecContext(ctx, "UPDATE users SET role=? WHERE id=?", role, id); err != nil {
			return err
		}
	}
	if password != "" {
		if len(password) < 8 {
			return errors.New("password must be at least 8 characters")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, "UPDATE users SET password_hash=? WHERE id=?", string(h), id); err != nil {
			return err
		}
		// Invalidate sessions on password change.
		s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", id)
	}
	return nil
}

// DeleteUser deletes a user and (via cascade) their nodes, keys and sessions.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id=?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- sessions ----

// Session is a logged-in browser session.
type Session struct {
	User     *User
	AuthTime time.Time // last time the user entered their password
	Expires  time.Time
}

// CreateSession creates a session for userID and returns the secret token.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, error) {
	tok := RandomToken(32)
	n := now()
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions(token_hash,user_id,created_at,expires_at,auth_time) VALUES(?,?,?,?,?)",
		HashToken(tok), userID, n, n+int64(ttl.Seconds()), n)
	if err != nil {
		return "", err
	}
	// Opportunistic cleanup.
	s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", n)
	return tok, nil
}

// GetSession returns the session for tok.
func (s *Store) GetSession(ctx context.Context, tok string) (*Session, error) {
	var uid, exp, at int64
	err := s.db.QueryRowContext(ctx,
		"SELECT user_id,expires_at,auth_time FROM sessions WHERE token_hash=? AND expires_at>?",
		HashToken(tok), now()).Scan(&uid, &exp, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u, err := s.GetUser(ctx, uid)
	if err != nil {
		return nil, err
	}
	return &Session{User: u, AuthTime: toTime(at), Expires: toTime(exp)}, nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(ctx context.Context, tok string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", HashToken(tok))
	return err
}

// ---- auth keys ----

// AuthKeyPrefix is prepended to all auth keys.
const AuthKeyPrefix = "plk-"

// AuthKey is a pre-authentication key for registering nodes.
type AuthKey struct {
	ID            int64     `json:"id"`
	Prefix        string    `json:"prefix"`
	UserID        int64     `json:"userID"`
	Description   string    `json:"description"`
	Reusable      bool      `json:"reusable"`
	Ephemeral     bool      `json:"ephemeral"`
	Preauthorized bool      `json:"preauthorized"`
	Tags          []string  `json:"tags"`
	UsedCount     int       `json:"usedCount"`
	Revoked       bool      `json:"revoked"`
	ExpiresAt     time.Time `json:"expiresAt"`
	CreatedAt     time.Time `json:"createdAt"`
}

// Valid reports whether the key can currently be used.
func (k *AuthKey) Valid() error {
	switch {
	case k.Revoked:
		return errors.New("auth key revoked")
	case time.Now().After(k.ExpiresAt):
		return errors.New("auth key expired")
	case !k.Reusable && k.UsedCount > 0:
		return errors.New("auth key already used")
	}
	return nil
}

// AuthKeyOptions configures a new auth key.
type AuthKeyOptions struct {
	UserID        int64
	Description   string
	Reusable      bool
	Ephemeral     bool
	Preauthorized bool
	Tags          []string
	Expiry        time.Duration
}

// CreateAuthKey creates an auth key and returns its secret value (shown once).
func (s *Store) CreateAuthKey(ctx context.Context, o AuthKeyOptions) (string, *AuthKey, error) {
	if o.Expiry <= 0 {
		o.Expiry = 90 * 24 * time.Hour
	}
	if o.Tags == nil {
		o.Tags = []string{}
	}
	for _, t := range o.Tags {
		if !strings.HasPrefix(t, "tag:") {
			return "", nil, fmt.Errorf("invalid tag %q (must start with tag:)", t)
		}
	}
	secret := AuthKeyPrefix + RandomToken(24)
	prefix := secret[:len(AuthKeyPrefix)+8]
	n := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO auth_keys
		(key_hash,prefix,user_id,description,reusable,ephemeral,preauthorized,tags,expires_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		HashToken(secret), prefix, o.UserID, o.Description, b2i(o.Reusable), b2i(o.Ephemeral),
		b2i(o.Preauthorized), jsonStr(o.Tags), n+int64(o.Expiry.Seconds()), n)
	if err != nil {
		return "", nil, err
	}
	id, _ := res.LastInsertId()
	k, err := s.GetAuthKey(ctx, id)
	return secret, k, err
}

const authKeyCols = "id,prefix,user_id,description,reusable,ephemeral,preauthorized,tags,used_count,revoked,expires_at,created_at"

func scanAuthKey(sc interface{ Scan(...any) error }) (*AuthKey, error) {
	var k AuthKey
	var tags string
	var exp, c int64
	err := sc.Scan(&k.ID, &k.Prefix, &k.UserID, &k.Description, &k.Reusable, &k.Ephemeral,
		&k.Preauthorized, &tags, &k.UsedCount, &k.Revoked, &exp, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(tags), &k.Tags)
	k.ExpiresAt, k.CreatedAt = toTime(exp), toTime(c)
	return &k, nil
}

// GetAuthKey returns an auth key by ID.
func (s *Store) GetAuthKey(ctx context.Context, id int64) (*AuthKey, error) {
	return scanAuthKey(s.db.QueryRowContext(ctx, "SELECT "+authKeyCols+" FROM auth_keys WHERE id=?", id))
}

// LookupAuthKey returns the auth key matching the secret value.
func (s *Store) LookupAuthKey(ctx context.Context, secret string) (*AuthKey, error) {
	return scanAuthKey(s.db.QueryRowContext(ctx,
		"SELECT "+authKeyCols+" FROM auth_keys WHERE key_hash=?", HashToken(strings.TrimSpace(secret))))
}

// ListAuthKeys returns auth keys, optionally filtered by user (0 = all).
func (s *Store) ListAuthKeys(ctx context.Context, userID int64) ([]*AuthKey, error) {
	q := "SELECT " + authKeyCols + " FROM auth_keys"
	var args []any
	if userID != 0 {
		q += " WHERE user_id=?"
		args = append(args, userID)
	}
	rows, err := s.db.QueryContext(ctx, q+" ORDER BY id DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuthKey{}
	for rows.Next() {
		k, err := scanAuthKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAuthKey revokes an auth key.
func (s *Store) RevokeAuthKey(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "UPDATE auth_keys SET revoked=1 WHERE id=?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UseAuthKey atomically increments the usage count if the key is still valid.
func (s *Store) UseAuthKey(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_keys SET used_count=used_count+1
		WHERE id=? AND revoked=0 AND expires_at>? AND (reusable=1 OR used_count=0)`, id, now())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("auth key no longer valid")
	}
	return nil
}
