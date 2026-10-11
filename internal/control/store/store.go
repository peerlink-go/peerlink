// Package store implements persistent storage for peerlink-control on SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Store is the control server database.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	// 1: initial schema
	`
CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
	display_name  TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL DEFAULT '',
	role          TEXT NOT NULL DEFAULT 'member',
	created_at    INTEGER NOT NULL
);
CREATE TABLE sessions (
	token_hash  TEXT PRIMARY KEY,
	user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	auth_time   INTEGER NOT NULL
);
CREATE TABLE auth_keys (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash      TEXT NOT NULL UNIQUE,
	prefix        TEXT NOT NULL,
	user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	description   TEXT NOT NULL DEFAULT '',
	reusable      INTEGER NOT NULL DEFAULT 0,
	ephemeral     INTEGER NOT NULL DEFAULT 0,
	preauthorized INTEGER NOT NULL DEFAULT 0,
	tags          TEXT NOT NULL DEFAULT '[]',
	used_count    INTEGER NOT NULL DEFAULT 0,
	revoked       INTEGER NOT NULL DEFAULT 0,
	expires_at    INTEGER NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE TABLE nodes (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	stable_id        TEXT NOT NULL UNIQUE,
	node_key         TEXT NOT NULL UNIQUE,
	disco_key        TEXT NOT NULL DEFAULT '',
	user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name             TEXT NOT NULL UNIQUE,
	ipv4             TEXT NOT NULL UNIQUE,
	hostinfo         TEXT NOT NULL DEFAULT '{}',
	endpoints        TEXT NOT NULL DEFAULT '[]',
	home_relay       INTEGER NOT NULL DEFAULT 0,
	authorized       INTEGER NOT NULL DEFAULT 0,
	ephemeral        INTEGER NOT NULL DEFAULT 0,
	tags             TEXT NOT NULL DEFAULT '[]',
	approved_routes  TEXT NOT NULL DEFAULT '[]',
	key_expiry       INTEGER NOT NULL DEFAULT 0,
	expiry_disabled  INTEGER NOT NULL DEFAULT 0,
	last_seen        INTEGER NOT NULL DEFAULT 0,
	auth_key_id      INTEGER,
	created_at       INTEGER NOT NULL
);
CREATE TABLE pending_logins (
	token       TEXT PRIMARY KEY,
	node_key    TEXT NOT NULL,
	hostinfo    TEXT NOT NULL DEFAULT '{}',
	user_id     INTEGER,
	created_at  INTEGER NOT NULL
);
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE audit_log (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	time     INTEGER NOT NULL,
	actor    TEXT NOT NULL,
	action   TEXT NOT NULL,
	target   TEXT NOT NULL DEFAULT '',
	details  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_time ON audit_log(time);
`,
	// 2: SSH
	`
CREATE TABLE ssh_checks (
	id          TEXT PRIMARY KEY,
	src_node_id INTEGER NOT NULL,
	dst_node_id INTEGER NOT NULL,
	user_id     INTEGER NOT NULL,
	ssh_user    TEXT NOT NULL,
	local_user  TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'pending',
	created_at  INTEGER NOT NULL
);
CREATE TABLE ssh_events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	time        INTEGER NOT NULL,
	src_node_id INTEGER NOT NULL,
	dst_node_id INTEGER NOT NULL,
	src_ip      TEXT NOT NULL,
	ssh_user    TEXT NOT NULL,
	local_user  TEXT NOT NULL,
	accepted    INTEGER NOT NULL,
	reason      TEXT NOT NULL DEFAULT '',
	session_id  TEXT NOT NULL DEFAULT '',
	command     TEXT NOT NULL DEFAULT '',
	ended       INTEGER NOT NULL DEFAULT 0,
	recording   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ssh_events_time ON ssh_events(time);
`,
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- helpers ----

func now() int64 { return time.Now().Unix() }

func toTime(u int64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0)
}

func fromTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// RandomToken returns a random hex token of n bytes.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// HashToken returns the SHA-256 hex digest of tok.
func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// ---- settings ----

// GetSetting returns the value for k, or "" if unset.
func (s *Store) GetSetting(ctx context.Context, k string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores k=v.
func (s *Store) SetSetting(ctx context.Context, k, v string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v)
	return err
}

// ---- audit ----

// AuditEntry is an administrative audit log record.
type AuditEntry struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Details string    `json:"details"`
}

// Audit appends an audit log entry. Errors are ignored.
func (s *Store) Audit(ctx context.Context, actor, action, target, details string) {
	s.db.ExecContext(ctx, "INSERT INTO audit_log(time,actor,action,target,details) VALUES(?,?,?,?,?)",
		now(), actor, action, target, details)
}

// ListAudit returns the newest audit entries.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id,time,actor,action,target,details FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var t int64
		if err := rows.Scan(&e.ID, &t, &e.Actor, &e.Action, &e.Target, &e.Details); err != nil {
			return nil, err
		}
		e.Time = toTime(t)
		out = append(out, e)
	}
	return out, rows.Err()
}
