// Package key implements Curve25519 (X25519) keys used by PeerLink for
// WireGuard node identity, disco messages and control-plane authentication.
package key

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Public is a 32-byte X25519 public key. Its zero value is "no key".
type Public [32]byte

// Private is a 32-byte X25519 private key.
type Private [32]byte

// NewPrivate generates a new random, WireGuard-clamped private key.
func NewPrivate() Private {
	var k Private
	if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	k.clamp()
	return k
}

func (k *Private) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// IsZero reports whether k is the zero key.
func (k Private) IsZero() bool { return k == Private{} }

// Public returns the public key corresponding to k.
func (k Private) Public() Public {
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		panic(err)
	}
	var p Public
	copy(p[:], priv.PublicKey().Bytes())
	return p
}

// Shared computes the X25519 shared secret between k and peer.
func (k Private) Shared(peer Public) ([32]byte, error) {
	var out [32]byte
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return out, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return out, err
	}
	s, err := priv.ECDH(pub)
	if err != nil {
		return out, err
	}
	copy(out[:], s)
	return out, nil
}

// HexString returns the hex encoding used by the WireGuard UAPI.
func (k Private) HexString() string { return hex.EncodeToString(k[:]) }

// String returns the base64 encoding of the key.
func (k Private) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k Private) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Private) UnmarshalText(b []byte) error { return decode(k[:], string(b)) }

// IsZero reports whether p is the zero key.
func (p Public) IsZero() bool { return p == Public{} }

// HexString returns the hex encoding used by the WireGuard UAPI.
func (p Public) HexString() string { return hex.EncodeToString(p[:]) }

// String returns the base64 encoding of the key.
func (p Public) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// ShortString returns an abbreviated form suitable for logs.
func (p Public) ShortString() string {
	s := p.String()
	return "[" + s[:5] + "]"
}

// MarshalText implements encoding.TextMarshaler.
func (p Public) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *Public) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*p = Public{}
		return nil
	}
	return decode(p[:], string(b))
}

// ParsePublic parses a base64 or hex encoded public key.
func ParsePublic(s string) (Public, error) {
	var p Public
	err := decode(p[:], s)
	return p, err
}

// ParsePublicHex parses a hex encoded public key (WireGuard UAPI format).
func ParsePublicHex(s string) (Public, error) {
	var p Public
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return p, errors.New("key: invalid hex public key")
	}
	copy(p[:], b)
	return p, nil
}

func decode(dst []byte, s string) error {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(dst, b)
		return nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		copy(dst, b)
		return nil
	}
	return fmt.Errorf("key: invalid key %q", s)
}
