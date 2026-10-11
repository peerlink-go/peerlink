// Package controlauth authenticates node requests to the control server.
//
// The node and control server each hold an X25519 key pair. Both sides derive
// the same shared secret via ECDH (node private + control public, or control
// private + node public). Each request carries an HMAC-SHA256 over the method,
// path, timestamp and body hash, proving possession of the node private key
// without ever transmitting it. Requests must be sent over TLS in production;
// the timestamp window limits replay.
package controlauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/peerlink-go/peerlink/internal/types/key"
)

const (
	HeaderNode      = "PeerLink-Node"
	HeaderTime      = "PeerLink-Time"
	HeaderSignature = "PeerLink-Signature"

	// MaxSkew is the maximum allowed clock difference.
	MaxSkew = 5 * time.Minute
	// MaxBody is the maximum signed request body size.
	MaxBody = 4 << 20
)

func deriveMAC(shared [32]byte) []byte {
	h := hmac.New(sha256.New, shared[:])
	h.Write([]byte("peerlink-control-auth-v1"))
	return h.Sum(nil)
}

func signature(macKey []byte, method, path string, ts int64, body []byte) []byte {
	bh := sha256.Sum256(body)
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte(method))
	m.Write([]byte{'\n'})
	m.Write([]byte(path))
	m.Write([]byte{'\n'})
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte{'\n'})
	m.Write([]byte(hex.EncodeToString(bh[:])))
	return m.Sum(nil)
}

// Signer signs requests on behalf of a node.
type Signer struct {
	nodePub key.Public
	macKey  []byte
}

// NewSigner returns a Signer for nodePriv talking to a control server with
// public key controlPub.
func NewSigner(nodePriv key.Private, controlPub key.Public) (*Signer, error) {
	shared, err := nodePriv.Shared(controlPub)
	if err != nil {
		return nil, err
	}
	return &Signer{nodePub: nodePriv.Public(), macKey: deriveMAC(shared)}, nil
}

// Sign adds authentication headers to req. body must be the exact request body.
func (s *Signer) Sign(req *http.Request, body []byte) {
	ts := time.Now().Unix()
	req.Header.Set(HeaderNode, s.nodePub.String())
	req.Header.Set(HeaderTime, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(
		signature(s.macKey, req.Method, req.URL.Path, ts, body)))
}

// Verifier verifies node requests on the control server.
type Verifier struct {
	priv key.Private
}

// NewVerifier returns a Verifier using the control server private key.
func NewVerifier(controlPriv key.Private) *Verifier { return &Verifier{priv: controlPriv} }

// Verify checks the request signature and returns the node public key and the
// request body (which has been fully read).
func (v *Verifier) Verify(r *http.Request) (key.Public, []byte, error) {
	var zero key.Public
	nodePub, err := key.ParsePublic(r.Header.Get(HeaderNode))
	if err != nil || nodePub.IsZero() {
		return zero, nil, errors.New("missing or invalid node key")
	}
	ts, err := strconv.ParseInt(r.Header.Get(HeaderTime), 10, 64)
	if err != nil {
		return zero, nil, errors.New("missing timestamp")
	}
	if d := time.Since(time.Unix(ts, 0)); d > MaxSkew || d < -MaxSkew {
		return zero, nil, errors.New("timestamp out of range (check clock)")
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get(HeaderSignature))
	if err != nil {
		return zero, nil, errors.New("invalid signature encoding")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody))
	if err != nil {
		return zero, nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	shared, err := v.priv.Shared(nodePub)
	if err != nil {
		return zero, nil, errors.New("invalid node key")
	}
	want := signature(deriveMAC(shared), r.Method, r.URL.Path, ts, body)
	if !hmac.Equal(sig, want) {
		return zero, nil, errors.New("bad signature")
	}
	return nodePub, body, nil
}
