package control_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/peerlink-go/peerlink/internal/control"
	"github.com/peerlink-go/peerlink/internal/control/store"
	"github.com/peerlink-go/peerlink/internal/controlauth"
	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// inMemoryTransport dispatches HTTP requests directly to an http.Handler
// without opening any OS TCP sockets (works in restricted sandbox environments).
type inMemoryTransport struct {
	handler http.Handler
}

func (t *inMemoryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pr, pw := io.Pipe()
	rec := httptest.NewRecorder()

	// Clone request body to prevent read race if any
	go func() {
		defer pw.Close()
		sw := &streamingResponseWriter{
			ResponseRecorder: rec,
			pipeWriter:       pw,
		}
		t.handler.ServeHTTP(sw, req)
	}()

	// Wait for headers to be written
	res := rec.Result()
	res.Body = pr
	return res, nil
}

type streamingResponseWriter struct {
	*httptest.ResponseRecorder
	pipeWriter *io.PipeWriter
	wroteHdr   bool
}

func (w *streamingResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHdr {
		w.ResponseRecorder.WriteHeader(statusCode)
		w.wroteHdr = true
	}
}

func (w *streamingResponseWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pipeWriter.Write(b)
}

func (w *streamingResponseWriter) Flush() {}

func newTestServer(t *testing.T) (*control.Server, *http.Client, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv, err := control.New(context.Background(), control.Config{
		Domain:    "peerlink.test",
		ServerURL: "http://peerlink.local",
	}, st)
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}

	client := &http.Client{
		Transport: &inMemoryTransport{handler: srv.Handler()},
	}
	return srv, client, st
}

func signAndDo(t *testing.T, client *http.Client, nodePriv key.Private, controlPub key.Public, method, url string, body any) (*http.Response, []byte) {
	t.Helper()
	signer, err := controlauth.NewSigner(nodePriv, controlPub)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	var bodyBytes []byte
	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	signer.Sign(req, bodyBytes)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	respBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp, respBytes
}

func TestControlKeyEndpoint(t *testing.T) {
	srv, client, _ := newTestServer(t)

	resp, err := client.Get("http://peerlink.local" + proto.PathKey)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var kr proto.KeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
		t.Fatal(err)
	}
	if kr.PublicKey != srv.PublicKey() {
		t.Fatalf("expected key %v, got %v", srv.PublicKey(), kr.PublicKey)
	}
}

func TestRegisterWithAuthKeyAndMapStream(t *testing.T) {
	srv, client, st := newTestServer(t)
	ctx := context.Background()

	// Create user
	u, err := st.CreateUser(ctx, "admin@example.com", "Admin", "password1234", store.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create AuthKey
	secret, _, err := st.CreateAuthKey(ctx, store.AuthKeyOptions{
		UserID:        u.ID,
		Description:   "test key",
		Reusable:      true,
		Preauthorized: true,
	})
	if err != nil {
		t.Fatalf("CreateAuthKey: %v", err)
	}

	nodePriv := key.NewPrivate()
	regReq := proto.RegisterRequest{
		Version: proto.ProtocolVersion,
		AuthKey: secret,
		Hostinfo: proto.Hostinfo{
			Hostname: "node-a",
			OS:       "linux",
		},
	}

	resp, body := signAndDo(t, client, nodePriv, srv.PublicKey(), "POST", "http://peerlink.local"+proto.PathRegister, regReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d: %s", resp.StatusCode, string(body))
	}

	var regResp proto.RegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		t.Fatalf("Unmarshal regResp: %v", err)
	}
	if !regResp.Authorized {
		t.Fatalf("expected node to be authorized")
	}

	// Now connect to /peerlink/v1/map (Stream=true)
	discoKey := key.NewPrivate().Public()
	mapReq := proto.MapRequest{
		Version:   proto.ProtocolVersion,
		DiscoKey:  discoKey,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.50:41641")},
		Stream:    true,
	}

	mapBody, _ := json.Marshal(mapReq)
	httpReq, err := http.NewRequest("POST", "http://peerlink.local"+proto.PathMap, bytes.NewReader(mapBody))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := controlauth.NewSigner(nodePriv, srv.PublicKey())
	signer.Sign(httpReq, mapBody)

	streamResp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("Map request failed: %v", err)
	}
	defer streamResp.Body.Close()

	if streamResp.StatusCode != http.StatusOK {
		t.Fatalf("map status = %d", streamResp.StatusCode)
	}

	// Read first MapResponse
	reader := bufio.NewReader(streamResp.Body)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes map response: %v", err)
	}

	var mapResp proto.MapResponse
	if err := json.Unmarshal(line, &mapResp); err != nil {
		t.Fatalf("Unmarshal map response: %v\nRaw: %s", err, string(line))
	}

	if mapResp.Node == nil {
		t.Fatalf("expected self node in mapResp, got nil")
	}
	if mapResp.Node.ShortName() != "node-a" {
		t.Fatalf("expected node-a, got %s", mapResp.Node.Name)
	}
	if len(mapResp.Node.Addresses) == 0 {
		t.Fatalf("expected allocated IP address")
	}

	// Register a second node and verify notification
	node2Priv := key.NewPrivate()
	reg2Req := proto.RegisterRequest{
		Version: proto.ProtocolVersion,
		AuthKey: secret,
		Hostinfo: proto.Hostinfo{
			Hostname: "node-b",
			OS:       "darwin",
		},
	}
	resp2, body2 := signAndDo(t, client, node2Priv, srv.PublicKey(), "POST", "http://peerlink.local"+proto.PathRegister, reg2Req)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("register node2 status = %d: %s", resp2.StatusCode, string(body2))
	}

	// node-a's map stream should receive updated map with node-b as peer
	line2, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes map response after peer added: %v", err)
	}

	var mapResp2 proto.MapResponse
	if err := json.Unmarshal(line2, &mapResp2); err != nil {
		t.Fatalf("Unmarshal second map response: %v", err)
	}
	if len(mapResp2.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(mapResp2.Peers))
	}
	if mapResp2.Peers[0].ShortName() != "node-b" {
		t.Fatalf("expected peer node-b, got %s", mapResp2.Peers[0].ShortName())
	}
}
