package integration_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/peerlink-go/peerlink/internal/control"
	"github.com/peerlink-go/peerlink/internal/control/store"
	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
	"github.com/peerlink-go/peerlink/internal/wgengine"
)

func TestMeshCoordinationAndPeerSetup(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// 1. Setup Control Server
	srv, err := control.New(ctx, control.Config{
		Domain:    "peerlink.test",
		ServerURL: "http://control.local",
	}, st)
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}

	// Create user & pre-authorized auth key
	u, err := st.CreateUser(ctx, "dev@example.com", "Developer", "password123", store.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	secret, _, err := st.CreateAuthKey(ctx, store.AuthKeyOptions{
		UserID:        u.ID,
		Description:   "integration test",
		Reusable:      true,
		Preauthorized: true,
	})
	if err != nil {
		t.Fatalf("CreateAuthKey: %v", err)
	}

	// 2. Setup Node A (WireGuard engine + SimTUN)
	privA := key.NewPrivate()
	simA := wgengine.NewSimTUN("peerlink-a", 1420)
	engA, err := wgengine.New(wgengine.Config{TunDevice: simA, TunName: "peerlink-a"})
	if err != nil {
		t.Fatalf("engA: %v", err)
	}
	defer engA.Close()
	engA.SetPrivateKey(privA)

	// Register Node A directly to control
	nodeA, err := st.CreateNode(ctx, store.NewNode{
		NodeKey:    privA.Public(),
		UserID:     u.ID,
		Authorized: true,
		Hostinfo: proto.Hostinfo{
			Hostname: "alice-laptop",
			OS:       "darwin",
		},
	})
	if err != nil {
		t.Fatalf("CreateNode A: %v", err)
	}

	// 3. Setup Node B (WireGuard engine + SimTUN)
	privB := key.NewPrivate()
	simB := wgengine.NewSimTUN("peerlink-b", 1420)
	engB, err := wgengine.New(wgengine.Config{TunDevice: simB, TunName: "peerlink-b"})
	if err != nil {
		t.Fatalf("engB: %v", err)
	}
	defer engB.Close()
	engB.SetPrivateKey(privB)

	nodeB, err := st.CreateNode(ctx, store.NewNode{
		NodeKey:    privB.Public(),
		UserID:     u.ID,
		Authorized: true,
		Hostinfo: proto.Hostinfo{
			Hostname: "bob-server",
			OS:       "linux",
		},
	})
	if err != nil {
		t.Fatalf("CreateNode B: %v", err)
	}

	// 4. Update Node A with NetMap (should contain Node B as peer)
	protoNodeA := proto.Node{
		ID:         nodeA.ID,
		Key:        nodeA.NodeKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(nodeA.IPv4.String() + "/32")},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix(nodeA.IPv4.String() + "/32")},
	}
	protoNodeB := proto.Node{
		ID:         nodeB.ID,
		Key:        nodeB.NodeKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(nodeB.IPv4.String() + "/32")},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix(nodeB.IPv4.String() + "/32")},
	}

	if err := engA.UpdateFromNetMap(&protoNodeA, []proto.Node{protoNodeB}); err != nil {
		t.Fatalf("engA.UpdateFromNetMap: %v", err)
	}
	if err := engB.UpdateFromNetMap(&protoNodeB, []proto.Node{protoNodeA}); err != nil {
		t.Fatalf("engB.UpdateFromNetMap: %v", err)
	}

	// Verify Node A has Node B configured as WireGuard peer
	stA, err := engA.Status()
	if err != nil {
		t.Fatalf("engA.Status: %v", err)
	}
	if len(stA) != 1 || stA[0].PublicKey != privB.Public() {
		t.Fatalf("expected node B as peer in node A, got %+v", stA)
	}

	// Verify Node B has Node A configured as WireGuard peer
	stB, err := engB.Status()
	if err != nil {
		t.Fatalf("engB.Status: %v", err)
	}
	if len(stB) != 1 || stB[0].PublicKey != privA.Public() {
		t.Fatalf("expected node A as peer in node B, got %+v", stB)
	}

	_ = srv
	_ = secret
}
