package wgengine_test

import (
	"net/netip"
	"testing"

	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
	"github.com/peerlink-go/peerlink/internal/wgengine"
)

func TestEngineLifecycleAndNetMapUpdate(t *testing.T) {
	sim := wgengine.NewSimTUN("test0", 1420)
	eng, err := wgengine.New(wgengine.Config{
		TunDevice: sim,
		TunName:   "test0",
	})
	if err != nil {
		t.Fatalf("wgengine.New: %v", err)
	}
	defer eng.Close()

	priv := key.NewPrivate()
	if err := eng.SetPrivateKey(priv); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	self := &proto.Node{
		Key:       priv.Public(),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	}

	peerKey1 := key.NewPrivate().Public()
	peerKey2 := key.NewPrivate().Public()

	peers := []proto.Node{
		{
			Key:        peerKey1,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:51820")},
		},
		{
			Key:        peerKey2,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
			Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("192.168.1.20:51820")},
		},
	}

	if err := eng.UpdateFromNetMap(self, peers); err != nil {
		t.Fatalf("UpdateFromNetMap: %v", err)
	}

	status, err := eng.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	if len(status) != 2 {
		t.Fatalf("expected 2 peers in status, got %d", len(status))
	}

	// Verify peers
	found1, found2 := false, false
	for _, p := range status {
		if p.PublicKey == peerKey1 {
			found1 = true
			if p.Endpoint != "192.168.1.10:51820" {
				t.Errorf("expected peer1 endpoint 192.168.1.10:51820, got %s", p.Endpoint)
			}
		}
		if p.PublicKey == peerKey2 {
			found2 = true
			if p.Endpoint != "192.168.1.20:51820" {
				t.Errorf("expected peer2 endpoint 192.168.1.20:51820, got %s", p.Endpoint)
			}
		}
	}
	if !found1 || !found2 {
		t.Fatalf("missing peer in status: found1=%v, found2=%v", found1, found2)
	}

	// Now remove peer2, keep only peer1
	peersUpdate := []proto.Node{
		{
			Key:        peerKey1,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:51820")},
		},
	}

	if err := eng.UpdateFromNetMap(self, peersUpdate); err != nil {
		t.Fatalf("UpdateFromNetMap (removal): %v", err)
	}

	status2, err := eng.Status()
	if err != nil {
		t.Fatalf("Status2: %v", err)
	}
	if len(status2) != 1 {
		t.Fatalf("expected 1 peer after update, got %d", len(status2))
	}
	if status2[0].PublicKey != peerKey1 {
		t.Fatalf("expected peer1 to remain, got %v", status2[0].PublicKey)
	}
}
