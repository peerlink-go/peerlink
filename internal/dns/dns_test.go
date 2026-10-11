package dns_test

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/peerlink-go/peerlink/internal/dns"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// buildQuery constructs a basic raw DNS A query for testing resolve() logic.
func buildAQuery(name string) []byte {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // Standard query
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // 1 Question

	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, l := range labels {
		pkt = append(pkt, byte(len(l)))
		pkt = append(pkt, []byte(l)...)
	}
	pkt = append(pkt, 0) // root label
	// QType = A (1), QClass = IN (1)
	pkt = append(pkt, 0, 1, 0, 1)
	return pkt
}

func TestMagicDNSResolution(t *testing.T) {
	srv := dns.NewServer(dns.Config{
		Domain:   "peerlink",
		ListenIP: netip.MustParseAddr("127.0.0.1"),
		Port:     53535,
	})
	defer srv.Close()

	self := &proto.Node{
		Name:      "my-laptop.peerlink.",
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	}
	peers := []proto.Node{
		{
			Name:      "db-server.peerlink.",
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		},
	}

	srv.UpdateRecords(peers, self)

	// Test query for "db-server.peerlink."
	q := buildAQuery("db-server.peerlink.")
	res := srv.ResolveForTest(q)
	if res == nil {
		t.Fatalf("expected non-nil response for db-server")
	}

	// Verify Answer Count is 1
	ancount := binary.BigEndian.Uint16(res[6:8])
	if ancount != 1 {
		t.Fatalf("expected 1 answer, got %d", ancount)
	}

	// Verify IP address in answer (last 4 bytes of A record)
	ipBytes := res[len(res)-4:]
	gotIP := netip.AddrFrom4([4]byte(ipBytes))
	wantIP := netip.MustParseAddr("100.64.0.2")
	if gotIP != wantIP {
		t.Fatalf("expected %v, got %v", wantIP, gotIP)
	}
}
