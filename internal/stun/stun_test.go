package stun_test

import (
	"net/netip"
	"testing"

	"github.com/peerlink-go/peerlink/internal/stun"
)

func TestSTUNEncodeDecode(t *testing.T) {
	req, txID, err := stun.BuildRequest()
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	if !stun.IsSTUN(req) {
		t.Fatalf("IsSTUN returned false for valid request")
	}

	clientAddr := netip.MustParseAddrPort("203.0.113.195:45678")
	resp := stun.BuildResponse(txID, clientAddr)

	if !stun.IsSTUN(resp) {
		t.Fatalf("IsSTUN returned false for valid response")
	}

	discoveredAddr, err := stun.ParseResponse(resp, txID)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}

	if discoveredAddr != clientAddr {
		t.Fatalf("expected %v, got %v", clientAddr, discoveredAddr)
	}
}
