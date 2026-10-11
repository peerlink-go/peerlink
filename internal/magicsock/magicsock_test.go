package magicsock_test

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/peerlink-go/peerlink/internal/magicsock"
	"github.com/peerlink-go/peerlink/internal/types/key"
)

func TestMagicsockRelayReceive(t *testing.T) {
	privA := key.NewPrivate()
	sock := magicsock.New(magicsock.Config{NodeKey: privA})
	defer sock.Close()

	fns, _, err := sock.Open(0)
	if err != nil {
		t.Skipf("UDP listen not permitted in sandbox: %v", err)
	}

	peerKey := key.NewPrivate().Public()
	testPacket := []byte("WG_ENCRYPTED_PACKET_OVER_RELAY")

	// Simulate packet arriving from Relay
	sock.ReceiveFromRelay(peerKey, testPacket)

	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 1024)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("ReceiveFunc: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 packet, got %d", n)
	}
	received := string(bufs[0][:sizes[0]])
	if received != string(testPacket) {
		t.Fatalf("expected %q, got %q", string(testPacket), received)
	}
	if eps[0].DstToString() != "relay:"+peerKey.ShortString() {
		t.Fatalf("expected relay endpoint string, got %s", eps[0].DstToString())
	}
}
