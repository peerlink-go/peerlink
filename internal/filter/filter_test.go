package filter_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/peerlink-go/peerlink/internal/filter"
	"github.com/peerlink-go/peerlink/internal/types/proto"
)

func makeIPv4TCP(src, dst netip.Addr, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[9] = 6    // TCP
	srcBytes := src.As4()
	copy(pkt[12:16], srcBytes[:])
	dstBytes := dst.As4()
	copy(pkt[16:20], dstBytes[:])
	// TCP header at offset 20: dstPort at 22:24
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

func TestFilterAcceptAndDrop(t *testing.T) {
	rules := []proto.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1"},
			DstPorts: []proto.NetPortRange{
				{
					IP:    "100.64.0.2",
					Ports: proto.PortRange{First: 22, Last: 22}, // only SSH port 22
				},
			},
			IPProto: []int{6}, // TCP
		},
	}

	flt := filter.New(rules)

	src := netip.MustParseAddr("100.64.0.1")
	dst := netip.MustParseAddr("100.64.0.2")

	// Port 22 should be accepted
	pkt22 := makeIPv4TCP(src, dst, 22)
	if flt.Match(pkt22) != filter.Accept {
		t.Fatalf("expected port 22 to be accepted")
	}

	// Port 80 should be dropped
	pkt80 := makeIPv4TCP(src, dst, 80)
	if flt.Match(pkt80) != filter.Drop {
		t.Fatalf("expected port 80 to be dropped")
	}

	// Different src IP should be dropped
	otherSrc := netip.MustParseAddr("100.64.0.99")
	pktFromOther := makeIPv4TCP(otherSrc, dst, 22)
	if flt.Match(pktFromOther) != filter.Drop {
		t.Fatalf("expected different src to be dropped")
	}
}
