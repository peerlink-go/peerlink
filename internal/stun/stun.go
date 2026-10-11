// Package stun implements a lightweight STUN (RFC 5389 / RFC 8489) client and server
// used by PeerLink nodes to discover their public UDP endpoint.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	MagicCookie = 0x2112A442

	// Message Types
	BindingRequest  = 0x0001
	BindingResponse = 0x0101

	// Attribute Types
	AttrMappedAddress    = 0x0001
	AttrXORMappedAddress = 0x0020
)

// Header is a 20-byte STUN message header.
type Header struct {
	Type          uint16
	Length        uint16
	MagicCookie   uint32
	TransactionID [12]byte
}

// BuildRequest creates a 20-byte STUN Binding Request packet.
func BuildRequest() ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, err
	}
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], BindingRequest)
	binary.BigEndian.PutUint16(pkt[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(pkt[4:8], MagicCookie)
	copy(pkt[8:20], txID[:])
	return pkt, txID, nil
}

// BuildResponse creates a STUN Binding Response packet with XOR-MAPPED-ADDRESS attribute.
func BuildResponse(txID [12]byte, clientAddr netip.AddrPort) []byte {
	// XOR-MAPPED-ADDRESS attribute length: 4 (header) + 8 (IPv4) = 12 bytes
	attrLen := uint16(8)
	if clientAddr.Addr().Is6() {
		attrLen = 20
	}
	pktLen := 20 + 4 + attrLen
	pkt := make([]byte, pktLen)

	binary.BigEndian.PutUint16(pkt[0:2], BindingResponse)
	binary.BigEndian.PutUint16(pkt[2:4], 4+attrLen)
	binary.BigEndian.PutUint32(pkt[4:8], MagicCookie)
	copy(pkt[8:20], txID[:])

	// Attribute Header
	binary.BigEndian.PutUint16(pkt[20:22], AttrXORMappedAddress)
	binary.BigEndian.PutUint16(pkt[22:24], attrLen)

	// Attribute Value
	pkt[24] = 0 // reserved
	if clientAddr.Addr().Is4() {
		pkt[25] = 0x01 // IPv4
		// XOR Port
		binary.BigEndian.PutUint16(pkt[26:28], clientAddr.Port()^uint16(MagicCookie>>16))
		// XOR IP
		ipBytes := clientAddr.Addr().As4()
		cookieBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cookieBytes, MagicCookie)
		for i := 0; i < 4; i++ {
			pkt[28+i] = ipBytes[i] ^ cookieBytes[i]
		}
	} else {
		pkt[25] = 0x02 // IPv6
		binary.BigEndian.PutUint16(pkt[26:28], clientAddr.Port()^uint16(MagicCookie>>16))
		ipBytes := clientAddr.Addr().As16()
		var xorBytes [16]byte
		binary.BigEndian.PutUint32(xorBytes[0:4], MagicCookie)
		copy(xorBytes[4:16], txID[:])
		for i := 0; i < 16; i++ {
			pkt[28+i] = ipBytes[i] ^ xorBytes[i]
		}
	}
	return pkt
}

// ParseResponse parses a STUN Binding Response and returns the discovered AddrPort.
func ParseResponse(pkt []byte, expectedTxID [12]byte) (netip.AddrPort, error) {
	if len(pkt) < 20 {
		return netip.AddrPort{}, errors.New("stun packet too short")
	}
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	if msgType != BindingResponse {
		return netip.AddrPort{}, fmt.Errorf("unexpected message type: 0x%04x", msgType)
	}
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if cookie != MagicCookie {
		return netip.AddrPort{}, errors.New("invalid magic cookie")
	}
	if !bytesEqual(pkt[8:20], expectedTxID[:]) {
		return netip.AddrPort{}, errors.New("transaction ID mismatch")
	}

	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if len(pkt) < 20+msgLen {
		return netip.AddrPort{}, errors.New("truncated message")
	}

	pos := 20
	end := 20 + msgLen
	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(pkt[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(pkt[pos+2 : pos+4]))
		pos += 4
		if pos+attrLen > end {
			break
		}

		if attrType == AttrXORMappedAddress && attrLen >= 8 {
			family := pkt[pos+1]
			xorPort := binary.BigEndian.Uint16(pkt[pos+2 : pos+4])
			realPort := xorPort ^ uint16(MagicCookie>>16)

			if family == 0x01 && attrLen >= 8 { // IPv4
				var cookieBytes [4]byte
				binary.BigEndian.PutUint32(cookieBytes[:], MagicCookie)
				var realIP [4]byte
				for i := 0; i < 4; i++ {
					realIP[i] = pkt[pos+4+i] ^ cookieBytes[i]
				}
				addr := netip.AddrFrom4(realIP)
				return netip.AddrPortFrom(addr, realPort), nil
			}
		}
		pos += (attrLen + 3) &^ 3 // 4-byte padding
	}

	return netip.AddrPort{}, errors.New("no mapped address found in stun response")
}

// IsSTUN reports whether pkt appears to be a STUN message.
func IsSTUN(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	// First two bits of STUN message type must be 00
	if pkt[0]&0xC0 != 0 {
		return false
	}
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	return cookie == MagicCookie
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Query performs a single STUN query to stunServerAddr over conn.
func Query(conn *net.UDPConn, stunServerAddr *net.UDPAddr, timeout time.Duration) (netip.AddrPort, error) {
	req, txID, err := BuildRequest()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := conn.WriteToUDP(req, stunServerAddr); err != nil {
		return netip.AddrPort{}, err
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if from.IP.Equal(stunServerAddr.IP) && from.Port == stunServerAddr.Port {
			return ParseResponse(buf[:n], txID)
		}
	}
}
