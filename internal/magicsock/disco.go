package magicsock

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/peerlink-go/peerlink/internal/types/key"
)

// DiscoMagic is the 4-byte header of PeerLink path discovery packets.
var DiscoMagic = [4]byte{'P', 'L', 'K', 'D'}

const (
	DiscoTypePing = 0x01
	DiscoTypePong = 0x02
)

// DiscoMessage is a path discovery probe for NAT hole punching.
type DiscoMessage struct {
	Type   byte
	Sender key.Public
	TxID   uint64
}

// BuildDiscoPing builds a 45-byte Ping probe packet.
func BuildDiscoPing(sender key.Public) ([]byte, uint64) {
	var txBytes [8]byte
	rand.Read(txBytes[:])
	txID := binary.BigEndian.Uint64(txBytes[:])

	pkt := make([]byte, 45)
	copy(pkt[0:4], DiscoMagic[:])
	pkt[4] = DiscoTypePing
	copy(pkt[5:37], sender[:])
	binary.BigEndian.PutUint64(pkt[37:45], txID)
	return pkt, txID
}

// BuildDiscoPong builds a 45-byte Pong reply packet.
func BuildDiscoPong(sender key.Public, txID uint64) []byte {
	pkt := make([]byte, 45)
	copy(pkt[0:4], DiscoMagic[:])
	pkt[4] = DiscoTypePong
	copy(pkt[5:37], sender[:])
	binary.BigEndian.PutUint64(pkt[37:45], txID)
	return pkt
}

// ParseDisco parses a discovery packet.
func ParseDisco(b []byte) (*DiscoMessage, error) {
	if len(b) < 45 {
		return nil, errors.New("disco packet too short")
	}
	if b[0] != 'P' || b[1] != 'L' || b[2] != 'K' || b[3] != 'D' {
		return nil, errors.New("invalid disco magic")
	}
	msg := &DiscoMessage{
		Type: b[4],
		TxID: binary.BigEndian.Uint64(b[37:45]),
	}
	copy(msg.Sender[:], b[5:37])
	return msg, nil
}

// IsDisco reports whether b begins with the discovery magic.
func IsDisco(b []byte) bool {
	return len(b) >= 45 && b[0] == 'P' && b[1] == 'L' && b[2] == 'K' && b[3] == 'D'
}
