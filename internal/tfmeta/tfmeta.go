// Package tfmeta holds the wire-level constants shared by client, agent and the
// eBPF program, plus (de)serialization of the traceflow_meta control block.
//
// Byte-order contract (must match bpf/traceflow.c):
//   - magic:     the 4 ASCII bytes "TFLO", i.e. big-endian 0x54464C4F on the wire.
//   - timestamp: little-endian uint64 (host order on x86-64), unix nanoseconds.
//   - id:        16 raw bytes (UUIDv4).
package tfmeta

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	// DSCP is the level-1 filter value; ToS is DSCP<<2.
	DSCP = 62
	ToS  = 0xF8

	// Magic is the level-2 filter word, "TFLO", in host integer form.
	Magic = 0x54464C4F

	// TTLMax is what the sender always sets; hop = TTLMax - ttl.
	TTLMax = 255

	// VXLANPort is the UDP destination port for VXLAN encapsulation.
	VXLANPort = 4789

	// MetaSize is the packed size of traceflow_meta on the wire.
	// 4 (magic) + 16 (id) + 1 (intercept) + 1 (need_response) + 8 (timestamp).
	MetaSize = 30

	// AuthSize is the HMAC-SHA256 appended after the meta when a key is used.
	AuthSize = 32
	// SignedSize is the payload length of a signed marked packet.
	SignedSize = MetaSize + AuthSize
)

// Interface type flags (set at load time). Auto parses VXLAN-then-regular per
// packet; the observation always reports the detected type, never Auto.
const (
	IfaceRegular = 0
	IfaceVXLAN   = 1
	IfaceAuto    = 2
)

// Meta is the control block placed right after the transport header.
type Meta struct {
	ID           [16]byte
	Intercept    bool
	NeedResponse bool
	Timestamp    uint64 // unix nanoseconds
}

// MagicBytes returns the magic word as it appears on the wire ("TFLO").
func MagicBytes() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, Magic)
	return b
}

// Marshal encodes the meta block exactly as the eBPF program expects to read it.
func (m Meta) Marshal() []byte {
	buf := make([]byte, MetaSize)
	binary.BigEndian.PutUint32(buf[0:4], Magic) // "TFLO"
	copy(buf[4:20], m.ID[:])
	if m.Intercept {
		buf[20] = 1
	}
	if m.NeedResponse {
		buf[21] = 1
	}
	binary.LittleEndian.PutUint64(buf[22:30], m.Timestamp)
	return buf
}

// Sign returns HMAC-SHA256(key, core) — the 32-byte authenticator appended
// after the 30-byte meta core.
func Sign(core, key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(core)
	return m.Sum(nil)
}

// Signed returns the meta core followed by its HMAC when key is non-empty, or
// the bare core otherwise.
func (m Meta) Signed(key []byte) []byte {
	core := m.Marshal()
	if len(key) == 0 {
		return core
	}
	return append(core, Sign(core, key)...)
}

// Verify reports whether payload carries a valid HMAC over its meta core. With
// an empty key it returns true (authentication disabled).
func Verify(payload, key []byte) bool {
	if len(key) == 0 {
		return true
	}
	if len(payload) < SignedSize {
		return false
	}
	return hmac.Equal(Sign(payload[:MetaSize], key), payload[MetaSize:SignedSize])
}

// Unmarshal decodes a meta block from a payload, verifying the magic.
func Unmarshal(b []byte) (Meta, error) {
	var m Meta
	if len(b) < MetaSize {
		return m, fmt.Errorf("payload too short for traceflow_meta: %d < %d", len(b), MetaSize)
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return m, fmt.Errorf("bad magic: not a traceflow packet")
	}
	copy(m.ID[:], b[4:20])
	m.Intercept = b[20] == 1
	m.NeedResponse = b[21] == 1
	m.Timestamp = binary.LittleEndian.Uint64(b[22:30])
	return m, nil
}
