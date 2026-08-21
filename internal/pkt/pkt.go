// Package pkt builds raw IPv4 packets (Ethernet/IP/ICMP/UDP/TCP and VXLAN
// encapsulation) used by the client to emit marked probes and by the agent to
// craft responses. Everything is IPv4-only and byte-exact so it can go straight
// onto an AF_PACKET / raw socket.
package pkt

import (
	"encoding/binary"
	"net"
)

// ICMP / ICMPv6 types we use.
const (
	ICMPEchoReply   = 0
	ICMPEchoRequest = 8

	ICMPv6EchoRequest = 128
	ICMPv6EchoReply   = 129
)

// EtherTypes.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
	EtherTypeVLAN = 0x8100
)

// TCP flag bits.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

// IP protocol numbers.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// checksum computes the standard 16-bit one's-complement Internet checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// l4Checksum computes a TCP/UDP checksum over the IPv4 pseudo-header + segment.
func l4Checksum(proto uint8, src, dst net.IP, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return checksum(pseudo)
}

// IPv4 assembles an IPv4 header (no options) in front of `payload`.
// tos carries DSCP<<2 (0xF8 for DSCP=62); ttl is the initial TTL.
func IPv4(tos uint8, ttl uint8, proto uint8, src, dst net.IP, payload []byte) []byte {
	total := 20 + len(payload)
	h := make([]byte, total)
	h[0] = 0x45 // version 4, IHL 5
	h[1] = tos
	binary.BigEndian.PutUint16(h[2:4], uint16(total))
	binary.BigEndian.PutUint16(h[4:6], 0)      // id
	binary.BigEndian.PutUint16(h[6:8], 0x4000) // don't fragment
	h[8] = ttl
	h[9] = proto
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	binary.BigEndian.PutUint16(h[10:12], checksum(h[:20]))
	copy(h[20:], payload)
	return h
}

// ICMP builds an ICMP echo message (request or reply) with id/seq and payload.
func ICMP(icmpType uint8, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = icmpType
	b[1] = 0 // code
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:4], checksum(b))
	return b
}

// UDP builds a UDP datagram with a correct checksum for the given IPs.
func UDP(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[6:8], l4Checksum(ProtoUDP, src, dst, b))
	return b
}

// TCP builds a TCP segment with the given flags/sequence numbers and payload.
func TCP(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = 5 << 4 // data offset 5 words, no options
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], 0xFFFF) // window
	copy(b[20:], payload)
	binary.BigEndian.PutUint16(b[16:18], l4Checksum(ProtoTCP, src, dst, b))
	return b
}

// Ethernet frames an L3 payload with the given MACs and EtherType (0x0800 = IP).
func Ethernet(dstMAC, srcMAC net.HardwareAddr, etherType uint16, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	copy(b[0:6], dstMAC)
	copy(b[6:12], srcMAC)
	binary.BigEndian.PutUint16(b[12:14], etherType)
	copy(b[14:], payload)
	return b
}

// EthernetVLAN frames an L3 payload with a single 802.1Q tag carrying vlanID.
func EthernetVLAN(dstMAC, srcMAC net.HardwareAddr, vlanID uint16, etherType uint16, payload []byte) []byte {
	b := make([]byte, 18+len(payload))
	copy(b[0:6], dstMAC)
	copy(b[6:12], srcMAC)
	binary.BigEndian.PutUint16(b[12:14], EtherTypeVLAN)
	binary.BigEndian.PutUint16(b[14:16], vlanID&0x0FFF) // PCP/DEI = 0
	binary.BigEndian.PutUint16(b[16:18], etherType)
	copy(b[18:], payload)
	return b
}

// l4Checksum6 computes a TCP/UDP/ICMPv6 checksum over the IPv6 pseudo-header.
func l4Checksum6(nextHdr uint8, src, dst net.IP, segment []byte) uint16 {
	ph := make([]byte, 40+len(segment))
	copy(ph[0:16], src.To16())
	copy(ph[16:32], dst.To16())
	binary.BigEndian.PutUint32(ph[32:36], uint32(len(segment)))
	ph[39] = nextHdr
	copy(ph[40:], segment)
	return checksum(ph)
}

// IPv6 assembles an IPv6 header in front of `payload`. tc carries DSCP<<2.
func IPv6(tc uint8, hopLimit uint8, nextHdr uint8, src, dst net.IP, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60 | (tc >> 4) // version 6 + high nibble of traffic class
	b[1] = (tc << 4) & 0xF0 // low nibble of traffic class + flow label (0)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = nextHdr
	b[7] = hopLimit
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	copy(b[40:], payload)
	return b
}

// ICMPv6 builds an ICMPv6 echo message; its checksum needs the IPv6 pseudo-header.
func ICMPv6(icmpType uint8, id, seq uint16, src, dst net.IP, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = icmpType
	b[1] = 0 // code
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:4], l4Checksum6(ProtoICMPv6, src, dst, b))
	return b
}

// UDP6 builds a UDP datagram with an IPv6 checksum.
func UDP6(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[6:8], l4Checksum6(ProtoUDP, src, dst, b))
	return b
}

// TCP6 builds a TCP segment with an IPv6 checksum.
func TCP6(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = 5 << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], 0xFFFF)
	copy(b[20:], payload)
	binary.BigEndian.PutUint16(b[16:18], l4Checksum6(ProtoTCP, src, dst, b))
	return b
}

// VXLAN wraps an inner Ethernet frame in a VXLAN header carrying the given VNI.
func VXLAN(vni uint32, innerFrame []byte) []byte {
	b := make([]byte, 8+len(innerFrame))
	b[0] = 0x08 // I flag set -> valid VNI
	binary.BigEndian.PutUint32(b[4:8], vni<<8)
	copy(b[8:], innerFrame)
	return b
}
