package pkt

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

var (
	testSrc = net.IPv4(10, 0, 0, 1)
	testDst = net.IPv4(10, 0, 0, 2)
)

// A correct one's-complement checksum makes the sum over the data that already
// includes the checksum field equal zero. Every builder below is validated this
// way.

func TestIPv4HeaderChecksumAndFields(t *testing.T) {
	payload := []byte("hello")
	h := IPv4(0xF8, 255, ProtoICMP, testSrc, testDst, payload)
	if len(h) != 20+len(payload) {
		t.Fatalf("len = %d, want %d", len(h), 20+len(payload))
	}
	if got := checksum(h[:20]); got != 0 {
		t.Fatalf("IPv4 header checksum verify = %#x, want 0", got)
	}
	if h[0] != 0x45 {
		t.Fatalf("version/ihl = %#x, want 0x45", h[0])
	}
	if h[1] != 0xF8 {
		t.Fatalf("tos = %#x, want 0xF8 (DSCP 62)", h[1])
	}
	if h[8] != 255 {
		t.Fatalf("ttl = %d, want 255", h[8])
	}
	if h[9] != ProtoICMP {
		t.Fatalf("proto = %d, want %d", h[9], ProtoICMP)
	}
	if got := binary.BigEndian.Uint16(h[2:4]); int(got) != len(h) {
		t.Fatalf("total length = %d, want %d", got, len(h))
	}
	if !net.IP(h[12:16]).Equal(testSrc) || !net.IP(h[16:20]).Equal(testDst) {
		t.Fatalf("src/dst mismatch: %v -> %v", net.IP(h[12:16]), net.IP(h[16:20]))
	}
}

func TestICMPChecksum(t *testing.T) {
	b := ICMP(ICMPEchoRequest, 0x1234, 7, []byte("payload"))
	if b[0] != ICMPEchoRequest {
		t.Fatalf("type = %d, want %d", b[0], ICMPEchoRequest)
	}
	if binary.BigEndian.Uint16(b[4:6]) != 0x1234 || binary.BigEndian.Uint16(b[6:8]) != 7 {
		t.Fatalf("id/seq = %d/%d, want 4660/7", binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8]))
	}
	if got := checksum(b); got != 0 {
		t.Fatalf("ICMP checksum verify = %#x, want 0", got)
	}
}

func TestUDPChecksum(t *testing.T) {
	b := UDP(testSrc, testDst, 40000, 4789, []byte("data"))
	if binary.BigEndian.Uint16(b[0:2]) != 40000 || binary.BigEndian.Uint16(b[2:4]) != 4789 {
		t.Fatal("udp ports mismatch")
	}
	if int(binary.BigEndian.Uint16(b[4:6])) != len(b) {
		t.Fatalf("udp length = %d, want %d", binary.BigEndian.Uint16(b[4:6]), len(b))
	}
	if got := l4Checksum(ProtoUDP, testSrc, testDst, b); got != 0 {
		t.Fatalf("UDP checksum verify = %#x, want 0", got)
	}
}

func TestTCPChecksumAndFlags(t *testing.T) {
	b := TCP(testSrc, testDst, 40000, 80, 0x2000, 0, FlagSYN, nil)
	if binary.BigEndian.Uint16(b[0:2]) != 40000 || binary.BigEndian.Uint16(b[2:4]) != 80 {
		t.Fatal("tcp ports mismatch")
	}
	if binary.BigEndian.Uint32(b[4:8]) != 0x2000 {
		t.Fatalf("seq = %#x, want 0x2000", binary.BigEndian.Uint32(b[4:8]))
	}
	if b[13] != FlagSYN {
		t.Fatalf("flags = %#x, want SYN(%#x)", b[13], FlagSYN)
	}
	if b[12]>>4 != 5 {
		t.Fatalf("data offset = %d words, want 5", b[12]>>4)
	}
	if got := l4Checksum(ProtoTCP, testSrc, testDst, b); got != 0 {
		t.Fatalf("TCP checksum verify = %#x, want 0", got)
	}
}

func TestVXLANEncoding(t *testing.T) {
	inner := []byte("innerframe")
	b := VXLAN(100, inner)
	if b[0]&0x08 == 0 {
		t.Fatalf("VXLAN I-flag not set: flags byte = %#x", b[0])
	}
	// VNI sits in the top 24 bits of the second word.
	if got := binary.BigEndian.Uint32(b[4:8]) >> 8; got != 100 {
		t.Fatalf("VNI = %d, want 100", got)
	}
	if string(b[8:]) != string(inner) {
		t.Fatal("inner frame not preserved")
	}
}

func TestEthernet(t *testing.T) {
	dst := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	src := net.HardwareAddr{7, 8, 9, 10, 11, 12}
	b := Ethernet(dst, src, 0x0800, []byte("x"))
	if !bytes.Equal(b[0:6], dst) {
		t.Fatalf("dst MAC = %x, want %x", b[0:6], dst)
	}
	if !bytes.Equal(b[6:12], src) {
		t.Fatalf("src MAC = %x, want %x", b[6:12], src)
	}
	if binary.BigEndian.Uint16(b[12:14]) != 0x0800 {
		t.Fatalf("ethertype = %#x, want 0x0800", binary.BigEndian.Uint16(b[12:14]))
	}
}

func TestChecksumOddLength(t *testing.T) {
	// Sanity: checksum handles odd-length buffers without panicking.
	_ = checksum([]byte{1, 2, 3})
}

var (
	testSrc6 = net.ParseIP("2001:db8::1")
	testDst6 = net.ParseIP("2001:db8::2")
)

func TestIPv6HeaderFields(t *testing.T) {
	payload := []byte("hello")
	h := IPv6(0xF8, 255, ProtoICMPv6, testSrc6, testDst6, payload)
	if len(h) != 40+len(payload) {
		t.Fatalf("len = %d, want %d", len(h), 40+len(payload))
	}
	if h[0]>>4 != 6 {
		t.Fatalf("version = %d, want 6", h[0]>>4)
	}
	// traffic class = high nibble from byte0 low, low nibble from byte1 high.
	tc := (h[0]&0x0F)<<4 | (h[1] >> 4)
	if tc != 0xF8 {
		t.Fatalf("traffic class = %#x, want 0xF8 (DSCP 62)", tc)
	}
	if h[6] != ProtoICMPv6 {
		t.Fatalf("next header = %d, want %d", h[6], ProtoICMPv6)
	}
	if h[7] != 255 {
		t.Fatalf("hop limit = %d, want 255", h[7])
	}
	if int(binary.BigEndian.Uint16(h[4:6])) != len(payload) {
		t.Fatalf("payload length = %d, want %d", binary.BigEndian.Uint16(h[4:6]), len(payload))
	}
	if !net.IP(h[8:24]).Equal(testSrc6) || !net.IP(h[24:40]).Equal(testDst6) {
		t.Fatal("v6 src/dst mismatch")
	}
}

func TestICMPv6Checksum(t *testing.T) {
	b := ICMPv6(ICMPv6EchoRequest, 0x1234, 7, testSrc6, testDst6, []byte("payload"))
	if b[0] != ICMPv6EchoRequest {
		t.Fatalf("type = %d, want %d", b[0], ICMPv6EchoRequest)
	}
	// ICMPv6 checksum covers the IPv6 pseudo-header.
	if got := l4Checksum6(ProtoICMPv6, testSrc6, testDst6, b); got != 0 {
		t.Fatalf("ICMPv6 checksum verify = %#x, want 0", got)
	}
}

func TestUDP6Checksum(t *testing.T) {
	b := UDP6(testSrc6, testDst6, 40000, 4789, []byte("data"))
	if got := l4Checksum6(ProtoUDP, testSrc6, testDst6, b); got != 0 {
		t.Fatalf("UDP6 checksum verify = %#x, want 0", got)
	}
}

func TestTCP6Checksum(t *testing.T) {
	b := TCP6(testSrc6, testDst6, 40000, 80, 0x2000, 0, FlagSYN, nil)
	if got := l4Checksum6(ProtoTCP, testSrc6, testDst6, b); got != 0 {
		t.Fatalf("TCP6 checksum verify = %#x, want 0", got)
	}
}

func TestEthernetVLAN(t *testing.T) {
	dst := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	src := net.HardwareAddr{7, 8, 9, 10, 11, 12}
	b := EthernetVLAN(dst, src, 100, EtherTypeIPv6, []byte("x"))
	if binary.BigEndian.Uint16(b[12:14]) != EtherTypeVLAN {
		t.Fatalf("outer TPID = %#x, want 0x8100", binary.BigEndian.Uint16(b[12:14]))
	}
	if binary.BigEndian.Uint16(b[14:16])&0x0FFF != 100 {
		t.Fatalf("VID = %d, want 100", binary.BigEndian.Uint16(b[14:16])&0x0FFF)
	}
	if binary.BigEndian.Uint16(b[16:18]) != EtherTypeIPv6 {
		t.Fatalf("inner ethertype = %#x, want 0x86DD", binary.BigEndian.Uint16(b[16:18]))
	}
	if string(b[18:]) != "x" {
		t.Fatal("payload not preserved after VLAN tag")
	}
}
