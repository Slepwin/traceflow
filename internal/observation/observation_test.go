package observation

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestRawSizeMatchesC guards the Go/C layout contract: struct observation is
// 88 bytes in bpf/traceflow.h. If this fails, the ring-buffer decode is skewed.
func TestRawSizeMatchesC(t *testing.T) {
	if got := binary.Size(Raw{}); got != 88 {
		t.Fatalf("binary.Size(Raw) = %d, want 88 (must match struct observation)", got)
	}
}

func TestLatencyClampAndSkew(t *testing.T) {
	now := time.Unix(0, 1_000_000_000)
	// meta timestamp in the future -> negative raw latency -> clamped + flagged.
	future := Raw{MetaTimestamp: uint64(now.UnixNano()) + 500_000_000}
	o := future.Enrich("n", now)
	if o.LatencyNS != 0 || !o.ClockSkew {
		t.Fatalf("future timestamp: latency=%d skew=%v, want 0/true", o.LatencyNS, o.ClockSkew)
	}
	// normal case: no skew flag.
	past := Raw{MetaTimestamp: uint64(now.UnixNano()) - 200_000_000, CaptureNS: 42}
	o = past.Enrich("n", now)
	if o.LatencyNS != 200_000_000 || o.ClockSkew {
		t.Fatalf("past timestamp: latency=%d skew=%v, want 2e8/false", o.LatencyNS, o.ClockSkew)
	}
	if o.CaptureNS != 42 {
		t.Fatalf("capture_ns = %d, want 42", o.CaptureNS)
	}
}

func v4(a, b, c, d byte) [16]byte { return [16]byte{a, b, c, d} }

func encode(t *testing.T, r Raw) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &r); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func TestParseRoundTrip(t *testing.T) {
	in := Raw{
		MetaTimestamp: 1_700_000_000_000_000_000,
		ID:            [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SrcIP:         v4(10, 0, 0, 1),
		DstIP:         v4(10, 0, 0, 2),
		VNI:           100,
		IfIndex:       12345,
		SrcPort:       40000,
		DstPort:       4789,
		VLANID:        42,
		IPVersion:     4,
		Hop:           1,
		Direction:     1,
		Action:        1,
		Protocol:      protoTCP,
		TCPFlags:      0x12, // SYN|ACK
		IfaceType:     1,
	}
	got, err := Parse(encode(t, in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestEnrichMappingV4(t *testing.T) {
	now := time.Unix(0, 2_000_000_000)
	r := Raw{
		MetaTimestamp: 1_000_000_000, // 1s before now -> ~1e9 ns latency
		SrcIP:         v4(10, 0, 0, 1),
		DstIP:         v4(192, 168, 1, 1),
		VNI:           4242,
		SrcPort:       1111,
		DstPort:       2222,
		VLANID:        7,
		IPVersion:     4,
		Hop:           3,
		Direction:     1, // EGRESS
		Action:        1, // INTERCEPTED
		Protocol:      protoTCP,
		TCPFlags:      0x12, // SYN|ACK
		IfaceType:     1,    // VXLAN
	}
	o := r.Enrich("hv-07", now)

	checks := map[string]struct{ got, want string }{
		"node_id":    {o.NodeID, "hv-07"},
		"direction":  {o.Direction, "EGRESS"},
		"action":     {o.Action, "INTERCEPTED"},
		"protocol":   {o.Protocol, "TCP"},
		"src_ip":     {o.SrcIP, "10.0.0.1"},
		"dst_ip":     {o.DstIP, "192.168.1.1"},
		"tcp_flags":  {o.TCPFlags, "SYN|ACK"},
		"iface_type": {o.IfaceType, "VXLAN"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
	if o.Hop != 3 || o.VNI != 4242 || o.SrcPort != 1111 || o.DstPort != 2222 || o.VLAN != 7 {
		t.Errorf("numeric fields wrong: %+v", o)
	}
	if o.LatencyNS != 1_000_000_000 {
		t.Errorf("latency = %d, want 1e9", o.LatencyNS)
	}
}

func TestEnrichMappingV6(t *testing.T) {
	// 2001:db8::1 -> 2001:db8::2, ICMPv6, no ports.
	var src, dst [16]byte
	copy(src[:], net.ParseIP("2001:db8::1").To16())
	copy(dst[:], net.ParseIP("2001:db8::2").To16())
	r := Raw{
		SrcIP:     src,
		DstIP:     dst,
		IPVersion: 6,
		SrcPort:   1234, // must be suppressed for ICMPv6
		DstPort:   5678,
		Protocol:  protoICMPv6,
		VLANID:    100,
	}
	o := r.Enrich("hv", time.Unix(0, 0))
	if o.Protocol != "ICMPv6" {
		t.Fatalf("protocol = %q, want ICMPv6", o.Protocol)
	}
	if o.SrcIP != "2001:db8::1" || o.DstIP != "2001:db8::2" {
		t.Fatalf("v6 addrs wrong: %s -> %s", o.SrcIP, o.DstIP)
	}
	if o.SrcPort != 0 || o.DstPort != 0 {
		t.Fatalf("ICMPv6 must not carry ports, got %d/%d", o.SrcPort, o.DstPort)
	}
	if o.VLAN != 100 {
		t.Fatalf("vlan = %d, want 100", o.VLAN)
	}
}

func TestEnrichICMPHasNoPorts(t *testing.T) {
	r := Raw{Protocol: protoICMP, SrcPort: 5, DstPort: 6}
	o := r.Enrich("n", time.Unix(0, 0))
	if o.SrcPort != 0 || o.DstPort != 0 {
		t.Fatalf("ICMP observation should not carry ports, got %d/%d", o.SrcPort, o.DstPort)
	}
	if o.Protocol != "ICMP" {
		t.Fatalf("protocol = %q, want ICMP", o.Protocol)
	}
}

func TestTCPFlagsString(t *testing.T) {
	cases := map[uint8]string{
		0x02: "SYN",
		0x12: "SYN|ACK",
		0x11: "FIN|ACK",
		0x14: "RST|ACK",
		0x00: "",
	}
	for f, want := range cases {
		if got := tcpFlagsString(f); got != want {
			t.Errorf("tcpFlagsString(%#x) = %q, want %q", f, got, want)
		}
	}
}

func TestParseRejectsShort(t *testing.T) {
	if _, err := Parse(make([]byte, 10)); err == nil {
		t.Fatal("expected error for short record")
	}
}
