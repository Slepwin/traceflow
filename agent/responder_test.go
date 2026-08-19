package main

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/traceflow/traceflow/internal/pkt"
	"github.com/traceflow/traceflow/internal/tfmeta"
)

var (
	clientIP = net.IPv4(10, 0, 0, 1)
	vmIP     = net.IPv4(10, 0, 0, 2)
)

// reply TCP fields (reply is IPv4[20] + TCP).
func replyTCP(t *testing.T, reply []byte) (flags uint8, seq, ack uint32) {
	t.Helper()
	if len(reply) < 40 {
		t.Fatalf("reply too short: %d", len(reply))
	}
	tcp := reply[20:]
	return tcp[13], binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12])
}

func newTestResponder(tcp bool) *responder {
	return &responder{tcpRespond: tcp, flows: map[string]*tcpFlow{}}
}

func meta() []byte {
	return tfmeta.Meta{NeedResponse: true}.Marshal()
}

func TestTCPHandshakeSequence(t *testing.T) {
	r := newTestResponder(true)
	const sport, dport = uint16(40000), uint16(80)
	const clientISN = uint32(0x2000)
	isn := serverISN(clientIP, vmIP, sport, dport)

	// SYN -> SYN/ACK, seq=isn, ack=clientISN+1
	syn := pkt.TCP(clientIP, vmIP, sport, dport, clientISN, 0, pkt.FlagSYN, meta())
	fl, seq, ack := replyTCP(t, r.buildTCPReply(clientIP, vmIP, syn, false))
	if fl != pkt.FlagSYN|pkt.FlagACK {
		t.Fatalf("SYN reply flags = %#x, want SYN|ACK", fl)
	}
	if seq != isn || ack != clientISN+1 {
		t.Fatalf("SYN/ACK seq=%#x ack=%#x, want %#x/%#x", seq, ack, isn, clientISN+1)
	}

	// data -> PSH/ACK, our seq = isn+1, ack = clientISN+1+len(data).
	// meta must lead the payload (magic at offset 0), label follows.
	data := append(meta(), []byte("PING")...)
	psh := pkt.TCP(clientIP, vmIP, sport, dport, clientISN+1, isn+1, pkt.FlagPSH|pkt.FlagACK, data)
	fl, seq, ack = replyTCP(t, r.buildTCPReply(clientIP, vmIP, psh, false))
	if fl != pkt.FlagPSH|pkt.FlagACK {
		t.Fatalf("data reply flags = %#x, want PSH|ACK", fl)
	}
	if seq != isn+1 {
		t.Fatalf("data reply seq = %#x, want %#x", seq, isn+1)
	}
	if ack != clientISN+1+uint32(len(data)) {
		t.Fatalf("data reply ack = %#x, want %#x", ack, clientISN+1+uint32(len(data)))
	}

	// FIN -> FIN/ACK, and the flow is forgotten
	fin := pkt.TCP(clientIP, vmIP, sport, dport, clientISN+1, isn+1, pkt.FlagFIN|pkt.FlagACK, nil)
	fl, _, _ = replyTCP(t, r.buildTCPReply(clientIP, vmIP, fin, false))
	if fl != pkt.FlagFIN|pkt.FlagACK {
		t.Fatalf("FIN reply flags = %#x, want FIN|ACK", fl)
	}
	if len(r.flows) != 0 {
		t.Fatalf("flow not cleaned up after FIN: %d entries", len(r.flows))
	}
}

func TestVLANFromAuxData(t *testing.T) {
	// tpacket_auxdata with TP_STATUS_VLAN_VALID and vlan_tci carrying VID 42.
	d := make([]byte, 20)
	binary.NativeEndian.PutUint32(d[0:4], 0x10)  // status: VLAN_VALID
	binary.NativeEndian.PutUint16(d[16:18], 42)  // vlan_tci -> VID 42
	if v, ok := vlanFromAuxData(d); !ok || v != 42 {
		t.Fatalf("vlanFromAuxData = %d,%v, want 42,true", v, ok)
	}
	// Without the valid bit -> no VLAN.
	binary.NativeEndian.PutUint32(d[0:4], 0)
	if _, ok := vlanFromAuxData(d); ok {
		t.Fatal("expected no VLAN when TP_STATUS_VLAN_VALID unset")
	}
	// Short buffer -> no VLAN.
	if _, ok := vlanFromAuxData(d[:10]); ok {
		t.Fatal("expected no VLAN for short aux data")
	}
}

func TestHMACGateResponder(t *testing.T) {
	key := []byte("k")
	r := newTestResponder(true)
	r.hmacKey = key
	// A signed ICMP echo request with need_response should be answered.
	signed := tfmeta.Meta{NeedResponse: true}.Signed(key)
	icmp := pkt.ICMP(pkt.ICMPEchoRequest, 1, 1, signed)
	l3 := pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoICMP, clientIP, vmIP, icmp)
	r.localIPs = map[[16]byte]bool{key16(vmIP): true}
	if got := r.buildReply(pkt.EtherTypeIPv4, l3); got == nil {
		t.Fatal("signed request should be answered")
	}
	// The same request unsigned must be rejected.
	unsigned := tfmeta.Meta{NeedResponse: true}.Marshal()
	icmp = pkt.ICMP(pkt.ICMPEchoRequest, 1, 1, unsigned)
	l3 = pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoICMP, clientIP, vmIP, icmp)
	if got := r.buildReply(pkt.EtherTypeIPv4, l3); got != nil {
		t.Fatal("unsigned request must not be answered under a key")
	}
}

func TestTCPRespondDisabled(t *testing.T) {
	r := newTestResponder(false)
	syn := pkt.TCP(clientIP, vmIP, 40000, 80, 0x2000, 0, pkt.FlagSYN, meta())
	if got := r.buildTCPReply(clientIP, vmIP, syn, false); got != nil {
		t.Fatalf("tcp-respond=false should not reply, got %d bytes", len(got))
	}
}
