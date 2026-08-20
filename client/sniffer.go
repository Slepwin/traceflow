package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/traceflow/traceflow/internal/pkt"
	"github.com/traceflow/traceflow/internal/tfmeta"
)

func flagSet() *flag.FlagSet { return flag.NewFlagSet("client", flag.ExitOnError) }

// capture is a decoded marked packet seen by the sniffer.
type capture struct {
	proto    uint8
	icmpType uint8
	srcPort  uint16
	dstPort  uint16
	tcpFlags uint8
	tcpSeq   uint32
	vni      uint32
	srcIP    string
	payload  []byte
	meta     tfmeta.Meta
}

// sniffer reads frames from all interfaces via an AF_PACKET raw socket and
// decodes the marked ones (regular or VXLAN-encapsulated).
type sniffer struct {
	fd int
}

func startSniffer(f *flags) *sniffer {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("AF_PACKET socket (need root): %v", err)
	}
	// Ifindex 0 -> capture on every interface.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL)}); err != nil {
		log.Fatalf("bind AF_PACKET: %v", err)
	}
	return &sniffer{fd: fd}
}

// close releases the AF_PACKET socket.
func (s *sniffer) close() {
	if s != nil {
		unix.Close(s.fd)
	}
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// next blocks for the next decodable marked packet, up to `deadline`.
func (s *sniffer) next(deadline time.Time) (capture, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return capture{}, false
	}
	tv := unix.NsecToTimeval(remaining.Nanoseconds())
	_ = unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 65536)
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return capture{}, false
	}
	return parseMarked(buf[:n])
}

// parseMarked decodes one frame, skipping VLAN tags and following VXLAN if the
// outer UDP targets 4789. Handles both IPv4 and IPv6.
func parseMarked(frame []byte) (capture, bool) {
	var c capture
	l3, et, _, ok := stripL2(frame)
	if !ok {
		return c, false
	}

	// Peek: VXLAN? (outer IPv4 or IPv6 / UDP to port 4789)
	if ol4, isUDP := outerUDP(et, l3); isUDP && len(ol4) >= 8 &&
		binary.BigEndian.Uint16(ol4[2:4]) == tfmeta.VXLANPort {
		vxl := ol4[8:]
		if len(vxl) < 8 || vxl[0]&0x08 == 0 { // I flag: only a set VNI is valid VXLAN
			return c, false
		}
		c.vni = binary.BigEndian.Uint32(vxl[4:8]) >> 8
		inner, iet, _, ok := stripL2(vxl[8:])
		if !ok {
			return c, false
		}
		l3, et = inner, iet
	}

	var l4 []byte
	switch et {
	case pkt.EtherTypeIPv4:
		ip, rest, ok := ipv4(l3)
		if !ok || ip.tos&0xFC != tfmeta.ToS { // level-1 filter
			return c, false
		}
		c.srcIP, c.proto, l4 = ip.src.String(), ip.proto, rest
	case pkt.EtherTypeIPv6:
		ip, rest, ok := ipv6(l3)
		if !ok || ip.tos&0xFC != tfmeta.ToS {
			return c, false
		}
		c.srcIP, c.proto, l4 = ip.src.String(), ip.nextHdr, rest
	default:
		return c, false
	}

	payload, ok := l4Fields(&c, c.proto, l4)
	if !ok {
		return c, false
	}
	meta, err := tfmeta.Unmarshal(payload)
	if err != nil { // level-2 filter
		return c, false
	}
	c.meta = meta
	c.payload = payload
	return c, true
}

// l4Fields fills the transport fields of c and returns the payload after L4.
func l4Fields(c *capture, proto uint8, l4 []byte) ([]byte, bool) {
	switch proto {
	case pkt.ProtoICMP, pkt.ProtoICMPv6:
		if len(l4) < 8 {
			return nil, false
		}
		c.icmpType = l4[0]
		return l4[8:], true
	case pkt.ProtoUDP:
		if len(l4) < 8 {
			return nil, false
		}
		c.srcPort = binary.BigEndian.Uint16(l4[0:2])
		c.dstPort = binary.BigEndian.Uint16(l4[2:4])
		return l4[8:], true
	case pkt.ProtoTCP:
		if len(l4) < 20 {
			return nil, false
		}
		c.srcPort = binary.BigEndian.Uint16(l4[0:2])
		c.dstPort = binary.BigEndian.Uint16(l4[2:4])
		c.tcpSeq = binary.BigEndian.Uint32(l4[4:8])
		c.tcpFlags = l4[13]
		doff := int(l4[12]>>4) * 4
		if doff < 20 || doff > len(l4) {
			return nil, false
		}
		return l4[doff:], true
	}
	return nil, false
}

// --- tiny parsers (client-local copies) -----------------------------------

type ipHdr struct {
	tos      uint8
	proto    uint8
	src, dst net.IP
}

// stripL2 removes Ethernet + up to two VLAN tags; returns l3, ethertype, VID.
func stripL2(frame []byte) ([]byte, uint16, uint16, bool) {
	if len(frame) < 14 {
		return nil, 0, 0, false
	}
	et := binary.BigEndian.Uint16(frame[12:14])
	off := 14
	var vlan uint16
	for n := 0; n < 2 && (et == pkt.EtherTypeVLAN || et == 0x88A8); n++ {
		if len(frame) < off+4 {
			return nil, 0, 0, false
		}
		if vlan == 0 {
			vlan = binary.BigEndian.Uint16(frame[off:off+2]) & 0x0FFF
		}
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	return frame[off:], et, vlan, true
}

func ipv4(l3 []byte) (ipHdr, []byte, bool) {
	if len(l3) < 20 {
		return ipHdr{}, nil, false
	}
	ihl := int(l3[0]&0x0F) * 4
	if ihl < 20 || ihl > len(l3) {
		return ipHdr{}, nil, false
	}
	h := ipHdr{tos: l3[1], proto: l3[9], src: net.IP(l3[12:16]), dst: net.IP(l3[16:20])}
	return h, l3[ihl:], true
}

type ip6Hdr struct {
	tos     uint8
	nextHdr uint8
	src     net.IP
}

func ipv6(l3 []byte) (ip6Hdr, []byte, bool) {
	if len(l3) < 40 {
		return ip6Hdr{}, nil, false
	}
	tc := (l3[0]&0x0F)<<4 | (l3[1] >> 4)
	return ip6Hdr{tos: tc, nextHdr: l3[6], src: net.IP(l3[8:24])}, l3[40:], true
}

// outerUDP returns the L4 bytes when the outer IPv4/IPv6 header carries UDP.
func outerUDP(etherType uint16, l3 []byte) ([]byte, bool) {
	switch etherType {
	case pkt.EtherTypeIPv4:
		if ip, l4, ok := ipv4(l3); ok && ip.proto == pkt.ProtoUDP {
			return l4, true
		}
	case pkt.EtherTypeIPv6:
		if ip, l4, ok := ipv6(l3); ok && ip.nextHdr == pkt.ProtoUDP {
			return l4, true
		}
	}
	return nil, false
}
