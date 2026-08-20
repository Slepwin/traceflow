package main

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/traceflow/traceflow/internal/pkt"
	"github.com/traceflow/traceflow/internal/tfmeta"
)

// responder sniffs the interface with an AF_PACKET raw socket and replies to
// marked packets that set need_response=1 — but ONLY when the inner destination
// is one of this agent's local VM addresses. Transit hops and tunnel/VTEP nodes
// (no local VM address) never answer; they only observe via the ring buffer,
// which is independent of this responder. Replies go straight to the wire (L2),
// preserving any VLAN tag and mirroring the address family (v4/v6). Because the
// request was addressed TO the VM, the address swap re-uses the VM's own MAC/IP
// as the reply source — what OVN port security expects.
type responder struct {
	iface      *net.Interface
	ifType     uint8
	fd         int
	localIPs   map[[16]byte]bool
	tcpRespond bool
	hmacKey    []byte              // if set, requests must carry a valid HMAC
	flows      map[string]*tcpFlow // per 4-tuple TCP state (Loop is single-goroutine)
}

// tcpFlow is the minimal server-side state for one TCP connection we answer.
type tcpFlow struct {
	serverNext uint32 // next sequence number we will send
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func newResponder(iface *net.Interface, ifType uint8, localIPs []net.IP, tcpRespond bool, hmacKey []byte) (*responder, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	ll := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: iface.Index}
	if err := unix.Bind(fd, ll); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Ask the kernel for per-packet aux data so we recover VLAN tags that NIC
	// acceleration strips from the frame bytes (offload). Best-effort.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		log.Printf("responder: PACKET_AUXDATA unavailable, offloaded VLANs may be missed: %v", err)
	}
	set := make(map[[16]byte]bool, len(localIPs))
	for _, ip := range localIPs {
		set[key16(ip)] = true
	}
	return &responder{
		iface: iface, ifType: ifType, fd: fd, localIPs: set,
		tcpRespond: tcpRespond, hmacKey: hmacKey, flows: map[string]*tcpFlow{},
	}, nil
}

// authOK reports whether the request payload is authenticated (or auth is off).
// A bad HMAC is counted and rejected — this is what stops a spoofed marker from
// triggering a reply (amplification / probe of internals).
func (r *responder) authOK(payload []byte) bool {
	if len(r.hmacKey) == 0 {
		return true
	}
	if tfmeta.Verify(payload, r.hmacKey) {
		return true
	}
	mtr.authFailures.Add(1)
	return false
}

func key16(ip net.IP) [16]byte {
	var k [16]byte
	copy(k[:], ip.To16())
	return k
}

// isLocal reports whether ip is one of this agent's local VM destinations — i.e.
// whether this node is the packet's final destination (works for v4 and v6).
func (r *responder) isLocal(ip net.IP) bool { return r.localIPs[key16(ip)] }

func (r *responder) Close() error { return unix.Close(r.fd) }

func (r *responder) send(frame []byte) {
	ll := &unix.SockaddrLinklayer{Ifindex: r.iface.Index, Halen: 6}
	copy(ll.Addr[:6], frame[0:6]) // destination MAC
	if err := unix.Sendto(r.fd, frame, 0, ll); err != nil {
		log.Printf("responder send: %v", err)
		return
	}
	mtr.repliesSent.Add(1)
}

func (r *responder) Loop() {
	buf := make([]byte, 65536)
	oob := make([]byte, 128) // room for the PACKET_AUXDATA control message
	for {
		n, oobn, _, _, err := unix.Recvmsg(r.fd, buf, oob, 0)
		if err != nil {
			if err == unix.EBADF || err == unix.EINTR {
				return
			}
			// Unexpected error (e.g. the interface going down): back off so a
			// sticky condition doesn't spin this goroutine at 100% CPU.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		auxVlan := auxVLAN(oob[:oobn])
		frame := make([]byte, n)
		copy(frame, buf[:n])
		r.handle(frame, auxVlan)
	}
}

// auxVLAN extracts a VLAN VID from a PACKET_AUXDATA control message, or 0 if the
// tag was not stripped (present in the frame bytes) / not offloaded.
func auxVLAN(oob []byte) uint16 {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, scm := range scms {
		if scm.Header.Level != unix.SOL_PACKET || scm.Header.Type != unix.PACKET_AUXDATA {
			continue
		}
		if v, ok := vlanFromAuxData(scm.Data); ok {
			return v
		}
	}
	return 0
}

// vlanFromAuxData decodes a struct tpacket_auxdata:
// status,len,snaplen (u32 x3), mac,net,vlan_tci,vlan_tpid (u16 x4) -> vlan_tci
// at offset 16. Returns the VID when TP_STATUS_VLAN_VALID is set.
func vlanFromAuxData(d []byte) (uint16, bool) {
	const tpStatusVLANValid = 0x10 // TP_STATUS_VLAN_VALID
	if len(d) < 20 {
		return 0, false
	}
	status := binary.NativeEndian.Uint32(d[0:4])
	if status&tpStatusVLANValid == 0 {
		return 0, false
	}
	return binary.NativeEndian.Uint16(d[16:18]) & 0x0FFF, true
}

// handle dispatches by configured mode; AUTO picks VXLAN vs regular the same way
// the eBPF program does. auxVlan is the offloaded (stripped) outermost VLAN, 0 if
// the tag is inline or absent.
func (r *responder) handle(frame []byte, auxVlan uint16) {
	switch r.ifType {
	case tfmeta.IfaceVXLAN:
		r.handleVXLAN(frame, auxVlan)
	case tfmeta.IfaceRegular:
		r.handleRegular(frame, auxVlan)
	default:
		if isVXLANFrame(frame) {
			r.handleVXLAN(frame, auxVlan)
		} else {
			r.handleRegular(frame, auxVlan)
		}
	}
}

func isVXLANFrame(frame []byte) bool {
	l2, ok := parseL2(frame)
	if !ok {
		return false
	}
	_, _, l4, ok := outerUDP(l2.etherType, l2.l3)
	return ok && len(l4) >= 8 && binary.BigEndian.Uint16(l4[2:4]) == tfmeta.VXLANPort
}

// outerUDP parses an outer IPv4/IPv6 header and returns (src,dst, l4, ok) when
// the next protocol is UDP. Used for VXLAN over either underlay family.
func outerUDP(etherType uint16, l3 []byte) (src, dst net.IP, l4 []byte, ok bool) {
	switch etherType {
	case pkt.EtherTypeIPv4:
		ip, rest, o := parseIPv4(l3)
		if !o || ip.proto != pkt.ProtoUDP {
			return nil, nil, nil, false
		}
		return ip.src, ip.dst, rest, true
	case pkt.EtherTypeIPv6:
		ip, rest, o := parseIPv6(l3)
		if !o || ip.nextHdr != pkt.ProtoUDP {
			return nil, nil, nil, false
		}
		return ip.src, ip.dst, rest, true
	}
	return nil, nil, nil, false
}

// --- regular path ---------------------------------------------------------

func (r *responder) handleRegular(frame []byte, auxVlan uint16) {
	l2, ok := parseL2(frame)
	if !ok {
		return
	}
	reply := r.buildReply(l2.etherType, l2.l3)
	if reply != nil {
		// Re-insert the tag: inline VID if the request carried one, else the
		// offloaded VID lifted from aux data.
		r.send(frameL2(l2.src, l2.dst, orVlan(l2.vlan, auxVlan), l2.etherType, reply))
	}
}

// orVlan returns the inline VID if set, otherwise the aux (offloaded) VID.
func orVlan(inline, aux uint16) uint16 {
	if inline != 0 {
		return inline
	}
	return aux
}

// --- vxlan path -----------------------------------------------------------

func (r *responder) handleVXLAN(frame []byte, auxVlan uint16) {
	oL2, ok := parseL2(frame)
	if !ok {
		return
	}
	osrc, odst, ol4, ok := outerUDP(oL2.etherType, oL2.l3)
	if !ok || len(ol4) < 8 || binary.BigEndian.Uint16(ol4[2:4]) != tfmeta.VXLANPort {
		return
	}
	vxl := ol4[8:]
	if len(vxl) < 8 || vxl[0]&0x08 == 0 { // I flag: only a set VNI is valid VXLAN
		return
	}
	vni := binary.BigEndian.Uint32(vxl[4:8]) >> 8

	iL2, ok := parseL2(vxl[8:])
	if !ok {
		return
	}
	innerReply := r.buildReply(iL2.etherType, iL2.l3)
	if innerReply == nil {
		return
	}

	// Re-encapsulate: swap MACs/IPs at every layer, keep the same VNI, the inner
	// VLAN tag, and the outer address family (v4 or v6).
	innerEth := frameL2(iL2.src, iL2.dst, iL2.vlan, iL2.etherType, innerReply)
	vxlan := pkt.VXLAN(vni, innerEth)
	var outerIP []byte
	if oL2.etherType == pkt.EtherTypeIPv6 {
		udp := pkt.UDP6(odst, osrc, tfmeta.VXLANPort, tfmeta.VXLANPort, vxlan)
		outerIP = pkt.IPv6(0, tfmeta.TTLMax, pkt.ProtoUDP, odst, osrc, udp)
	} else {
		udp := pkt.UDP(odst, osrc, tfmeta.VXLANPort, tfmeta.VXLANPort, vxlan)
		outerIP = pkt.IPv4(0, tfmeta.TTLMax, pkt.ProtoUDP, odst, osrc, udp)
	}
	// The offloaded tag (if any) belongs to the outer/underlay frame.
	r.send(frameL2(oL2.src, oL2.dst, orVlan(oL2.vlan, auxVlan), oL2.etherType, outerIP))
}

// buildReply parses an inbound L3 packet (v4 or v6) and returns the IPv4/IPv6
// reply payload (without Ethernet), or nil if no reply is warranted. Gated on
// the destination being local.
func (r *responder) buildReply(etherType uint16, l3 []byte) []byte {
	var src, dst net.IP
	var proto uint8
	var l4 []byte
	var v6 bool

	switch etherType {
	case pkt.EtherTypeIPv4:
		ip, rest, ok := parseIPv4(l3)
		if !ok || ip.tos&0xFC != tfmeta.ToS { // level-1 filter
			return nil
		}
		src, dst, proto, l4 = ip.src, ip.dst, ip.proto, rest
	case pkt.EtherTypeIPv6:
		ip, rest, ok := parseIPv6(l3)
		if !ok || ip.tos&0xFC != tfmeta.ToS {
			return nil
		}
		src, dst, proto, l4, v6 = ip.src, ip.dst, ip.nextHdr, rest, true
	default:
		return nil
	}

	// Answer only for the local destination VM; transit/VTEP nodes only observe.
	if !r.isLocal(dst) {
		return nil
	}
	return r.buildReplyL4(src, dst, proto, l4, v6)
}

func (r *responder) buildReplyL4(src, dst net.IP, proto uint8, l4 []byte, v6 bool) []byte {
	switch {
	case proto == pkt.ProtoICMP || proto == pkt.ProtoICMPv6:
		if len(l4) < 8 {
			return nil
		}
		payload := l4[8:]
		meta, err := tfmeta.Unmarshal(payload)
		if err != nil || !meta.NeedResponse || !r.authOK(payload) {
			return nil
		}
		id := binary.BigEndian.Uint16(l4[4:6])
		seq := binary.BigEndian.Uint16(l4[6:8])
		if v6 {
			icmp := pkt.ICMPv6(pkt.ICMPv6EchoReply, id, seq, dst, src, r.sanitize(payload))
			return pkt.IPv6(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoICMPv6, dst, src, icmp)
		}
		icmp := pkt.ICMP(pkt.ICMPEchoReply, id, seq, r.sanitize(payload))
		return pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoICMP, dst, src, icmp)

	case proto == pkt.ProtoUDP:
		if len(l4) < 8 {
			return nil
		}
		payload := l4[8:]
		meta, err := tfmeta.Unmarshal(payload)
		if err != nil || !meta.NeedResponse || !r.authOK(payload) {
			return nil
		}
		sport := binary.BigEndian.Uint16(l4[0:2])
		dport := binary.BigEndian.Uint16(l4[2:4])
		if v6 {
			udp := pkt.UDP6(dst, src, dport, sport, r.sanitize(payload))
			return pkt.IPv6(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoUDP, dst, src, udp)
		}
		udp := pkt.UDP(dst, src, dport, sport, r.sanitize(payload))
		return pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoUDP, dst, src, udp)

	case proto == pkt.ProtoTCP:
		return r.buildTCPReply(src, dst, l4, v6)
	}
	return nil
}

// buildTCPReply is a minimal but sequence-correct userspace TCP responder:
//
//	SYN            -> SYN/ACK  (server ISN derived from the 4-tuple)
//	data (PSH)     -> ACK + echoed data, advancing our sequence
//	FIN            -> FIN/ACK  and the flow is forgotten
//
// State per connection lives in r.flows; the reader Loop is single-goroutine so
// no locking is needed. Disabled with --tcp-respond=false so the real VM stack
// answers instead (avoids double-replies to a live service).
func (r *responder) buildTCPReply(src, dst net.IP, tcp []byte, v6 bool) []byte {
	if !r.tcpRespond || len(tcp) < 20 {
		return nil
	}
	sport := binary.BigEndian.Uint16(tcp[0:2])
	dport := binary.BigEndian.Uint16(tcp[2:4])
	clientSeq := binary.BigEndian.Uint32(tcp[4:8])
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return nil
	}
	flags := tcp[13]
	data := tcp[doff:]
	key := flowKey(src, dst, sport, dport)

	// A RST only tears down our flow state; it elicits no reply, so it needs no
	// auth and emits nothing.
	if flags&pkt.FlagRST != 0 {
		delete(r.flows, key)
		return nil
	}

	// Every TCP segment that would elicit a reply must carry a valid, authenticated
	// meta that asks for a response — the same gate the ICMP/UDP paths apply. The
	// real client signs every segment (SYN, ACK, data, FIN), so this never rejects
	// a genuine probe, but it stops a bare or unsigned SYN/FIN (ToS=0xF8 aimed at a
	// known VM IP) from reflecting a SYN/ACK or FIN/ACK — closing the amplification
	// and probing vector that would otherwise bypass --hmac-key on the TCP path.
	meta, err := tfmeta.Unmarshal(data)
	if err != nil || !meta.NeedResponse || !r.authOK(data) {
		return nil
	}

	mk := func(seq, ack uint32, fl uint8, payload []byte) []byte {
		if v6 {
			seg := pkt.TCP6(dst, src, dport, sport, seq, ack, fl, payload)
			return pkt.IPv6(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoTCP, dst, src, seg)
		}
		seg := pkt.TCP(dst, src, dport, sport, seq, ack, fl, payload)
		return pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoTCP, dst, src, seg)
	}

	switch {
	case flags&pkt.FlagSYN != 0 && flags&pkt.FlagACK == 0:
		isn := serverISN(src, dst, sport, dport)
		if len(r.flows) > 4096 { // crude cap against leaks
			r.flows = map[string]*tcpFlow{}
		}
		// Echo the meta so the SYN/ACK is itself marked (observable on the
		// return path) and the client can correlate it by run id. The SYN flag
		// consumes one sequence number and the echoed payload consumes len(echo)
		// more, so our next sequence advances past both — otherwise the later
		// data reply would overlap the SYN/ACK's own sequence space.
		echo := r.sanitize(data)
		r.flows[key] = &tcpFlow{serverNext: isn + 1 + uint32(len(echo))}
		return mk(isn, clientSeq+1, pkt.FlagSYN|pkt.FlagACK, echo)

	case flags&pkt.FlagFIN != 0:
		f := r.flows[key]
		seq := serverISN(src, dst, sport, dport) + 1
		if f != nil {
			seq = f.serverNext
		}
		delete(r.flows, key)
		return mk(seq, clientSeq+uint32(len(data))+1, pkt.FlagFIN|pkt.FlagACK, r.sanitize(data))

	case flags&pkt.FlagPSH != 0 && len(data) > 0:
		f := r.flows[key]
		if f == nil { // data without a tracked handshake — start from derived ISN
			f = &tcpFlow{serverNext: serverISN(src, dst, sport, dport) + 1}
			r.flows[key] = f
		}
		echo := r.sanitize(data)
		seg := mk(f.serverNext, clientSeq+uint32(len(data)), pkt.FlagPSH|pkt.FlagACK, echo)
		f.serverNext += uint32(len(echo))
		return seg
	}
	return nil
}

// flowKey identifies a connection by its 4-tuple (client side first).
func flowKey(src, dst net.IP, sport, dport uint16) string {
	return fmt.Sprintf("%s:%d>%s:%d", src, sport, dst, dport)
}

// serverISN derives a stable initial sequence number from the 4-tuple, so the
// handshake is deterministic without needing a RNG.
func serverISN(src, dst net.IP, sport, dport uint16) uint32 {
	h := fnv.New32a()
	h.Write(src.To16())
	h.Write(dst.To16())
	var p [4]byte
	binary.BigEndian.PutUint16(p[0:2], sport)
	binary.BigEndian.PutUint16(p[2:4], dport)
	h.Write(p[:])
	return h.Sum32()
}

// sanitize copies a payload, clears the intercept/need_response bytes (so the
// echoed packet is observed on the return path but triggers no second response),
// and re-signs it when HMAC auth is on (so the return-path packet stays valid).
func (r *responder) sanitize(p []byte) []byte {
	out := make([]byte, len(p))
	copy(out, p)
	if len(out) >= tfmeta.MetaSize {
		out[20] = 0 // intercept
		out[21] = 0 // need_response
	}
	if len(r.hmacKey) > 0 && len(out) >= tfmeta.SignedSize {
		copy(out[tfmeta.MetaSize:tfmeta.SignedSize], tfmeta.Sign(out[:tfmeta.MetaSize], r.hmacKey))
	}
	return out
}

// --- tiny parsers ---------------------------------------------------------

type l2info struct {
	dst, src  net.HardwareAddr
	etherType uint16
	vlan      uint16
	l3        []byte
}

// parseL2 strips Ethernet and up to two VLAN tags, returning the outermost VID.
func parseL2(frame []byte) (l2info, bool) {
	if len(frame) < 14 {
		return l2info{}, false
	}
	i := l2info{dst: net.HardwareAddr(frame[0:6]), src: net.HardwareAddr(frame[6:12])}
	et := binary.BigEndian.Uint16(frame[12:14])
	off := 14
	for n := 0; n < 2 && (et == pkt.EtherTypeVLAN || et == 0x88A8); n++ {
		if len(frame) < off+4 {
			return l2info{}, false
		}
		if i.vlan == 0 {
			i.vlan = binary.BigEndian.Uint16(frame[off:off+2]) & 0x0FFF
		}
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	i.etherType = et
	i.l3 = frame[off:]
	return i, true
}

func frameL2(dstMAC, srcMAC net.HardwareAddr, vlan uint16, etherType uint16, payload []byte) []byte {
	if vlan != 0 {
		return pkt.EthernetVLAN(dstMAC, srcMAC, vlan, etherType, payload)
	}
	return pkt.Ethernet(dstMAC, srcMAC, etherType, payload)
}

type ipInfo struct {
	tos      uint8
	proto    uint8
	src, dst net.IP
}

func parseIPv4(l3 []byte) (ipInfo, []byte, bool) {
	if len(l3) < 20 {
		return ipInfo{}, nil, false
	}
	ihl := int(l3[0]&0x0F) * 4
	if ihl < 20 || ihl > len(l3) {
		return ipInfo{}, nil, false
	}
	return ipInfo{tos: l3[1], proto: l3[9], src: net.IP(l3[12:16]), dst: net.IP(l3[16:20])}, l3[ihl:], true
}

type ip6Info struct {
	tos      uint8
	nextHdr  uint8
	src, dst net.IP
}

// parseIPv6 reads a fixed IPv6 header (no extension headers, matching probes).
func parseIPv6(l3 []byte) (ip6Info, []byte, bool) {
	if len(l3) < 40 {
		return ip6Info{}, nil, false
	}
	tc := (l3[0]&0x0F)<<4 | (l3[1] >> 4)
	return ip6Info{tos: tc, nextHdr: l3[6], src: net.IP(l3[8:24]), dst: net.IP(l3[24:40])}, l3[40:], true
}
