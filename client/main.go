// Command client sends marked traceflow probes — the diagnostic driver that a
// monitoring system triggers. Every probe carries DSCP=62, TTL=255 and a
// traceflow_meta control block, so agents along the path observe it.
//
// Sub-commands:
//
//	icmp   ICMP echo request        (--response waits for echo reply)
//	udp    UDP datagram             (--response waits for a UDP reply)
//	htcp   TCP handshake            (SYN -> SYN/ACK -> ACK)
//	tcp    TCP handshake + data + FIN (full dialog)
//	vxlan  VXLAN-encapsulated marked ICMP with a given VNI
//
// Packets are sent with an AF_INET raw socket (IP_HDRINCL), so we set the ToS,
// TTL and payload ourselves and let the kernel route. Replies are captured with
// an AF_PACKET sniffer (all interfaces), matched by run UUID — this sidesteps
// the kernel's own TCP/UDP stack, which would otherwise RST or reject our
// hand-crafted flows.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/traceflow/traceflow/internal/ovs"
	"github.com/traceflow/traceflow/internal/pkt"
	"github.com/traceflow/traceflow/internal/tfmeta"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := newFlags(cmd)
	fs.parse(os.Args[2:])
	applyAsVM(fs)

	switch cmd {
	case "icmp":
		runICMP(fs)
	case "udp":
		runUDP(fs)
	case "htcp":
		runTCP(fs, false)
	case "tcp":
		runTCP(fs, true)
	case "vxlan":
		runVXLAN(fs)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: client <icmp|udp|htcp|tcp|vxlan> [flags]")
	fmt.Fprintln(os.Stderr, "  common: --dst IP(v4/v6) [--src IP] [--response] [--deliver] [--timeout 2s]")
	fmt.Fprintln(os.Stderr, "  udp/htcp/tcp: --dport N [--sport N]")
	fmt.Fprintln(os.Stderr, "  ipv6/vlan (L2 send): --iface NAME --dst-mac MAC [--vlan VID] [--src-mac MAC]")
	fmt.Fprintln(os.Stderr, "  --as-vm: fill src IP/MAC from the OVS tap (--iface) for OVN port security")
	fmt.Fprintln(os.Stderr, "  vxlan: --dst VTEP --inner-src IP --inner-dst IP --vni N")
	os.Exit(2)
}

// --- flags ----------------------------------------------------------------

type flags struct {
	src, dst           string
	innerSrc, innerDst string
	sport, dport, vni  int
	vlan               int
	iface              string
	dstMAC, srcMAC     string
	asVM               bool
	hmacKey            string
	response, deliver  bool
	timeout            time.Duration
}

// payload returns the meta signed with the shared key (or bare if no key).
func (f *flags) payload(m tfmeta.Meta) []byte { return m.Signed([]byte(f.hmacKey)) }

func newFlags(cmd string) *flags { return &flags{sport: 40000, timeout: 2 * time.Second} }

func (f *flags) parse(args []string) {
	fs := flagSet()
	fs.StringVar(&f.src, "src", "", "source IP (default: auto)")
	fs.StringVar(&f.dst, "dst", "", "destination IP, v4 or v6 (required)")
	fs.StringVar(&f.innerSrc, "inner-src", "", "inner source IP (vxlan)")
	fs.StringVar(&f.innerDst, "inner-dst", "", "inner destination IP (vxlan)")
	fs.IntVar(&f.sport, "sport", 40000, "source port")
	fs.IntVar(&f.dport, "dport", 0, "destination port")
	fs.IntVar(&f.vni, "vni", 0, "VXLAN VNI")
	fs.IntVar(&f.vlan, "vlan", 0, "802.1Q VLAN id to tag the probe with (0 = untagged)")
	fs.StringVar(&f.iface, "iface", "", "interface for L2 send (required for IPv6/VLAN)")
	fs.StringVar(&f.dstMAC, "dst-mac", "", "next-hop MAC for L2 send (required for IPv6/VLAN)")
	fs.StringVar(&f.srcMAC, "src-mac", "", "source MAC for L2 send (default: iface MAC)")
	fs.BoolVar(&f.asVM, "as-vm", false, "resolve src IP/MAC from the OVS tap (--iface) so OVN port security passes")
	fs.StringVar(&f.hmacKey, "hmac-key", "", "shared secret to sign the probe (must match the agent's --hmac-key)")
	fs.BoolVar(&f.response, "response", false, "wait for a response")
	fs.BoolVar(&f.deliver, "deliver", false, "deliver the probe to the destination VM (the agent does not intercept or answer; the VM's own stack replies)")
	fs.DurationVar(&f.timeout, "timeout", 2*time.Second, "response timeout")
	_ = fs.Parse(args)
	if f.dst == "" {
		usage()
	}
}

// --- meta helpers ---------------------------------------------------------

func (f *flags) newMeta() (tfmeta.Meta, [16]byte) {
	id := uuid.New()
	m := tfmeta.Meta{
		ID:           id,
		Deliver:      f.deliver,
		NeedResponse: f.response,
		Timestamp:    uint64(time.Now().UnixNano()),
	}
	return m, id
}

func srcIP(f *flags, dst net.IP) net.IP {
	if f.src != "" {
		return net.ParseIP(f.src)
	}
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		log.Fatalf("cannot determine source IP (use --src): %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP
}

// --- ICMP -----------------------------------------------------------------

func runICMP(f *flags) {
	dst := mustIP(f.dst)
	src := srcIP(f, dst)
	meta, id := f.newMeta()

	sn := startSniffer(f)
	defer sn.close()
	l3, v6 := icmpL3(src, dst, 0x1234, 1, f.payload(meta))
	emit(f, dst, l3, v6)
	log.Printf("sent marked ICMP%s %s -> %s (id=%s)", v6tag(v6), src, dst, uuid.UUID(id))

	if f.response {
		waitReply(sn, f, id, isEchoReply, "ICMP echo reply")
	}
}

// --- UDP ------------------------------------------------------------------

func runUDP(f *flags) {
	if f.dport == 0 {
		f.dport = 7
	}
	dst := mustIP(f.dst)
	src := srcIP(f, dst)
	meta, id := f.newMeta()

	sn := startSniffer(f)
	defer sn.close()
	l3, v6 := udpL3(src, dst, uint16(f.sport), uint16(f.dport), f.payload(meta))
	emit(f, dst, l3, v6)
	log.Printf("sent marked UDP%s %s:%d -> %s:%d (id=%s)", v6tag(v6), src, f.sport, dst, f.dport, uuid.UUID(id))

	if f.response {
		waitReply(sn, f, id, func(c capture) bool {
			return c.proto == pkt.ProtoUDP && c.dstPort == uint16(f.sport)
		}, "UDP reply")
	}
}

// --- TCP (htcp: handshake only; tcp: full dialog with data + FIN) ----------

func runTCP(f *flags, withData bool) {
	if f.dport == 0 {
		f.dport = 80
	}
	dst := mustIP(f.dst)
	src := srcIP(f, dst)
	sp, dp := uint16(f.sport), uint16(f.dport)
	const clientISN = 0x2000

	sn := startSniffer(f)
	defer sn.close()
	meta, id := f.newMeta()
	v6 := isV6(dst)

	// SYN (carries meta so agents observe it).
	send := func(seq, ack uint32, fl uint8, payload []byte) {
		var l3 []byte
		if v6 {
			seg := pkt.TCP6(src, dst, sp, dp, seq, ack, fl, payload)
			l3 = pkt.IPv6(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoTCP, src, dst, seg)
		} else {
			seg := pkt.TCP(src, dst, sp, dp, seq, ack, fl, payload)
			l3 = pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoTCP, src, dst, seg)
		}
		emit(f, dst, l3, v6)
	}
	send(clientISN, 0, pkt.FlagSYN, f.payload(meta))
	log.Printf("SYN%s %s:%d -> %s:%d (id=%s)", v6tag(v6), src, sp, dst, dp, uuid.UUID(id))

	// Await SYN/ACK.
	synack, ok := recvMatch(sn, f, id, func(c capture) bool {
		return c.proto == pkt.ProtoTCP && c.dstPort == sp &&
			c.tcpFlags&pkt.FlagSYN != 0 && c.tcpFlags&pkt.FlagACK != 0
	})
	if !ok {
		log.Printf("no SYN/ACK within %s", f.timeout)
		return
	}
	serverISN := synack.tcpSeq
	log.Printf("got SYN/ACK (server seq=%#x)", serverISN)

	// ACK.
	send(clientISN+1, serverISN+1, pkt.FlagACK, f.payload(meta))
	log.Printf("ACK — handshake complete")

	if !withData {
		return
	}

	// Data segment: meta MUST lead the payload (that's where eBPF and the
	// responder look for the magic); a human-readable label follows.
	data := append(f.payload(meta), []byte("TRACEFLOW-PING")...)
	send(clientISN+1, serverISN+1, pkt.FlagPSH|pkt.FlagACK, data)
	log.Printf("sent data (%d bytes)", len(data))
	if dr, ok := recvMatch(sn, f, id, func(c capture) bool {
		return c.proto == pkt.ProtoTCP && c.dstPort == sp && c.tcpFlags&pkt.FlagPSH != 0
	}); ok {
		log.Printf("got data reply (%d bytes)", len(dr.payload))
	}

	// FIN.
	send(clientISN+1+uint32(len(data)), serverISN+1, pkt.FlagFIN|pkt.FlagACK, f.payload(meta))
	if _, ok := recvMatch(sn, f, id, func(c capture) bool {
		return c.proto == pkt.ProtoTCP && c.dstPort == sp && c.tcpFlags&pkt.FlagFIN != 0
	}); ok {
		log.Printf("got FIN/ACK — session closed")
	}
}

// --- VXLAN ----------------------------------------------------------------

func runVXLAN(f *flags) {
	if f.innerSrc == "" || f.innerDst == "" || f.vni == 0 {
		log.Fatal("vxlan requires --inner-src, --inner-dst and --vni")
	}
	outerDst := mustIP(f.dst)
	outerSrc := srcIP(f, outerDst)
	innerSrc := mustIP(f.innerSrc)
	innerDst := mustIP(f.innerDst)
	meta, id := f.newMeta()

	sn := startSniffer(f)
	defer sn.close()

	// Inner marked ICMP/ICMPv6 echo request (outer is always IPv4/UDP).
	innerIP, innerV6 := icmpL3(innerSrc, innerDst, 0x1234, 1, f.payload(meta))
	innerEt := uint16(pkt.EtherTypeIPv4)
	if innerV6 {
		innerEt = pkt.EtherTypeIPv6
	}
	dummyMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	innerEth := pkt.Ethernet(dummyMAC, dummyMAC, innerEt, innerIP)
	vxlan := pkt.VXLAN(uint32(f.vni), innerEth)

	// Outer underlay may itself be IPv4 or IPv6.
	outerV6 := isV6(outerDst)
	var outerL3 []byte
	if outerV6 {
		udp := pkt.UDP6(outerSrc, outerDst, uint16(f.sport), tfmeta.VXLANPort, vxlan)
		outerL3 = pkt.IPv6(0, tfmeta.TTLMax, pkt.ProtoUDP, outerSrc, outerDst, udp)
	} else {
		udp := pkt.UDP(outerSrc, outerDst, uint16(f.sport), tfmeta.VXLANPort, vxlan)
		outerL3 = pkt.IPv4(0, tfmeta.TTLMax, pkt.ProtoUDP, outerSrc, outerDst, udp)
	}
	emit(f, outerDst, outerL3, outerV6)
	log.Printf("sent VXLAN(vni=%d) marked ICMP%s %s -> %s over %s%s -> %s (id=%s)",
		f.vni, v6tag(innerV6), innerSrc, innerDst, v6tag(outerV6), outerSrc, outerDst, uuid.UUID(id))

	if f.response {
		waitReply(sn, f, id, func(c capture) bool {
			return c.vni == uint32(f.vni) && isEchoReply(c)
		}, "VXLAN ICMP echo reply")
	}
}

// --- send / receive -------------------------------------------------------

// applyAsVM fills --src / --src-mac from the OVS tap named by --iface so the
// injected probe carries the VM's real addresses (OVN port security allows only
// those). Because --iface is set, emit() already takes the L2 path.
func applyAsVM(f *flags) {
	if !f.asVM {
		return
	}
	if f.iface == "" {
		log.Fatal("--as-vm requires --iface (the VM's tap)")
	}
	port, err := ovs.LookupPort(context.Background(), f.iface)
	if err != nil {
		log.Fatalf("--as-vm: %v", err)
	}
	if f.srcMAC == "" {
		f.srcMAC = port.MAC
	}
	if f.src == "" {
		wantV6 := isV6(mustIP(f.dst))
		for _, ip := range port.IPs {
			if isV6(ip) == wantV6 {
				f.src = ip.String()
				break
			}
		}
	}
	if f.src == "" || f.srcMAC == "" {
		log.Fatalf("--as-vm: could not resolve src (ip=%q mac=%q) for tap %s", f.src, f.srcMAC, f.iface)
	}
	log.Printf("--as-vm: src=%s src-mac=%s (tap %s)", f.src, f.srcMAC, f.iface)
}

func isV6(ip net.IP) bool { return ip.To4() == nil }

func v6tag(v6 bool) string {
	if v6 {
		return "v6"
	}
	return ""
}

// icmpL3 builds an IPv4+ICMP or IPv6+ICMPv6 echo request; returns (l3, isV6).
func icmpL3(src, dst net.IP, id, seq uint16, payload []byte) ([]byte, bool) {
	if isV6(dst) {
		ic := pkt.ICMPv6(pkt.ICMPv6EchoRequest, id, seq, src, dst, payload)
		return pkt.IPv6(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoICMPv6, src, dst, ic), true
	}
	ic := pkt.ICMP(pkt.ICMPEchoRequest, id, seq, payload)
	return pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoICMP, src, dst, ic), false
}

// udpL3 builds an IPv4+UDP or IPv6+UDP datagram; returns (l3, isV6).
func udpL3(src, dst net.IP, sport, dport uint16, payload []byte) ([]byte, bool) {
	if isV6(dst) {
		u := pkt.UDP6(src, dst, sport, dport, payload)
		return pkt.IPv6(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoUDP, src, dst, u), true
	}
	u := pkt.UDP(src, dst, sport, dport, payload)
	return pkt.IPv4(tfmeta.ToS, tfmeta.TTLMax, pkt.ProtoUDP, src, dst, u), false
}

func isEchoReply(c capture) bool {
	return (c.proto == pkt.ProtoICMP && c.icmpType == pkt.ICMPEchoReply) ||
		(c.proto == pkt.ProtoICMPv6 && c.icmpType == pkt.ICMPv6EchoReply)
}

// emit sends an L3 packet. IPv4 without VLAN goes via an AF_INET raw socket
// (kernel routes). IPv6 or VLAN needs L2 framing, so it goes via AF_PACKET and
// requires --iface and --dst-mac.
func emit(f *flags, dst net.IP, l3 []byte, v6 bool) {
	if v6 || f.vlan > 0 || f.iface != "" {
		sendL2(f, l3, v6)
		return
	}
	sendIP(dst, l3)
}

func sendL2(f *flags, l3 []byte, v6 bool) {
	if f.iface == "" || f.dstMAC == "" {
		log.Fatal("IPv6/VLAN sending requires --iface and --dst-mac")
	}
	ifi, err := net.InterfaceByName(f.iface)
	if err != nil {
		log.Fatalf("interface %q: %v", f.iface, err)
	}
	dmac, err := net.ParseMAC(f.dstMAC)
	if err != nil {
		log.Fatalf("bad --dst-mac: %v", err)
	}
	smac := ifi.HardwareAddr
	if f.srcMAC != "" {
		if m, err := net.ParseMAC(f.srcMAC); err == nil {
			smac = m
		} else {
			log.Fatalf("bad --src-mac: %v", err)
		}
	}
	et := uint16(pkt.EtherTypeIPv4)
	if v6 {
		et = pkt.EtherTypeIPv6
	}
	var frame []byte
	if f.vlan > 0 {
		frame = pkt.EthernetVLAN(dmac, smac, uint16(f.vlan), et, l3)
	} else {
		frame = pkt.Ethernet(dmac, smac, et, l3)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("AF_PACKET socket (need root): %v", err)
	}
	defer unix.Close(fd)
	ll := &unix.SockaddrLinklayer{Ifindex: ifi.Index, Halen: 6}
	copy(ll.Addr[:6], dmac)
	if err := unix.Sendto(fd, frame, 0, ll); err != nil {
		log.Fatalf("L2 sendto on %s: %v", f.iface, err)
	}
}

func sendIP(dst net.IP, ipPacket []byte) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("raw socket (need root): %v", err)
	}
	defer unix.Close(fd)
	var addr unix.SockaddrInet4
	copy(addr.Addr[:], dst.To4())
	if err := unix.Sendto(fd, ipPacket, 0, &addr); err != nil {
		log.Fatalf("sendto %s: %v", dst, err)
	}
}

func waitReply(sn *sniffer, f *flags, id [16]byte, match func(capture) bool, what string) {
	if c, ok := recvMatch(sn, f, id, match); ok {
		lat := time.Since(time.Unix(0, int64(c.meta.Timestamp)))
		log.Printf("<- %s from %s (latency ~%s)", what, c.srcIP, lat)
	} else {
		log.Printf("no %s within %s", what, f.timeout)
	}
}

func recvMatch(sn *sniffer, f *flags, id [16]byte, match func(capture) bool) (capture, bool) {
	deadline := time.Now().Add(f.timeout)
	for time.Now().Before(deadline) {
		c, ok := sn.next(deadline)
		if !ok {
			continue
		}
		if c.meta.ID != id {
			continue
		}
		if match(c) {
			return c, true
		}
	}
	return capture{}, false
}

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		log.Fatalf("invalid IP: %q", s)
	}
	return ip
}
