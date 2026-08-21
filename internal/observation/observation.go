// Package observation decodes ring-buffer records emitted by the eBPF program
// and turns them into the enriched, JSON-friendly record the agent prints.
package observation

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ifName resolves an interface index to its name (namespace-local), cached.
var (
	ifNameMu    sync.Mutex
	ifNameCache = map[uint32]string{}
)

func ifName(idx uint32) string {
	if idx == 0 {
		return ""
	}
	ifNameMu.Lock()
	defer ifNameMu.Unlock()
	if n, ok := ifNameCache[idx]; ok {
		return n
	}
	name := ""
	if ifi, err := net.InterfaceByIndex(int(idx)); err == nil {
		name = ifi.Name
	}
	ifNameCache[idx] = name
	return name
}

// Raw mirrors `struct observation` in bpf/traceflow.h byte-for-byte (88 bytes).
// Numeric fields are host byte order (little-endian on x86-64); IP addresses are
// stored as raw network-order bytes (IPv4 in the first 4 bytes, IPv6 in all 16).
type Raw struct {
	MetaTimestamp uint64
	CaptureNS     uint64
	ID            [16]byte
	SrcIP         [16]byte
	DstIP         [16]byte
	VNI           uint32
	IfIndex       uint32
	SrcPort       uint16
	DstPort       uint16
	VLANID        uint16
	IPVersion     uint8
	Hop           uint8
	Direction     uint8
	Action        uint8
	Protocol      uint8
	TCPFlags      uint8
	IfaceType     uint8
	_             [3]uint8
}

// Observation is the enriched record printed by the agent.
type Observation struct {
	ID            string `json:"id"`
	NodeID        string `json:"node_id"`
	Hop           uint8  `json:"hop"`
	Direction     string `json:"direction"`
	VNI           uint32 `json:"vni"`
	VLAN          uint16 `json:"vlan,omitempty"`
	Action        string `json:"action"`
	Protocol      string `json:"protocol"`
	IPVersion     uint8  `json:"ip_version"`
	IfIndex       uint32 `json:"ifindex,omitempty"`
	Iface         string `json:"iface,omitempty"`          // interface name for ifindex
	LogicalSwitch string `json:"logical_switch,omitempty"` // OVN, filled by agent
	AZ            string `json:"az,omitempty"`             // availability zone, filled by agent
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       uint16 `json:"src_port,omitempty"`
	DstPort       uint16 `json:"dst_port,omitempty"`
	TCPFlags      string `json:"tcp_flags,omitempty"`
	IfaceType     string `json:"iface_type"`
	Timestamp     string `json:"timestamp"`            // capture wall-clock (agent)
	CaptureNS     uint64 `json:"capture_ns"`           // kernel monotonic capture time
	LatencyNS     int64  `json:"latency_ns"`           // clamped >= 0
	ClockSkew     bool   `json:"clock_skew,omitempty"` // true when raw latency < 0
}

// Parse decodes a ring-buffer record into Raw.
func Parse(record []byte) (Raw, error) {
	var r Raw
	if err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &r); err != nil {
		return r, fmt.Errorf("decode observation: %w", err)
	}
	return r, nil
}

// Enrich turns a Raw record into a printable Observation, stamping it with the
// local node id and the capture time `now`.
func (r Raw) Enrich(nodeID string, now time.Time) Observation {
	o := Observation{
		ID:        uuid.UUID(r.ID).String(),
		NodeID:    nodeID,
		Hop:       r.Hop,
		Direction: directionString(r.Direction),
		VNI:       r.VNI,
		VLAN:      r.VLANID,
		Action:    actionString(r.Action),
		Protocol:  protocolString(r.Protocol),
		IPVersion: r.IPVersion,
		SrcIP:     ipString(r.IPVersion, r.SrcIP),
		DstIP:     ipString(r.IPVersion, r.DstIP),
		IfaceType: ifaceString(r.IfaceType),
		IfIndex:   r.IfIndex,
		Iface:     ifName(r.IfIndex),
		Timestamp: now.Format(time.RFC3339Nano),
		CaptureNS: r.CaptureNS,
	}
	if !isICMP(r.Protocol) {
		o.SrcPort = r.SrcPort
		o.DstPort = r.DstPort
	}
	if r.Protocol == protoTCP {
		o.TCPFlags = tcpFlagsString(r.TCPFlags)
	}
	if r.MetaTimestamp != 0 {
		// Cross-host wall-clock delta: meaningful only with tight time sync
		// (PTP). A negative value means the sender/agent clocks disagree, so we
		// clamp to 0 and flag it rather than emit a misleading negative latency.
		lat := now.UnixNano() - int64(r.MetaTimestamp)
		if lat < 0 {
			o.ClockSkew = true
			lat = 0
		}
		o.LatencyNS = lat
	}
	return o
}

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

func isICMP(p uint8) bool { return p == protoICMP || p == protoICMPv6 }

func directionString(d uint8) string {
	if d == 1 {
		return "EGRESS"
	}
	return "INGRESS"
}

func actionString(a uint8) string {
	if a == 1 {
		return "INTERCEPTED"
	}
	return "FORWARDED"
}

func protocolString(p uint8) string {
	switch p {
	case protoICMP:
		return "ICMP"
	case protoICMPv6:
		return "ICMPv6"
	case protoTCP:
		return "TCP"
	case protoUDP:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO(%d)", p)
	}
}

func ifaceString(t uint8) string {
	if t == 1 {
		return "VXLAN"
	}
	return "REGULAR"
}

// ipString renders the address from raw network-order bytes: 4 bytes for IPv4,
// 16 for IPv6.
func ipString(version uint8, b [16]byte) string {
	if version == 6 {
		return net.IP(b[:]).String()
	}
	return net.IP(b[:4]).String()
}

// tcpFlagsString renders the raw TCP flags byte as "SYN|ACK" style text.
func tcpFlagsString(f uint8) string {
	names := []struct {
		bit  uint8
		name string
	}{
		{0x01, "FIN"},
		{0x02, "SYN"},
		{0x04, "RST"},
		{0x08, "PSH"},
		{0x10, "ACK"},
		{0x20, "URG"},
	}
	var set []string
	for _, n := range names {
		if f&n.bit != 0 {
			set = append(set, n.name)
		}
	}
	if len(set) == 0 {
		return ""
	}
	return strings.Join(set, "|")
}
