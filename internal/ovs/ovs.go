// Package ovs discovers OVN VM ports via ovs-vsctl / ovn-nbctl and parses their
// OVSDB JSON output. Shared by the agent (watch mode) and the client (--as-vm,
// injecting a probe with the source VM's real MAC/IP so OVN port security lets
// it through). Command execution is best-effort; the pure parsers are unit-tested.
package ovs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Port is a discovered VM interface: the host-side tap name, the VM's MAC, and
// its IPs (resolved from OVN; empty means unknown / observe-only).
type Port struct {
	Name string
	MAC  string
	IPs  []net.IP
}

// Iface is one row of `ovs-vsctl list Interface` we care about.
type Iface struct {
	Name    string
	MAC     string
	IfaceID string // external_ids:iface-id — the OVN logical port name
}

// DiscoverPorts enumerates all OVN VM taps and resolves each VM's addresses.
func DiscoverPorts(ctx context.Context) ([]Port, error) {
	out, err := runCmd(ctx, "ovs-vsctl", "--format=json",
		"--columns=name,external_ids,mac_in_use", "list", "Interface")
	if err != nil {
		return nil, err
	}
	ifaces, err := ParseInterfaces(out)
	if err != nil {
		return nil, err
	}
	ports := make([]Port, 0, len(ifaces))
	for _, ifc := range ifaces {
		ports = append(ports, Port{Name: ifc.Name, MAC: ifc.MAC, IPs: resolveIPs(ctx, ifc.IfaceID)})
	}
	return ports, nil
}

// LookupPort resolves a single tap by host-side name (for the client's --as-vm).
func LookupPort(ctx context.Context, name string) (Port, error) {
	out, err := runCmd(ctx, "ovs-vsctl", "--format=json",
		"--columns=name,external_ids,mac_in_use", "find", "Interface", "name="+name)
	if err != nil {
		return Port{}, err
	}
	ifaces, err := ParseInterfaces(out)
	if err != nil {
		return Port{}, err
	}
	if len(ifaces) == 0 {
		return Port{}, fmt.Errorf("no OVN VIF interface named %q", name)
	}
	ifc := ifaces[0]
	return Port{Name: ifc.Name, MAC: ifc.MAC, IPs: resolveIPs(ctx, ifc.IfaceID)}, nil
}

// LookupDatapathName maps an OVN datapath tunnel key (VNI) to a human name via
// the SB DB (Datapath_Binding.external_ids). Best-effort: empty on any failure
// or when the VNI is not an OVN datapath key (e.g. a DCI VXLAN VNI).
func LookupDatapathName(ctx context.Context, vni uint32) (string, error) {
	out, err := runCmd(ctx, "ovn-sbctl", "--format=json", "--columns=external_ids",
		"find", "Datapath_Binding", fmt.Sprintf("tunnel_key=%d", vni))
	if err != nil {
		return "", err
	}
	var resp struct {
		Data     [][]json.RawMessage `json:"data"`
		Headings []string            `json:"headings"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", err
	}
	for _, row := range resp.Data {
		if len(row) == 0 {
			continue
		}
		eids := ovsMap(row[0])
		// OVN sets name/logical-switch depending on version.
		for _, k := range []string{"name", "logical-switch", "name2"} {
			if v := eids[k]; v != "" {
				return v, nil
			}
		}
	}
	return "", nil
}

// resolveIPs looks up a logical port's addresses in the OVN NB DB. Best-effort.
func resolveIPs(ctx context.Context, ifaceID string) []net.IP {
	if ifaceID == "" {
		return nil
	}
	out, err := runCmd(ctx, "ovn-nbctl", "--format=json", "--columns=addresses",
		"list", "Logical_Switch_Port", ifaceID)
	if err != nil {
		return nil
	}
	ips, _ := ParseNBAddresses(out)
	return ips
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return exec.CommandContext(cctx, name, args...).Output()
}

// --- OVSDB JSON parsing (pure, unit-tested) ---------------------------------

// ParseInterfaces decodes `ovs-vsctl --format=json list Interface`. Only ports
// carrying external_ids:iface-id (OVN VIFs) are returned.
func ParseInterfaces(data []byte) ([]Iface, error) {
	var resp struct {
		Data     [][]json.RawMessage `json:"data"`
		Headings []string            `json:"headings"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	col := map[string]int{"name": -1, "external_ids": -1, "mac_in_use": -1}
	for i, h := range resp.Headings {
		if _, ok := col[h]; ok {
			col[h] = i
		}
	}
	var out []Iface
	for _, row := range resp.Data {
		ni, ei, mi := col["name"], col["external_ids"], col["mac_in_use"]
		if ni < 0 || ni >= len(row) {
			continue
		}
		eids := map[string]string{}
		if ei >= 0 && ei < len(row) {
			eids = ovsMap(row[ei])
		}
		ifaceID := eids["iface-id"]
		if ifaceID == "" {
			continue // not an OVN VIF port
		}
		mac := eids["attached-mac"]
		if mac == "" && mi >= 0 && mi < len(row) {
			mac = ovsScalar(row[mi])
		}
		out = append(out, Iface{Name: ovsScalar(row[ni]), MAC: mac, IfaceID: ifaceID})
	}
	return out, nil
}

// ParseNBAddresses decodes the `addresses` column of Logical_Switch_Port into
// IPs (the MAC and keywords like "dynamic"/"router" are skipped).
func ParseNBAddresses(data []byte) ([]net.IP, error) {
	var resp struct {
		Data     [][]json.RawMessage `json:"data"`
		Headings []string            `json:"headings"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	idx := -1
	for i, h := range resp.Headings {
		if h == "addresses" {
			idx = i
		}
	}
	if idx < 0 {
		idx = 0
	}
	var ips []net.IP
	for _, row := range resp.Data {
		if idx >= len(row) {
			continue
		}
		for _, entry := range ovsList(row[idx]) {
			for _, field := range strings.Fields(entry) {
				if ip := net.ParseIP(field); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}

// ovsScalar reads an OVSDB scalar that may be a bare string or a 1-element set.
func ovsScalar(raw json.RawMessage) string {
	if l := ovsList(raw); len(l) > 0 {
		return l[0]
	}
	return ""
}

// ovsList reads an OVSDB value that is either a bare string or a ["set",[...]].
func ovsList(raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil && len(arr) == 2 {
		var tag string
		if json.Unmarshal(arr[0], &tag) == nil && tag == "set" {
			var items []string
			if json.Unmarshal(arr[1], &items) == nil {
				return items
			}
		}
	}
	return nil
}

// ovsMap reads an OVSDB ["map",[[k,v],...]] into a Go map.
func ovsMap(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) != 2 {
		return out
	}
	var tag string
	if json.Unmarshal(arr[0], &tag) != nil || tag != "map" {
		return out
	}
	var pairs [][]string
	if json.Unmarshal(arr[1], &pairs) != nil {
		return out
	}
	for _, p := range pairs {
		if len(p) == 2 {
			out[p[0]] = p[1]
		}
	}
	return out
}
