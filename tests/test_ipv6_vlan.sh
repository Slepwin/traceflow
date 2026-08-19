#!/usr/bin/env bash
# test_ipv6_vlan.sh — IPv6 and 802.1Q VLAN observation over a veth pair.
#
#   ns-a  <--veth-->  ns-b   (agent on veth-b, auto mode)
#
# Case 1 (IPv6): client sends a marked ICMPv6 echo (v6 uses L2 send: --iface +
#   --dst-mac). Agent must observe protocol=ICMPv6, ip_version=6, correct v6
#   addresses.
# Case 2 (VLAN): client sends a VLAN-tagged marked ICMP (--vlan 42). Agent's
#   parse_l2 skips the tag and records vlan=42 in the observation.

source "$(dirname "$0")/lib.sh"

setup() {
	mkns a
	mkns b
	veth a veth-a 10.44.0.1/24 b veth-b 10.44.0.2/24
	# add IPv6 addresses on the same link
	nsx a ip -6 addr add fd00:44::1/64 dev veth-a
	nsx b ip -6 addr add fd00:44::2/64 dev veth-b
}

teardown() {
	stop_agents
	local n
	for n in "${CREATED_NS[@]:-}"; do
		[ -n "$n" ] && ip netns del "$n" 2>/dev/null || true
	done
	CREATED_NS=(); AGENT_OUT=(); AGENT_ERR=()
}

require_bins
require_netns

# --- IPv6 -------------------------------------------------------------------
info "IPv6: marked ICMPv6 over veth"
setup
DMAC="$(mac b veth-b)"
run_agent b veth-b auto hv-b --local-ip fd00:44::2; idx=$RA
nsx a "$CLIENT" icmp --src fd00:44::1 --dst fd00:44::2 \
	--iface veth-a --dst-mac "$DMAC" --response --timeout 2s || true
assert_obs "$idx" \
	'.protocol=="ICMPv6" and .ip_version==6 and .src_ip=="fd00:44::1" and .dst_ip=="fd00:44::2"' \
	"agent observed marked ICMPv6 fd00:44::1 -> fd00:44::2"
teardown

# --- VLAN -------------------------------------------------------------------
info "VLAN: marked ICMP tagged with VID 42"
setup
DMAC="$(mac b veth-b)"
run_agent b veth-b auto hv-b --local-ip 10.44.0.2; idx=$RA
nsx a "$CLIENT" icmp --src 10.44.0.1 --dst 10.44.0.2 \
	--iface veth-a --dst-mac "$DMAC" --vlan 42 --timeout 2s || true
assert_obs "$idx" \
	'.protocol=="ICMP" and .vlan==42 and .dst_ip=="10.44.0.2"' \
	"agent observed marked ICMP tagged with VLAN 42"
teardown

info "IPv6/VLAN tests passed"
