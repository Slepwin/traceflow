#!/usr/bin/env bash
# test_vxlan.sh — VXLAN overlay case.
#
# Topology (underlay only — the client crafts the encapsulation itself, so no
# kernel vxlan netdevice is needed; this exercises OUR outer/VNI/inner parser):
#
#   ns-a  10.30.0.1/24 --veth-- 10.30.0.2/24  ns-b   <- agent here
#
# The client in ns-a sends a VXLAN-encapsulated marked ICMP (VNI=100) to the
# underlay IP of ns-b. The agent on ns-b's underlay veth must observe it with
# vni=100, iface_type=VXLAN, protocol=ICMP. We run the agent once per mode to
# prove the hybrid (auto) detects VXLAN exactly like the explicit setting.
#
# It also checks the structural guard: even with --allow-intercept, an
# encapsulated packet asking to be intercepted is FORWARDED, never dropped.

source "$(dirname "$0")/lib.sh"

VNI=100
UNDER_A=10.30.0.1
UNDER_B=10.30.0.2
INNER_S=10.200.0.1
INNER_D=10.200.0.2

setup_underlay() {
	mkns a
	mkns b
	veth a veth-a "$UNDER_A/24" b veth-b "$UNDER_B/24"
}

run_case() {
	local mode="$1"
	info "VXLAN case: agent iface-type=$mode"
	setup_underlay

	# allow-intercept on purpose: the kernel guard must still refuse to drop
	# encapsulated traffic.
	run_agent b veth-b "$mode" "hv-$mode" --allow-intercept
	local idx=$RA

	# Marked VXLAN ICMP that ALSO requests interception + a response.
	nsx a "$CLIENT" vxlan --dst "$UNDER_B" \
		--inner-src "$INNER_S" --inner-dst "$INNER_D" \
		--vni "$VNI" --intercept --response --timeout 2s || true

	assert_obs "$idx" \
		".vni==$VNI and .iface_type==\"VXLAN\" and .protocol==\"ICMP\" and .src_ip==\"$INNER_S\" and .dst_ip==\"$INNER_D\"" \
		"agent observed VNI=$VNI inner ICMP ($INNER_S -> $INNER_D)"

	# Structural guard: encapsulated packet is never intercepted.
	assert_obs "$idx" \
		".vni==$VNI and .action==\"FORWARDED\"" \
		"encapsulated packet FORWARDED despite --intercept + --allow-intercept (kernel guard)"

	# Per-case teardown (keep the shared work dir for the next case).
	stop_agents
	local n
	for n in "${CREATED_NS[@]:-}"; do
		[ -n "$n" ] && ip netns del "$n" 2>/dev/null || true
	done
	CREATED_NS=(); AGENT_OUT=(); AGENT_ERR=()
}

require_bins
require_netns
run_case vxlan
run_case auto
info "VXLAN tests passed"
