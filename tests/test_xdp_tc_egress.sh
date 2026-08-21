#!/usr/bin/env bash
# test_xdp_tc_egress.sh — XDP ingress + TC egress companion (--xdp --xdp-tc-egress).
#
# XDP is ingress-only, so plain --xdp never observes traffic leaving the netdev.
# --xdp-tc-egress attaches the TC egress program alongside the XDP hook, so
# stack-transmitted packets are observed as well.
#
#   nsA 10.81.0.1 --veth-- 10.81.0.2 nsB (agent --xdp --xdp-tc-egress)
#
# Checks: the agent reports hook=xdp+tc-egress; an XDP program is on the netdev;
# an inbound probe is observed at INGRESS (XDP) and an outbound probe sent from
# nsB is observed at EGRESS (TC).

source "$(dirname "$0")/lib.sh"

require_bins
require_netns
info "XDP + TC egress (--xdp --xdp-tc-egress)"

mkns a
mkns b
veth a veth-a 10.81.0.1/24 b veth-b 10.81.0.2/24

start_agent b xEg --xdp --xdp-tc-egress --iface veth-b --iface-type auto --local-ip 10.81.0.2
idx=$RA

wait_for_line "$(agent_err "$idx")" "hook=xdp+tc-egress" 3 || fail "agent did not report hook=xdp+tc-egress"
nsx b ip link show veth-b | grep -qE "xdp" || fail "no XDP program on veth-b"
log "OK: XDP program attached to veth-b"

# Ingress: probe from nsA into the agent's netdev, seen by the XDP hook.
nsx a "$CLIENT" icmp --src 10.81.0.1 --dst 10.81.0.2 --timeout 2s || true
assert_obs "$idx" \
	'.protocol=="ICMP" and .direction=="INGRESS" and .dst_ip=="10.81.0.2"' \
	"inbound marked ICMP observed via the XDP hook (ingress)"

# Egress: probe sent FROM nsB leaves veth-b through the stack — invisible to
# XDP, but the TC egress companion observes it.
nsx b "$CLIENT" icmp --src 10.81.0.2 --dst 10.81.0.1 --timeout 2s || true
assert_obs "$idx" \
	'.protocol=="ICMP" and .direction=="EGRESS" and .dst_ip=="10.81.0.1"' \
	"outbound marked ICMP observed via the TC egress hook"

info "xdp-tc-egress tests passed"
