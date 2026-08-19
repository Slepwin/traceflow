#!/usr/bin/env bash
# test_xdp.sh — the XDP attach path (--xdp).
#
# For NICs driven in native/AF_XDP mode (e.g. OVS with type=afxdp) OVS may
# XDP_REDIRECT frames to an AF_XDP socket before the TC hook runs, so a TC
# program never sees them. The agent can attach the same observation logic at
# the XDP hook instead. XDP is ingress-only.
#
#   nsA 10.80.0.1 --veth-- 10.80.0.2 nsB (agent --xdp)
#
# Checks: the agent reports hook=xdp; an XDP program is really on the netdev; a
# marked probe is observed at ingress.

source "$(dirname "$0")/lib.sh"

require_bins
require_netns
info "XDP attach path (--xdp)"

mkns a
mkns b
veth a veth-a 10.80.0.1/24 b veth-b 10.80.0.2/24

start_agent b xB --xdp --iface veth-b --iface-type auto --local-ip 10.80.0.2
idx=$RA

wait_for_line "$(agent_err "$idx")" "hook=xdp" 3 || fail "agent did not attach via XDP"
nsx b ip link show veth-b | grep -qE "xdp" || fail "no XDP program on veth-b"
log "OK: XDP program attached to veth-b"

nsx a "$CLIENT" icmp --src 10.80.0.1 --dst 10.80.0.2 --timeout 2s || true
assert_obs "$idx" \
	'.protocol=="ICMP" and .direction=="INGRESS" and .dst_ip=="10.80.0.2"' \
	"marked ICMP observed via the XDP hook (ingress)"

info "xdp tests passed"
