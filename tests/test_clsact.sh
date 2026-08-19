#!/usr/bin/env bash
# test_clsact.sh — the classic clsact/cls_bpf attach path (kernels < 6.6).
#
# On a TCX-capable kernel the fallback is forced with TRACEFLOW_FORCE_CLSACT=1 so
# the netlink attach code (clsact qdisc + cls_bpf filter, byte-order of the
# protocol match, and teardown) is exercised anywhere.
#
#   nsA 10.62.0.1 --veth-- 10.62.0.2 nsB (agent, forced clsact)
#
# Checks: the agent logs the fallback; a cls_bpf filter is actually attached
# (visible via `tc filter`, unlike TCX); a probe is observed (so the filter
# matches and runs the program).

source "$(dirname "$0")/lib.sh"

require_bins
require_netns
info "clsact/cls_bpf fallback (forced)"

mkns a
mkns b
veth a veth-a 10.62.0.1/24 b veth-b 10.62.0.2/24

export TRACEFLOW_FORCE_CLSACT=1
start_agent b hB --iface veth-b --iface-type auto --local-ip 10.62.0.2
unset TRACEFLOW_FORCE_CLSACT
idx=$RA

wait_for_line "$(agent_err "$idx")" "clsact" 3 || fail "agent did not take the clsact path"
log "OK: agent used clsact/cls_bpf"

# The cls_bpf filter must be really attached (TCX would show nothing here).
nsx b tc filter show dev veth-b ingress | grep -q "id " || fail "no cls_bpf ingress filter attached"
nsx b tc filter show dev veth-b egress  | grep -q "id " || fail "no cls_bpf egress filter attached"
log "OK: cls_bpf filters attached (visible via tc filter)"

# A probe must be observed -> the filter matches (validates protocol byte-order).
nsx a "$CLIENT" icmp --src 10.62.0.1 --dst 10.62.0.2 --timeout 2s || true
assert_obs "$idx" '.protocol=="ICMP" and .dst_ip=="10.62.0.2"' \
	"marked ICMP observed through cls_bpf"

info "clsact tests passed"
