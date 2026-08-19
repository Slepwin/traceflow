#!/usr/bin/env bash
# test_hmac.sh — HMAC authentication of the marker.
#
#   nsA 10.61.0.1 --veth-- 10.61.0.2 nsB (agent --hmac-key SECRET, answers local)
#
# A correctly-signed probe is answered by the responder (replies_sent grows);
# an unsigned probe is rejected (auth_failures grows) — this is what stops a
# spoofed marker from triggering a reply / amplification. Metrics isolate the
# responder's decision from the kernel's own echo (the veth dst is a real IP).

source "$(dirname "$0")/lib.sh"

METRICS=127.0.0.1:9161

require_bins
require_netns
info "hmac: signed answered, unsigned rejected"

mkns a
mkns b
veth a veth-a 10.61.0.1/24 b veth-b 10.61.0.2/24

start_agent b hB --iface veth-b --iface-type auto --local-ip 10.61.0.2 \
	--hmac-key SECRET --metrics-addr "$METRICS"

# Correctly signed probe -> responder answers (replies_sent grows to >= 1).
nsx a "$CLIENT" icmp --src 10.61.0.1 --dst 10.61.0.2 --hmac-key SECRET --response --timeout 2s || true
assert_metric_ge b "$METRICS" traceflow_replies_sent_total 1 "signed probe answered by responder"
replies="$(metric_ns b "$METRICS" traceflow_replies_sent_total)"

# Unsigned probe -> rejected (auth_failures grows), and replies_sent does NOT.
nsx a "$CLIENT" icmp --src 10.61.0.1 --dst 10.61.0.2 --response --timeout 1s || true
assert_metric_ge b "$METRICS" traceflow_auth_failures_total 1 "unsigned probe rejected"
replies2="$(metric_ns b "$METRICS" traceflow_replies_sent_total)"
[ "$replies2" -eq "$replies" ] || fail "responder answered an unsigned probe (replies $replies -> $replies2)"
log "OK: responder did not answer the unsigned probe (replies unchanged=$replies2)"

info "hmac tests passed"
