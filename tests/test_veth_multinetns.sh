#!/usr/bin/env bash
# test_veth_multinetns.sh — veth between multiple netns, with an L3 router in
# the middle so TTL actually decrements and the hop counter advances.
#
#   ns1 (10.51.1.1) --veth-- (10.51.1.254) ns2 (10.51.2.254) --veth-- (10.51.2.1) ns3
#                                     router (ip_forward=1)
#
# A marked ICMP goes ns1 -> ns3. Agents run in auto mode on:
#   - ns2 ingress iface (p1r)  node "ns2-in"   : sees TTL=255  -> hop 0
#   - ns2 egress  iface (p2r)  node "ns2-out"  : sees TTL=254  -> hop 1  (router decremented)
#   - ns3 iface   (p2)         node "ns3"      : sees TTL=254  -> hop 1
#
# This demonstrates the spec's rule: L2 delivery within a subnet keeps `hop`
# constant, an L3 router bumps it, and the same run `id` correlates observations
# across different `node_id`s.

source "$(dirname "$0")/lib.sh"

require_bins
require_netns
info "veth multi-netns routed chain"

mkns 1
mkns 2
mkns 3

veth 1 p1  10.51.1.1/24   2 p1r 10.51.1.254/24
veth 2 p2r 10.51.2.254/24 3 p2  10.51.2.1/24
enable_forward 2

# Routing: ns1 default via ns2; ns3 back-route to ns1's subnet via ns2.
nsx 1 ip route add default via 10.51.1.254
nsx 3 ip route add 10.51.1.0/24 via 10.51.2.254

# The two router-side agents are transit -> observe-only (no --local-ip).
# Only the destination agent (ns3) answers, and only for its local VM IP.
run_agent 2 p1r auto ns2-in;                 a_in=$RA
run_agent 2 p2r auto ns2-out;                a_out=$RA
run_agent 3 p2 auto ns3 --local-ip 10.51.2.1; a_ns3=$RA

# Marked ICMP ns1 -> ns3 (with response so the return path is exercised too).
nsx 1 "$CLIENT" icmp --src 10.51.1.1 --dst 10.51.2.1 --response --timeout 2s || true

# Ingress at the router: TTL still 255 -> hop 0.
assert_obs "$a_in" \
	'.protocol=="ICMP" and .dst_ip=="10.51.2.1" and .direction=="INGRESS" and .hop==0' \
	"router ingress sees hop 0 (TTL 255, not yet routed)"

# Egress at the router after forwarding: TTL 254 -> hop 1.
assert_obs "$a_out" \
	'.protocol=="ICMP" and .dst_ip=="10.51.2.1" and .direction=="EGRESS" and .hop==1' \
	"router egress sees hop 1 (TTL decremented on forward)"

# Destination namespace: arrives at hop 1.
assert_obs "$a_ns3" \
	'.protocol=="ICMP" and .dst_ip=="10.51.2.1" and .hop==1' \
	"ns3 receives the probe at hop 1"

# Correlation: the run id seen at ns3 must also appear at the router hops.
RUN_ID="$(jq -rs 'map(select(.dst_ip=="10.51.2.1")) | .[0].id' "${AGENT_OUT[$a_ns3]}")"
[ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] || fail "could not extract run id from ns3 observations"
log "run id = $RUN_ID"
assert_obs "$a_in"  ".id==\"$RUN_ID\"" "same run id correlates ns2-in with ns3"
assert_obs "$a_out" ".id==\"$RUN_ID\"" "same run id correlates ns2-out with ns3"

# Responder gating: only the destination agent answers. ns3 should emit a marked
# ICMP echo reply from its local IP; transit agents (no --local-ip) never do.
assert_obs "$a_ns3" \
	'.protocol=="ICMP" and .src_ip=="10.51.2.1" and .direction=="EGRESS"' \
	"dst VM (ns3) answered: marked echo reply egressed from local 10.51.2.1"

info "veth multi-netns tests passed"
