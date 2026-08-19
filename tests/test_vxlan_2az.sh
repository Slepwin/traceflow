#!/usr/bin/env bash
# test_vxlan_2az.sh — two OVN-style chassis in two AZs, joined by VXLAN, with NO
# veth anywhere. The inter-netns underlay is built from OVS internal ports (real
# kernel netdevs, not veth); the inter-AZ overlay is a kernel VXLAN device.
#
#   host: OVS br-underlay (normal L2 switch)
#           ula ── moved to ns az1        ulb ── moved to ns az2
#
#   ns az1 (AZ1 / hypervisor 1)              ns az2 (AZ2 / hypervisor 2)
#     ula      172.16.9.1/24  (underlay)       ulb      172.16.9.2/24
#     vxlan0   id 100, remote .2  ── VXLAN ──   vxlan0   id 100, remote .1
#       10.0.0.1/24  (VM-A)                       10.0.0.2/24  (VM-B)
#
# A marked ICMP VM-A -> VM-B is observed at three points, all correlated by run
# id: (1) VM-A's overlay netdev, (2) the inter-AZ VXLAN on the underlay, and
# (3) VM-B's overlay netdev. Requires OVS running; skips otherwise.

source "$(dirname "$0")/lib.sh"

BR="bru-$SFX"
ULA="ula-$SFX"
ULB="ulb-$SFX"

setup() {
	mkns az1
	mkns az2

	ovs-vsctl add-br "$BR" -- set bridge "$BR" fail-mode=standalone
	CLEANUP_HOOKS+=("ovs-vsctl --if-exists del-br $BR")
	ovs-vsctl add-port "$BR" "$ULA" -- set Interface "$ULA" type=internal
	ovs-vsctl add-port "$BR" "$ULB" -- set Interface "$ULB" type=internal

	# Move each underlay internal port into its chassis netns (no veth).
	ip link set "$ULA" netns "$(ns az1)"
	ip link set "$ULB" netns "$(ns az2)"
	nsx az1 ip addr add 172.16.9.1/24 dev "$ULA"; nsx az1 ip link set "$ULA" up; nsx az1 ip link set lo up
	nsx az2 ip addr add 172.16.9.2/24 dev "$ULB"; nsx az2 ip link set "$ULB" up; nsx az2 ip link set lo up

	# Inter-AZ VXLAN overlay (VNI 100) carrying the VMs.
	nsx az1 ip link add vxlan0 type vxlan id 100 remote 172.16.9.2 dstport 4789 dev "$ULA"
	nsx az1 ip addr add 10.0.0.1/24 dev vxlan0; nsx az1 ip link set vxlan0 up
	nsx az2 ip link add vxlan0 type vxlan id 100 remote 172.16.9.1 dstport 4789 dev "$ULB"
	nsx az2 ip addr add 10.0.0.2/24 dev vxlan0; nsx az2 ip link set vxlan0 up
}

require_bins
require_netns
require_ovs
info "2-AZ VXLAN (no veth): OVS internal-port underlay + kernel VXLAN overlay"

setup

# Sanity: overlay reachability across the VXLAN inter-AZ link.
nsx az1 ping -c1 -W2 10.0.0.2 >/dev/null 2>&1 || fail "overlay VM-A -> VM-B not reachable (VXLAN underlay broken)"
log "OK: VM-A can reach VM-B across the inter-AZ VXLAN"

# Observation points.
start_agent az1 az1-vmA --watch-vxlan;                    a_vmA=$RA
wait_for_line "$(agent_err "$a_vmA")" "attached vxlan0" 5 || fail "az1 watcher did not attach vxlan0"
run_agent   az1 "$ULA" vxlan az1-underlay;                 a_ul=$RA
start_agent az2 az2-vmB --watch-vxlan --local-ip 10.0.0.2; a_vmB=$RA
wait_for_line "$(agent_err "$a_vmB")" "attached vxlan0" 5 || fail "az2 watcher did not attach vxlan0"

# Marked ICMP VM-A -> VM-B across the AZs.
nsx az1 "$CLIENT" icmp --src 10.0.0.1 --dst 10.0.0.2 --response --timeout 2s || true

# 1. VM-A side: inner packet on the overlay netdev, tagged with the device VNI.
assert_obs "$a_vmA" \
	'.vni==100 and .iface_type=="VXLAN" and .protocol=="ICMP" and .src_ip=="10.0.0.1" and .dst_ip=="10.0.0.2"' \
	"VM-A observed marked ICMP on overlay (device vni=100)"

# 2. Inter-AZ VXLAN leg: encapsulated packet on the underlay, VNI from the wire.
assert_obs "$a_ul" \
	'.vni==100 and .iface_type=="VXLAN" and .protocol=="ICMP" and .src_ip=="10.0.0.1" and .dst_ip=="10.0.0.2"' \
	"inter-AZ VXLAN leg observed on underlay (packet vni=100)"

# 3. VM-B side: inner packet arrives after decap, same VNI.
assert_obs "$a_vmB" \
	'.vni==100 and .iface_type=="VXLAN" and .protocol=="ICMP" and .src_ip=="10.0.0.1" and .dst_ip=="10.0.0.2"' \
	"VM-B observed the delivered marked ICMP (device vni=100)"

# Correlation: the same run id must appear at all three points.
RUN_ID="$(jq -rs 'map(select(.dst_ip=="10.0.0.2")) | .[0].id' "${AGENT_OUT[$a_vmA]}")"
[ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] || fail "no run id at VM-A"
assert_obs "$a_ul"  ".id==\"$RUN_ID\"" "same run id on the inter-AZ VXLAN leg"
assert_obs "$a_vmB" ".id==\"$RUN_ID\"" "same run id at VM-B"
log "run id $RUN_ID correlates VM-A -> inter-AZ VXLAN -> VM-B"

info "2-AZ VXLAN tests passed"
