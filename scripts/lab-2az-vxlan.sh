#!/usr/bin/env bash
# lab-2az-vxlan.sh — two chassis in two AZs joined by VXLAN, with NO veth.
# The inter-netns underlay is built from OVS internal ports; the inter-AZ overlay
# is a kernel VXLAN device. Mirrors tests/test_vxlan_2az.sh for hands-on use.
#
#   sudo ./scripts/lab-2az-vxlan.sh up      # build the topology (needs OVS running)
#   sudo ./scripts/lab-2az-vxlan.sh agents  # run the 3 observation agents
#   sudo ./scripts/lab-2az-vxlan.sh probe   # send a marked ICMP VM-A -> VM-B
#   sudo ./scripts/lab-2az-vxlan.sh down    # tear everything down
#
#   host: OVS br-underlay (normal L2 switch)
#           ula ── az1                 ulb ── az2
#   az1: ula 172.16.9.1  vxlan0(id100) 10.0.0.1 (VM-A)
#   az2: ulb 172.16.9.2  vxlan0(id100) 10.0.0.2 (VM-B)
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin"
BR=bru-lab; ULA=ula-lab; ULB=ulb-lab

up() {
	pgrep ovs-vswitchd >/dev/null || { echo "start OVS first: sudo ovs-ctl start"; exit 1; }
	ip netns add az1; ip netns add az2
	ovs-vsctl add-br "$BR" -- set bridge "$BR" fail-mode=standalone
	ovs-vsctl add-port "$BR" "$ULA" -- set Interface "$ULA" type=internal
	ovs-vsctl add-port "$BR" "$ULB" -- set Interface "$ULB" type=internal
	ip link set "$ULA" netns az1; ip link set "$ULB" netns az2
	ip netns exec az1 ip addr add 172.16.9.1/24 dev "$ULA"; ip netns exec az1 ip link set "$ULA" up; ip netns exec az1 ip link set lo up
	ip netns exec az2 ip addr add 172.16.9.2/24 dev "$ULB"; ip netns exec az2 ip link set "$ULB" up; ip netns exec az2 ip link set lo up
	ip netns exec az1 ip link add vxlan0 type vxlan id 100 remote 172.16.9.2 dstport 4789 dev "$ULA"
	ip netns exec az1 ip addr add 10.0.0.1/24 dev vxlan0; ip netns exec az1 ip link set vxlan0 up
	ip netns exec az2 ip link add vxlan0 type vxlan id 100 remote 172.16.9.1 dstport 4789 dev "$ULB"
	ip netns exec az2 ip addr add 10.0.0.2/24 dev vxlan0; ip netns exec az2 ip link set vxlan0 up
	echo "up: az1(VM-A 10.0.0.1) <== VXLAN vni100 ==> az2(VM-B 10.0.0.2), underlay 172.16.9.0/24 (no veth)"
	ip netns exec az1 ping -c1 -W2 10.0.0.2 >/dev/null && echo "overlay reachable" || echo "overlay NOT reachable"
}

agents() {
	echo "az1 VM-A (overlay netdev, device-VNI):"
	ip netns exec az1 "$BIN/agent" --watch-vxlan --node-id az1-vmA &
	echo "az1 inter-AZ VXLAN leg (underlay, packet-VNI):"
	ip netns exec az1 "$BIN/agent" --iface "$ULA" --iface-type vxlan --node-id az1-underlay &
	echo "az2 VM-B (overlay netdev, answers):"
	ip netns exec az2 "$BIN/agent" --watch-vxlan --node-id az2-vmB --local-ip 10.0.0.2 &
	wait
}

probe() {
	ip netns exec az1 "$BIN/client" icmp --src 10.0.0.1 --dst 10.0.0.2 --response
}

down() {
	pkill -f "$BIN/agent" 2>/dev/null || true
	ip netns del az1 2>/dev/null || true
	ip netns del az2 2>/dev/null || true
	ovs-vsctl --if-exists del-br "$BR" 2>/dev/null || true
	echo "down"
}

case "${1:-}" in
	up) up ;;
	agents) agents ;;
	probe) probe ;;
	down) down ;;
	*) echo "usage: $0 {up|agents|probe|down}"; exit 2 ;;
esac
