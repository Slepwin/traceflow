#!/usr/bin/env bash
# test_watch_vxlan.sh — netlink-driven per-tenant VXLAN watcher (inter-AZ).
#
# Two netns act as VXLAN VTEPs over a veth underlay; each has a vxlan0 (VNI 100)
# with an overlay IP. The agent in nsB runs --watch-vxlan (no --iface): it
# subscribes to netlink link events, attaches eBPF to vxlan0, and registers the
# device VNI so observations off that netdev are tagged.
#
#   nsA 10.99.0.1 --veth-- 10.99.0.2 nsB
#   vxlan0(id100) 10.200.0.1        10.200.0.2 vxlan0(id100)   <- agent --watch-vxlan
#
# Checks:
#   1. existing vxlan0 is auto-attached at startup;
#   2. a marked ICMP over the overlay is observed with vni=100, iface=VXLAN
#      (device-VNI enrichment: eBPF sees the decapsulated inner frame);
#   3. a vxlan101 created AFTER startup is attached (RTM_NEWLINK);
#   4. deleting vxlan0 (as OVN/a controller would) detaches it (RTM_DELLINK).

source "$(dirname "$0")/lib.sh"

UNDER_A=10.99.0.1
UNDER_B=10.99.0.2
OV_A=10.200.0.1
OV_B=10.200.0.2

# add_vxlan <ns> <name> <vni> <remote-underlay-ip> [overlay-ip/cidr]
# The underlay device in ns X is veth-X (created by the veth helper).
add_vxlan() {
	local n name vni remote ovip
	n="$1"; name="$2"; vni="$3"; remote="$4"; ovip="${5:-}"
	nsx "$n" ip link add "$name" type vxlan id "$vni" remote "$remote" dstport 4789 dev "veth-$n"
	[ -n "$ovip" ] && nsx "$n" ip addr add "$ovip" dev "$name"
	nsx "$n" ip link set "$name" up
}

require_bins
require_netns
info "watch-vxlan: netlink lifecycle + device-VNI enrichment"

mkns a
mkns b
veth a veth-a "$UNDER_A/24" b veth-b "$UNDER_B/24"
add_vxlan a vxlan0 100 "$UNDER_B" "$OV_A/24"
add_vxlan b vxlan0 100 "$UNDER_A" "$OV_B/24"

# Agent in nsB, watching VXLAN netdevs via netlink (no --iface).
start_agent b nsB --watch-vxlan
idx=$RA
err="$(agent_err "$idx")"

# 1. Existing vxlan0 attached at startup.
wait_for_line "$err" "attached vxlan0" 5 || fail "watcher did not attach existing vxlan0"
log "OK: startup enumeration attached vxlan0 (vni=100)"

# 2. Marked ICMP over the overlay -> observed with device VNI.
nsx a "$CLIENT" icmp --src "$OV_A" --dst "$OV_B" --timeout 2s || true
assert_obs "$idx" \
	'.vni==100 and .iface_type=="VXLAN" and .protocol=="ICMP" and .dst_ip=="'"$OV_B"'"' \
	"marked ICMP over overlay observed with device vni=100 (iface=VXLAN)"

# 3. Dynamic create (RTM_NEWLINK).
add_vxlan b vxlan101 101 "$UNDER_A"
wait_for_line "$err" "attached vxlan101" 5 || fail "watcher did not attach vxlan101 on create"
log "OK: RTM_NEWLINK attached vxlan101 (vni=101)"

# 4. Dynamic delete (RTM_DELLINK) — as OVN/an external controller removing a tenant.
nsx b ip link del vxlan0
wait_for_line "$err" "detached vxlan0" 5 || fail "watcher did not detach vxlan0 on delete"
log "OK: RTM_DELLINK detached vxlan0"

info "watch-vxlan tests passed"
