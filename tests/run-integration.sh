#!/usr/bin/env bash
# run-integration.sh — run all traceflow integration tests and summarize.
#
# Needs CAP_NET_ADMIN (netns/veth) and real BPF capabilities (load + TCX attach).
# Individual tests exit 77 to SKIP when the environment can't load eBPF; that is
# reported as SKIP, not FAIL, so this is safe to wire into CI on limited runners.
#
#   ./tests/run-integration.sh            # uses ./bin/{agent,client}
#   AGENT=... CLIENT=... ./tests/run-integration.sh
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS=(test_veth_multinetns.sh test_vxlan.sh test_ipv6_vlan.sh test_watch_vxlan.sh test_hmac.sh test_clsact.sh test_vxlan_2az.sh test_xdp.sh test_xdp_tc_egress.sh)

pass=0 skip=0 fail=0
for t in "${TESTS[@]}"; do
	printf '\n########## %s ##########\n' "$t"
	bash "$DIR/$t"
	rc=$?
	case $rc in
		0)  echo "RESULT: PASS ($t)"; pass=$((pass+1)) ;;
		77) echo "RESULT: SKIP ($t)"; skip=$((skip+1)) ;;
		*)  echo "RESULT: FAIL ($t) rc=$rc"; fail=$((fail+1)) ;;
	esac
done

printf '\n==================================\n'
printf 'summary: %d passed, %d skipped, %d failed\n' "$pass" "$skip" "$fail"
[ "$fail" -eq 0 ] || exit 1
