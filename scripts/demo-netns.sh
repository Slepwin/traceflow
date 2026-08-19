#!/usr/bin/env bash
# demo-netns.sh — spin up a two-namespace veth lab to exercise traceflow end to
# end on a single machine, then send a marked ICMP probe with a response.
#
#   sudo ./scripts/demo-netns.sh up      # create ns1 <-> ns2 veth link
#   sudo ./scripts/demo-netns.sh agent   # run the agent inside ns2 (regular)
#   sudo ./scripts/demo-netns.sh probe    # send a marked ICMP probe from ns1
#   sudo ./scripts/demo-netns.sh down     # tear everything down
#
# Layout:
#   ns1 (10.10.0.1) --veth-- (10.10.0.2) ns2
set -euo pipefail

BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/bin"

up() {
  ip netns add ns1
  ip netns add ns2
  ip link add veth1 netns ns1 type veth peer name veth2 netns ns2
  ip netns exec ns1 ip addr add 10.10.0.1/24 dev veth1
  ip netns exec ns2 ip addr add 10.10.0.2/24 dev veth2
  ip netns exec ns1 ip link set veth1 up
  ip netns exec ns2 ip link set veth2 up
  ip netns exec ns1 ip link set lo up
  ip netns exec ns2 ip link set lo up
  echo "lab up: ns1(10.10.0.1) <-> ns2(10.10.0.2)"
}

agent() {
  echo "starting agent in ns2 on veth2 (regular, allow-intercept, answers for local 10.10.0.2)"
  ip netns exec ns2 "$BIN_DIR/agent" --iface veth2 --iface-type regular \
    --allow-intercept --node-id ns2 --local-ip 10.10.0.2
}

probe() {
  echo "sending marked ICMP 10.10.0.1 -> 10.10.0.2 with --response"
  ip netns exec ns1 "$BIN_DIR/client" icmp --src 10.10.0.1 --dst 10.10.0.2 --response
}

down() {
  ip netns del ns1 2>/dev/null || true
  ip netns del ns2 2>/dev/null || true
  echo "lab down"
}

case "${1:-}" in
  up) up ;;
  agent) agent ;;
  probe) probe ;;
  down) down ;;
  *) echo "usage: $0 {up|agent|probe|down}"; exit 2 ;;
esac
