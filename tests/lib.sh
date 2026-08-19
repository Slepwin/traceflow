# shellcheck shell=bash
# lib.sh — shared helpers for traceflow integration tests.
#
# Provides network-namespace lifecycle, agent process management (with a
# capability probe that turns "cannot load eBPF here" into a clean SKIP rather
# than a failure), and jq-based assertions over the agent's JSON observation
# stream.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT_DIR/bin}"
AGENT="${AGENT:-$BIN_DIR/agent}"
CLIENT="${CLIENT:-$BIN_DIR/client}"
WORK="$(mktemp -d)"

# Unique suffix so parallel/rerun invocations never collide.
SFX="tf$$"

RA=""  # set by run_agent to the new agent's index
declare -a CREATED_NS=()
declare -a CLEANUP_HOOKS=()  # extra teardown commands (e.g. OVS bridges), eval'd on exit
declare -a AGENT_PIDS=()
declare -a AGENT_OUT=()
declare -a AGENT_ERR=()

# Exit codes: 0 pass, 1 fail, 77 skip (autotools convention).
SKIP=77

log()  { printf '  %s\n' "$*" >&2; }
info() { printf '\n=== %s ===\n' "$*" >&2; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$*" >&2; exit $SKIP; }

require_bins() {
	[ -x "$AGENT" ]  || fail "agent binary not found at $AGENT (run: make build)"
	[ -x "$CLIENT" ] || fail "client binary not found at $CLIENT (run: make build)"
	command -v ip >/dev/null || fail "iproute2 (ip) not installed"
	command -v jq >/dev/null || fail "jq not installed"
}

# require_netns probes whether we can actually create AND exec inside a network
# namespace. Rootless containers often allow `ip netns add` but deny the per-ns
# /sys remount that `ip netns exec` performs ("mount of /sys failed"). In that
# case we SKIP rather than FAIL — run rootful (sudo podman / host) for a real run.
require_netns() {
	local probe="tfprobe-$$"
	ip netns add "$probe" 2>/dev/null || skip "cannot create netns (need CAP_NET_ADMIN)"
	if ! ip netns exec "$probe" true 2>/dev/null; then
		ip netns del "$probe" 2>/dev/null || true
		skip "cannot exec inside netns here (rootless /sys mount denied); run rootful podman or on the host"
	fi
	ip netns del "$probe" 2>/dev/null || true
}

require_ovs() {
	command -v ovs-vsctl >/dev/null || skip "ovs-vsctl not installed"
	pgrep ovs-vswitchd >/dev/null || skip "ovs-vswitchd not running"
	ovs-vsctl show >/dev/null 2>&1 || skip "OVS not reachable (ovsdb down)"
}

ns() { echo "${1}-${SFX}"; }

mkns() {
	local name; name="$(ns "$1")"
	ip netns add "$name" 2>/dev/null || skip "cannot create netns (need CAP_NET_ADMIN): $name"
	CREATED_NS+=("$name")
	ip netns exec "$name" ip link set lo up
}

nsx() { ip netns exec "$(ns "$1")" "${@:2}"; }

# mac <ns> <iface> -> prints the interface MAC address.
mac() { nsx "$1" cat "/sys/class/net/$2/address"; }

# veth <nsA> <ifA> <ipA/cidr> <nsB> <ifB> <ipB/cidr>
veth() {
	local nsA ifA ipA nsB ifB ipB
	nsA="$(ns "$1")"; ifA="$2"; ipA="$3"; nsB="$(ns "$4")"; ifB="$5"; ipB="$6"
	ip link add "$ifA" netns "$nsA" type veth peer name "$ifB" netns "$nsB"
	ip netns exec "$nsA" ip addr add "$ipA" dev "$ifA"
	ip netns exec "$nsB" ip addr add "$ipB" dev "$ifB"
	ip netns exec "$nsA" ip link set "$ifA" up
	ip netns exec "$nsB" ip link set "$ifB" up
}

enable_forward() { nsx "$1" sysctl -qw net.ipv4.ip_forward=1; }

# http_get_ns <ns> <host:port> <path> -> response body via /dev/tcp (no curl dep).
http_get_ns() {
	nsx "$1" bash -c "exec 3<>/dev/tcp/${2%:*}/${2#*:}; printf 'GET $3 HTTP/1.0\r\n\r\n' >&3; cat <&3"
}

# metric_ns <ns> <host:port> <metric-name> -> the counter/gauge value (0 if absent).
metric_ns() {
	local v
	v="$(http_get_ns "$1" "$2" /metrics 2>/dev/null | grep -E "^$3\{" | awk '{print $NF}')"
	echo "${v:-0}"
}

# assert_metric_ge <ns> <host:port> <metric-name> <min> <desc> — polls up to 5s.
assert_metric_ge() {
	local end=$((SECONDS + 5)) v=0
	while [ $SECONDS -lt $end ]; do
		v="$(metric_ns "$1" "$2" "$3")"
		if [ "${v:-0}" -ge "$4" ]; then
			log "OK: $5 ($3=$v)"
			return 0
		fi
		sleep 0.3
	done
	fail "$5 ($3=${v:-0}, want >= $4)"
}

# start_agent <ns> <node-id> [agent args...]
# Generic agent starter (any flags: --iface, --watch, --watch-vxlan, ...). Sets
# the global RA to the new agent's index. Must NOT be called in a command
# substitution: the AGENT_* arrays (and skip/fail's exit) need the parent shell.
start_agent() {
	local nsname node
	nsname="$1"; node="$2"; shift 2
	local idx="${#AGENT_PIDS[@]}"
	local out="$WORK/agent-${node}-${idx}.jsonl"
	local err="$WORK/agent-${node}-${idx}.log"
	# Background `ip netns exec` DIRECTLY (not the nsx function): ip netns exec
	# execs the agent in place, so $! is the agent's own PID and kill reaches it.
	# Backgrounding a shell function instead makes $! the subshell and leaks the
	# agent child.
	ip netns exec "$(ns "$nsname")" "$AGENT" --node-id "$node" "$@" >"$out" 2>"$err" &
	local pid=$!
	AGENT_PIDS+=("$pid")
	AGENT_OUT+=("$out")
	AGENT_ERR+=("$err")

	# Wait for the "agent up" banner; if the process dies first, inspect why.
	if ! wait_for_line "$err" "traceflow agent up" 5; then
		if ! kill -0 "$pid" 2>/dev/null; then
			if grep -qiE "operation not permitted|permission denied|CAP_|bpf|RLIMIT" "$err"; then
				skip "agent could not load eBPF here (needs real BPF caps): $(tail -1 "$err")"
			fi
			fail "agent exited during startup: $(tail -3 "$err")"
		fi
		fail "agent did not come up in time: $(tail -3 "$err")"
	fi
	RA="$idx"
}

# run_agent <ns> <iface> <iface-type> <node-id> [extra args...] — static attach.
run_agent() {
	local nsname iface itype node
	nsname="$1"; iface="$2"; itype="$3"; node="$4"; shift 4
	start_agent "$nsname" "$node" --iface "$iface" --iface-type "$itype" "$@"
}

# agent_err <index> -> path to that agent's stderr log (for log assertions).
agent_err() { echo "${AGENT_ERR[$1]}"; }

wait_for_line() {
	local file="$1" pat="$2" timeout="${3:-5}"
	local end=$((SECONDS + timeout))
	while [ $SECONDS -lt $end ]; do
		[ -f "$file" ] && grep -q "$pat" "$file" && return 0
		sleep 0.1
	done
	return 1
}

# assert_obs <agent-index> <jq-boolean-expr-over-array> <description>
assert_obs() {
	local out="${AGENT_OUT[$1]}"; local expr="$2"; local desc="$3"
	# Give the ringbuf reader a moment to flush.
	local end=$((SECONDS + 3))
	while [ $SECONDS -lt $end ]; do
		if jq -es "any(.[]; $expr)" "$out" >/dev/null 2>&1 \
			&& [ "$(jq -es "any(.[]; $expr)" "$out" 2>/dev/null)" = "true" ]; then
			log "OK: $desc"
			return 0
		fi
		sleep 0.2
	done
	printf 'observations seen by agent %d:\n' "$1" >&2
	jq -es '.' "$out" >&2 2>/dev/null || cat "$out" >&2
	fail "$desc"
}

stop_agents() {
	local pid
	for pid in "${AGENT_PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	done
	for pid in "${AGENT_PIDS[@]:-}"; do
		[ -n "$pid" ] && wait "$pid" 2>/dev/null || true
	done
	AGENT_PIDS=()
}

cleanup() {
	stop_agents
	local h
	for h in "${CLEANUP_HOOKS[@]:-}"; do
		[ -n "$h" ] && eval "$h" 2>/dev/null || true
	done
	local n
	for n in "${CREATED_NS[@]:-}"; do
		[ -n "$n" ] && ip netns del "$n" 2>/dev/null || true
	done
	rm -rf "$WORK"
}
trap cleanup EXIT
