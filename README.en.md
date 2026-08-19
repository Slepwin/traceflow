# Traceflow

eBPF-based network-path diagnostics for overlay (VXLAN) networks.

Traceflow sends a specially **marked** packet and observes which hosts it passes
through — like `traceroute`, but it sees not only IP routing but also tunnels,
VNIs and switching on hypervisor hosts. An eBPF program on the TC hook of each
interface recognizes "our" packet and emits an **observation** — a record that
the packet passed this point. The **collector** groups observations from every
host by the shared run `id` and reconstructs the full path.

```
 client                      hypervisor A                 hypervisor B
 ┌─────────┐   marked pkt    ┌────────────┐   overlay    ┌────────────┐
 │  client │ ───────────────▶│ agent+eBPF │ ────────────▶│ agent+eBPF │
 └─────────┘  DSCP62+magic   │  TC hook   │   VXLAN/tap  │  TC hook   │
      ▲                      └─────┬──────┘              └─────┬──────┘
      │        observations        │  ringbuf                  │
      │        (JSON / HTTP)        ▼                           ▼
      └──────────────────────  collector  ◀──────────────  (by run id)
```

## How "our" packet is recognized — two-level filtering

| Level | Check | Why |
|-------|-------|-----|
| L1 | `DSCP=62` (ToS `0xF8` in the IP header) | One instruction. 99.99% of traffic with a different DSCP is dropped instantly without touching the payload. |
| L2 | magic `0x54464C4F` ("TFLO") in the payload | DSCP=62 can be used by other traffic too; the magic guarantees this is our packet. |

Additionally `TTL=255` at the sender, so `hop = 255 - TTL`. L2 switching does not
change TTL: several observations on one L3 hop share the same `hop` but differ by
`node_id`. Optionally, an **HMAC** authenticates the marker (see below).

## Control block in the payload (`traceflow_meta`, 30 bytes)

Placed right after the transport header (ICMP/UDP/TCP):

| Field | Size | Meaning |
|-------|------|---------|
| `magic` | 4 | `0x54464C4F` ("TFLO"), network byte order |
| `id` | 16 | UUIDv4 — the run identifier, shared across all hops |
| `intercept` | 1 | 1 = intercept the packet (do not forward) |
| `need_response` | 1 | 1 = reply back |
| `timestamp` | 8 | send time (unix ns, little-endian) — for latency |

With `--hmac-key`, an HMAC-SHA256 over these 30 bytes is appended (payload = 62 B).

## Observation model — tap vs VXLAN

Two attach points, matching a real OVN/OVS deployment:

```
  intra-AZ (tap model)                         inter-AZ (VXLAN)
  agent on the VM tap                          agent on the underlay / vxlan netdev

  VM ──tap──▶ [eBPF] ──▶ OVS ──Geneve──▶ ...    ... ──▶ [eBPF] ──▶ VXLAN ──▶ other AZ
       inner frame, DSCP+magic visible               outer Eth/IP/UDP/VXLAN + inner
       iface_type=REGULAR                            iface_type=VXLAN, VNI from wire
```

- **Regular / tap** (`iface_type=regular`): `[Eth][VLAN?][IPv4/IPv6][L4][meta]`.
  The inner tenant frame, before encapsulation / after decapsulation.
- **VXLAN underlay** (`iface_type=vxlan`): the agent skips outer
  `Eth/IP/UDP:4789/VXLAN`, extracts the 24-bit VNI, and parses the inner frame.
  Outer may be IPv4 or IPv6.
- **VXLAN netdev** (per-tenant device): the kernel already decapsulated, so the
  eBPF sees an inner frame with no VNI in the bytes. The netlink watcher reads
  the device VNI (`Vxlan.VxlanId`) into a map keyed by `ifindex`; the eBPF tags
  the observation via `skb->ifindex`. `collect_metadata` devices (per-packet VNI)
  are covered via `bpf_skb_get_tunnel_key`.
- **`auto`** (default): per packet, try VXLAN, fall back to regular.

## Load flags & the safety guards

| Flag | Values | Meaning |
|------|--------|---------|
| `allow_intercept` | true / false | May drop packets. Tap=true, VXLAN=false |
| `interface_type` | **auto** / regular / vxlan | How to parse (default `auto`) |

Two independent guards mean a packet is dropped only if `intercept` is requested
**and** the attachment allows it **and** (in the kernel) the packet is not
VXLAN-encapsulated — so transit/tunnel traffic is only ever observed.

## Agent — one per hypervisor

1. Loads eBPF via `cilium/ebpf` (pure Go, no CGO).
2. Writes the config map (`allow_intercept`, `interface_type`).
3. Attaches the observation program. Default is the **TC hook** (ingress+egress):
   **TCX** on kernel ≥6.6, with an automatic fallback to classic
   **clsact + cls_bpf** via netlink (down to ~4.5). With `--xdp` it attaches at
   the **XDP hook** instead (ingress-only) — see *OVS-DPDK / AF_XDP* below.
4. Reads observations from the ring buffer and prints JSON (or ships to a collector).
5. **Answers only for the destination VM.** Observations are captured on every
   hop; a reply to `need_response=1` is built only when the inner `dst_ip` is a
   local VM address (`--local-ip`, or resolved by the watcher). Transit/VTEP nodes
   are observe-only. TCP is a small, sequence-correct userspace responder
   (`--tcp-respond=false` lets the real VM stack answer instead).

Replies go out via **AF_PACKET** (L2 raw socket), bypassing the kernel routing
stack; the address swap re-uses the VM's own MAC/IP, which OVN port security
expects.

### Dynamic attach (watch modes)

- `--watch` — discovers OVN VM taps via `ovs-vsctl` (`external_ids:iface-id`),
  attaches/detaches eBPF as VMs come and go, resolves each VM's IPs from the OVN
  NB DB (`ovn-nbctl`, best-effort) so the responder answers automatically.
- `--watch-vxlan` — follows per-tenant VXLAN netdevs via **netlink** link events
  (created/removed by OVN or any controller) and tags observations with the
  device VNI.

## Client — the probe sender

| Command | What |
|---------|------|
| `icmp` | ICMP / ICMPv6 echo (`--response` waits for a reply) |
| `udp` | UDP datagram |
| `tcp` | TCP handshake: SYN → SYN/ACK → ACK |
| `ptcp` | handshake + data + FIN — full dialog |
| `vxlan` | VXLAN-encapsulated marked ICMP with a given VNI |

IPv4 without VLAN is sent via an AF_INET raw socket (`IP_HDRINCL`). IPv6 or VLAN
needs L2 framing, so it goes via AF_PACKET (`--iface` + `--dst-mac`, `--vlan`).
`--as-vm` fills the source IP/MAC from the OVS tap so OVN port security passes.
`--hmac-key` signs the probe. Replies are captured with an AF_PACKET sniffer.

## Observation (JSON)

```json
{
  "id": "3f2b...-uuid",
  "node_id": "hv-07",
  "hop": 1,
  "direction": "INGRESS",
  "vni": 100,
  "vlan": 42,
  "protocol": "ICMP",
  "ip_version": 4,
  "ifindex": 7,
  "iface": "tap0abc",
  "logical_switch": "ls-tenant-a",
  "az": "az-east-1",
  "src_ip": "10.10.0.1",
  "dst_ip": "10.10.0.2",
  "tcp_flags": "SYN|ACK",
  "iface_type": "VXLAN",
  "timestamp": "2026-08-19T12:00:00.123Z",
  "capture_ns": 51230948120,
  "latency_ns": 351200
}
```

`timestamp` is the capture wall-clock; `capture_ns` is the kernel-monotonic
capture time; `latency_ns` is clamped to ≥0 (a negative delta means cross-host
clock skew and is flagged `clock_skew`). `az`/`logical_switch` are added by the
agent (`--az`, and VNI→switch from the OVN SB DB, best-effort).

## Authentication (HMAC)

`DSCP=62 + magic` is spoofable. `--hmac-key <secret>` enables HMAC-SHA256 over
the meta core; the **responder verifies it and does not reply without a valid
HMAC** (`traceflow_auth_failures_total`), which stops amplification / probing.
Echo replies are re-signed so the return path stays valid. (eBPF cannot compute
HMAC cheaply, so *observations* remain advisory; enforcement is at the responder.)

## Collector (path assembly)

`collector` ingests observations over HTTP and groups them by run `id` — a key
that is stable even where NAT rewrites the 5-tuple, so a path across SNAT/DNAT is
assembled as one flow. Agents ship with `--collector-url`.

```
GET /paths            — run ids with counts
GET /path?id=<uuid>   — the run's observations, ordered by hop then time
```

### OTLP export (distributed tracing)

A traced path maps 1:1 onto tracing spans, so the agent can export directly to
any OpenTelemetry backend (Tempo/Jaeger/…) — no bespoke UI needed:

```bash
sudo bin/agent --watch --az az-1 --otlp-endpoint otel-collector:4318
```

Each observation becomes a **span**; the run UUID **is** the 128-bit **trace id**
(so every host's observations land in one trace); fields become attributes
(`traceflow.node_id/az/hop/vni/direction/…`, `source.address`, `destination.address`).
Spans of a run share a synthetic parent derived from the UUID and are ordered by
the `hop` attribute — a network path is not a call tree, so they are correlated
by trace id + hop, not causal nesting. Transport is OTLP/HTTP (protobuf POST to
`<endpoint>/v1/traces`, insecure by default).

## Components

```
bpf/traceflow.c        eBPF/TC program: 2-level filter, VXLAN, VLAN, IPv6, ringbuf
internal/tfmeta        constants + (de)serialization + HMAC of traceflow_meta
internal/pkt           packet builders Eth/IP{4,6}/ICMP{,v6}/UDP/TCP/VXLAN + checksums
internal/observation   ring-buffer decode -> JSON
internal/ovs           OVS/OVN discovery (ovs-vsctl/ovn-nbctl/ovn-sbctl) + parsers
agent/                 eBPF loader, ring reader, responder, watchers, metrics, emitter
client/                marked-probe sender + AF_PACKET sniffer
collector/             HTTP collector: group observations by run id, assemble paths
scripts/               demo-netns.sh, lab-2az-vxlan.sh
tests/                 unit (Go) + integration (netns / veth / VXLAN / OVN)
```

## Build

```bash
sudo apt install -y clang llvm libbpf-dev linux-libc-dev make golang
make deps        # go mod tidy
make generate    # bpf2go: bpf/traceflow.c -> agent/traceflow_bpf*.go
make build       # -> bin/{agent,client,collector}
```

Runtime: Linux (TCX needs ≥6.6; older kernels use the clsact fallback), run as
root or with `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_NET_RAW`.

### Rootless container

```bash
make image                                   # unit tests run in the builder stage
podman run --rm --privileged traceflow itest # integration suite (rootful for real BPF)
```

Rootless podman can build the image and run unit tests, but loading eBPF and
`ip netns exec` need real BPF/net capabilities — the integration tests SKIP (not
fail) when they are unavailable; run rootful or on the host.

## Tests

```bash
make test    # Go unit tests (no root)
make itest   # integration suite (needs root; TESTS below)
```

Integration suite (each SKIPs cleanly when its prerequisites are missing):

- `test_veth_multinetns.sh` — routed `ns1 — ns2(router) — ns3`: hop 0/1 across
  the L3 router, run-id correlation, dst-VM responder.
- `test_vxlan.sh` — VXLAN underlay parse (VNI, structural intercept guard).
- `test_ipv6_vlan.sh` — ICMPv6 and 802.1Q VLAN observation.
- `test_watch_vxlan.sh` — netlink VXLAN watcher: attach existing, dynamic
  create/delete, device-VNI enrichment.
- `test_hmac.sh` — signed answered, unsigned rejected (via metrics).
- `test_clsact.sh` — the clsact/cls_bpf fallback (`TRACEFLOW_FORCE_CLSACT=1`).
- `test_xdp.sh` — the XDP attach path (`--xdp`): program on the netdev, ingress
  observation.
- `test_vxlan_2az.sh` — **two chassis / two AZs joined by VXLAN, no veth** (needs
  OVS). See below.

## Two-AZ VXLAN lab (no veth)

Two OVN-style chassis in two AZs, joined by VXLAN, with **no veth anywhere**: the
inter-netns underlay is built from **OVS internal ports** (real kernel netdevs),
the inter-AZ overlay is a **kernel VXLAN device**.

```
 host: OVS br-underlay  (normal L2 switch)
          ula ── moved into ns az1        ulb ── moved into ns az2
 ┌──────────────── ns az1 (AZ1) ────────┐   ┌──────────── ns az2 (AZ2) ─────────┐
 │  ula   172.16.9.1/24  (underlay)      │   │  ulb   172.16.9.2/24              │
 │  vxlan0 id100 remote .2 ── VXLAN(100) ┼───┼── vxlan0 id100 remote .1          │
 │    10.0.0.1/24  (VM-A)                │   │    10.0.0.2/24  (VM-B)            │
 └───────────────────────────────────────┘   └───────────────────────────────────┘

 A marked ICMP VM-A -> VM-B is observed at three points, one run id:
   (1) VM-A overlay netdev  (device vni=100)
   (2) inter-AZ VXLAN leg on the underlay  (packet vni=100, outer Eth/IP/UDP/VXLAN)
   (3) VM-B overlay netdev  (device vni=100)
```

```bash
sudo ovs-ctl start
sudo ./scripts/lab-2az-vxlan.sh up
sudo ./scripts/lab-2az-vxlan.sh agents &
sudo ./scripts/lab-2az-vxlan.sh probe
sudo ./scripts/lab-2az-vxlan.sh down
```

Why internal ports: an OVS internal port is a real kernel netdev that
stays attached to the OVS datapath even after being moved into a netns — so two
netns "chassis" are wired together through the host datapath with zero veth. (The
`ovs-sandbox` / `make sandbox` tool uses the **dummy** datapath, where no real
packets flow through kernel netdevs, so eBPF/TC cannot observe them — a real
kernel datapath is required.)

## Notes / limitations

- **HMAC** is enforced at the responder; observations are advisory (eBPF does not
  compute HMAC).
- **latency** across hosts needs tight time sync (PTP); it is clamped and flagged
  on skew.
- **IPv6** extension headers are walked (bounded); a non-first fragment carries no
  transport header and is not marked.
- **Portability**: TCX (≥6.6) with a clsact/cls_bpf netlink fallback; the program
  touches only stable UAPI (`__sk_buff` + packet bytes), so no CO-RE is needed.
## OVS-DPDK / AF_XDP

With OVS-DPDK the datapath is in userspace, so the TC path can miss traffic:

- **OVS with `type=afxdp` netdevs** — the NIC stays a kernel netdev, but OVS
  loads an XDP program that `XDP_REDIRECT`s frames to an AF_XDP socket *before*
  the TC hook, so a TC program never sees them. `--xdp` attaches the same
  two-level filter / parsers at the **XDP hook** (which runs first), emits the
  same observations, and returns `XDP_PASS` so OVS still gets the frame. It
  prefers native (driver) mode and falls back to generic (SKB) mode.

  ```bash
  sudo bin/agent --xdp --iface eth0 --node-id hv-01
  ```

  Caveat: only one XDP program can own a netdev unless an `xdp-dispatcher`
  (libxdp) is used; on a NIC that already runs OVS's XDP program, chaining via
  libxdp is required. XDP is ingress-only here.

- **OVS-DPDK with a DPDK PMD (vfio-pci)** — the NIC is fully owned by the
  userspace DPDK driver, so there is **no kernel netdev** and neither TC nor XDP
  can attach. Observation there needs an OVS mirror port / native OVS tracing;
  that is out of scope.

- **vhost-user VM ports** — the VM connects over a unix socket + shared memory,
  with no netdev, so eBPF cannot observe at the port regardless.

## Notes / limitations (cont.)
```
