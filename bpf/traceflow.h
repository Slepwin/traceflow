/* SPDX-License-Identifier: GPL-2.0 */
/*
 * traceflow.h — shared definitions between the eBPF program and userspace.
 *
 * The structs here describe:
 *   - traceflow_meta : the control block carried inside the packet payload,
 *                      right after the transport (ICMP/UDP/TCP) header.
 *   - observation    : one record pushed to the ring buffer per marked packet.
 *   - tf_config      : the per-attachment config (iface type, respond flags).
 *
 * Field order in `observation` is deliberately largest-to-smallest so that the
 * natural C alignment matches the Go struct read on the userspace side without
 * hidden padding. Keep both sides in sync.
 */
#ifndef __TRACEFLOW_H__
#define __TRACEFLOW_H__

/* Level-1 filter: DSCP value carried in the IP ToS byte (DSCP=62 -> ToS=0xF8). */
#define TF_DSCP        62
#define TF_TOS         0xF8

/* Level-2 filter: magic word "TFLO" as seen on the wire (network byte order). */
#define TF_MAGIC       0x54464C4FU

/* Sender always uses TTL=255 so hop = TF_TTL_MAX - ttl. */
#define TF_TTL_MAX     255

/* UDP destination port used for VXLAN encapsulation (IANA default). */
#define TF_VXLAN_PORT  4789

/* iface_type flag values (set via config map at load time).
 * AUTO parses VXLAN-then-regular per packet; the observation always reports the
 * detected type (REGULAR or VXLAN), never AUTO. */
#define TF_IFACE_REGULAR 0
#define TF_IFACE_VXLAN   1
#define TF_IFACE_AUTO    2

/* direction values. */
#define TF_DIR_INGRESS 0
#define TF_DIR_EGRESS  1

/* action values. */
#define TF_ACT_FORWARDED   0
#define TF_ACT_INTERCEPTED 1

/* protocol values (mirror the IP protocol numbers we care about). */
#define TF_PROTO_ICMP   1
#define TF_PROTO_TCP    6
#define TF_PROTO_UDP    17
#define TF_PROTO_ICMPV6 58

/*
 * Control block embedded in the payload. __attribute__((packed)) so there is no
 * padding: it is parsed byte-for-byte out of the packet.
 *
 *   magic         4  0x54464C4F confirmation that this is our packet
 *   id           16  UUIDv4 — run identifier, shared across all hops
 *   deliver       1  0 = agent intercepts at the destination (default);
 *                    1 = deliver the original to the VM, let its stack answer
 *   need_response 1  1 = reply back to the sender
 *   timestamp     8  send time in unix nanoseconds (for latency)
 */
struct traceflow_meta {
	__u32 magic;
	__u8  id[16];
	__u8  deliver;
	__u8  need_response;
	__u64 timestamp;
} __attribute__((packed));

/* One row emitted to the ring buffer per observed marked packet (88 bytes).
 * IP addresses are stored as raw network-order bytes: IPv4 uses the first 4
 * bytes, IPv6 all 16. Ports/vlan are host byte order. */
struct observation {
	__u64 meta_timestamp; /* traceflow_meta.timestamp (sender send time)     */
	__u64 capture_ns;     /* bpf_ktime_get_ns() at capture (kernel monotonic)*/
	__u8  id[16];         /* run UUID                                         */
	__u8  src_ip[16];     /* inner src IP (v4 in [0:4], v6 in [0:16])        */
	__u8  dst_ip[16];     /* inner dst IP                                     */
	__u32 vni;            /* VXLAN VNI (0 when not VXLAN)                     */
	__u32 ifindex;        /* skb->ifindex — which interface saw the packet   */
	__u16 src_port;       /* UDP/TCP source port, host byte order            */
	__u16 dst_port;       /* UDP/TCP destination port, host byte order       */
	__u16 vlan_id;        /* 802.1Q VID (0 when untagged), host byte order   */
	__u8  ip_version;     /* 4 or 6                                          */
	__u8  hop;            /* TF_TTL_MAX - ttl (or hop_limit for v6)          */
	__u8  direction;      /* TF_DIR_*                                        */
	__u8  action;         /* TF_ACT_*                                        */
	__u8  protocol;       /* TF_PROTO_*                                      */
	__u8  tcp_flags;      /* raw TCP flags byte (0 for non-TCP)              */
	__u8  iface_type;     /* TF_IFACE_*                                      */
	__u8  _pad[3];        /* pad to a multiple of 8 bytes                    */
};

/* stats_map (per-CPU array) counter indices — see bpf/traceflow.c. */
#define TF_STAT_OBSERVED     0  /* marked packets pushed to the ring buffer */
#define TF_STAT_RINGBUF_FULL 1  /* observations dropped: ring buffer full   */
#define TF_STAT_MAX          2

/* Per-attachment configuration, stored in an array map at index 0. */
struct tf_config {
	__u8 iface_type;   /* TF_IFACE_REGULAR / TF_IFACE_VXLAN / TF_IFACE_AUTO  */
	__u8 respond;      /* 1 = this agent answers marked probes locally       */
	__u8 tcp_respond;  /* 1 = answer TCP in userspace (else defer to the VM) */
	__u8 _pad;
};

#endif /* __TRACEFLOW_H__ */
