// SPDX-License-Identifier: GPL-2.0
/*
 * traceflow.c — TC (clsact) classifier that spots marked diagnostic packets.
 *
 * Pipeline per packet:
 *   1. If iface_type == VXLAN, walk outer Ethernet/IP/UDP/VXLAN and grab the VNI,
 *      then continue parsing on the inner Ethernet frame.
 *   2. Parse Ethernet + IPv4.
 *   3. LEVEL-1 FILTER: check DSCP. Non-marked traffic (99.99%) leaves here in a
 *      couple of instructions without touching the payload.
 *   4. Parse the transport header (ICMP/UDP/TCP) to reach the payload.
 *   5. LEVEL-2 FILTER: check the "TFLO" magic in traceflow_meta.
 *   6. Emit an observation to the ring buffer.
 *   7. If the packet asks to be intercepted AND this attachment allows it,
 *      drop it (TC_ACT_SHOT). Tunnel ports load with allow_intercept=false, so
 *      transit traffic is never dropped.
 *
 * All packet access is direct (data/data_end) with explicit bounds checks so the
 * verifier is happy. Numeric fields written to `observation` are host byte order
 * so the Go side can decode with LittleEndian on x86-64. IPs are ntohl'd to host
 * order; ports are ntohs'd; the magic is compared in network order.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "traceflow.h"

/* TC action codes (from linux/pkt_cls.h, redefined to stay header-light). */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* EtherTypes. */
#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

char LICENSE[] SEC("license") = "GPL";

/* ---- minimal on-wire structs (avoid pulling conflicting kernel uapi) ---- */

struct ethhdr_ {
	__u8  h_dest[6];
	__u8  h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct vlanhdr_ {
	__be16 tci;      /* PCP(3) DEI(1) VID(12) */
	__be16 h_proto;  /* inner ethertype */
} __attribute__((packed));

struct ipv6hdr_ {
	__u8  ver_tc;       /* version:4 (high), traffic-class high nibble (low) */
	__u8  tc_low_flow;  /* traffic-class low nibble (high), flow label (low) */
	__be16 flow_low;
	__be16 payload_len;
	__u8  next_hdr;
	__u8  hop_limit;
	__u8  saddr[16];
	__u8  daddr[16];
} __attribute__((packed));

struct iphdr_ {
	__u8  ihl_version;   /* first IP byte: version=high nibble, ihl=low nibble */
	__u8  tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed));

struct udphdr_ {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

struct tcphdr_ {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8  doff_res;      /* data offset in high nibble */
	__u8  flags;         /* CWR ECE URG ACK PSH RST SYN FIN */
	__be16 window;
	__be16 check;
	__be16 urg_ptr;
} __attribute__((packed));

struct icmphdr_ {
	__u8  type;
	__u8  code;
	__be16 checksum;
	__be16 id;
	__be16 seq;
} __attribute__((packed));

struct vxlanhdr_ {
	__be32 flags;        /* I flag in top byte */
	__be32 vni_reserved; /* VNI in top 24 bits */
} __attribute__((packed));

/* ---- maps ---- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tf_config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

/* Per-CPU counters, summed in userspace and exported as Prometheus metrics. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TF_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/*
 * iface_vni maps an interface index to a VXLAN VNI. Populated by the netlink
 * watcher for per-tenant vxlan netdevs: on such a device the packet is already
 * decapsulated (inner frame), so the VNI is not in the bytes — it is a property
 * of the device. handle() looks it up by skb->ifindex to tag the observation.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   /* ifindex */
	__type(value, __u32); /* VNI     */
} iface_vni SEC(".maps");

/* ---- helpers ---- */

static __always_inline struct tf_config *get_config(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline void stat_incr(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&stats_map, &idx);
	if (c)
		(*c)++; /* per-CPU: no atomic needed */
}

/*
 * parse_l4_and_meta — from `l4` (start of the transport header) run the level-2
 * magic filter and, on a hit, fill obs ports/flags/protocol/meta. ICMP and
 * ICMPv6 share an 8-byte echo header. Returns 1 on a confirmed marked packet.
 */
static __always_inline int parse_l4_and_meta(void *l4, void *data_end, __u8 proto,
					     struct observation *obs, __u8 *want_drop)
{
	void *payload = 0;
	__u16 sport = 0, dport = 0;
	__u8 tcp_flags = 0;

	if (proto == TF_PROTO_ICMP || proto == TF_PROTO_ICMPV6) {
		struct icmphdr_ *icmp = l4;
		if ((void *)(icmp + 1) > data_end)
			return 0;
		payload = (void *)(icmp + 1);
	} else if (proto == TF_PROTO_UDP) {
		struct udphdr_ *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return 0;
		sport = bpf_ntohs(udp->source);
		dport = bpf_ntohs(udp->dest);
		payload = (void *)(udp + 1);
	} else if (proto == TF_PROTO_TCP) {
		struct tcphdr_ *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return 0;
		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
		tcp_flags = tcp->flags;
		__u32 doff = (tcp->doff_res >> 4) * 4;
		if (doff < sizeof(struct tcphdr_))
			return 0;
		payload = (void *)tcp + doff;
	} else {
		return 0;
	}

	/* LEVEL-2 FILTER: the "TFLO" magic. */
	struct traceflow_meta *meta = payload;
	if ((void *)(meta + 1) > data_end)
		return 0;
	if (meta->magic != bpf_htonl(TF_MAGIC))
		return 0;

	obs->meta_timestamp = meta->timestamp;
	__builtin_memcpy(obs->id, meta->id, 16);
	obs->src_port = sport;
	obs->dst_port = dport;
	obs->tcp_flags = tcp_flags;
	obs->protocol = proto;
	*want_drop = meta->intercept;
	return 1;
}

/*
 * parse_ipv4 — level-1 DSCP filter on the IPv4 ToS, then addresses/hop and L4.
 * Zeroes the upper 12 address bytes so a v6 leftover from a failed VXLAN attempt
 * cannot bleed into a v4 hit during AUTO fallback.
 */
static __always_inline int parse_ipv4(void *l3, void *data_end,
				      struct observation *obs, __u8 *want_drop)
{
	struct iphdr_ *ip = l3;
	if ((void *)(ip + 1) > data_end)
		return 0;
	if ((ip->tos & 0xFC) != TF_TOS)     /* LEVEL-1 FILTER */
		return 0;
	if ((ip->ihl_version >> 4) != 4)
		return 0;
	__u32 ihl = (ip->ihl_version & 0x0F) * 4;
	if (ihl < sizeof(struct iphdr_))
		return 0;
	void *l4 = (void *)ip + ihl;
	if (l4 > data_end)
		return 0;

	obs->ip_version = 4;
	__builtin_memset(obs->src_ip, 0, 16);
	__builtin_memcpy(obs->src_ip, &ip->saddr, 4);
	__builtin_memset(obs->dst_ip, 0, 16);
	__builtin_memcpy(obs->dst_ip, &ip->daddr, 4);
	obs->hop = (__u8)(TF_TTL_MAX - ip->ttl);
	return parse_l4_and_meta(l4, data_end, ip->protocol, obs, want_drop);
}

/*
 * parse_ipv6 — level-1 DSCP filter on the IPv6 traffic class, then addresses/hop
 * and L4. Extension headers are not walked: probes carry none, so next_hdr is the
 * transport protocol directly.
 */
static __always_inline int parse_ipv6(void *l3, void *data_end,
				      struct observation *obs, __u8 *want_drop)
{
	struct ipv6hdr_ *ip6 = l3;
	if ((void *)(ip6 + 1) > data_end)
		return 0;
	if ((ip6->ver_tc >> 4) != 6)
		return 0;
	__u8 tc = ((ip6->ver_tc & 0x0F) << 4) | (ip6->tc_low_flow >> 4);
	if ((tc & 0xFC) != TF_TOS)          /* LEVEL-1 FILTER */
		return 0;

	obs->ip_version = 6;
	__builtin_memcpy(obs->src_ip, ip6->saddr, 16);
	__builtin_memcpy(obs->dst_ip, ip6->daddr, 16);
	obs->hop = (__u8)(TF_TTL_MAX - ip6->hop_limit);

	/*
	 * Walk a bounded number of IPv6 extension headers to reach the transport
	 * header. Hop-by-Hop(0)/Routing(43)/Dest-Opts(60) are variable length;
	 * Fragment(44) is fixed 8 bytes — a non-first fragment carries no transport
	 * header so we bail. Anything else is treated as the transport protocol.
	 */
	__u8 nexthdr = ip6->next_hdr;
	void *cur = (void *)(ip6 + 1);
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (nexthdr == TF_PROTO_ICMPV6 || nexthdr == TF_PROTO_TCP ||
		    nexthdr == TF_PROTO_UDP)
			break;
		if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
			struct ipv6_opt_ { __u8 nh; __u8 len; } *eh = cur;
			if ((void *)(eh + 1) > data_end)
				return 0;
			nexthdr = eh->nh;
			cur = (__u8 *)cur + ((__u32)eh->len + 1) * 8;
			if (cur > data_end)
				return 0;
		} else if (nexthdr == 44) {
			struct ipv6_frag_ { __u8 nh; __u8 res; __be16 off; __be32 id; } *fh = cur;
			if ((void *)(fh + 1) > data_end)
				return 0;
			if ((bpf_ntohs(fh->off) & 0xFFF8) != 0)
				return 0; /* non-first fragment: no transport header */
			nexthdr = fh->nh;
			cur = (void *)(fh + 1);
		} else {
			break;
		}
	}
	return parse_l4_and_meta(cur, data_end, nexthdr, obs, want_drop);
}

/*
 * parse_l2 — advance past Ethernet and up to two 802.1Q/802.1AD VLAN tags,
 * returning the inner ethertype (network order), the outermost VID, and the L3
 * pointer. Returns 0 only on a truncated frame.
 */
static __always_inline int parse_l2(void *data, void *data_end,
				    __u16 *ethertype, __u16 *vlan_id, void **l3)
{
	struct ethhdr_ *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;
	__u16 proto = eth->h_proto;   /* network order */
	void *cur = (void *)(eth + 1);
	__u16 vid = 0;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
			struct vlanhdr_ *v = cur;
			if ((void *)(v + 1) > data_end)
				return 0;
			if (vid == 0)
				vid = bpf_ntohs(v->tci) & 0x0FFF;
			proto = v->h_proto;
			cur = (void *)(v + 1);
		}
	}
	*ethertype = proto;
	*vlan_id = vid;
	*l3 = cur;
	return 1;
}

/* dispatch an L3 pointer to the v4 or v6 parser by (network-order) ethertype. */
static __always_inline int parse_l3(void *l3, void *data_end, __u16 ethertype,
				    struct observation *obs, __u8 *want_drop)
{
	if (ethertype == bpf_htons(ETH_P_IP))
		return parse_ipv4(l3, data_end, obs, want_drop);
	if (ethertype == bpf_htons(ETH_P_IPV6))
		return parse_ipv6(l3, data_end, obs, want_drop);
	return 0;
}

/*
 * parse_vxlan — try to read the frame as VXLAN-encapsulated:
 *   [Eth][VLAN?][outer IPv4][UDP:4789][VXLAN][inner Eth][VLAN?][IPv4/IPv6][L4][meta]
 * Any structural mismatch returns 0 so AUTO mode can fall back to regular. The
 * VID written to obs is the inner (tenant) tag. Outer IP is IPv4 only.
 */
/*
 * parse_vxlan — [Eth][VLAN?][outer IPv4/IPv6][UDP:4789][VXLAN][inner Eth][VLAN?]
 *               [IPv4/IPv6][L4][meta]. Outer IP may be v4 or v6 (no ext headers
 * on the underlay). The VID written to obs is the inner (tenant) tag.
 */
static __always_inline int parse_vxlan(void *data, void *data_end,
				       struct observation *obs, __u8 *want_drop)
{
	__u16 oetype, ovid;
	void *ol3;
	if (!parse_l2(data, data_end, &oetype, &ovid, &ol3))
		return 0;

	struct udphdr_ *oudp;
	if (oetype == bpf_htons(ETH_P_IP)) {
		struct iphdr_ *oip = ol3;
		if ((void *)(oip + 1) > data_end)
			return 0;
		if (oip->protocol != TF_PROTO_UDP)
			return 0;
		__u32 oihl = (oip->ihl_version & 0x0F) * 4;
		if (oihl < sizeof(struct iphdr_))
			return 0;
		oudp = (void *)oip + oihl;
	} else if (oetype == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr_ *oip6 = ol3;
		if ((void *)(oip6 + 1) > data_end)
			return 0;
		if (oip6->next_hdr != TF_PROTO_UDP) /* underlay: no ext headers */
			return 0;
		oudp = (void *)(oip6 + 1);
	} else {
		return 0;
	}

	if ((void *)(oudp + 1) > data_end)
		return 0;
	if (oudp->dest != bpf_htons(TF_VXLAN_PORT))
		return 0;

	struct vxlanhdr_ *vx = (void *)(oudp + 1);
	if ((void *)(vx + 1) > data_end)
		return 0;
	__u32 vni = bpf_ntohl(vx->vni_reserved) >> 8;

	__u16 ietype, ivid;
	void *il3;
	if (!parse_l2((void *)(vx + 1), data_end, &ietype, &ivid, &il3))
		return 0;

	obs->iface_type = TF_IFACE_VXLAN;
	obs->vni = vni;
	obs->vlan_id = ivid;
	return parse_l3(il3, data_end, ietype, obs, want_drop);
}

/*
 * parse_regular — [Ethernet][VLAN?][IPv4/IPv6][L4][meta], no encapsulation.
 * skb_vlan carries the VLAN VID lifted from skb metadata (offload case): when
 * the NIC strips the tag, it is not in the packet bytes, so parse_l2 sees vid=0
 * and we fall back to the offloaded value.
 */
static __always_inline int parse_regular(void *data, void *data_end,
					 struct observation *obs, __u8 *want_drop,
					 __u16 skb_vlan)
{
	__u16 etype, vid;
	void *l3;
	if (!parse_l2(data, data_end, &etype, &vid, &l3))
		return 0;
	if (vid == 0)
		vid = skb_vlan;

	obs->iface_type = TF_IFACE_REGULAR;
	obs->vni = 0;
	obs->vlan_id = vid;
	return parse_l3(l3, data_end, etype, obs, want_drop);
}

static __always_inline int handle(struct __sk_buff *skb, __u8 direction)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct tf_config *cfg = get_config();
	if (!cfg)
		return TC_ACT_OK;

	struct observation obs = {};
	obs.direction = direction;
	obs.ifindex = skb->ifindex;

	/* VLAN offload: when the NIC strips the outer tag it lands in skb metadata
	 * instead of the packet bytes. Lift the VID here for the regular path. */
	__u16 skb_vlan = 0;
	if (skb->vlan_present)
		skb_vlan = (__u16)(skb->vlan_tci & 0x0FFF);

	__u8 mode = cfg->iface_type;
	__u8 want_drop = 0;
	int matched = 0;

	/*
	 * Mode selection:
	 *   VXLAN    -> parse encapsulation only.
	 *   REGULAR  -> parse plain frame only.
	 *   AUTO     -> try VXLAN first; on any mismatch fall back to regular.
	 * The VXLAN attempt is cheap for non-tunnel traffic: it bails as soon as
	 * the outer header is not UDP/4789, so it costs a couple of extra loads.
	 */
	if (mode == TF_IFACE_VXLAN || mode == TF_IFACE_AUTO)
		matched = parse_vxlan(data, data_end, &obs, &want_drop);
	if (!matched && (mode == TF_IFACE_REGULAR || mode == TF_IFACE_AUTO))
		matched = parse_regular(data, data_end, &obs, &want_drop, skb_vlan);
	if (!matched)
		return TC_ACT_OK;

	/*
	 * Device-VNI enrichment: on a per-tenant VXLAN netdev the frame is already
	 * decapsulated, so parse matched as regular and obs.vni is 0. Tag it with
	 * the device's VNI (registered by the netlink watcher, keyed by ifindex).
	 */
	if (obs.vni == 0) {
		__u32 ifidx = skb->ifindex;
		__u32 *dev_vni = bpf_map_lookup_elem(&iface_vni, &ifidx);
		if (dev_vni) {
			obs.vni = *dev_vni;
			obs.iface_type = TF_IFACE_VXLAN;
		}
	}
	/*
	 * collect_metadata / external VXLAN devices carry the VNI per-packet as
	 * tunnel metadata (VxlanId is 0, so the map above misses). Pull it from the
	 * skb tunnel key; on a non-tunnel skb the helper fails and we leave vni as-is.
	 */
	if (obs.vni == 0) {
		struct bpf_tunnel_key tk = {};
		if (bpf_skb_get_tunnel_key(skb, &tk, sizeof(tk), 0) == 0 && tk.tunnel_id != 0) {
			obs.vni = (__u32)tk.tunnel_id;
			obs.iface_type = TF_IFACE_VXLAN;
		}
	}

	/*
	 * Safety guard — two independent conditions must both hold to drop:
	 *   1. this attachment is configured to allow interception, and
	 *   2. the packet was NOT VXLAN-encapsulated.
	 * (2) is structural: even if loaded with allow_intercept=true in AUTO
	 * mode, transit (encapsulated) traffic is never dropped, only observed.
	 */
	__u8 do_drop = want_drop && cfg->allow_intercept &&
		       obs.iface_type != TF_IFACE_VXLAN;
	obs.action = do_drop ? TF_ACT_INTERCEPTED : TF_ACT_FORWARDED;
	obs.capture_ns = bpf_ktime_get_ns();

	struct observation *ring = bpf_ringbuf_reserve(&events, sizeof(*ring), 0);
	if (ring) {
		__builtin_memcpy(ring, &obs, sizeof(*ring));
		bpf_ringbuf_submit(ring, 0);
		stat_incr(TF_STAT_OBSERVED);
	} else {
		stat_incr(TF_STAT_RINGBUF_FULL); /* dropped: reader too slow */
	}

	return do_drop ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("tc/ingress")
int traceflow_ingress(struct __sk_buff *skb)
{
	return handle(skb, TF_DIR_INGRESS);
}

SEC("tc/egress")
int traceflow_egress(struct __sk_buff *skb)
{
	return handle(skb, TF_DIR_EGRESS);
}

/*
 * XDP entry point. Same two-level filter and parsers as the TC path, at the XDP
 * hook — the eBPF-visible entry point on NICs driven in native/AF_XDP mode,
 * where OVS may XDP_REDIRECT frames to an AF_XDP socket before the TC hook runs,
 * so a TC program would never see them. XDP is ingress-only, so there is no VLAN
 * offload (the tag is inline pre-stack) and no skb tunnel-key helper; the
 * device-VNI map still applies (keyed by ingress_ifindex). Returns XDP_PASS so
 * traffic continues to OVS/the stack.
 */
SEC("xdp")
int traceflow_xdp(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct tf_config *cfg = get_config();
	if (!cfg)
		return XDP_PASS;

	struct observation obs = {};
	obs.direction = TF_DIR_INGRESS;
	obs.ifindex = ctx->ingress_ifindex;

	__u8 mode = cfg->iface_type;
	__u8 want_drop = 0;
	int matched = 0;

	if (mode == TF_IFACE_VXLAN || mode == TF_IFACE_AUTO)
		matched = parse_vxlan(data, data_end, &obs, &want_drop);
	if (!matched && (mode == TF_IFACE_REGULAR || mode == TF_IFACE_AUTO))
		matched = parse_regular(data, data_end, &obs, &want_drop, 0);
	if (!matched)
		return XDP_PASS;

	if (obs.vni == 0) {
		__u32 ifidx = ctx->ingress_ifindex;
		__u32 *dev_vni = bpf_map_lookup_elem(&iface_vni, &ifidx);
		if (dev_vni) {
			obs.vni = *dev_vni;
			obs.iface_type = TF_IFACE_VXLAN;
		}
	}

	__u8 do_drop = want_drop && cfg->allow_intercept &&
		       obs.iface_type != TF_IFACE_VXLAN;
	obs.action = do_drop ? TF_ACT_INTERCEPTED : TF_ACT_FORWARDED;
	obs.capture_ns = bpf_ktime_get_ns();

	struct observation *ring = bpf_ringbuf_reserve(&events, sizeof(*ring), 0);
	if (ring) {
		__builtin_memcpy(ring, &obs, sizeof(*ring));
		bpf_ringbuf_submit(ring, 0);
		stat_incr(TF_STAT_OBSERVED);
	} else {
		stat_incr(TF_STAT_RINGBUF_FULL);
	}

	return do_drop ? XDP_DROP : XDP_PASS;
}
