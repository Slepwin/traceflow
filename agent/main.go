// Command agent loads the traceflow eBPF program onto a TC hook, streams
// observations from the ring buffer, optionally answers marked packets destined
// to a local VM, and exports metrics.
//
// Two attach modes:
//
//	--iface NAME   attach to a single interface (static).
//	--watch        discover OVN VM tap ports via ovs-vsctl and attach/detach
//	               eBPF as VMs come and go; per-tap responders answer for that
//	               VM's addresses (resolved from OVN, best-effort).
//
// Flags:
//
//	--iface-type   auto | regular | vxlan          (default auto)
//	--node-id      identifier for this host (default: hostname)
//	--respond      answer packets whose dst is a --local-ip / discovered VM IP
//	--local-ip     comma-separated local VM IPs (static mode)
//	--metrics-addr host:port for Prometheus /metrics + /healthz ("" = off)
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/traceflow/traceflow/internal/observation"
	"github.com/traceflow/traceflow/internal/tfmeta"
)

// tfConfig mirrors `struct tf_config` (4 bytes) in bpf/traceflow.h.
type tfConfig struct {
	IfaceType  uint8
	Respond    uint8
	TCPRespond uint8
	_          uint8
}

// opts bundles the resolved agent configuration.
type opts struct {
	ifaceName     string
	ifType        uint8
	nodeID        string
	respond       bool
	tcpRespond    bool
	localIPs      []net.IP
	watch         bool
	watchInterval time.Duration
	watchVXLAN    bool
	metricsAddr   string
	hmacKey       []byte
	az            string
	collectorURL  string
	otlpEndpoint  string
	xdp           bool
}

func main() {
	var (
		ifaceName    = flag.String("iface", "", "interface to attach to (or use --watch)")
		ifaceType    = flag.String("iface-type", "auto", "interface type: auto | regular | vxlan")
		nodeID       = flag.String("node-id", "", "node identifier (default: hostname)")
		respond      = flag.Bool("respond", true, "reply to need_response=1 packets whose dst is a local VM IP")
		tcpRespond   = flag.Bool("tcp-respond", true, "answer TCP probes in userspace; false lets the real VM stack reply")
		localIPCSV   = flag.String("local-ip", "", "comma-separated local VM IPs this agent answers for (static mode)")
		watch        = flag.Bool("watch", false, "auto-attach to OVN VM taps via ovs-vsctl and follow VM lifecycle")
		watchInt     = flag.Duration("watch-interval", 5*time.Second, "tap re-scan interval in --watch mode")
		watchVXLAN   = flag.Bool("watch-vxlan", false, "follow per-tenant VXLAN netdevs via netlink and tag observations with the device VNI")
		metricsAddr  = flag.String("metrics-addr", "", "host:port for Prometheus /metrics + /healthz (empty = off)")
		hmacKey      = flag.String("hmac-key", "", "shared secret; responder rejects requests without a valid HMAC (empty = auth off)")
		az           = flag.String("az", "", "availability zone; tagged onto every observation")
		collectorURL = flag.String("collector-url", "", "POST each observation as JSON to this URL (empty = stdout only)")
		otlpEndpoint = flag.String("otlp-endpoint", "", "OTLP/HTTP endpoint host:port; export each observation as a span (run id = trace id)")
		xdp          = flag.Bool("xdp", false, "attach at the XDP hook (ingress-only) instead of TC — for NICs in native/AF_XDP mode")
	)
	flag.Parse()

	if *ifaceName == "" && !*watch && !*watchVXLAN {
		log.Fatal("need --iface NAME, --watch, or --watch-vxlan")
	}
	if *nodeID == "" {
		h, _ := os.Hostname()
		*nodeID = h
	}

	var ifType uint8
	switch *ifaceType {
	case "auto":
		ifType = tfmeta.IfaceAuto
	case "regular":
		ifType = tfmeta.IfaceRegular
	case "vxlan":
		ifType = tfmeta.IfaceVXLAN
	default:
		log.Fatalf("invalid --iface-type %q (want auto|regular|vxlan)", *ifaceType)
	}

	// Watch modes attach to VM taps and to VXLAN netdevs, both of which present
	// plain inner frames — so the parse mode must be auto/regular, never vxlan.
	if (*watch || *watchVXLAN) && ifType == tfmeta.IfaceVXLAN {
		log.Printf("watch mode: overriding --iface-type=vxlan to auto (netdevs carry inner frames)")
		ifType = tfmeta.IfaceAuto
	}

	localIPs, err := parseLocalIPs(*localIPCSV)
	if err != nil {
		log.Fatal(err)
	}

	err = run(opts{
		ifaceName:     *ifaceName,
		ifType:        ifType,
		nodeID:        *nodeID,
		respond:       *respond,
		tcpRespond:    *tcpRespond,
		localIPs:      localIPs,
		watch:         *watch,
		watchInterval: *watchInt,
		watchVXLAN:    *watchVXLAN,
		metricsAddr:   *metricsAddr,
		hmacKey:       []byte(*hmacKey),
		az:            *az,
		collectorURL:  *collectorURL,
		otlpEndpoint:  *otlpEndpoint,
		xdp:           *xdp,
	})
	if err != nil {
		log.Fatal(err)
	}
}

func run(o opts) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs traceflowObjects
	if err := loadTraceflowObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	cfg := tfConfig{IfaceType: o.ifType}
	if o.respond {
		cfg.Respond = 1
	}
	if o.tcpRespond {
		cfg.TCPRespond = 1
	}
	if err := objs.ConfigMap.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("write config map: %w", err)
	}

	// Register static local VM IPs so the eBPF program intercepts probes destined
	// here (watch mode registers per-tap IPs as taps come and go).
	if err := addLocalIPs(objs.LocalIps, o.localIPs); err != nil {
		return fmt.Errorf("write local_ips map: %w", err)
	}

	if o.metricsAddr != "" {
		srv := serveMetrics(o.metricsAddr, o.nodeID, objs.StatsMap)
		defer srv.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	// Close the reader on signal so readLoop returns and defers unwind.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	hook := "tc"
	if o.xdp {
		hook = "xdp"
	}
	log.Printf("traceflow agent up: hook=%s type=%s node_id=%s respond=%v",
		hook, ifaceTypeString(o.ifType), o.nodeID, o.respond)

	if o.ifaceName != "" {
		closeAttach, err := attachStatic(&objs, o)
		if err != nil {
			return err
		}
		defer closeAttach()
	}
	em := newEmitter(o)
	defer em.close()

	if o.watch {
		mgr := newTapManager(&objs, o.ifType, o.respond, o.tcpRespond, o.hmacKey, o.xdp)
		defer mgr.closeAll()
		stop := make(chan struct{})
		defer close(stop)
		go runWatcher(stop, mgr, o.watchInterval)
		log.Printf("tap watch up: ovs-vsctl every %s", o.watchInterval)
	}
	if o.watchVXLAN {
		vm := newVXLANManager(&objs, o.xdp)
		defer vm.closeAll()
		stop := make(chan struct{})
		defer close(stop)
		go runVXLANWatcher(stop, vm)
		log.Printf("vxlan watch up: netlink link events")
	}

	readLoop(rd, em)
	return nil
}

// attachStatic attaches to a single named interface and, when eligible, starts a
// responder for the configured local IPs. Returns a cleanup closure.
func attachStatic(objs *traceflowObjects, o opts) (func(), error) {
	iface, err := net.InterfaceByName(o.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", o.ifaceName, err)
	}
	detach, err := attachIface(objs, iface.Index, o.xdp)
	if err != nil {
		return nil, err
	}
	var resp *responder
	switch {
	case o.respond && len(o.localIPs) > 0:
		resp, err = newResponder(iface, o.ifType, o.localIPs, o.tcpRespond, o.hmacKey)
		if err != nil {
			detach()
			return nil, fmt.Errorf("start responder: %w", err)
		}
		go resp.Loop()
		log.Printf("responder answering for local dst: %v", o.localIPs)
	case o.respond:
		log.Printf("observe-only: no --local-ip given, this agent never replies (transit/VTEP)")
	}
	log.Printf("traceflow agent up: iface=%s type=%s node_id=%s",
		o.ifaceName, ifaceTypeString(o.ifType), o.nodeID)

	return func() {
		detach()
		if resp != nil {
			resp.Close()
		}
	}, nil
}

func readLoop(rd *ringbuf.Reader, em *emitter) {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("shutting down")
				return
			}
			mtr.readErrors.Add(1)
			log.Printf("ringbuf read: %v", err)
			continue
		}
		raw, err := observation.Parse(rec.RawSample)
		if err != nil {
			mtr.parseErrors.Add(1)
			log.Printf("parse observation: %v", err)
			continue
		}
		em.emit(raw.Enrich(em.nodeID, time.Now()))
	}
}

// parseLocalIPs turns a comma-separated list into []net.IP, rejecting junk.
func parseLocalIPs(csv string) ([]net.IP, error) {
	if csv == "" {
		return nil, nil
	}
	var out []net.IP
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid --local-ip entry %q", s)
		}
		out = append(out, ip)
	}
	return out, nil
}

// ipKey16 renders an IP into the 16-byte key layout the eBPF observation uses:
// IPv4 in the first 4 bytes (rest zero), IPv6 in all 16. This matches obs.dst_ip
// so a local_ips lookup keyed on the inner dst hits.
func ipKey16(ip net.IP) [16]byte {
	var k [16]byte
	if v4 := ip.To4(); v4 != nil {
		copy(k[:4], v4)
	} else {
		copy(k[:], ip.To16())
	}
	return k
}

// addLocalIPs registers VM destination IPs in the local_ips map, telling the eBPF
// program that this host is their final destination (so it intercepts probes to
// them). Safe to call with a nil/empty slice.
func addLocalIPs(m *ebpf.Map, ips []net.IP) error {
	for _, ip := range ips {
		k := ipKey16(ip)
		if err := m.Put(k, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

// delLocalIPs removes VM destination IPs from the local_ips map.
func delLocalIPs(m *ebpf.Map, ips []net.IP) {
	for _, ip := range ips {
		k := ipKey16(ip)
		_ = m.Delete(k)
	}
}

func ifaceTypeString(t uint8) string {
	switch t {
	case tfmeta.IfaceAuto:
		return "auto"
	case tfmeta.IfaceVXLAN:
		return "vxlan"
	default:
		return "regular"
	}
}
