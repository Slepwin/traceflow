package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

// stats_map indices (mirror bpf/traceflow.h).
const (
	statObserved    uint32 = 0 // TF_STAT_OBSERVED
	statRingbufFull uint32 = 1 // TF_STAT_RINGBUF_FULL
)

// metrics holds the userspace-side counters. The eBPF-side counters live in the
// per-CPU stats map and are read on demand.
type metrics struct {
	parseErrors  atomic.Uint64
	readErrors   atomic.Uint64
	repliesSent  atomic.Uint64
	authFailures atomic.Uint64
	tapsWatched  atomic.Int64
	vxlanWatched atomic.Int64
}

var mtr metrics

// sumPerCPU reads one per-CPU counter and sums across CPUs.
func sumPerCPU(m *ebpf.Map, key uint32) uint64 {
	var vals []uint64
	if err := m.Lookup(key, &vals); err != nil {
		return 0
	}
	var s uint64
	for _, v := range vals {
		s += v
	}
	return s
}

// serveMetrics starts a tiny HTTP server exposing /metrics (Prometheus text) and
// /healthz. Returns the server so the caller can Close it on shutdown.
func serveMetrics(addr, nodeID string, stats *ebpf.Map) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		counter(w, "traceflow_observations_total",
			"Marked packets observed and pushed to the ring buffer.",
			nodeID, sumPerCPU(stats, statObserved))
		counter(w, "traceflow_ringbuf_drops_total",
			"Observations dropped because the ring buffer was full (reader too slow).",
			nodeID, sumPerCPU(stats, statRingbufFull))
		counter(w, "traceflow_parse_errors_total",
			"Ring-buffer records that failed to decode.",
			nodeID, mtr.parseErrors.Load())
		counter(w, "traceflow_ringbuf_read_errors_total",
			"Ring-buffer read errors.",
			nodeID, mtr.readErrors.Load())
		counter(w, "traceflow_replies_sent_total",
			"Replies emitted by the responder.",
			nodeID, mtr.repliesSent.Load())
		counter(w, "traceflow_auth_failures_total",
			"Requests rejected by the responder for a bad/missing HMAC.",
			nodeID, mtr.authFailures.Load())
		gauge(w, "traceflow_taps_watched",
			"VM taps currently attached in watch mode.",
			nodeID, uint64(mtr.tapsWatched.Load()))
		gauge(w, "traceflow_vxlan_ifaces_watched",
			"Per-tenant VXLAN netdevs currently attached (netlink watcher).",
			nodeID, uint64(mtr.vxlanWatched.Load()))
		gauge(w, "traceflow_up", "1 if the agent is running.", nodeID, 1)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server: %v", err)
		}
	}()
	log.Printf("metrics on http://%s/metrics (and /healthz)", addr)
	return srv
}

func counter(w http.ResponseWriter, name, help, node string, v uint64) {
	metric(w, name, help, "counter", node, v)
}

func gauge(w http.ResponseWriter, name, help, node string, v uint64) {
	metric(w, name, help, "gauge", node, v)
}

func metric(w http.ResponseWriter, name, help, typ, node string, v uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s{node=%q} %d\n", name, help, name, typ, name, node, v)
}
