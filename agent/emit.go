package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/traceflow/traceflow/internal/observation"
	"github.com/traceflow/traceflow/internal/ovs"
)

// emitter enriches each observation (AZ, VNI→logical switch) and sinks it to
// stdout and, optionally, to a collector over HTTP.
type emitter struct {
	nodeID string
	az     string
	enc    *json.Encoder

	// VNI -> OVN logical-switch name, resolved best-effort from the SB DB.
	lsMu    sync.Mutex
	lsCache map[uint32]string

	// collector sink (nil when --collector-url is empty)
	url    string
	client *http.Client
	queue  chan observation.Observation
	wg     sync.WaitGroup

	// OTLP sink (nil when --otlp-endpoint is empty)
	otlp *otlpSink
}

func newEmitter(o opts) *emitter {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	e := &emitter{nodeID: o.nodeID, az: o.az, enc: enc, lsCache: map[uint32]string{}}
	if o.collectorURL != "" {
		e.url = o.collectorURL
		e.client = &http.Client{Timeout: 3 * time.Second}
		e.queue = make(chan observation.Observation, 1024)
		e.wg.Add(1)
		go e.shipLoop()
		log.Printf("shipping observations to collector %s", o.collectorURL)
	}
	if o.otlpEndpoint != "" {
		sink, err := newOTLPSink(o.otlpEndpoint, o.nodeID, o.az)
		if err != nil {
			log.Printf("otlp: disabled (%v)", err)
		} else {
			e.otlp = sink
			log.Printf("exporting observations as OTLP spans to %s", o.otlpEndpoint)
		}
	}
	return e
}

func (e *emitter) emit(obs observation.Observation) {
	obs.AZ = e.az
	if obs.VNI != 0 {
		obs.LogicalSwitch = e.logicalSwitch(obs.VNI)
	}
	if err := e.enc.Encode(obs); err != nil {
		log.Printf("encode observation: %v", err)
	}
	if e.queue != nil {
		select {
		case e.queue <- obs:
		default: // collector backpressure: drop rather than block the reader
		}
	}
	if e.otlp != nil {
		e.otlp.export(obs)
	}
}

func (e *emitter) close() {
	if e.queue != nil {
		close(e.queue)
		e.wg.Wait()
	}
	if e.otlp != nil {
		e.otlp.shutdown()
	}
}

func (e *emitter) shipLoop() {
	defer e.wg.Done()
	for obs := range e.queue {
		body, err := json.Marshal(obs)
		if err != nil {
			continue
		}
		resp, err := e.client.Post(e.url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("collector post: %v", err)
			continue
		}
		resp.Body.Close()
	}
}

// logicalSwitch resolves a VNI to its OVN logical-switch name via the SB DB,
// cached. Empty if OVN is unavailable or the VNI is not an OVN datapath key
// (e.g. a DCI VXLAN VNI).
func (e *emitter) logicalSwitch(vni uint32) string {
	e.lsMu.Lock()
	defer e.lsMu.Unlock()
	if n, ok := e.lsCache[vni]; ok {
		return n
	}
	name, _ := ovs.LookupDatapathName(context.Background(), vni)
	e.lsCache[vni] = name
	return name
}
