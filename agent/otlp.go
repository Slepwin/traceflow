package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/traceflow/traceflow/internal/observation"
)

// otlpSink exports each observation as an OpenTelemetry span. The run UUID maps
// directly onto the 128-bit OTLP trace id, so observations from every host along
// a path land in one trace; each is a span whose fields become attributes. A
// synthetic parent span id is derived from the UUID so all spans of a run share
// a common parent (they cluster as one trace in Jaeger/Tempo) without any agent
// having to own a root span. A network path is not a call tree, so spans are
// correlated by the trace id and the `hop` attribute, not by causal nesting.
type otlpSink struct {
	tp     *sdktrace.TracerProvider
	tracer trace.Tracer
}

func newOTLPSink(endpoint, nodeID, az string) (*otlpSink, error) {
	// otlptracehttp posts protobuf to <endpoint>/v1/traces. Endpoint is host:port
	// (no scheme); TLS is off by default here.
	exp, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	attrs := []attribute.KeyValue{
		attribute.String("service.name", "traceflow"),
		attribute.String("host.name", nodeID),
	}
	if az != "" {
		attrs = append(attrs, attribute.String("cloud.availability_zone", az))
	}
	res, err := resource.New(context.Background(), resource.WithAttributes(attrs...))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		// Short batch timeout so path spans reach the backend promptly, not only
		// on shutdown — diagnostics want the trace visible quickly.
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(time.Second)),
		sdktrace.WithResource(res),
	)
	return &otlpSink{tp: tp, tracer: tp.Tracer("traceflow")}, nil
}

// export turns one observation into a span. Non-blocking: the batch span
// processor queues and exports asynchronously.
func (s *otlpSink) export(o observation.Observation) {
	u, err := uuid.Parse(o.ID)
	if err != nil {
		return
	}
	tid := trace.TraceID(u) // both are [16]byte
	var parent trace.SpanID
	copy(parent[:], u[:8]) // deterministic synthetic root, shared across agents

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     parent,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), sc)

	start := time.Now()
	if t, err := time.Parse(time.RFC3339Nano, o.Timestamp); err == nil {
		start = t
	}
	name := fmt.Sprintf("%s %s %s→%s", o.NodeID, o.Direction, o.SrcIP, o.DstIP)

	_, span := s.tracer.Start(ctx, name,
		trace.WithTimestamp(start),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(otlpAttrs(o)...),
	)
	span.End(trace.WithTimestamp(start)) // point-in-time observation
}

func (s *otlpSink) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.tp.Shutdown(ctx); err != nil {
		log.Printf("otlp shutdown: %v", err)
	}
}

func otlpAttrs(o observation.Observation) []attribute.KeyValue {
	a := []attribute.KeyValue{
		attribute.String("traceflow.node_id", o.NodeID),
		attribute.Int("traceflow.hop", int(o.Hop)),
		attribute.String("traceflow.direction", o.Direction),
		attribute.String("traceflow.protocol", o.Protocol),
		attribute.String("traceflow.iface_type", o.IfaceType),
		attribute.String("traceflow.action", o.Action),
		attribute.String("source.address", o.SrcIP),
		attribute.String("destination.address", o.DstIP),
		attribute.Int64("traceflow.latency_ns", o.LatencyNS),
	}
	if o.VNI != 0 {
		a = append(a, attribute.Int64("traceflow.vni", int64(o.VNI)))
	}
	if o.VLAN != 0 {
		a = append(a, attribute.Int("traceflow.vlan", int(o.VLAN)))
	}
	if o.AZ != "" {
		a = append(a, attribute.String("cloud.availability_zone", o.AZ))
	}
	if o.Iface != "" {
		a = append(a, attribute.String("traceflow.iface", o.Iface))
	}
	if o.LogicalSwitch != "" {
		a = append(a, attribute.String("traceflow.logical_switch", o.LogicalSwitch))
	}
	if o.SrcPort != 0 {
		a = append(a, attribute.Int("source.port", int(o.SrcPort)))
	}
	if o.DstPort != 0 {
		a = append(a, attribute.Int("destination.port", int(o.DstPort)))
	}
	if o.TCPFlags != "" {
		a = append(a, attribute.String("traceflow.tcp_flags", o.TCPFlags))
	}
	if o.ClockSkew {
		a = append(a, attribute.Bool("traceflow.clock_skew", true))
	}
	return a
}
