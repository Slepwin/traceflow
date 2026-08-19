module github.com/traceflow/traceflow

go 1.22

require (
	github.com/cilium/ebpf v0.16.0
	github.com/google/uuid v1.6.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	go.opentelemetry.io/otel v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.28.0
	go.opentelemetry.io/otel/sdk v1.28.0
	go.opentelemetry.io/otel/trace v1.28.0
	golang.org/x/sys v0.24.0
)
