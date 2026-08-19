package main

// Compile bpf/traceflow.c and generate Go bindings (traceflow_bpfel.go etc.).
// Run with `go generate ./...` (needs clang + libbpf headers). The generated
// symbols used below: loadTraceflowObjects, traceflowObjects,
// {TraceflowIngress,TraceflowEgress} programs, {ConfigMap,Events} maps.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" traceflow ../bpf/traceflow.c -- -I../bpf
