# Traceflow - per-component release images.
#
# One shared builder stage compiles the eBPF object and cross-builds all three
# static Go binaries; three small final stages package one component each.
#
# The builder runs on the *build* platform (native, no emulation) and cross
# compiles to $TARGETARCH via GOARCH - so `docker buildx --platform
# linux/amd64,linux/arm64` is fast. The eBPF object is endianness-specific, not
# arch-specific: bpf2go emits both a little- and big-endian variant and the Go
# build selects by GOARCH build tags, so generating once on the build host is
# correct for every little-endian target (amd64, arm64).
#
# Build a single component:
#   docker buildx build -f deploy/docker/Dockerfile --target agent \
#       -t traceflow-agent:dev --load .
#
# CI builds each target for linux/amd64,linux/arm64 and pushes to GHCR.

########################  builder  ########################
# --platform=$BUILDPLATFORM keeps the toolchain native; we cross-compile in Go.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.22-bookworm AS builder

# eBPF toolchain: clang/llvm compile bpf/traceflow.c; libbpf-dev + linux-libc-dev
# provide <bpf/bpf_helpers.h> and <linux/bpf.h>. No CGO - cilium/ebpf is pure Go.
RUN apt-get update && apt-get install -y --no-install-recommends \
	clang llvm libbpf-dev linux-libc-dev make \
	&& rm -rf /var/lib/apt/lists/*

# clang with `-target bpf` does not search the Debian multiarch include dir, so
# <asm/types.h> (pulled in by <linux/bpf.h>) is not found. Symlink it into the
# default search path. Arch-agnostic: picks whatever *-linux-gnu dir exists.
RUN set -eux; d="$(ls -d /usr/include/*-linux-gnu | head -1)"; ln -sf "$d/asm" /usr/include/asm

WORKDIR /src
ENV GOFLAGS=-mod=mod CGO_ENABLED=0

# Resolve modules first for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS/TARGETARCH are provided by buildx for the platform being produced.
ARG TARGETOS
ARG TARGETARCH

# Generate the eBPF bindings once (host-independent), then cross-compile every
# binary for the requested target. Building all three here means the layer is
# shared across the three final stages within one platform build.
RUN go generate ./... \
	&& GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/agent     ./agent \
	&& GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/client    ./client \
	&& GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/collector ./collector

########################  agent  ########################
# Loads eBPF, may shell out to `ip`/`ovs-vsctl` in watch mode -> needs iproute2.
# Runs privileged (BPF + net caps); stays root.
FROM docker.io/library/debian:bookworm-slim AS agent
RUN apt-get update && apt-get install -y --no-install-recommends \
	iproute2 procps \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/agent /usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/agent"]

########################  client  ########################
# Sends marked probes over a raw socket; pure Go, no external tools needed.
FROM docker.io/library/debian:bookworm-slim AS client
RUN apt-get update && apt-get install -y --no-install-recommends \
	iproute2 \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/client /usr/local/bin/client
ENTRYPOINT ["/usr/local/bin/client"]

########################  collector  ########################
# Pure HTTP aggregator - a static binary on distroless, no shell, runs nonroot.
FROM gcr.io/distroless/static-debian12:nonroot AS collector
COPY --from=builder /out/collector /usr/local/bin/collector
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/collector"]
