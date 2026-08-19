# Traceflow — rootless-podman-friendly multi-stage build.
#
# Build (rootless):
#   podman build -t traceflow:latest -f Containerfile .
#
# Run the agent (needs BPF + net caps; rootless may require --privileged and a
# kernel that permits BPF from a user namespace — otherwise run rootful):
#   podman run --rm --privileged --net=host traceflow:latest \
#       agent --iface eth0 --node-id hv-01
#
# Run the integration suite inside the container (creates its own netns):
#   podman run --rm --privileged traceflow:latest itest
#
# Unit tests run at build time in the builder stage, so a green build means the
# pure-logic tests passed.

########################  builder  ########################
FROM docker.io/library/golang:1.22-bookworm AS builder

# eBPF toolchain: clang/llvm compile bpf/traceflow.c; libbpf-dev + linux-libc-dev
# provide <bpf/bpf_helpers.h> and <linux/bpf.h>. No CGO — cilium/ebpf is pure Go.
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
COPY go.mod ./
RUN go mod tidy

COPY . .
# Recompute go.sum against the full source, generate eBPF bindings, test, build.
RUN go mod tidy \
	&& go generate ./... \
	&& go vet ./... \
	&& go test ./... \
	&& go build -o /out/agent ./agent \
	&& go build -o /out/client ./client \
	&& go build -o /out/collector ./collector

########################  runtime  ########################
FROM docker.io/library/debian:bookworm-slim

# iproute2 (ip/netns/veth/vxlan), procps (sysctl), jq for the test asserts.
RUN apt-get update && apt-get install -y --no-install-recommends \
	iproute2 procps jq bash \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/agent     /usr/local/bin/agent
COPY --from=builder /out/client    /usr/local/bin/client
COPY --from=builder /out/collector /usr/local/bin/collector

WORKDIR /opt/traceflow
COPY tests   ./tests
COPY scripts ./scripts
COPY README.md ./

# Point the test harness at the installed binaries.
ENV AGENT=/usr/local/bin/agent CLIENT=/usr/local/bin/client

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["help"]
