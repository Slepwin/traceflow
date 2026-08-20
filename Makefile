# Traceflow — build orchestration.
#
# Prerequisites:
#   - Go >= 1.22
#   - clang/llvm (for compiling the eBPF C via bpf2go)
#   - libbpf headers  (Debian/Ubuntu: apt install libbpf-dev clang llvm)
#   - Linux kernel >= 6.6 (TCX attach) with CAP_BPF / root to run
#
# Typical flow:
#   make deps        # go mod tidy
#   make generate    # compile bpf/traceflow.c -> Go bindings
#   make build       # produce bin/agent and bin/client

BIN := bin
IMAGE ?= traceflow:latest

# Per-component release images (deploy/docker/Dockerfile). REGISTRY/OWNER/VERSION
# override the tag: e.g. `make images REGISTRY=ghcr.io OWNER=slepwin VERSION=v1.4.0`.
REGISTRY  ?= ghcr.io
OWNER     ?= slepwin
VERSION   ?= dev
PLATFORMS ?= linux/amd64,linux/arm64
DOCKERFILE := deploy/docker/Dockerfile
COMPONENTS := agent client collector

.PHONY: all deps generate build agent client collector test itest image image-itest \
	images images-push $(addprefix image-,$(COMPONENTS)) clean

all: build

deps:
	go mod tidy

# Compiles bpf/traceflow.c and writes traceflow_bpfel.go / *_bpfeb.go + objects.
generate:
	cd agent && go generate ./...

build: generate agent client collector

agent:
	CGO_ENABLED=0 go build -o $(BIN)/agent ./agent

client:
	CGO_ENABLED=0 go build -o $(BIN)/client ./client

collector:
	CGO_ENABLED=0 go build -o $(BIN)/collector ./collector

# Pure-logic unit tests — no root, no eBPF, no netns. Includes the agent's OVS
# JSON parser tests (needs generated bindings: run `make generate` first).
test:
	go test ./...

# Integration tests — build the binaries, then run the netns/veth/VXLAN suite.
# Needs CAP_NET_ADMIN + BPF caps; tests SKIP (not fail) when eBPF can't load.
itest: build
	./tests/run-integration.sh

# Rootless container image (unit tests run in the builder stage).
image:
	podman build -t $(IMAGE) -f Containerfile .

# Run the integration suite inside the container (needs --privileged).
image-itest: image
	podman run --rm --privileged $(IMAGE) itest

# Per-component images. `make images` builds all three locally (single-arch,
# loaded into the engine); `make image-agent` builds just one. Uses docker
# buildx — the same Dockerfile CI pushes multi-arch.
images: $(addprefix image-,$(COMPONENTS))

image-%:
	docker buildx build -f $(DOCKERFILE) --target $* \
		-t $(REGISTRY)/$(OWNER)/traceflow-$*:$(VERSION) --load .

# Build and push all three multi-arch (needs `docker login $(REGISTRY)`).
images-push:
	@for c in $(COMPONENTS); do \
		docker buildx build -f $(DOCKERFILE) --target $$c \
			--platform $(PLATFORMS) \
			-t $(REGISTRY)/$(OWNER)/traceflow-$$c:$(VERSION) --push . ; \
	done

clean:
	rm -rf $(BIN)
	rm -f agent/traceflow_bpf*.go agent/traceflow_bpf*.o
