# Minimal Base Image
FROM golang:1.23.2 AS builder

WORKDIR /workspace

# Install required dependencies
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
	clang \
	git \
	libbpf-dev \
	libseccomp-dev \
	build-essential \
	bpftool \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the required file to build the application
COPY cmd/ cmd/
COPY ebpf/ ebpf/
COPY internal/ internal/
COPY main.go main.go
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile 

# Build harpoon
RUN make build

# Final stage
FROM debian:bookworm-slim

WORKDIR /

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
    libelf1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/bin/harpoon .

# run it with the following command:
# docker run \
# -it \
# --rm \
# --privileged \
# --net=host \
# --pid=host \
# -v /sys/kernel/debug/:/sys/kernel/debug:rw \
# harpoon:latest
ENTRYPOINT ["/bin/bash"]
