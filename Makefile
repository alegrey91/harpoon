BINARY_NAME=harpoon
BINARY_DIR=./bin
OUTPUT_DIR=./output
IMAGE_NAME?=alegrey91/harpoon
GO_VERSION := $(shell grep '^toolchain' go.mod | awk '{print $$2}' | sed 's/go//')


build-static-libbpfgo:
	git submodule update --init --recursive && \
	make libbpfgo-static

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

build-bpf: create-output-dir
	clang -g -O2 -c -target bpf -D__TARGET_ARCH_x86 -o ${OUTPUT_DIR}/ebpf.o ebpf/ebpf.c
	cp ${OUTPUT_DIR}/ebpf.o ./internal/embeddable/output/

build-go: create-bin-dir
	go mod download
	export CURRENT_DIR=$(shell pwd); \
	CC=gcc \
	CGO_CFLAGS="-I $$CURRENT_DIR/libbpfgo/output" \
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build-go-cover: create-bin-dir
	go mod download
	export CURRENT_DIR=$(shell pwd); \
	CC=gcc \
	CGO_CFLAGS="-I $$CURRENT_DIR/libbpfgo/output" \
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-cover \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build: create-bin-dir vmlinux.h build-static-libbpfgo build-bpf
	go mod download
	export CURRENT_DIR=$(shell pwd); \
	CC=gcc \
	CGO_CFLAGS="-I $$CURRENT_DIR/libbpfgo/output" \
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build-gh: create-bin-dir vmlinux.h build-static-libbpfgo build-bpf
ifndef GITHUB_REF_NAME
	$(error GITHUB_REF_NAME is undefined)
endif
	go mod download
	export CURRENT_DIR=$(shell pwd); \
	CC=gcc \
	CGO_CFLAGS="-I $$CURRENT_DIR/libbpfgo/output" \
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-ldflags="-s -w -X 'github.com/alegrey91/harpoon/cmd.Version=${GITHUB_REF_NAME}'" \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build-docker: build
ifdef GITHUB_REF_NAME
	docker build \
	        --no-cache \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(IMAGE_NAME):latest \
		-t $(IMAGE_NAME):$(GITHUB_REF_NAME) \
		.
else
	docker build \
		--no-cache \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(IMAGE_NAME):latest \
		.
endif

push-docker:
ifdef GITHUB_REF_NAME
	docker push ${IMAGE_NAME}:${GITHUB_REF_NAME}
	docker push ${IMAGE_NAME}:latest
endif

unit-tests:
	mkdir -p /tmp/unit/
	go test \
	  -cover \
	  -v \
	  $(shell go list ./... | grep -v "github.com/alegrey91/harpoon$$" | grep -v ebpf | grep -v cmd) \
	  -skip TestHarpoon \
	  -args -test.gocoverdir=/tmp/unit/

integration-tests:
	mkdir -p /tmp/integration
	go test \
	  -exec sudo \
	  -cover \
	  -v main_test.go \
	  -args -test.gocoverdir=/tmp/integration/

create-bin-dir:
	mkdir -p ${BINARY_DIR}

create-output-dir:
	mkdir -p ${OUTPUT_DIR}

install:
	cp ${BINARY_DIR}/${BINARY_NAME} /usr/local/bin

clean:
	rm -rf ${OUTPUT_DIR}
	rm -rf ${BINARY_DIR}
	rm -rf ./libbpfgo

go-version:
	@grep '^toolchain' go.mod | awk '{print $$2}' | sed 's/go//'
