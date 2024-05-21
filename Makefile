BINARY_NAME=harpoon
BINARY_DIR=./bin
OUTPUT_DIR=./output

build-static-libbpfgo:
	git clone https://github.com/aquasecurity/libbpfgo.git && \
	cd libbpfgo/ && \
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
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build: create-bin-dir vmlinux.h build-static-libbpfgo build-bpf
	go mod download
	export CURRENT_DIR=$(shell pwd); \
	CC=gcc \
	CGO_CFLAGS="-I $$CURRENT_DIR/libbpfgo/output" \
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf.a" \
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
	CGO_LDFLAGS="-lelf -lz $$CURRENT_DIR/libbpfgo/output/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-ldflags="-s -w -X 'github.com/alegrey91/harpoon/cmd.Version=${GITHUB_REF_NAME}'" \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

create-bin-dir:
	mkdir -p ${BINARY_DIR}

create-output-dir:
	mkdir -p ${OUTPUT_DIR}

clean:
	rm -rf ${OUTPUT_DIR}
	rm -rf ${BINARY_DIR}
	rm -rf ./libbpfgo
