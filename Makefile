BINARY_NAME=harpoon
BINARY_DIR=./bin

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

build-bpf:
	clang -g -O2 -c -target bpf -o ebpf.o ebpf/ebpf.c

build: create-bin-dir vmlinux.h build-bpf
	go mod download
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lelf -lz /usr/lib64/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build-gh: create-bin-dir vmlinux.h build-bpf
ifndef GITHUB_REF_NAME
	$(error GITHUB_REF_NAME is undefined)
endif
	go mod download
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lelf -lz /usr/lib64/libbpf.a" \
	go build \
		-tags core,ebpf \
		-v \
		-ldflags="-s -w -X 'main.version=${GITHUB_REF_NAME}'" \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

create-bin-dir:
	mkdir -p ${BINARY_DIR}

clean:
	rm -rf ./bin
