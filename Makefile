BINARY_NAME=harpoon
BINARY_DIR=./bin

build: create-bin-dir
	go mod download
	go build \
		-v \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

build-gh: create-bin-dir
	go mod download
	go build \
		-v \
		-ldflags="-s -w -X 'main.version=${GITHUB_REF_NAME}'" \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		.

create-bin-dir:
	mkdir -p ${BINARY_DIR}
