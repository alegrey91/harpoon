BINARY_NAME=example-app
BINARY_DIR=bin
UNIT_TEST_DIR=/tmp/unit

build:
	go mod download
	go build \
		-v \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		main.go

test-build:
	go build \
		-v \
		-cover \
		-o ${BINARY_DIR}/${BINARY_NAME} \
		main.go

run:
	go run main.go

test: unit-test

# here we are compiling the _test package(s) we want to test,
# so we are able to run manually unsing the `strace` utility.
unit-test:
	rm -rf ${UNIT_TEST_DIR}
	mkdir ${UNIT_TEST_DIR}
	# loop over each package
	go test \
		-cover \
		-c github.com/alegrey91/${BINARY_NAME}/pkg/randomic \
		-o ${BINARY_DIR}/randomic.test;

clean:
	rm -rf ${BINARY_DIR}/*
	rm -rf ${UNIT_TEST_DIR}
	rm -rf ${INTEGRATION_TEST_DIR}
	rm -rf ${STRACE_LOG_DIR}

all: build
