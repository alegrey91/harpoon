# Final stage
FROM ubuntu:24.10

WORKDIR /

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
    libelf1 && \
    rm -rf /var/lib/apt/lists/*

COPY bin/harpoon .

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
