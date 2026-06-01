FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    python3 \
    python3-pip \
    golang-go \
    linux-tools-common \
    linux-tools-generic \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip3 install -r cortex/requirements.txt
RUN make all

CMD ["sh", "-c", "sudo bin/telos_daemon & python3 cortex/main.py"]
