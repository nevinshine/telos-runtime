.PHONY: all build bpf loader clean

all: build

build: bpf loader

bpf:
	@echo "Compiling eBPF bytecode..."
	# clang commands will go here

loader:
	@echo "Building Go loaders..."
	# go build commands will go here

clean:
	rm -rf bin/
