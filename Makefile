# TELOS Runtime - Build System
#
# Targets:
#   all      - Build everything
#   bpf      - Compile eBPF bytecode
#   loader   - Build Go loader daemon
#   proto    - Regenerate protobuf files
#   install  - Install extension and daemons
#   clean    - Remove build artifacts
#   test     - Run tests
#
# Requirements:
#   - clang (with BPF target support)
#   - llvm
#   - Go 1.21+
#   - Python 3.10+
#   - libbpf-dev
#   - bpftool (optional, for debugging)

# === CONFIGURATION ===

CLANG := clang
GO := go
PYTHON := python3

# BPF compilation flags
BPF_CFLAGS := -O2 -g -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -Wall -Werror

# Kernel headers for vmlinux.h
# Generate with: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
VMLINUX_H := telos_core/src/vmlinux.h

# Output directory
BIN_DIR := bin

# === SOURCE FILES ===

BPF_SRC := telos_core/src/bpf_lsm.c
BPF_OBJ := $(BIN_DIR)/bpf_lsm.o

LOADER_SRC := telos_core/loader/main.go
LOADER_BIN := $(BIN_DIR)/telos_daemon

# === PHONY TARGETS ===

.PHONY: all bpf loader proto install install_ext clean test vmlinux help

# === DEFAULT TARGET ===

all: bpf loader
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════╗"
	@echo "║              TELOS Build Complete                      ║"
	@echo "╚═══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Outputs:"
	@echo "  $(BPF_OBJ)     - eBPF bytecode"
	@echo "  $(LOADER_BIN)  - Userspace daemon"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Install Python deps:  pip install -r cortex/requirements.txt"
	@echo "  2. Start Core:           sudo $(LOADER_BIN)"
	@echo "  3. Start Cortex:         $(PYTHON) cortex/main.py"
	@echo "  4. Install extension:    make install_ext"
	@echo ""

# === BPF TARGET ===

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Generate vmlinux.h if not present
vmlinux:
	@if [ ! -f $(VMLINUX_H) ]; then \
		echo "Generating vmlinux.h from BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
		echo "✓ Generated $(VMLINUX_H)"; \
	else \
		echo "✓ vmlinux.h already exists"; \
	fi

bpf: $(BIN_DIR) vmlinux
	@echo "Compiling eBPF bytecode..."
	$(CLANG) $(BPF_CFLAGS) \
		-I$(dir $(VMLINUX_H)) \
		-I. \
		-c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "✓ Built $(BPF_OBJ)"

# === GO LOADER TARGET ===

loader: $(BIN_DIR)
	@echo "Building Go loader..."
	cd telos_core/loader && $(GO) mod tidy
	cd telos_core/loader && $(GO) build -o ../../$(LOADER_BIN) main.go
	@echo "✓ Built $(LOADER_BIN)"

# === PROTOBUF TARGET ===

proto:
	@echo "Regenerating protobuf files..."
	# Python
	$(PYTHON) -m grpc_tools.protoc \
		-I. \
		--python_out=. \
		--grpc_python_out=. \
		shared/protocol.proto
	# Go
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		shared/protocol.proto
	@echo "✓ Protobuf files regenerated"

# === INSTALLATION TARGETS ===

install: install_ext install_deps
	@echo "✓ Installation complete"

install_ext:
	@echo "Installing Chrome extension native host..."
	chmod +x browser_eye/native_host/install_host.sh
	./browser_eye/native_host/install_host.sh
	chmod +x browser_eye/native_host/host_messaging.py

install_deps:
	@echo "Installing Python dependencies..."
	pip install -r cortex/requirements.txt

# === TEST TARGETS ===

test: test_loader
	@echo "✓ All tests passed"

test_loader:
	@echo "Testing Go loader build..."
	cd telos_core/loader && $(GO) build -o /dev/null main.go
	@echo "✓ Loader builds successfully"

# === CLEAN TARGET ===

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f /sys/fs/bpf/telos/*
	rm -f /var/run/telos.sock
	rm -f /tmp/telos_*.log
	@echo "✓ Clean complete"

# === HELP ===

help:
	@echo "TELOS Runtime Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all         Build BPF and loader (default)"
	@echo "  bpf         Compile eBPF bytecode only"
	@echo "  loader      Build Go loader only"
	@echo "  vmlinux     Generate vmlinux.h from kernel BTF"
	@echo "  proto       Regenerate protobuf files"
	@echo "  install     Install everything"
	@echo "  install_ext Install Chrome native host"
	@echo "  clean       Remove build artifacts"
	@echo "  test        Run tests"
	@echo "  help        Show this help"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Linux kernel 5.15+ with BTF and LSM BPF support"
	@echo "  - clang with BPF target"
	@echo "  - Go 1.21+"
	@echo "  - bpftool (for vmlinux.h generation)"
