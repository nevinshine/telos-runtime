#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

VMLINUX_BTF="/sys/kernel/btf/vmlinux"
VMLINUX_HEADER="telos_core/src/vmlinux.h"
VMLINUX_HEADER_FALLBACK=""

BPF_CFLAGS=(
  -O2
  -g
  -target bpf
  -D__TARGET_ARCH_x86
  -Wall
  -Werror
  -Wno-missing-declarations
)

BPF_SYS_INCLUDES=()
host_multiarch=""
if command -v dpkg-architecture >/dev/null 2>&1; then
  host_multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
fi
if [ -n "$host_multiarch" ] && [ -d "/usr/include/$host_multiarch" ]; then
  BPF_SYS_INCLUDES+=("-I/usr/include/$host_multiarch")
fi

uname_arch_include="/usr/include/$(uname -m)-linux-gnu"
if [ -d "$uname_arch_include" ] && [ "$uname_arch_include" != "/usr/include/$host_multiarch" ]; then
  BPF_SYS_INCLUDES+=("-I$uname_arch_include")
fi

echo "[ebpf] Kernel: $(uname -r)"
echo "[ebpf] CWD: $PWD"
if [ "${#BPF_SYS_INCLUDES[@]}" -gt 0 ]; then
  echo "[ebpf] Extra system include flags: ${BPF_SYS_INCLUDES[*]}"
fi

if ! command -v clang >/dev/null 2>&1; then
  echo "[ebpf] Missing required tool: clang"
  exit 1
fi

echo "[ebpf] clang: $(command -v clang)"
clang --version | head -n 1

BPFTOOL_BIN=""
if command -v bpftool >/dev/null 2>&1; then
  maybe_bpftool="$(command -v bpftool)"
  if "$maybe_bpftool" version >/dev/null 2>&1; then
    BPFTOOL_BIN="$maybe_bpftool"
  fi
fi

if [ -z "$BPFTOOL_BIN" ]; then
  while IFS= read -r candidate; do
    if [ -x "$candidate" ] && "$candidate" version >/dev/null 2>&1; then
      BPFTOOL_BIN="$candidate"
      break
    fi
  done < <(
    find /usr/lib -type f -name bpftool 2>/dev/null | sort -V -r
  )
fi

if [ -n "$BPFTOOL_BIN" ] && [ -r "$VMLINUX_BTF" ]; then
  echo "[ebpf] bpftool: $BPFTOOL_BIN"
  "$BPFTOOL_BIN" version
  echo "[ebpf] Generating $VMLINUX_HEADER from kernel BTF..."
  "$BPFTOOL_BIN" btf dump file "$VMLINUX_BTF" format c > "$VMLINUX_HEADER"
  echo "[ebpf] Generated vmlinux.h lines: $(wc -l < "$VMLINUX_HEADER")"
else
  echo "[ebpf] Runnable bpftool+kernel BTF unavailable, attempting linux-bpf-dev fallback."
  VMLINUX_HEADER_FALLBACK="$(find /usr/include -type f \( -path '*/linux/vmlinux.h' -o -path '*/linux/bpf/vmlinux.h' \) 2>/dev/null | head -n 1 || true)"
  if [ -z "$VMLINUX_HEADER_FALLBACK" ]; then
    echo "[ebpf] Could not find fallback vmlinux.h under /usr/include."
    echo "[ebpf] Install linux-bpf-dev or provide a runnable bpftool."
    ls -la /sys/kernel/btf || true
    exit 1
  fi
  echo "[ebpf] Using fallback header: $VMLINUX_HEADER_FALLBACK"
  cp "$VMLINUX_HEADER_FALLBACK" "$VMLINUX_HEADER"
fi

echo "[ebpf] Compiling telos_core/src/bpf_lsm.c..."
clang "${BPF_CFLAGS[@]}" \
  "${BPF_SYS_INCLUDES[@]}" \
  -Itelos_core/src \
  -I. \
  -c telos_core/src/bpf_lsm.c \
  -o /tmp/telos-bpf_lsm.o

echo "[ebpf] Compiling telos_edge/src/xdp_filter.c..."
clang "${BPF_CFLAGS[@]}" \
  "${BPF_SYS_INCLUDES[@]}" \
  -I. \
  -c telos_edge/src/xdp_filter.c \
  -o /tmp/telos-xdp_filter.o

echo "[ebpf] Compiling telos_core/mirage_poc/mirage.bpf.c..."
clang "${BPF_CFLAGS[@]}" \
  "${BPF_SYS_INCLUDES[@]}" \
  -Itelos_core/src \
  -I. \
  -c telos_core/mirage_poc/mirage.bpf.c \
  -o /tmp/telos-mirage.o

echo "[ebpf] eBPF build validation passed."
