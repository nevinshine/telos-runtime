#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    echo "[test] Missing Python executable (python/python3)."
    exit 1
  fi
fi

GO_BIN="${GO_BIN:-go}"
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
  echo "[test] Missing Go executable (go)."
  exit 1
fi

echo "[test] Running Go module tests..."
go_workspace_modules="$(
  "$GO_BIN" work edit -json 2>/dev/null \
    | "$PYTHON_BIN" -c 'import json,sys; data=json.load(sys.stdin); [print(use.get("DiskPath","")) for use in data.get("Use", [])]' \
    | sed '/^$/d' \
    | sort -u
)"
if [ -z "$go_workspace_modules" ]; then
  echo "[test] No Go workspace modules found in go.work."
  exit 1
fi
while IFS= read -r module_dir; do
  [ -n "$module_dir" ] || continue
  if [ ! -d "$module_dir" ]; then
    echo "[test] Skipping missing module directory: $module_dir"
    continue
  fi
  echo "[test] go test ./... ($module_dir)"
  (cd "$module_dir" && "$GO_BIN" test ./...)
done <<EOF_GO_MODULES
$go_workspace_modules
EOF_GO_MODULES

echo "[test] Running Python unit tests..."
"$PYTHON_BIN" -m unittest discover -s cortex -p 'test_*.py'

selected_test_count=0
test_files="$(find tests -type f -name 'test_*.py' 2>/dev/null | sort || true)"
if [ -n "$test_files" ]; then
  while IFS= read -r test_file; do
    if [ "$test_file" = "tests/test_web_dashboard.py" ] && [ ! -f web_dashboard.py ]; then
      echo "[test] Skipping tests/test_web_dashboard.py because web_dashboard.py is not present in this checkout."
      continue
    fi

    test_module="${test_file%.py}"
    test_module="${test_module#./}"
    test_module="${test_module//\//.}"
    "$PYTHON_BIN" -m unittest "$test_module"
    selected_test_count=$((selected_test_count + 1))
  done <<EOF_TESTS
$test_files
EOF_TESTS
fi

if [ "$selected_test_count" -eq 0 ]; then
  echo "[test] No runnable tests found under tests/."
fi

echo "[test] All tests passed."
