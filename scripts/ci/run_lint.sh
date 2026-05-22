#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    echo "[lint] Missing Python executable (python/python3)."
    exit 1
  fi
fi

GO_BIN="${GO_BIN:-go}"
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
  echo "[lint] Missing Go executable (go)."
  exit 1
fi

echo "[lint] Running Python lint checks (ruff)..."
ruff check --select E9,F63,F7 .

echo "[lint] Running Python syntax compilation checks..."
python_files_count="$(
  find . \
    \( -path './.git' -o -path './.venv' -o -path './venv' \) -prune -o \
    -type f -name '*.py' -print \
    | wc -l \
    | tr -d ' '
)"
if [ "$python_files_count" -gt 0 ]; then
  find . \
    \( -path './.git' -o -path './.venv' -o -path './venv' \) -prune -o \
    -type f -name '*.py' -print0 \
    | xargs -0 "$PYTHON_BIN" -m compileall -q
else
  echo "[lint] No Python files found."
fi

echo "[lint] Checking Go formatting with gofmt..."
if [ -n "${GITHUB_BASE_REF:-}" ]; then
  git fetch --no-tags --depth=1 origin "$GITHUB_BASE_REF" >/dev/null 2>&1 || true
  go_files="$(git diff --name-only "origin/$GITHUB_BASE_REF"...HEAD -- '*.go' | sort || true)"
else
  go_files="$(find . -type f -name '*.go' -not -path './.git/*' | sort)"
fi

go_files_count="$(printf '%s\n' "$go_files" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "$go_files_count" -gt 0 ]; then
  unformatted="$(printf '%s\n' "$go_files" | sed '/^$/d' | while IFS= read -r go_file; do
    [ -f "$go_file" ] || continue
    gofmt -l "$go_file"
  done)"
  if [ -n "$unformatted" ]; then
    echo "[lint] The following files are not gofmt-formatted:"
    echo "$unformatted"
    exit 1
  fi
else
  echo "[lint] No Go files found."
fi

echo "[lint] Running go vet for Go modules..."
go_workspace_modules="$(
  "$GO_BIN" work edit -json 2>/dev/null \
    | "$PYTHON_BIN" -c 'import json,sys; data=json.load(sys.stdin); [print(use.get("DiskPath","")) for use in data.get("Use", [])]' \
    | sed '/^$/d' \
    | sort -u
)"
if [ -z "$go_workspace_modules" ]; then
  echo "[lint] No Go workspace modules found in go.work."
else
  while IFS= read -r module_dir; do
    [ -n "$module_dir" ] || continue
    if [ ! -d "$module_dir" ]; then
      echo "[lint] Skipping missing module directory: $module_dir"
      continue
    fi
    echo "[lint] go vet ./... ($module_dir)"
    (cd "$module_dir" && "$GO_BIN" vet ./...)
  done <<EOF_GO_MODULES
$go_workspace_modules
EOF_GO_MODULES
fi

echo "[lint] All lint checks passed."
