#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

die() {
  printf 'STORAGE_CONFORMANCE_FAILURE: %s\n' "$*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || die 'cargo is required'

backend=${ZODE_CONFORMANCE_BACKEND:-sqlite}
if [[ ! "$backend" =~ ^[A-Za-z0-9._-]+$ ]]; then
  die "invalid conformance backend label"
fi

endpoint_bin=${ZODE_CONFORMANCE_ENDPOINT_BIN:-"$ROOT/target/debug/zode"}
[[ -f "$endpoint_bin" ]] || die "conformance endpoint binary is missing: $endpoint_bin"
[[ -x "$endpoint_bin" ]] || die "conformance endpoint binary is not executable: $endpoint_bin"

mkdir -p "$ROOT/target/ci"
umask 077
adapter_suite='null'
if [[ "$backend" == sqlite ]]; then
  adapter_suite='"sqlite_storage_e2e"'
fi
printf '{"schema":"zode.storage-http-sse-conformance.v1","backend":"%s","suite":"http_sse_e2e","adapter_suite":%s}\n' \
  "$backend" "$adapter_suite" >"$ROOT/target/ci/storage-conformance.json"

export ZODE_CONFORMANCE_BACKEND="$backend"
export ZODE_CONFORMANCE_ENDPOINT_BIN="$endpoint_bin"
printf '== HTTP/SSE storage conformance backend=%s ==\n' "$backend"
cargo test --locked --test http_sse_e2e -- --nocapture
if [[ "$backend" == sqlite ]]; then
  printf '== SQLite adapter recovery conformance ==\n'
  cargo test --locked --test sqlite_storage_e2e -- --nocapture
else
  printf '== SQLite adapter recovery conformance omitted for backend=%s (backend-neutral suite only) ==\n' "$backend"
fi
