#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
UI_DIR=${ZODE_CI_UI_DIR:-"$ROOT/target/ci/ui"}

die() {
  printf 'CI_VERIFY_FAILURE: %s\n' "$*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || die 'cargo is required'
command -v pnpm >/dev/null 2>&1 || die 'pnpm is required (the repository pins pnpm@11.20.0)'
command -v node >/dev/null 2>&1 || die 'node is required'

printf '%s\n' '== static gates =='
cargo fmt --all -- --check
cargo clippy --locked --test process_capture_e2e -- -D warnings
node --check "$ROOT/web/e2e/support/harness.cjs"
node --check "$ROOT/web/e2e/support/harness_regressions.spec.cjs"
node --check "$ROOT/web/e2e/playwright.config.cjs"
node --check "$ROOT/tests/support/process_seam.cjs"
node --check "$ROOT/scripts/ci/assert-playwright-results.cjs"

printf '%s\n' '== locked Rust builds =='
cargo build --locked --manifest-path "$ROOT/Cargo.toml" --bin zode
cargo build --locked --manifest-path "$ROOT/server/Cargo.toml" --bin zode-server

printf '%s\n' '== locked Vite+ UI build =='
pnpm --dir "$ROOT/web" exec vp build --outDir "$UI_DIR"

test -x "$ROOT/target/debug/zode" || die 'Endpoint binary was not produced'
test -x "$ROOT/server/target/debug/zode-server" || die 'Server binary was not produced'
test -x "$ROOT/web/e2e/node_modules/.bin/playwright" || die 'Playwright binary was not installed'
test -f "$UI_DIR/index.html" || die 'Vite+ build did not produce index.html'

printf '%s\n' '== deterministic real-process/browser/replay E2E =='
cargo test --locked --test process_capture_e2e -- --nocapture
printf '%s\n' '== locked Server incident replay E2E =='
set +e
cargo test --locked --manifest-path "$ROOT/server/Cargo.toml" \
  --test access_ingress_e2e \
  e2e_replay_access_ingress_initial_404_cassette \
  -- --exact --nocapture
server_replay_status=$?
set -e
export ZODE_ENDPOINT_BIN="$ROOT/target/debug/zode"
export ZODE_SERVER_BIN="$ROOT/server/target/debug/zode-server"
export ZODE_UI_ASSETS_DIRECTORY="$UI_DIR"
export ZODE_WEB_E2E_UI_MODE=assets
export CI=true

# This is the same command on a checkout and on the developer machine. The
# Playwright config's complete Chromium collection is intentional: a shared
# smoke-only pass must not hide a product/browser regression. All fixtures are
# local and deterministic; no real LLM credentials are read. Use the installed
# binary directly so the JSON report is not mixed with pnpm's own output.
PLAYWRIGHT_REPORT="$ROOT/target/ci/playwright-results.json"
mkdir -p "$(dirname "$PLAYWRIGHT_REPORT")"
set +e
"$ROOT/web/e2e/node_modules/.bin/playwright" test \
  --config="$ROOT/web/e2e/playwright.config.cjs" \
  --project=chromium \
  --reporter=json >"$PLAYWRIGHT_REPORT"
playwright_status=$?
set -e
node "$ROOT/scripts/ci/assert-playwright-results.cjs" "$PLAYWRIGHT_REPORT"
if ((server_replay_status != 0)); then
  printf 'CI_VERIFY_FAILURE: Server incident replay gate exited with %s\n' "$server_replay_status" >&2
  exit 1
fi
if ((playwright_status != 0)); then
  exit "$playwright_status"
fi
