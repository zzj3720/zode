#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"
UI_DIR=${ZODE_CI_PRODUCT_UI_DIR:-"$ROOT/target/ci/product-ui"}
PLAYWRIGHT="$ROOT/web/e2e/node_modules/.bin/playwright"
MANIFEST="$ROOT/scripts/ci/approved-product-playwright-manifest.json"
PRODUCT_LIST="$ROOT/target/ci/approved-product-playwright-list.txt"
PRODUCT_REPORT="$ROOT/target/ci/approved-product-playwright-results.json"
PRODUCT_PROGRESS="$ROOT/target/ci/approved-product-playwright-progress.log"

die() {
  printf 'CI_PRODUCT_VERIFY_FAILURE: %s\n' "$*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || die 'cargo is required'
command -v pnpm >/dev/null 2>&1 || die 'pnpm is required (the repository pins pnpm@11.20.0)'
command -v node >/dev/null 2>&1 || die 'node is required'
test -x "$PLAYWRIGHT" || die 'Playwright binary was not installed'
node --check "$ROOT/scripts/ci/assert-product-playwright-list.cjs"
node --check "$ROOT/scripts/ci/assert-playwright-results.cjs"

PRODUCT_FILES=()
while IFS= read -r file; do
  PRODUCT_FILES+=("${file#"$ROOT/web/e2e/"}")
done < <(find "$ROOT/web/e2e/specs" -type f \( -name '*.spec.cjs' -o -name '*.spec.ts' \) -print | sort)
(( ${#PRODUCT_FILES[@]} > 0 )) || die 'no product Playwright specs were found'

mkdir -p "$ROOT/target/ci"
(
  cd "$ROOT/web/e2e"
  "$PLAYWRIGHT" test --config=playwright.config.cjs --project=chromium \
    "${PRODUCT_FILES[@]}" --list --reporter=line
) >"$PRODUCT_LIST"
node "$ROOT/scripts/ci/assert-product-playwright-list.cjs" \
  "$PRODUCT_LIST" "$ROOT/web/e2e/specs" "$MANIFEST"

printf '%s\n' '== exact-revision product build =='
cargo build --locked --manifest-path "$ROOT/Cargo.toml" --bin zode
cargo build --locked --manifest-path "$ROOT/server/Cargo.toml" --bin zode-server
pnpm --dir "$ROOT/web" exec vp build --outDir "$UI_DIR"

test -x "$ROOT/target/debug/zode" || die 'Endpoint binary was not produced'
test -x "$ROOT/server/target/debug/zode-server" || die 'Server binary was not produced'
test -f "$UI_DIR/index.html" || die 'Vite+ build did not produce index.html'

export ZODE_ENDPOINT_BIN="$ROOT/target/debug/zode"
export ZODE_SERVER_BIN="$ROOT/server/target/debug/zode-server"
export ZODE_UI_ASSETS_DIRECTORY="$UI_DIR"
export ZODE_WEB_E2E_UI_MODE=assets
export PATH="$ROOT/web/node_modules/.bin:$PATH"
export CI=true
# shellcheck source=scripts/ci/scrub-live-provider-env.sh
source "$ROOT/scripts/ci/scrub-live-provider-env.sh"

printf '%s\n' '== complete approved real-browser/process product matrix =='
: >"$PRODUCT_REPORT"
: >"$PRODUCT_PROGRESS"
set +e
(
  cd "$ROOT/web/e2e"
  PLAYWRIGHT_JSON_OUTPUT_FILE="$PRODUCT_REPORT" "$PLAYWRIGHT" test \
    --config=playwright.config.cjs --project=chromium "${PRODUCT_FILES[@]}" \
    --reporter=line,json
) >"$PRODUCT_PROGRESS" 2>&1
playwright_status=$?
set -e

set +e
node "$ROOT/scripts/ci/assert-playwright-results.cjs" \
  "$PRODUCT_REPORT" "$MANIFEST" "${PRODUCT_FILES[@]}"
audit_status=$?
set -e
if ((playwright_status != 0)); then
  die "Playwright product matrix exited with $playwright_status"
fi
if ((audit_status != 0)); then
  die "Playwright product result audit exited with $audit_status"
fi
