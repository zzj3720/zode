#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"
UI_DIR=${ZODE_CI_PRODUCT_UI_DIR:-"$ROOT/target/ci/product-ui"}
PLAYWRIGHT="$ROOT/web/e2e/node_modules/.bin/playwright"

die() {
  printf 'CI_PRODUCT_VERIFY_FAILURE: %s\n' "$*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || die 'cargo is required'
command -v pnpm >/dev/null 2>&1 || die 'pnpm is required (the repository pins pnpm@11.20.0)'
command -v node >/dev/null 2>&1 || die 'node is required'
node --check "$ROOT/web/e2e/support/harness.cjs"
node --check "$ROOT/scripts/ci/assert-product-playwright-list.cjs"
node --check "$ROOT/scripts/ci/assert-playwright-results.cjs"
node --check "$ROOT/scripts/ci/product-playwright-matrix.cjs"

printf '%s\n' '== exact-main product build =='
cargo build --locked --manifest-path "$ROOT/Cargo.toml" --bin zode
cargo build --locked --manifest-path "$ROOT/server/Cargo.toml" --bin zode-server
pnpm --dir "$ROOT/web" exec vp build --outDir "$UI_DIR"

test -x "$ROOT/target/debug/zode" || die 'Endpoint binary was not produced'
test -x "$ROOT/server/target/debug/zode-server" || die 'Server binary was not produced'
test -x "$PLAYWRIGHT" || die 'Playwright binary was not installed'
test -f "$UI_DIR/index.html" || die 'Vite+ build did not produce index.html'

export ZODE_ENDPOINT_BIN="$ROOT/target/debug/zode"
export ZODE_SERVER_BIN="$ROOT/server/target/debug/zode-server"
export ZODE_UI_ASSETS_DIRECTORY="$UI_DIR"
export ZODE_WEB_E2E_UI_MODE=assets
export PATH="$ROOT/web/node_modules/.bin:$PATH"
export CI=true
# shellcheck source=scripts/ci/scrub-live-provider-env.sh
source "$ROOT/scripts/ci/scrub-live-provider-env.sh"

PRODUCT_FILES=()
while IFS= read -r file; do
  PRODUCT_FILES+=("${file#"$ROOT/web/e2e/"}")
done < <(find "$ROOT/web/e2e/specs" -type f \( -name '*.spec.cjs' -o -name '*.spec.ts' \) -print | sort)
(( ${#PRODUCT_FILES[@]} > 0 )) || die 'no approved product Playwright specs were found'

printf '%s\n' '== approved product collection (all specs, no silent subset) =='
"$ROOT/scripts/ci/collect-approved-product.sh"

RUN_FILES=("${PRODUCT_FILES[@]}")
REPORT_SUFFIX=
if [[ -n ${ZODE_CI_PRODUCT_SPEC:-} ]]; then
  approved=false
  for file in "${PRODUCT_FILES[@]}"; do
    if [[ $file == "$ZODE_CI_PRODUCT_SPEC" ]]; then
      approved=true
      break
    fi
  done
  [[ $approved == true ]] || die "selected product spec is not approved: $ZODE_CI_PRODUCT_SPEC"
  RUN_FILES=("$ZODE_CI_PRODUCT_SPEC")
  shard_id=${ZODE_CI_PRODUCT_SHARD_ID:-$(basename "$ZODE_CI_PRODUCT_SPEC")}
  [[ $shard_id =~ ^[A-Za-z0-9._-]+$ ]] || die 'product shard id contains unsafe characters'
  REPORT_SUFFIX="-$shard_id"
fi

PRODUCT_REPORT="$ROOT/target/ci/approved-product-playwright${REPORT_SUFFIX}-results.json"
PRODUCT_PROGRESS="$ROOT/target/ci/approved-product-playwright${REPORT_SUFFIX}-progress.log"
mkdir -p "$(dirname "$PRODUCT_REPORT")"

printf '%s\n' '== approved product real-browser/process E2E =='
: >"$PRODUCT_REPORT"
: >"$PRODUCT_PROGRESS"
set +e
(
  cd "$ROOT/web/e2e"
  PLAYWRIGHT_JSON_OUTPUT_FILE="$PRODUCT_REPORT" "$PLAYWRIGHT" test \
    --config="$ROOT/web/e2e/playwright.config.cjs" \
    --project=chromium "${RUN_FILES[@]}" --reporter=line,json
) >"$PRODUCT_PROGRESS" 2>&1
playwright_status=$?
set -e

# A product failure is a product failure.  The result audit separately rejects
# every skipped or unrun selected test so platform/readiness gaps cannot become
# a green product signal.
set +e
node "$ROOT/scripts/ci/assert-playwright-results.cjs" \
  "$PRODUCT_REPORT" "$ROOT/scripts/ci/approved-product-playwright-manifest.json" "${RUN_FILES[@]}"
audit_status=$?
set -e
if ((playwright_status != 0)); then
  die "Playwright approved product gate exited with $playwright_status"
fi
if ((audit_status != 0)); then
  die "Playwright approved product result audit exited with $audit_status"
fi
