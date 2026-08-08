#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
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
# The product gate is deterministic and must never discover or consume a live
# provider credential from a developer shell or CI secret environment.
unset ZODE_RUN_LIVE_PROVIDER_E2E ZODE_E2E_LIVE_PROVIDER_BASE_URL ZODE_E2E_LIVE_PROVIDER_API_KEY
unset ZODE_E2E_LIVE_PROVIDER_MODEL ZODE_E2E_LIVE_PROVIDER_ID
unset ZODE_RELEASE_LIVE_PROVIDER_API_KEY ZODE_RELEASE_PROVIDER_API_KEY ZODE_RELEASE_SECRET_VALUES_JSON
unset OPENCODE_GO_API_KEY OPENCODE_API_KEY DEEPSEEK_API_KEY OPENAI_API_KEY OPENROUTER_API_KEY
unset ANTHROPIC_API_KEY GOOGLE_API_KEY GEMINI_API_KEY MISTRAL_API_KEY
unset TOGETHER_API_KEY XAI_API_KEY GROQ_API_KEY COHERE_API_KEY

PRODUCT_FILES=()
while IFS= read -r file; do
  PRODUCT_FILES+=("${file#"$ROOT/web/e2e/"}")
done < <(find "$ROOT/web/e2e/specs" -type f \( -name '*.spec.cjs' -o -name '*.spec.ts' \) -print | sort)
(( ${#PRODUCT_FILES[@]} > 0 )) || die 'no approved product Playwright specs were found'

PRODUCT_LIST="$ROOT/target/ci/approved-product-playwright-list.txt"
PRODUCT_REPORT="$ROOT/target/ci/approved-product-playwright-results.json"
mkdir -p "$(dirname "$PRODUCT_LIST")"

printf '%s\n' '== approved product collection (all specs, no silent subset) =='
set +e
(
  cd "$ROOT/web/e2e"
  "$PLAYWRIGHT" test --config="$ROOT/web/e2e/playwright.config.cjs" \
    --project=chromium "${PRODUCT_FILES[@]}" --list --reporter=line
) >"$PRODUCT_LIST"
list_status=$?
set -e
if ((list_status != 0)); then
  die "Playwright product collection exited with $list_status"
fi
node "$ROOT/scripts/ci/assert-product-playwright-list.cjs" \
  "$PRODUCT_LIST" "$ROOT/web/e2e/specs" "$ROOT/scripts/ci/approved-product-playwright-manifest.json"

printf '%s\n' '== approved product real-browser/process E2E =='
set +e
(
  cd "$ROOT/web/e2e"
  "$PLAYWRIGHT" test --config="$ROOT/web/e2e/playwright.config.cjs" \
    --project=chromium "${PRODUCT_FILES[@]}" --reporter=json
) >"$PRODUCT_REPORT"
playwright_status=$?
set -e

# A product failure is a product failure.  The result audit separately rejects
# every skipped or unrun selected test so platform/readiness gaps cannot become
# a green product signal.
set +e
node "$ROOT/scripts/ci/assert-playwright-results.cjs" "$PRODUCT_REPORT"
audit_status=$?
set -e
if ((playwright_status != 0)); then
  die "Playwright approved product gate exited with $playwright_status"
fi
if ((audit_status != 0)); then
  die "Playwright approved product result audit exited with $audit_status"
fi
