#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"
PLAYWRIGHT="$ROOT/web/e2e/node_modules/.bin/playwright"
PRODUCT_LIST=${ZODE_CI_PRODUCT_LIST:-"$ROOT/target/ci/approved-product-playwright-list.txt"}
PRODUCT_MATRIX=${ZODE_CI_PRODUCT_MATRIX:-"$ROOT/target/ci/approved-product-playwright-matrix.json"}

# shellcheck source=scripts/ci/scrub-live-provider-env.sh
source "$ROOT/scripts/ci/scrub-live-provider-env.sh"

die() {
  printf 'CI_PRODUCT_VERIFY_FAILURE: %s\n' "$*" >&2
  exit 1
}

command -v node >/dev/null 2>&1 || die 'node is required'
test -x "$PLAYWRIGHT" || die 'Playwright binary was not installed'
node --check "$ROOT/scripts/ci/assert-product-playwright-list.cjs"
node --check "$ROOT/scripts/ci/product-playwright-matrix.cjs"

PRODUCT_FILES=()
while IFS= read -r file; do
  PRODUCT_FILES+=("${file#"$ROOT/web/e2e/"}")
done < <(find "$ROOT/web/e2e/specs" -type f \( -name '*.spec.cjs' -o -name '*.spec.ts' \) -print | sort)
(( ${#PRODUCT_FILES[@]} > 0 )) || die 'no approved product Playwright specs were found'

mkdir -p "$(dirname "$PRODUCT_LIST")" "$(dirname "$PRODUCT_MATRIX")"
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
node "$ROOT/scripts/ci/product-playwright-matrix.cjs" \
  "$ROOT/scripts/ci/approved-product-playwright-manifest.json" "$ROOT/web/e2e/specs" >"$PRODUCT_MATRIX"
