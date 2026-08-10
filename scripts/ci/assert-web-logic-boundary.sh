#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

die() {
  printf 'CI_WEB_LOGIC_BOUNDARY_FAILURE: %s\n' "$*" >&2
  exit 1
}

if grep -REn "(from|import\\()[[:space:]]*['\"](react|react-dom|@emotion|@radix-ui|@preact/signals-react)" \
  "$ROOT/web/src/logic"; then
  die 'domain logic imports a visual framework'
fi

if grep -REn '(^|[^[:alnum:]_])(fetch|EventSource|WebSocket)([^[:alnum:]_]|$)' \
  "$ROOT/web/src/logic"; then
  die 'domain logic bypasses the single Server client'
fi

if grep -En '(AbortController|Last-Event-ID|endpointEvents|CursorStore|cursor)' \
  "$ROOT/web/src/logic/session.ts"; then
  die 'Session owns stream, cursor, or reconnect state'
fi

server_client_roots=$(grep -Rl 'new ServerClient(' "$ROOT/web/src" || true)
server_client_count=$(printf '%s\n' "$server_client_roots" | awk 'NF { count += 1 } END { print count + 0 }')
(( server_client_count == 1 )) || die 'ServerClient must have exactly one composition root'
[[ "$server_client_roots" == "$ROOT/web/src/logic/index.ts" ]] || \
  die 'ServerClient is constructed outside the logic composition root'

if find "$ROOT/web/src" -maxdepth 1 -type f \( -name '*.ts' -o -name '*.tsx' \) -print0 |
  xargs -0 grep -En "(fetch\\(|EventSource|WebSocket|ServerClient|from[[:space:]]+['\"]\\./api)"; then
  die 'visual entry owns transport or imports the Server API client'
fi

if grep -REn '/v1/(endpoints/[^/]+/)?sessions/[^/]+/events' \
  "$ROOT/src" "$ROOT/server/src" "$ROOT/web/src"; then
  die 'session-scoped SSE route or client path is present'
fi

printf '%s\n' 'Web logic boundary audit: one Server client, Endpoint-owned SSE, Session transport-free'
