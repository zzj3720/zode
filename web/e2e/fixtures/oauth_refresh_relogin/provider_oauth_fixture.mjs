#!/usr/bin/env node

import http from "node:http";
import { randomUUID } from "node:crypto";
import { URL } from "node:url";

const MODES = new Set([
  "oauth_success",
  "oauth_failed",
  "oauth_cancelled",
  "refresh_held",
  "refresh_success",
  "refresh_idempotent_drop_response",
  "refresh_unknown",
]);

const PORT_ARGUMENT = process.argv.indexOf("--port");
const configuredPort = PORT_ARGUMENT === -1 ? 0 : Number(process.argv[PORT_ARGUMENT + 1]);
if (!Number.isInteger(configuredPort) || configuredPort < 0 || configuredPort > 65_535) {
  throw new Error("--port must be an integer between 0 and 65535");
}

const state = {
  mode: "oauth_success",
  authorizeCount: 0,
  tokenCount: 0,
  refreshCount: 0,
  authorizationCodeCount: 0,
  grantTypes: [],
  states: new Map(),
  authorizationCodes: new Map(),
  idempotentResults: new Map(),
  consumedRefreshTokens: new Set(),
  heldRefreshResponses: new Set(),
  modelRequestCount: 0,
  oauthCredentialModelRequests: 0,
  refreshedCredentialModelRequests: 0,
  invalidModelAuthorizations: 0,
};

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function text(response, status, body, contentType = "text/plain; charset=utf-8") {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": contentType,
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function redirect(response, location) {
  response.writeHead(302, {
    "cache-control": "no-store",
    "location": location,
    "referrer-policy": "no-referrer",
  });
  response.end();
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 128 * 1024) {
      throw new Error("fixture request body is too large");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function safeMode(value) {
  if (typeof value !== "string" || !MODES.has(value)) {
    throw new Error("unsupported fixture mode");
  }
  return value;
}

function resetCounters() {
  state.authorizeCount = 0;
  state.tokenCount = 0;
  state.refreshCount = 0;
  state.authorizationCodeCount = 0;
  state.grantTypes.length = 0;
  state.states.clear();
  state.authorizationCodes.clear();
  state.idempotentResults.clear();
  state.consumedRefreshTokens.clear();
  state.modelRequestCount = 0;
  state.oauthCredentialModelRequests = 0;
  state.refreshedCredentialModelRequests = 0;
  state.invalidModelAuthorizations = 0;
}

function safeState() {
  return {
    mode: state.mode,
    authorize_count: state.authorizeCount,
    token_count: state.tokenCount,
    refresh_count: state.refreshCount,
    authorization_code_count: state.authorizationCodeCount,
    grant_types: [...state.grantTypes],
    active_authorizations: state.states.size,
    consumed_refresh_count: state.consumedRefreshTokens.size,
    idempotent_operation_count: state.idempotentResults.size,
    held_refresh_count: state.heldRefreshResponses.size,
    model_request_count: state.modelRequestCount,
    oauth_credential_model_requests: state.oauthCredentialModelRequests,
    refreshed_credential_model_requests: state.refreshedCredentialModelRequests,
    invalid_model_authorizations: state.invalidModelAuthorizations,
  };
}

function oauthPage(authorizeUrl) {
  const escaped = authorizeUrl
    .replaceAll("&", "&amp;")
    .replaceAll("\"", "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Fixture provider authorization</title></head>
  <body>
    <main>
      <h1>Fixture provider authorization</h1>
      <p id="oauth-prompt">The provider is asking for an explicit authorization decision.</p>
      <form method="post" action="/oauth/authorize/decision">
        <input type="hidden" name="authorize_url" value="${escaped}">
        <button type="submit" name="decision" value="approve">Approve</button>
        <button type="submit" name="decision" value="cancel">Cancel</button>
      </form>
    </main>
  </body>
</html>`;
}

function tokenResponse(response, value) {
  json(response, 200, {
    token_type: "Bearer",
    expires_in: 3600,
    ...value,
  });
}

function tokenFailure(response, error = "invalid_grant") {
  json(response, 400, {
    error,
    error_description: "fixture provider rejected the synthetic credential exchange",
  });
}

function callbackLocation(redirectUri, params) {
  const callback = new URL(redirectUri);
  for (const [name, value] of Object.entries(params)) {
    callback.searchParams.set(name, value);
  }
  return callback.toString();
}

async function handleAuthorize(request, response, requestUrl) {
  const redirectUri = requestUrl.searchParams.get("redirect_uri");
  const oauthState = requestUrl.searchParams.get("state");
  if (!redirectUri || !oauthState || requestUrl.searchParams.has("ticket")) {
    return json(response, 400, { error: "invalid_authorize_request" });
  }

  state.authorizeCount += 1;
  state.states.set(oauthState, { redirectUri });
  return text(response, 200, oauthPage(requestUrl.toString()), "text/html; charset=utf-8");
}

async function handleAuthorizeDecision(request, response) {
  const form = new URLSearchParams(await readBody(request));
  const authorizeUrl = form.get("authorize_url");
  const decision = form.get("decision");
  if (!authorizeUrl || (decision !== "approve" && decision !== "cancel")) {
    return json(response, 400, { error: "invalid_authorize_decision" });
  }

  const requestUrl = new URL(authorizeUrl);
  const oauthState = requestUrl.searchParams.get("state");
  const authorization = oauthState ? state.states.get(oauthState) : undefined;
  if (!oauthState || !authorization) {
    return json(response, 400, { error: "unknown_authorize_state" });
  }
  state.states.delete(oauthState);

  if (decision === "cancel" || state.mode === "oauth_cancelled") {
    return redirect(response, callbackLocation(authorization.redirectUri, {
      state: oauthState,
      error: "access_denied",
      error_description: "the fixture user cancelled authorization",
    }));
  }
  if (state.mode === "oauth_failed") {
    return redirect(response, callbackLocation(authorization.redirectUri, {
      state: oauthState,
      error: "temporarily_unavailable",
      error_description: "the fixture provider rejected authorization",
    }));
  }

  const code = `oauth-code-${++state.authorizationCodeCount}`;
  state.authorizationCodes.set(code, { oauthState });
  return redirect(response, callbackLocation(authorization.redirectUri, {
    state: oauthState,
    code,
  }));
}

async function handleToken(request, response) {
  const form = new URLSearchParams(await readBody(request));
  const grantType = form.get("grant_type");
  state.tokenCount += 1;
  state.grantTypes.push(grantType || "unknown");

  if (grantType === "authorization_code") {
    const code = form.get("code");
    if (!code || !state.authorizationCodes.has(code)) {
      return tokenFailure(response);
    }
    state.authorizationCodes.delete(code);
    if (state.mode === "oauth_failed") {
      return tokenFailure(response, "invalid_client");
    }
    return tokenResponse(response, {
      access_token: "fixture-access-token-oauth-1",
      refresh_token: "fixture-refresh-token-oauth-1",
    });
  }

  if (grantType !== "refresh_token") {
    return tokenFailure(response, "unsupported_grant_type");
  }

  state.refreshCount += 1;
  const operationId = request.headers["x-zode-refresh-operation-id"] || form.get("operation_id") || "no-operation-id";
  const refreshToken = form.get("refresh_token") || "missing-refresh-token";
  state.consumedRefreshTokens.add(refreshToken);

  if (state.mode === "refresh_held") {
    state.heldRefreshResponses.add(response);
    response.once("close", () => state.heldRefreshResponses.delete(response));
    return;
  }

  if (state.mode === "refresh_success") {
    return tokenResponse(response, {
      access_token: "fixture-access-token-refresh-success",
      refresh_token: "fixture-refresh-token-refresh-success",
    });
  }

  if (state.mode === "refresh_idempotent_drop_response") {
    const result = {
      access_token: "fixture-access-token-refresh-idempotent",
      refresh_token: "fixture-refresh-token-refresh-idempotent",
    };
    if (!state.idempotentResults.has(operationId)) {
      state.idempotentResults.set(operationId, result);
      request.socket.destroy();
      return;
    }
    return tokenResponse(response, state.idempotentResults.get(operationId));
  }

  if (state.mode === "refresh_unknown") {
    request.socket.destroy();
    return;
  }

  return tokenFailure(response);
}

async function handleModel(request, response) {
  await readBody(request);
  state.modelRequestCount += 1;
  const authorization = request.headers.authorization;
  let content;
  if (authorization === "Bearer fixture-access-token-oauth-1") {
    state.oauthCredentialModelRequests += 1;
    content = "OAUTH_REVISION_1";
  } else if (
    authorization === "Bearer fixture-access-token-refresh-success" ||
    authorization === "Bearer fixture-access-token-refresh-idempotent"
  ) {
    state.refreshedCredentialModelRequests += 1;
    content = "OAUTH_REFRESHED_REVISION";
  } else {
    state.invalidModelAuthorizations += 1;
    return json(response, 401, { error: { code: "invalid_provider_credential" } });
  }
  const body = [
    `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("");
  return text(response, 200, body, "text/event-stream");
}

async function handle(request, response) {
  const requestUrl = new URL(request.url, "http://127.0.0.1");
  if (request.method === "GET" && requestUrl.pathname === "/healthz") {
    return json(response, 200, { schema: "zode.oauth-fixture-health.v1", ready: true });
  }
  if (request.method === "GET" && requestUrl.pathname === "/control/state") {
    return json(response, 200, safeState());
  }
  if (request.method === "POST" && requestUrl.pathname === "/control/reset") {
    resetCounters();
    return json(response, 200, safeState());
  }
  if (request.method === "POST" && requestUrl.pathname === "/control/mode") {
    const body = JSON.parse(await readBody(request));
    state.mode = safeMode(body.mode);
    resetCounters();
    return json(response, 200, safeState());
  }
  if (request.method === "POST" && requestUrl.pathname === "/control/release-refresh") {
    const pending = [...state.heldRefreshResponses];
    for (const held of pending) {
      tokenResponse(held, {
        access_token: "fixture-access-token-refresh-success",
        refresh_token: "fixture-refresh-token-refresh-success",
      });
    }
    return json(response, 200, safeState());
  }
  if (request.method === "GET" && requestUrl.pathname === "/oauth/authorize") {
    return handleAuthorize(request, response, requestUrl);
  }
  if (request.method === "POST" && requestUrl.pathname === "/oauth/authorize/decision") {
    return handleAuthorizeDecision(request, response);
  }
  if (request.method === "POST" && requestUrl.pathname === "/oauth/token") {
    return handleToken(request, response);
  }
  if (
    request.method === "POST" &&
    ["/chat/completions", "/v1/chat/completions"].includes(requestUrl.pathname)
  ) {
    return handleModel(request, response);
  }
  return json(response, 404, { error: "not_found" });
}

const server = http.createServer((request, response) => {
  handle(request, response).catch(() => {
    if (!response.headersSent) {
      json(response, 400, { error: "fixture_request_invalid" });
    } else {
      response.destroy();
    }
  });
});

server.listen(configuredPort, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("fixture did not receive a TCP address");
  }
  process.stdout.write(`ZODE_OAUTH_FIXTURE_READY http://127.0.0.1:${address.port}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
