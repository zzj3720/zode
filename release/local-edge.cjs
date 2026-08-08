#!/usr/bin/env node
'use strict';

/*
 * The local test-channel Access edge.  It is deliberately separate from the
 * product binaries: it signs short-lived local Access assertions, serves the
 * matching JWKS, and forwards the browser to the loopback management origin.
 * It has no recorder, replay, provider, or release-control surface.
 */
const { createPublicKey, sign } = require('node:crypto');
const { existsSync, lstatSync, readFileSync } = require('node:fs');
const http = require('node:http');
const { resolve } = require('node:path');

const args = process.argv.slice(2);
function arg(name) {
  const index = args.indexOf(name);
  return index >= 0 && typeof args[index + 1] === 'string' ? args[index + 1] : null;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

function isLoopbackHost(value) {
  return value === '127.0.0.1' || value === '::1' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(value);
}

function loopbackOrigin(value, label) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${label} is not a URL`); }
  if (parsed.protocol !== 'http:' || !isLoopbackHost(parsed.hostname) || !parsed.port
      || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password) {
    throw new Error(`${label} must be an HTTP loopback origin`);
  }
  return parsed;
}

const statePath = arg('--state');
if (!statePath) {
  fail('local edge requires --state');
} else {
  let state;
  try {
    const absoluteStatePath = resolve(statePath);
    const stat = lstatSync(absoluteStatePath);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
      throw new Error('state file is not private');
    }
    state = JSON.parse(readFileSync(absoluteStatePath, 'utf8'));
    if (state?.schema !== 'zode.local-channel.v1'
        || typeof state.channel_root !== 'string'
        || typeof state.edge_host !== 'string'
        || !Number.isInteger(state.edge_port)
        || typeof state.server_origin !== 'string'
        || typeof state.issuer !== 'string'
        || typeof state.audience !== 'string'
        || typeof state.key_path !== 'string') {
      throw new Error('state file has an invalid local-channel schema');
    }
    if (state.edge_host !== '127.0.0.1' || state.edge_port < 1 || state.edge_port > 65535) {
      throw new Error('local Access edge must bind a loopback address');
    }
    const serverOrigin = loopbackOrigin(state.server_origin, 'local Server origin');
    const issuerOrigin = loopbackOrigin(state.issuer, 'local Access issuer');
    if (issuerOrigin.hostname !== state.edge_host || Number(issuerOrigin.port) !== state.edge_port) {
      throw new Error('local Access issuer must match the loopback edge address');
    }
    const endpointOrigin = new URL(`http://${state.endpoint_listen}`);
    if (!isLoopbackHost(endpointOrigin.hostname) || !endpointOrigin.port) {
      throw new Error('local Endpoint must bind a loopback address');
    }
    const keyPath = resolve(state.key_path);
    const keyStat = lstatSync(keyPath);
    if (!keyStat.isFile() || keyStat.isSymbolicLink() || (keyStat.mode & 0o077) !== 0) {
      throw new Error('local Access key is not private');
    }
    if (!keyPath.startsWith(`${resolve(state.channel_root)}${require('node:path').sep}`)) {
      throw new Error('local Access key escaped channel root');
    }
    const privateKey = readFileSync(keyPath, 'utf8');
    const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
    const kid = state.key_id;
    const audience = state.audience;
    const issuer = state.issuer;
    const target = serverOrigin;

    function base64Url(value) {
      return Buffer.from(JSON.stringify(value)).toString('base64url');
    }

    function assertion() {
      const now = Math.floor(Date.now() / 1000);
      const header = base64Url({ alg: 'RS256', kid, typ: 'JWT' });
      const claims = base64Url({
        iss: issuer,
        aud: [audience],
        sub: 'zode-local-channel-user',
        iat: now,
        nbf: now - 1,
        exp: now + 600,
        type: 'app',
      });
      const signature = sign('RSA-SHA256', Buffer.from(`${header}.${claims}`), privateKey).toString('base64url');
      return `${header}.${claims}.${signature}`;
    }

    function sendJson(response, status, value) {
      response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      response.end(JSON.stringify(value));
    }

    const server = http.createServer((request, response) => {
      if (request.method === 'GET' && request.url === '/__zode_local_edge_ready') {
        sendJson(response, 200, { schema: 'zode.local-channel-edge.v1', status: 'ready' });
        return;
      }
      if (request.method === 'GET' && request.url === '/jwks') {
        sendJson(response, 200, { keys: [{ ...publicJwk, kid, use: 'sig', alg: 'RS256' }] });
        return;
      }
      const headers = { ...request.headers };
      delete headers.connection;
      delete headers['cf-access-jwt-assertion'];
      headers.host = target.host;
      headers['cf-access-jwt-assertion'] = assertion();
      const upstream = http.request({
        hostname: target.hostname,
        port: target.port,
        method: request.method,
        path: request.url,
        headers,
      }, (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      });
      upstream.on('error', (error) => {
        if (!response.headersSent) sendJson(response, 502, { error: 'local_edge_upstream_unavailable' });
        else response.end();
        process.stderr.write(`upstream error: ${String(error)}\n`);
      });
      request.on('error', () => upstream.destroy());
      request.pipe(upstream);
    });

    const close = () => server.close(() => process.exit(0));
    process.once('SIGTERM', close);
    process.once('SIGINT', close);
    server.once('error', (error) => { process.stderr.write(`${String(error)}\n`); process.exitCode = 1; });
    server.listen(state.edge_port, state.edge_host, () => {
      process.stdout.write(`ZODE_LOCAL_EDGE_READY http://${state.edge_host}:${state.edge_port}/\n`);
    });
  } catch (error) {
    fail(`local edge startup failed: ${String(error.message || error)}`);
  }
}
