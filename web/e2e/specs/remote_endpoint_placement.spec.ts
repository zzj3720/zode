import { test, expect, type APIRequestContext, type BrowserContext, type Locator, type Page, type Request as PlaywrightRequest, type Response as PlaywrightResponse } from "@playwright/test";
import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, request as httpRequest, type Server as HttpServer } from "node:http";
import { cpSync, mkdtempSync, mkdirSync, chmodSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";

const SERVER_AUTHORITY = "web-remote-endpoint-placement-server";
const ACCESS_AUDIENCE = "zode-web-remote-endpoint-placement";
const ACCESS_SUBJECT = "web-remote-endpoint-placement-human";
const REMOTE_LABEL = "Remote fixture endpoint";
const REMOTE_CONTROL_SECRET = "remote-endpoint-control-secret-web-e2e";
const REMOTE_ENDPOINT_AUTHORITY = SERVER_AUTHORITY;
const READY_TIMEOUT_MS = 20_000;
const HTTP_TIMEOUT_MS = 10_000;
const ULID = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$/;
const REPO_ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const CASSETTE_PATH = fileURLToPath(
  new URL("../fixtures/remote_endpoint_placement/remote-endpoint-add.first-failure.json", import.meta.url),
);

type JsonObject = Record<string, any>;

type ReadyProcess = {
  child: ChildProcessWithoutNullStreams;
  baseUrl: string;
  stdout: string;
  stderr: string;
  stop: () => Promise<{ stdout: string; stderr: string }>;
  restart: () => Promise<ReadyProcess>;
};

type AccessFixture = {
  issuer: string;
  jwksUrl: string;
  sign: (subject?: string) => string;
  startEdge: (targetBaseUrl: string) => Promise<AccessEdge>;
  close: () => Promise<void>;
};

type AccessEdge = {
  baseUrl: string;
  close: () => Promise<void>;
};

type Harness = {
  root: string;
  serverDatabase: string;
  serverSecrets: string;
  access: AccessFixture;
  edge: AccessEdge;
  server: ReadyProcess;
  remote: ReadyProcess;
  remoteEndpointId: string;
};

type ServerOnlyHarness = {
  root: string;
  access: AccessFixture;
  edge: AccessEdge;
  server: ReadyProcess;
};

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function jsonBody(
  value: unknown,
  replacer: ((key: string, nestedValue: unknown) => unknown) | null = null,
  space?: number,
): string {
  const serialized = JSON.stringify(value, replacer ?? undefined, space);
  if (serialized === undefined) throw new Error("fixture JSON could not be serialized");
  return serialized;
}

function assertSafeText(value: string, marker: string, label: string): void {
  if (value.includes(marker)) {
    throw new Error(`${label} contained a secret marker`);
  }
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as JsonObject)
        .sort()
        .map((key) => [key, canonicalize((value as JsonObject)[key])]),
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return jsonBody(canonicalize(value));
}

function cassetteDigest(cassette: JsonObject): string {
  const withoutDigest = structuredClone(cassette) as JsonObject;
  delete withoutDigest.whole_digest;
  return `sha256:${sha256(canonicalJson(withoutDigest))}`;
}

async function listen(server: HttpServer): Promise<number> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = server.address() as AddressInfo;
  return address.port;
}

async function reserveLoopbackPort(): Promise<number> {
  const server = createServer();
  const port = await listen(server);
  await new Promise<void>((resolvePromise, reject) => {
    server.close((error) => (error ? reject(error) : resolvePromise()));
  });
  return port;
}

function signAccessToken(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], issuer: string, subject: string): string {
  const now = Math.floor(Date.now() / 1_000);
  const header = base64Url(jsonBody({ alg: "RS256", kid: "web-remote-endpoint-placement-key", typ: "JWT" }));
  const payload = base64Url(
    jsonBody({
      iss: issuer,
      aud: [ACCESS_AUDIENCE],
      sub: subject,
      type: "app",
      iat: now,
      nbf: now - 1,
      exp: now + 300,
    }),
  );
  const unsigned = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  return `${unsigned}.${signer.sign(privateKey).toString("base64url")}`;
}

async function startAccessFixture(): Promise<AccessFixture> {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2_048 });
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonObject;
  const server = createServer((request, response) => {
    if (request.url !== "/cdn-cgi/access/certs" && request.url !== "/jwks") {
      response.statusCode = 404;
      response.end();
      return;
    }
    response.setHeader("content-type", "application/json");
    response.end(
      jsonBody({
        keys: [
          {
            kty: publicJwk.kty,
            n: publicJwk.n,
            e: publicJwk.e,
            kid: "web-remote-endpoint-placement-key",
            use: "sig",
            alg: "RS256",
          },
        ],
      }),
    );
  });
  const port = await listen(server);
  const issuer = `http://127.0.0.1:${port}/`;
  async function startEdge(targetBaseUrl: string): Promise<AccessEdge> {
    const edge = createServer((incoming, outgoing) => {
      const target = new URL(incoming.url ?? "/", targetBaseUrl);
      const headers: Record<string, string | string[] | undefined> = { ...incoming.headers };
      delete headers.host;
      delete headers.connection;
      delete headers["content-length"];
      headers.host = target.host;
      headers["cf-access-jwt-assertion"] = signAccessToken(privateKey, issuer, ACCESS_SUBJECT);
      const upstream = httpRequest(
        {
          hostname: target.hostname,
          port: target.port,
          path: `${target.pathname}${target.search}`,
          method: incoming.method,
          headers,
        },
        (response) => {
          const responseHeaders: Record<string, string | string[] | undefined> = { ...response.headers };
          delete responseHeaders.connection;
          delete responseHeaders["keep-alive"];
          delete responseHeaders["transfer-encoding"];
          outgoing.writeHead(response.statusCode ?? 502, responseHeaders);
          response.pipe(outgoing);
        },
      );
      upstream.once("error", () => {
        if (!outgoing.headersSent) {
          outgoing.statusCode = 502;
          outgoing.end();
        } else {
          outgoing.destroy();
        }
      });
      incoming.pipe(upstream);
    });
    const edgePort = await listen(edge);
    return {
      baseUrl: `http://127.0.0.1:${edgePort}`,
      close: async () => {
        if (edge.listening) {
          await new Promise<void>((resolvePromise, reject) => {
            edge.close((error) => (error ? reject(error) : resolvePromise()));
          });
        }
      },
    };
  }
  return {
    issuer,
    jwksUrl: `${issuer}cdn-cgi/access/certs`,
    sign: (subject = ACCESS_SUBJECT) => signAccessToken(privateKey, issuer, subject),
    startEdge,
    close: async () => {
      await new Promise<void>((resolvePromise, reject) => {
        server.close((error) => (error ? reject(error) : resolvePromise()));
      });
    },
  };
}

function startChildProcess(binary: string, args: string[], readyPrefix: string): Promise<ReadyProcess> {
  const child = spawn(binary, args, {
    cwd: REPO_ROOT,
    env: { ...process.env, RUST_BACKTRACE: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  }) as unknown as ChildProcessWithoutNullStreams;
  let stdout = "";
  let stderr = "";
  let stopped = false;
  let readyResolve: (baseUrl: string) => void = () => undefined;
  let readyReject: (error: Error) => void = () => undefined;
  const ready = new Promise<string>((resolvePromise, reject) => {
    readyResolve = resolvePromise;
    readyReject = reject;
  });

  const observe = (chunk: Buffer, target: "stdout" | "stderr") => {
    if (target === "stdout") {
      stdout += chunk.toString("utf8");
      const marker = stdout.indexOf(readyPrefix);
      if (marker >= 0) {
        const line = stdout.slice(marker + readyPrefix.length).split(/\r?\n/, 1)[0]?.trim();
        if (line) readyResolve(line);
      }
    } else {
      stderr += chunk.toString("utf8");
    }
  };
  child.stdout.on("data", (chunk: Buffer) => observe(chunk, "stdout"));
  child.stderr.on("data", (chunk: Buffer) => observe(chunk, "stderr"));
  child.once("error", (error) => readyReject(error));
  child.once("exit", (code, signal) => {
    if (!stopped) {
      readyReject(new Error(`${basename(binary)} exited before readiness (${code ?? "signal"}:${signal ?? ""})`));
    }
  });

  const readyWithTimeout = new Promise<string>((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`process did not emit ${readyPrefix}`)), READY_TIMEOUT_MS);
    ready.then(
      (value) => {
        clearTimeout(timer);
        resolvePromise(value);
      },
      (error: Error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });

  return readyWithTimeout
    .then((baseUrl) => {
      const readyProcess: ReadyProcess = {
        child,
        baseUrl,
        get stdout() {
          return stdout;
        },
        get stderr() {
          return stderr;
        },
        stop: async () => {
          if (!stopped && child.exitCode === null && child.signalCode === null) {
            stopped = true;
            child.kill("SIGTERM");
            await new Promise<void>((resolvePromise) => {
              const timer = setTimeout(() => {
                if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
                resolvePromise();
              }, 5_000);
              child.once("close", () => {
                clearTimeout(timer);
                resolvePromise();
              });
            });
          }
          return { stdout, stderr };
        },
        restart: async () => {
          await readyProcess.stop();
          const replacement = await startChildProcess(binary, args, readyPrefix);
          if (replacement.baseUrl !== baseUrl) {
            await replacement.stop();
            throw new Error("real Endpoint changed its URL across restart");
          }
          return replacement;
        },
      };
      return readyProcess;
    })
    .catch(async (error) => {
      stopped = true;
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      throw error;
    });
}

function writeEndpointConfig(root: string, authorityId: string, secretFile: string, listenAddress: string): string {
  const credentials = join(root, "credentials");
  const blobs = join(root, "blobs");
  mkdirSync(credentials, { recursive: true });
  mkdirSync(blobs, { recursive: true });
  const configPath = join(root, "endpoint-config.json");
  writeFileSync(
    configPath,
    jsonBody({
      schema: "zode.config.v1",
      listen: listenAddress,
      runtime_store: { kind: "sqlite", path: join(root, "endpoint.sqlite3") },
      credential_replica_store: { kind: "files", directory: credentials },
      blob_store: { kind: "files", directory: blobs },
      controller_auth: [
        {
          authority_id: authorityId,
          revision: 1,
          kind: "bearer_secret_file",
          secret_file: secretFile,
        },
      ],
      runtime: {
        tool_foreground_ms: 3_000,
        snapshot_every_events: 1_000,
        max_rounds_per_activation: 8,
        model_step_max_attempts: 1,
        model_retry_base_ms: 1,
        model_retry_max_ms: 10,
      },
      provider_execution: {
        adapter_kinds: ["openai_compatible"],
        allowed_base_url_origins: ["http://127.0.0.1"],
      },
      callback: { allowed_public_origins: ["http://127.0.0.1"] },
      tools: [],
    }, null, 2),
  );
  return configPath;
}

function writeServerConfig(
  root: string,
  issuer: string,
  jwksUrl: string,
  managementPort: number,
  uiAssetsDirectory: string,
  options: {
    deployment: "all_in_one" | "server_only";
    endpointBinary?: string;
    localEndpointConfig?: string;
    localListenAddress?: string;
    localBootstrapSecret?: string;
  },
): { path: string; database: string; secrets: string } {
  const database = join(root, "server.sqlite3");
  const secrets = join(root, "server-secrets");
  mkdirSync(secrets, { recursive: true });
  const subjectKey = join(root, "subject.key");
  writeFileSync(subjectKey, Buffer.alloc(32, 0x42));
  chmodSync(subjectKey, 0o600);
  const path = join(root, "server-config.json");
  const config: JsonObject = {
    schema: "zode.server-config.v1",
    listen: `127.0.0.1:${managementPort}`,
    management_origin: `http://127.0.0.1:${managementPort}`,
    callback_origin: `http://127.0.0.2:${managementPort}`,
    server_authority_id: SERVER_AUTHORITY,
    deployment: options.deployment,
    ui_mode: "assets",
    ui_assets_directory: uiAssetsDirectory,
    control_database: database,
    secret_directory: secrets,
    access: {
      issuer,
      audiences: [ACCESS_AUDIENCE],
      jwks_url: jwksUrl,
      subject_key_file: subjectKey,
      subject_key_version: 1,
    },
  };
  if (options.deployment === "all_in_one") {
    if (
      !options.endpointBinary ||
      !options.localEndpointConfig ||
      !options.localListenAddress ||
      !options.localBootstrapSecret
    ) {
      throw new Error("all-in-one Server config omitted the local Endpoint composition");
    }
    config.local_endpoint = {
      executable: options.endpointBinary,
      config: options.localEndpointConfig,
      listen: options.localListenAddress,
      bootstrap_controller_secret_file: options.localBootstrapSecret,
    };
  }
  writeFileSync(path, jsonBody(config, null, 2));
  return { path, database, secrets };
}

function materializeUiAssets(root: string): string {
  const source = process.env.ZODE_UI_ASSETS_DIRECTORY ?? resolve(REPO_ROOT, "target/ci/product-ui");
  const destination = join(root, "ui");
  cpSync(source, destination, { recursive: true, force: false, errorOnExist: true });
  return destination;
}

async function startHarness(): Promise<Harness> {
  const endpointBinary = process.env.ZODE_ENDPOINT_BIN ?? resolve(REPO_ROOT, "target/debug/zode");
  const serverBinary =
    process.env.ZODE_SERVER_BIN ??
    process.env.CARGO_BIN_EXE_zode_server ??
    resolve(REPO_ROOT, "server/target/debug/zode-server");
  const root = mkdtempSync(join(tmpdir(), "zode-web-remote-endpoint-placement-"));
  const localRoot = join(root, "local-endpoint");
  const remoteRoot = join(root, "remote-endpoint");
  mkdirSync(localRoot, { recursive: true });
  mkdirSync(remoteRoot, { recursive: true });
  const localPort = await reserveLoopbackPort();
  const remotePort = await reserveLoopbackPort();
  const localListen = `127.0.0.1:${localPort}`;
  const remoteListen = `127.0.0.1:${remotePort}`;
  const localBootstrapSecret = join(localRoot, "controller.secret");
  const remoteSecretFile = join(remoteRoot, "controller.secret");
  writeFileSync(localBootstrapSecret, randomBytes(32), { mode: 0o600 });
  chmodSync(localBootstrapSecret, 0o600);
  writeFileSync(remoteSecretFile, REMOTE_CONTROL_SECRET);
  chmodSync(remoteSecretFile, 0o600);
  const localConfig = writeEndpointConfig(localRoot, SERVER_AUTHORITY, localBootstrapSecret, localListen);
  const remoteConfig = writeEndpointConfig(remoteRoot, REMOTE_ENDPOINT_AUTHORITY, remoteSecretFile, remoteListen);
  let access: AccessFixture | undefined;
  let remote: ReadyProcess | undefined;
  let server: ReadyProcess | undefined;
  let edge: AccessEdge | undefined;
  try {
    access = await startAccessFixture();
    const uiAssetsDirectory = materializeUiAssets(root);
    const serverConfig = writeServerConfig(
      root,
      access.issuer,
      access.jwksUrl,
      await reserveLoopbackPort(),
      uiAssetsDirectory,
      {
        deployment: "all_in_one",
        endpointBinary,
        localEndpointConfig: localConfig,
        localListenAddress: localListen,
        localBootstrapSecret,
      },
    );
    remote = await startChildProcess(endpointBinary, ["--config", remoteConfig, "--listen", remoteListen], "ZODE_READY ");
    const identityResponse = await fetch(`${remote.baseUrl}/v1/identity`, {
      headers: {
        Authorization: `Bearer ${REMOTE_CONTROL_SECRET}`,
        "Zode-Subject": "web-remote-endpoint-placement-identity",
      },
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
    const identityText = await identityResponse.text();
    assertSafeText(identityText, REMOTE_CONTROL_SECRET, "remote identity response");
    if (!identityResponse.ok) throw new Error("remote Endpoint identity probe failed");
    const remoteIdentity = JSON.parse(identityText) as JsonObject;
    if (typeof remoteIdentity.endpoint_id !== "string" || remoteIdentity.endpoint_id.length === 0) {
      throw new Error("remote Endpoint did not return its stable endpoint_id");
    }
    server = await startChildProcess(serverBinary, ["--config", serverConfig.path], "ZODE_SERVER_READY ");
    edge = await access.startEdge(server.baseUrl);
    return {
      root,
      serverDatabase: serverConfig.database,
      serverSecrets: serverConfig.secrets,
      access,
      edge,
      server,
      remote,
      remoteEndpointId: remoteIdentity.endpoint_id,
    };
  } catch (error) {
    await edge?.close().catch(() => undefined);
    await server?.stop().catch(() => undefined);
    await remote?.stop().catch(() => undefined);
    await access?.close().catch(() => undefined);
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

async function startServerOnlyHarness(): Promise<ServerOnlyHarness> {
  const serverBinary =
    process.env.ZODE_SERVER_BIN ??
    process.env.CARGO_BIN_EXE_zode_server ??
    resolve(REPO_ROOT, "server/target/debug/zode-server");
  const root = mkdtempSync(join(tmpdir(), "zode-web-server-only-"));
  let access: AccessFixture | undefined;
  let server: ReadyProcess | undefined;
  let edge: AccessEdge | undefined;
  try {
    access = await startAccessFixture();
    const uiAssetsDirectory = materializeUiAssets(root);
    const serverConfig = writeServerConfig(root, access.issuer, access.jwksUrl, await reserveLoopbackPort(), uiAssetsDirectory, {
      deployment: "server_only",
    });
    server = await startChildProcess(serverBinary, ["--config", serverConfig.path], "ZODE_SERVER_READY ");
    edge = await access.startEdge(server.baseUrl);
    return { root, access, edge, server };
  } catch (error) {
    await edge?.close().catch(() => undefined);
    await server?.stop().catch(() => undefined);
    await access?.close().catch(() => undefined);
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

function loadCassette(): JsonObject {
  const raw = readFileSync(CASSETTE_PATH, "utf8");
  const cassette = JSON.parse(raw) as JsonObject;
  if (cassette.schema !== "zode.http-incident-recording.v1" || cassette.version !== 1) {
    throw new Error("remote endpoint placement cassette schema changed");
  }
  if (typeof cassette.purpose !== "string" || cassette.boundary !== "browser->management-origin") {
    throw new Error("remote endpoint placement cassette omitted its browser boundary");
  }
  if (cassette.owner !== "e2e_remote_endpoint_add_probe_and_endpoint_scoped_session_placement") {
    throw new Error("remote endpoint placement cassette owner changed");
  }
  if (!Array.isArray(cassette.secret_slots) || cassette.secret_slots.includes(REMOTE_CONTROL_SECRET)) {
    throw new Error("remote endpoint placement cassette contains an unredacted secret");
  }
  if (cassette.whole_digest !== cassetteDigest(cassette)) {
    throw new Error("remote endpoint placement cassette integrity digest changed");
  }
  if (
    cassette.first_failure?.exchange_sequence !== 0 ||
    cassette.first_failure?.status !== 404 ||
    cassette.first_failure?.safe_error !== "missing_public_endpoint_route"
  ) {
    throw new Error("remote endpoint placement first failure was changed");
  }
  if (
    cassette.expected_after_fix?.status !== 201 ||
    cassette.replay_policy?.same_first_failure_is_red !== true ||
    cassette.replay_policy?.no_shallow_404_pass !== true
  ) {
    throw new Error("remote endpoint placement cassette permits a shallow 404 pass");
  }
  if (
    cassette.target_contract?.success_status !== 201 ||
    cassette.target_contract?.endpoint_id_source !== "remote_endpoint_identity_probe" ||
    cassette.target_contract?.session_url !== "/endpoints/{endpoint_id}/sessions/{session_id}" ||
    cassette.target_contract?.session_id_source !== "endpoint_generated_ulid"
  ) {
    throw new Error("remote endpoint placement target contract was changed");
  }
  if (
    cassette.placement_contract?.session_create_and_list_path !== "/v1/endpoints/{endpoint_id}/sessions" ||
    cassette.placement_contract?.id_only_session_lookup?.path !== "/v1/sessions/{session_id}" ||
    cassette.placement_contract?.id_only_session_lookup?.status !== 404 ||
    cassette.placement_contract?.server_session_state !== "absent" ||
    cassette.placement_contract?.server_store?.session_ids !== "absent" ||
    cassette.placement_contract?.server_store?.events !== "absent" ||
    cassette.placement_contract?.server_store?.resume_cursors !== "absent" ||
    cassette.placement_contract?.unreachable?.authoritative !== false ||
    cassette.placement_contract?.unreachable?.automatic_migration !== false ||
    cassette.placement_contract?.server_only_local_endpoint_id !== null
  ) {
    throw new Error("remote endpoint placement placement contract was changed");
  }
  const exchange = cassette.exchanges?.[0];
  if (!exchange || exchange.sequence !== 0) throw new Error("remote endpoint placement cassette omitted exchange 0");
  if (exchange.request?.method !== "POST" || exchange.request?.path !== "/v1/endpoints") {
    throw new Error("remote endpoint placement cassette request boundary changed");
  }
  if (exchange.request.body_sha256 !== `sha256:${sha256(exchange.request.raw_body)}`) {
    throw new Error("remote endpoint placement cassette request body digest changed");
  }
  if (
    !/^sha256:[0-9a-f]{64}$/.test(exchange.request.fingerprint ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(exchange.recorded_response?.fingerprint ?? "")
  ) {
    throw new Error("remote endpoint placement cassette omitted canonical fingerprints");
  }
  if (exchange.recorded_response?.status !== 404 || exchange.recorded_response?.completed !== true) {
    throw new Error("remote endpoint placement cassette response boundary changed");
  }
  const responseBody = Buffer.concat(
    (exchange.recorded_response.chunks ?? []).map((chunk: JsonObject) => Buffer.from(chunk.body_hex, "hex")),
  );
  if (exchange.recorded_response.body_sha256 !== `sha256:${sha256(responseBody.toString("utf8"))}`) {
    throw new Error("remote endpoint placement cassette response digest changed");
  }
  const serialized = raw.toLowerCase();
  if (serialized.includes(REMOTE_CONTROL_SECRET.toLowerCase()) || serialized.includes("eyj")) {
    throw new Error("remote endpoint placement cassette retained live credential material");
  }
  return cassette;
}

function replaceSlots(value: unknown, slots: Record<string, string>): unknown {
  if (typeof value === "string") {
    if (slots[value]) return slots[value];
    return value.replace(/\$\{([A-Z0-9_]+)\}/g, (whole, name: string) => slots[name] ?? whole);
  }
  if (Array.isArray(value)) return value.map((item) => replaceSlots(item, slots));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceSlots(item, slots)]));
  }
  return value;
}

function captureFirstOccurrenceEvidence(
  request: PlaywrightRequest,
  response: PlaywrightResponse,
  responseBody: string,
  owner: string,
): string {
  const rawBody = request.postData() ?? "";
  let parsedBody: JsonObject;
  try {
    parsedBody = JSON.parse(rawBody) as JsonObject;
  } catch {
    throw new Error("first remote-endpoint failure body was not JSON; refusing unsafe capture");
  }
  const safeBody: JsonObject = {
    label: parsedBody.label,
    base_url: "${SLOT_ENDPOINT_BASE_URL}",
    control_auth: {
      kind: parsedBody.control_auth?.kind,
      secret: "${SLOT_ENDPOINT_CONTROL_SECRET}",
    },
  };
  const requestHeaders = request.headers();
  const safeRequestHeaders = {
    "cf-access-jwt-assertion": "${SLOT_ACCESS_ASSERTION}",
    "content-type": requestHeaders["content-type"] ?? "application/json",
    "idempotency-key": requestHeaders["idempotency-key"] ?? "",
  };
  const safeResponseHeaders = Object.fromEntries(
    ["cache-control", "content-type", "location", "referrer-policy"]
      .map((name) => [name, response.headers()[name]])
      .filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
  assertSafeText(responseBody, REMOTE_CONTROL_SECRET, "first-occurrence response");
  const safeResponseChunk = {
    offset_us: 0,
    body_hex: Buffer.from(responseBody, "utf8").toString("hex"),
  };
  const requestFingerprint = {
    method: request.method(),
    path: new URL(request.url()).pathname,
    headers: safeRequestHeaders,
    body: safeBody,
  };
  const responseFingerprint = {
    status: response.status(),
    headers: safeResponseHeaders,
    chunks: [safeResponseChunk],
    completed: true,
    termination: "complete",
  };
  const evidence: JsonObject = {
    schema: "zode.http-incident-recording.v1",
    version: 1,
    recording_id: `${owner}-first-occurrence-runtime`,
    purpose: "Retain the first real browser remote Endpoint add failure before repair or retry.",
    owner,
    boundary: "browser->management-origin",
    secret_slots: [
      "SLOT_ACCESS_ASSERTION",
      "SLOT_ENDPOINT_BASE_URL",
      "SLOT_ENDPOINT_CONTROL_SECRET",
    ],
    first_failure: {
      exchange_sequence: 0,
      status: response.status(),
      safe_error: response.status() === 404 ? "missing_public_endpoint_route" : "observed_remote_endpoint_add_failure",
    },
    canonical_fingerprint: {
      algorithm: "sha256",
      request: `sha256:${sha256(canonicalJson(requestFingerprint))}`,
      response: `sha256:${sha256(canonicalJson(responseFingerprint))}`,
    },
    exchanges: [
      {
        sequence: 0,
        request: {
          method: request.method(),
          path: new URL(request.url()).pathname,
          semantic_headers: safeRequestHeaders,
          raw_body: jsonBody(safeBody),
          canonical_json: safeBody,
          body_sha256: `sha256:${sha256(jsonBody(safeBody))}`,
        },
        recorded_response: {
          status: response.status(),
          semantic_headers: safeResponseHeaders,
          chunks: [safeResponseChunk],
          completed: true,
          termination: "complete",
          body_sha256: `sha256:${sha256(responseBody)}`,
        },
      },
    ],
  };
  evidence.whole_digest = cassetteDigest(evidence);
  const quarantineRoot = resolve(
    process.env.ZODE_RECORDING_QUARANTINE ?? join(process.cwd(), "target/test-recordings/quarantine"),
  );
  mkdirSync(quarantineRoot, { recursive: true, mode: 0o700 });
  chmodSync(quarantineRoot, 0o700);
  const runRoot = mkdtempSync(join(quarantineRoot, "remote-endpoint-placement-"));
  chmodSync(runRoot, 0o700);
  const evidencePath = join(runRoot, "first-occurrence.json");
  const serialized = jsonBody(evidence, null, 2);
  if (serialized.includes(REMOTE_CONTROL_SECRET) || serialized.includes("eyJ")) {
    throw new Error("first-occurrence capture retained live credential material");
  }
  writeFileSync(evidencePath, `${serialized}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(evidencePath, 0o600);
  return evidencePath;
}

async function replayFirstFailure(
  api: APIRequestContext,
  serverBaseUrl: string,
  assertion: string,
  remoteBaseUrl: string,
  cassette: JsonObject,
): Promise<void> {
  const slots: Record<string, string> = {
    SLOT_ACCESS_ASSERTION: assertion,
    SLOT_ENDPOINT_BASE_URL: remoteBaseUrl,
    SLOT_ENDPOINT_CONTROL_SECRET: REMOTE_CONTROL_SECRET,
  };
  const exchange = cassette.exchanges[0] as JsonObject;
  const request = exchange.request as JsonObject;
  const filledHeaders = replaceSlots(request.semantic_headers, slots) as Record<string, string>;
  const filledBody = replaceSlots(request.raw_body, slots) as string;
  const response = await api.fetch(`${serverBaseUrl}${request.path}`, {
    method: request.method,
    headers: filledHeaders,
    data: filledBody,
  });
  const body = await response.text();
  assertSafeText(body, REMOTE_CONTROL_SECRET, "replayed response");
  const expectedBody = Buffer.concat(
    (exchange.recorded_response.chunks ?? []).map((chunk: JsonObject) => Buffer.from(chunk.body_hex, "hex")),
  ).toString("utf8");
  if (response.status() === 404 || response.status() === 405) {
    throw new Error(`SHALLOW_NON_EVIDENCE: retained missing endpoint route still returned ${response.status()}`);
  }
  const reproduced = response.status() === cassette.first_failure.status && body === expectedBody;
  if (reproduced) {
    throw new Error("SHALLOW_NON_EVIDENCE: the retained first remote-endpoint-add failure still reproduces");
  }
  expect(response.status()).toBe(cassette.expected_after_fix.status);
  const success = JSON.parse(body) as JsonObject;
  expect(typeof success.endpoint_id).toBe("string");
  expect(JSON.stringify(success).includes(REMOTE_CONTROL_SECRET)).toBe(false);
}

function requestPath(request: PlaywrightRequest): string {
  return new URL(request.url()).pathname;
}

function responsePath(response: PlaywrightResponse): string {
  return new URL(response.url()).pathname;
}

function requireBehavioralEntry(response: PlaywrightResponse | null, path: string): PlaywrightResponse {
  const status = response?.status() ?? 0;
  if (status === 404 || status === 405) {
    throw new Error(`SHALLOW_NON_EVIDENCE: ${path} is still a missing public route (status=${status})`);
  }
  if (response === null) {
    throw new Error(`NON_BEHAVIORAL_EVIDENCE: no public response arrived for ${path}`);
  }
  return response;
}

function endpointItems(value: unknown): JsonObject[] {
  const items = Array.isArray(value) ? value : (value as JsonObject | null)?.items;
  return Array.isArray(items) ? (items as JsonObject[]) : [];
}

async function addRemoteEndpoint(
  page: Page,
  remoteBaseUrl: string,
  remoteEndpointId: string,
  cassette: JsonObject,
  owner: string,
): Promise<JsonObject> {
  await page.getByRole("link", { name: /^Endpoints$/i }).click();
  await page.getByRole("button", { name: /add remote endpoint/i }).click();
  const dialog = page.getByRole("dialog");
  const label = dialog.getByLabel(/^Label$/i);
  const url = dialog.getByLabel(/reachable URL|base URL/i);
  const secret = dialog.getByLabel(/control secret/i);
  await expect(secret).toHaveAttribute("type", "password");
  await label.fill(REMOTE_LABEL);
  await url.fill(remoteBaseUrl);
  await secret.fill(REMOTE_CONTROL_SECRET);

  const progress = page
    .locator('[role="status"], [aria-live="polite"]')
    .filter({ hasText: /probing|checking|connecting/i })
    .first();
  const requestPromise = page.waitForRequest(
    (request) => request.method() === "POST" && requestPath(request) === "/v1/endpoints",
  );
  const responsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && responsePath(response) === "/v1/endpoints",
  );
  const progressPromise = expect(progress).toBeVisible({ timeout: HTTP_TIMEOUT_MS });
  await dialog.getByRole("button", { name: /add endpoint/i }).click();
  await progressPromise;
  const [request, response] = await Promise.all([requestPromise, responsePromise]);
  const requestBody = request.postDataJSON() as JsonObject;
  expect(request.headers()["idempotency-key"]).toBeTruthy();
  const requestMatchesContract =
    requestBody.label === REMOTE_LABEL &&
    requestBody.base_url === remoteBaseUrl &&
    requestBody.control_auth?.kind === "bearer" &&
    requestBody.control_auth?.secret === REMOTE_CONTROL_SECRET &&
    !Object.prototype.hasOwnProperty.call(requestBody, "endpoint_id");
  expect(requestMatchesContract).toBe(true);
  const responseBody = await response.text();
  assertSafeText(responseBody, REMOTE_CONTROL_SECRET, "remote Endpoint create response");
  const firstFailureExchange = cassette.exchanges[0] as JsonObject;
  const firstFailureBody = Buffer.concat(
    (firstFailureExchange.recorded_response.chunks ?? []).map((chunk: JsonObject) => Buffer.from(chunk.body_hex, "hex")),
  ).toString("utf8");
  if (response.status() !== 201) {
    const evidencePath = captureFirstOccurrenceEvidence(request, response, responseBody, owner);
    if (response.status() === cassette.first_failure.status && responseBody === firstFailureBody) {
      throw new Error(`SHALLOW_NON_EVIDENCE: the retained first remote-endpoint-add failure still reproduces; evidence=${evidencePath}`);
    }
    if (response.status() === 404 || response.status() === 405) {
      throw new Error(`SHALLOW_NON_EVIDENCE: remote Endpoint add route is missing; evidence=${evidencePath}`);
    }
    throw new Error(`remote Endpoint add failed with ${response.status()}; evidence=${evidencePath}`);
  }
  const endpoint = JSON.parse(responseBody) as JsonObject;
  expect(endpoint.endpoint_id).toBe(remoteEndpointId);
  expect(JSON.stringify(endpoint).includes(REMOTE_CONTROL_SECRET)).toBe(false);
  const secretValues = await page.getByLabel(/control secret/i).evaluateAll((elements) =>
    elements.map((element) => (element as HTMLInputElement).value),
  );
  expect(secretValues.every((value) => value === "")).toBe(true);
  await expect(page.getByText(REMOTE_LABEL, { exact: true })).toBeVisible();
  return endpoint;
}

async function selectEndpoint(dialog: Locator, endpointLabel: string): Promise<void> {
  const escapedLabel = endpointLabel.replace(/[.*+?^${}()|[\[\]\\]/g, "\\$&");
  const radio = dialog.getByRole("radio", { name: new RegExp(escapedLabel, "i") });
  await expect(radio).toHaveCount(1);
  await radio.check();
}

async function createSession(page: Page, endpointId: string, endpointLabel: string): Promise<{ endpointId: string; sessionId: string }> {
  await page.getByRole("link", { name: /^Sessions$/i }).click();
  await page.getByRole("button", { name: /new session|create session/i }).click();
  const dialog = page.getByRole("dialog");
  await selectEndpoint(dialog, endpointLabel);
  const createRequestPromise = page.waitForRequest(
    (request) => request.method() === "POST" && requestPath(request) === `/v1/endpoints/${endpointId}/sessions`,
  );
  const createResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && responsePath(response) === `/v1/endpoints/${endpointId}/sessions`,
  );
  await dialog.getByRole("button", { name: /create session/i }).click();
  const [request, response] = await Promise.all([createRequestPromise, createResponsePromise]);
  const requestBody = request.postDataJSON() as JsonObject;
  expect(request.headers()["idempotency-key"]).toBeTruthy();
  expect(Object.prototype.hasOwnProperty.call(requestBody, "session_id")).toBe(false);
  expect(response.status()).toBe(201);
  const body = (await response.json()) as JsonObject;
  const sessionId = body.session_id;
  expect(typeof sessionId).toBe("string");
  expect(sessionId).toMatch(ULID);
  await expect(page).toHaveURL(new RegExp(`/endpoints/${endpointId}/sessions/${sessionId}$`));
  return { endpointId, sessionId };
}

function walkFiles(root: string): string[] {
  if (!statSafe(root)) return [];
  const metadata = statSync(root);
  if (metadata.isFile()) return [root];
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) =>
    walkFiles(join(root, entry.name)),
  );
}

function statSafe(path: string): boolean {
  try {
    return statSync(path).isFile() || statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function assertBrowserRequestsUseManagementServer(
  requests: PlaywrightRequest[],
  managementBaseUrl: string,
): void {
  const managementOrigin = new URL(managementBaseUrl).origin;
  for (const request of requests) {
    const url = new URL(request.url());
    if (url.protocol !== "http:" && url.protocol !== "https:") continue;
    if (url.origin !== managementOrigin) {
      throw new Error(`browser request escaped the management Server origin: ${url.origin}${url.pathname}`);
    }
  }
}

function assertServerDoesNotPersistSessionState(
  harness: Harness,
  sessionIds: string[],
  serverOutput: { stdout: string; stderr: string },
): void {
  // Endpoint SQLite roots are intentionally not under this list: session IDs belong there.
  const serverFiles = [
    harness.serverDatabase,
    `${harness.serverDatabase}-wal`,
    `${harness.serverDatabase}-shm`,
    `${harness.serverDatabase}-journal`,
    ...walkFiles(harness.serverSecrets),
  ].filter(statSafe);
  const forbiddenServerStoreMarkers = ["session", "event", "cursor"].map((marker) => Buffer.from(marker));
  for (const sessionId of sessionIds) {
    if (serverOutput.stdout.includes(sessionId) || serverOutput.stderr.includes(sessionId)) {
      throw new Error("Server output contained an Endpoint-owned session ID");
    }
  }
  for (const file of serverFiles) {
    const bytes = readFileSync(file);
    for (const sessionId of sessionIds) {
      if (bytes.includes(Buffer.from(sessionId))) {
        throw new Error(`Server persisted an Endpoint-owned session ID in ${basename(file)}`);
      }
    }
    for (const marker of forbiddenServerStoreMarkers) {
      if (bytes.includes(marker)) {
        throw new Error(`Server store contained a session/event/cursor marker in ${basename(file)}`);
      }
    }
  }
}

async function assertSecretFreeBrowserSurface(
  page: Page,
  context: BrowserContext,
  secret: string,
  consoleMessages: string[],
): Promise<void> {
  const renderedSurface = await page.locator("body").innerText();
  const accessibleSurface = await page.locator("body *").evaluateAll((elements) =>
    elements
      .flatMap((element) => [
        element.textContent ?? "",
        element.getAttribute("aria-label") ?? "",
        element.getAttribute("title") ?? "",
      ])
      .join("\n"),
  );
  const storage = await page.evaluate(() =>
    JSON.stringify({
      local: Object.fromEntries(Object.entries(localStorage)),
      session: Object.fromEntries(Object.entries(sessionStorage)),
    }),
  );
  expect(renderedSurface.includes(secret)).toBe(false);
  expect(accessibleSurface.includes(secret)).toBe(false);
  expect(storage.includes(secret)).toBe(false);
  expect(page.url().includes(secret)).toBe(false);
  expect(consoleMessages.some((message) => message.includes(secret))).toBe(false);
  const cookies = await context.cookies();
  expect(cookies.some((cookie) => cookie.value.includes(secret))).toBe(false);
}

test("e2e_remote_endpoint_add_probe_and_endpoint_scoped_session_placement", async ({ browser }) => {
  const cassette = loadCassette();
  const harness = await startHarness();
  const assertion = harness.access.sign();
  const context = await browser.newContext();
  const page = await context.newPage();
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  page.on("pageerror", (error) => consoleMessages.push(error.message));
  const observedRequests: PlaywrightRequest[] = [];
  page.on("request", (request) => observedRequests.push(request));
  const sessionIds: string[] = [];
  let serverOutput: { stdout: string; stderr: string } | undefined;
  let remoteStopped = false;

  try {
    if (process.env.ZODE_REPLAY_CASSETTE === "1") {
      await replayFirstFailure(context.request, harness.edge.baseUrl, assertion, harness.remote.baseUrl, cassette);
      return;
    }

    const endpointListPromise = page
      .waitForResponse(
        (response) => response.request().method() === "GET" && responsePath(response) === "/v1/endpoints",
      )
      .catch(() => null);
    const navigation = await page.goto(harness.edge.baseUrl);
    requireBehavioralEntry(navigation, "/");
    const endpointListResponse = requireBehavioralEntry(await endpointListPromise, "/v1/endpoints");
    const endpointList = (await endpointListResponse.json()) as JsonObject;
    const localEndpoint = endpointItems(endpointList).find((item: JsonObject) => item.kind === "local");
    expect(localEndpoint).toBeTruthy();
    if (!localEndpoint) throw new Error("all-in-one Server did not expose its built-in local Endpoint");
    expect(typeof localEndpoint.endpoint_id).toBe("string");
    expect(localEndpoint.status).toMatch(/online|degraded/i);
    const localEndpointId = localEndpoint.endpoint_id as string;
    const localEndpointLabel = localEndpoint.label as string;
    await expect(page.getByText(localEndpointLabel, { exact: true })).toBeVisible();

    const remoteEndpoint = await addRemoteEndpoint(
      page,
      harness.remote.baseUrl,
      harness.remoteEndpointId,
      cassette,
      "e2e_remote_endpoint_add_probe_and_endpoint_scoped_session_placement",
    );
    expect(remoteEndpoint.kind).toBe("remote");
    expect(remoteEndpoint.status).toMatch(/online|degraded/i);

    const localSession = await createSession(page, localEndpointId, localEndpointLabel);
    sessionIds.push(localSession.sessionId);
    expect(new URL(page.url()).pathname).toBe(`/endpoints/${localSession.endpointId}/sessions/${localSession.sessionId}`);

    const remoteSession = await createSession(page, harness.remoteEndpointId, REMOTE_LABEL);
    sessionIds.push(remoteSession.sessionId);
    expect(new URL(page.url()).pathname).toBe(`/endpoints/${remoteSession.endpointId}/sessions/${remoteSession.sessionId}`);

    const idOnlyResponse = await context.request.get(
      `${harness.edge.baseUrl}/v1/sessions/${remoteSession.sessionId}`,
      { headers: { "Cf-Access-Jwt-Assertion": assertion } },
    );
    expect(idOnlyResponse.status()).toBe(404);
    expect(
      observedRequests.some((request) => new URL(request.url()).pathname === `/v1/sessions/${remoteSession.sessionId}`),
    ).toBe(false);

    await harness.remote.stop();
    remoteStopped = true;
    await expect(page.getByText(/disconnected|endpoint unreachable/i).first()).toBeVisible({ timeout: HTTP_TIMEOUT_MS });
    await expect(page.getByText(/agent failed|session failed|runtime failure/i)).toHaveCount(0);

    await page.getByRole("link", { name: /^Endpoints$/i }).click();
    const remoteCard = page.getByRole("listitem").filter({ hasText: REMOTE_LABEL });
    await expect(remoteCard).toBeVisible();
    const probeButton = remoteCard.getByRole("button", { name: /probe/i });
    const probeProgress = page
      .locator('[role="status"], [aria-live="polite"]')
      .filter({ hasText: /probing|checking|connecting/i })
      .first();
    const probeResponsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST" && responsePath(response) === `/v1/endpoints/${harness.remoteEndpointId}/probe`,
    );
    const probeProgressPromise = expect(probeProgress).toBeVisible({ timeout: HTTP_TIMEOUT_MS });
    await probeButton.click();
    await probeProgressPromise;
    const probeResponse = await probeResponsePromise;
    const probeBody = await probeResponse.text();
    assertSafeText(probeBody, REMOTE_CONTROL_SECRET, "unreachable probe response");
    expect(probeResponse.status()).toBe(503);
    const probeJson = JSON.parse(probeBody) as JsonObject;
    expect(probeJson.error?.code).toBe("endpoint_unavailable");
    await expect(remoteCard).toContainText(/unreachable/i);
    await expect(page.getByText(/non-authoritative/i)).toBeVisible();
    await expect(remoteCard).not.toContainText(/deleted/i);
    await expect(remoteCard.getByRole("button", { name: /migrate|move/i })).toHaveCount(0);
    await expect(page.getByText(REMOTE_LABEL, { exact: true })).toBeVisible();

    await expect(probeButton).toBeEnabled();
    harness.remote = await harness.remote.restart();
    remoteStopped = false;
    const onlineProbeResponsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST" && responsePath(response) === `/v1/endpoints/${harness.remoteEndpointId}/probe`,
    );
    const onlineProbeProgressPromise = expect(
      page
        .locator('[role="status"], [aria-live="polite"]')
        .filter({ hasText: /probing|checking|connecting/i })
        .first(),
    ).toBeVisible({ timeout: HTTP_TIMEOUT_MS });
    await probeButton.click();
    await onlineProbeProgressPromise;
    const onlineProbeResponse = await onlineProbeResponsePromise;
    const onlineProbeBody = await onlineProbeResponse.text();
    assertSafeText(onlineProbeBody, REMOTE_CONTROL_SECRET, "online probe response");
    expect(onlineProbeResponse.status()).toBe(200);
    await expect(remoteCard).toContainText(/online|reachable/i);
    await expect(remoteCard).not.toContainText(/unreachable|deleted/i);

    await assertSecretFreeBrowserSurface(page, context, REMOTE_CONTROL_SECRET, consoleMessages);
  } finally {
    try {
      await context.close();
      if (!remoteStopped) await harness.remote.stop();
      serverOutput = await harness.server.stop();
      await harness.edge.close();
      await harness.access.close();
      if (sessionIds.length > 0 && serverOutput) {
        assertServerDoesNotPersistSessionState(harness, sessionIds, serverOutput);
      }
      assertBrowserRequestsUseManagementServer(observedRequests, harness.edge.baseUrl);
    } finally {
      rmSync(harness.root, { recursive: true, force: true });
    }
  }
});

test("e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror", async ({ browser }) => {
  const cassette = loadCassette();
  const harness = await startHarness();
  const assertion = harness.access.sign();
  const context = await browser.newContext();
  const page = await context.newPage();
  const observedRequests: PlaywrightRequest[] = [];
  page.on("request", (request) => observedRequests.push(request));
  const sessionIds: string[] = [];
  let remoteStopped = false;
  let serverOutput: { stdout: string; stderr: string } | undefined;

  try {
    const endpointListPromise = page
      .waitForResponse(
        (response) => response.request().method() === "GET" && responsePath(response) === "/v1/endpoints",
      )
      .catch(() => null);
    const navigation = await page.goto(harness.edge.baseUrl);
    requireBehavioralEntry(navigation, "/");
    const endpointListResponse = requireBehavioralEntry(await endpointListPromise, "/v1/endpoints");
    const endpointList = (await endpointListResponse.json()) as JsonObject;
    const localEndpoint = endpointItems(endpointList).find((item: JsonObject) => item.kind === "local");
    expect(localEndpoint).toBeTruthy();
    if (!localEndpoint) throw new Error("all-in-one Server did not expose its built-in local Endpoint");
    const localEndpointId = localEndpoint.endpoint_id as string;
    const localEndpointLabel = localEndpoint.label as string;

    await addRemoteEndpoint(
      page,
      harness.remote.baseUrl,
      harness.remoteEndpointId,
      cassette,
      "e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror",
    );
    const localSession = await createSession(page, localEndpointId, localEndpointLabel);
    const remoteSession = await createSession(page, harness.remoteEndpointId, REMOTE_LABEL);
    sessionIds.push(localSession.sessionId, remoteSession.sessionId);

    expect(
      observedRequests.some(
        (request) => requestPath(request) === `/v1/endpoints/${localEndpointId}/sessions`,
      ),
    ).toBe(true);
    expect(
      observedRequests.some(
        (request) => requestPath(request) === `/v1/endpoints/${harness.remoteEndpointId}/sessions`,
      ),
    ).toBe(true);
    expect(
      observedRequests.some((request) => /^\/v1\/sessions\/[^/]+$/.test(requestPath(request))),
    ).toBe(false);

    await page.getByRole("link", { name: /^Sessions$/i }).click();
    await expect
      .poll(
        () =>
          new Set(
            observedRequests
              .filter((request) => request.method() === "GET")
              .map((request) => requestPath(request)),
          ),
        { timeout: HTTP_TIMEOUT_MS },
      )
      .toEqual(
        expect.arrayContaining([
          `/v1/endpoints/${localEndpointId}/sessions`,
          `/v1/endpoints/${harness.remoteEndpointId}/sessions`,
        ]),
      );
    const headings = await page.getByRole("heading").allTextContents();
    expect(headings.some((heading) => heading.includes(localEndpointLabel))).toBe(true);
    expect(headings.some((heading) => heading.includes(REMOTE_LABEL))).toBe(true);
    const hrefs = await page.getByRole("link").evaluateAll((links) =>
      links
        .map((link) => link.getAttribute("href"))
        .filter((href): href is string => href !== null),
    );
    expect(hrefs).toContain(`/endpoints/${localSession.endpointId}/sessions/${localSession.sessionId}`);
    expect(hrefs).toContain(`/endpoints/${remoteSession.endpointId}/sessions/${remoteSession.sessionId}`);
    expect(hrefs.some((href) => /^\/sessions\/[^/]+$/.test(href))).toBe(false);

    for (const sessionId of sessionIds) {
      const idOnlyResponse = await context.request.get(
        `${harness.edge.baseUrl}/v1/sessions/${sessionId}`,
        { headers: { "Cf-Access-Jwt-Assertion": assertion } },
      );
      expect(idOnlyResponse.status()).toBe(404);
    }

    const remoteSessionLink = page.getByRole("link", { name: new RegExp(remoteSession.sessionId) });
    await remoteSessionLink.click();
    await harness.remote.stop();
    remoteStopped = true;
    await expect(page.getByText(/non-authoritative/i)).toBeVisible({ timeout: HTTP_TIMEOUT_MS });
    await expect(page.getByRole("button", { name: /migrate|move/i })).toHaveCount(0);
    await expect(page.getByText(/deleted/i)).toHaveCount(0);
  } finally {
    try {
      await context.close();
      if (!remoteStopped) await harness.remote.stop();
      serverOutput = await harness.server.stop();
      await harness.edge.close();
      await harness.access.close();
      if (sessionIds.length > 0 && serverOutput) {
        assertServerDoesNotPersistSessionState(harness, sessionIds, serverOutput);
      }
      assertBrowserRequestsUseManagementServer(observedRequests, harness.edge.baseUrl);
    } finally {
      rmSync(harness.root, { recursive: true, force: true });
    }
  }
});

test("e2e_browser_server_only_local_endpoint_id_null_has_no_phantom_builtin_endpoint", async ({ browser }) => {
  const harness = await startServerOnlyHarness();
  const context = await browser.newContext();
  const page = await context.newPage();
  const observedRequests: PlaywrightRequest[] = [];
  page.on("request", (request) => observedRequests.push(request));

  try {
    const systemPromise = page
      .waitForResponse(
        (response) => response.request().method() === "GET" && responsePath(response) === "/v1/system",
      )
      .catch(() => null);
    const endpointListPromise = page
      .waitForResponse(
        (response) => response.request().method() === "GET" && responsePath(response) === "/v1/endpoints",
      )
      .catch(() => null);
    const navigation = await page.goto(harness.edge.baseUrl);
    requireBehavioralEntry(navigation, "/");
    const systemResponse = requireBehavioralEntry(await systemPromise, "/v1/system");
    const endpointListResponse = requireBehavioralEntry(await endpointListPromise, "/v1/endpoints");
    const system = (await systemResponse.json()) as JsonObject;
    const endpointList = (await endpointListResponse.json()) as JsonObject;
    expect(system.schema).toBe("zode.system.v1");
    expect(system.deployment).toBe("server_only");
    expect(system.local_endpoint_id).toBeNull();
    const items = endpointItems(endpointList);
    expect(Array.isArray(items)).toBe(true);
    expect(items.some((item: JsonObject) => item.kind === "local")).toBe(false);
    await expect(page.getByText(/built-in local endpoint|this machine/i)).toHaveCount(0);
  } finally {
    try {
      await context.close();
      await harness.server.stop();
      await harness.edge.close();
      await harness.access.close();
      assertBrowserRequestsUseManagementServer(observedRequests, harness.edge.baseUrl);
    } finally {
      rmSync(harness.root, { recursive: true, force: true });
    }
  }
});
