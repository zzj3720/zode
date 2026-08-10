const { spawn } = require("node:child_process");
const {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
} = require("node:crypto");
const fs = require("node:fs/promises");
const { lstatSync, readFileSync, readdirSync, watch } = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { createInterface } = require("node:readline");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RecordingJournal,
  SecretLedger,
} = require("../support/harness.cjs");
const {
  expectSelectedExecutionProfile,
  selectRadixValue,
} = require("../support/radix.cjs");

const E2E = "e2e_all_in_one_first_run_uses_normal_server_api_and_local_endpoint";
const HISTORICAL_INCIDENT_OWNER = "e2e_ui_all_in_one_first_run_creates_profile_and_chats";
const liveProviderBaseUrl = process.env.ZODE_E2E_LIVE_PROVIDER_BASE_URL;
const liveProviderApiKey = process.env.ZODE_E2E_LIVE_PROVIDER_API_KEY;
if (Boolean(liveProviderBaseUrl) !== Boolean(liveProviderApiKey)) {
  throw new Error("live browser provider configuration is incomplete");
}
const LIVE_PROVIDER = Boolean(liveProviderBaseUrl);
const FINAL_ASSISTANT = LIVE_PROVIDER ? "ZODE_E2_LIVE_OK" : "ZODE_UI_DURABLE_FINAL_ASSISTANT";
const PROVIDER_ID = LIVE_PROVIDER ? "opencode-go" : "openai-compatible-e2e";
const MODEL_ID = LIVE_PROVIDER ? "deepseek-v4-flash" : "ui-e2e-model";
const USER_MESSAGE = LIVE_PROVIDER
  ? "Reply with exactly ZODE_E2_LIVE_OK."
  : "Hello from the real browser";
const LATER_GAP_RELATION = "later_test_reproduction_of_gap";
const CAPTURE_LATER_GAP = process.env.ZODE_UI_CAPTURE_LATER_RECONNECT_GAP === "1";
const RECONNECT_FAILURE = "UI_SSE_RECONNECT_STATUS_STUCK";
const SERVER_AUTHORITY_ID = "server-all-in-one-ui-e2e";
const SAME_START_CAPABILITY_TOOL = "all_in_one_same_start_probe";
const BARRIERS = Object.freeze({
  controllerSeed: "server_controller_authority_and_endpoint_seed_staged",
  childReady: "endpoint_zode_ready",
  activeAuthorityProbe: "authenticated_endpoint_identity_and_capability_probe",
  endpointCapabilities: "endpoint_get_v1_capabilities",
  localCatalog: "local_endpoint_catalog_committed",
  serverBootstrap: "server_all_in_one_bootstrap",
  serverReady: "zode_server_ready_after_local_endpoint_catalog",
  uiEntry: "management_get_root_ui",
  systemDeployment: "server_get_v1_system_all_in_one",
});
const SESSION_PATH = /^\/endpoints\/([^/]+)\/sessions\/([0-9A-HJKMNP-TV-Z]{26})$/;
const READY_TIMEOUT_MS = 20_000;
const STOP_TIMEOUT_MS = 8_000;
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const SAFE_REQUEST_HEADERS = new Set([
  "accept",
  "content-type",
  "idempotency-key",
  "origin",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
]);
const SAFE_RESPONSE_HEADERS = new Set([
  "cache-control",
  "content-type",
  "referrer-policy",
]);

function productEnvironment(source) {
  const environment = { ...source };
  for (const key of [
    "ZODE_E2E_LIVE_PROVIDER_API_KEY",
    "OPENCODE_GO_API_KEY",
    "OPENCODE_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
  ]) {
    delete environment[key];
  }
  return environment;
}

const repositoryRoot = path.resolve(__dirname, "..", "..", "..");
const uiAssetsDirectory =
  process.env.ZODE_UI_ASSETS_DIRECTORY || path.join(repositoryRoot, "web", "dist");
const trackedIncidentPath = path.join(
  repositoryRoot,
  "web",
  "e2e",
  "fixtures",
  "all_in_one_first_run_initial_404.v1.json",
);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function envelopeDigest(value) {
  const unsigned = structuredClone(value);
  delete unsigned.envelope_digest;
  return `sha256:${sha256(Buffer.from(JSON.stringify(canonicalize(unsigned))))}`;
}

function headersFrom(source, allowlist) {
  const result = {};
  for (const [name, value] of Object.entries(source)) {
    const lower = name.toLowerCase();
    if (!allowlist.has(lower) || value == null) {
      continue;
    }
    result[lower] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return result;
}

function exactJson(value) {
  return JSON.stringify(canonicalize(value));
}

function assertExact(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function decodeExactBase64(value, label) {
  if (typeof value !== "string") {
    throw new Error(`${label} is not base64 text`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new Error(`${label} is not canonical base64`);
  }
  return bytes;
}

function assertTrackedIncident(cassette, source) {
  const exchange = cassette?.exchanges?.[0];
  const expectedSlot = {
    ACCESS_ASSERTION_RS256: {
      placeholder: "<ACCESS_ASSERTION_RS256>",
      kind: "test-owned Cloudflare Access RS256 assertion",
    },
  };
  const expectedCaptureContext = {
    deployment: "server_only_scaffold",
    endpoint_process: "real standalone Endpoint",
    reason: "canonical all_in_one exited before readiness and produced no HTTP exchange",
    access_admission:
      "not implemented in the source capture; current replay separately requires JWKS contact",
  };
  if (
    cassette.schema !== "zode.http-incident-recording.v1" ||
    cassette.recording_id !== "all-in-one-first-run-initial-404-v1" ||
    cassette.owner_e2e !== HISTORICAL_INCIDENT_OWNER ||
    cassette.boundary !== "browser_access_edge_management_http" ||
    cassette.first_observed?.safe_error !==
      "management UI entry returned 404 before bootstrap" ||
    cassette.first_observed?.status !== 404 ||
    exactJson(cassette.capture_context) !== exactJson(expectedCaptureContext) ||
    exactJson(cassette.secret_slots) !== exactJson(expectedSlot) ||
    cassette.timing_mode !== "immediate" ||
    cassette.envelope_digest !== envelopeDigest(cassette) ||
    !Array.isArray(cassette.exchanges) ||
    cassette.exchanges.length !== 1 ||
    exchange?.sequence !== 1 ||
    exchange.request?.method !== "GET" ||
    exchange.request?.path !== "/" ||
    !exchange.request?.headers ||
    typeof exchange.request.headers !== "object" ||
    exchange.request?.headers?.["cf-access-jwt-assertion"] !==
      "<ACCESS_ASSERTION_RS256>" ||
    exchange.response?.status !== 404 ||
    exchange.response?.outcome !== "completed" ||
    !Array.isArray(exchange.response?.chunks) ||
    !exchange.response?.headers ||
    typeof exchange.response.headers !== "object"
  ) {
    throw new Error("all_in_one_first_run incident cassette is invalid");
  }

  const requestHeaderNames = Object.keys(exchange.request.headers);
  if (
    requestHeaderNames.some(
      (name) => name !== "cf-access-jwt-assertion" && !SAFE_REQUEST_HEADERS.has(name),
    ) ||
    Object.keys(exchange.response.headers).some((name) => !SAFE_RESPONSE_HEADERS.has(name))
  ) {
    throw new Error("all_in_one_first_run cassette retained a non-semantic header");
  }

  const requestBody = decodeExactBase64(
    exchange.request.body_base64,
    "incident request body",
  );
  const responseBody = Buffer.concat(
    exchange.response.chunks.map((chunk, index) => {
      if (
        !Number.isSafeInteger(chunk.offset_us) ||
        chunk.offset_us < 0 ||
        (index > 0 && chunk.offset_us < exchange.response.chunks[index - 1].offset_us)
      ) {
        throw new Error("incident response chunk timing is invalid");
      }
      return decodeExactBase64(chunk.body_base64, "incident response chunk");
    }),
  );
  assertExact(sha256(requestBody), exchange.request.body_sha256, "incident request digest");
  assertExact(sha256(responseBody), exchange.response.body_sha256, "incident response digest");

  if (
    /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(source) ||
    /"(?:authorization|cookie|set-cookie|proxy-authorization|x-api-key)"\s*:/i.test(source)
  ) {
    throw new Error("all_in_one_first_run cassette failed its secret scan");
  }
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

class HarnessBarrierError extends Error {
  constructor(message, cause = null) {
    super(`HARNESS_FAILURE barrier=process_control: ${message}`, {
      ...(cause ? { cause } : {}),
    });
    this.name = "HarnessBarrierError";
  }
}

function prioritizeGateFailure(primary, error, label) {
  return new AggregateError(primary ? [error, primary] : [error], label);
}

async function readBounded(stream, onChunk = null) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error("test HTTP body exceeded the recording bound");
    }
    onChunk?.(bytes);
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

async function commandOutput(binary, args, allowedExitCodes = [0]) {
  const child = spawn(binary, args, { stdio: ["ignore", "pipe", "pipe"] });
  try {
    const [stdout, stderr, result] = await withTimeout(
      Promise.all([
        readBounded(child.stdout),
        readBounded(child.stderr),
        new Promise((resolve, reject) => {
          child.once("error", reject);
          child.once("exit", (code, signal) => resolve({ code, signal }));
        }),
      ]),
      5_000,
      `${path.basename(binary)} process observation`,
    );
    if (result.signal || !allowedExitCodes.includes(result.code)) {
      throw new Error(`${path.basename(binary)} process observation failed`);
    }
    return { stdout: stdout.toString("utf8"), stderr: stderr.toString("utf8") };
  } catch (error) {
    if (child.exitCode == null && child.signalCode == null) {
      child.kill("SIGKILL");
    }
    throw error;
  }
}

async function directChildPids(parentPid) {
  const result = await commandOutput(
    "/usr/bin/pgrep",
    ["-P", String(parentPid)],
    [0, 1],
  );
  return result.stdout
    .split(/\s+/)
    .filter(Boolean)
    .map((value) => Number(value))
    .filter(Number.isSafeInteger);
}

async function processCommand(pid) {
  const result = await commandOutput(
    "/bin/ps",
    ["-p", String(pid), "-o", "command="],
    [0, 1],
  );
  return result.stdout.trim();
}

async function assertTcpClientOwnedByProcess(socket, expectedPid, label) {
  if (
    socket.remoteAddress !== "127.0.0.1" ||
    !Number.isSafeInteger(socket.remotePort) ||
    socket.localAddress !== "127.0.0.1" ||
    !Number.isSafeInteger(socket.localPort) ||
    !Number.isSafeInteger(expectedPid)
  ) {
    throw new HarnessBarrierError(`${label} did not expose a loopback process-owned socket`);
  }
  const result = await commandOutput(
    "/usr/sbin/lsof",
    ["-nP", "-a", "-p", String(expectedPid), "-iTCP"],
    [0, 1],
  );
  const connection =
    `127.0.0.1:${socket.remotePort}->127.0.0.1:${socket.localPort}`;
  if (
    !result.stdout
      .split(/\r?\n/)
      .some((line) => line.includes(connection) && line.includes("(ESTABLISHED)"))
  ) {
    throw new Error(`${label} did not originate from the supervised Server process`);
  }
}

async function waitForProcessGone(pid, label) {
  await withTimeout(
    new Promise((resolve) => {
      const check = () => {
        try {
          process.kill(pid, 0);
          setTimeout(check, 25);
        } catch (error) {
          if (error?.code === "ESRCH") {
            resolve();
            return;
          }
          setTimeout(check, 25);
        }
      };
      check();
    }),
    STOP_TIMEOUT_MS,
    label,
  );
}

async function waitForProcessStopped(pid, label) {
  await withTimeout(
    new Promise((resolve, reject) => {
      const inspect = async () => {
        try {
          const result = await commandOutput(
            "/bin/ps",
            ["-p", String(pid), "-o", "state="],
            [0, 1],
          );
          const state = result.stdout.trim();
          if (!state) {
            reject(new Error(`${label} exited before its stop barrier`));
            return;
          }
          if (state.includes("T")) {
            resolve();
            return;
          }
          setTimeout(inspect, 5);
        } catch (error) {
          reject(error);
        }
      };
      inspect();
    }),
    READY_TIMEOUT_MS,
    label,
  );
}

async function listenLoopback(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test server did not expose a loopback address");
  }
  return `http://127.0.0.1:${address.port}`;
}

async function closeHttpServer(server) {
  if (!server?.listening) {
    return;
  }
  await withTimeout(
    new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
      server.closeAllConnections?.();
    }),
    STOP_TIMEOUT_MS,
    "test HTTP server shutdown",
  );
}

async function allocateLoopbackAddress() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("could not allocate a stable local Endpoint address");
  }
  const value = `127.0.0.1:${address.port}`;
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return value;
}

class TcpGate {
  static async start(label) {
    const sockets = new Set();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      socket.destroy();
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();
    if (!address || typeof address === "string" || address.port === 0) {
      throw new Error(`${label} did not hold a fixed nonzero loopback address`);
    }
    return new TcpGate(
      label,
      server,
      sockets,
      `127.0.0.1:${address.port}`,
    );
  }

  constructor(label, server, sockets, listenAddress) {
    this.label = label;
    this.server = server;
    this.sockets = sockets;
    this.listenAddress = listenAddress;
  }

  assertStillHolding(expected) {
    const address = this.server.address();
    if (
      !this.server.listening ||
      !address ||
      typeof address === "string" ||
      `127.0.0.1:${address.port}` !== expected
    ) {
      throw new Error(`${this.label} stopped holding its configured address`);
    }
  }

  async stop() {
    for (const socket of this.sockets) {
      socket.destroy();
    }
    this.sockets.clear();
    if (!this.server.listening) {
      return;
    }
    await withTimeout(
      new Promise((resolve, reject) => {
        this.server.close((error) => (error ? reject(error) : resolve()));
      }),
      STOP_TIMEOUT_MS,
      `${this.label} shutdown`,
    );
  }
}

class FileCreationBarrier {
  static arm(pathname, label, onObserved) {
    let resolveObserved;
    let rejectObserved;
    let settling = false;
    const observed = new Promise((resolve, reject) => {
      resolveObserved = resolve;
      rejectObserved = reject;
    });
    const watcher = watch(path.dirname(pathname), (_event, filename) => {
      if (
        settling ||
        (filename != null && String(filename) !== path.basename(pathname))
      ) {
        return;
      }
      try {
        const metadata = lstatSync(pathname);
        if (!metadata.isFile() || metadata.size === 0) {
          return;
        }
        settling = true;
        onObserved();
        resolveObserved();
      } catch (error) {
        if (error?.code !== "ENOENT") {
          rejectObserved(error);
        }
      }
    });
    watcher.once("error", rejectObserved);
    return new FileCreationBarrier(pathname, label, watcher, observed);
  }

  constructor(pathname, label, watcher, observed) {
    this.pathname = pathname;
    this.label = label;
    this.watcher = watcher;
    this.observed = observed;
  }

  async wait(process) {
    await withTimeout(
      Promise.race([
        this.observed,
        process.exit.then(({ code, signal }) => {
          throw new Error(
            `${path.basename(process.binary)} exited before ${this.label} (code=${code}, signal=${signal})`,
          );
        }),
      ]),
      READY_TIMEOUT_MS,
      this.label,
    );
  }

  stop() {
    this.watcher.close();
  }
}

function storeFamilyBytesSync(directory, basenamePrefix) {
  return readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.startsWith(basenamePrefix))
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((entry) => readFileSync(path.join(directory, entry.name)));
}

class FileContentBarrier {
  static arm(directory, basenamePrefix, requiredMarkers, label, onObserved) {
    let resolveObserved;
    let rejectObserved;
    let settling = false;
    const observed = new Promise((resolve, reject) => {
      resolveObserved = resolve;
      rejectObserved = reject;
    });
    const scan = () => {
      if (settling) {
        return;
      }
      try {
        const markers = requiredMarkers();
        if (!Array.isArray(markers) || markers.length === 0) {
          return;
        }
        const bytes = storeFamilyBytesSync(directory, basenamePrefix);
        if (
          bytes.length === 0 ||
          markers.some(
            (marker) =>
              typeof marker !== "string" ||
              marker.length === 0 ||
              !bytes.some((content) => content.includes(Buffer.from(marker))),
          )
        ) {
          return;
        }
        settling = true;
        onObserved();
        resolveObserved(bytes);
      } catch (error) {
        if (error?.code !== "ENOENT") {
          settling = true;
          rejectObserved(error);
        }
      }
    };
    const watcher = watch(directory, (_event, filename) => {
      if (
        filename == null ||
        String(filename).startsWith(basenamePrefix)
      ) {
        scan();
      }
    });
    watcher.once("error", (error) => {
      settling = true;
      rejectObserved(error);
    });
    scan();
    return new FileContentBarrier(label, watcher, observed, scan);
  }

  constructor(label, watcher, observed, scan) {
    this.label = label;
    this.watcher = watcher;
    this.observed = observed;
    this.scan = scan;
  }

  async wait(process) {
    return withTimeout(
      Promise.race([
        this.observed,
        process.exit.then(({ code, signal }) => {
          throw new Error(
            `${path.basename(process.binary)} exited before ${this.label} (code=${code}, signal=${signal})`,
          );
        }),
      ]),
      READY_TIMEOUT_MS,
      this.label,
    );
  }

  stop() {
    this.watcher.close();
  }
}

function randomSecret(label) {
  return `${label}-${randomBytes(32).toString("base64url")}`;
}

async function writePrivate(pathname, bytes) {
  await fs.writeFile(pathname, bytes, { flag: "wx", mode: 0o600 });
}

async function writeExecutable(pathname, source) {
  await fs.writeFile(pathname, source, { flag: "wx", mode: 0o700 });
}

async function writeJson(pathname, value) {
  await fs.writeFile(pathname, `${JSON.stringify(value, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

async function replaceJson(pathname, value) {
  const replacement = `${pathname}.replacement-${randomBytes(8).toString("hex")}`;
  try {
    await writeJson(replacement, value);
    await fs.rename(replacement, pathname);
  } finally {
    await fs.unlink(replacement).catch((error) => {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    });
  }
}

async function regularFilesUnder(directory) {
  const files = [];
  const visit = async (current) => {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const pathname = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error("test-owned persistence tree unexpectedly contains a symlink");
      }
      if (entry.isDirectory()) {
        await visit(pathname);
      } else if (entry.isFile()) {
        files.push(pathname);
      }
    }
  };
  await visit(directory);
  return files;
}

async function pathExists(pathname) {
  try {
    await fs.lstat(pathname);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function privateFileFact(pathname, label) {
  const metadata = await fs.lstat(pathname);
  const parent = await fs.lstat(path.dirname(pathname));
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file`);
  }
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077) !== 0) {
    throw new Error(`${label} is not inside a private directory`);
  }
  if ((metadata.mode & 0o077) !== 0 || metadata.nlink !== 1) {
    throw new Error(`${label} is not private and independently owned`);
  }
  const bytes = await fs.readFile(pathname);
  if (
    bytes.length === 0 ||
    bytes.length > 64 * 1024 ||
    bytes.some((byte) => byte <= 0x20 || byte === 0x7f)
  ) {
    throw new Error(`${label} is not a bounded bearer credential`);
  }
  return {
    pathname,
    bytes,
    digest: sha256(bytes),
    dev: metadata.dev,
    ino: metadata.ino,
    nlink: metadata.nlink,
    mode: metadata.mode & 0o777,
  };
}

async function bootstrapSeedCreationFact(pathname, label) {
  const metadata = await fs.lstat(pathname);
  const parent = await fs.lstat(path.dirname(pathname));
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file`);
  }
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077) !== 0) {
    throw new Error(`${label} is not inside a private directory`);
  }
  if ((metadata.mode & 0o077) !== 0 || ![1, 2].includes(metadata.nlink)) {
    throw new Error(`${label} is not a private create-new seed candidate`);
  }
  if (metadata.nlink === 2) {
    const siblings = [];
    for (const candidate of await regularFilesUnder(path.dirname(pathname))) {
      const fact = await fs.lstat(candidate);
      if (fact.dev === metadata.dev && fact.ino === metadata.ino) siblings.push(candidate);
    }
    if (
      siblings.length !== 2 ||
      !siblings.includes(pathname) ||
      !siblings.some((candidate) => path.basename(candidate).endsWith(".zode-server-pending"))
    ) {
      throw new Error(`${label} hard-link claim was not the bounded create-new pending file`);
    }
  }
  const bytes = await fs.readFile(pathname);
  if (
    bytes.length === 0 ||
    bytes.length > 64 * 1024 ||
    bytes.some((byte) => byte <= 0x20 || byte === 0x7f)
  ) {
    throw new Error(`${label} is not a bounded bearer credential`);
  }
  return {
    pathname,
    bytes,
    digest: sha256(bytes),
    dev: metadata.dev,
    ino: metadata.ino,
    nlink: metadata.nlink,
    mode: metadata.mode & 0o777,
  };
}

function assertIndependentCopies(left, right, label) {
  if (!left.bytes.equals(right.bytes)) {
    throw new Error(`${label} did not contain identical controller authority bytes`);
  }
  if (
    path.resolve(left.pathname) === path.resolve(right.pathname) ||
    (left.dev === right.dev && left.ino === right.ino)
  ) {
    throw new Error(`${label} reused one file instead of two independent copies`);
  }
}

function assertIndependentFiles(left, right, label) {
  if (
    path.resolve(left.pathname) === path.resolve(right.pathname) ||
    (left.dev === right.dev && left.ino === right.ino)
  ) {
    throw new Error(`${label} reused one file instead of two independent stores`);
  }
}

async function privateOpaqueFileFact(pathname, label) {
  const metadata = await fs.lstat(pathname);
  const parent = await fs.lstat(path.dirname(pathname));
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file`);
  }
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077) !== 0) {
    throw new Error(`${label} is not inside a private directory`);
  }
  if ((metadata.mode & 0o077) !== 0 || metadata.nlink !== 1) {
    throw new Error(`${label} is not private and independently owned`);
  }
  const bytes = await fs.readFile(pathname);
  if (bytes.length === 0 || bytes.length > 128 * 1024) {
    throw new Error(`${label} is not a bounded protected value`);
  }
  return {
    pathname,
    bytes,
    digest: sha256(bytes),
    dev: metadata.dev,
    ino: metadata.ino,
    nlink: metadata.nlink,
    mode: metadata.mode & 0o777,
  };
}

async function oneEncryptedAuthorityFile(directory, plaintext, label) {
  const files = await regularFilesUnder(directory);
  if (files.length !== 1) {
    throw new Error(`${label} had ${files.length} protected files, expected one`);
  }
  const fact = await privateOpaqueFileFact(files[0], label);
  const magic = Buffer.from("zode.server-secret.v1\0", "utf8");
  if (!fact.bytes.subarray(0, magic.length).equals(magic) || fact.bytes.includes(plaintext)) {
    throw new Error(`${label} did not retain one encrypted-at-rest controller authority`);
  }
  return fact;
}

async function matchingPrivateFiles(directory, expectedBytes) {
  const matches = [];
  for (const pathname of await regularFilesUnder(directory)) {
    const metadata = await fs.lstat(pathname);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.size !== expectedBytes.length
    ) {
      continue;
    }
    const bytes = await fs.readFile(pathname);
    if (bytes.equals(expectedBytes)) {
      matches.push(await privateFileFact(pathname, "controller authority copy"));
    }
  }
  return matches;
}

async function oneMatchingPrivateFile(directory, expectedBytes, label) {
  const matches = await matchingPrivateFiles(directory, expectedBytes);
  if (matches.length !== 1) {
    throw new Error(`${label} had ${matches.length} matching private copies, expected one`);
  }
  return matches[0];
}

async function storeFamilyBytes(directory, basenamePrefix) {
  const files = (await regularFilesUnder(directory))
    .filter((pathname) => path.basename(pathname).startsWith(basenamePrefix))
    .sort();
  if (files.length === 0) {
    throw new Error(`${basenamePrefix} store family was not created`);
  }
  return Promise.all(files.map((pathname) => fs.readFile(pathname)));
}

async function assertBinary(pathname, label) {
  const metadata = await fs.stat(pathname).catch(() => null);
  if (!metadata?.isFile()) {
    throw new Error(`${label} binary is missing at ${pathname}`);
  }
}

class ReadyProcess {
  static launch(binary, args, { env = process.env } = {}) {
    const child = spawn(binary, args, {
      cwd: repositoryRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return new ReadyProcess(child, binary);
  }

  static async start(binary, args, prefix, options = {}) {
    const managed = ReadyProcess.launch(binary, args, options);
    try {
      managed.readyValue = await managed.waitForLine(prefix);
      return managed;
    } catch (error) {
      await managed.stop().catch(() => {});
      throw error;
    }
  }

  constructor(child, binary) {
    this.child = child;
    this.binary = binary;
    this.readyValue = null;
    this.stdout = "";
    this.stderr = "";
    this.stopObservation = null;
    child.stdout.on("data", (chunk) => {
      this.stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      this.stderr += chunk.toString("utf8");
    });
    this.exit = new Promise((resolve) => {
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
  }

  async waitForLine(prefix, onMatched = null) {
    const lines = createInterface({ input: this.child.stdout });
    try {
      const value = await withTimeout(
        new Promise((resolve, reject) => {
          const onLine = (line) => {
            if (line.startsWith(prefix)) {
              const matched = line.slice(prefix.length).trim();
              try {
                onMatched?.(matched);
                cleanup();
                resolve(matched);
              } catch (error) {
                cleanup();
                reject(error);
              }
            }
          };
          const onError = (error) => {
            cleanup();
            reject(new Error(`${path.basename(this.binary)} failed to spawn`, { cause: error }));
          };
          const onExit = ({ code, signal }) => {
            cleanup();
            reject(
              new Error(
                `${path.basename(this.binary)} exited before readiness (code=${code}, signal=${signal})`,
              ),
            );
          };
          const cleanup = () => {
            lines.off("line", onLine);
            this.child.off("error", onError);
          };
          lines.on("line", onLine);
          this.child.once("error", onError);
          this.exit.then(onExit);
        }),
        READY_TIMEOUT_MS,
        `${path.basename(this.binary)} readiness`,
      );
      if (!value) {
        throw new Error(`${path.basename(this.binary)} emitted an empty readiness value`);
      }
      return value;
    } finally {
      lines.close();
    }
  }

  async waitForExit(label) {
    return withTimeout(this.exit, READY_TIMEOUT_MS, label);
  }

  assertOutputSecretFree(secrets) {
    const output = `${this.stdout}\n${this.stderr}`;
    for (const secret of secrets) {
      if (secret && output.includes(secret)) {
        throw new Error(`${path.basename(this.binary)} output exposed a test secret`);
      }
    }
    if (/eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(output)) {
      throw new Error(`${path.basename(this.binary)} output exposed an Access assertion`);
    }
  }

  async stop() {
    if (this.child.exitCode != null || this.child.signalCode != null) {
      const result = await this.exit;
      this.stopObservation ??= {
        forcedSigkill: false,
        result,
      };
      return;
    }
    this.child.kill("SIGTERM");
    try {
      const result = await withTimeout(
        this.exit,
        STOP_TIMEOUT_MS,
        `${path.basename(this.binary)} shutdown`,
      );
      this.stopObservation = { forcedSigkill: false, result };
    } catch {
      this.child.kill("SIGKILL");
      const result = await withTimeout(
        this.exit,
        STOP_TIMEOUT_MS,
        `${path.basename(this.binary)} reap`,
      );
      this.stopObservation = { forcedSigkill: true, result };
    }
  }
}

class IncidentRecorder {
  static async create() {
    let cassette = null;
    let source = null;
    try {
      const bytes = await fs.readFile(trackedIncidentPath);
      source = bytes.toString("utf8");
      cassette = JSON.parse(source);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
    if (cassette) {
      assertTrackedIncident(cassette, source);
    }
    return new IncidentRecorder(cassette);
  }

  constructor(cassette) {
    this.cassette = cassette;
    this.expectRecordedBlocked =
      process.env.ZODE_UI_EXPECT_RECORDED_BLOCKED === "1";
    this.consumed = 0;
    this.firstFailure = null;
    this.replayed = null;
    this.publicResponseBodies = [];
    this.semanticCandidates = new Map();
  }

  async observe(observed) {
    this.publicResponseBodies.push(
      Buffer.concat(observed.response_chunks.map((chunk) => chunk.body)).toString("utf8"),
    );
    const exchangeKey = `${observed.method} ${observed.path}`;
    if (exchangeKey === "GET /v1/system" || exchangeKey === "GET /v1/endpoints") {
      this.semanticCandidates.set(exchangeKey, observed);
    }
    const exchange = this.cassette?.exchanges[0] ?? null;
    const matchesCassette =
      exchange &&
      exchange.request.method === observed.method &&
      exchange.request.path === observed.path;

    if (matchesCassette) {
      const requestHeaders = headersFrom(observed.forwarded_headers, SAFE_REQUEST_HEADERS);
      requestHeaders["cf-access-jwt-assertion"] = "<ACCESS_ASSERTION_RS256>";
      assertExact(observed.method, exchange.request.method, "incident request method");
      assertExact(observed.path, exchange.request.path, "incident request path");
      assertExact(exactJson(requestHeaders), exactJson(exchange.request.headers), "incident headers");
      assertExact(
        observed.request_body.toString("base64"),
        exchange.request.body_base64,
        "incident request body",
      );
      assertExact(sha256(observed.request_body), exchange.request.body_sha256, "incident body digest");
      this.consumed += 1;
      if (this.consumed !== 1) {
        throw new Error("all_in_one_first_run cassette was consumed more than once");
      }
      if (this.expectRecordedBlocked) {
        const body = Buffer.concat(observed.response_chunks.map((chunk) => chunk.body));
        assertExact(observed.status, exchange.response.status, "recorded blocked response status");
        assertExact(
          observed.outcome,
          exchange.response.outcome,
          "recorded blocked response outcome",
        );
        assertExact(
          sha256(body),
          exchange.response.body_sha256,
          "recorded blocked response digest",
        );
        assertExact(
          exactJson(headersFrom(observed.response_headers, SAFE_RESPONSE_HEADERS)),
          exactJson(exchange.response.headers),
          "recorded blocked response headers",
        );
        assertExact(
          exactJson(observed.response_chunks.map((chunk) => chunk.body.toString("base64"))),
          exactJson(exchange.response.chunks.map((chunk) => chunk.body_base64)),
          "recorded blocked response chunks",
        );
      }
      this.replayed = {
        method: observed.method,
        path: observed.path,
        status: observed.status,
        outcome: observed.outcome,
      };
      return;
    }

    const isDocument =
      observed.path === "/" && observed.inbound_headers["sec-fetch-dest"] === "document";
    const relevantFailure = observed.status >= 400 && (isDocument || observed.path.startsWith("/v1/"));
    if (relevantFailure && !this.firstFailure) {
      this.firstFailure = await this.flushRaw(observed);
    }
  }

  async retainSemanticFailure(method, requestPath, safeError) {
    if (this.firstFailure) {
      return this.firstFailure;
    }
    const observed = this.semanticCandidates.get(`${method} ${requestPath}`);
    if (!observed) {
      throw new Error(`cannot retain unobserved semantic failure ${method} ${requestPath}`);
    }
    this.firstFailure = await this.flushRaw(observed, safeError);
    return this.firstFailure;
  }

  async flushRaw(observed, safeError = null) {
    const runId = `${Date.now()}-${process.pid}-${sha256(Buffer.from(String(process.hrtime.bigint()))).slice(0, 12)}`;
    const directory = path.join(
      repositoryRoot,
      "target",
      "test-recordings",
      "quarantine",
      `all_in_one_first_run-${runId}`,
    );
    await fs.mkdir(directory, { recursive: false, mode: 0o700 });
    const pathname = path.join(directory, "all_in_one_first_run_first_failure.raw.json");
    const responseBody = Buffer.concat(observed.response_chunks.map((chunk) => chunk.body));
    const raw = {
      schema: "zode.http-incident-raw.v1",
      owner_e2e: E2E,
      boundary: "browser_access_edge_management_http",
      ...(safeError ? { safe_error: safeError } : {}),
      captured_at_ms: Date.now(),
      request: {
        method: observed.method,
        path: observed.path,
        inbound_headers: observed.inbound_headers,
        forwarded_headers: observed.forwarded_headers,
        body_base64: observed.request_body.toString("base64"),
        body_sha256: sha256(observed.request_body),
      },
      response: {
        status: observed.status,
        headers: observed.response_headers,
        chunks: observed.response_chunks.map((chunk) => ({
          offset_us: chunk.offset_us,
          body_base64: chunk.body.toString("base64"),
        })),
        body_sha256: sha256(responseBody),
        outcome: observed.outcome,
      },
    };
    await fs.writeFile(pathname, `${JSON.stringify(raw, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    return {
      pathname,
      method: observed.method,
      path: observed.path,
      status: observed.status,
      safeError,
    };
  }

  assertComplete() {
    if (this.cassette && this.consumed !== 1) {
      throw new Error(`all_in_one_first_run cassette consumption was ${this.consumed}, expected 1`);
    }
  }

  failureSummary() {
    if (this.firstFailure) {
      const failure = this.firstFailure;
      return `${failure.method} ${failure.path} -> ${failure.status}${failure.safeError ? ` (${failure.safeError})` : ""}; quarantine=${failure.pathname}`;
    }
    if (this.replayed) {
      return `cassette replay ${this.replayed.method} ${this.replayed.path} -> ${this.replayed.status} (${this.replayed.outcome})`;
    }
    return null;
  }
}

async function writePrivateDurableJson(pathname, value) {
  const handle = await fs.open(pathname, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const directory = await fs.open(path.dirname(pathname), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

class LaterGapCapture {
  static async create() {
    if (!CAPTURE_LATER_GAP) {
      return null;
    }
    const quarantine = path.join(
      repositoryRoot,
      "target",
      "test-recordings",
      "quarantine",
      "management-browser-reconnect-later",
    );
    await fs.mkdir(quarantine, { recursive: true, mode: 0o700 });
    await fs.chmod(quarantine, 0o700);
    const root = await fs.mkdtemp(path.join(quarantine, "run-"));
    await fs.chmod(root, 0o700);
    const ledger = new SecretLedger();
    return new LaterGapCapture(root, ledger, new RecordingJournal({ rootDir: root, ledger }));
  }

  constructor(root, ledger, journal) {
    this.root = root;
    this.ledger = ledger;
    this.journal = journal;
    this.captureSetId = null;
    this.firstFailure = null;
    this.lastRecord = null;
    this.accessAssertionSequence = 0;
    this.flushed = null;
    this.activeRecordings = new Set();
  }

  addSecret(label, value) {
    this.ledger.add(label, value);
  }

  addAccessAssertion(value) {
    this.accessAssertionSequence += 1;
    this.ledger.add(`access_assertion_${this.accessAssertionSequence}`, value);
  }

  arm() {
    if (this.captureSetId) {
      throw new Error("later gap capture was armed more than once");
    }
    this.captureSetId = this.journal.beginCaptureSet({ e2eName: E2E, maxMembers: 64 });
  }

  begin(request, { reconnect = false } = {}) {
    if (!this.captureSetId) {
      return null;
    }
    const recording = this.journal.beginIngress({
      boundary: "management-access-edge",
      method: request.method,
      requestPath: request.url,
      requestHeaders: request.headers,
      captureSetId: this.captureSetId,
    });
    recording.laterGapReconnect = reconnect;
    this.activeRecordings.add(recording);
    return recording;
  }

  ingressChunk(recording, chunk) {
    if (recording) {
      this.journal.ingressChunk(recording, chunk);
    }
  }

  endIngress(recording) {
    return recording ? this.journal.endIngress(recording) : null;
  }

  updateHeaders(recording, headers) {
    if (recording) {
      this.journal.updateIngressHeaders(recording, headers);
    }
  }

  responseStarted(recording, status, headers) {
    if (recording) {
      this.journal.responseStarted(recording, { status, headers });
    }
  }

  chunk(recording, bytes, offsetUs) {
    if (recording) {
      this.journal.chunk(recording, bytes, offsetUs);
    }
  }

  finish(recording, outcome) {
    if (!recording) {
      return null;
    }
    if (recording.responseStatus === undefined && outcome === "client_disconnected") {
      this.journal.responseStarted(recording, { status: 499, headers: {} });
    }
    const record = this.journal.finish(recording, outcome);
    this.activeRecordings.delete(recording);
    this.lastRecord = record;
    if (recording.laterGapReconnect) {
      this.firstFailure = record;
    }
    return record;
  }

  finishReconnectsAfterBrowserContextClose() {
    for (const recording of [...this.activeRecordings]) {
      if (recording.laterGapReconnect) {
        this.finish(recording, "client_disconnected");
      }
    }
  }

  async flushFailure({ classification, firstObserved } = {}) {
    if (this.flushed) {
      return this.flushed;
    }
    const failure = this.firstFailure ?? this.lastRecord;
    if (!this.captureSetId || !failure) {
      throw new Error("later gap capture did not retain a public exchange before failure");
    }
    const reconnect = this.firstFailure !== null;
    const safeClassification = reconnect
      ? RECONNECT_FAILURE
      : classification ?? "MANAGEMENT_BROWSER_PRE_RECONNECT_FAILURE";
    const safeFirstObserved = reconnect
      ? {
          expected_connection_state: "Live",
          observed_connection_state: "Reconnecting",
          durable_assistant_reply_count: 1,
        }
      : firstObserved ?? "the real browser suite stopped before the SSE reconnect assertion";
    await this.journal.waitForIdle();
    const capture = this.journal.flushCaptureSet(this.captureSetId, {
      firstFailureRecordingId: failure.recordingId,
    });
    const metadataPath = path.join(this.root, "later-reproduction.v1.json");
    await writePrivateDurableJson(metadataPath, {
      schema: "zode.evidence-gap-later-reproduction.v1",
      version: 1,
      owning_e2e: E2E,
      recording_id: this.captureSetId,
      relation: LATER_GAP_RELATION,
      original_evidence_gap:
        "target/test-recordings/quarantine/local-evidence-gaps/all-in-one-sse-live-and-child-reap-first-run-evidence-gap.v1.json",
      classification: safeClassification,
      first_failure_recording_id: failure.recordingId,
      first_observed: safeFirstObserved,
      raw_exchange_retained: true,
      source_digest: capture.sourceDigest,
      do_not_relabel_as_first: true,
    });
    this.flushed = {
      root: this.root,
      metadataPath,
      captureSetId: this.captureSetId,
      firstFailureRecordingId: failure.recordingId,
    };
    return this.flushed;
  }
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function accessAssertion({ privateKey, kid, issuer, audience, subject }) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", kid, typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({
      iss: issuer,
      aud: [audience],
      type: "app",
      sub: subject,
      iat: now,
      nbf: now - 1,
      exp: now + 300,
    }),
  );
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url")}`;
}

function forwardedHeaders(headers, assertion) {
  const result = { ...headers };
  delete result.connection;
  delete result["proxy-authorization"];
  delete result["transfer-encoding"];
  result["cf-access-jwt-assertion"] = assertion;
  return result;
}

function responseHeaders(headers) {
  const result = { ...headers };
  delete result.connection;
  delete result["keep-alive"];
  delete result["transfer-encoding"];
  return result;
}

function proxyRequestHeaders(headers, targetHost) {
  const result = { ...headers };
  delete result.connection;
  delete result.host;
  delete result["proxy-authorization"];
  delete result["proxy-connection"];
  delete result["transfer-encoding"];
  result.host = targetHost;
  return result;
}

function requireExactObjectKeys(value, expected, label) {
  if (
    !value ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    exactJson(Object.keys(value).sort()) !== exactJson([...expected].sort())
  ) {
    throw new Error(`${label} did not have the exact public keys`);
  }
}

class EndpointProbeWire {
  static async start(endpointOrigin, activeAuthorityBytes, beforeCapabilityResponse) {
    const wire = new EndpointProbeWire(
      endpointOrigin,
      activeAuthorityBytes,
      beforeCapabilityResponse,
    );
    wire.server = http.createServer((request, response) => {
      wire.handle(request, response).catch((error) => {
        wire.fail(error);
        if (!response.headersSent) {
          response.writeHead(502, { "content-type": "text/plain" });
        }
        if (!response.destroyed) {
          response.end("test Endpoint probe wire failure");
        }
      });
    });
    wire.origin = await listenLoopback(wire.server);
    return wire;
  }

  constructor(endpointOrigin, activeAuthorityBytes, beforeCapabilityResponse) {
    this.endpointOrigin = new URL(endpointOrigin).origin;
    this.activeAuthorityBytes = Buffer.from(activeAuthorityBytes);
    this.expectedAuthorization = Buffer.concat([
      Buffer.from("Bearer "),
      this.activeAuthorityBytes,
    ]);
    this.beforeCapabilityResponse = beforeCapabilityResponse;
    this.origin = null;
    this.server = null;
    this.pending = 0;
    this.pendingFinite = 0;
    this.idleWaiters = [];
    this.errors = [];
    this.exchanges = new Map();
    this.probeSourcePids = new Map();
    this.expectedServerPid = null;
    this.startupObservationComplete = false;
    this.completeSettled = false;
    this.complete = new Promise((resolve, reject) => {
      this.resolveComplete = resolve;
      this.rejectComplete = reject;
    });
    void this.complete.catch(() => {});
  }

  processEnvironment(source) {
    const env = { ...source };
    for (const name of [
      "ALL_PROXY",
      "all_proxy",
      "HTTP_PROXY",
      "http_proxy",
      "HTTPS_PROXY",
      "https_proxy",
      "NO_PROXY",
      "no_proxy",
      "REQUEST_METHOD",
    ]) {
      delete env[name];
    }
    env.HTTP_PROXY = this.origin;
    env.http_proxy = this.origin;
    env.NO_PROXY = "";
    env.no_proxy = "";
    return env;
  }

  setExpectedServerPid(pid) {
    if (!Number.isSafeInteger(pid) || this.expectedServerPid != null) {
      throw new HarnessBarrierError("Endpoint probe wire received an invalid Server PID");
    }
    this.expectedServerPid = pid;
  }

  fail(error) {
    this.errors.push(error);
    if (!this.completeSettled) {
      this.completeSettled = true;
      this.rejectComplete(error);
    }
  }

  settleRequest() {
    this.pending -= 1;
    if (this.pending === 0) {
      for (const resolve of this.idleWaiters.splice(0)) {
        resolve();
      }
    }
  }

  async waitForIdle() {
    if (this.pendingFinite === 0) {
      return;
    }
    await withTimeout(
      new Promise((resolve) => this.idleWaiters.push(resolve)),
      STOP_TIMEOUT_MS,
      "Endpoint probe wire idle barrier",
    );
  }

  async handle(request, response) {
    this.pending += 1;
    try {
      const target = new URL(request.url);
      if (target.protocol !== "http:") {
        throw new Error("Endpoint probe wire received a non-HTTP target");
      }
      const requestBody = await readBounded(request);
      const probePath =
        !this.startupObservationComplete &&
        target.origin === this.endpointOrigin &&
        (target.pathname === "/v1/identity" ||
          target.pathname === "/v1/capabilities") &&
        target.search === ""
          ? target.pathname
          : null;
      if (probePath) {
        this.validateProbeRequest(request, requestBody, probePath);
        await assertTcpClientOwnedByProcess(
          request.socket,
          this.expectedServerPid,
          `${probePath} probe connection`,
        );
        this.probeSourcePids.set(probePath, this.expectedServerPid);
      }
      await this.forward({ request, response, requestBody, target, probePath });
    } finally {
      this.settleRequest();
    }
  }

  validateProbeRequest(request, requestBody, probePath) {
    if (
      request.method !== "GET" ||
      requestBody.length !== 0 ||
      typeof request.headers.authorization !== "string" ||
      !Buffer.from(request.headers.authorization).equals(this.expectedAuthorization)
    ) {
      throw new Error(
        `${probePath} was not an empty authenticated GET using the active controller authority`,
      );
    }
    if (this.exchanges.has(probePath)) {
      throw new Error(`${probePath} was probed more than once during one Server startup`);
    }
    if (probePath === "/v1/capabilities" && !this.exchanges.has("/v1/identity")) {
      throw new Error("Server probed Endpoint capabilities before identity");
    }
  }

  async forward({ request, response, requestBody, target, probePath }) {
    await new Promise((resolve, reject) => {
      const upstream = http.request(target, {
        method: request.method,
        headers: proxyRequestHeaders(request.headers, target.host),
      });
      upstream.once("error", reject);
      upstream.once("response", (upstreamResponse) => {
        if (probePath) {
          this.forwardProbeResponse({
            request,
            response,
            requestBody,
            target,
            probePath,
            upstreamResponse,
          }).then(resolve, reject);
          return;
        }

        response.writeHead(
          upstreamResponse.statusCode ?? 502,
          responseHeaders(upstreamResponse.headers),
        );
        let settled = false;
        const finish = (error = null) => {
          if (settled) {
            return;
          }
          settled = true;
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        };
        response.once("close", () => {
          if (!settled) {
            upstreamResponse.destroy();
            finish();
          }
        });
        upstreamResponse.on("data", (chunk) => {
          if (!response.destroyed) {
            response.write(chunk);
          }
        });
        upstreamResponse.once("end", () => {
          if (!response.destroyed) {
            response.end();
          }
          finish();
        });
        upstreamResponse.once("error", finish);
      });
      if (requestBody.length > 0) {
        upstream.write(requestBody);
      }
      upstream.end();
    });
  }

  async forwardProbeResponse({
    request,
    response,
    requestBody,
    target,
    probePath,
    upstreamResponse,
  }) {
    const body = await readBounded(upstreamResponse);
    const status = upstreamResponse.statusCode ?? 502;
    const contentType = Array.isArray(upstreamResponse.headers["content-type"])
      ? upstreamResponse.headers["content-type"].join(", ")
      : String(upstreamResponse.headers["content-type"] ?? "");
    if (status !== 200 || !contentType.toLowerCase().includes("application/json")) {
      throw new Error(`${probePath} did not return a complete JSON HTTP 200 response`);
    }
    if (body.includes(this.activeAuthorityBytes)) {
      throw new Error(`${probePath} response exposed the active controller credential`);
    }
    let json;
    try {
      json = JSON.parse(body.toString("utf8"));
    } catch {
      throw new Error(`${probePath} response was not JSON`);
    }
    if (probePath === "/v1/capabilities") {
      this.beforeCapabilityResponse();
    }
    this.validateProbeResponse(probePath, json);
    this.exchanges.set(probePath, {
      request: {
        method: request.method,
        origin: target.origin,
        path: probePath,
        authorization: "<ACTIVE_CONTROLLER_AUTHORITY>",
        source_server_pid: this.probeSourcePids.get(probePath),
        zode_subject_present: typeof request.headers["zode-subject"] === "string",
        body_sha256: sha256(requestBody),
      },
      response: {
        status,
        content_type: contentType,
        body_sha256: sha256(body),
        json,
      },
    });
    if (
      this.exchanges.has("/v1/identity") &&
      this.exchanges.has("/v1/capabilities") &&
      !this.completeSettled
    ) {
      this.completeSettled = true;
      this.resolveComplete(this.safeEvidence());
    }
    response.writeHead(status, responseHeaders(upstreamResponse.headers));
    response.end(body);
  }

  validateProbeResponse(probePath, json) {
    if (probePath === "/v1/identity") {
      requireExactObjectKeys(
        json,
        ["authority_id", "endpoint_id", "protocol_version", "revision", "schema"],
        "Endpoint identity response",
      );
      if (
        json.schema !== "zode.identity.v1" ||
        json.protocol_version !== "zode.endpoint.v1" ||
        typeof json.endpoint_id !== "string" ||
        json.endpoint_id.length === 0 ||
        json.authority_id !== SERVER_AUTHORITY_ID ||
        json.revision !== 1
      ) {
        throw new Error("Endpoint identity response did not prove the active authority");
      }
      return;
    }

    const identity = this.exchanges.get("/v1/identity")?.response.json;
    requireExactObjectKeys(
      json,
      [
        "auth_replica_credential_schemas",
        "built_in_tools",
        "endpoint_id",
        "limits",
        "outbound_capabilities",
        "protocol_version",
        "provider_adapter_kinds",
        "schema",
        "tools",
      ],
      "Endpoint capabilities response",
    );
    requireExactObjectKeys(
      json.limits,
      [
        "max_auth_replica_request_bytes",
        "max_inline_tool_output_bytes",
        "max_session_request_bytes",
        "wait_for_default_seconds",
        "wait_for_max_seconds",
        "wait_for_min_seconds",
      ],
      "Endpoint capability limits",
    );
    if (
      json.schema !== "zode.endpoint-capabilities.v1" ||
      json.protocol_version !== "zode.endpoint.v1" ||
      json.endpoint_id !== identity.endpoint_id ||
      exactJson(json.provider_adapter_kinds) !== exactJson(["openai_compatible"]) ||
      exactJson(json.auth_replica_credential_schemas) !==
        exactJson(["openai-compatible.api-key.v1"]) ||
      exactJson(json.outbound_capabilities) !== exactJson(["provider_http", "tool_http"]) ||
      exactJson(json.built_in_tools) !== exactJson(["wait_for"]) ||
      exactJson(json.tools) !==
        exactJson([{ name: SAME_START_CAPABILITY_TOOL, completion_mode: "response" }]) ||
      exactJson(json.limits) !==
        exactJson({
          max_session_request_bytes: 262144,
          max_auth_replica_request_bytes: 131072,
          max_inline_tool_output_bytes: 65536,
          wait_for_min_seconds: 1,
          wait_for_default_seconds: 60,
          wait_for_max_seconds: 600,
        })
    ) {
      throw new Error("Endpoint capabilities response did not match the active composition");
    }
  }

  catalogMarkers() {
    const identity = this.exchanges.get("/v1/identity")?.response.json;
    const capabilities = this.exchanges.get("/v1/capabilities")?.response.json;
    if (!identity || !capabilities) {
      return [];
    }
    return [
      identity.endpoint_id,
      SERVER_AUTHORITY_ID,
      "zode.endpoint.v1",
      this.endpointOrigin,
      SAME_START_CAPABILITY_TOOL,
    ];
  }

  safeEvidence() {
    return ["/v1/identity", "/v1/capabilities"].map((probePath) =>
      structuredClone(this.exchanges.get(probePath)),
    );
  }

  async waitForComplete(process) {
    return withTimeout(
      Promise.race([
        this.complete,
        process.exit.then(({ code, signal }) => {
          throw new Error(
            `${path.basename(process.binary)} exited before authenticated Endpoint probes completed (code=${code}, signal=${signal})`,
          );
        }),
      ]),
      READY_TIMEOUT_MS,
      "authenticated Endpoint identity/capability wire barrier",
    );
  }

  assertComplete() {
    if (this.errors.length > 0 || this.exchanges.size !== 2) {
      throw new Error("Endpoint probe wire did not consume exactly two valid exchanges");
    }
  }

  finishStartupObservation() {
    this.assertComplete();
    this.startupObservationComplete = true;
  }

  async stop() {
    const errors = [];
    try {
      await this.waitForIdle();
    } catch (error) {
      errors.push(error);
    }
    try {
      await closeHttpServer(this.server);
    } catch (error) {
      errors.push(error);
    }
    try {
      this.assertComplete();
    } catch (error) {
      errors.push(error);
    }
    this.expectedAuthorization.fill(0);
    this.activeAuthorityBytes.fill(0);
    if (errors.length > 0) {
      throw new Error("Endpoint probe wire cleanup/evidence gate failed", {
        cause: errors[0],
      });
    }
  }
}

class AccessEdge {
  static async start(recorder, laterGapCapture = null) {
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { format: "pem", type: "spki" },
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
    });
    const edge = new AccessEdge(recorder, laterGapCapture, pair.privateKey, pair.publicKey);
    edge.server = http.createServer((request, response) => {
      edge.handle(request, response).catch((error) => {
        edge.errors.push(error);
        if (!response.headersSent) {
          response.writeHead(502, { "content-type": "text/plain" });
        }
        if (!response.destroyed) {
          response.end("test access edge failure");
        }
      });
    });
    edge.baseUrl = await listenLoopback(edge.server);
    edge.issuer = edge.baseUrl;
    return edge;
  }

  constructor(recorder, laterGapCapture, privateKey, publicKey) {
    this.recorder = recorder;
    this.laterGapCapture = laterGapCapture;
    this.privateKey = createPrivateKey(privateKey);
    this.publicKey = createPublicKey(publicKey);
    this.kid = "all-in-one-first-run-rs256";
    this.audience = "all-in-one-first-run-audience";
    this.subject = "all-in-one-first-run-human";
    this.target = null;
    this.baseUrl = null;
    this.issuer = null;
    this.server = null;
    this.pending = 0;
    this.pendingFinite = 0;
    this.idleWaiters = [];
    this.errors = [];
    this.lastAssertion = null;
    this.jwksRequests = 0;
    this.activeSse = null;
    this.sseStreams = new Set();
    this.sseFinalText = null;
    this.droppedFinalEventId = null;
    this.sseDropped = false;
    this.sseDropPromise = null;
    this.sseReconnectPromise = null;
    this.resolveSseDrop = null;
    this.resolveSseReconnect = null;
    this.sseChunkWaiters = [];
  }

  setTarget(baseUrl) {
    this.target = new URL(baseUrl);
  }

  armSseDrop(finalText) {
    if (this.sseDropPromise) {
      throw new Error("SSE disconnect barrier was already armed");
    }
    this.sseFinalText = finalText;
    this.sseDropPromise = new Promise((resolve) => {
      this.resolveSseDrop = resolve;
    });
    this.sseReconnectPromise = new Promise((resolve) => {
      this.resolveSseReconnect = resolve;
    });
  }

  finalSseFrames() {
    if (!this.activeSse) return [];
    return Buffer.concat(this.activeSse.chunks.map((chunk) => chunk.body))
      .toString("utf8")
      .split(/\r?\n\r?\n/)
      .filter(
        (frame) =>
          frame.includes(this.sseFinalText) &&
          (/^event:\s*assistant_message_committed\s*$/m.test(frame) ||
            /"kind"\s*:\s*"assistant_message_committed"/.test(frame)),
      );
  }

  async dropSseAfterBrowserBarrier() {
    if (!this.sseDropPromise || !this.activeSse) {
      throw new Error("no active proxied SSE stream was available for the disconnect barrier");
    }
    if (this.sseDropped) {
      throw new Error("proxied SSE stream was already disconnected");
    }
    const frames = await withTimeout(
      new Promise((resolve, reject) => {
        const inspect = () => {
          const observed = this.finalSseFrames();
          if (observed.length === 1) {
            resolve(observed);
            return;
          }
          if (observed.length > 1) {
            reject(new Error(
              `proxied SSE contained ${observed.length} frames for the durable final, expected one`,
            ));
            return;
          }
          this.sseChunkWaiters.push(inspect);
        };
        inspect();
      }),
      20_000,
      "proxied SSE durable-final observation barrier",
    );
    if (frames.length !== 1) {
      throw new Error(
        `proxied SSE contained ${frames.length} frames for the durable final, expected one`,
      );
    }
    const eventId = /^id:\s*(\S+)\s*$/m.exec(frames[0])?.[1] ?? null;
    if (!eventId) {
      throw new Error("durable final SSE frame omitted its Endpoint event ID");
    }
    this.droppedFinalEventId = eventId;
    this.sseDropped = true;
    const active = this.activeSse;
    void (async () => {
      try {
        await active.finish("disconnected");
      } catch (error) {
        this.errors.push(error);
      } finally {
        active.response.destroy();
        active.upstream.destroy();
        this.resolveSseDrop?.();
      }
    })();
  }

  async waitForSseDrop() {
    await withTimeout(this.sseDropPromise, 20_000, "proxied SSE disconnect barrier");
  }

  async waitForSseReconnect() {
    await withTimeout(this.sseReconnectPromise, 20_000, "proxied SSE reconnect barrier");
  }

  async finishActiveSseAfterBrowserContextClose() {
    const active = [...this.sseStreams];
    for (const stream of active) {
      stream.upstream.pause();
      stream.upstream.removeAllListeners("data");
    }
    this.laterGapCapture?.finishReconnectsAfterBrowserContextClose();
    if (active.length === 0) {
      return;
    }
    await withTimeout(
      Promise.all(active.map((stream) => stream.finish("client_disconnected"))),
      STOP_TIMEOUT_MS,
      "reconnect SSE client-disconnect recording terminal",
    );
    for (const stream of active) {
      stream.response.destroy();
      stream.upstream.destroy();
    }
  }

  async waitForIdle() {
    if (this.pendingFinite === 0) {
      return;
    }
    await withTimeout(
      new Promise((resolve) => this.idleWaiters.push(resolve)),
      10_000,
      "Access edge idle barrier",
    );
  }

  settleRequest(isEventStream) {
    this.pending -= 1;
    if (!isEventStream) {
      this.pendingFinite -= 1;
    }
    if (this.pendingFinite === 0) {
      for (const resolve of this.idleWaiters.splice(0)) {
        resolve();
      }
    }
  }

  async handle(request, response) {
    if (request.url === "/cdn-cgi/access/certs") {
      this.jwksRequests += 1;
      const jwk = this.publicKey.export({ format: "jwk" });
      response.writeHead(200, { "cache-control": "no-store", "content-type": "application/json" });
      response.end(JSON.stringify({ keys: [{ ...jwk, kid: this.kid, alg: "RS256", use: "sig" }] }));
      return;
    }
    if (!this.target) {
      response.writeHead(503, { "content-type": "text/plain" });
      response.end("management target unavailable");
      return;
    }

    const isEventStream = new URL(request.url, "http://access-edge.invalid").pathname.endsWith(
      "/events",
    );
    this.pending += 1;
    if (!isEventStream) {
      this.pendingFinite += 1;
    }
    try {
      const reconnect =
        this.sseDropped &&
        isEventStream &&
        typeof request.headers["last-event-id"] === "string" &&
        request.headers["last-event-id"].length > 0;
      const recording = this.laterGapCapture?.begin(request, { reconnect }) ?? null;
      let body;
      try {
        body = await readBounded(request, (chunk) =>
          this.laterGapCapture?.ingressChunk(recording, chunk),
        );
        this.laterGapCapture?.endIngress(recording);
      } catch (error) {
        if (recording) {
          this.laterGapCapture.responseStarted(recording, 400, {
            "content-type": "application/json",
          });
          this.laterGapCapture.finish(recording, "transport_error");
        }
        throw error;
      }
      const assertion = accessAssertion({
        privateKey: this.privateKey,
        kid: this.kid,
        issuer: this.issuer,
        audience: this.audience,
        subject: this.subject,
      });
      this.lastAssertion = assertion;
      if (recording) {
        this.laterGapCapture.addAccessAssertion(assertion);
      }
      const target = new URL(request.url, this.target);
      const headers = forwardedHeaders(request.headers, assertion);
      this.laterGapCapture?.updateHeaders(recording, headers);
      if (reconnect) {
        if (request.headers["last-event-id"] !== this.droppedFinalEventId) {
          throw new Error("SSE reconnect cursor did not equal the durable final event ID");
        }
        this.resolveSseReconnect?.();
      }
      await this.proxy({
        request,
        response,
        body,
        target,
        headers,
        recording,
        isEventStream,
      });
    } finally {
      this.settleRequest(isEventStream);
    }
  }

  async proxy({ request, response, body, target, headers, recording, isEventStream }) {
    await new Promise((resolve, reject) => {
      const upstream = http.request(target, { method: request.method, headers });
      upstream.once("error", (error) => {
        if (recording && recording.responseStatus === undefined) {
          this.laterGapCapture.responseStarted(recording, 502, {
            "content-type": "application/json",
          });
          this.laterGapCapture.finish(recording, "transport_error");
        }
        reject(error);
      });
      upstream.once("response", (upstreamResponse) => {
        if (recording?.finished) {
          upstreamResponse.destroy();
          resolve();
          return;
        }
        const status = upstreamResponse.statusCode ?? 502;
        this.laterGapCapture?.responseStarted(recording, status, upstreamResponse.headers);
        response.writeHead(status, responseHeaders(upstreamResponse.headers));
        const chunks = [];
        const started = process.hrtime.bigint();
        let finished = false;
        let finishPromise = null;
        let streamState = null;
        const finish = (outcome) => {
          if (finishPromise) {
            return finishPromise;
          }
          finished = true;
          finishPromise = (async () => {
            if (this.activeSse?.upstream === upstreamResponse) {
              this.activeSse = null;
            }
            if (streamState) {
              this.sseStreams.delete(streamState);
            }
            this.laterGapCapture?.finish(recording, outcome);
            await this.recorder.observe({
              method: request.method,
              path: request.url,
              inbound_headers: request.headers,
              forwarded_headers: headers,
              request_body: body,
              status,
              response_headers: upstreamResponse.headers,
              response_chunks: chunks,
              outcome,
            });
          })();
          finishPromise.then(resolve, reject);
          return finishPromise;
        };
        if (isEventStream) {
          streamState = {
            response,
            upstream: upstreamResponse,
            finish,
            chunks,
          };
          this.activeSse = streamState;
          this.sseStreams.add(streamState);
        }
        response.once("close", () => {
          if (!finished) {
            void finish("client_disconnected").then(
              () => upstreamResponse.destroy(),
              () => upstreamResponse.destroy(),
            );
          }
        });
        upstreamResponse.on("data", (chunk) => {
          const bytes = Buffer.from(chunk);
          const offsetUs = Number((process.hrtime.bigint() - started) / 1_000n);
          this.laterGapCapture?.chunk(recording, bytes, offsetUs);
          chunks.push({
            offset_us: offsetUs,
            body: bytes,
          });
          for (const resolveChunk of this.sseChunkWaiters.splice(0)) {
            resolveChunk();
          }
          if (!response.destroyed) {
            response.write(bytes);
          }
        });
        upstreamResponse.once("end", () => {
          if (!response.destroyed) {
            response.end();
          }
          void finish("completed");
        });
        upstreamResponse.once("error", (error) => {
          if (!this.sseDropped && !finished) {
            reject(error);
          }
        });
      });
      if (body.length > 0) {
        upstream.write(body);
      }
      upstream.end();
    });
  }

  async stop() {
    const errors = [];
    try {
      await this.waitForIdle();
    } catch (error) {
      errors.push(error);
    }
    try {
      await closeHttpServer(this.server);
    } catch (error) {
      errors.push(error);
    }
    try {
      if (this.target) {
        this.recorder.assertComplete();
      }
    } catch (error) {
      errors.push(error);
    }
    if (this.errors.length > 0) {
      errors.push(new Error("test Access edge observed a proxy failure", { cause: this.errors[0] }));
    }
    if (errors.length > 0) {
      throw new Error("test Access edge cleanup/evidence gate failed", { cause: errors[0] });
    }
  }
}

class FakeProvider {
  static async start() {
    const requests = [];
    const server = http.createServer(async (request, response) => {
      const body = await readBounded(request);
      requests.push({ method: request.method, path: request.url, headers: request.headers, body });
      if (request.method !== "POST") {
        response.writeHead(404, { "content-type": "text/plain" });
        response.end("Not Found");
        return;
      }
      response.writeHead(200, {
        "cache-control": "no-cache",
        "content-type": "text/event-stream",
      });
      response.write(
        `data: ${JSON.stringify({
          id: "all-in-one-first-run-completion",
          object: "chat.completion.chunk",
          choices: [{ index: 0, delta: { content: FINAL_ASSISTANT }, finish_reason: null }],
        })}\n\n`,
      );
      response.write(
        `data: ${JSON.stringify({
          id: "all-in-one-first-run-completion",
          object: "chat.completion.chunk",
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        })}\n\n`,
      );
      response.end("data: [DONE]\n\n");
    });
    const origin = await listenLoopback(server);
    return new FakeProvider(server, origin, `${origin}/v1`, requests);
  }

  constructor(server, origin, baseUrl, requests) {
    this.server = server;
    this.origin = origin;
    this.baseUrl = baseUrl;
    this.requests = requests;
  }

  async stop() {
    await closeHttpServer(this.server);
  }
}

class ExternalRecordedProvider {
  static fromEnvironment() {
    const baseUrl = new URL(liveProviderBaseUrl);
    return new ExternalRecordedProvider(baseUrl.origin, baseUrl.toString().replace(/\/$/, ""));
  }

  constructor(origin, baseUrl) {
    this.origin = origin;
    this.baseUrl = baseUrl;
    this.requests = null;
  }

  async stop() {}
}

class Harness {
  static async start() {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "zode-all-in-one-ui-e2e-"));
    const recorder = await IncidentRecorder.create();
    const laterGapCapture = await LaterGapCapture.create();
    const provider = LIVE_PROVIDER
      ? ExternalRecordedProvider.fromEnvironment()
      : await FakeProvider.start();
    const edge = await AccessEdge.start(recorder, laterGapCapture);
    const harness = new Harness(root, recorder, provider, edge, laterGapCapture);
    try {
      await harness.startProcesses();
      await harness.assertIndependentEndpointChild();
      return harness;
    } catch (error) {
      let failure = error;
      try {
        await harness.stop();
      } catch (cleanupError) {
        failure = prioritizeGateFailure(
          error,
          cleanupError,
          "all-in-one bootstrap failure cleanup did not complete",
        );
      }
      if (error instanceof HarnessBarrierError) {
        throw new HarnessBarrierError(error.message.replace(/^HARNESS_FAILURE barrier=process_control: /, ""), failure);
      }
      if (harness.bootstrapStage !== "entry") {
        const cause = error instanceof Error ? error.message : String(error);
        throw new Error(
          `BEHAVIORAL_RED barrier=${harness.bootstrapStage}: all-in-one bootstrap crossed its public-entry prerequisite but failed before the complete readiness chain; cause=${cause}`,
          { cause: failure },
        );
      }
      throw shallowNonEvidence(
        BARRIERS.serverBootstrap,
        `requires=${BARRIERS.controllerSeed},${BARRIERS.childReady},${BARRIERS.activeAuthorityProbe},${BARRIERS.localCatalog},${BARRIERS.serverReady},${BARRIERS.endpointCapabilities}; real all-in-one Server did not cross authenticated local Endpoint composition and public readiness`,
        failure,
      );
    }
  }

  constructor(root, recorder, provider, edge, laterGapCapture) {
    this.root = root;
    this.recorder = recorder;
    this.provider = provider;
    this.edge = edge;
    this.laterGapCapture = laterGapCapture;
    this.server = null;
    this.preReadyBootstrapProcess = null;
    this.publicBindGate = null;
    this.endpointProbeWire = null;
    this.endpointProbeEvidence = null;
    this.scaffoldEndpoint = null;
    this.scaffoldCapture = false;
    this.endpointBinary = null;
    this.endpointConfiguredExecutable = null;
    this.serverBinary = null;
    this.endpointConfig = null;
    this.endpointConfigDocument = null;
    this.serverConfig = null;
    this.endpointListen = null;
    this.serverListen = null;
    this.endpointSeed = null;
    this.allInOneEndpointPid = null;
    this.preReadyEndpointPid = null;
    this.endpointRoot = null;
    this.serverRoot = null;
    this.serverAuthorityFact = null;
    this.endpointActiveAuthorityFact = null;
    this.controllerAuthorityBytes = null;
    this.preReadyCatalogBytes = null;
    this.sameStartCatalogBytes = null;
    this.bootstrapStage = "entry";
    this.endpointSessionId = null;
    this.apiKey = liveProviderApiKey ?? randomSecret("all-in-one-api-key");
    this.endpointControlSecret = randomSecret("all-in-one-controller");
    this.staleEndpointSeed = randomSecret("all-in-one-stale-seed");
    this.subjectKey = randomBytes(24).toString("base64url");
    this.secrets = [
      this.apiKey,
      this.endpointControlSecret,
      this.staleEndpointSeed,
      this.subjectKey,
      this.edge.subject,
    ];
    for (const [label, value] of [
      ["provider_api_key", this.apiKey],
      ["endpoint_controller_secret", this.endpointControlSecret],
      ["stale_endpoint_seed", this.staleEndpointSeed],
      ["access_subject_key", this.subjectKey],
      ["access_subject", this.edge.subject],
    ]) {
      this.laterGapCapture?.addSecret(label, value);
    }
  }

  armLaterGapCapture() {
    this.laterGapCapture?.arm();
  }

  async retainLaterGapFailure(options) {
    if (!this.laterGapCapture) {
      return null;
    }
    return this.laterGapCapture.flushFailure(options);
  }

  endpointServerEnvironment(source, { stopEndpointAtEntry = false } = {}) {
    const environment = productEnvironment(source);
    if (this.endpointConfiguredExecutable !== this.endpointBinary) {
      environment.ZODE_E2E_REAL_ENDPOINT = this.endpointBinary;
      if (stopEndpointAtEntry) {
        environment.ZODE_E2E_ENDPOINT_SELF_STOP = "1";
      } else {
        delete environment.ZODE_E2E_ENDPOINT_SELF_STOP;
      }
    }
    return environment;
  }

  isOwnedEndpointCommand(command) {
    return (
      (command.includes(this.endpointBinary) ||
        command.includes(this.endpointConfiguredExecutable)) &&
      command.includes(`--config ${this.endpointConfig}`) &&
      command.includes(`--listen ${this.endpointListen}`)
    );
  }

  async startProcesses() {
    const endpointBinary = path.resolve(
      process.env.ZODE_ENDPOINT_BIN ?? path.join(repositoryRoot, "target", "debug", "zode"),
    );
    const serverBinary = path.resolve(
      process.env.ZODE_SERVER_BIN ??
        path.join(repositoryRoot, "server", "target", "debug", "zode-server"),
    );
    await assertBinary(endpointBinary, "Endpoint");
    await assertBinary(serverBinary, "Server");
    this.endpointBinary = endpointBinary;
    this.serverBinary = serverBinary;

    const endpointRoot = path.join(this.root, "endpoint");
    const serverRoot = path.join(this.root, "server");
    this.endpointRoot = endpointRoot;
    this.serverRoot = serverRoot;
    await fs.mkdir(path.join(endpointRoot, "credentials"), { recursive: true, mode: 0o700 });
    await fs.mkdir(path.join(endpointRoot, "blobs"), { recursive: true, mode: 0o700 });
    await fs.mkdir(path.join(serverRoot, "secrets"), { recursive: true, mode: 0o700 });
    const scaffoldCapture = process.env.ZODE_UI_SCAFFOLD_CAPTURE === "1";
    this.scaffoldCapture = scaffoldCapture;
    let endpointConfiguredExecutable = endpointBinary;
    if (!scaffoldCapture) {
      this.publicBindGate = await TcpGate.start("final public Server bind barrier");
      // The first launch stops in the same child PID before exec so the
      // short-lived seed can be inspected without racing its real Endpoint
      // consumer. Resuming that PID immediately execs the production binary.
      endpointConfiguredExecutable = path.join(this.root, "endpoint-launch-gate");
      await writeExecutable(
        endpointConfiguredExecutable,
        [
          "#!/bin/sh",
          "set -eu",
          'if [ "${ZODE_E2E_ENDPOINT_SELF_STOP:-}" = "1" ]; then',
          '  kill -STOP "$$"',
          "fi",
          'exec "$ZODE_E2E_REAL_ENDPOINT" "$@"',
          "",
        ].join("\n"),
      );
    }
    this.endpointConfiguredExecutable = endpointConfiguredExecutable;
    const endpointListen = await allocateLoopbackAddress();
    const callbackOrigin = new URL(this.edge.baseUrl);
    callbackOrigin.hostname = "127.0.0.2";
    const endpointConfig = path.join(endpointRoot, "endpoint.json");
    this.endpointConfig = endpointConfig;
    this.endpointListen = endpointListen;
    const endpointSeed = path.join(endpointRoot, "controller.seed");
    this.endpointSeed = endpointSeed;
    const endpointConfigDocument = {
      schema: "zode.config.v1",
      listen: endpointListen,
      runtime_store: { kind: "sqlite", path: "runtime.sqlite3" },
      credential_replica_store: { kind: "files", directory: "credentials" },
      blob_store: { kind: "files", directory: "blobs" },
      controller_auth: [
        {
          authority_id: SERVER_AUTHORITY_ID,
          revision: 1,
          kind: "bearer_secret_file",
          secret_file: "controller.seed",
        },
      ],
      runtime: {
        tool_foreground_ms: 100,
        max_rounds_per_activation: 8,
        model_step_max_attempts: 1,
        model_retry_base_ms: 1,
        model_retry_max_ms: 10,
        snapshot_every_events: 1,
      },
      provider_execution: {
        adapter_kinds: ["openai_compatible"],
        allowed_base_url_origins: [this.provider.origin],
      },
      callback: { allowed_public_origins: [callbackOrigin.origin] },
      tools: [],
    };
    this.endpointConfigDocument = endpointConfigDocument;
    await writeJson(endpointConfig, endpointConfigDocument);

    if (scaffoldCapture) {
      await writePrivate(endpointSeed, this.endpointControlSecret);
      this.scaffoldEndpoint = await ReadyProcess.start(
        endpointBinary,
        ["--config", endpointConfig],
        "ZODE_READY ",
        { env: productEnvironment(process.env) },
      );
    }

    const subjectKey = path.join(serverRoot, "subject.key");
    await writePrivate(subjectKey, this.subjectKey);
    const serverListen = scaffoldCapture
      ? "127.0.0.1:0"
      : this.publicBindGate.listenAddress;
    this.serverListen = serverListen;
    const installedUiDirectory = path.join(serverRoot, "ui");
    if (!scaffoldCapture) {
      await fs.cp(uiAssetsDirectory, installedUiDirectory, {
        recursive: true,
        force: false,
        errorOnExist: true,
      });
    }
    const serverConfig = {
      schema: "zode.server-config.v1",
      listen: serverListen,
      management_origin: this.edge.baseUrl,
      callback_origin: callbackOrigin.origin,
      server_authority_id: SERVER_AUTHORITY_ID,
      deployment: scaffoldCapture ? "server_only" : "all_in_one",
      ui_mode: scaffoldCapture ? "api_only" : "assets",
      ...(scaffoldCapture
        ? {}
        : { ui_assets_directory: installedUiDirectory }),
      control_database: "control.sqlite3",
      secret_directory: "secrets",
      access: {
        issuer: this.edge.issuer,
        audiences: [this.edge.audience],
        jwks_url: `${this.edge.baseUrl}/cdn-cgi/access/certs`,
        subject_key_file: "subject.key",
        subject_key_version: 1,
      },
    };
    if (!scaffoldCapture) {
      serverConfig.local_endpoint = {
        executable: endpointConfiguredExecutable,
        config: endpointConfig,
        listen: endpointListen,
        bootstrap_controller_secret_file: "controller.seed",
      };
    }
    const serverConfigPath = path.join(serverRoot, "server.json");
    this.serverConfig = serverConfigPath;
    await writeJson(serverConfigPath, serverConfig);
    if (scaffoldCapture) {
      this.server = await ReadyProcess.start(
        serverBinary,
        ["--config", serverConfigPath],
        "ZODE_SERVER_READY ",
        { env: productEnvironment(process.env) },
      );
      this.edge.setTarget(this.server.readyValue);
      return;
    }

    await this.observeBootstrapBeforePublicBind();

    await this.installSameStartProbeCapability();
    await writePrivate(endpointSeed, this.staleEndpointSeed);
    this.server = await this.startReadyServerAfterActiveAuthorityProbe();
    const expectedPublicOrigin = `http://${serverListen}`;
    if (this.server.readyValue !== expectedPublicOrigin) {
      throw new Error(
        `Server READY used ${this.server.readyValue}, expected configured ${expectedPublicOrigin}`,
      );
    }
    this.edge.setTarget(this.server.readyValue);
  }

  async installSameStartProbeCapability() {
    if (
      this.preReadyCatalogBytes.some((bytes) =>
        bytes.includes(Buffer.from(SAME_START_CAPABILITY_TOOL)),
      )
    ) {
      throw new Error("same-start capability marker was already present in the old catalog");
    }
    const next = structuredClone(this.endpointConfigDocument);
    next.tools = [
      {
        name: SAME_START_CAPABILITY_TOOL,
        description: "same-start authenticated capability probe barrier",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        completion_mode: "response",
        auto_wait_timeout_seconds: 20,
        recovery: {
          on_running_restart: "unknown_outcome",
          retry_dispatch: "never",
        },
        adapter: {
          kind: "http",
          url: `${this.provider.origin}/all-in-one-same-start-tool`,
        },
      },
    ];
    await replaceJson(this.endpointConfig, next);
    this.endpointConfigDocument = next;
  }

  async startReadyServerAfterActiveAuthorityProbe() {
    const endpointOrigin = `http://${this.endpointListen}`;
    const wire = await EndpointProbeWire.start(
      endpointOrigin,
      this.endpointActiveAuthorityFact.bytes,
      () => {
        if (
          storeFamilyBytesSync(this.serverRoot, "control.sqlite3").some((bytes) =>
            bytes.includes(Buffer.from(SAME_START_CAPABILITY_TOOL)),
          )
        ) {
          throw new Error(
            `BEHAVIORAL_RED barrier=${BARRIERS.activeAuthorityProbe}: Server projected the dynamic capability before receiving the real child response`,
          );
        }
      },
    );
    this.endpointProbeWire = wire;
    let managed = null;
    let catalogBarrier = null;
    let endpointPid = null;

    try {
      catalogBarrier = FileContentBarrier.arm(
        this.serverRoot,
        "control.sqlite3",
        () => wire.catalogMarkers(),
        "same-start local Endpoint catalog projection",
        () => {},
      );
      managed = ReadyProcess.launch(
        this.serverBinary,
        ["--config", this.serverConfig],
        { env: wire.processEnvironment(this.endpointServerEnvironment(process.env)) },
      );
      wire.setExpectedServerPid(managed.child.pid);
      this.server = managed;
      const readiness = managed.waitForLine("ZODE_SERVER_READY ");
      void readiness.catch(() => {});

      endpointPid = await this.waitForOneEndpointChild(managed);

      this.endpointProbeEvidence = await Promise.race([
        wire.waitForComplete(managed),
        readiness.then(() => {
          throw new HarnessBarrierError(
            "Server reached ZODE_SERVER_READY before its authenticated Endpoint probes",
          );
        }),
      ]);
      this.bootstrapStage = BARRIERS.activeAuthorityProbe;
      catalogBarrier.scan();

      this.sameStartCatalogBytes = await Promise.race([
        catalogBarrier.wait(managed),
        readiness.then(() => {
          const markers = wire.catalogMarkers();
          const bytes = storeFamilyBytesSync(this.serverRoot, "control.sqlite3");
          const missing = markers.filter(
            (marker) => !bytes.some((content) => content.includes(Buffer.from(marker))),
          );
          if (missing.length > 0) {
            throw new HarnessBarrierError(
              `Server reached ZODE_SERVER_READY before a complete local Endpoint catalog; missing=${missing.join(",")}`,
            );
          }
          return bytes;
        }),
      ]);
      this.bootstrapStage = BARRIERS.localCatalog;
      const readyValue = await readiness;
      await this.assertRestartRejectedStaleSeed();
      wire.finishStartupObservation();
      managed.readyValue = readyValue;
      this.allInOneEndpointPid = endpointPid;
      this.bootstrapStage = BARRIERS.serverReady;
      return managed;
    } finally {
      catalogBarrier?.stop();
    }
  }

  async matchingEndpointChildren(serverProcess) {
    const parentPid = serverProcess?.child.pid;
    if (!Number.isSafeInteger(parentPid)) {
      throw new Error("all-in-one Server process identity is unavailable");
    }
    const matching = [];
    for (const pid of await directChildPids(parentPid)) {
      const command = await processCommand(pid);
      if (this.isOwnedEndpointCommand(command)) {
        matching.push(pid);
      }
    }
    return matching;
  }

  async waitForOneEndpointChild(serverProcess) {
    return withTimeout(
      new Promise((resolve, reject) => {
        const inspect = async () => {
          try {
            const matching = await this.matchingEndpointChildren(serverProcess);
            if (matching.length === 1) {
              resolve(matching[0]);
              return;
            }
            if (matching.length > 1) {
              reject(new Error("all-in-one Server spawned more than one Endpoint candidate"));
              return;
            }
            if (
              serverProcess.child.exitCode != null ||
              serverProcess.child.signalCode != null
            ) {
              reject(new Error("Server exited before a real Endpoint child was observable"));
              return;
            }
            setTimeout(inspect, 5);
          } catch (error) {
            reject(error);
          }
        };
        inspect();
      }),
      READY_TIMEOUT_MS,
      "real Endpoint child process barrier",
    );
  }

  async assertEndpointPidReaped(pid, label) {
    const command = await processCommand(pid);
    if (!command) {
      return;
    }
    const isOwnedEndpoint = this.isOwnedEndpointCommand(command);
    if (!isOwnedEndpoint) {
      throw new Error(`${label} Endpoint PID was unexpectedly reused`);
    }
    try {
      process.kill(pid, "SIGTERM");
    } catch (error) {
      if (error?.code !== "ESRCH") {
        throw error;
      }
    }
    try {
      await waitForProcessGone(pid, `${label} Endpoint cleanup`);
    } catch {
      process.kill(pid, "SIGKILL");
      await waitForProcessGone(pid, `${label} Endpoint reap`);
    }
    throw new Error(`${label} Server exited without reaping its supervised Endpoint child`);
  }

  async observeBootstrapBeforePublicBind() {
    let process;
    let endpointPid;
    let endpointPausedAtEntry = false;
    const seedCreated = FileCreationBarrier.arm(
      this.endpointSeed,
      "Server-generated Endpoint seed creation",
      () => {},
    );
    process = ReadyProcess.launch(this.serverBinary, ["--config", this.serverConfig], {
      env: this.endpointServerEnvironment(globalThis.process.env, {
        stopEndpointAtEntry: true,
      }),
    });
    this.preReadyBootstrapProcess = process;
    try {
      await seedCreated.wait(process);
      endpointPid = await this.waitForOneEndpointChild(process);
      try {
        await waitForProcessStopped(
          endpointPid,
          "test-owned Endpoint launch gate stopped before seed consumption",
        );
      } catch (error) {
        throw new HarnessBarrierError("Endpoint seed-consumption gate did not settle", error);
      }
      endpointPausedAtEntry = true;
      const entryCommand = await processCommand(endpointPid);
      if (!entryCommand.includes(this.endpointConfiguredExecutable)) {
        throw new HarnessBarrierError(
          "Endpoint launch gate did not retain the configured executable before real exec",
        );
      }
      const seed = await bootstrapSeedCreationFact(
        this.endpointSeed,
        "one-time Endpoint bootstrap seed",
      );
      const authority = await oneEncryptedAuthorityFile(
        path.join(this.serverRoot, "secrets", "endpoints"),
        seed.bytes,
        "Server controller authority store",
      );
      assertIndependentFiles(authority, seed, "Server authority and Endpoint seed");
      this.serverAuthorityFact = authority;
      this.controllerAuthorityBytes = Buffer.from(seed.bytes);
      this.bootstrapStage = BARRIERS.controllerSeed;
      const authorityText = seed.bytes.toString("utf8");
      if (!Buffer.from(authorityText, "utf8").equals(seed.bytes)) {
        throw new Error("Server-generated controller authority was not UTF-8 bearer text");
      }
      this.secrets.push(authorityText);
    } finally {
      if (endpointPausedAtEntry) {
        try {
          globalThis.process.kill(endpointPid, "SIGCONT");
          endpointPausedAtEntry = false;
        } catch (error) {
          if (error?.code !== "ESRCH") {
            throw error;
          }
        }
      }
      seedCreated.stop();
    }
    const result = await process.waitForExit("all-in-one pre-public-bind process exit");
    this.preReadyEndpointPid = endpointPid;
    await this.assertEndpointPidReaped(endpointPid, "pre-public-bind");
    this.publicBindGate.assertStillHolding(this.serverListen);
    if (
      result.signal ||
      result.code === 0 ||
      process.stdout.split(/\r?\n/).some((line) => line.startsWith("ZODE_SERVER_READY "))
    ) {
      throw new Error("Server did not fail cleanly at the deliberately held final public bind");
    }
    const bindFailure = `${process.stdout}\n${process.stderr}`.toLowerCase();
    if (
      !/(?:address already in use|eaddrinuse|addrinuse|os error (?:48|98))/.test(bindFailure)
    ) {
      throw new Error(
        "Server exited after local catalog composition for a reason other than the held final public bind",
      );
    }
    if (await pathExists(this.endpointSeed)) {
      throw new Error("Endpoint bootstrap seed was not consumed before final Server bind");
    }

    const authority = await privateOpaqueFileFact(
      this.serverAuthorityFact.pathname,
      "Server controller authority after Endpoint bootstrap",
    );
    if (authority.digest !== this.serverAuthorityFact.digest) {
      throw new Error("Server authority changed while the Endpoint consumed its seed");
    }
    const active = await oneMatchingPrivateFile(
      this.endpointRoot,
      this.controllerAuthorityBytes,
      "Endpoint durable active controller store",
    );
    if (authority.bytes.includes(active.bytes)) {
      throw new Error("Server protected store exposed the active Endpoint controller plaintext");
    }
    assertIndependentFiles(authority, active, "Server and active Endpoint controller stores");
    this.serverAuthorityFact = authority;
    this.endpointActiveAuthorityFact = active;
    this.bootstrapStage = BARRIERS.childReady;
    this.preReadyCatalogBytes = await storeFamilyBytes(this.serverRoot, "control.sqlite3");
    for (const marker of [
      "zode.endpoint.v1",
      "openai_compatible",
      `http://${this.endpointListen}`,
    ]) {
      if (!this.preReadyCatalogBytes.some((bytes) => bytes.includes(Buffer.from(marker)))) {
        throw new Error(
          `Server control store omitted pre-bind local catalog marker ${marker}`,
        );
      }
    }
    this.bootstrapStage = BARRIERS.localCatalog;
    process.assertOutputSecretFree(this.secrets);
    await this.publicBindGate.stop();
    this.publicBindGate = null;
  }

  async assertRestartRejectedStaleSeed() {
    const response = await fetch(`http://${this.endpointListen}/v1/identity`, {
      headers: {
        authorization: `Bearer ${this.staleEndpointSeed}`,
        "zode-subject": "all-in-one-stale-seed-probe",
      },
    });
    const body = await response.text();
    if (response.status !== 401) {
      throw new Error(
        `restart accepted a stale Endpoint bootstrap seed through the public identity route; status=${response.status}`,
      );
    }
    if (body.includes(this.staleEndpointSeed)) {
      throw new Error("public stale-seed rejection exposed the rejected credential");
    }
  }

  assertCatalogsPrecedeReady(localEndpointId) {
    if (this.scaffoldCapture) {
      return;
    }
    const [identityExchange, capabilitiesExchange] = this.endpointProbeEvidence ?? [];
    if (
      identityExchange?.request?.path !== "/v1/identity" ||
      identityExchange?.request?.authorization !== "<ACTIVE_CONTROLLER_AUTHORITY>" ||
      identityExchange?.request?.source_server_pid !== this.server?.child.pid ||
      identityExchange?.response?.json?.endpoint_id !== localEndpointId ||
      capabilitiesExchange?.request?.path !== "/v1/capabilities" ||
      capabilitiesExchange?.request?.authorization !== "<ACTIVE_CONTROLLER_AUTHORITY>" ||
      capabilitiesExchange?.request?.source_server_pid !== this.server?.child.pid ||
      capabilitiesExchange?.response?.json?.endpoint_id !== localEndpointId
    ) {
      throw new Error(
        `BEHAVIORAL_RED barrier=${BARRIERS.activeAuthorityProbe}: public local Endpoint did not match the recorded active-authority identity/capability exchanges`,
      );
    }
    for (const observation of [
      {
        label: "first-start catalog before the held public bind",
        bytes: this.preReadyCatalogBytes,
        markers: [localEndpointId, "zode.endpoint.v1", "openai_compatible"],
      },
      {
        label: "active-authority catalog captured while the public port still refused",
        bytes: this.sameStartCatalogBytes,
        markers: [
          localEndpointId,
          SERVER_AUTHORITY_ID,
          "zode.endpoint.v1",
          "openai_compatible",
          SAME_START_CAPABILITY_TOOL,
        ],
      },
    ]) {
      for (const marker of [...observation.markers, `http://${this.endpointListen}`]) {
        if (!observation.bytes.some((bytes) => bytes.includes(Buffer.from(marker)))) {
          throw new Error(
            `BEHAVIORAL_RED barrier=${BARRIERS.localCatalog}: ${observation.label} omitted ${marker}`,
          );
        }
      }
    }
  }

  async assertIndependentEndpointChild() {
    if (this.scaffoldCapture) {
      return;
    }
    const matching = await this.matchingEndpointChildren(this.server);
    if (matching.length !== 1) {
      throw new Error(
        `all-in-one Server supervised ${matching.length} matching real Endpoint children, expected one`,
      );
    }
    this.allInOneEndpointPid = matching[0];
  }

  async assertAllInOneChildReaped() {
    if (!this.allInOneEndpointPid) {
      return;
    }
    await this.assertEndpointPidReaped(this.allInOneEndpointPid, "all-in-one cleanup");
  }

  async assertSecretFree(evidence) {
    let tracked = "";
    try {
      tracked = await fs.readFile(trackedIncidentPath, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
    const publicEvidence = [
      ...evidence,
      ...this.recorder.publicResponseBodies,
      JSON.stringify(this.endpointProbeEvidence ?? []),
      tracked,
    ].join("\n");
    const forbidden = [...this.secrets, this.edge.lastAssertion].filter(Boolean);
    for (const secret of forbidden) {
      if (publicEvidence.includes(secret)) {
        throw new Error("browser-visible evidence exposed a test secret");
      }
    }
    if (/eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(publicEvidence)) {
      throw new Error("browser-visible evidence exposed an Access assertion");
    }
    this.server?.assertOutputSecretFree(forbidden);
    this.preReadyBootstrapProcess?.assertOutputSecretFree(forbidden);
    this.scaffoldEndpoint?.assertOutputSecretFree(forbidden);
  }

  async assertPersistenceSecretFree() {
    const stores = [];
    for (const [root, prefix] of [
      [this.serverRoot, "control.sqlite3"],
      [this.endpointRoot, "runtime.sqlite3"],
    ]) {
      for (const pathname of await regularFilesUnder(root)) {
        if (path.basename(pathname).startsWith(prefix)) {
          stores.push({ pathname, serverOwned: root === this.serverRoot });
        }
      }
    }
    const forbidden = [...this.secrets, this.edge.lastAssertion].filter(Boolean);
    for (const store of stores) {
      const bytes = await fs.readFile(store.pathname);
      for (const secret of forbidden) {
        if (bytes.includes(Buffer.from(secret))) {
          throw new Error("ordinary SQLite persistence exposed a test secret");
        }
      }
      const text = bytes.toString("utf8");
      if (/eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text)) {
        throw new Error("ordinary SQLite persistence exposed an Access assertion");
      }
      if (
        store.serverOwned &&
        this.endpointSessionId &&
        bytes.includes(Buffer.from(this.endpointSessionId))
      ) {
        throw new Error("Server control SQLite persisted an Endpoint-owned session ID");
      }
    }
  }

  async stop() {
    const errors = [];
    for (const operation of [
      async () => {
        await this.server?.stop();
        await this.assertAllInOneChildReaped();
        process.stderr.write(
          `ZODE_E2E_CHILD_REAP_OBSERVATION server_forced_sigkill=${this.server?.stopObservation?.forcedSigkill === true} endpoint_reaped=true\n`,
        );
      },
      () => this.preReadyBootstrapProcess?.stop(),
      () => this.publicBindGate?.stop(),
      () => this.scaffoldEndpoint?.stop(),
      () => this.endpointProbeWire?.stop(),
      () => this.edge?.stop(),
      () => this.provider?.stop(),
    ]) {
      try {
        await operation();
      } catch (error) {
        errors.push(error);
      }
    }
    if (errors.length > 0) {
      throw new Error("all_in_one_first_run cleanup failed", { cause: errors[0] });
    }
  }
}

async function browserJson(page, requestPath) {
  return page.evaluate(async (pathname) => {
    const response = await fetch(pathname, {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    const body = await response.text();
    let json = null;
    try {
      json = JSON.parse(body);
    } catch {
      // The route assertion owns invalid public JSON, not the browser harness.
    }
    return { status: response.status, body, json };
  }, requestPath);
}

function shallowNonEvidence(barrier, detail, cause = null) {
  return new Error(`SHALLOW_NON_EVIDENCE barrier=${barrier}: ${detail}`, {
    ...(cause ? { cause } : {}),
  });
}

async function semanticBehavioralRed(harness, method, requestPath, safeError, detail) {
  await harness.edge.waitForIdle();
  const retained = await harness.recorder.retainSemanticFailure(
    method,
    requestPath,
    safeError,
  );
  const barrier =
    requestPath === "/v1/endpoints"
      ? BARRIERS.endpointCapabilities
      : BARRIERS.systemDeployment;
  return new Error(
    `BEHAVIORAL_RED barrier=${barrier} error=${safeError}: ${detail}; quarantine=${retained.pathname}`,
  );
}

async function requireAllInOneSystem(harness, page) {
  const system = await browserJson(page, "/v1/system");
  await harness.edge.waitForIdle();
  if (system.status === 404 || system.status === 405) {
    throw shallowNonEvidence(
      BARRIERS.systemDeployment,
      `public GET /v1/system route is not available (status=${system.status})`,
    );
  }
  if (system.status !== 200) {
    throw new Error(
      `BEHAVIORAL_RED barrier=${BARRIERS.systemDeployment}: GET /v1/system returned ${system.status}; ${harness.recorder.failureSummary() ?? "no incident was retained"}`,
    );
  }
  if (system.json?.schema !== "zode.system.v1") {
    throw await semanticBehavioralRed(
      harness,
      "GET",
      "/v1/system",
      "system_schema_mismatch",
      "route returned 200 without zode.system.v1",
    );
  }
  if (system.json.deployment === "server_only" && system.json.local_endpoint_id === null) {
    throw await semanticBehavioralRed(
      harness,
      "GET",
      "/v1/system",
      "all_in_one_reported_server_only_null",
      "a ready Server with one supervised local Endpoint reported the server-only null-local state",
    );
  }
  if (
    system.json.deployment !== "all_in_one" ||
    typeof system.json.local_endpoint_id !== "string" ||
    system.json.local_endpoint_id.length === 0
  ) {
    throw await semanticBehavioralRed(
      harness,
      "GET",
      "/v1/system",
      "all_in_one_system_state_mismatch",
      "route did not bind all_in_one to one non-empty local_endpoint_id",
    );
  }
  return system;
}

async function requireProbedLocalEndpoint(harness, page, localEndpointId) {
  const endpoints = await browserJson(page, "/v1/endpoints");
  await harness.edge.waitForIdle();
  if (endpoints.status === 404 || endpoints.status === 405) {
    throw shallowNonEvidence(
      BARRIERS.endpointCapabilities,
      `normal GET /v1/endpoints route is not available (status=${endpoints.status})`,
    );
  }
  if (endpoints.status !== 200) {
    throw new Error(
      `BEHAVIORAL_RED barrier=${BARRIERS.endpointCapabilities}: GET /v1/endpoints returned ${endpoints.status}; ${harness.recorder.failureSummary() ?? "no incident was retained"}`,
    );
  }

  const items = Array.isArray(endpoints.json) ? endpoints.json : endpoints.json?.items;
  const local = Array.isArray(items)
    ? items.filter((endpoint) => endpoint.kind === "local")
    : [];
  if (
    !Array.isArray(items) ||
    items.length !== 1 ||
    local.length !== 1 ||
    local[0]?.endpoint_id !== localEndpointId ||
    items[0]?.endpoint_id !== localEndpointId
  ) {
    throw await semanticBehavioralRed(
      harness,
      "GET",
      "/v1/endpoints",
      "all_in_one_local_catalog_mismatch",
      "normal Endpoint catalog did not contain exactly the system-declared local Endpoint",
    );
  }

  const endpoint = local[0];
  const providers = Array.isArray(endpoint.capabilities?.providers)
    ? [...endpoint.capabilities.providers].sort()
    : null;
  const tools = Array.isArray(endpoint.capabilities?.tools)
    ? [...endpoint.capabilities.tools].sort()
    : null;
  if (
    endpoint.status !== "online" ||
    endpoint.disabled !== false ||
    endpoint.controller_authority_id !== SERVER_AUTHORITY_ID ||
    endpoint.controller_credential_revision !== 1 ||
    endpoint.capabilities?.protocol_version !== "zode.endpoint.v1" ||
    exactJson(providers) !== exactJson(["openai_compatible"]) ||
    exactJson(tools) !== exactJson([SAME_START_CAPABILITY_TOOL])
  ) {
    throw await semanticBehavioralRed(
      harness,
      "GET",
      "/v1/endpoints",
      "local_endpoint_capabilities_probe_mismatch",
      "catalog observation did not prove the authenticated Endpoint /v1/capabilities result",
    );
  }
  return endpoint;
}

async function clickVisible(page, choices, label) {
  for (const choice of choices) {
    const locator = page.getByRole(choice.role, { name: choice.name, exact: true });
    if ((await locator.count()) > 0 && (await locator.first().isVisible())) {
      await locator.first().click();
      return;
    }
  }
  throw new Error(`UI omitted the accessible ${label} action`);
}

async function fillVisible(page, names, value, label) {
  for (const name of names) {
    const locator = page.getByLabel(name, { exact: true });
    if ((await locator.count()) > 0 && (await locator.first().isVisible())) {
      await locator.first().fill(value);
      return locator.first();
    }
  }
  throw new Error(`UI omitted the accessible ${label} field`);
}

async function selectVisible(page, names, value, label) {
  for (const name of names) {
    const locator = page.getByLabel(name, { exact: true });
    if ((await locator.count()) > 0 && (await locator.first().isVisible())) {
      await selectRadixValue(page, locator.first(), value);
      return;
    }
  }
  throw new Error(`UI omitted the accessible ${label} selection`);
}

function sessionIdentity(url) {
  const pathname = new URL(url).pathname;
  const match = SESSION_PATH.exec(pathname);
  if (!match) {
    throw new Error(`session URL omitted endpoint_id or Endpoint ULID: ${pathname}`);
  }
  return { endpointId: match[1], sessionId: match[2] };
}

async function waitForSessionUrl(page) {
  await expect.poll(() => new URL(page.url()).pathname).toMatch(SESSION_PATH);
  return sessionIdentity(page.url());
}

async function browserStorage(page) {
  return page.evaluate(() => {
    const result = {
      historyState: window.history.state,
    };
    for (const [name, storage] of [
      ["localStorage", window.localStorage],
      ["sessionStorage", window.sessionStorage],
    ]) {
      result[name] = {};
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        result[name][key] = storage.getItem(key);
      }
    }
    return JSON.stringify(result);
  });
}

async function browserDomEvidence(page) {
  return page.evaluate(() =>
    JSON.stringify(
      Array.from(document.querySelectorAll("*")).map((element) => {
        const evidence = {
          tag: element.tagName.toLowerCase(),
          attributes: Object.fromEntries(
            Array.from(element.attributes).map((attribute) => [attribute.name, attribute.value]),
          ),
        };
        if (
          element instanceof HTMLInputElement ||
          element instanceof HTMLTextAreaElement ||
          element instanceof HTMLSelectElement
        ) {
          evidence.value = element.value;
        }
        return evidence;
      }),
    ),
  );
}

async function downloadedEvidence(downloads) {
  const evidence = [];
  for (const download of downloads) {
    evidence.push(download.suggestedFilename());
    const pathname = await download.path();
    if (pathname) {
      evidence.push((await fs.readFile(pathname)).toString("utf8"));
    }
  }
  return evidence.join("\n");
}

async function waitForProviderProfileReady(page, endpointId) {
  let selected = null;
  await expect
    .poll(async () => {
      const profiles = await browserJson(page, `/v1/providers/${PROVIDER_ID}/auth-profiles`);
      if (profiles.status !== 200) {
        return `profiles:${profiles.status}`;
      }
      const items = Array.isArray(profiles.json) ? profiles.json : profiles.json?.items;
      selected = items?.find((profile) => profile.label === "UI E2E profile") ?? null;
      if (!selected?.profile_id) {
        return "profile:missing";
      }
      const replicas = await browserJson(page, `/v1/auth-profiles/${selected.profile_id}/replicas`);
      if (replicas.status !== 200) {
        return `replicas:${replicas.status}`;
      }
      const states = Array.isArray(replicas.json) ? replicas.json : replicas.json?.items;
      const local = states?.find((replica) => replica.endpoint_id === endpointId);
      if (local?.status !== "ready" || local?.installed_revision !== selected.revision) {
        return `replica:${local?.status ?? "missing"}`;
      }
      return "ready";
    })
    .toBe("ready");
  return selected;
}

test(E2E, async ({ playwright }) => {
  const browser = await playwright.chromium.launch({ env: productEnvironment(process.env) });
  delete process.env.ZODE_E2E_LIVE_PROVIDER_API_KEY;
  let harness;
  try {
    harness = await Harness.start();
  } catch (error) {
    await browser.close().catch(() => {});
    throw error;
  }
  const storageWrites = [];
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
  });
  await context.exposeBinding("__zodeE2eRecordStorageWrite", (_source, write) => {
    storageWrites.push(write);
  });
  await context.addInitScript(() => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function setItem(key, value) {
      void window.__zodeE2eRecordStorageWrite({
        storage: this === window.localStorage ? "localStorage" : "sessionStorage",
        key: String(key),
        value: String(value),
      });
      return original.call(this, key, value);
    };
    for (const method of ["add", "put"]) {
      const indexedDbWrite = IDBObjectStore.prototype[method];
      IDBObjectStore.prototype[method] = function recordIndexedDbWrite(value, key) {
        void window.__zodeE2eRecordStorageWrite({
          storage: "indexedDB",
          database: this.transaction.db.name,
          store: this.name,
          key,
          value,
        });
        return indexedDbWrite.call(this, value, key);
      };
    }
  });
  const page = await context.newPage();
  const consoleEvidence = [];
  const downloads = [];
  const browserHttpRequests = [];
  const eventRequests = [];
  page.on("console", (message) => consoleEvidence.push(message.text()));
  page.on("pageerror", (error) => consoleEvidence.push(error.message));
  page.on("download", (download) => downloads.push(download));
  context.on("request", (request) => {
    const url = new URL(request.url());
    if (url.protocol === "http:" || url.protocol === "https:") {
      browserHttpRequests.push({
        method: request.method(),
        url: request.url(),
        headers: request.headers(),
      });
    }
    if (url.pathname.endsWith("/events")) {
      eventRequests.push({
        url: request.url(),
        headers: request.allHeaders().catch(() => null),
      });
    }
  });

  let primaryError = null;
  let reconnectFailureObserved = false;
  try {
    harness.armLaterGapCapture();
    let entry;
    try {
      entry = await page.goto(`${harness.edge.baseUrl}/`, {
        waitUntil: "domcontentloaded",
        timeout: 20_000,
      });
    } catch (error) {
      await harness.edge.waitForIdle();
      const incident = harness.recorder.failureSummary();
      throw shallowNonEvidence(
        BARRIERS.uiEntry,
        `real browser GET / did not reach a production UI document${incident ? `; ${incident}` : ""}`,
        error,
      );
    }
    await harness.edge.waitForIdle();
    if (!entry || entry.status() >= 400) {
      if (harness.recorder.expectRecordedBlocked) {
        expect(harness.edge.jwksRequests).toBeGreaterThan(0);
      }
      const incident = harness.recorder.failureSummary();
      throw shallowNonEvidence(
        BARRIERS.uiEntry,
        `production UI route is unavailable: status=${entry?.status() ?? "none"}${incident ? `; ${incident}` : ""}`,
      );
    }
    const entryContentType = entry.headers()["content-type"] ?? "";
    const uiDocument = await page.evaluate(() => ({
      hasBody: Boolean(document.body),
      bodyChildren: document.body?.childElementCount ?? 0,
    }));
    if (
      !entryContentType.toLowerCase().includes("text/html") ||
      !uiDocument.hasBody ||
      uiDocument.bodyChildren === 0
    ) {
      throw shallowNonEvidence(
        BARRIERS.uiEntry,
        "GET / returned without a non-empty HTML application document",
      );
    }
    if (harness.edge.jwksRequests === 0) {
      throw shallowNonEvidence(
        BARRIERS.uiEntry,
        "management UI document was not admitted through the real JWKS-backed Access verifier",
      );
    }

    const system = await requireAllInOneSystem(harness, page);

    await expect(page.getByRole("heading", { name: "Log in", exact: true })).toHaveCount(0);
    await expect(page.getByLabel("Zode token", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /(?:log|sign) in|log out/i })).toHaveCount(0);
    await expect(page.getByRole("link", { name: /(?:log|sign) in|log out/i })).toHaveCount(0);
    const applicationCookies = (await context.cookies())
      .map((cookie) => cookie.name)
      .filter(
        (name) =>
          !name.toLowerCase().startsWith("cf_") &&
          /zode|session|auth|token|login|^sid$/i.test(name),
      );
    expect(applicationCookies).toEqual([]);

    const localEndpoint = await requireProbedLocalEndpoint(
      harness,
      page,
      system.json.local_endpoint_id,
    );
    harness.assertCatalogsPrecedeReady(localEndpoint.endpoint_id);
    if (!LIVE_PROVIDER) {
      expect(harness.provider.requests).toHaveLength(0);
    }

    await page.getByRole("button", { name: "Zode", exact: true }).click();
    await clickVisible(
      page,
      [
        { role: "menuitem", name: "Providers" },
      ],
      "Providers navigation",
    );
    await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
    await clickVisible(
      page,
      [
        { role: "button", name: "Configure provider" },
        { role: "button", name: "Add provider" },
      ],
      "provider configuration",
    );
    await fillVisible(page, ["Provider ID", "Provider"], PROVIDER_ID, "provider ID");
    await expect(page.getByText("OpenAI compatible", { exact: true })).toBeVisible();
    await fillVisible(page, ["Base URL", "Provider base URL"], harness.provider.baseUrl, "base URL");
    await fillVisible(page, ["Models", "Model"], MODEL_ID, "model catalog");
    await clickVisible(
      page,
      [
        { role: "button", name: "Save provider" },
        { role: "button", name: "Create provider" },
      ],
      "provider save",
    );

    await expect(
      page.getByRole("button", { name: "Add API key profile", exact: true }),
    ).toBeVisible();

    await clickVisible(
      page,
      [
        { role: "button", name: "Add API key profile" },
        { role: "button", name: "Add profile" },
      ],
      "API-key profile create",
    );
    await fillVisible(page, ["Profile label", "Label"], "UI E2E profile", "profile label");
    const apiKeyField = await fillVisible(page, ["API key"], harness.apiKey, "write-only API key");
    expect(await apiKeyField.getAttribute("type")).toBe("password");
    const localShare = page.getByRole("checkbox", { name: /this machine|built-in local endpoint/i });
    await expect(localShare).toHaveCount(1);
    await localShare.check();
    await clickVisible(
      page,
      [
        { role: "button", name: "Create profile" },
        { role: "button", name: "Save profile" },
      ],
      "profile save",
    );
    const profile = await waitForProviderProfileReady(page, localEndpoint.endpoint_id);
    const retainedApiKey = page.getByLabel("API key", { exact: true });
    if ((await retainedApiKey.count()) > 0 && (await retainedApiKey.first().isVisible())) {
      expect(await retainedApiKey.first().inputValue()).toBe("");
    }

    await clickVisible(
      page,
      [
        { role: "link", name: "New session" },
      ],
      "New session navigation",
    );
    await expect(
      page.getByRole("heading", { name: "What do you want to work on?", exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Environment", exact: true })).toContainText(
      "This machine",
    );
    await expectSelectedExecutionProfile(
      page,
      page.getByRole("button", { name: "Choose model and reasoning", exact: true }),
      MODEL_ID,
      "UI E2E profile",
    );
    await clickVisible(
      page,
      [
        { role: "button", name: "Start session" },
        { role: "button", name: "Create" },
      ],
      "session admission",
    );
    const created = await waitForSessionUrl(page);
    harness.endpointSessionId = created.sessionId;
    expect(created.endpointId).toBe(localEndpoint.endpoint_id);

    harness.edge.armSseDrop(FINAL_ASSISTANT);
    await fillVisible(page, ["Message", "Send a message"], USER_MESSAGE, "composer");
    await clickVisible(
      page,
      [
        { role: "button", name: "Send" },
        { role: "button", name: "Send message" },
      ],
      "message send",
    );
    const durableFinal = page.getByText(FINAL_ASSISTANT, { exact: true });
    await expect(durableFinal).toHaveCount(1);
    await harness.edge.dropSseAfterBrowserBarrier();
    await harness.edge.waitForSseDrop();
    await harness.edge.waitForSseReconnect();
    await expect(durableFinal).toHaveCount(1);
    try {
      await expect(page.getByText("Connected to Endpoint", { exact: true })).toHaveCount(1);
    } catch (error) {
      process.stderr.write(
        `ZODE_E2E_UI_RECONNECT_OBSERVATION classification=${RECONNECT_FAILURE} relation=${LATER_GAP_RELATION} observed=Reconnecting expected=Live durable_assistant_reply_count=1\n`,
      );
      throw new ProductBehaviorFailure(
        RECONNECT_FAILURE,
        `relation=${LATER_GAP_RELATION}; durable assistant reply remained exactly once but the real browser stayed Reconnecting after a Last-Event-ID reconnect`,
        { relation: LATER_GAP_RELATION, cause: error instanceof Error ? error.message : String(error) },
      );
    }
    expect(sessionIdentity(page.url())).toEqual(created);
    if (process.env.ZODE_E2E_SCREENSHOT_PATH) {
      await fs.mkdir(path.dirname(process.env.ZODE_E2E_SCREENSHOT_PATH), {
        recursive: true,
        mode: 0o700,
      });
      await page.screenshot({
        path: process.env.ZODE_E2E_SCREENSHOT_PATH,
        fullPage: true,
      });
    }

    const observedEventRequests = (
      await Promise.all(
        eventRequests.map(async (request) => ({
          url: request.url,
          headers: await request.headers,
        })),
      )
    ).filter((request) => request.headers !== null);
    expect(observedEventRequests.length).toBeGreaterThanOrEqual(2);
    for (const request of observedEventRequests) {
      const url = new URL(request.url);
      expect(url.origin).toBe(harness.edge.baseUrl);
      expect(url.pathname).toBe(`/v1/endpoints/${created.endpointId}/events`);
    }
    expect(
      observedEventRequests
        .slice(1)
        .some(
          (request) =>
            request.headers["last-event-id"] === harness.edge.droppedFinalEventId,
        ),
    ).toBe(true);

    await page.reload({ waitUntil: "domcontentloaded" });
    expect(await waitForSessionUrl(page)).toEqual(created);
    await expect(page.getByText(FINAL_ASSISTANT, { exact: true })).toHaveCount(1);
    const session = await browserJson(
      page,
      `/v1/endpoints/${created.endpointId}/sessions/${created.sessionId}`,
    );
    expect(session.status, session.body).toBe(200);
    const finals = (session.json?.transcript ?? []).filter(
      (message) => message.role === "assistant" && message.content === FINAL_ASSISTANT,
    );
    expect(finals).toHaveLength(1);
    if (!LIVE_PROVIDER) {
      expect(harness.provider.requests).toHaveLength(1);
      const providerRequest = harness.provider.requests[0];
      if (providerRequest.headers.authorization !== `Bearer ${harness.apiKey}`) {
        throw new Error(
          "Endpoint provider request did not use the selected write-only profile secret",
        );
      }
      expect(providerRequest.method).toBe("POST");
      expect(providerRequest.path).toBe("/v1/chat/completions");
      const providerBody = JSON.parse(providerRequest.body.toString("utf8"));
      expect(providerBody.model).toBe(MODEL_ID);
      expect(providerBody.messages).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ role: "user", content: USER_MESSAGE }),
        ]),
      );
      expect(providerRequest.body.includes(Buffer.from(harness.apiKey))).toBe(false);
    }

    expect(browserHttpRequests.length).toBeGreaterThan(0);
    for (const browserRequest of browserHttpRequests) {
      const url = new URL(browserRequest.url);
      expect(url.origin).toBe(harness.edge.baseUrl);
      expect(url.pathname).not.toBe("/cdn-cgi/access/certs");
    }
    const browserCommands = browserHttpRequests.map((request) => {
      const url = new URL(request.url);
      return `${request.method} ${url.pathname}`;
    });
    expect(
      browserCommands.filter(
        (command) => command === `POST /v1/endpoints/${created.endpointId}/sessions`,
      ),
    ).toHaveLength(1);
    const createRequest = browserHttpRequests.find((request) => {
      const url = new URL(request.url);
      return (
        request.method === "POST" &&
        url.pathname === `/v1/endpoints/${created.endpointId}/sessions`
      );
    });
    const messageRequest = browserHttpRequests.find((request) => {
      const url = new URL(request.url);
      return (
        request.method === "POST" &&
        url.pathname ===
          `/v1/endpoints/${created.endpointId}/sessions/${created.sessionId}/messages`
      );
    });
    expect(createRequest?.headers["idempotency-key"]?.length).toBeGreaterThan(0);
    expect(messageRequest?.headers["idempotency-key"]?.length).toBeGreaterThan(0);
    expect(messageRequest.headers["idempotency-key"]).not.toBe(
      createRequest.headers["idempotency-key"],
    );
    expect(
      browserCommands.filter(
        (command) =>
          command ===
          `POST /v1/endpoints/${created.endpointId}/sessions/${created.sessionId}/messages`,
      ),
    ).toHaveLength(1);
  } catch (error) {
    primaryError = error;
    reconnectFailureObserved = error?.classification === RECONNECT_FAILURE;
  } finally {
    const evidence = [];
    try {
      if (!page.isClosed()) {
        evidence.push(await page.locator("html").innerText().catch(() => ""));
        evidence.push(await browserDomEvidence(page).catch(() => ""));
        evidence.push(await browserStorage(page).catch(() => ""));
        evidence.push(page.url());
      }
      evidence.push(consoleEvidence.join("\n"));
      evidence.push(JSON.stringify(storageWrites));
      evidence.push(browserHttpRequests.map((request) => request.url).join("\n"));
      evidence.push(await downloadedEvidence(downloads));
      await harness.assertSecretFree(evidence);
    } catch (error) {
      primaryError = prioritizeGateFailure(
        primaryError,
        error,
        "all_in_one_first_run secret evidence gate failed",
      );
    }
    let browserContextClosed = false;
    try {
      await context.close();
      browserContextClosed = true;
    } catch (error) {
      primaryError = prioritizeGateFailure(
        primaryError,
        error,
        "all_in_one_first_run browser cleanup failed",
      );
    }
    if (CAPTURE_LATER_GAP && primaryError) {
      try {
        if (!browserContextClosed) {
          throw new Error(
            "browser context did not close, so a client-disconnect terminal cannot be recorded",
          );
        }
        await harness.edge.finishActiveSseAfterBrowserContextClose();
        const retained = await harness.retainLaterGapFailure({
          classification: reconnectFailureObserved
            ? RECONNECT_FAILURE
            : "MANAGEMENT_BROWSER_PRE_RECONNECT_FAILURE",
          firstObserved: reconnectFailureObserved
            ? undefined
            : `relation=${LATER_GAP_RELATION}; the complete real browser suite stopped before the SSE reconnect assertion`,
        });
        if (retained) {
          process.stderr.write(`ZODE_E2E_LATER_GAP_CAPTURE ${retained.root}\n`);
        }
      } catch (error) {
        primaryError = prioritizeGateFailure(
          primaryError,
          error,
          "all_in_one_first_run later reproduction capture failed",
        );
      }
    }
    await browser.close().catch((error) => {
      primaryError = prioritizeGateFailure(
        primaryError,
        error,
        "all_in_one_first_run browser process cleanup failed",
      );
    });
    await harness.stop().catch((error) => {
      primaryError = prioritizeGateFailure(
        primaryError,
        error,
        "all_in_one_first_run recorder/process cleanup gate failed",
      );
    });
    await harness.assertPersistenceSecretFree().catch((error) => {
      primaryError = prioritizeGateFailure(
        primaryError,
        error,
        "all_in_one_first_run persistence secret/state gate failed",
      );
    });
  }
  if (primaryError) {
    throw primaryError;
  }
});
