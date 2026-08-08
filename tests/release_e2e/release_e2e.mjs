#!/usr/bin/env node

import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fchmodSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  lstatSync,
  watch,
  writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";

const OWNER = "e2e_ui_release_pipeline_atomic_promotion_and_rollback";
const SCHEMA = "zode.release-artifact.v1";
const INCIDENT_SCHEMA = "zode.http-incident-recording.v1";
const ARTIFACT_BINDING_E2E = "e2e_release_artifact_binds_server_endpoint_and_ui_tree";
const PROMOTION_REVISION_E2E = "e2e_release_promotion_never_mixes_server_and_ui_revision";
const BLOCKED_EXIT = 78;
const BODY_LIMIT = 2 * 1024 * 1024;
const PROCESS_LOCATOR_SCHEMA = "zode.e2e.process-locator.v1";
const PROCESS_STOP_SCHEMA = "zode.e2e.process-stop.v1";
const PROCESS_LOCATOR_REQUIRED_KEYS = new Set([
  "schema",
  "instance_id",
  "role",
  "pid",
  "started_at_unix_ms",
  "process_group_id",
  "session_id",
  "executable_path",
  "executable_sha256",
]);
const PROCESS_LOCATOR_OPTIONAL_KEYS = new Set(["control_origin"]);
const PROCESS_STOP_REQUIRED_KEYS = new Set([
  "schema",
  "instance_id",
  "requested_at_unix_ms",
  "observed_pids",
  "reaped_pids",
  "leaked_pids",
  "timed_out",
  "exit_status",
  "flush_status",
]);

class Blocked extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "Blocked";
    this.code = code;
    this.details = details;
  }
}

class BehaviorFailure extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "BehaviorFailure";
    this.code = code;
    this.details = details;
  }
}

function usage() {
  return [
    "usage: run_release_e2e.sh [--promote-incident] [--replay CASSETTE] [--keep-workdir]",
    "required env: ZODE_RELEASE_BASELINE_REVISION ZODE_RELEASE_CANDIDATE_REVISION",
    "              ZODE_RELEASE_FAILED_REVISION ZODE_RELEASE_DRIVER_RELATIVE_PATH ZODE_RELEASE_UI_URL",
    "replay env: ZODE_RELEASE_REPLAY_EXPECTATION=red|green (required with --replay)",
  ].join("\n");
}

function parseArgs(argv) {
  const result = { promote: false, replay: null, keepWorkdir: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--promote-incident") {
      result.promote = true;
    } else if (argument === "--keep-workdir") {
      result.keepWorkdir = true;
    } else if (argument === "--replay") {
      result.replay = argv[++index];
      if (!result.replay) throw new Error(usage());
    } else if (argument === "--help" || argument === "-h") {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${argument}\n${usage()}`);
    }
  }
  return result;
}

function runSync(command, args, options = {}) {
  const encoding = Object.prototype.hasOwnProperty.call(options, "encoding")
    ? options.encoding
    : "utf8";
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    // `null` is intentional for git archive: tar receives the exact bytes,
    // never a UTF-8 round-trip of an opaque binary stream.
    encoding,
    input: options.input,
    maxBuffer: 8 * 1024 * 1024,
    timeout: options.timeout ?? 300_000,
  });
  if (result.error) throw result.error;
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function commandOutput(command, args, cwd) {
  const result = runSync(command, args, { cwd });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed (${result.status})`);
  }
  return result.stdout.trim();
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sleep(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function ensureDirectory(path, mode = 0o700) {
  rejectSymlinkAncestors(path, "directory");
  mkdirSync(path, { recursive: true, mode });
  chmodSync(path, mode);
}

function lstatOrNull(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function exactObjectKeys(value, required, optional = new Set(), label = "object") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Blocked("process_contract_invalid", `${label} must be a JSON object`);
  }
  const keys = new Set(Object.keys(value));
  for (const key of required) {
    if (!keys.has(key)) throw new Blocked("process_contract_invalid", `${label} is missing ${key}`);
  }
  for (const key of keys) {
    if (!required.has(key) && !optional.has(key)) {
      throw new Blocked("process_contract_invalid", `${label} contains an unsupported field`, { field: key });
    }
  }
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Blocked("process_contract_invalid", `${label} must be a positive integer`);
  }
}

function readJsonContract(path, schema, required, optional, phase, label) {
  if (typeof path !== "string" || !isAbsolute(path)) {
    throw new Blocked("process_contract_invalid", `${phase}: ${label} path must be absolute`);
  }
  const stat = lstatOrNull(path);
  if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
    throw new Blocked("process_contract_invalid", `${phase}: ${label} path is not a regular file`, { label });
  }
  let value;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Blocked("process_contract_invalid", `${phase}: ${label} is not valid JSON`, { error: String(error) });
  }
  exactObjectKeys(value, required, optional, label);
  if (value.schema !== schema) {
    throw new Blocked("process_contract_invalid", `${phase}: ${label} has the wrong schema`, {
      expected: schema,
      observed: value.schema ?? null,
    });
  }
  return value;
}

function validateProcessLocator(path, phase) {
  const locator = readJsonContract(
    path,
    PROCESS_LOCATOR_SCHEMA,
    PROCESS_LOCATOR_REQUIRED_KEYS,
    PROCESS_LOCATOR_OPTIONAL_KEYS,
    phase,
    "process locator",
  );
  if (!new Set(["server", "endpoint"]).has(locator.role)) {
    throw new Blocked("process_contract_invalid", `${phase}: process locator role is not server/endpoint`, {
      role: locator.role,
    });
  }
  for (const [field, value] of Object.entries({
    instance_id: locator.instance_id,
    session_id: locator.session_id,
    executable_path: locator.executable_path,
    executable_sha256: locator.executable_sha256,
  })) {
    if (typeof value !== "string" || !value) {
      throw new Blocked("process_contract_invalid", `${phase}: locator ${field} must be non-empty text`);
    }
  }
  positiveInteger(locator.pid, `${phase}: locator pid`);
  positiveInteger(locator.started_at_unix_ms, `${phase}: locator started_at_unix_ms`);
  positiveInteger(locator.process_group_id, `${phase}: locator process_group_id`);
  if (!isAbsolute(locator.executable_path)) {
    throw new Blocked("process_contract_invalid", `${phase}: locator executable_path must be absolute`);
  }
  if (!/^[a-f0-9]{64}$/.test(locator.executable_sha256)) {
    throw new Blocked("process_contract_invalid", `${phase}: locator executable_sha256 is not a SHA-256 digest`);
  }
  if (locator.control_origin !== undefined) {
    let origin;
    try {
      origin = new URL(locator.control_origin);
    } catch {
      throw new Blocked("process_contract_invalid", `${phase}: locator control_origin is not a URL`);
    }
    if (origin.protocol !== "http:" || !new Set(["127.0.0.1", "localhost", "::1"]).has(origin.hostname)) {
      throw new Blocked("process_contract_invalid", `${phase}: locator control_origin is not local HTTP`);
    }
  }
  return locator;
}

function validateProcessStop(report, phase) {
  exactObjectKeys(report, PROCESS_STOP_REQUIRED_KEYS, new Set(), "process stop report");
  if (report.schema !== PROCESS_STOP_SCHEMA) {
    throw new Blocked("process_contract_invalid", `${phase}: process stop report has the wrong schema`, {
      expected: PROCESS_STOP_SCHEMA,
      observed: report.schema ?? null,
    });
  }
  if (typeof report.instance_id !== "string" || !report.instance_id) {
    throw new Blocked("process_contract_invalid", `${phase}: process stop instance_id must be non-empty text`);
  }
  positiveInteger(report.requested_at_unix_ms, `${phase}: stop requested_at_unix_ms`);
  if (!Array.isArray(report.observed_pids) || report.observed_pids.length === 0) {
    throw new Blocked("process_contract_invalid", `${phase}: stop observed_pids must contain process evidence`);
  }
  const observedIds = new Set();
  for (const [index, observed] of report.observed_pids.entries()) {
    exactObjectKeys(
      observed,
      new Set(["pid", "role", "started_at_unix_ms", "process_group_id", "session_id", "executable_path", "executable_sha256"]),
      new Set(),
      `process stop observed_pids[${index}]`,
    );
    positiveInteger(observed.pid, `${phase}: stop observed_pids[${index}].pid`);
    if (observedIds.has(observed.pid)) throw new Blocked("process_contract_invalid", `${phase}: stop observed_pids contains duplicate PIDs`);
    observedIds.add(observed.pid);
    if (!(observed.role === "supervisor" || observed.role === "server" || observed.role === "endpoint")) {
      throw new Blocked("process_contract_invalid", `${phase}: stop observed_pids[${index}].role is not recognized`);
    }
    positiveInteger(observed.started_at_unix_ms, `${phase}: stop observed_pids[${index}].started_at_unix_ms`);
    positiveInteger(observed.process_group_id, `${phase}: stop observed_pids[${index}].process_group_id`);
    if (typeof observed.session_id !== "string" || !observed.session_id) {
      throw new Blocked("process_contract_invalid", `${phase}: stop observed_pids[${index}].session_id must be non-empty text`);
    }
    if (typeof observed.executable_path !== "string" || !isAbsolute(observed.executable_path)) {
      throw new Blocked("process_contract_invalid", `${phase}: stop observed_pids[${index}].executable_path must be absolute`);
    }
    if (!/^[a-f0-9]{64}$/.test(observed.executable_sha256)) {
      throw new Blocked("process_contract_invalid", `${phase}: stop observed_pids[${index}].executable_sha256 is not a SHA-256 digest`);
    }
  }
  for (const field of ["reaped_pids", "leaked_pids"]) {
    if (!Array.isArray(report[field]) || report[field].some((pid) => !Number.isSafeInteger(pid) || pid <= 0)) {
      throw new Blocked("process_contract_invalid", `${phase}: stop ${field} must contain positive integer PIDs`);
    }
    if (new Set(report[field]).size !== report[field].length) {
      throw new Blocked("process_contract_invalid", `${phase}: stop ${field} contains duplicate PIDs`);
    }
    if (report[field].some((pid) => !observedIds.has(pid))) {
      throw new Blocked("process_contract_invalid", `${phase}: stop ${field} contains an unobserved PID`);
    }
  }
  if (typeof report.timed_out !== "boolean") {
    throw new Blocked("process_contract_invalid", `${phase}: stop timed_out must be boolean`);
  }
  if (report.exit_status !== null && !Number.isSafeInteger(report.exit_status)) {
    throw new Blocked("process_contract_invalid", `${phase}: stop exit_status must be integer or null`);
  }
  if (typeof report.flush_status !== "string" || !report.flush_status) {
    throw new Blocked("process_contract_invalid", `${phase}: stop flush_status must be non-empty text`);
  }
  return report;
}

function stopReportsFromPayload(payload, phase) {
  if (Array.isArray(payload?.stop_reports)) {
    if (!payload.stop_reports.length) {
      throw new Blocked("release_process_stop_missing", `${phase}: teardown returned no stop reports`);
    }
    return payload.stop_reports.map((report) => validateProcessStop(report, phase));
  }
  if (payload?.stop && typeof payload.stop === "object") return [validateProcessStop(payload.stop, phase)];
  if (payload?.schema === PROCESS_STOP_SCHEMA) return [validateProcessStop(payload, phase)];
  throw new Blocked("release_process_stop_missing", `${phase}: teardown did not return process-stop.v1 evidence`);
}

function parseReadyLocatorLines(output, phase) {
  const paths = [];
  for (const line of String(output ?? "").split(/\r?\n/)) {
    const match = line.match(/^ZODE_PROCESS_READY\s+(\S+)$/);
    if (!match) continue;
    if (!isAbsolute(match[1])) {
      throw new Blocked("process_locator_invalid", `${phase}: ZODE_PROCESS_READY path must be absolute`);
    }
    paths.push(match[1]);
  }
  if (new Set(paths).size !== paths.length) {
    throw new Blocked("process_locator_invalid", `${phase}: duplicate ZODE_PROCESS_READY locator paths`);
  }
  return paths;
}

function pathIsContained(root, candidate) {
  const relativePath = relative(resolve(root), resolve(candidate));
  return relativePath === ""
    || (!isAbsolute(relativePath)
      && relativePath !== ".."
      && !relativePath.startsWith(`..${sep}`));
}

function rejectSymlinkAncestors(path, label) {
  let current = resolve(path);
  while (true) {
    const stat = lstatOrNull(current);
    if (stat?.isSymbolicLink()) {
      throw new Blocked("release_path_invalid", `${label} has a symlink ancestor`, { path: current });
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function assertOwnedFilePath(root, path, label) {
  if (!pathIsContained(root, path)) {
    throw new BehaviorFailure("release_process_instance_mismatch", `${label} is outside the release root`, {
      path,
      release_root: root,
    });
  }
  rejectSymlinkAncestors(path, label);
  const stat = lstatOrNull(path);
  if (!stat || stat.isSymbolicLink()) {
    throw new BehaviorFailure("release_process_locator_invalid", `${label} is not a regular file`, { path });
  }
  let canonical;
  try { canonical = realpathSync(path); } catch (error) {
    throw new BehaviorFailure("release_process_locator_invalid", `${label} cannot be resolved`, { path, error: String(error) });
  }
  if (!pathIsContained(root, canonical)) {
    throw new BehaviorFailure("release_process_instance_mismatch", `${label} resolves outside the release root`, {
      path,
      canonical,
      release_root: root,
    });
  }
}

function assertReleaseRoot(releaseRoot) {
  const root = resolve(releaseRoot);
  const stat = lstatOrNull(root);
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) {
    throw new BehaviorFailure("release_pointer_outside_root", "releaseRoot must be a canonical directory", {
      release_root: root,
    });
  }
  let canonical;
  try {
    canonical = realpathSync(root);
  } catch (error) {
    throw new BehaviorFailure("torn_release_pointer", "releaseRoot could not be resolved", {
      release_root: root,
      error: String(error),
    });
  }
  if (canonical !== root) {
    throw new BehaviorFailure("release_pointer_outside_root", "releaseRoot resolves through a symlink", {
      release_root: root,
      canonical,
    });
  }
  return root;
}

function assertReleasePointerPath(releaseRoot, path, pointer) {
  const root = assertReleaseRoot(releaseRoot);
  const lexical = resolve(path);
  if (!pathIsContained(root, lexical)) {
    throw new BehaviorFailure("release_pointer_outside_root", `${pointer} is outside releaseRoot`, {
      pointer,
      release_root: root,
      path: lexical,
    });
  }
  const stat = lstatOrNull(path);
  if (!stat) return;
  let canonical;
  try {
    canonical = realpathSync(path);
  } catch (error) {
    throw new BehaviorFailure("torn_release_pointer", `${pointer} could not be resolved`, {
      pointer,
      path,
      error: String(error),
    });
  }
  if (!pathIsContained(root, canonical)) {
    throw new BehaviorFailure("release_pointer_outside_root", `${pointer} resolves outside releaseRoot`, {
      pointer,
      release_root: root,
      path,
      canonical,
    });
  }
}

function makeImmutableTree(path) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) {
    artifactBindingFailure("release payload contains a symlink", { path });
  }
  if (stat.isDirectory()) {
    for (const name of readdirSync(path).sort()) makeImmutableTree(join(path, name));
    chmodSync(path, 0o555);
    return;
  }
  if (!stat.isFile()) {
    artifactBindingFailure("release payload contains a non-regular entry", { path });
  }
  chmodSync(path, stat.mode & 0o555);
}

function assertImmutableTree(path, label) {
  const stat = lstatOrNull(path);
  if (!stat || stat.isSymbolicLink()) {
    artifactBindingFailure(`${label} is missing or is a symlink`, { path });
  }
  if ((stat.mode & 0o222) !== 0) {
    artifactBindingFailure(`${label} is writable`, { path, mode: stat.mode & 0o777 });
  }
  if (stat.isDirectory()) {
    for (const name of readdirSync(path).sort()) assertImmutableTree(join(path, name), label);
  } else if (!stat.isFile()) {
    artifactBindingFailure(`${label} contains a non-regular entry`, { path });
  }
}

function writeExclusive(path, bytes, mode) {
  const descriptor = openSync(path, "wx", mode);
  try {
    writeFileSync(descriptor, bytes);
    fchmodSync(descriptor, mode);
  } finally {
    closeSync(descriptor);
  }
}

function canonicalCommit(repoRoot, revision) {
  const result = runSync("git", ["rev-parse", "--verify", `${revision}^{commit}`], {
    cwd: repoRoot,
  });
  if (result.status !== 0) {
    throw new Blocked("invalid_revision", `revision is not a commit: ${revision}`, {
      revision,
      stderr: result.stderr.trim().slice(-1000),
    });
  }
  return result.stdout.trim();
}

function trackedPathExists(repoRoot, commit, path) {
  const result = runSync("git", ["cat-file", "-e", `${commit}:${path}`], { cwd: repoRoot });
  return result.status === 0;
}

function extractCommit(repoRoot, commit, destination) {
  // The release source is the commit's tracked tree only.  In particular, an
  // uncommitted candidate worktree must never become an implicit release
  // input through a copy fallback.
  ensureDirectory(destination);
  const archive = runSync("git", ["archive", "--format=tar", commit], {
    cwd: repoRoot,
    encoding: null,
  });
  if (archive.status !== 0) {
    throw new Blocked("archive_failed", `cannot archive frozen revision ${commit}`, {
      stderr: Buffer.from(archive.stderr ?? []).toString("utf8").trim().slice(-1000),
    });
  }
  const unpack = runSync("tar", ["-xf", "-", "-C", destination], {
    input: archive.stdout,
  });
  if (unpack.status !== 0) {
    throw new Blocked("checkout_failed", `cannot unpack frozen revision ${commit}`, {
      stderr: unpack.stderr.trim().slice(-1000),
    });
  }
  assertArchiveTree(destination, destination);
}

function assertArchiveTree(path, root) {
  const stat = lstatOrNull(path);
  if (!stat) throw new Blocked("archive_surface_invalid", "frozen archive is missing an extracted path", { path });
  if (stat.isSymbolicLink()) {
    throw new Blocked("archive_surface_invalid", "frozen archive contains a symlink", {
      path: relative(root, path),
    });
  }
  if (stat.isDirectory()) {
    for (const name of readdirSync(path).sort()) assertArchiveTree(join(path, name), root);
  } else if (!stat.isFile()) {
    throw new Blocked("archive_surface_invalid", "frozen archive contains a non-regular entry", {
      path: relative(root, path),
    });
  }
}

function requiredSurface(repoRoot, commit, driverRelativePath) {
  const required = [
    "Cargo.toml",
    "Cargo.lock",
    "src",
    "protocol/Cargo.toml",
    "protocol/src",
    "protocol/src/lib.rs",
    "server/Cargo.toml",
    "server/Cargo.lock",
    "server/src",
    "server/src/main.rs",
    "web/package.json",
    "web/pnpm-lock.yaml",
    "web/pnpm-workspace.yaml",
    "web/tsconfig.json",
    "web/index.html",
    "web/src",
    "web/src/main.ts",
    "web/vite.config.ts",
  ];
  if (driverRelativePath) required.push(driverRelativePath);
  const missing = required.filter((path) => !trackedPathExists(repoRoot, commit, path));
  return missing;
}

function runChecked(command, args, cwd, logPath) {
  const result = runSync(command, args, { cwd });
  const output = `${result.stdout}${result.stderr}`;
  writeFileSync(logPath, output, { mode: 0o600 });
  if (result.status !== 0) {
    throw new Blocked("build_failed", `${command} failed for frozen checkout`, {
      command,
      args,
      log: logPath,
    });
  }
}

function firstExisting(paths) {
  return paths.find((path) => existsSync(path)) ?? null;
}

function copyTree(source, destination) {
  const result = runSync("cp", ["-R", source, destination]);
  if (result.status !== 0) {
    throw new Blocked("artifact_copy_failed", `cannot package ${source}`, {
      stderr: result.stderr.trim().slice(-1000),
    });
  }
}

function selectDriverSource(checkout, relativePath) {
  if (!relativePath || isAbsolute(relativePath)) {
    throw new Blocked("release_driver_not_in_checkout", "release driver must be selected by a relative path inside the frozen checkout", {
      relative_path: relativePath ?? null,
    });
  }
  const source = resolve(checkout, relativePath);
  if (!pathIsContained(checkout, source)) {
    throw new Blocked("release_driver_not_in_checkout", "release driver path escapes the frozen checkout", {
      relative_path: relativePath,
    });
  }
  let resolvedSource;
  try {
    resolvedSource = realpathSync(source);
  } catch (error) {
    throw new Blocked("release_driver_missing", "frozen checkout does not contain a resolvable real release driver", {
      relative_path: relativePath,
      source,
      error: String(error),
    });
  }
  if (!pathIsContained(realpathSync(checkout), resolvedSource)) {
    throw new Blocked("release_driver_not_in_checkout", "release driver resolves outside the frozen checkout", {
      relative_path: relativePath,
      source,
      resolved_source: resolvedSource,
    });
  }
  const stat = lstatOrNull(source);
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) {
    throw new Blocked("release_driver_missing", "frozen checkout does not contain the real release driver", {
      relative_path: relativePath,
      source,
    });
  }
  return source;
}

function packageArtifact(checkout, commit, outputRoot, logsRoot, driverSource, sourceTreeSha256) {
  const web = join(checkout, "web");
  const ui = firstExisting([join(web, "dist")]);
  const server = firstExisting([
    join(checkout, "server", "target", "release", "zode-server"),
    join(checkout, "target", "release", "zode-server"),
  ]);
  const endpoint = firstExisting([join(checkout, "target", "release", "zode")]);
  if (!ui || !server || !endpoint) {
    throw new Blocked("missing_build_output", "frozen checkout did not produce UI, Server, and Endpoint artifacts", {
      revision: commit,
      missing: {
        ui: ui ? null : "web/dist or web/build",
        server: server ? null : "zode-server",
        endpoint: endpoint ? null : "zode",
      },
      logs: logsRoot,
    });
  }

  const artifact = join(outputRoot, commit);
  ensureDirectory(artifact);
  const uiDestination = join(artifact, "ui");
  copyTree(ui, artifact);
  renameSync(join(artifact, basename(ui)), uiDestination);
  const serverDestination = join(artifact, "zode-server");
  const endpointDestination = join(artifact, "zode");
  const driverDestination = join(artifact, "release-driver");
  copyFileSync(server, serverDestination);
  copyFileSync(endpoint, endpointDestination);
  copyFileSync(driverSource, driverDestination);
  makeImmutableTree(uiDestination);
  chmodSync(serverDestination, 0o555);
  chmodSync(endpointDestination, 0o555);
  chmodSync(driverDestination, 0o555);

  const components = {
    ui: {
      kind: "tree",
      path: "ui",
      revision: commit,
      tree_sha256: treeDigest(uiDestination),
    },
    server: {
      kind: "binary",
      path: "zode-server",
      revision: commit,
      binary_sha256: sha256(readFileSync(serverDestination)),
    },
    endpoint: {
      kind: "binary",
      path: "zode",
      revision: commit,
      binary_sha256: sha256(readFileSync(endpointDestination)),
    },
  };
  const driverBinding = {
    kind: "executable",
    path: "release-driver",
    revision: commit,
    binary_sha256: sha256(readFileSync(driverDestination)),
  };
  const manifest = {
    schema: SCHEMA,
    revision: commit,
    source: {
      kind: "git-archive",
      revision: commit,
      tree_sha256: sourceTreeSha256,
    },
    components,
    driver: driverBinding,
    binding: {
      revision: commit,
      source_tree_sha256: sourceTreeSha256,
      ui_tree_sha256: components.ui.tree_sha256,
      server_binary_sha256: components.server.binary_sha256,
      endpoint_binary_sha256: components.endpoint.binary_sha256,
      driver_binary_sha256: driverBinding.binary_sha256,
    },
  };
  const manifestWithoutDigest = jsonBytes(manifest);
  const finalManifest = { ...manifest, manifest_sha256: sha256(manifestWithoutDigest) };
  const manifestPath = join(artifact, "manifest.json");
  writeExclusive(manifestPath, jsonBytes(finalManifest), 0o444);
  chmodSync(artifact, 0o555);
  const record = {
    artifact,
    manifest: finalManifest,
    manifestPath,
    driverPath: driverDestination,
    driver: driverBinding,
    revision: commit,
  };
  return e2e_release_artifact_binds_server_endpoint_and_ui_tree({
    artifact: record,
    label: basename(checkout),
    revision: commit,
  });
}

function treeDigest(path) {
  const entries = [];
  const rootStat = lstatSync(path);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o222) !== 0) {
    artifactBindingFailure("UI artifact tree root is not an immutable directory", {
      path,
      mode: rootStat.mode & 0o777,
    });
  }
  function visit(current, relativePath) {
    const names = readdirSync(current).sort();
    for (const name of names) {
      const absolute = join(current, name);
      const rel = join(relativePath, name);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        artifactBindingFailure("UI artifact tree contains a symlink", { path: absolute, relative_path: rel });
      }
      if ((stat.mode & 0o222) !== 0) {
        artifactBindingFailure("UI artifact tree is writable", { path: absolute, relative_path: rel });
      }
      if (stat.isDirectory()) visit(absolute, rel);
      else if (stat.isFile()) entries.push({ path: rel, mode: stat.mode & 0o777, sha256: sha256(readFileSync(absolute)) });
      else artifactBindingFailure("UI artifact tree contains a non-regular entry", { path: absolute, relative_path: rel });
    }
  }
  visit(path, "");
  return sha256(jsonBytes(entries));
}

function sourceTreeDigest(path) {
  const entries = [];
  function visit(current, relativePath) {
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) {
      throw new Blocked("archive_surface_invalid", "frozen source tree contains a symlink", {
        path: relative(path, current),
      });
    }
    if (stat.isDirectory()) {
      for (const name of readdirSync(current).sort()) visit(join(current, name), join(relativePath, name));
      return;
    }
    if (!stat.isFile()) {
      throw new Blocked("archive_surface_invalid", "frozen source tree contains a non-regular entry", {
        path: relative(path, current),
      });
    }
    entries.push({ path: relativePath, mode: stat.mode & 0o777, sha256: sha256(readFileSync(current)) });
  }
  visit(path, "");
  return sha256(jsonBytes(entries));
}

function artifactBindingFailure(message, details = {}) {
  throw new BehaviorFailure("release_artifact_manifest_mismatch", message, {
    e2e_name: ARTIFACT_BINDING_E2E,
    ...details,
  });
}

function assertDigestFile(path, expected, label, details) {
  const stat = lstatOrNull(path);
  if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
    artifactBindingFailure(`${label} is missing or is not a regular file`, { ...details, path });
  }
  if ((stat.mode & 0o222) !== 0 || (stat.mode & 0o111) === 0) {
    artifactBindingFailure(`${label} is not an immutable executable`, { ...details, path, mode: stat.mode & 0o777 });
  }
  let observed;
  try {
    observed = sha256(readFileSync(path));
  } catch (error) {
    artifactBindingFailure(`${label} could not be hashed`, { ...details, path, error: String(error) });
  }
  if (observed !== expected) {
    artifactBindingFailure(`${label} digest does not match its manifest`, {
      ...details,
      path,
      expected,
      observed,
    });
  }
}

function assertExecutableDigest(path, expected, label, phase = "release driver invocation") {
  const stat = lstatOrNull(path);
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o222) !== 0 || (stat.mode & 0o111) === 0) {
    throw new BehaviorFailure("release_executable_invalid", `${phase}: ${label} is not an immutable regular executable`, {
      e2e_name: PROMOTION_REVISION_E2E,
      path,
      mode: stat?.mode ? stat.mode & 0o777 : null,
    });
  }
  let observed;
  try {
    observed = sha256(readFileSync(path));
  } catch (error) {
    throw new BehaviorFailure("release_executable_invalid", `${phase}: ${label} could not be hashed`, {
      e2e_name: PROMOTION_REVISION_E2E,
      path,
      error: String(error),
    });
  }
  if (observed !== expected) {
    throw new BehaviorFailure("release_executable_digest_mismatch", `${phase}: ${label} digest changed`, {
      e2e_name: PROMOTION_REVISION_E2E,
      path,
      expected,
      observed,
    });
  }
}

function assertManifestEnvelope(manifestPath, manifest, details) {
  const { manifest_sha256: digest, ...withoutDigest } = manifest;
  if (typeof digest !== "string" || sha256(jsonBytes(withoutDigest)) !== digest) {
    artifactBindingFailure("release manifest envelope is not self-consistent", {
      ...details,
      manifestPath,
    });
  }
}

function assertSafeArtifactPath(artifactRoot, relativePath, component, details) {
  if (typeof relativePath !== "string" || relativePath !== component) {
    artifactBindingFailure(`${component} manifest path is not canonical`, {
      ...details,
      expected: component,
      observed: relativePath,
    });
  }
  const resolved = resolve(artifactRoot, relativePath);
  if (resolved !== join(artifactRoot, component)) {
    artifactBindingFailure(`${component} manifest path escapes the artifact`, {
      ...details,
      path: relativePath,
    });
  }
  return resolved;
}

function e2e_release_artifact_binds_server_endpoint_and_ui_tree({ artifact, label, revision }) {
  const details = { label, revision, artifact: artifact.artifact };
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(artifact.manifestPath, "utf8"));
  } catch (error) {
    artifactBindingFailure("release artifact manifest cannot be read", { ...details, error: String(error) });
  }
  if (manifest.schema !== SCHEMA || manifest.revision !== revision) {
    artifactBindingFailure("release manifest is not bound to the frozen revision", {
      ...details,
      observed_revision: manifest.revision ?? null,
      schema: manifest.schema ?? null,
    });
  }
  if (
    !manifest.source
    || manifest.source.kind !== "git-archive"
    || manifest.source.revision !== revision
    || !/^[a-f0-9]{64}$/.test(String(manifest.source.tree_sha256 ?? ""))
  ) {
    artifactBindingFailure("release manifest does not bind immutable archived source", { ...details });
  }
  assertManifestEnvelope(artifact.manifestPath, manifest, details);
  const manifestStat = lstatOrNull(artifact.manifestPath);
  if (!manifestStat || !manifestStat.isFile() || manifestStat.isSymbolicLink()) {
    artifactBindingFailure("release manifest is not a regular file", { ...details, manifestPath: artifact.manifestPath });
  }
  if ((manifestStat.mode & 0o222) !== 0) {
    artifactBindingFailure("release manifest is writable", { ...details, manifestPath: artifact.manifestPath });
  }

  const components = manifest.components;
  const componentNames = Object.keys(components ?? {}).sort();
  if (JSON.stringify(componentNames) !== JSON.stringify(["endpoint", "server", "ui"])) {
    artifactBindingFailure("release manifest must bind exactly UI, Server, and Endpoint components", {
      ...details,
      components: componentNames,
    });
  }
  const binding = manifest.binding;
  if (
    !binding
    || binding.revision !== revision
    || typeof binding.ui_tree_sha256 !== "string"
    || typeof binding.server_binary_sha256 !== "string"
    || typeof binding.endpoint_binary_sha256 !== "string"
    || typeof binding.driver_binary_sha256 !== "string"
    || binding.source_tree_sha256 !== manifest.source.tree_sha256
  ) {
    artifactBindingFailure("release manifest has no revision binding for all runtime components", { ...details });
  }

  const ui = components.ui;
  const server = components.server;
  const endpoint = components.endpoint;
  const driver = manifest.driver;
  if (![ui, server, endpoint].every((component) => component && typeof component === "object")) {
    artifactBindingFailure("release manifest has an incomplete component binding", { ...details });
  }
  for (const [name, component] of Object.entries({ ui, server, endpoint })) {
    if (component.revision !== revision) {
      artifactBindingFailure(`${name} component is bound to a different revision`, {
        ...details,
        component: name,
        observed_revision: component.revision ?? null,
      });
    }
  }
  if (ui.kind !== "tree" || ui.tree_sha256 !== binding.ui_tree_sha256) {
    artifactBindingFailure("UI component is not bound to its immutable tree digest", { ...details });
  }
  if (server.kind !== "binary" || server.binary_sha256 !== binding.server_binary_sha256) {
    artifactBindingFailure("Server component is not bound to its immutable binary digest", { ...details });
  }
  if (endpoint.kind !== "binary" || endpoint.binary_sha256 !== binding.endpoint_binary_sha256) {
    artifactBindingFailure("Endpoint component is not bound to its immutable binary digest", { ...details });
  }
  if (
    !driver
    || driver.kind !== "executable"
    || driver.revision !== revision
    || driver.binary_sha256 !== binding.driver_binary_sha256
  ) {
    artifactBindingFailure("release driver is not bound to the immutable checkout executable", { ...details });
  }

  const uiPath = assertSafeArtifactPath(artifact.artifact, ui.path, "ui", details);
  const serverPath = assertSafeArtifactPath(artifact.artifact, server.path, "zode-server", details);
  const endpointPath = assertSafeArtifactPath(artifact.artifact, endpoint.path, "zode", details);
  const driverPath = assertSafeArtifactPath(artifact.artifact, driver.path, "release-driver", details);
  const artifactStat = lstatOrNull(artifact.artifact);
  if (!artifactStat || !artifactStat.isDirectory() || (artifactStat.mode & 0o222) !== 0) {
    artifactBindingFailure("release artifact root is not immutable", {
      ...details,
      path: artifact.artifact,
      mode: artifactStat?.mode ? artifactStat.mode & 0o777 : null,
    });
  }
  const uiStat = lstatOrNull(uiPath);
  if (!uiStat || !uiStat.isDirectory() || uiStat.isSymbolicLink()) {
    artifactBindingFailure("UI artifact tree is missing", { ...details, path: uiPath });
  }
  assertImmutableTree(uiPath, "UI artifact tree");
  if (treeDigest(uiPath) !== ui.tree_sha256 || ui.tree_sha256 !== binding.ui_tree_sha256) {
    artifactBindingFailure("UI artifact tree digest does not match the manifest", { ...details, path: uiPath });
  }
  assertDigestFile(serverPath, server.binary_sha256, "Server binary", { ...details, component: "server" });
  assertDigestFile(endpointPath, endpoint.binary_sha256, "Endpoint binary", { ...details, component: "endpoint" });
  assertDigestFile(driverPath, driver.binary_sha256, "release driver", { ...details, component: "driver" });

  return {
    artifact: artifact.artifact,
    manifest,
    manifestPath: artifact.manifestPath,
    driverPath,
    driver,
    revision,
  };
}

function parseJsonLine(output, label) {
  const lines = output.trim().split(/\r?\n/).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      return JSON.parse(lines[index]);
    } catch {
      // Driver logs may precede its final JSON result.
    }
  }
  throw new Blocked("driver_protocol", `${label} did not return a JSON result`, {
    line_count: output.trim().split(/\r?\n/).filter(Boolean).length,
  });
}

function driverInvocationArgs(operation, releaseRoot, artifact) {
  const args = [operation, "--release-root", releaseRoot, "--json"];
  if (artifact) args.push("--artifact", artifact);
  return args;
}

function productionDriverEnv() {
  const env = { ...process.env };
  for (const key of [
    "ZODE_RELEASE_DRIVER_ARGS_JSON",
    "ZODE_RELEASE_E2E_OWNER",
    "ZODE_RELEASE_E2E_MODE",
    "ZODE_RELEASE_E2E_NAME",
    "ZODE_RELEASE_REPLAY_CASSETTE",
    "ZODE_RELEASE_REPLAY_EXPECTATION",
    "ZODE_RELEASE_REPLAY_ADAPTER",
    "ZODE_RELEASE_SECRET_VALUES_JSON",
    "ZODE_RELEASE_QUARANTINE",
    "ZODE_RELEASE_CASSETTES",
  ]) delete env[key];
  return env;
}

function driverCapture(options, operation, artifact, result) {
  if (!options.capture) return;
  const requestBody = {
    operation,
    e2e_name: options.e2eName ?? PROMOTION_REVISION_E2E,
    artifact_revision: options.captureArtifact?.manifest?.revision ?? null,
    artifact_manifest_sha256: options.captureArtifact?.manifestPath
      ? sha256(readFileSync(options.captureArtifact.manifestPath))
      : null,
  };
  const sequence = options.sequenceAllocator
    ? options.sequenceAllocator()
    : options.capture.length;
  options.capture.push({
    sequence,
    boundary: "release-driver",
    request: {
      method: "CLI",
      path: `release-driver/${operation}`,
      headers: {},
      body: boundedBuffer(Buffer.from(JSON.stringify(requestBody), "utf8")),
    },
    response: {
      status: result.status,
      headers: {},
      body: boundedBuffer(Buffer.from(`${result.stdout}${result.stderr}`, "utf8")),
      completed: result.status !== null && result.status !== undefined,
      request_failed: result.status === null || result.status === undefined,
      disconnected: result.status === null || result.status === undefined,
      failure: options.failure ?? null,
      expected_failure: options.expectedFailure === true,
    },
  });
}

function finalizeDriverResult(driver, operation, result, options = {}) {
  const output = `${result.stdout}\n${result.stderr}`;
  const readyLocatorPaths = parseReadyLocatorLines(output, `${operation} driver`);
  const payload = parseJsonLine(output, `${operation} driver`);
  return { ...result, payload, readyLocatorPaths };
}

function runDriver(driver, operation, releaseRoot, artifact, options = {}) {
  if (typeof options.driverSha256 !== "string") {
    throw new Blocked("release_driver_unbound", "release driver invocation has no immutable manifest binding", {
      operation,
    });
  }
  assertExecutableDigest(driver, options.driverSha256, "release driver", `${operation} driver invocation`);
  if (options.replay) {
    throw new Blocked("production_driver_replay_forbidden", "the production release driver cannot receive a cassette or replay mode");
  }
  const args = driverInvocationArgs(operation, releaseRoot, artifact);
  let result;
  try {
    result = runSync(driver, args, {
      // A driver is an immutable artifact executable.  Never let it resolve
      // relative helpers/configuration from the dirty harness checkout.
      cwd: options.cwd ?? dirname(driver),
      env: productionDriverEnv(),
    });
  } catch (error) {
    const failed = { status: null, signal: null, stdout: "", stderr: String(error) };
    driverCapture({ ...options, failure: "driver_exception" }, operation, artifact, failed);
    throw error;
  }
  driverCapture(options, operation, artifact, result);
  return finalizeDriverResult(driver, operation, result, options);
}

function runDriverAsync(driver, operation, releaseRoot, artifact, options = {}) {
  if (typeof options.driverSha256 !== "string") {
    return Promise.reject(new Blocked("release_driver_unbound", "release driver invocation has no immutable manifest binding", {
      operation,
    }));
  }
  if (options.replay) {
    return Promise.reject(new Blocked("production_driver_replay_forbidden", "the production release driver cannot receive a cassette or replay mode"));
  }
  try {
    assertExecutableDigest(driver, options.driverSha256, "release driver", `${operation} driver invocation`);
  } catch (error) {
    return Promise.reject(error);
  }
  const args = driverInvocationArgs(operation, releaseRoot, artifact);
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(driver, args, {
      cwd: options.cwd ?? dirname(driver),
      env: productionDriverEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const rejectWithCapture = (failure) => {
      const result = { status: null, signal: "SIGKILL", stdout, stderr };
      try {
        driverCapture({ ...options, failure: failure.code }, operation, artifact, result);
      } catch (captureError) {
        rejectPromise(captureError);
        return;
      }
      rejectPromise(failure);
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      rejectWithCapture(new BehaviorFailure("release_driver_timeout", `${operation} driver exceeded its bounded timeout`, {
        e2e_name: PROMOTION_REVISION_E2E,
        operation,
      }));
    }, options.timeoutMs ?? 120_000);
    child.stdout.on("data", (chunk) => {
      if (settled) return;
      stdout += chunk.toString("utf8");
      if (stdout.length + stderr.length > 8 * 1024 * 1024 && !settled) {
        settled = true;
        clearTimeout(timer);
        child.kill("SIGKILL");
        rejectWithCapture(new BehaviorFailure("release_driver_output_oversize", `${operation} driver output exceeded its bound`, {
          e2e_name: PROMOTION_REVISION_E2E,
          operation,
        }));
      }
    });
    child.stderr.on("data", (chunk) => {
      if (settled) return;
      stderr += chunk.toString("utf8");
      if (stdout.length + stderr.length > 8 * 1024 * 1024) {
        settled = true;
        clearTimeout(timer);
        child.kill("SIGKILL");
        rejectWithCapture(new BehaviorFailure("release_driver_output_oversize", `${operation} driver output exceeded its bound`, {
          e2e_name: PROMOTION_REVISION_E2E,
          operation,
        }));
      }
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const failure = new Blocked("release_driver_spawn_failed", `${operation} driver could not be started`, { error: String(error) });
      try {
        driverCapture({ ...options, failure: "driver_spawn_failed" }, operation, artifact, { status: null, signal: null, stdout, stderr: String(error) });
        rejectPromise(failure);
      } catch (captureError) {
        rejectPromise(captureError);
      }
    });
    child.on("close", (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const result = { status: status ?? 1, signal, stdout, stderr };
      try {
        driverCapture(options, operation, artifact, result);
        resolvePromise(finalizeDriverResult(driver, operation, result, options));
      } catch (error) {
        rejectPromise(error);
      }
    });
  });
}

function runReplayAdapter(adapter, driver, operation, releaseRoot, artifact, cassette, options = {}) {
  if (!cassette) throw new Blocked("replay_cassette_missing", "replay adapter requires an immutable cassette path");
  if (typeof adapter !== "string" || !isAbsolute(adapter)) {
    throw new Blocked("replay_adapter_missing", "a test-owned absolute replay adapter is required for cassette replay");
  }
  const adapterStat = lstatOrNull(adapter);
  if (
    !adapterStat
    || !adapterStat.isFile()
    || adapterStat.isSymbolicLink()
    || (adapterStat.mode & 0o111) === 0
    || (adapterStat.mode & 0o222) !== 0
  ) {
    throw new Blocked("replay_adapter_missing", "the configured replay adapter is not an immutable executable");
  }
  if (options.adapterRoot && !pathIsContained(options.adapterRoot, adapter)) {
    throw new Blocked("replay_adapter_missing", "the replay adapter must be selected from the repository's test-owned seam", {
      adapter,
      adapter_root: resolve(options.adapterRoot),
    });
  }
  if (options.adapterRoot) {
    try { rejectSymlinkAncestors(adapter, "replay adapter"); } catch (error) {
      if (error instanceof Blocked) throw error;
      throw new Blocked("replay_adapter_missing", "the replay adapter path could not be verified", { error: String(error) });
    }
    let adapterRootReal;
    let adapterReal;
    try {
      adapterRootReal = realpathSync(options.adapterRoot);
      adapterReal = realpathSync(adapter);
    } catch (error) {
      throw new Blocked("replay_adapter_missing", "the replay adapter path could not be resolved", { error: String(error) });
    }
    if (!pathIsContained(adapterRootReal, adapterReal)) {
      throw new Blocked("replay_adapter_missing", "the replay adapter resolves outside the test-owned seam");
    }
  }
  assertExecutableDigest(driver, options.driverSha256, "release driver", `${operation} replay adapter invocation`);
  const cassetteStat = lstatOrNull(cassette);
  if (!cassetteStat || !cassetteStat.isFile() || cassetteStat.isSymbolicLink() || (cassetteStat.mode & 0o222) !== 0) {
    throw new Blocked("cassette_not_immutable", "replay cassette is missing or writable");
  }
  const args = [
    "--driver", driver,
    ...driverInvocationArgs(operation, releaseRoot, artifact),
    "--cassette", cassette,
  ];
  const env = {
    PATH: process.env.PATH || "/usr/bin:/bin",
    NODE_PATH: process.env.NODE_PATH,
    TMPDIR: process.env.TMPDIR,
    ZODE_RELEASE_ACCESS_ASSERTION: process.env.ZODE_RELEASE_ACCESS_ASSERTION,
    ZODE_RELEASE_ACCESS_JWT_ASSERTION: process.env.ZODE_RELEASE_ACCESS_JWT_ASSERTION,
    ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER: process.env.ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER,
    ZODE_RELEASE_CONTROLLER_BEARER: process.env.ZODE_RELEASE_CONTROLLER_BEARER,
    ZODE_RELEASE_ACCESS_ISSUER: process.env.ZODE_RELEASE_ACCESS_ISSUER,
    ZODE_RELEASE_ACCESS_JWKS_URL: process.env.ZODE_RELEASE_ACCESS_JWKS_URL,
    ZODE_RELEASE_ACCESS_AUDIENCE: process.env.ZODE_RELEASE_ACCESS_AUDIENCE,
    ZODE_RELEASE_SERVER_LISTEN: process.env.ZODE_RELEASE_SERVER_LISTEN,
    ZODE_RELEASE_ENDPOINT_LISTEN: process.env.ZODE_RELEASE_ENDPOINT_LISTEN,
    ZODE_RELEASE_UI_URL: process.env.ZODE_RELEASE_UI_URL,
    ZODE_RELEASE_REPLAY_EXPECTATION: process.env.ZODE_RELEASE_REPLAY_EXPECTATION,
  };
  for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
  const result = runSync(adapter, args, {
    cwd: dirname(adapter),
    env,
  });
  driverCapture(options, operation, artifact, result);
  return finalizeDriverResult(driver, operation, result, options);
}

function readPointer(releaseRoot, pointer) {
  if (!new Set(["current", "previous"]).has(pointer)) {
    throw new BehaviorFailure("release_pointer_invalid", "release pointer name is not canonical", { pointer });
  }
  const root = assertReleaseRoot(releaseRoot);
  const path = join(root, pointer);
  assertReleasePointerPath(root, path, pointer);
  // existsSync follows symlinks and hides a broken pointer. lstat keeps the
  // torn transition observable instead of treating it as an empty pointer.
  if (!lstatOrNull(path)) return null;
  let target = path;
  try {
    if (lstatSync(path).isSymbolicLink()) {
      try {
        target = realpathSync(path);
      } catch (error) {
        // Before bootstrap (or when previous is intentionally empty), the
        // stable alias may point into the active pointer-state directory
        // without a corresponding entry.  That is a canonical null pointer;
        // any other broken link remains a torn-pointer failure.
        const alias = readlinkSync(path);
        const stateLink = join(root, "pointer-state");
        const stateStat = lstatOrNull(stateLink);
        if (
          alias === `pointer-state/${pointer}`
          && stateStat?.isSymbolicLink()
        ) {
          try {
            const stateRoot = realpathSync(stateLink);
            if (pathIsContained(root, stateRoot) && !lstatOrNull(join(stateRoot, pointer))) return null;
          } catch {
            // Fall through to the torn-pointer error below.
          }
        }
        throw error;
      }
    }
    assertReleasePointerPath(root, target, pointer);
  } catch (error) {
    if (error instanceof BehaviorFailure) throw error;
    throw new BehaviorFailure("torn_release_pointer", `${pointer} could not be resolved`, {
      error: String(error),
    });
  }
  const manifestPath = join(target, "manifest.json");
  assertReleasePointerPath(root, manifestPath, `${pointer}/manifest.json`);
  try {
    const manifestStat = lstatOrNull(manifestPath);
    if (!manifestStat || !manifestStat.isFile() || manifestStat.isSymbolicLink() || (manifestStat.mode & 0o222) !== 0) {
      throw new Error("pointer manifest is not a regular file");
    }
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.schema !== SCHEMA || typeof manifest.revision !== "string") {
      throw new Error("invalid release manifest schema");
    }
    assertManifestEnvelope(manifestPath, manifest, { pointer, path: manifestPath });
    // Pointer metadata is an artifact admission boundary as well.  Validate
    // the immutable UI/binary digests here, before any state comparison or
    // health claim can rely on a same-revision forged manifest.
    e2e_release_artifact_binds_server_endpoint_and_ui_tree({
      artifact: { artifact: target, manifest, manifestPath },
      label: `pointer:${pointer}`,
      revision: manifest.revision,
    });
    return { path, target, manifest };
  } catch (error) {
    if (error instanceof BehaviorFailure) throw error;
    throw new BehaviorFailure("torn_release_pointer", `${pointer} does not resolve to a valid manifest`, {
      path,
      error: String(error),
    });
  }
}

function pointerSnapshot(releaseRoot) {
  const root = assertReleaseRoot(releaseRoot);
  const snapshot = {};
  for (const pointer of ["current", "previous"]) {
    const path = join(root, pointer);
    assertReleasePointerPath(root, path, pointer);
    const observed = readPointer(root, pointer);
    if (!observed) {
      snapshot[pointer] = null;
      continue;
    }
    const link = lstatSync(path);
    const target = link.isSymbolicLink() ? readlinkSync(path) : null;
    snapshot[pointer] = {
      kind: link.isSymbolicLink() ? "symlink" : link.isDirectory() ? "directory" : "other",
      target,
      resolved: observed.target,
      manifest_sha256: sha256(readFileSync(join(observed.target, "manifest.json"))),
    };
  }
  return snapshot;
}

function assertSnapshotEqual(before, after, phase) {
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new BehaviorFailure("current_previous_mutated", `${phase}: current/previous changed unexpectedly`, {
      before,
      after,
    });
  }
}

function assertPointers(releaseRoot, expectedCurrent, expectedPrevious, phase) {
  const current = readPointer(releaseRoot, "current");
  const previous = readPointer(releaseRoot, "previous");
  if (!current || current.manifest.revision !== expectedCurrent) {
    throw new BehaviorFailure("current_revision_mismatch", `${phase}: current is not the expected revision`, {
      expected: expectedCurrent,
      observed: current?.manifest?.revision ?? null,
    });
  }
  const observedPrevious = previous?.manifest?.revision ?? null;
  if (observedPrevious !== expectedPrevious) {
    throw new BehaviorFailure("previous_revision_mismatch", `${phase}: previous is not the expected revision`, {
      expected: expectedPrevious,
      observed: observedPrevious,
    });
  }
  return { current, previous };
}

function manifestFileDigest(manifestPath) {
  return sha256(readFileSync(manifestPath));
}

function pointerArtifactIdentity(pointerResult) {
  return pointerResult
    ? {
        revision: pointerResult.manifest.revision,
        manifest_sha256: manifestFileDigest(join(pointerResult.target, "manifest.json")),
      }
    : { revision: null, manifest_sha256: null };
}

function expectedArtifactIdentity(artifact) {
  return artifact
    ? { revision: artifact.manifest.revision, manifest_sha256: manifestFileDigest(artifact.manifestPath) }
    : { revision: null, manifest_sha256: null };
}

function artifactPayloadSnapshot(artifact, label) {
  try {
    const manifestPath = artifact.manifestPath;
    const uiPath = join(artifact.artifact, "ui");
    const serverPath = join(artifact.artifact, "zode-server");
    const endpointPath = join(artifact.artifact, "zode");
    const driverPath = artifact.driverPath ?? join(artifact.artifact, "release-driver");
    const manifestStat = lstatOrNull(manifestPath);
    const serverStat = lstatOrNull(serverPath);
    const endpointStat = lstatOrNull(endpointPath);
    const driverStat = lstatOrNull(driverPath);
    const artifactStat = lstatOrNull(artifact.artifact);
    if (
      !artifactStat
      || !artifactStat.isDirectory()
      || !manifestStat
      || !serverStat
      || !endpointStat
      || !driverStat
      || !manifestStat.isFile()
      || !serverStat.isFile()
      || !endpointStat.isFile()
      || !driverStat.isFile()
      || (artifactStat.mode & 0o222) !== 0
      || (manifestStat.mode & 0o222) !== 0
      || (serverStat.mode & 0o222) !== 0
      || (endpointStat.mode & 0o222) !== 0
      || (driverStat.mode & 0o222) !== 0
    ) {
      throw new Error("artifact component is missing or not a regular file");
    }
    assertImmutableTree(uiPath, "UI artifact tree");
    return {
      label,
      revision: artifact.revision,
      manifest_sha256: sha256(readFileSync(manifestPath)),
      manifest_mode: manifestStat.mode & 0o777,
      ui_tree_sha256: treeDigest(uiPath),
      server_binary_sha256: sha256(readFileSync(serverPath)),
      server_mode: serverStat.mode & 0o777,
      endpoint_binary_sha256: sha256(readFileSync(endpointPath)),
      endpoint_mode: endpointStat.mode & 0o777,
      driver_binary_sha256: sha256(readFileSync(driverPath)),
      driver_mode: driverStat.mode & 0o777,
    };
  } catch (error) {
    throw new BehaviorFailure("staged_payload_mutated", `${label}: packaged release payload is unreadable`, {
      e2e_name: PROMOTION_REVISION_E2E,
      revision: artifact?.revision ?? null,
      error: String(error),
    });
  }
}

function assertArtifactPayloadUnchanged(before, artifact, phase) {
  const after = artifactPayloadSnapshot(artifact, before.label);
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new BehaviorFailure("staged_payload_mutated", `${phase}: staged artifact payload changed after it was handed to the release driver`, {
      e2e_name: PROMOTION_REVISION_E2E,
      before,
      after,
    });
  }
}

function snapshotArtifacts(artifacts) {
  return Object.fromEntries(
    Object.entries(artifacts).map(([label, artifact]) => [label, artifactPayloadSnapshot(artifact, label)]),
  );
}

function assertArtifactsUnchanged(artifacts, snapshots, phase) {
  for (const [label, artifact] of Object.entries(artifacts)) {
    assertArtifactPayloadUnchanged(snapshots[label], artifact, phase);
  }
}

function assertPointerArtifact(releaseRoot, pointer, expectedArtifact, phase) {
  const observed = readPointer(releaseRoot, pointer);
  const expected = expectedArtifactIdentity(expectedArtifact);
  const actual = pointerArtifactIdentity(observed);
  if (!observed || actual.revision !== expected.revision || actual.manifest_sha256 !== expected.manifest_sha256) {
    throw new BehaviorFailure("release_pointer_artifact_mismatch", `${phase}: ${pointer} is not the expected artifact`, {
      e2e_name: PROMOTION_REVISION_E2E,
      pointer,
      expected,
      observed: actual,
    });
  }
  e2e_release_artifact_binds_server_endpoint_and_ui_tree({
    artifact: {
      artifact: observed.target,
      manifest: observed.manifest,
      manifestPath: join(observed.target, "manifest.json"),
      revision: expected.revision,
    },
    label: `${phase}:${pointer}`,
    revision: expected.revision,
  });
  return observed;
}

function assertReleaseState(releaseRoot, expectedCurrent, expectedPrevious, phase) {
  const current = expectedCurrent
    ? assertPointerArtifact(releaseRoot, "current", expectedCurrent, phase)
    : readPointer(releaseRoot, "current");
  const previous = expectedPrevious
    ? assertPointerArtifact(releaseRoot, "previous", expectedPrevious, phase)
    : readPointer(releaseRoot, "previous");
  if (!expectedCurrent && current) {
    throw new BehaviorFailure("current_revision_mismatch", `${phase}: current should be empty`, {
      e2e_name: PROMOTION_REVISION_E2E,
      observed: pointerArtifactIdentity(current),
    });
  }
  if (!expectedPrevious && previous) {
    throw new BehaviorFailure("previous_revision_mismatch", `${phase}: previous should be empty`, {
      e2e_name: PROMOTION_REVISION_E2E,
      observed: pointerArtifactIdentity(previous),
    });
  }
  return { current, previous };
}

function healthBindingFailure(code, message, details = {}) {
  throw new BehaviorFailure(code, message, {
    e2e_name: PROMOTION_REVISION_E2E,
    ...details,
  });
}

function runtimeBindingFromArtifact(artifact) {
  const components = artifact.manifest.components;
  return {
    revision: artifact.manifest.revision,
    ui_revision: components.ui.revision,
    server_revision: components.server.revision,
    endpoint_revision: components.endpoint.revision,
    ui_tree_sha256: components.ui.tree_sha256,
    server_binary_sha256: components.server.binary_sha256,
    endpoint_binary_sha256: components.endpoint.binary_sha256,
  };
}

function assertRuntimeBinding(observed, expectedArtifact, phase, source) {
  const expected = runtimeBindingFromArtifact(expectedArtifact);
  const actual = {
    revision: observed?.revision ?? null,
    ui_revision: observed?.ui_revision ?? null,
    server_revision: observed?.server_revision ?? null,
    endpoint_revision: observed?.endpoint_revision ?? null,
    ui_tree_sha256: observed?.ui_tree_sha256 ?? null,
    server_binary_sha256: observed?.server_binary_sha256 ?? null,
    endpoint_binary_sha256: observed?.endpoint_binary_sha256 ?? null,
  };
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    healthBindingFailure("release_runtime_revision_mismatch", `${phase}: ${source} mixes release component revisions`, {
      phase,
      source,
      expected,
      observed: actual,
    });
  }
  return actual;
}

function assertHealthPayload(payload, expectedArtifact, phase) {
  if (
    payload?.status !== "ok"
    || payload?.source !== "live_process"
    || payload?.ui_mode !== "assets"
    || payload?.ui_assets_directory !== "ui"
    || !payload.components
    || payload.checks?.ui !== "ok"
    || payload.checks?.server !== "ok"
    || payload.checks?.endpoint !== "ok"
  ) {
    healthBindingFailure("release_health_invalid", `${phase}: health did not return a complete runtime binding`, {
      phase,
      observed_status: payload?.status ?? null,
      observed_source: payload?.source ?? null,
      observed_ui_mode: payload?.ui_mode ?? null,
      observed_ui_assets_directory: payload?.ui_assets_directory ?? null,
      observed_checks: payload?.checks ?? null,
    });
  }
  const health = {
    revision: payload.revision,
    ui_revision: payload.components.ui?.revision,
    server_revision: payload.components.server?.revision,
    endpoint_revision: payload.components.endpoint?.revision,
    ui_tree_sha256: payload.components.ui?.tree_sha256,
    server_binary_sha256: payload.components.server?.binary_sha256,
    endpoint_binary_sha256: payload.components.endpoint?.binary_sha256,
  };
  return assertRuntimeBinding(health, expectedArtifact, phase, "real release health");
}

function assertRealHealthFailure(result, failedArtifact, phase) {
  if (result.status === 0) {
    throw new Blocked("failed_fixture_healthy", `${phase}: the failed revision passed the real health gate`);
  }
  const payload = result.payload?.health;
  const checks = payload?.checks;
  if (
    !payload
    || payload.source !== "live_process"
    || payload.ui_mode !== "assets"
    || payload.ui_assets_directory !== "ui"
    || payload.status === "ok"
    || !payload.components
    || !checks
    || [checks.ui, checks.server, checks.endpoint].every((check) => check === "ok")
  ) {
    throw new Blocked("health_failure_protocol", `${phase}: failed staging did not report a live process health failure`, {
      status: result.status,
      observed_status: payload?.status ?? null,
      observed_source: payload?.source ?? null,
      observed_ui_mode: payload?.ui_mode ?? null,
      observed_ui_assets_directory: payload?.ui_assets_directory ?? null,
      observed_checks: checks ?? null,
    });
  }
  const observed = {
    revision: payload.revision,
    ui_revision: payload.components.ui?.revision,
    server_revision: payload.components.server?.revision,
    endpoint_revision: payload.components.endpoint?.revision,
    ui_tree_sha256: payload.components.ui?.tree_sha256,
    server_binary_sha256: payload.components.server?.binary_sha256,
    endpoint_binary_sha256: payload.components.endpoint?.binary_sha256,
  };
  const expected = runtimeBindingFromArtifact(failedArtifact);
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    healthBindingFailure("release_health_failure_revision_mismatch", `${phase}: reported health failure is not for the staged failed artifact`, {
      phase,
      expected,
      observed,
    });
  }
  return observed;
}

function releaseProcessTable(releaseRoot, phase) {
  const root = resolve(releaseRoot);
  assertReleaseRoot(root);
  let result;
  try {
    // `comm` is the kernel-reported executable name; process discovery must
    // not depend on the release root being copied into argv.
    result = runSync("ps", ["-axo", "pid=,ppid=,stat=,comm="]);
  } catch (error) {
    throw new BehaviorFailure("release_process_probe_failed", `${phase}: cannot inspect live release processes`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      error: String(error),
    });
  }
  if (result.status !== 0) {
    throw new BehaviorFailure("release_process_probe_failed", `${phase}: process table probe failed`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      status: result.status,
      stderr: result.stderr.trim().slice(-1000),
    });
  }
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/);
      if (!match) return null;
      const [, pid, ppid, stat, comm] = match;
      return { pid: Number(pid), ppid: Number(ppid), stat, comm };
    })
    .filter(Boolean);
}

function processExecutablePath(entry, phase) {
  const procPath = `/proc/${entry.pid}/exe`;
  if (lstatOrNull(procPath)) {
    try {
      return realpathSync(procPath);
    } catch (error) {
      throw new BehaviorFailure("release_process_probe_failed", `${phase}: live PID executable could not be resolved`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        pid: entry.pid,
        error: String(error),
      });
    }
  }
  let result;
  try {
    result = runSync("lsof", ["-nP", "-a", "-p", String(entry.pid), "-d", "txt", "-Fn"]);
  } catch (error) {
    throw new BehaviorFailure("release_process_probe_failed", `${phase}: no executable probe is available for live PID`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      pid: entry.pid,
      error: String(error),
    });
  }
  if (result.status !== 0) {
    throw new BehaviorFailure("release_process_probe_failed", `${phase}: lsof could not inspect live PID`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      pid: entry.pid,
      status: result.status,
      stderr: result.stderr.trim().slice(-1000),
    });
  }
  const pathLine = result.stdout.split(/\r?\n/).find((line) => line.startsWith("n"));
  if (!pathLine || pathLine.length === 1) {
    throw new BehaviorFailure("release_process_probe_failed", `${phase}: lsof returned no live executable`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      pid: entry.pid,
    });
  }
  return pathLine.slice(1);
}

function processDescendantPids(entries, roots) {
  const pids = new Set(roots);
  let changed = true;
  while (changed) {
    changed = false;
    for (const entry of entries) {
      if (pids.has(entry.ppid) && !pids.has(entry.pid)) {
        pids.add(entry.pid);
        changed = true;
      }
    }
  }
  return [...pids];
}

function locatorPathsFromHealth(health, phase) {
  const processes = health?.processes;
  if (!processes || typeof processes !== "object" || Array.isArray(processes)) {
    throw new Blocked("release_process_locator_missing", `${phase}: live health omitted process locator evidence`);
  }
  exactObjectKeys(processes, new Set(["locator_paths"]), new Set(), "health.processes");
  if (!Array.isArray(processes.locator_paths) || processes.locator_paths.length !== 2) {
    throw new Blocked("release_process_locator_missing", `${phase}: health.processes.locator_paths must contain Server and Endpoint locators`);
  }
  if (processes.locator_paths.some((path) => typeof path !== "string" || !isAbsolute(path))) {
    throw new Blocked("release_process_locator_invalid", `${phase}: process locator paths must be absolute`);
  }
  if (new Set(processes.locator_paths).size !== processes.locator_paths.length) {
    throw new Blocked("release_process_locator_invalid", `${phase}: process locator paths are not unique`);
  }
  return processes.locator_paths;
}

function processIdentityProbe(pid, phase) {
  const result = runSync("ps", ["-p", String(pid), "-o", "pid=,pgid=,sid="]);
  if (result.status !== 0) {
    throw new BehaviorFailure("release_process_missing", `${phase}: locator PID is not live`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      pid,
    });
  }
  const match = result.stdout.trim().match(/^(\d+)\s+(\d+)\s+(\d+)$/);
  if (!match) {
    throw new BehaviorFailure("release_process_probe_failed", `${phase}: locator PID identity probe was malformed`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      pid,
    });
  }
  return { pid: Number(match[1]), process_group_id: Number(match[2]), session_id: match[3] };
}

function assertLiveReleaseProcesses(releaseRoot, expectedArtifact, phase, health) {
  const root = assertReleaseRoot(releaseRoot);
  const locatorPaths = locatorPathsFromHealth(health, phase);
  const locators = locatorPaths.map((path) => {
    if (!pathIsContained(root, path) || !path.includes(`${sep}instances${sep}`)) {
      throw new BehaviorFailure("release_process_instance_mismatch", `${phase}: locator is outside this release instance namespace`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        path,
        release_root: root,
      });
    }
    assertOwnedFilePath(root, path, `${phase}: process locator`);
    const stat = lstatOrNull(path);
    if (!stat || (stat.mode & 0o222) !== 0 || (stat.mode & 0o777) !== 0o444) {
      throw new BehaviorFailure("release_process_locator_invalid", `${phase}: locator is not an immutable driver-owned file`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        path,
      });
    }
    return validateProcessLocator(path, phase);
  });
  const instances = new Set(locators.map((locator) => locator.instance_id));
  if (instances.size !== 1) {
    throw new BehaviorFailure("release_process_instance_mismatch", `${phase}: Server and Endpoint locators are not from one release instance`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      instances: [...instances],
    });
  }
  const roles = new Set(locators.map((locator) => locator.role));
  if (roles.size !== 2 || !roles.has("server") || !roles.has("endpoint")) {
    throw new BehaviorFailure("release_process_topology", `${phase}: locator evidence does not contain one Server and one Endpoint`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      roles: [...roles],
    });
  }
  const expected = expectedArtifact.manifest.components;
  const byRole = {};
  for (const locator of locators) {
    const identity = processIdentityProbe(locator.pid, phase);
    if (identity.process_group_id !== locator.process_group_id || identity.session_id !== locator.session_id) {
      throw new BehaviorFailure("release_process_instance_mismatch", `${phase}: live PID identity does not match its locator`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role: locator.role,
        pid: locator.pid,
      });
    }
    const executable = processExecutablePath({ pid: locator.pid }, phase);
    const resolvedLocatorExecutable = realpathSync(locator.executable_path);
    if (executable !== resolvedLocatorExecutable) {
      throw new BehaviorFailure("release_process_instance_mismatch", `${phase}: locator executable does not own its live PID`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role: locator.role,
        pid: locator.pid,
      });
    }
    const digest = sha256(readFileSync(executable));
    const expectedDigest = locator.role === "server" ? expected.server.binary_sha256 : expected.endpoint.binary_sha256;
    if (digest !== locator.executable_sha256 || digest !== expectedDigest) {
      throw new BehaviorFailure("release_process_digest_mismatch", `${phase}: live executable is not the locator and artifact digest`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role: locator.role,
        pid: locator.pid,
        expected: expectedDigest,
        observed: digest,
      });
    }
    const stat = lstatOrNull(executable);
    if (!stat || stat.isSymbolicLink() || (stat.mode & 0o222) !== 0 || (stat.mode & 0o111) === 0) {
      throw new BehaviorFailure("release_process_executable_invalid", `${phase}: live ${locator.role} executable is not immutable`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role: locator.role,
        pid: locator.pid,
      });
    }
    byRole[locator.role] = { pid: locator.pid, executable, locator };
  }
  const entries = releaseProcessTable(releaseRoot, phase);
  const entryByPid = new Map(entries.map((entry) => [entry.pid, entry]));
  if (entryByPid.get(byRole.endpoint.pid)?.ppid !== byRole.server.pid) {
    throw new BehaviorFailure("release_process_topology", `${phase}: Endpoint PID is not the Server's direct child`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      server_pid: byRole.server.pid,
      endpoint_pid: byRole.endpoint.pid,
      observed_parent_pid: entryByPid.get(byRole.endpoint.pid)?.ppid ?? null,
    });
  }
  const pids = processDescendantPids(entries, [byRole.server.pid, byRole.endpoint.pid]);
  return {
    ...byRole,
    instance_id: locators[0].instance_id,
    locator_paths: locatorPaths,
    pids,
  };
}

function assertReleaseProcessesReaped(releaseRoot, phase, observedPids = [], stopReports = [], observedEvidence = new Map()) {
  if (!Array.isArray(stopReports) || !stopReports.length) {
    throw new Blocked("release_process_stop_missing", `${phase}: teardown did not return process-stop.v1 evidence`);
  }
  for (const report of stopReports) {
    validateProcessStop(report, phase);
    if (report.timed_out || report.leaked_pids.length || report.flush_status !== "success" || report.exit_status !== 0) {
      throw new BehaviorFailure("release_process_stop_failed", `${phase}: process-stop.v1 reported an incomplete stop`, {
        e2e_name: PROMOTION_REVISION_E2E,
        instance_id: report.instance_id,
        timed_out: report.timed_out,
        leaked_pids: report.leaked_pids,
        exit_status: report.exit_status,
        flush_status: report.flush_status,
      });
    }
    for (const entry of report.observed_pids) {
      const expected = observedEvidence.get(entry.pid);
      if (expected && (
        entry.role !== expected.role
        || entry.started_at_unix_ms !== expected.started_at_unix_ms
        || entry.process_group_id !== expected.process_group_id
        || entry.session_id !== expected.session_id
        || entry.executable_path !== expected.executable
        || entry.executable_sha256 !== expected.executable_sha256
      )) {
        throw new BehaviorFailure("release_process_stop_mismatch", `${phase}: stop evidence disagrees with the independently observed locator`, {
          e2e_name: PROMOTION_REVISION_E2E,
          pid: entry.pid,
          expected,
          observed: entry,
        });
      }
    }
    const observed = new Set(report.observed_pids.map((entry) => entry.pid));
    for (const pid of observed) {
      if (!report.reaped_pids.includes(pid)) {
        throw new BehaviorFailure("release_process_stop_failed", `${phase}: stop report omitted an observed PID from reaped_pids`, {
          e2e_name: PROMOTION_REVISION_E2E,
          instance_id: report.instance_id,
          pid,
        });
      }
    }
  }
  let persistent = [];
  if (observedPids.length) {
    let result;
    try {
      result = runSync("ps", ["-p", observedPids.join(","), "-o", "pid=,ppid=,stat=,comm="]);
    } catch (error) {
      throw new BehaviorFailure("release_process_probe_failed", `${phase}: observed release PIDs could not be rechecked`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        observed_pids: observedPids,
        error: String(error),
      });
    }
    persistent = result.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  }
  if (persistent.length) {
    throw new BehaviorFailure("release_process_leaked", `${phase}: release Server/Endpoint state was not reaped`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      observed_pid_state: persistent,
    });
  }
}

function assertLocalHealthProbeUrl(value, role, phase) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Blocked("release_http_probe_invalid", `${phase}: ${role} readiness URL is invalid`, { role });
  }
  if (url.protocol !== "http:" || !new Set(["127.0.0.1", "localhost", "::1"]).has(url.hostname)) {
    throw new Blocked("release_http_probe_not_local", `${phase}: ${role} readiness URL is not local HTTP`, {
      role,
      host: url.hostname,
      protocol: url.protocol,
    });
  }
  const expectedPath = role === "server" ? "/v1/system" : "/v1/health";
  if (url.pathname !== expectedPath) {
    throw new Blocked("release_http_probe_invalid", `${phase}: ${role} readiness URL is not the canonical public route`, {
      role,
      expected_path: expectedPath,
      observed_path: url.pathname,
    });
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Blocked("release_http_probe_invalid", `${phase}: ${role} readiness URL contains credentials or opaque query state`, {
      role,
    });
  }
  return url.toString();
}

function healthProbeHeaders(role, phase) {
  if (role === "server" || role === "ui") {
    const assertion = process.env.ZODE_RELEASE_ACCESS_ASSERTION
      || process.env.ZODE_RELEASE_ACCESS_JWT_ASSERTION;
    if (!assertion) {
      throw new Blocked("release_http_probe_auth_missing", `${phase}: local Server probe requires a test-channel Access assertion`, {
        role,
        required_env: "ZODE_RELEASE_ACCESS_ASSERTION",
      });
    }
    return [`Cf-Access-Jwt-Assertion: ${assertion}`];
  }
  const bearer = process.env.ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER
    || process.env.ZODE_RELEASE_CONTROLLER_BEARER;
  if (!bearer) {
    throw new Blocked("release_http_probe_auth_missing", `${phase}: local Endpoint probe requires a test-channel controller bearer`, {
      role,
      required_env: "ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER",
    });
  }
  return [`Authorization: Bearer ${bearer}`];
}

function readRealHttpResponse(url, role, phase) {
  const probeHeaders = healthProbeHeaders(role, phase);
  const probeRoot = mkdtempSync(join(tmpdir(), "zode-release-http-probe-"));
  const bodyPath = join(probeRoot, "body");
  let result;
  try {
    result = runSync("curl", [
      "--silent",
      "--show-error",
      "--noproxy",
      "*",
      "--max-time",
      "5",
      "--max-redirs",
      "0",
      ...probeHeaders.flatMap((header) => ["--header", header]),
      "--output",
      bodyPath,
      "--write-out",
      "%{http_code}",
      url,
    ]);
  } catch (error) {
    rmSync(probeRoot, { recursive: true, force: true });
    throw new Blocked("release_http_probe_unavailable", `${phase}: curl is required for independent HTTP readiness`, {
      role,
      error: String(error),
    });
  }
  try {
    const bodyStat = lstatOrNull(bodyPath);
    if (bodyStat && bodyStat.size > BODY_LIMIT) {
      throw new BehaviorFailure("release_http_body_oversize", `${phase}: real ${role} HTTP body exceeded the bounded probe size`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role,
        bytes: bodyStat.size,
        limit: BODY_LIMIT,
      });
    }
    const body = bodyStat ? readFileSync(bodyPath) : Buffer.alloc(0);
    const statusText = result.stdout.trim();
    const status = /^\d{3}$/.test(statusText) ? Number(statusText) : null;
    return {
      role,
      url: safeUrl(url),
      status,
      transport_status: result.status,
      body,
      body_bytes: body.length,
      body_sha256: sha256(body),
      stderr: result.stderr.trim().slice(-1000),
    };
  } finally {
    rmSync(probeRoot, { recursive: true, force: true });
  }
}

function parseRealHealthBody(observation, role) {
  const text = observation.body.toString("utf8");
  if (!text.trim()) {
    return { valid: false, ready: false, schema: null, error: "empty body" };
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    return { valid: false, ready: false, schema: null, error: `invalid JSON: ${String(error)}` };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { valid: false, ready: false, schema: null, error: "body is not a JSON object" };
  }
  if (role === "server") {
    const valid = value.schema === "zode.system.v1"
      && value.deployment === "all_in_one"
      && typeof value.local_endpoint_id === "string"
      && value.ingress?.management_auth === "cloudflare_access"
      && value.ingress?.callback_origin === "separate"
      && typeof value.features?.remote_endpoints === "boolean"
      && typeof value.features?.provider_auth === "boolean";
    return {
      valid,
      ready: valid,
      schema: typeof value.schema === "string" ? value.schema : null,
      error: valid ? null : "body does not match zode.system.v1",
    };
  }
  const valid = value.schema === "zode.endpoint-health.v1"
    && typeof value.protocol_version === "string"
    && typeof value.endpoint_id === "string"
    && typeof value.status === "string";
  return {
    valid,
    ready: valid && value.status === "ready",
    schema: typeof value.schema === "string" ? value.schema : null,
    error: valid ? null : "body does not match zode.endpoint-health.v1",
  };
}

function publicHttpObservation(observation) {
  return {
    role: observation.role,
    url: observation.url,
    status: observation.status,
    transport_status: observation.transport_status,
    body_bytes: observation.body_bytes,
    body_sha256: observation.body_sha256,
    body_schema: observation.parsed?.schema ?? null,
    body_valid: observation.parsed?.valid ?? false,
    body_ready: observation.parsed?.ready ?? false,
  };
}

function assertHttpProbeOwnedByProcess(url, role, processEvidence, phase, label = role) {
  const owner = processEvidence?.[role];
  if (!owner || !Number.isSafeInteger(owner.pid) || owner.pid <= 0) {
    throw new BehaviorFailure("release_http_listener_mismatch", `${phase}: no live ${label} listener owner PID is available`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      role: label,
      url: safeUrl(url),
    });
  }
  const parsed = new URL(url);
  const port = parsed.port || (parsed.protocol === "http:" ? "80" : "443");
  let result;
  try {
    // The listener owner is the independently observed release process, not
    // this harness.  Using process.pid here would only prove that the test
    // process itself does not own the port and would turn every valid release
    // into a false mismatch.
    result = runSync("lsof", ["-nP", "-a", "-p", String(owner.pid), `-iTCP:${port}`, "-sTCP:LISTEN", "-Fn"]);
  } catch (error) {
    throw new Blocked("release_http_probe_unavailable", `${phase}: lsof is required to bind HTTP readiness to the live PID`, {
      role: label,
      error: String(error),
    });
  }
  if (result.status !== 0 || !result.stdout.split(/\r?\n/).some((line) => line.startsWith("n"))) {
    throw new BehaviorFailure("release_http_listener_mismatch", `${phase}: ${label} listener is not owned by its expected live PID`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      role: label,
      owner_role: role,
      pid: owner.pid,
      port,
      url: safeUrl(url),
      status: result.status,
    });
  }
}

function assertRealHttpReadiness(health, phase, processEvidence, options = {}) {
  const expectHealthy = options.expectHealthy !== false;
  const probes = health?.probes;
  if (!probes || typeof probes.server_url !== "string" || typeof probes.endpoint_url !== "string") {
    throw new Blocked("release_http_probe_missing", `${phase}: driver health did not expose independent Server/Endpoint readiness URLs`, {
      required: ["health.probes.server_url", "health.probes.endpoint_url"],
    });
  }
  const serverUrl = assertLocalHealthProbeUrl(probes.server_url, "server", phase);
  const endpointUrl = assertLocalHealthProbeUrl(probes.endpoint_url, "endpoint", phase);
  assertHttpProbeOwnedByProcess(serverUrl, "server", processEvidence, phase);
  assertHttpProbeOwnedByProcess(endpointUrl, "endpoint", processEvidence, phase);
  const observations = [
    readRealHttpResponse(serverUrl, "server", phase),
    readRealHttpResponse(endpointUrl, "endpoint", phase),
  ];
  for (const observation of observations) {
    if ([401, 403, 404].includes(observation.status)) {
      throw new Blocked("release_http_probe_missing", `${phase}: real ${observation.role} readiness route is unavailable`, {
        role: observation.role,
        status: observation.status,
        url: observation.url,
      });
    }
    observation.parsed = observation.status === null
      ? { valid: false, ready: false, schema: null, error: "HTTP transport did not return a status" }
      : parseRealHealthBody(observation, observation.role);
    const statusHealthy = Number.isInteger(observation.status)
      && observation.status >= 200
      && observation.status < 300;
    observation.failed = observation.transport_status !== 0
      || !statusHealthy
      || !observation.parsed.valid
      || !observation.parsed.ready;
    if (expectHealthy && observation.failed) {
      if (!statusHealthy) {
        throw new BehaviorFailure("release_http_not_ready", `${phase}: real ${observation.role} HTTP readiness was not successful`, {
          e2e_name: PROMOTION_REVISION_E2E,
          phase,
          ...publicHttpObservation(observation),
          stderr: observation.stderr,
        });
      }
      throw new BehaviorFailure("release_http_body_invalid", `${phase}: real ${observation.role} readiness body was not the expected public contract`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        ...publicHttpObservation(observation),
        body_error: observation.parsed.error,
      });
    }
  }
  // A staged instance deliberately uses isolated listeners.  When no stable
  // browser URL is supplied, probe its own UI origin derived from the same
  // live Server readiness URL instead of accidentally checking current.
  const uiUrl = options.uiUrl ?? `${new URL(serverUrl).origin}/`;
  if (uiUrl) {
    observations.push(probeUiListener(uiUrl, processEvidence, phase, {
      expectHealthy,
      expectedArtifact: options.expectedArtifact,
    }));
  }
  return observations;
}

function servedUiAssetReferences(html) {
  const references = new Set(["/index.html"]);
  const pattern = /\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  for (const match of html.matchAll(pattern)) {
    const value = String(match[1] ?? "").split(/[?#]/, 1)[0];
    if (value.startsWith("/")) references.add(value);
  }
  return [...references].sort();
}

function assertServedUiTree(uiUrl, rootObservation, expectedArtifact, phase) {
  if (!expectedArtifact) return;
  const uiRoot = join(expectedArtifact.artifact, "ui");
  const indexPath = join(uiRoot, "index.html");
  const indexStat = lstatOrNull(indexPath);
  if (!indexStat || !indexStat.isFile() || indexStat.isSymbolicLink()) {
    throw new BehaviorFailure("release_ui_tree_missing", `${phase}: packaged UI has no index.html`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      path: indexPath,
    });
  }
  const expectedIndex = readFileSync(indexPath);
  if (sha256(expectedIndex) !== rootObservation.body_sha256) {
    throw new BehaviorFailure("release_ui_tree_mismatch", `${phase}: served UI index does not match the selected immutable tree`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      expected: sha256(expectedIndex),
      observed: rootObservation.body_sha256,
    });
  }
  const html = rootObservation.body.toString("utf8");
  for (const reference of servedUiAssetReferences(html)) {
    let url;
    try { url = new URL(reference, uiUrl); } catch { throw new BehaviorFailure("release_ui_tree_mismatch", `${phase}: UI asset URL is invalid`, { e2e_name: PROMOTION_REVISION_E2E, phase, reference }); }
    if (url.origin !== new URL(uiUrl).origin || url.search || url.hash) {
      throw new BehaviorFailure("release_ui_tree_mismatch", `${phase}: UI asset reference leaves the selected origin`, { e2e_name: PROMOTION_REVISION_E2E, phase, reference });
    }
    const relativePath = decodeURIComponent(url.pathname).replace(/^\//, "");
    const localPath = resolve(uiRoot, relativePath);
    if (!pathIsContained(uiRoot, localPath)) {
      throw new BehaviorFailure("release_ui_tree_mismatch", `${phase}: UI asset reference escapes the immutable tree`, { e2e_name: PROMOTION_REVISION_E2E, phase, reference });
    }
    const fileStat = lstatOrNull(localPath);
    if (!fileStat || !fileStat.isFile() || fileStat.isSymbolicLink()) {
      throw new BehaviorFailure("release_ui_tree_mismatch", `${phase}: served UI asset is absent from the immutable tree`, { e2e_name: PROMOTION_REVISION_E2E, phase, reference, path: localPath });
    }
    const observation = readRealHttpResponse(url.toString(), "ui", phase);
    if (observation.transport_status !== 0 || observation.status < 200 || observation.status >= 300
        || sha256(readFileSync(localPath)) !== observation.body_sha256) {
      throw new BehaviorFailure("release_ui_tree_mismatch", `${phase}: served UI asset bytes do not match the selected immutable tree`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        reference,
        status: observation.status,
        expected: sha256(readFileSync(localPath)),
        observed: observation.body_sha256,
      });
    }
  }
}

function probeUiListener(uiUrl, processEvidence, phase, { expectHealthy = true, expectedArtifact = null } = {}) {
  const url = assertLocalBrowserUrl(uiUrl);
  assertHttpProbeOwnedByProcess(url, "server", processEvidence, phase, "ui");
  const observation = readRealHttpResponse(url, "ui", phase);
  if ([401, 403, 404].includes(observation.status)) {
    throw new Blocked("release_ui_route_missing", `${phase}: real UI listener returned a missing/unauthorized route`, {
      status: observation.status,
      url: safeUrl(url),
    });
  }
  const text = observation.body.toString("utf8").trim();
  const bodyValid = text.length > 0 && /(?:<!doctype\s+html|<html\b|<body\b|<script\b)/i.test(text);
  const statusHealthy = Number.isInteger(observation.status)
    && observation.status >= 200
    && observation.status < 300
    && observation.transport_status === 0;
  observation.parsed = {
    valid: bodyValid,
    ready: statusHealthy && bodyValid,
    schema: "html",
    error: bodyValid ? null : "UI response is not a non-empty HTML document",
  };
  observation.failed = !observation.parsed.ready;
  if (expectHealthy && observation.failed) {
    throw new BehaviorFailure("release_ui_body_invalid", `${phase}: real UI listener did not return a usable document`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      ...publicHttpObservation(observation),
      body_error: observation.parsed.error,
      stderr: observation.stderr,
    });
  }
  if (!observation.failed && expectHealthy) assertServedUiTree(uiUrl, observation, expectedArtifact, phase);
  return observation;
}

function assertFailedStageIndependentObservation(result, failedArtifact, releaseRoot, phase, options = {}) {
  const liveProcesses = assertLiveReleaseProcesses(releaseRoot, failedArtifact, phase, result.payload?.health);
  options.onLiveProcesses?.(liveProcesses);
  const observations = assertRealHttpReadiness(result.payload?.health, phase, liveProcesses, {
    expectHealthy: false,
    uiUrl: null,
    expectedArtifact: failedArtifact,
  });
  const failedObservations = observations.filter((observation) => observation.failed);
  if (!failedObservations.length) {
    throw new Blocked("failed_fixture_healthy", `${phase}: independent live PID/HTTP observations were all healthy`, {
      phase,
      observations: observations.map(publicHttpObservation),
    });
  }
  return { liveProcesses, observations };
}

function assertCandidateStageIndependentObservation(result, candidateArtifact, releaseRoot, phase, options = {}) {
  if (result.status !== 0) {
    throw new Blocked("candidate_stage_failed", `${phase}: candidate staging did not complete`, { status: result.status });
  }
  const liveProcesses = assertLiveReleaseProcesses(releaseRoot, candidateArtifact, phase, result.payload?.health);
  options.onLiveProcesses?.(liveProcesses);
  const observations = assertRealHttpReadiness(result.payload?.health, phase, liveProcesses, {
    expectHealthy: true,
    uiUrl: null,
    expectedArtifact: candidateArtifact,
  });
  const health = assertHealthPayload(result.payload?.health, candidateArtifact, phase);
  return { liveProcesses, observations, health };
}

function readReleaseHealth(driver, releaseRoot, expectedArtifact, phase, options = {}) {
  try {
    const result = options.replay
      ? runReplayAdapter(
        options.replayAdapter,
        driver,
        "health",
        releaseRoot,
        null,
        options.replay,
        {
          capture: options.capture,
          e2eName: PROMOTION_REVISION_E2E,
          driverSha256: options.driverSha256,
          sequenceAllocator: options.sequenceAllocator,
          captureArtifact: expectedArtifact,
          adapterRoot: options.replayAdapterRoot,
        },
      )
      : runDriver(driver, "health", releaseRoot, null, {
      capture: options.capture,
      e2eName: PROMOTION_REVISION_E2E,
      driverSha256: options.driverSha256,
      sequenceAllocator: options.sequenceAllocator,
      captureArtifact: expectedArtifact,
      });
    const liveProcesses = assertLiveReleaseProcesses(releaseRoot, expectedArtifact, phase, result.payload?.health);
    options.onLiveProcesses?.(liveProcesses);
    assertRealHttpReadiness(result.payload?.health, phase, liveProcesses, {
      expectHealthy: true,
      uiUrl: options.uiUrl,
      expectedArtifact,
    });
    if (result.status !== 0) {
      healthBindingFailure("release_health_failed", `${phase}: real release health is not healthy`, {
        phase,
        status: result.status,
      });
    }
    const health = assertHealthPayload(result.payload?.health, expectedArtifact, phase);
    return health;
  } catch (error) {
    if (error instanceof BehaviorFailure && !error.details?.first_failure) {
      error.details = { ...error.details, driver_operation: "health" };
    }
    throw error;
  }
}

function pointerState(releaseRoot) {
  const current = readPointer(releaseRoot, "current");
  const previous = readPointer(releaseRoot, "previous");
  return {
    current: pointerArtifactIdentity(current),
    previous: pointerArtifactIdentity(previous),
  };
}

function expectedPointerState(currentArtifact, previousArtifact) {
  return {
    current: expectedArtifactIdentity(currentArtifact),
    previous: expectedArtifactIdentity(previousArtifact),
  };
}

function pointerStatesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function observePointerTransition(releaseRoot, before, after, phase, action) {
  const root = assertReleaseRoot(releaseRoot);
  const initial = pointerState(root);
  if (!pointerStatesEqual(initial, before)) {
    throw new BehaviorFailure("release_pointer_transition_precondition", `${phase}: pointer state was not stable before the browser action`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      expected: before,
      observed: initial,
    });
  }

  return new Promise((resolvePromise, rejectPromise) => {
    let watcher;
    let timer;
    let settled = false;
    let actionStarted = false;
    let actionCompleted = false;
    const afterPointerEventsObserved = new Set();
    const canonicalPointerNames = new Set(["current", "previous"]);
    const transactionPointerName = "pointer-state";
    const canonicalWatcherEvents = new Set(["rename", "change"]);
    const events = [];

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      watcher?.close();
    };
    const finish = (error, evidence = {}) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) rejectPromise(error);
      else resolvePromise({ before, after, filesystem_events: events, ...evidence });
    };
    const fail = (error, source) => {
      if (error instanceof BehaviorFailure) {
        finish(error);
        return;
      }
      finish(new BehaviorFailure("release_pointer_transition_failed", `${phase}: filesystem transition observation failed`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        source,
        error: String(error),
      }));
    };
    const inspect = (source, event, filename) => {
      if (settled) return;
      try {
        const observed = pointerState(root);
        const isBefore = pointerStatesEqual(observed, before);
        const isAfter = pointerStatesEqual(observed, after);
        if (!isBefore && !isAfter) {
          throw new BehaviorFailure("torn_release_pointer", `${phase}: filesystem watcher observed a non-canonical pointer state`, {
            e2e_name: PROMOTION_REVISION_E2E,
            phase,
            source,
            event,
            filename,
            expected: { before, after },
            observed,
          });
        }
        if (
          actionStarted
          && canonicalWatcherEvents.has(event)
          && (canonicalPointerNames.has(filename) || filename === transactionPointerName)
        ) {
          events.push({ source, event, filename, state: isAfter ? "after" : "before" });
          if (isAfter) {
            if (filename === transactionPointerName) {
              afterPointerEventsObserved.add("current");
              afterPointerEventsObserved.add("previous");
            } else {
              afterPointerEventsObserved.add(filename);
            }
          }
        }
        if (actionCompleted && afterPointerEventsObserved.size === 2) {
          finish(null, { observed });
        }
      } catch (error) {
        fail(error, source);
      }
    };

    try {
      watcher = watch(root, { persistent: false }, (event, filename) => {
        inspect("fs.watch", event, filename ? String(filename) : null);
      });
    } catch (error) {
      fail(error, "fs.watch");
      return;
    }

    timer = setTimeout(() => {
      finish(new BehaviorFailure("pointer_transition_timeout", `${phase}: filesystem transition was not positively observed`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        expected: { before, after },
        filesystem_events: events,
        required_pointer_events: ["current", "previous"],
        observed_after_pointer_events: [...afterPointerEventsObserved],
      }));
    }, 10_000);

    inspect("pre-action", null, null);
    Promise.resolve()
      .then(() => {
        actionStarted = true;
        return action();
      })
      .then(() => {
        actionCompleted = true;
        inspect("post-action", null, null);
        if (afterPointerEventsObserved.size !== 2) return;
        finish(null, { observed: pointerState(root) });
      })
      .catch((error) => fail(error, "browser-action"));
  });
}

function observeStablePointerState(releaseRoot, expected, phase, action) {
  const root = assertReleaseRoot(releaseRoot);
  const initial = pointerSnapshot(root);
  if (JSON.stringify(initial) !== JSON.stringify(expected)) {
    throw new BehaviorFailure("stage_pointer_precondition", `${phase}: release pointers were not stable before staging`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
    });
  }
  return new Promise((resolvePromise, rejectPromise) => {
    let watcher;
    let timer;
    let settled = false;
    const events = [];
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      watcher?.close();
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectPromise(error instanceof BehaviorFailure ? error : new BehaviorFailure("stage_pointer_watch_failed", `${phase}: pointer watcher failed`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        error: String(error),
      }));
    };
    const inspect = (event, filename) => {
      if (settled || !["current", "previous"].includes(filename) || !["rename", "change"].includes(event)) return;
      events.push({ event, filename });
      fail(new BehaviorFailure("stage_pointer_mutated", `${phase}: staging emitted a current/previous filesystem event`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        event,
        filename,
        events,
      }));
    };
    try {
      watcher = watch(root, { persistent: false }, (event, filename) => inspect(event, filename ? String(filename) : null));
    } catch (error) {
      fail(error);
      return;
    }
    timer = setTimeout(() => fail(new BehaviorFailure("stage_pointer_watch_timeout", `${phase}: staging did not finish within the bounded watcher timeout`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
    })), 120_000);
    Promise.resolve()
      .then(action)
      .then(() => {
        if (settled) return;
        const final = pointerSnapshot(root);
        if (JSON.stringify(final) !== JSON.stringify(expected)) {
          fail(new BehaviorFailure("stage_pointer_mutated", `${phase}: staging changed current/previous`, {
            e2e_name: PROMOTION_REVISION_E2E,
            phase,
          }));
          return;
        }
        settled = true;
        cleanup();
        resolvePromise({ expected, observed: final, filesystem_events: events });
      })
      .catch(fail);
  });
}

function resolvePlaywright() {
  try {
    return createRequire(import.meta.url)("playwright");
  } catch {
    const playwrightBinary = process.env.PLAYWRIGHT_BIN
      || runSync("which", ["playwright"]).stdout.trim();
    if (playwrightBinary) {
      const nodeRoot = dirname(dirname(dirname(resolve(playwrightBinary))));
      try {
        return createRequire(import.meta.url)(join(nodeRoot, "lib", "node_modules", "playwright"));
      } catch {
        // Fall through to the explicit blocked result below.
      }
    }
    throw new Blocked("browser_runtime_missing", "Playwright is not available to the harness", {
      hint: "set NODE_PATH or PLAYWRIGHT_BIN to a real Playwright installation",
    });
  }
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}${url.search}`;
  } catch {
    return "<invalid-url>";
  }
}

function assertLocalBrowserUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Blocked("browser_entry_invalid", "ZODE_RELEASE_UI_URL is not a valid URL");
  }
  if (!new Set(["127.0.0.1", "localhost", "::1"]).has(url.hostname)) {
    throw new Blocked("browser_entry_not_local", "release E2E browser entry must be a local test/staging origin", {
      host: url.hostname,
    });
  }
  if (url.username || url.password) {
    throw new Blocked("browser_entry_invalid", "release E2E browser entry must not contain URL credentials");
  }
  return url.toString();
}

function safeHeaders(headers) {
  const allow = new Set(["accept", "content-type", "cache-control"]);
  const result = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (allow.has(name.toLowerCase())) result[name.toLowerCase()] = String(value);
  }
  return result;
}

function boundedBuffer(buffer) {
  const bytes = Buffer.from(buffer ?? []);
  return {
    base64: bytes.subarray(0, BODY_LIMIT).toString("base64"),
    truncated: bytes.length > BODY_LIMIT,
    sha256: sha256(bytes),
  };
}

async function e2e_release_promotion_never_mixes_server_and_ui_revision({
  uiUrl,
  releaseRoot,
  baselineArtifact,
  candidateArtifact,
  healthCheck,
  promoteRelease,
  rollbackRelease,
  replay,
  exchangeSequenceOffset = 0,
  sequenceAllocator,
}) {
  const playwright = resolvePlaywright();
  const executablePath = process.env.ZODE_RELEASE_BROWSER_EXECUTABLE
    || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  const browser = await playwright.chromium.launch({
    executablePath: existsSync(executablePath) ? executablePath : undefined,
    headless: process.env.ZODE_RELEASE_HEADFUL !== "1",
  });
  const accessAssertion = process.env.ZODE_RELEASE_ACCESS_ASSERTION
    || process.env.ZODE_RELEASE_ACCESS_JWT_ASSERTION;
  if (!accessAssertion) {
    await browser.close();
    throw new Blocked("browser_auth_missing", "the real management browser requires a test-channel Access assertion", {
      required_env: "ZODE_RELEASE_ACCESS_ASSERTION",
    });
  }
  const context = await browser.newContext({
    extraHTTPHeaders: { "Cf-Access-Jwt-Assertion": accessAssertion },
  });
  const page = await context.newPage();
  const exchanges = new Map();
  const exchangeList = [];
  const pendingResponses = new Set();
  const browserSystemResponses = [];
  const browserManagementResponses = new Map();
  page.on("request", (request) => {
    const key = `${request.method()} ${safeUrl(request.url())} ${exchangeList.length}`;
    const entry = {
      sequence: sequenceAllocator
        ? sequenceAllocator()
        : exchangeSequenceOffset + exchangeList.length,
      request: {
        method: request.method(),
        path: safeUrl(request.url()),
        headers: safeHeaders(request.headers()),
        body: boundedBuffer(request.postDataBuffer()),
      },
    };
    exchanges.set(request, entry);
    exchangeList.push(entry);
    void key;
  });
  page.on("response", (response) => {
    const entry = exchanges.get(response.request());
    if (!entry) return;
    const pending = (async () => {
      try {
        const prior = entry.response;
        entry.response = {
          status: response.status(),
          headers: safeHeaders(await response.allHeaders()),
          body: boundedBuffer(await Promise.race([
            response.body(),
            sleep(10_000).then(() => { throw new Error("response_body_timeout"); }),
          ])),
          completed: prior?.request_failed === true ? false : true,
          request_failed: prior?.request_failed === true,
          disconnected: prior?.disconnected === true,
          failure: prior?.failure ?? null,
        };
        try {
          const responseUrl = new URL(response.url());
          if (responseUrl.pathname === "/v1/system") {
            let parsed = null;
            try { parsed = JSON.parse(entry.response.body?.base64 ? Buffer.from(entry.response.body.base64, "base64").toString("utf8") : ""); } catch { /* invalid body is reported below */ }
            browserSystemResponses.push({
              status: entry.response.status,
              body_sha256: entry.response.body?.sha256 ?? null,
              parsed,
              exchange: entry,
            });
          }
          if (responseUrl.pathname === "/v1/endpoints" || responseUrl.pathname === "/v1/providers") {
            let parsed = null;
            try { parsed = JSON.parse(entry.response.body?.base64 ? Buffer.from(entry.response.body.base64, "base64").toString("utf8") : ""); } catch { /* invalid body is reported below */ }
            const values = browserManagementResponses.get(responseUrl.pathname) ?? [];
            values.push({ status: entry.response.status, body_sha256: entry.response.body?.sha256 ?? null, parsed, exchange: entry });
            browserManagementResponses.set(responseUrl.pathname, values);
          }
        } catch { /* malformed URLs are recorded as ordinary browser exchanges */ }
      } catch (error) {
        const prior = entry.response;
        entry.response = {
          status: response.status(),
          headers: prior?.headers ?? {},
          body: prior?.body ?? null,
          completed: false,
          request_failed: prior?.request_failed === true,
          disconnected: true,
          failure: prior?.failure ?? String(error),
        };
      } finally {
        pendingResponses.delete(pending);
      }
    })();
    pendingResponses.add(pending);
  });
  page.on("requestfailed", (request) => {
    const entry = exchanges.get(request);
    if (!entry) return;
    const failure = request.failure()?.errorText ?? "requestfailed";
    entry.response = {
      status: entry.response?.status ?? null,
      headers: entry.response?.headers ?? {},
      body: entry.response?.body ?? null,
      completed: false,
      request_failed: true,
      disconnected: true,
      failure,
    };
  });

  try {
    const browserObservationCounts = () => ({
      system: browserSystemResponses.length,
      management: Object.fromEntries([...browserManagementResponses.entries()].map(([pathname, values]) => [pathname, values.length])),
    });
    const assertBrowserSystem = async (phase, since = { system: 0 }) => {
      await Promise.allSettled([...pendingResponses]);
      const observation = browserSystemResponses.slice(since.system ?? 0).at(-1);
      if (
        !observation
        || observation.status < 200
        || observation.status >= 300
        || observation.parsed?.schema !== "zode.system.v1"
        || observation.parsed?.deployment !== "all_in_one"
        || typeof observation.parsed?.local_endpoint_id !== "string"
        || !observation.parsed.local_endpoint_id
      ) {
        throw new BehaviorFailure("browser_server_path_invalid", `${phase}: browser did not receive a valid Access-protected all-in-one system response`, {
          e2e_name: PROMOTION_REVISION_E2E,
          phase,
          observed: observation ?? null,
          first_failure: observation?.exchange ? exchangeIdentity(observation.exchange) : undefined,
        });
      }
      return observation.parsed;
    };
    const assertBrowserManagementApis = async (phase, expectedEndpointId, since = { management: {} }) => {
      await Promise.allSettled([...pendingResponses]);
      for (const [pathname, schema] of [["/v1/endpoints", "zode.endpoints.v1"], ["/v1/providers", "zode.providers.v1"]]) {
        const start = since.management?.[pathname] ?? 0;
        const observation = browserManagementResponses.get(pathname)?.slice(start).at(-1);
        if (!observation || observation.status < 200 || observation.status >= 300 || observation.parsed?.schema !== schema) {
          throw new BehaviorFailure("browser_management_api_invalid", `${phase}: browser did not complete the normal ${pathname} management request`, {
            e2e_name: PROMOTION_REVISION_E2E,
            phase,
            pathname,
            observed: observation ?? null,
            first_failure: observation?.exchange ? exchangeIdentity(observation.exchange) : undefined,
          });
        }
      }
      const endpointStart = since.management?.["/v1/endpoints"] ?? 0;
      const endpoints = browserManagementResponses.get("/v1/endpoints")?.slice(endpointStart).at(-1)?.parsed?.endpoints;
      if (!Array.isArray(endpoints) || !endpoints.some((endpoint) => endpoint?.endpoint_id === expectedEndpointId)) {
        throw new BehaviorFailure("browser_local_endpoint_missing", `${phase}: the Server endpoint catalog does not contain the built-in Endpoint identity`, {
          e2e_name: PROMOTION_REVISION_E2E,
          phase,
          expected_endpoint_id: expectedEndpointId,
          observed_endpoint_ids: Array.isArray(endpoints) ? endpoints.map((endpoint) => endpoint?.endpoint_id ?? null) : null,
          first_failure: browserManagementResponses.get("/v1/endpoints")?.slice(endpointStart).at(-1)?.exchange
            ? exchangeIdentity(browserManagementResponses.get("/v1/endpoints").slice(endpointStart).at(-1).exchange)
            : undefined,
        });
      }
    };
    const response = await page.goto(uiUrl, { waitUntil: "domcontentloaded", timeout: 10_000 });
    const status = response?.status() ?? 0;
    if (status < 200 || status >= 300) {
      throw new Blocked("browser_http_entry", `browser entry returned HTTP ${status}`, {
        url: safeUrl(uiUrl),
      });
    }
    const shell = await page.locator("body").innerText({ timeout: 5_000 }).catch(() => "");
    if (!(shell.includes("Sessions") && shell.includes("Endpoints") && shell.includes("Providers"))) {
      throw new Blocked("browser_shell_missing", "browser reached a document without the real management UI shell", {
        url: safeUrl(uiUrl),
        body_preview: shell.slice(0, 300),
      });
    }

    const state = async () => page.evaluate(() => ({
      body_text: document.body?.innerText?.slice(0, 2_000) ?? "",
      title: document.title ?? "",
    }));
    const initial = await state();
    // The browser is intentionally not a release-control or release-metadata
    // client.  Pointer/manifest/process/digest binding is performed by this
    // harness outside the product.  The browser proves only the real,
    // Access-protected UI -> Server -> built-in Endpoint path is usable.
    if (!initial.body_text.trim()) {
      throw new BehaviorFailure("browser_empty_document", "browser returned an empty management document", {
        e2e_name: PROMOTION_REVISION_E2E,
        observed: initial,
      });
    }
    // No browser observation exists before the first navigation; keep the
    // zero baseline explicit so the first response cannot be mistaken for a
    // stale response from an earlier phase.
    const initialObservation = { system: 0, management: {} };
    const initialSystem = await assertBrowserSystem("before browser promotion", initialObservation);
    await assertBrowserManagementApis("before browser promotion", initialSystem.local_endpoint_id, initialObservation);
    await healthCheck(baselineArtifact, "before browser promotion");

    let promotionObservation;
    await observePointerTransition(
      releaseRoot,
      expectedPointerState(baselineArtifact, null),
      expectedPointerState(candidateArtifact, baselineArtifact),
      "promotion",
      async () => {
        promotionObservation = browserObservationCounts();
        const promotion = await promoteRelease();
        if (promotion.status !== 0) {
          throw new BehaviorFailure("release_promote_failed", "operator promotion did not complete successfully", {
            e2e_name: PROMOTION_REVISION_E2E,
            status: promotion.status,
          });
        }
        await page.reload({ waitUntil: "domcontentloaded", timeout: 10_000 });
      },
    );
    const promotedSystem = await assertBrowserSystem("after browser promotion", promotionObservation);
    await assertBrowserManagementApis("after browser promotion", initialSystem.local_endpoint_id, promotionObservation);
    if (promotedSystem.local_endpoint_id !== initialSystem.local_endpoint_id) {
      throw new BehaviorFailure("release_local_endpoint_identity_changed", "promotion replaced the persistent built-in Endpoint identity", {
        e2e_name: PROMOTION_REVISION_E2E,
        phase: "after browser promotion",
        expected: initialSystem.local_endpoint_id,
        observed: promotedSystem.local_endpoint_id,
      });
    }
    const promoted = await state();
    if (!promoted.body_text.trim()) {
      throw new BehaviorFailure("browser_empty_document", "browser returned an empty document after promotion", {
        e2e_name: PROMOTION_REVISION_E2E,
        observed: promoted,
      });
    }
    const promotedHealth = await healthCheck(candidateArtifact, "after browser promotion");
    assertReleaseState(releaseRoot, candidateArtifact, baselineArtifact, "after browser promotion");

    let rollbackObservation;
    await observePointerTransition(
      releaseRoot,
      expectedPointerState(candidateArtifact, baselineArtifact),
      expectedPointerState(baselineArtifact, candidateArtifact),
      "rollback",
      async () => {
        rollbackObservation = browserObservationCounts();
        const rollback = await rollbackRelease();
        if (rollback.status !== 0) {
          throw new BehaviorFailure("release_rollback_failed", "operator rollback did not complete successfully", {
            e2e_name: PROMOTION_REVISION_E2E,
            status: rollback.status,
          });
        }
        await page.reload({ waitUntil: "domcontentloaded", timeout: 10_000 });
      },
    );
    const rolledBackSystem = await assertBrowserSystem("after browser rollback", rollbackObservation);
    await assertBrowserManagementApis("after browser rollback", initialSystem.local_endpoint_id, rollbackObservation);
    if (rolledBackSystem.local_endpoint_id !== initialSystem.local_endpoint_id) {
      throw new BehaviorFailure("release_local_endpoint_identity_changed", "rollback replaced the persistent built-in Endpoint identity", {
        e2e_name: PROMOTION_REVISION_E2E,
        phase: "after browser rollback",
        expected: initialSystem.local_endpoint_id,
        observed: rolledBackSystem.local_endpoint_id,
      });
    }
    const rolledBack = await state();
    if (!rolledBack.body_text.trim()) {
      throw new BehaviorFailure("browser_empty_document", "browser returned an empty document after rollback", {
        e2e_name: PROMOTION_REVISION_E2E,
        observed: rolledBack,
      });
    }
    const rolledBackHealth = await healthCheck(baselineArtifact, "after browser rollback");
    assertReleaseState(releaseRoot, baselineArtifact, candidateArtifact, "after browser rollback");

    const reloadObservation = browserObservationCounts();
    const reloadResponse = await page.reload({ waitUntil: "domcontentloaded", timeout: 10_000 });
    const reloadStatus = reloadResponse?.status() ?? 0;
    if (reloadStatus < 200 || reloadStatus >= 300) {
      throw new BehaviorFailure("browser_rollback_reload_failed", "browser reload after rollback did not return a successful UI document", {
        e2e_name: PROMOTION_REVISION_E2E,
        status: reloadStatus,
      });
    }
    const reloaded = await state();
    if (!reloaded.body_text.trim()) {
      throw new BehaviorFailure("browser_empty_document", "browser returned an empty document after rollback reload", {
        e2e_name: PROMOTION_REVISION_E2E,
        observed: reloaded,
      });
    }
    const reloadedSystem = await assertBrowserSystem("after browser rollback reload", reloadObservation);
    await assertBrowserManagementApis("after browser rollback reload", initialSystem.local_endpoint_id, reloadObservation);
    if (reloadedSystem.local_endpoint_id !== initialSystem.local_endpoint_id) {
      throw new BehaviorFailure("release_local_endpoint_identity_changed", "rollback reload changed the persistent built-in Endpoint identity", {
        e2e_name: PROMOTION_REVISION_E2E,
        phase: "after browser rollback reload",
        expected: initialSystem.local_endpoint_id,
        observed: reloadedSystem.local_endpoint_id,
      });
    }
    const reloadedHealth = await healthCheck(baselineArtifact, "after browser rollback reload");
    assertReleaseState(releaseRoot, baselineArtifact, candidateArtifact, "after browser rollback reload");
    await Promise.allSettled([...pendingResponses]);
    return { exchanges: exchangeList, browser: { initial, promoted, rolledBack, reloaded }, system: { initial: initialSystem, promoted: promotedSystem, rolledBack: rolledBackSystem, reloaded: reloadedSystem }, replay };
  } catch (error) {
    await Promise.allSettled([...pendingResponses]);
    if (!(error instanceof BehaviorFailure)) {
      const failedRequest = firstFailedBrowserExchange(exchangeList);
      if (failedRequest) {
        error = new BehaviorFailure("browser_request_failed", "the real browser observed a failed or disconnected request", {
          e2e_name: PROMOTION_REVISION_E2E,
          cause: String(error),
          first_failure: exchangeIdentity(failedRequest),
          exchanges: exchangeList,
        });
      }
    }
    if (error instanceof BehaviorFailure) {
      const firstFailure = error.details?.first_failure ?? firstFailedBrowserExchange(exchangeList);
      error.details = {
        e2e_name: PROMOTION_REVISION_E2E,
        ...error.details,
        first_failure: firstFailure ? exchangeIdentity(firstFailure) : undefined,
        exchanges: exchangeList,
      };
    }
    throw error;
  } finally {
    await context.close();
    await browser.close();
  }
}

function sanitizeText(value, knownValues = []) {
  let result = String(value ?? "");
  for (const [index, secret] of knownValues.entries()) {
    if (secret) result = result.split(secret).join(`{{SYNTHETIC_SECRET_${index + 1}}}`);
  }
  result = result.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer {{SYNTHETIC_ACCESS_TOKEN}}");
  result = result.replace(
    /(authorization|cookie|set-cookie|password|secret|token|assertion|client_secret|code|state)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;}]+)/gi,
    "$1: \"{{SYNTHETIC_SECRET}}\"",
  );
  return result;
}

function sanitizeValue(value, knownValues) {
  if (typeof value === "string") return sanitizeText(value, knownValues);
  if (Array.isArray(value)) return value.map((entry) => sanitizeValue(entry, knownValues));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, sanitizeValue(entry, knownValues)]));
  }
  return value;
}

function replaceKnownSecretBytes(bytes, knownValues) {
  let result = Buffer.from(bytes);
  for (const [index, secret] of knownValues.entries()) {
    if (!secret) continue;
    const needle = Buffer.from(secret, "utf8");
    if (!needle.length) continue;
    const replacement = Buffer.from(`{{SYNTHETIC_SECRET_${index + 1}}}`, "utf8");
    const chunks = [];
    let start = 0;
    while (start <= result.length - needle.length) {
      const found = result.indexOf(needle, start);
      if (found < 0) break;
      chunks.push(result.subarray(start, found), replacement);
      start = found + needle.length;
    }
    if (chunks.length) {
      chunks.push(result.subarray(start));
      result = Buffer.concat(chunks);
    }
  }
  return result;
}

function decodeCanonicalBase64(value, label) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    cassetteSecurityFailure(`${label} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    cassetteSecurityFailure(`${label} is not canonical base64`);
  }
  return decoded;
}

function safeIncident(raw, knownValues) {
  const safeBody = (body) => {
    if (!body) return body;
    const originalBytes = decodeCanonicalBase64(body.base64, "incident body");
    const originalSha256 = body.sha256;
    // Preserve exact bytes for binary/opaque responses.  Only configured
    // secret values are replaced in a body; broad UTF-8 regex rewriting would
    // corrupt assets or change the failure being recorded.
    const safeBytes = replaceKnownSecretBytes(originalBytes, knownValues);
    return {
      ...body,
      base64: safeBytes.toString("base64"),
      sha256: sha256(safeBytes),
      recorded_sha256: originalSha256,
    };
  };
  const exchanges = raw.exchanges.map((exchange) => ({
    sequence: exchange.sequence,
    request: {
      method: exchange.request.method,
      path: sanitizeText(exchange.request.path, knownValues),
      headers: sanitizeValue(exchange.request.headers, knownValues),
      body: safeBody(exchange.request.body),
    },
    response: exchange.response && {
      status: exchange.response.status,
      headers: sanitizeValue(exchange.response.headers, knownValues),
      body: safeBody(exchange.response.body),
      completed: exchange.response.completed,
      request_failed: exchange.response.request_failed === true,
      disconnected: exchange.response.disconnected === true,
      failure: exchange.response.failure
        ? sanitizeText(exchange.response.failure, knownValues)
        : null,
    },
  }));
  return {
    schema: INCIDENT_SCHEMA,
    recording_id: raw.recording_id,
    purpose: "first post-rule release-path behavioral failure",
    owner: OWNER,
    e2e_name: raw.e2e_name,
    boundary: raw.binding?.boundary ?? "management-browser-release-entry",
    first_observed: sanitizeValue(raw.first_observed, knownValues),
    binding: sanitizeValue(raw.binding, knownValues),
    provenance: raw.provenance,
    synthetic_secret_slots: [
      "SYNTHETIC_ACCESS_TOKEN",
      "SYNTHETIC_SECRET",
      ...knownValues.map((_, index) => `SYNTHETIC_SECRET_${index + 1}`),
    ],
    exchanges,
  };
}

function cassetteSecurityFailure(message, details = {}) {
  throw new Blocked("cassette_secret_scan_failed", message, details);
}

function scanSecretText(value, label, knownValues) {
  const text = String(value);
  for (const secret of knownValues) {
    if (secret && text.includes(secret)) cassetteSecurityFailure(`${label} contains a configured secret value`);
  }
  if (
    /Bearer\s+[A-Za-z0-9._~+/=-]+/i.test(text)
    || /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----/i.test(text)
    || /\b(?:sk|pk|rk)-[A-Za-z0-9]{8,}\b/i.test(text)
    || /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/.test(text)
  ) {
    cassetteSecurityFailure(`${label} contains a secret-bearing marker`);
  }
}

function scanSecretValue(value, label, knownValues) {
  if (typeof value === "string") {
    scanSecretText(value, label, knownValues);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => scanSecretValue(entry, `${label}[${index}]`, knownValues));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      if (
        /^(authorization|cookie|set-cookie|password|secret|token|assertion|client_secret)$/i.test(key)
        && typeof entry === "string"
        && !/^\{\{SYNTHETIC_[A-Z0-9_]+\}\}$/.test(entry)
      ) {
        cassetteSecurityFailure(`${label}.${key} was not replaced with a synthetic slot`);
      }
      scanSecretValue(entry, `${label}.${key}`, knownValues);
    }
  }
}

function scanCassette(cassette, knownValues) {
  scanSecretValue(cassette, "cassette", knownValues);
  for (const [exchangeIndex, exchange] of (cassette.exchanges ?? []).entries()) {
    for (const [kind, body] of [["request", exchange.request?.body], ["response", exchange.response?.body]]) {
      if (!body) continue;
      const decoded = decodeCanonicalBase64(body.base64, `cassette ${kind} body ${exchangeIndex}`);
      if (body.sha256 !== sha256(decoded)) {
        cassetteSecurityFailure(`cassette ${kind} body ${exchangeIndex} digest does not match its canonical base64`);
      }
      if (body.recorded_sha256 !== undefined && !/^[a-f0-9]{64}$/.test(String(body.recorded_sha256))) {
        cassetteSecurityFailure(`cassette ${kind} body ${exchangeIndex} has an invalid recorded digest`);
      }
      scanSecretText(decoded.toString("utf8"), `cassette ${kind} body ${exchangeIndex}`, knownValues);
    }
  }
}

function exchangeIdentity(exchange) {
  return {
    sequence: exchange.sequence,
    boundary: exchange.boundary ?? (exchange.request?.method === "CLI" ? "release-driver" : "management-browser-release-entry"),
    method: exchange.request?.method ?? null,
    path: exchange.request?.path ?? null,
    response_status: exchange.response?.status ?? null,
    response_completed: exchange.response?.completed ?? false,
    request_failed: exchange.response?.request_failed === true,
    disconnected: exchange.response?.disconnected === true,
    response_failure: exchange.response?.failure ?? null,
    request_sha256: exchange.request?.body?.sha256 ?? null,
    response_sha256: exchange.response?.body?.sha256 ?? null,
  };
}

function failedExchange(exchange) {
  if (!exchange?.response) return false;
  if (exchange.request?.method === "CLI") {
    return exchange.response.expected_failure !== true && exchange.response.status !== 0;
  }
  return exchange.response.request_failed === true
    || exchange.response.disconnected === true
    || exchange.response.status >= 400
    || exchange.response.completed === false;
}

function firstFailedBrowserExchange(exchanges) {
  return exchanges.find((exchange) => exchange.request?.method !== "CLI" && failedExchange(exchange));
}

function firstFailedRecordedExchange(exchanges) {
  return exchanges.find((exchange) => exchange.request?.method === "CLI" && failedExchange(exchange));
}

function selectFirstFailureExchange(exchanges, failure) {
  const expected = failure.details?.first_failure ?? {};
  const expectedSequence = Number.isSafeInteger(expected.sequence) ? expected.sequence : null;
  const expectedBoundary = expected.boundary ?? null;
  const expectedMethod = expected.method ?? null;
  const expectedPath = expected.path ?? failure.details?.path ?? null;
  const expectedStatus = expected.response_status ?? failure.details?.status ?? null;
  const expectedCompleted = expected.response_completed ?? null;
  const expectedRequestFailed = expected.request_failed ?? null;
  const expectedDisconnected = expected.disconnected ?? null;
  const expectedResponseFailure = expected.response_failure ?? null;
  const expectedRequestSha256 = expected.request_sha256 ?? null;
  const expectedResponseSha256 = expected.response_sha256 ?? null;
  const browserExchanges = exchanges.filter((exchange) => exchange.request?.method !== "CLI");
  if (expectedSequence !== null) {
    const exact = exchanges.filter((exchange) => exchange.sequence === expectedSequence);
    if (exact.length !== 1) {
      throw new Blocked("first_failure_exchange_missing", "the recorded first occurrence sequence is not unique", {
        e2e_name: failure.details?.e2e_name ?? PROMOTION_REVISION_E2E,
        exchange_sequence: expectedSequence,
        matches: exact.length,
      });
    }
    const observed = exchangeIdentity(exact[0]);
    if (
      (expectedPath !== null && observed.path !== expectedPath)
      || (expectedBoundary !== null && observed.boundary !== expectedBoundary)
      || (expectedMethod !== null && observed.method !== expectedMethod)
      || (expectedStatus !== null && observed.response_status !== expectedStatus)
      || (expectedCompleted !== null && observed.response_completed !== expectedCompleted)
      || (expectedRequestFailed !== null && observed.request_failed !== expectedRequestFailed)
      || (expectedDisconnected !== null && observed.disconnected !== expectedDisconnected)
      || (expectedResponseFailure !== null && observed.response_failure !== expectedResponseFailure)
      || (expectedRequestSha256 !== null && observed.request_sha256 !== expectedRequestSha256)
      || (expectedResponseSha256 !== null && observed.response_sha256 !== expectedResponseSha256)
    ) {
      throw new Blocked("first_failure_exchange_mismatch", "the exact first occurrence sequence has different exchange metadata", {
        e2e_name: failure.details?.e2e_name ?? PROMOTION_REVISION_E2E,
        expected: { sequence: expectedSequence, path: expectedPath, status: expectedStatus },
        observed,
      });
    }
    return exact[0];
  }
  const hasExplicitBinding = expectedPath !== null || expectedStatus !== null;
  const matching = (hasExplicitBinding ? exchanges : browserExchanges).find((exchange) => (
    (expectedPath === null || exchange.request?.path === expectedPath)
    && (expectedBoundary === null || exchangeIdentity(exchange).boundary === expectedBoundary)
    && (expectedMethod === null || exchange.request?.method === expectedMethod)
    && (expectedStatus === null || exchange.response?.status === expectedStatus)
    && (expectedCompleted === null || exchange.response?.completed === expectedCompleted)
    && (expectedRequestFailed === null || exchange.response?.request_failed === expectedRequestFailed)
    && (expectedDisconnected === null || exchange.response?.disconnected === expectedDisconnected)
    && (expectedResponseFailure === null || exchange.response?.failure === expectedResponseFailure)
    && (expectedRequestSha256 === null || exchange.request?.body?.sha256 === expectedRequestSha256)
    && (expectedResponseSha256 === null || exchange.response?.body?.sha256 === expectedResponseSha256)
    && (hasExplicitBinding || exchange.response?.status >= 400 || exchange.response?.completed === false)
  ));
  if (matching) return matching;
  const firstFailedResponse = firstFailedBrowserExchange(browserExchanges);
  if (firstFailedResponse) return firstFailedResponse;
  const operation = failure.details?.driver_operation;
  if (typeof operation === "string") {
    const driverExchange = exchanges.find((exchange) => exchange.request?.path === `release-driver/${operation}`);
    if (driverExchange) return driverExchange;
  }
  const firstFailedDriver = firstFailedRecordedExchange(exchanges);
  if (firstFailedDriver) return firstFailedDriver;
  // A semantic browser assertion can fail after a successful 2xx document
  // (for example, an empty or wrong shell).  Preserve the earliest browser
  // exchange rather than downgrading that public failure to an unrecordable
  // harness error.
  if (failure instanceof BehaviorFailure && browserExchanges.length) return browserExchanges[0];
  throw new Blocked("first_failure_exchange_missing", "the release failure has no captured exchange to bind to", {
    e2e_name: failure.details?.e2e_name ?? PROMOTION_REVISION_E2E,
    expected_path: expectedPath,
    expected_status: expectedStatus,
    browser_exchange_count: browserExchanges.length,
    driver_operation: operation ?? null,
  });
}

function assertCassetteBinding(cassette, label = "cassette") {
  const binding = cassette.binding;
  const provenance = cassette.provenance;
  const firstObserved = cassette.first_observed?.first_exchange;
  if (
    cassette.e2e_name !== PROMOTION_REVISION_E2E
    || cassette.boundary !== "management-browser-release-entry"
    || !binding
    || binding.e2e_name !== PROMOTION_REVISION_E2E
    || binding.boundary !== "management-browser-release-entry"
    || !Array.isArray(cassette.exchanges)
    || !Number.isSafeInteger(binding.exchange_sequence)
    || binding.exchange_sequence < 0
    || typeof binding.method !== "string"
    || typeof binding.path !== "string"
    || (binding.response_status !== null && !Number.isInteger(binding.response_status))
    || typeof binding.response_completed !== "boolean"
    || typeof binding.request_failed !== "boolean"
    || typeof binding.disconnected !== "boolean"
    || !firstObserved
    || !provenance
    || !/^[a-f0-9]{40}$/.test(provenance.baseline_revision ?? "")
    || !/^[a-f0-9]{40}$/.test(provenance.candidate_revision ?? "")
    || !/^[a-f0-9]{40}$/.test(provenance.failed_revision ?? "")
    || !/^[a-f0-9]{64}$/.test(provenance.baseline_manifest_sha256 ?? "")
    || !/^[a-f0-9]{64}$/.test(provenance.candidate_manifest_sha256 ?? "")
    || !/^[a-f0-9]{64}$/.test(provenance.failed_manifest_sha256 ?? "")
    || !/^[a-f0-9]{64}$/.test(provenance.driver_sha256 ?? "")
  ) {
    throw new Blocked("cassette_binding_mismatch", `${label} is not bound to the exact promotion browser failure`);
  }
  const sequenceValues = cassette.exchanges.map((entry) => entry.sequence);
  if (
    sequenceValues.some((sequence) => !Number.isSafeInteger(sequence) || sequence < 0)
    || new Set(sequenceValues).size !== sequenceValues.length
    || sequenceValues.some((sequence, index) => index > 0 && sequence <= sequenceValues[index - 1])
  ) {
    throw new Blocked("cassette_binding_mismatch", `${label} does not contain strictly ordered exact exchange sequences`);
  }
  const matches = (cassette.exchanges ?? []).filter((entry) => entry.sequence === binding.exchange_sequence);
  if (matches.length !== 1) throw new Blocked("cassette_binding_mismatch", `${label} does not contain one exact bound first exchange`);
  const exchange = matches[0];
  const observed = exchangeIdentity(exchange);
  if (
    observed.path !== binding.path
    || observed.method !== binding.method
    || observed.boundary !== binding.boundary
    || observed.response_status !== binding.response_status
    || observed.response_completed !== binding.response_completed
    || observed.request_failed !== binding.request_failed
    || observed.disconnected !== binding.disconnected
    || observed.response_failure !== (binding.response_failure ?? null)
    || (binding.request_sha256 && (exchange.request.body?.recorded_sha256 ?? observed.request_sha256) !== binding.request_sha256)
    || (binding.response_sha256 && (exchange.response?.body?.recorded_sha256 ?? observed.response_sha256) !== binding.response_sha256)
  ) {
    throw new Blocked("cassette_binding_mismatch", `${label} first exchange does not match its binding`, {
      binding,
      observed,
    });
  }
  if (
    firstObserved.sequence !== binding.exchange_sequence
    || firstObserved.boundary !== binding.boundary
    || firstObserved.path !== binding.path
    || firstObserved.method !== binding.method
    || firstObserved.response_status !== binding.response_status
    || firstObserved.response_completed !== binding.response_completed
    || firstObserved.request_failed !== binding.request_failed
    || firstObserved.disconnected !== binding.disconnected
    || firstObserved.response_failure !== (binding.response_failure ?? null)
    || firstObserved.request_sha256 !== binding.request_sha256
    || firstObserved.response_sha256 !== binding.response_sha256
  ) {
    throw new Blocked("cassette_binding_mismatch", `${label} first_observed metadata does not match its bound exchange`);
  }
}

function assertReplayFailureBinding(cassette, failure) {
  const binding = cassette.binding;
  const matches = (failure.details?.exchanges ?? []).filter((exchange) => exchange.sequence === binding.exchange_sequence);
  const observed = matches.length === 1 ? matches[0] : null;
  if (!observed) {
    throw new BehaviorFailure("replay_binding_mismatch", "replay did not reproduce the cassette-bound browser exchange", {
      e2e_name: PROMOTION_REVISION_E2E,
      binding,
      observed_sequence_matches: matches.length,
    });
  }
  const identity = exchangeIdentity(observed);
  if (
    identity.path !== binding.path
    || identity.method !== binding.method
    || identity.boundary !== binding.boundary
    || identity.response_status !== binding.response_status
    || identity.response_completed !== binding.response_completed
    || identity.request_failed !== binding.request_failed
    || identity.disconnected !== binding.disconnected
    || identity.response_failure !== (binding.response_failure ?? null)
    || (binding.request_sha256
    && identity.request_sha256 !== binding.request_sha256
    )
    || (binding.response_sha256
    && identity.response_sha256 !== binding.response_sha256
    )
  ) {
    throw new BehaviorFailure("replay_binding_mismatch", "replay browser exchange fingerprints differ from the cassette binding", {
      e2e_name: PROMOTION_REVISION_E2E,
      binding,
      observed: identity,
    });
  }
}

function writeIncident(exchanges, failure, quarantineRoot, cassetteRoot, promote, knownValues = null, provenance = null) {
  const recordingId = `${new Date().toISOString().replace(/[-:.TZ]/g, "")}-${randomUUID()}`;
  const rawRoot = join(quarantineRoot, recordingId);
  ensureDirectory(rawRoot, 0o700);
  const rawPath = join(rawRoot, "incident.raw.json");
  const normalizedExchanges = exchanges.map((exchange, sequence) => ({
    ...exchange,
    sequence: Number.isSafeInteger(exchange.sequence) ? exchange.sequence : sequence,
  }));
  const sequenceSet = new Set(normalizedExchanges.map((exchange) => exchange.sequence));
  if (sequenceSet.size !== normalizedExchanges.length) {
    throw new Blocked("exchange_sequence_not_unique", "incident exchanges do not have unique exact sequences", {
      rawPath,
    });
  }
  const e2eName = failure.details?.e2e_name ?? PROMOTION_REVISION_E2E;
  const truncated = normalizedExchanges.some((exchange) => exchange.request?.body?.truncated || exchange.response?.body?.truncated);
  if (truncated) {
    // A bounded capture is useful diagnostics but is not a replayable first
    // occurrence.  Keep it only in ignored quarantine and fail closed before
    // any immutable cassette can be promoted.
    const raw = {
      schema: INCIDENT_SCHEMA,
      recording_id: recordingId,
      owner: OWNER,
      e2e_name: e2eName,
      first_observed: { code: failure.code, message: failure.message, details: publicFailureDetails(failure.details) },
      provenance,
      recording_blocked: "body_truncated",
      exchanges: normalizedExchanges,
    };
    writeExclusive(rawPath, jsonBytes(raw), 0o600);
    throw new Blocked("recording_body_truncated", `${failure.message}; raw capture is bounded and cannot be promoted`, { rawPath });
  }
  let firstExchange;
  try {
    firstExchange = selectFirstFailureExchange(normalizedExchanges, failure);
  } catch (error) {
    const raw = {
      schema: INCIDENT_SCHEMA,
      recording_id: recordingId,
      owner: OWNER,
      e2e_name: e2eName,
      first_observed: {
        code: failure.code,
        message: failure.message,
        details: publicFailureDetails(failure.details),
      },
      provenance,
      exchanges: normalizedExchanges,
    };
    writeExclusive(rawPath, jsonBytes(raw), 0o600);
    if (error instanceof Blocked) {
      throw new Blocked(error.code, `${error.message}; raw evidence: ${rawPath}`, {
        ...error.details,
        rawPath,
      });
    }
    throw error;
  }
  const raw = {
    schema: INCIDENT_SCHEMA,
    recording_id: recordingId,
    owner: OWNER,
    e2e_name: e2eName,
    provenance,
    exchanges: normalizedExchanges,
  };
  const firstObserved = exchangeIdentity(firstExchange);
  raw.first_observed = {
    code: failure.code,
    message: failure.message,
    details: publicFailureDetails(failure.details),
    first_exchange: firstObserved,
  };
  raw.binding = {
    e2e_name: raw.e2e_name,
    boundary: firstObserved.boundary,
    exchange_sequence: firstObserved.sequence,
    path: firstObserved.path,
    method: firstObserved.method,
    response_status: firstObserved.response_status,
    response_completed: firstObserved.response_completed,
    request_failed: firstObserved.request_failed,
    disconnected: firstObserved.disconnected,
    response_failure: firstObserved.response_failure,
    request_sha256: firstObserved.request_sha256,
    response_sha256: firstObserved.response_sha256,
  };
  writeExclusive(rawPath, jsonBytes(raw), 0o600);
  let cassettePath = null;
  let promotionSkipped = null;
  if (promote && firstObserved.boundary !== "management-browser-release-entry") {
    promotionSkipped = "first failure was a release-driver exchange; browser cassette promotion is not applicable";
  } else if (promote) {
    const safeValues = knownValues ?? knownSecretValues({ required: true });
    const cassette = safeIncident(raw, safeValues);
    assertCassetteBinding(cassette, "promoted cassette");
    scanCassette(cassette, safeValues);
    ensureDirectory(cassetteRoot, 0o755);
    const withoutDigest = jsonBytes(cassette);
    const final = { ...cassette, envelope_sha256: sha256(withoutDigest) };
    cassettePath = join(cassetteRoot, `${recordingId}.json`);
    writeExclusive(cassettePath, jsonBytes(final), 0o444);
  }
  return { rawPath, cassettePath, promotionSkipped };
}

function knownSecretValues({ required = false } = {}) {
  const raw = process.env.ZODE_RELEASE_SECRET_VALUES_JSON;
  if (!raw) {
    if (required) {
      throw new Blocked("secret_values_missing", "secret inventory is required before cassette promotion or replay");
    }
    return [];
  }
  try {
    const values = JSON.parse(raw);
    if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
      throw new Error("expected an array of strings");
    }
    return values.filter(Boolean);
  } catch (error) {
    throw new Blocked("secret_values_invalid", "ZODE_RELEASE_SECRET_VALUES_JSON is malformed; refusing to record a cassette", {
      error: String(error),
    });
  }
}

function publicFailureDetails(details) {
  if (!details || typeof details !== "object") return details;
  const safe = { ...details };
  delete safe.exchanges;
  return safe;
}

function bindDriverOperationFailure(failure, exchanges, operation, artifact = null) {
  if (!(failure instanceof BehaviorFailure) || failure.details?.first_failure) return failure;
  const expectedRevision = artifact?.manifest?.revision ?? null;
  const exchange = [...exchanges].reverse().find((entry) => {
    if (entry.request?.path !== `release-driver/${operation}`) return false;
    if (!expectedRevision) return true;
    try {
      const body = entry.request?.body?.base64 ? JSON.parse(Buffer.from(entry.request.body.base64, "base64").toString("utf8")) : null;
      return body?.artifact_revision === expectedRevision;
    } catch {
      return false;
    }
  });
  if (exchange) {
    failure.details = {
      ...failure.details,
      driver_operation: operation,
      first_failure: exchangeIdentity(exchange),
    };
  }
  return failure;
}

function normalizeIncidentEvidence(recordedExchanges, browserExchanges, failure) {
  // Every boundary allocates from the same monotonic sequence while the live
  // scenario is running.  Preserve those exact values and merge by sequence;
  // rewriting all browser exchanges after the CLI list would turn an
  // interleaved first occurrence into a different causal order (and can
  // create duplicate sequence numbers).
  const recorded = recordedExchanges.map((exchange, index) => ({
    ...exchange,
    sequence: Number.isSafeInteger(exchange.sequence) ? exchange.sequence : index,
  }));
  const browser = (browserExchanges ?? []).map((exchange, index) => ({
    ...exchange,
    sequence: Number.isSafeInteger(exchange.sequence)
      ? exchange.sequence
      : recorded.length + index,
  }));
  const merged = [...recorded, ...browser].sort((left, right) => left.sequence - right.sequence);
  let firstFailure = failure.details?.first_failure;
  if (firstFailure?.boundary === "management-browser-release-entry") {
    const local = browser.find((exchange) => exchange.sequence === firstFailure.sequence);
    if (local) firstFailure = { ...firstFailure, sequence: local.sequence };
  }
  if (!firstFailure) {
    const browserFailure = firstFailedBrowserExchange(browser);
    const driverFailure = typeof failure.details?.driver_operation === "string"
      ? recorded.find((exchange) => exchange.request?.path === `release-driver/${failure.details.driver_operation}`)
      : firstFailedRecordedExchange(recorded);
    const selected = browserFailure ?? driverFailure;
    if (selected) firstFailure = exchangeIdentity(selected);
  }
  if (firstFailure && firstFailure !== failure.details?.first_failure) {
    failure.details = { ...failure.details, first_failure: firstFailure };
  }
  return { exchanges: merged, failure };
}

async function buildRevision({ repoRoot, commit, workRoot, label, driverRelativePath }) {
  const missing = requiredSurface(repoRoot, commit, driverRelativePath);
  if (missing.length) {
    throw new Blocked("missing_build_surface", `${label} frozen revision has no complete UI+Server+Endpoint build surface`, {
      revision: commit,
      missing,
      evidence: "git cat-file -e commit:path; git archive of the tracked commit is the only source",
      dirty_worktree: "not copied",
    });
  }
  const checkout = join(workRoot, `${label}-checkout`);
  extractCommit(repoRoot, commit, checkout);
  const sourceTreeSha256 = sourceTreeDigest(checkout);
  const logs = join(workRoot, `${label}-logs`);
  ensureDirectory(logs, 0o700);
  runChecked("vp", ["install", "--frozen-lockfile"], join(checkout, "web"), join(logs, "ui-install.log"));
  runChecked("vp", ["build"], join(checkout, "web"), join(logs, "ui.log"));
  runChecked("vp", ["exec", "cargo", "build", "--release", "--locked", "--manifest-path", join(checkout, "Cargo.toml")], checkout, join(logs, "endpoint.log"));
  runChecked("vp", ["exec", "cargo", "build", "--release", "--locked", "--manifest-path", join(checkout, "server", "Cargo.toml")], checkout, join(logs, "server.log"));
  const driverSource = selectDriverSource(checkout, driverRelativePath);
  return packageArtifact(checkout, commit, join(workRoot, "artifacts"), logs, driverSource, sourceTreeSha256);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const replayExpectation = args.replay ? process.env.ZODE_RELEASE_REPLAY_EXPECTATION : null;
  if (args.replay && !new Set(["red", "green"]).has(replayExpectation)) {
    throw new Blocked("replay_expectation_missing", "--replay requires ZODE_RELEASE_REPLAY_EXPECTATION=red or green");
  }
  const repoRoot = commandOutput("git", ["rev-parse", "--show-toplevel"], process.cwd());
  const baselineInput = process.env.ZODE_RELEASE_BASELINE_REVISION;
  const candidateInput = process.env.ZODE_RELEASE_CANDIDATE_REVISION;
  const failedInput = process.env.ZODE_RELEASE_FAILED_REVISION;
  if (!baselineInput || !candidateInput || !failedInput) {
    throw new Blocked("missing_revision_input", "three frozen revisions are required for install, promotion, and rollback", {
      required: ["ZODE_RELEASE_BASELINE_REVISION", "ZODE_RELEASE_CANDIDATE_REVISION", "ZODE_RELEASE_FAILED_REVISION"],
    });
  }
  const revisions = {
    baseline: canonicalCommit(repoRoot, baselineInput),
    candidate: canonicalCommit(repoRoot, candidateInput),
    failed: canonicalCommit(repoRoot, failedInput),
  };
  if (revisions.baseline === revisions.candidate || revisions.baseline === revisions.failed || revisions.candidate === revisions.failed) {
    throw new Blocked("revisions_not_distinct", "baseline, candidate, and failed revisions must be distinct commits", revisions);
  }

  const driverRelativePath = process.env.ZODE_RELEASE_DRIVER_RELATIVE_PATH;
  if (!driverRelativePath) {
    throw new Blocked("release_driver_missing", "a relative release driver path in the frozen checkout is required", {
      expected: "ZODE_RELEASE_DRIVER_RELATIVE_PATH",
    });
  }

  // macOS commonly exposes tmpdir through /var -> /private/var.  Resolve the
  // fresh directory once so the driver and harness share the same canonical
  // release-root spelling without relaxing the no-symlink boundary.
  const workRoot = resolve(realpathSync(mkdtempSync(join(tmpdir(), "zode-release-e2e-"))));
  let incident = null;
  let driver = null;
  let driverRecord = null;
  let releaseRoot = null;
  let artifacts = null;
  let artifactSnapshots = null;
  let runSucceeded = false;
  let teardownFailure = null;
  let payloadFailure = null;
  let reapFailure = null;
  let successReport = null;
  // This set must outlive the inner scenario try so the outer finally can
  // recheck every independently observed PID after teardown.
  const observedReleasePids = new Set();
  const observedReleaseInstances = new Set();
  const observedReleaseEvidence = new Map();
  let stopReports = [];
  const recordedExchanges = [];
  let browserExchangesForIncident = [];
  let recordingProvenance = null;
  try {
    artifacts = {};
    for (const [label, commit] of Object.entries(revisions)) {
      artifacts[label] = await buildRevision({ repoRoot, commit, workRoot, label, driverRelativePath });
    }
    artifactSnapshots = snapshotArtifacts(artifacts);
    driverRecord = artifacts.baseline.driver;
    recordingProvenance = {
      baseline_revision: revisions.baseline,
      candidate_revision: revisions.candidate,
      failed_revision: revisions.failed,
      baseline_manifest_sha256: sha256(readFileSync(artifacts.baseline.manifestPath)),
      candidate_manifest_sha256: sha256(readFileSync(artifacts.candidate.manifestPath)),
      failed_manifest_sha256: sha256(readFileSync(artifacts.failed.manifestPath)),
      driver_sha256: driverRecord.binary_sha256,
    };
    driver = artifacts.baseline.driverPath;
    assertExecutableDigest(driver, driverRecord.binary_sha256, "release driver", "immutable checkout selection");
    const uiUrl = process.env.ZODE_RELEASE_UI_URL;
    if (!uiUrl) throw new Blocked("browser_entry_missing", "ZODE_RELEASE_UI_URL is required for the real browser entry");
    assertLocalBrowserUrl(uiUrl);
    releaseRoot = join(workRoot, "release-root");
    ensureDirectory(releaseRoot, 0o700);
    assertReleaseRoot(releaseRoot);
    let nextExchangeSequenceValue = 0;
    const nextExchangeSequence = () => nextExchangeSequenceValue++;
    const replayAdapterPath = args.replay
      ? resolve(process.env.ZODE_RELEASE_REPLAY_ADAPTER || "")
      : null;
    if (args.replay && !process.env.ZODE_RELEASE_REPLAY_ADAPTER) {
      throw new Blocked("replay_adapter_missing", "--replay requires a test-owned replay adapter; production driver receives no cassette");
    }
    let replayPassed = false;
    const invokeDriver = (operation, artifact, options = {}) => runDriver(
      driver,
      operation,
      releaseRoot,
      artifact,
      {
        ...options,
        driverSha256: driverRecord.binary_sha256,
        sequenceAllocator: nextExchangeSequence,
        captureArtifact: options.captureArtifact ?? artifact,
        adapterRoot: repoRoot,
      },
    );
    const invokeDriverAsync = (operation, artifact, options = {}) => runDriverAsync(
      driver,
      operation,
      releaseRoot,
      artifact,
      {
        ...options,
        driverSha256: driverRecord.binary_sha256,
        sequenceAllocator: nextExchangeSequence,
        captureArtifact: options.captureArtifact ?? artifact,
        adapterRoot: repoRoot,
      },
    );
    const invokeReplayDriver = (operation, artifact, cassette, options = {}) => runReplayAdapter(
      replayAdapterPath,
      driver,
      operation,
      releaseRoot,
      artifact,
      cassette,
      {
        ...options,
        driverSha256: driverRecord.binary_sha256,
        sequenceAllocator: nextExchangeSequence,
        captureArtifact: options.captureArtifact ?? artifact,
        adapterRoot: repoRoot,
      },
    );
    const recordReleaseProcesses = (processes) => {
      if (processes.instance_id) observedReleaseInstances.add(processes.instance_id);
      for (const pid of processes.pids ?? [processes.server.pid, processes.endpoint.pid]) {
        observedReleasePids.add(pid);
      }
      for (const role of ["server", "endpoint"]) {
        const process = processes[role];
        if (!process) continue;
        observedReleaseEvidence.set(process.pid, {
          role,
          started_at_unix_ms: process.locator.started_at_unix_ms,
          process_group_id: process.locator.process_group_id,
          session_id: process.locator.session_id,
          executable: process.executable,
          executable_sha256: process.locator.executable_sha256,
        });
      }
    };
    const healthCheck = (expectedArtifact, phase, options = {}) => readReleaseHealth(
      driver,
      releaseRoot,
      expectedArtifact,
      phase,
      {
        capture: recordedExchanges,
        replay: options.replay,
        driverSha256: driverRecord.binary_sha256,
        sequenceAllocator: nextExchangeSequence,
        captureArtifact: expectedArtifact,
        replayAdapter: replayAdapterPath,
        replayAdapterRoot: repoRoot,
        uiUrl,
        onLiveProcesses: recordReleaseProcesses,
      },
    );
    const promoteRelease = () => invokeDriverAsync("promote", null, {
      capture: recordedExchanges,
      e2eName: PROMOTION_REVISION_E2E,
    });
    const rollbackRelease = () => invokeDriverAsync("rollback", null, {
      capture: recordedExchanges,
      e2eName: PROMOTION_REVISION_E2E,
    });

    try {
      if (args.replay) {
        const cassettePath = resolve(args.replay);
        const cassetteStat = lstatOrNull(cassettePath);
        if (!cassetteStat || !cassetteStat.isFile() || cassetteStat.isSymbolicLink()) {
          throw new Blocked("cassette_missing", `cassette is missing or is not a regular file: ${cassettePath}`);
        }
        const cassette = JSON.parse(readFileSync(cassettePath, "utf8"));
        if (cassette.schema !== INCIDENT_SCHEMA || cassette.owner !== OWNER) {
          throw new Blocked("cassette_owner_mismatch", "cassette is not owned by this release E2E");
        }
        assertCassetteBinding(cassette, "replay cassette");
        const cassetteBrowserExchanges = cassette.exchanges.filter(
          (exchange) => exchangeIdentity(exchange).boundary === "management-browser-release-entry",
        );
        const cassetteBrowserIndex = cassetteBrowserExchanges.findIndex(
          (exchange) => exchange.sequence === cassette.binding.exchange_sequence,
        );
        if (cassetteBrowserIndex < 0) {
          throw new Blocked("cassette_binding_mismatch", "replay cassette bound sequence is not a browser exchange");
        }
        const replayExchangeSequenceOffset = cassette.binding.exchange_sequence - cassetteBrowserIndex;
        scanCassette(cassette, knownSecretValues({ required: true }));
        if (JSON.stringify(cassette.provenance) !== JSON.stringify(recordingProvenance)) {
          throw new Blocked("cassette_provenance_mismatch", "replay cassette was recorded for different immutable revisions or driver digest", {
            expected: recordingProvenance,
            observed: cassette.provenance ?? null,
          });
        }
        if ((cassetteStat.mode & 0o222) !== 0) {
          throw new Blocked("cassette_not_immutable", "replay cassette is writable");
        }
        const { envelope_sha256: envelopeDigest, ...withoutDigest } = cassette;
        if (!envelopeDigest || sha256(jsonBytes(withoutDigest)) !== envelopeDigest) {
          throw new Blocked("cassette_integrity", "replay cassette envelope digest does not match");
        }
        const replayBootstrap = invokeReplayDriver("bootstrap", artifacts.baseline.artifact, cassettePath, { capture: recordedExchanges });
        const replayFailedStage = invokeReplayDriver("stage", artifacts.failed.artifact, cassettePath, {
          capture: recordedExchanges,
          expectedFailure: true,
        });
        const replayStage = invokeReplayDriver("stage", artifacts.candidate.artifact, cassettePath, { capture: recordedExchanges });
        if (replayBootstrap.status !== 0 || replayFailedStage.status === 0 || replayStage.status !== 0) {
          throw new Blocked("replay_setup_failed", "the immutable cassette could not reach the same browser setup", {
            bootstrap_status: replayBootstrap.status,
            failed_stage_status: replayFailedStage.status,
            stage_status: replayStage.status,
          });
        }
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after replay setup");
        assertReleaseState(releaseRoot, artifacts.baseline, null, "after replay setup");
        healthCheck(artifacts.baseline, "after replay setup", { replay: cassettePath });
        try {
          try {
            const replayResult = await e2e_release_promotion_never_mixes_server_and_ui_revision({
              uiUrl,
              releaseRoot,
              baselineArtifact: artifacts.baseline,
              candidateArtifact: artifacts.candidate,
              healthCheck: (expectedArtifact, phase) => healthCheck(expectedArtifact, phase, { replay: cassettePath }),
              promoteRelease: () => invokeReplayDriver("promote", null, cassettePath, { capture: recordedExchanges }),
              rollbackRelease: () => invokeReplayDriver("rollback", null, cassettePath, { capture: recordedExchanges }),
              replay: cassettePath,
              exchangeSequenceOffset: replayExchangeSequenceOffset,
              // Replay browser requests use the cassette's browser-relative
              // sequence offset.  A fresh live allocator would silently
              // override that mapping and make an otherwise exact cassette
              // appear to bind to the wrong exchange.
              sequenceAllocator: null,
            });
            browserExchangesForIncident = replayResult.exchanges;
          } catch (failure) {
            if (failure instanceof Blocked) throw failure;
            assertReplayFailureBinding(cassette, failure);
            const expected = cassette.first_observed?.code;
            if (expected && failure.code !== expected) {
              throw new BehaviorFailure("replay_reason_mismatch", "the immutable cassette failed for a different safe reason", {
                expected,
                observed: failure.code,
              });
            }
            throw failure;
          }
          if (replayExpectation === "red") {
            throw new BehaviorFailure("replay_did_not_red", "the immutable cassette did not reproduce its recorded failure");
          }
          replayPassed = true;
        } finally {
          assertArtifactsUnchanged(artifacts, artifactSnapshots, "after replay promotion and rollback");
        }
      }

      if (replayPassed) {
        runSucceeded = true;
        successReport = {
          ok: true,
          owner: OWNER,
          mode: "replay-green",
          e2e_names: [ARTIFACT_BINDING_E2E, PROMOTION_REVISION_E2E],
          revisions,
          driver_sha256: driverRecord.binary_sha256,
          workRoot: args.keepWorkdir ? workRoot : undefined,
        };
        return;
      }

      const capture = { capture: recordedExchanges };
      const bootstrap = invokeDriver("bootstrap", artifacts.baseline.artifact, {
        ...capture,
        e2eName: PROMOTION_REVISION_E2E,
      });
      if (bootstrap.status !== 0) throw new Blocked("bootstrap_failed", "baseline bootstrap failed before a valid browser path", { status: bootstrap.status });
      try {
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after baseline bootstrap");
        assertReleaseState(releaseRoot, artifacts.baseline, null, "after baseline bootstrap");
        healthCheck(artifacts.baseline, "after baseline bootstrap");
      } catch (error) {
        throw bindDriverOperationFailure(error, recordedExchanges, "bootstrap", artifacts.baseline);
      }

      const beforeFailedStage = pointerSnapshot(releaseRoot);
      let failed;
      await observeStablePointerState(
        releaseRoot,
        beforeFailedStage,
        "failed health gate",
        async () => {
          failed = await invokeDriverAsync("stage", artifacts.failed.artifact, {
            ...capture,
            e2eName: PROMOTION_REVISION_E2E,
            expectedFailure: true,
          });
        },
      );
      try {
        assertFailedStageIndependentObservation(failed, artifacts.failed, releaseRoot, "failed health gate", {
          uiUrl,
          onLiveProcesses: recordReleaseProcesses,
        });
        assertRealHealthFailure(failed, artifacts.failed, "failed health gate");
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after failed health gate");
        assertReleaseState(releaseRoot, artifacts.baseline, null, "after failed health gate");
        assertSnapshotEqual(beforeFailedStage, pointerSnapshot(releaseRoot), "after failed health gate");
        healthCheck(artifacts.baseline, "after failed health gate");
      } catch (error) {
        throw bindDriverOperationFailure(error, recordedExchanges, "stage", artifacts.failed);
      }

      const beforeCandidateStage = pointerSnapshot(releaseRoot);
      let staged;
      await observeStablePointerState(
        releaseRoot,
        beforeCandidateStage,
        "candidate staging",
        async () => {
          staged = await invokeDriverAsync("stage", artifacts.candidate.artifact, {
            ...capture,
            e2eName: PROMOTION_REVISION_E2E,
          });
        },
      );
      try {
        assertCandidateStageIndependentObservation(staged, artifacts.candidate, releaseRoot, "candidate staging", {
          uiUrl,
          onLiveProcesses: recordReleaseProcesses,
        });
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after candidate staging");
        assertReleaseState(releaseRoot, artifacts.baseline, null, "before browser promotion");
        assertSnapshotEqual(beforeCandidateStage, pointerSnapshot(releaseRoot), "before browser promotion");
      } catch (error) {
        throw bindDriverOperationFailure(error, recordedExchanges, "stage", artifacts.candidate);
      }

      try {
        const liveResult = await e2e_release_promotion_never_mixes_server_and_ui_revision({
          uiUrl,
          releaseRoot,
          baselineArtifact: artifacts.baseline,
          candidateArtifact: artifacts.candidate,
          healthCheck,
          promoteRelease,
          rollbackRelease,
          replay: null,
          sequenceAllocator: nextExchangeSequence,
        });
        browserExchangesForIncident = liveResult.exchanges;
      } finally {
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after promotion and rollback");
      }
    } catch (failure) {
      if (failure instanceof BehaviorFailure && !args.replay && recordingProvenance) {
        // Keep raw captures in the ignored test-recording area.  Reviewed
        // cassettes belong to this owning suite's immutable fixture tree;
        // neither default is a tracked-looking output directory.
        const quarantineRoot = resolve(process.env.ZODE_RELEASE_QUARANTINE || join(repoRoot, "target", "test-recordings", "quarantine"));
        const cassetteRoot = resolve(process.env.ZODE_RELEASE_CASSETTES || join(repoRoot, "tests", "release_e2e", "fixtures", "incidents"));
        const browserExchanges = failure.details?.exchanges || browserExchangesForIncident;
        const evidence = normalizeIncidentEvidence(recordedExchanges, browserExchanges, failure);
        incident = writeIncident(
          evidence.exchanges,
          evidence.failure,
          quarantineRoot,
          cassetteRoot,
          args.promote,
          knownSecretValues({ required: args.promote }),
          recordingProvenance,
        );
        throw new BehaviorFailure(
          evidence.failure.code,
          `${evidence.failure.message}; first occurrence: ${incident.rawPath}${incident.cassettePath ? `; cassette: ${incident.cassettePath}` : ""}`,
          { ...publicFailureDetails(evidence.failure.details), incident },
        );
      }
      throw failure;
    }
    runSucceeded = true;
    successReport = {
      ok: true,
      owner: OWNER,
      e2e_names: [ARTIFACT_BINDING_E2E, PROMOTION_REVISION_E2E],
      revisions,
      driver_sha256: driverRecord.binary_sha256,
      workRoot: args.keepWorkdir ? workRoot : undefined,
    };
  } finally {
    if (driver && releaseRoot) {
      try {
        const teardown = runDriver(driver, "teardown", releaseRoot, null, {
          driverSha256: driverRecord?.binary_sha256,
        });
        stopReports = stopReportsFromPayload(teardown.payload, "after teardown");
        const stoppedInstances = new Set(stopReports.map((report) => report.instance_id));
        for (const instanceId of observedReleaseInstances) {
          if (!stoppedInstances.has(instanceId)) {
            throw new BehaviorFailure("release_process_stop_missing", "teardown did not report every observed release instance", {
              e2e_name: PROMOTION_REVISION_E2E,
              instance_id: instanceId,
            });
          }
        }
        if (teardown.status !== 0) {
          teardownFailure = new BehaviorFailure("teardown_failed", "release teardown returned a non-zero exit status", {
            e2e_name: PROMOTION_REVISION_E2E,
            exit_status: teardown.status,
          });
        }
      } catch (error) {
        teardownFailure = new BehaviorFailure("teardown_failed", "release teardown did not complete with a valid result", {
          e2e_name: PROMOTION_REVISION_E2E,
          error: String(error),
        });
      }
    }
    if (releaseRoot) {
      try {
        assertReleaseProcessesReaped(releaseRoot, "after teardown", [...observedReleasePids], stopReports, observedReleaseEvidence);
      } catch (error) {
        reapFailure = error instanceof BehaviorFailure
          ? error
          : new BehaviorFailure("release_process_leaked", "release process reap could not be verified", { error: String(error) });
      }
    }
    if (artifacts && artifactSnapshots) {
      try {
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after teardown");
      } catch (error) {
        payloadFailure = error instanceof BehaviorFailure
          ? error
          : new BehaviorFailure("staged_payload_mutated", "release payload re-hash after teardown failed", { error: String(error) });
      }
    }
    if (!args.keepWorkdir) rmSync(workRoot, { recursive: true, force: true });
    const cleanupFailures = [teardownFailure, reapFailure, payloadFailure].filter(Boolean);
    if (cleanupFailures.length && !runSucceeded) {
      console.error(JSON.stringify({
        status: "CLEANUP_FAILED",
        owner: OWNER,
        failures: cleanupFailures.map((failure) => ({
          code: failure.code,
          message: failure.message,
          details: failure.details,
        })),
      }, null, 2));
    }
    if (runSucceeded && cleanupFailures.length) {
      if (cleanupFailures.length === 1) throw cleanupFailures[0];
      throw new BehaviorFailure("release_cleanup_failed", "release teardown, reap, or payload re-hash failed", {
        failures: cleanupFailures.map((failure) => ({
          code: failure.code,
          message: failure.message,
          details: failure.details,
        })),
      });
    }
  }
  if (successReport) console.log(JSON.stringify(successReport, null, 2));
}

try {
  await main();
} catch (error) {
  if (error instanceof BehaviorFailure) {
    console.error(JSON.stringify({ status: "RED", owner: OWNER, code: error.code, message: error.message, details: publicFailureDetails(error.details) }, null, 2));
    process.exitCode = 1;
  } else if (error instanceof Blocked) {
    console.error(JSON.stringify({ status: "BLOCKED", owner: OWNER, code: error.code, message: error.message, details: error.details }, null, 2));
    process.exitCode = BLOCKED_EXIT;
  } else {
    console.error(JSON.stringify({ status: "HARNESS_ERROR", owner: OWNER, code: "unexpected_harness_error", message: String(error) }, null, 2));
    process.exitCode = 2;
  }
}
