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
import { spawnSync } from "node:child_process";
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
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: options.encoding ?? "utf8",
    input: options.input,
    maxBuffer: 8 * 1024 * 1024,
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

function ensureDirectory(path, mode = 0o700) {
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

function pathIsContained(root, candidate) {
  const relativePath = relative(resolve(root), resolve(candidate));
  return relativePath === ""
    || (!isAbsolute(relativePath)
      && relativePath !== ".."
      && !relativePath.startsWith(`..${sep}`));
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
}

function requiredSurface(repoRoot, commit) {
  const required = [
    "Cargo.toml",
    "Cargo.lock",
    "server/Cargo.toml",
    "server/Cargo.lock",
    "web/package.json",
  ];
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
  if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
    throw new Blocked("release_driver_missing", "frozen checkout does not contain the real release driver", {
      relative_path: relativePath,
      source,
    });
  }
  return source;
}

function packageArtifact(checkout, commit, outputRoot, logsRoot, driverSource) {
  const web = join(checkout, "web");
  const ui = firstExisting([join(web, "dist"), join(web, "build")]);
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
    components,
    driver: driverBinding,
    binding: {
      revision: commit,
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

function runDriver(driver, operation, releaseRoot, artifact, options = {}) {
  if (typeof options.driverSha256 !== "string") {
    throw new Blocked("release_driver_unbound", "release driver invocation has no immutable manifest binding", {
      operation,
    });
  }
  assertExecutableDigest(driver, options.driverSha256, "release driver", `${operation} driver invocation`);
  let extra = [];
  if (process.env.ZODE_RELEASE_DRIVER_ARGS_JSON) {
    try {
      extra = JSON.parse(process.env.ZODE_RELEASE_DRIVER_ARGS_JSON);
    } catch (error) {
      throw new Blocked("driver_arguments", "ZODE_RELEASE_DRIVER_ARGS_JSON is malformed", { error: String(error) });
    }
  }
  if (!Array.isArray(extra) || extra.some((value) => typeof value !== "string")) {
    throw new Blocked("driver_arguments", "ZODE_RELEASE_DRIVER_ARGS_JSON must be a JSON string array");
  }
  const args = [...extra, operation, "--release-root", releaseRoot, "--json"];
  if (artifact) args.push("--artifact", artifact);
  if (options.replay) args.push("--replay-cassette", options.replay);
  const result = runSync(driver, args, {
    cwd: options.cwd,
    env: {
      ...process.env,
      ZODE_RELEASE_E2E_OWNER: OWNER,
      ZODE_RELEASE_E2E_MODE: options.replay ? "replay" : "live",
      ZODE_RELEASE_E2E_NAME: options.e2eName ?? PROMOTION_REVISION_E2E,
      ...(options.replay ? { ZODE_RELEASE_REPLAY_CASSETTE: options.replay } : {}),
    },
  });
  if (options.capture) {
    options.capture.push({
      sequence: options.capture.length,
      request: {
        method: "CLI",
        path: `release-driver/${operation}`,
        headers: {},
        body: boundedBuffer(Buffer.from(JSON.stringify({ operation, e2e_name: options.e2eName ?? PROMOTION_REVISION_E2E }), "utf8")),
      },
      response: {
        status: result.status,
        headers: {},
        body: boundedBuffer(Buffer.from(`${result.stdout}${result.stderr}`, "utf8")),
        completed: true,
      },
    });
  }
  const payload = parseJsonLine(`${result.stdout}\n${result.stderr}`, `${operation} driver`);
  return { ...result, payload };
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
    if (lstatSync(path).isSymbolicLink()) target = realpathSync(path);
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

function processHasRole(executable, role) {
  const rolePattern = role === "server"
    ? /(?:^|[\/\s])zode-server(?:$|[\s])/i
    : /(?:^|[\/\s])zode(?:$|[\s])/i;
  return rolePattern.test(executable);
}

function processNameHasRole(name, role) {
  const executableName = basename(String(name));
  return role === "server" ? executableName === "zode-server" : executableName === "zode";
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

function assertLiveReleaseProcesses(releaseRoot, expectedArtifact, phase) {
  const entries = releaseProcessTable(releaseRoot, phase);
  const candidates = entries.filter((entry) => (
    processNameHasRole(entry.comm, "server") || processNameHasRole(entry.comm, "endpoint")
  ));
  if (!candidates.length) {
    throw new Blocked("release_process_missing", `${phase}: no live release process was available for independent observation`, {
      required: ["Server PID", "Endpoint PID", "immutable executable", "HTTP listener"],
    });
  }
  const annotated = candidates.map((entry) => ({ ...entry, executable: processExecutablePath(entry, phase) }));
  const servers = annotated.filter((entry) => processHasRole(entry.executable, "server"));
  const endpoints = annotated.filter((entry) => processHasRole(entry.executable, "endpoint"));
  if (servers.length !== 1 || endpoints.length !== 1 || servers[0].pid === endpoints[0].pid) {
    throw new BehaviorFailure("release_process_topology", `${phase}: live Server and Endpoint PIDs were not independently observed`, {
      e2e_name: PROMOTION_REVISION_E2E,
      phase,
      server_pids: servers.map((entry) => entry.pid),
      endpoint_pids: endpoints.map((entry) => entry.pid),
      processes: annotated,
    });
  }
  const expected = expectedArtifact.manifest.components;
  for (const [role, entry, digest] of [
    ["server", servers[0], expected.server.binary_sha256],
    ["endpoint", endpoints[0], expected.endpoint.binary_sha256],
  ]) {
    const stat = lstatOrNull(entry.executable);
    if (!stat || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o222) !== 0 || (stat.mode & 0o111) === 0) {
      throw new BehaviorFailure("release_process_executable_invalid", `${phase}: live ${role} executable is not immutable`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role,
        pid: entry.pid,
        executable: entry.executable,
      });
    }
    let observed;
    try {
      observed = sha256(readFileSync(entry.executable));
    } catch (error) {
      throw new BehaviorFailure("release_process_probe_failed", `${phase}: live ${role} executable could not be hashed`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role,
        pid: entry.pid,
        executable: entry.executable,
        error: String(error),
      });
    }
    if (observed !== digest) {
      throw new BehaviorFailure("release_process_digest_mismatch", `${phase}: live ${role} executable is not the bound artifact`, {
        e2e_name: PROMOTION_REVISION_E2E,
        phase,
        role,
        pid: entry.pid,
        executable: entry.executable,
        expected: digest,
        observed,
      });
    }
  }
  const pids = processDescendantPids(entries, [servers[0].pid, endpoints[0].pid]);
  return {
    server: { pid: servers[0].pid, executable: servers[0].executable },
    endpoint: { pid: endpoints[0].pid, executable: endpoints[0].executable },
    pids,
  };
}

function assertReleaseProcessesReaped(releaseRoot, phase, observedPids = []) {
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

function readRealHttpResponse(url, role, phase) {
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
      && (value.deployment === "server_only" || value.deployment === "all_in_one")
      && (typeof value.local_endpoint_id === "string" || value.local_endpoint_id === null)
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
  const process = processEvidence?.[role];
  if (!process) {
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
    result = runSync("lsof", ["-nP", "-a", "-p", String(process.pid), `-iTCP:${port}`, "-sTCP:LISTEN", "-Fn"]);
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
      pid: process.pid,
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
  if (options.uiUrl) {
    observations.push(probeUiListener(options.uiUrl, processEvidence, phase, { expectHealthy }));
  }
  return observations;
}

function probeUiListener(uiUrl, processEvidence, phase, { expectHealthy = true } = {}) {
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
  return observation;
}

function assertFailedStageIndependentObservation(result, failedArtifact, releaseRoot, phase, options = {}) {
  const liveProcesses = assertLiveReleaseProcesses(releaseRoot, failedArtifact, phase);
  options.onLiveProcesses?.(liveProcesses);
  const observations = assertRealHttpReadiness(result.payload?.health, phase, liveProcesses, {
    expectHealthy: false,
    uiUrl: options.uiUrl,
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

function readReleaseHealth(driver, releaseRoot, expectedArtifact, phase, options = {}) {
  try {
    const result = runDriver(driver, "health", releaseRoot, null, {
      capture: options.capture,
      e2eName: PROMOTION_REVISION_E2E,
      replay: options.replay,
      driverSha256: options.driverSha256,
    });
    const liveProcesses = assertLiveReleaseProcesses(releaseRoot, expectedArtifact, phase);
    options.onLiveProcesses?.(liveProcesses);
    assertRealHttpReadiness(result.payload?.health, phase, liveProcesses, {
      expectHealthy: true,
      uiUrl: options.uiUrl,
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
        if (actionStarted && canonicalWatcherEvents.has(event) && canonicalPointerNames.has(filename)) {
          events.push({ source, event, filename, state: isAfter ? "after" : "before" });
          if (isAfter) afterPointerEventsObserved.add(filename);
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
  replay,
  exchangeSequenceOffset = 0,
}) {
  const playwright = resolvePlaywright();
  const executablePath = process.env.ZODE_RELEASE_BROWSER_EXECUTABLE
    || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  const browser = await playwright.chromium.launch({
    executablePath: existsSync(executablePath) ? executablePath : undefined,
    headless: process.env.ZODE_RELEASE_HEADFUL !== "1",
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  const exchanges = new Map();
  const exchangeList = [];
  const pendingResponses = new Set();
  page.on("request", (request) => {
    const key = `${request.method()} ${safeUrl(request.url())} ${exchangeList.length}`;
    const entry = {
      sequence: exchangeSequenceOffset + exchangeList.length,
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
          body: boundedBuffer(await response.body()),
          completed: prior?.request_failed === true ? false : true,
          request_failed: prior?.request_failed === true,
          disconnected: prior?.disconnected === true,
          failure: prior?.failure ?? null,
        };
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

    const state = async () => page.evaluate(() => {
      const marker = (selector) => {
        const node = document.querySelector(selector);
        if (!node) return null;
        return node.getAttribute(selector.slice(1, -1))?.trim() || node.textContent?.trim() || null;
      };
      return {
        current: marker("[data-zode-release-current-revision]"),
        previous: marker("[data-zode-release-previous-revision]"),
        staged: marker("[data-zode-release-staged-revision]"),
        runtime: {
          revision: marker("[data-zode-release-runtime-revision]"),
          ui_revision: marker("[data-zode-release-ui-revision]"),
          server_revision: marker("[data-zode-release-server-revision]"),
          endpoint_revision: marker("[data-zode-release-endpoint-revision]"),
          ui_tree_sha256: marker("[data-zode-release-ui-tree-sha256]"),
          server_binary_sha256: marker("[data-zode-release-server-binary-sha256]"),
          endpoint_binary_sha256: marker("[data-zode-release-endpoint-binary-sha256]"),
        },
      };
    });
    const initial = await state();
    if (!initial.current || initial.current !== baselineArtifact.revision) {
      throw new BehaviorFailure("browser_current_mismatch", "browser did not show the baseline current revision", {
        e2e_name: PROMOTION_REVISION_E2E,
        expected: baselineArtifact.revision,
        observed: initial,
      });
    }
    if (initial.staged !== candidateArtifact.revision) {
      throw new BehaviorFailure("browser_staged_mismatch", "browser did not show the staged candidate revision", {
        e2e_name: PROMOTION_REVISION_E2E,
        expected: candidateArtifact.revision,
        observed: initial,
      });
    }
    const initialRuntime = assertRuntimeBinding(initial.runtime, baselineArtifact, "before browser promotion", "browser");
    const initialHealth = await healthCheck(baselineArtifact, "before browser promotion");
    if (JSON.stringify(initialRuntime) !== JSON.stringify(initialHealth)) {
      healthBindingFailure("release_browser_health_mismatch", "browser and real health disagree before promotion", {
        phase: "before browser promotion",
        browser: initialRuntime,
        health: initialHealth,
      });
    }

    await observePointerTransition(
      releaseRoot,
      expectedPointerState(baselineArtifact, null),
      expectedPointerState(candidateArtifact, baselineArtifact),
      "promotion",
      async () => {
        await page.getByRole("button", { name: "Promote staged release", exact: true }).click();
        await page.waitForFunction(
          (expected) => {
            const marker = (selector) => {
              const node = document.querySelector(selector);
              return node?.getAttribute(selector.slice(1, -1))?.trim() || node?.textContent?.trim() || null;
            };
            return marker("[data-zode-release-current-revision]") === expected.current
              && marker("[data-zode-release-previous-revision]") === expected.previous;
          },
          { current: candidateArtifact.revision, previous: baselineArtifact.revision },
          { timeout: 10_000 },
        );
      },
    );
    const promoted = await state();
    if (promoted.current !== candidateArtifact.revision || promoted.previous !== baselineArtifact.revision) {
      throw new BehaviorFailure("browser_promotion_mismatch", "browser promotion did not produce current/previous atomically", {
        e2e_name: PROMOTION_REVISION_E2E,
        expected: { current: candidateArtifact.revision, previous: baselineArtifact.revision },
        observed: promoted,
      });
    }
    assertRuntimeBinding(promoted.runtime, candidateArtifact, "after browser promotion", "browser");
    const promotedHealth = await healthCheck(candidateArtifact, "after browser promotion");
    if (JSON.stringify(promoted.runtime) !== JSON.stringify(promotedHealth)) {
      healthBindingFailure("release_browser_health_mismatch", "browser and real health disagree after promotion", {
        phase: "after browser promotion",
        browser: promoted.runtime,
        health: promotedHealth,
      });
    }
    assertReleaseState(releaseRoot, candidateArtifact, baselineArtifact, "after browser promotion");

    await observePointerTransition(
      releaseRoot,
      expectedPointerState(candidateArtifact, baselineArtifact),
      expectedPointerState(baselineArtifact, candidateArtifact),
      "rollback",
      async () => {
        await page.getByRole("button", { name: "Rollback current release", exact: true }).click();
        await page.waitForFunction(
          (expected) => {
            const marker = (selector) => {
              const node = document.querySelector(selector);
              return node?.getAttribute(selector.slice(1, -1))?.trim() || node?.textContent?.trim() || null;
            };
            return marker("[data-zode-release-current-revision]") === expected.current
              && marker("[data-zode-release-previous-revision]") === expected.previous;
          },
          { current: baselineArtifact.revision, previous: candidateArtifact.revision },
          { timeout: 10_000 },
        );
      },
    );
    const rolledBack = await state();
    if (rolledBack.current !== baselineArtifact.revision || rolledBack.previous !== candidateArtifact.revision) {
      throw new BehaviorFailure("browser_rollback_mismatch", "browser rollback did not restore the previous release", {
        e2e_name: PROMOTION_REVISION_E2E,
        expected: { current: baselineArtifact.revision, previous: candidateArtifact.revision },
        observed: rolledBack,
      });
    }
    assertRuntimeBinding(rolledBack.runtime, baselineArtifact, "after browser rollback", "browser");
    const rolledBackHealth = await healthCheck(baselineArtifact, "after browser rollback");
    if (JSON.stringify(rolledBack.runtime) !== JSON.stringify(rolledBackHealth)) {
      healthBindingFailure("release_browser_health_mismatch", "browser and real health disagree after rollback", {
        phase: "after browser rollback",
        browser: rolledBack.runtime,
        health: rolledBackHealth,
      });
    }
    assertReleaseState(releaseRoot, baselineArtifact, candidateArtifact, "after browser rollback");

    const reloadResponse = await page.reload({ waitUntil: "domcontentloaded", timeout: 10_000 });
    const reloadStatus = reloadResponse?.status() ?? 0;
    if (reloadStatus < 200 || reloadStatus >= 300) {
      throw new BehaviorFailure("browser_rollback_reload_failed", "browser reload after rollback did not return a successful UI document", {
        e2e_name: PROMOTION_REVISION_E2E,
        status: reloadStatus,
      });
    }
    await page.waitForFunction(
      (expected) => {
        const marker = (selector) => {
          const node = document.querySelector(selector);
          return node?.getAttribute(selector.slice(1, -1))?.trim() || node?.textContent?.trim() || null;
        };
        return marker("[data-zode-release-current-revision]") === expected.current
          && marker("[data-zode-release-previous-revision]") === expected.previous;
      },
      { current: baselineArtifact.revision, previous: candidateArtifact.revision },
      { timeout: 10_000 },
    );
    const reloaded = await state();
    if (reloaded.current !== baselineArtifact.revision || reloaded.previous !== candidateArtifact.revision) {
      throw new BehaviorFailure("browser_rollback_reload_mismatch", "browser reload did not retain the rolled-back release pointers", {
        e2e_name: PROMOTION_REVISION_E2E,
        expected: { current: baselineArtifact.revision, previous: candidateArtifact.revision },
        observed: reloaded,
      });
    }
    assertRuntimeBinding(reloaded.runtime, baselineArtifact, "after browser rollback reload", "browser");
    const reloadedHealth = await healthCheck(baselineArtifact, "after browser rollback reload");
    if (JSON.stringify(reloaded.runtime) !== JSON.stringify(reloadedHealth)) {
      healthBindingFailure("release_browser_health_mismatch", "browser reload and real health disagree after rollback", {
        phase: "after browser rollback reload",
        browser: reloaded.runtime,
        health: reloadedHealth,
      });
    }
    assertReleaseState(releaseRoot, baselineArtifact, candidateArtifact, "after browser rollback reload");
    await Promise.allSettled([...pendingResponses]);
    return { exchanges: exchangeList, browser: { initial, promoted, rolledBack, reloaded }, replay };
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
    const safeBytes = Buffer.from(
      sanitizeText(originalBytes.toString("utf8"), knownValues),
      "utf8",
    );
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
    synthetic_secret_slots: ["SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_SECRET"],
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
  if (exchange.request?.method === "CLI") return exchange.response.status !== 0;
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
  ) {
    throw new Blocked("cassette_binding_mismatch", `${label} is not bound to the exact promotion browser failure`);
  }
  const sequenceValues = cassette.exchanges.map((entry) => entry.sequence);
  if (
    sequenceValues.some((sequence) => !Number.isSafeInteger(sequence) || sequence < 0)
    || new Set(sequenceValues).size !== sequenceValues.length
  ) {
    throw new Blocked("cassette_binding_mismatch", `${label} does not contain unique exact exchange sequences`);
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

function writeIncident(exchanges, failure, quarantineRoot, cassetteRoot, promote, knownValues = null) {
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

function bindDriverOperationFailure(failure, exchanges, operation) {
  if (!(failure instanceof BehaviorFailure) || failure.details?.first_failure) return failure;
  const exchange = exchanges.find((entry) => entry.request?.path === `release-driver/${operation}`);
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
  const recorded = recordedExchanges.map((exchange) => ({ ...exchange }));
  const browser = (browserExchanges ?? []).map((exchange, index) => ({
    ...exchange,
    sequence: recorded.length + index,
  }));
  let firstFailure = failure.details?.first_failure;
  if (firstFailure?.boundary === "management-browser-release-entry") {
    const local = (browserExchanges ?? []).find((exchange) => exchange.sequence === firstFailure.sequence);
    if (local) {
      firstFailure = { ...firstFailure, sequence: recorded.length + ((browserExchanges ?? []).indexOf(local)) };
    }
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
  return { exchanges: [...recorded, ...browser], failure };
}

async function buildRevision({ repoRoot, commit, workRoot, label, driverRelativePath }) {
  const missing = requiredSurface(repoRoot, commit);
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
  const logs = join(workRoot, `${label}-logs`);
  ensureDirectory(logs, 0o700);
  runChecked("vp", ["build"], join(checkout, "web"), join(logs, "ui.log"));
  runChecked("vp", ["exec", "cargo", "build", "--release", "--locked", "--manifest-path", join(checkout, "Cargo.toml")], checkout, join(logs, "endpoint.log"));
  runChecked("vp", ["exec", "cargo", "build", "--release", "--locked", "--manifest-path", join(checkout, "server", "Cargo.toml")], checkout, join(logs, "server.log"));
  const driverSource = selectDriverSource(checkout, driverRelativePath);
  return packageArtifact(checkout, commit, join(workRoot, "artifacts"), logs, driverSource);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
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

  const workRoot = resolve(mkdtempSync(join(tmpdir(), "zode-release-e2e-")));
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
  try {
    artifacts = {};
    for (const [label, commit] of Object.entries(revisions)) {
      artifacts[label] = await buildRevision({ repoRoot, commit, workRoot, label, driverRelativePath });
    }
    artifactSnapshots = snapshotArtifacts(artifacts);
    driverRecord = artifacts.baseline.driver;
    driver = artifacts.baseline.driverPath;
    assertExecutableDigest(driver, driverRecord.binary_sha256, "release driver", "immutable checkout selection");
    const uiUrl = process.env.ZODE_RELEASE_UI_URL;
    if (!uiUrl) throw new Blocked("browser_entry_missing", "ZODE_RELEASE_UI_URL is required for the real browser entry");
    assertLocalBrowserUrl(uiUrl);
    releaseRoot = join(workRoot, "release-root");
    ensureDirectory(releaseRoot, 0o700);
    assertReleaseRoot(releaseRoot);
    const recordedExchanges = [];
    let browserExchangesForIncident = [];
    const invokeDriver = (operation, artifact, options = {}) => runDriver(
      driver,
      operation,
      releaseRoot,
      artifact,
      { ...options, driverSha256: driverRecord.binary_sha256 },
    );
    const recordReleaseProcesses = (processes) => {
      for (const pid of processes.pids ?? [processes.server.pid, processes.endpoint.pid]) {
        observedReleasePids.add(pid);
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
        uiUrl,
        onLiveProcesses: recordReleaseProcesses,
      },
    );

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
        if ((cassetteStat.mode & 0o222) !== 0) {
          throw new Blocked("cassette_not_immutable", "replay cassette is writable");
        }
        const { envelope_sha256: envelopeDigest, ...withoutDigest } = cassette;
        if (!envelopeDigest || sha256(jsonBytes(withoutDigest)) !== envelopeDigest) {
          throw new Blocked("cassette_integrity", "replay cassette envelope digest does not match");
        }
        const replayBootstrap = invokeDriver("bootstrap", artifacts.baseline.artifact, { replay: cassettePath, capture: recordedExchanges });
        const replayStage = invokeDriver("stage", artifacts.candidate.artifact, { replay: cassettePath, capture: recordedExchanges });
        if (replayBootstrap.status !== 0 || replayStage.status !== 0) {
          throw new Blocked("replay_setup_failed", "the immutable cassette could not reach the same browser setup", {
            bootstrap_status: replayBootstrap.status,
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
              replay: cassettePath,
              exchangeSequenceOffset: replayExchangeSequenceOffset,
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
          throw new BehaviorFailure("replay_did_not_red", "the immutable cassette did not reproduce its recorded failure");
        } finally {
          assertArtifactsUnchanged(artifacts, artifactSnapshots, "after replay promotion and rollback");
        }
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
        throw bindDriverOperationFailure(error, recordedExchanges, "bootstrap");
      }

      const beforeFailedStage = pointerSnapshot(releaseRoot);
      const failed = invokeDriver("stage", artifacts.failed.artifact, {
        ...capture,
        e2eName: PROMOTION_REVISION_E2E,
      });
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
        throw bindDriverOperationFailure(error, recordedExchanges, "stage");
      }

      const beforeCandidateStage = pointerSnapshot(releaseRoot);
      const staged = invokeDriver("stage", artifacts.candidate.artifact, {
        ...capture,
        e2eName: PROMOTION_REVISION_E2E,
      });
      if (staged.status !== 0) throw new Blocked("candidate_stage_failed", "candidate did not reach the browser promotion stage", { status: staged.status });
      try {
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after candidate staging");
        assertReleaseState(releaseRoot, artifacts.baseline, null, "before browser promotion");
        assertSnapshotEqual(beforeCandidateStage, pointerSnapshot(releaseRoot), "before browser promotion");
        healthCheck(artifacts.baseline, "before browser promotion");
      } catch (error) {
        throw bindDriverOperationFailure(error, recordedExchanges, "stage");
      }

      try {
        const liveResult = await e2e_release_promotion_never_mixes_server_and_ui_revision({
          uiUrl,
          releaseRoot,
          baselineArtifact: artifacts.baseline,
          candidateArtifact: artifacts.candidate,
          healthCheck,
          replay: null,
        });
        browserExchangesForIncident = liveResult.exchanges;
      } finally {
        assertArtifactsUnchanged(artifacts, artifactSnapshots, "after promotion and rollback");
      }
    } catch (failure) {
      if (failure instanceof BehaviorFailure && !args.replay) {
        const quarantineRoot = resolve(process.env.ZODE_RELEASE_QUARANTINE || join(repoRoot, "tests", "release_e2e", "quarantine"));
        const cassetteRoot = resolve(process.env.ZODE_RELEASE_CASSETTES || join(repoRoot, "tests", "release_e2e", "cassettes"));
        const browserExchanges = failure.details?.exchanges || browserExchangesForIncident;
        const evidence = normalizeIncidentEvidence(recordedExchanges, browserExchanges, failure);
        incident = writeIncident(
          evidence.exchanges,
          evidence.failure,
          quarantineRoot,
          cassetteRoot,
          args.promote,
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
        assertReleaseProcessesReaped(releaseRoot, "after teardown", [...observedReleasePids]);
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
