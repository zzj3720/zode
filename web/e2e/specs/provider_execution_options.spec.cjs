const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RealProcess,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");

const E2E = "e2e_server_forwards_and_endpoint_persists_provider_execution_options";
const CAPTURE_ENV = "ZODE_CAPTURE_PROVIDER_EXECUTION_OPTIONS_LATER_GAP";
const RELATION = "later_test_reproduction_of_gap";
const CLASSIFICATION = `PROVIDER_EXECUTION_OPTIONS_DROPPED__${RELATION}`;
const HARNESS_CLASSIFICATION = `HARNESS_PROVIDER_EXECUTION_OPTIONS_PRECONDITION_FAILED__${RELATION}`;
const FLUSH_CLASSIFICATION = `HARNESS_PROVIDER_EXECUTION_OPTIONS_CAPTURE_FLUSH_FAILED__${RELATION}`;
const ORIGINAL_GAP =
  "target/test-recordings/quarantine/local-evidence-gaps/provider-execution-options-harness-authority-first-run-evidence-gap.v1.json";
const INCIDENT_DIRECTORY = path.resolve(
  __dirname,
  "..",
  "fixtures",
  "incidents",
);
const INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0004-2952afcc-96c4-4a55-bff0-c52774e1f714-027b06e4-94fc-4e68-8683-3092aeb27622.v1.json",
);
const PROVIDER = "options-fixture";
const MODEL = "options-model";
const OPTIONS = Object.freeze({
  options_fixture: Object.freeze({ routing_tag: "persist-across-endpoint-restart" }),
});
const ROOT = path.resolve(__dirname, "..", "..", "..");

function assertLaterCassetteIdentity() {
  const cassette = JSON.parse(fs.readFileSync(INCIDENT_CASSETTE, "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.e2e_name).toBe(E2E);
  expect(cassette.classification).toBe(CLASSIFICATION);
  expect(cassette.first_observed).toContain(`relation=${RELATION}`);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges).toHaveLength(1);
  expect(cassette.exchanges[0].boundary).toBe("management-access-edge");
  expect(cassette.exchanges[0].method).toBe("GET");
  expect(cassette.exchanges[0].response.status).toBe(200);
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function writePrivateDurableJson(filePath, value) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(filePath));
}

function captureSetRecords(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function failureRecord(records, error) {
  const requestPath = error?.details?.requestPath;
  return (requestPath && records.find((record) => record.path === requestPath))
    || records.find((record) => record.response.status >= 400)
    || records.at(-1);
}

function writeFlushGap(harness, captureSetId, error) {
  const gapPath = path.join(harness.journal.rootDir, `${captureSetId}.flush-gap.v1.json`);
  writePrivateDurableJson(gapPath, {
    schema: "zode.test-evidence-gap.v1",
    version: 1,
    owning_e2e: E2E,
    capture_set_id: captureSetId,
    relation: RELATION,
    original_evidence_gap: ORIGINAL_GAP,
    classification: FLUSH_CLASSIFICATION,
    raw_exchange_retained: captureSetRecords(harness, captureSetId).length > 0,
    capture_set_flushed: false,
    do_not_relabel_later_capture: true,
    cause_classification: error?.classification || "recording_flush_failure",
  });
  return gapPath;
}

async function sealCaptureSet(harness, captureSetId, error, relatedCaptureSets = []) {
  try {
    await harness.journal.waitForIdle();
    if (!error) return harness.journal.flushCaptureSet(captureSetId);

    const records = captureSetRecords(harness, captureSetId);
    const record = failureRecord(records, error);
    if (!record) {
      throw new ProductBehaviorFailure(
        FLUSH_CLASSIFICATION,
        "the armed later-reproduction capture contained no completed public exchange",
        { captureSetId, relation: RELATION },
      );
    }
    const capture = harness.journal.flushCaptureSet(captureSetId, {
      firstFailureRecordingId: record.recordingId,
    });
    const metadataPath = path.join(
      harness.journal.rootDir,
      `${captureSetId}.later-reproduction.v1.json`,
    );
    writePrivateDurableJson(metadataPath, {
      schema: "zode.evidence-gap-later-reproduction.v1",
      version: 1,
      owning_e2e: E2E,
      recording_id: record.recordingId,
      capture_set_id: captureSetId,
      relation: RELATION,
      original_evidence_gap: ORIGINAL_GAP,
      classification: error.classification || HARNESS_CLASSIFICATION,
      first_failure_recording_id: record.recordingId,
      first_observed: {
        target_options_assertion_reached: error.classification === CLASSIFICATION,
        request_path: record.path,
        response_status: record.response.status,
      },
      raw_exchange_retained: true,
      source_digest: capture.sourceDigest,
      related_capture_sets: relatedCaptureSets,
      do_not_relabel_as_first: true,
    });
    return { ...capture, metadataPath };
  } catch (flushError) {
    let gapPath;
    try {
      gapPath = writeFlushGap(harness, captureSetId, flushError);
    } catch (gapError) {
      throw new AggregateError(
        [flushError, gapError],
        "later-reproduction capture flush and durable gap metadata both failed",
      );
    }
    throw new ProductBehaviorFailure(
      FLUSH_CLASSIFICATION,
      `later-reproduction capture did not flush; gap=${gapPath}`,
      { captureSetId, relation: RELATION },
    );
  }
}

async function promoteLaterFailure(harness, capture) {
  return harness.journal.promoteFlushedCaptureSet(capture.captureSetId, {
    e2eName: E2E,
    classification: CLASSIFICATION,
    firstObserved:
      `relation=${RELATION}; non-empty safe provider_execution.options were absent after a real Endpoint restart`,
    firstFailureRecordingId: capture.firstFailureRecordingId,
    destinationDirectory: INCIDENT_DIRECTORY,
    replay: (envelope) => harness.journal.replay(envelope, {
      baseUrl: harness.managementUrl,
    }),
  });
}

function productEnvironment(source) {
  const environment = { ...source, NODE_ENV: "test" };
  for (const key of [
    "OPENCODE_GO_API_KEY",
    "OPENCODE_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
  ]) {
    delete environment[key];
  }
  return environment;
}

async function managementJson(harness, method, requestPath, body, idempotencyKey) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (idempotencyKey !== undefined) headers["idempotency-key"] = idempotencyKey;
  const response = await fetch(`${harness.managementUrl}${requestPath}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: response.status, headers: Object.fromEntries(response.headers), text, json };
}

async function requireStatus(result, expected, label) {
  expect(result.status, `${label}: ${result.text}`).toBe(expected);
  return result.json;
}

async function startEndpointRecordingProxy(harness, target) {
  return startHttpServer((request, response) =>
    proxyHttp({
      targetBaseUrl: target.baseUrl,
      request,
      response,
      extraHeaders: {},
      boundary: "server-endpoint-control",
      journal: harness.journal,
      ledger: harness.ledger,
      captureSetId: target.captureSetId,
      canonicalOrigin: target.baseUrl,
    }).catch((error) => {
      harness.journal._fail(error);
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json" });
      }
      if (!response.writableEnded) {
        response.end(JSON.stringify({ error: { code: "endpoint_unavailable", retryable: true } }));
      }
    }),
  );
}

async function restartEndpoint(harness) {
  await harness.endpoint.stop();
  const configPath = path.join(harness.runRoot, "endpoint", "endpoint-config.json");
  const binary = process.env.ZODE_ENDPOINT_BIN || path.join(ROOT, "target", "debug", "zode");
  return RealProcess.start({
    name: "endpoint",
    binary,
    args: ["--config", configPath],
    cwd: ROOT,
    env: productEnvironment(process.env),
    readyPrefix: "ZODE_READY ",
    ledger: harness.ledger,
    logDir: path.join(harness.runRoot, "logs", "endpoint-options-restart"),
    startupCaptureRoot: path.join(harness.journal.rootDir, "startup-options-restart"),
    startupConfigBytes: fs.readFileSync(configPath),
    e2eName: E2E,
  });
}

async function exerciseOptionsContract(harness, endpointCaptureSetId) {
  const target = {
    baseUrl: harness.endpoint.baseUrl,
    captureSetId: endpointCaptureSetId,
  };
  const endpointProxy = await startEndpointRecordingProxy(harness, target);
  let restartedEndpoint;
  try {
    const endpoint = await requireStatus(
      await managementJson(
        harness,
        "POST",
        "/v1/endpoints",
        {
          label: "Options persistence Endpoint",
          base_url: endpointProxy.baseUrl,
          control_auth: { kind: "bearer", secret: harness.controllerSecret },
        },
        "options-endpoint-create",
      ),
      201,
      "Endpoint catalog create",
    );
    const endpointId = endpoint?.endpoint_id;
    expect(typeof endpointId).toBe("string");

    const providerBaseUrl = `${harness.providerProxy.baseUrl}/v1`;
    const descriptor = await requireStatus(
      await managementJson(
        harness,
        "PUT",
        `/v1/providers/${PROVIDER}`,
        {
          kind: "openai_compatible",
          base_url: providerBaseUrl,
          models: [MODEL],
          options: OPTIONS,
        },
        "options-provider-descriptor",
      ),
      200,
      "provider descriptor create",
    );
    expect(descriptor?.options).toEqual(OPTIONS);

    const profile = await requireStatus(
      await managementJson(
        harness,
        "POST",
        `/v1/providers/${PROVIDER}/auth-profiles`,
        {
          kind: "api_key",
          label: "Options profile",
          api_key: harness.providerSecret,
          make_default: true,
          sharing: { mode: "selected", endpoint_ids: [endpointId] },
        },
        "options-profile-create",
      ),
      201,
      "profile create and replica distribution",
    );
    expect(profile?.status).toBe("ready");

    const created = await requireStatus(
      await managementJson(
        harness,
        "POST",
        `/v1/endpoints/${endpointId}/sessions`,
        {
          model: {
            provider: PROVIDER,
            model: MODEL,
            provider_execution: {
              schema: "zode.provider-execution.v1",
              revision: descriptor.revision,
              kind: descriptor.kind,
              base_url: descriptor.base_url,
              options: OPTIONS,
            },
            auth_profile_id: profile.auth_profile_id,
            minimum_auth_revision: profile.revision,
          },
          tools: [],
        },
        "options-session-create",
      ),
      201,
      "Server-proxied Endpoint session create",
    );
    const sessionId = created?.session_id;
    expect(typeof sessionId).toBe("string");

    restartedEndpoint = await restartEndpoint(harness);
    target.baseUrl = restartedEndpoint.baseUrl;

    const sessionPath = `/v1/endpoints/${endpointId}/sessions/${sessionId}`;
    return {
      endpointId,
      sessionId,
      sessionPath,
      target,
      endpointProxy,
      restartedEndpoint,
    };
  } catch (error) {
    await endpointProxy.close().catch(() => undefined);
    await restartedEndpoint?.stop().catch(() => undefined);
    throw error;
  }
}

async function readSessionAfterRestart(harness, sessionPath) {
  return requireStatus(
    await managementJson(harness, "GET", sessionPath),
    200,
    "Endpoint-owned session read after restart",
  );
}

test(E2E, async () => {
  test.setTimeout(120_000);
  assertLaterCassetteIdentity();
  const capture = process.env[CAPTURE_ENV] === "1";
  const harness = await createWebE2EHarness({
    e2eName: E2E,
    uiMode: "api_only",
    includeServerOrigins: true,
    authorityId: "web-e2e-options-authority",
  });
  const endpointCaptureSetId = harness.journal.beginCaptureSet({
    e2eName: `${E2E}__server_endpoint_companion`,
    maxMembers: 32,
  });
  let captureSetId = harness.beginCaptureSet({
    e2eName: `${E2E}__preconditions`,
    maxMembers: 32,
  });
  let captureSetSealed = false;
  let outcome;
  let primaryError;
  let retained;
  try {
    outcome = await exerciseOptionsContract(harness, endpointCaptureSetId);
    await sealCaptureSet(harness, captureSetId);
    captureSetSealed = true;

    captureSetId = harness.beginCaptureSet({ e2eName: E2E, maxMembers: 4 });
    captureSetSealed = false;
    outcome.session = await readSessionAfterRestart(harness, outcome.sessionPath);
    const observed = outcome.session?.model?.provider_execution_options;
    if (JSON.stringify(observed) !== JSON.stringify(OPTIONS)) {
      const failure = new ProductBehaviorFailure(
        CLASSIFICATION,
        "Endpoint-owned session lost the Server-validated provider_execution.options across restart",
        { requestPath: outcome.sessionPath, relation: RELATION },
      );
      throw failure;
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      const endpointCapture = await sealCaptureSet(harness, endpointCaptureSetId);
      if (!captureSetSealed || primaryError) {
        retained = await sealCaptureSet(harness, captureSetId, primaryError, [{
          boundary: "server-endpoint-control",
          capture_set_id: endpointCapture.captureSetId,
          source_digest: endpointCapture.sourceDigest,
        }]);
        captureSetSealed = true;
      }
      if (primaryError && capture) {
        const promoted = primaryError.classification === CLASSIFICATION
          ? await promoteLaterFailure(harness, retained)
          : undefined;
        primaryError = new ProductBehaviorFailure(
          primaryError.classification || HARNESS_CLASSIFICATION,
          `${primaryError.message}; later reproduction=${retained.metadataPath}`
            + (promoted ? `; cassette=${promoted.cassettePath}` : ""),
          {
            ...(primaryError.details || {}),
            captureSetId,
            recordingId: retained.firstFailureRecordingId,
            relation: RELATION,
            ...(promoted ? { cassettePath: promoted.cassettePath } : {}),
          },
        );
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    await outcome?.endpointProxy.close().catch(() => undefined);
    await outcome?.restartedEndpoint.stop().catch(() => undefined);
    try {
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
});
