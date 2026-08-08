const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");

const INCIDENT_DIRECTORY = path.resolve(__dirname, "..", "fixtures", "incidents");
const CAPTURE_CASE_ENV = "ZODE_CAPTURE_SURFACE_AUTHORITY_CASE";
const BOUNDARY = "management-authority-edge";

const CASES = [
  {
    key: "userinfo",
    e2eName: "e2e_browser_management_surface_authority_rejects_userinfo",
    classification: "MANAGEMENT_SURFACE_USERINFO_AUTHORITY_ACCEPTED",
    host: "attacker@127.0.0.1",
    firstObserved: "userinfo in the actual Host authority selected the Access-protected management surface",
    assert(summary) {
      expect(summary.status).toBe(404);
      expect(hasNoStore(summary.headers)).toBe(true);
      expect(summary.headers["content-type"] || "").not.toContain("text/html");
      expect(summary.body).not.toMatch(/<(?:html|script|link|main|nav)\b/iu);
    },
  },
  {
    key: "default-port",
    e2eName: "e2e_browser_management_surface_authority_accepts_default_port_alias",
    classification: "MANAGEMENT_SURFACE_DEFAULT_PORT_ALIAS_REJECTED",
    host: "127.0.0.1:80",
    firstObserved: "the canonical HTTP management origin rejected its explicit default-port Host alias",
    assert(summary) {
      expect(summary.status).toBe(200);
      expect(hasNoStore(summary.headers)).toBe(true);
      expect(JSON.parse(summary.body).schema).toBe("zode.system.v1");
    },
  },
];

function matchingCassettes(testCase) {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === testCase.e2eName
          && value.classification === testCase.classification;
      } catch {
        return false;
      }
    });
}

function assertCassetteIdentity(testCase) {
  const matches = matchingCassettes(testCase);
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.first_observed).toBe(testCase.firstObserved);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges).toHaveLength(1);
  expect(cassette.exchanges[0].boundary).toBe(BOUNDARY);
  expect(cassette.exchanges[0].method).toBe("GET");
  expect(cassette.exchanges[0].path).toBe("/v1/system");
}

function hasNoStore(headers) {
  return (headers["cache-control"] || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .includes("no-store");
}

async function summarize(response) {
  return {
    status: response.status(),
    headers: response.headers(),
    body: await response.text(),
  };
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

async function startAuthorityEdge(harness, captureSetId, host) {
  const assertion = harness.access.issue();
  return startHttpServer((request, response) => proxyHttp({
    targetBaseUrl: harness.server.baseUrl,
    request,
    response,
    extraHeaders: {
      host,
      "cf-access-jwt-assertion": assertion,
    },
    boundary: BOUNDARY,
    journal: harness.journal,
    ledger: harness.ledger,
    captureSetId,
    preserveIncomingHost: true,
  }).catch((error) => {
    harness.journal._fail(error);
    if (!response.headersSent) {
      response.writeHead(502, { "content-type": "application/json" });
    }
    if (!response.writableEnded) {
      response.end(JSON.stringify({ error: { code: "management_unavailable", retryable: true } }));
    }
  }));
}

async function runAuthorityCase(context, testCase) {
  const captureRequested = process.env[CAPTURE_CASE_ENV] === testCase.key;
  if (!captureRequested) assertCassetteIdentity(testCase);

  const harness = await createWebE2EHarness({
    e2eName: testCase.e2eName,
    uiMode: "api_only",
    includeServerOrigins: true,
  });
  const captureSetId = harness.beginCaptureSet({
    e2eName: testCase.e2eName,
    maxMembers: 1,
  });
  const edge = await startAuthorityEdge(harness, captureSetId, testCase.host);
  let primaryError;
  try {
    const summary = await summarize(await context.request.get(`${edge.baseUrl}/v1/system`, {
      headers: { accept: "application/json" },
    }));
    try {
      testCase.assert(summary);
    } catch (error) {
      throw new ProductBehaviorFailure(
        testCase.classification,
        `${testCase.firstObserved}; status=${summary.status}`,
        { status: summary.status, requestPath: "/v1/system" },
      );
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      const records = recordsFor(harness, captureSetId);
      expect(records).toHaveLength(1);
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: records[0].recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        expect(fs.statSync(records[0].rawPath).mode & 0o777).toBe(0o600);
        if (captureRequested && primaryError.classification === testCase.classification) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: testCase.e2eName,
            classification: testCase.classification,
            firstObserved: testCase.firstObserved,
            firstFailureRecordingId: records[0].recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: edge.baseUrl,
              boundaryBaseUrls: { [BOUNDARY]: edge.baseUrl },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            testCase.classification,
            `${primaryError.message}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: records[0].recordingId },
          );
        }
      } else {
        harness.journal.flushCaptureSet(captureSetId);
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    try {
      await edge.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
    try {
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
}

for (const testCase of CASES) {
  test(testCase.e2eName, async ({ context }) => {
    test.setTimeout(120_000);
    await runAuthorityCase(context, testCase);
  });
}
