const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const { expect, test } = require("@playwright/test");

const {
  ProductBehaviorFailure,
  createWebE2EHarness,
  startHttpServer,
} = require("../support/harness.cjs");

const MODEL = "ui-logic-model";
const CAPTURE_CASE_ENV = "ZODE_CAPTURE_UI_LOGIC_CASE";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "..", "fixtures", "incidents");

const CASES = {
  session: {
    name: "e2e_browser_session_logic_survives_shell_navigation_without_losing_draft_or_duplicating_effects",
    classification: "SESSION_LOGIC_DID_NOT_SURVIVE_SHELL_NAVIGATION",
    firstObserved:
      "after the Server admitted a message but the browser lost its response, replacing the visual route discarded the command identity and a retry used a second idempotency key",
  },
  sessionSwitch: {
    name: "e2e_browser_switching_sessions_clears_the_previous_unsent_draft",
    classification: "SWITCHING_SESSIONS_RETAINED_THE_PREVIOUS_DRAFT",
    firstObserved:
      "after the user opened another canonical session and returned, the first session still showed its unsent draft even though no message had been submitted",
  },
  endpoint: {
    name: "e2e_browser_endpoint_reconciles_canonical_sessions_without_duplicate_streams_or_rows",
    classification: "CANONICAL_SESSION_REOPENED_A_DUPLICATE_STREAM",
    firstObserved:
      "activating the already-selected canonical Endpoint/session route opened a second public event stream instead of retaining the existing Session observation",
  },
  endpointStream: {
    name: "e2e_browser_endpoint_stream_multiplexes_sessions_across_navigation_and_reconnect",
    classification: "ENDPOINT_STREAM_DID_NOT_MULTIPLEX_SESSIONS_ACROSS_RECONNECT",
    firstObserved:
      "one browser application did not retain one Endpoint-wide stream and cursor while two sessions received durable results across navigation and reconnect",
  },
  authority: {
    name: "e2e_browser_provider_endpoint_and_settings_models_follow_server_authority_without_shadow_state",
    classification: "BROWSER_MODELS_DID_NOT_FOLLOW_SERVER_AUTHORITY",
    firstObserved:
      "after public Server authority acquired the provider default and Endpoint, the provider model refreshed but the Endpoints surface retained its bootstrap inventory and could not expose the authoritative Endpoint",
  },
  confirmedManagementMutation: {
    name: "e2e_browser_confirmed_management_mutation_is_not_downgraded_by_projection_failure",
    classification: "CONFIRMED_MANAGEMENT_MUTATION_WAS_DOWNGRADED_BY_PROJECTION_FAILURE",
    firstObserved:
      "after the Server confirmed a default-profile mutation, one temporary projection failure replaced the accepted result with an unknown mutation error",
  },
  inventory: {
    name: "e2e_browser_initial_home_reconciles_preexisting_endpoint_sessions",
    classification:
      "INITIAL_SESSION_INVENTORY_NOT_RECONCILED__later_test_reproduction_of_gap",
    firstObserved:
      "relation=later_test_reproduction_of_gap; the initial Home bootstrap loaded its Endpoint inventory but did not query that Endpoint's preexisting sessions, so Recent stayed empty",
    captureSet: true,
  },
};

async function managementJson(page, method, path, body, idempotencyKey) {
  return page.evaluate(
    async ({ requestMethod, requestPath, requestBody, key }) => {
      const headers = { accept: "application/json" };
      if (requestBody !== undefined) headers["content-type"] = "application/json";
      if (key) headers["idempotency-key"] = key;
      const response = await fetch(requestPath, {
        method: requestMethod,
        headers,
        body: requestBody === undefined ? undefined : JSON.stringify(requestBody),
      });
      let responseBody = null;
      try {
        responseBody = await response.json();
      } catch {
        // The status remains the public assertion for an empty response.
      }
      return { status: response.status, body: responseBody };
    },
    {
      requestMethod: method,
      requestPath: path,
      requestBody: body,
      key: idempotencyKey,
    },
  );
}

function requireStatus(result, expected, label) {
  expect(result.status, `${label}: ${JSON.stringify(result.body)}`).toBe(expected);
  return result.body;
}

async function seedProduct(
  page,
  harness,
  suffix,
  { secondProfile = false, endpointBaseUrl = harness.endpoint.baseUrl } = {},
) {
  const endpoint = requireStatus(
    await managementJson(
      page,
      "POST",
      "/v1/endpoints",
      {
        label: `UI logic Endpoint ${suffix}`,
        base_url: endpointBaseUrl,
        control_auth: { kind: "bearer", secret: harness.controllerSecret },
      },
      `ui-logic-endpoint-${suffix}`,
    ),
    201,
    "create Endpoint",
  );
  const provider = `ui-logic-${suffix}`;
  requireStatus(
    await managementJson(
      page,
      "PUT",
      `/v1/providers/${provider}`,
      {
        kind: "openai_compatible",
        base_url: `${harness.providerProxy.baseUrl}/v1`,
        models: [MODEL],
        options: {},
      },
      `ui-logic-provider-${suffix}`,
    ),
    200,
    "configure provider",
  );
  const createProfile = async (label, makeDefault, key) =>
    requireStatus(
      await managementJson(
        page,
        "POST",
        `/v1/providers/${provider}/auth-profiles`,
        {
          kind: "api_key",
          label,
          api_key: harness.providerSecret,
          make_default: makeDefault,
          sharing: { mode: "selected", endpoint_ids: [endpoint.endpoint_id] },
        },
        key,
      ),
      201,
      `create ${label}`,
    );
  const firstProfile = await createProfile(
    `Primary profile ${suffix}`,
    true,
    `ui-logic-profile-primary-${suffix}`,
  );
  const alternateProfile = secondProfile
    ? await createProfile(
        `Alternate profile ${suffix}`,
        false,
        `ui-logic-profile-alternate-${suffix}`,
      )
    : null;
  await expect
    .poll(
      async () => {
        const result = await managementJson(
          page,
          "GET",
          `/v1/providers/${provider}/auth-profiles`,
        );
        const profile = result.body?.items?.find(
          (candidate) => candidate.auth_profile_id === firstProfile.auth_profile_id,
        );
        return profile?.distribution?.find(
          (replica) => replica.endpoint_id === endpoint.endpoint_id,
        )?.status;
      },
      { timeout: 20_000 },
    )
    .toBe("ready");
  const session = requireStatus(
    await managementJson(
      page,
      "POST",
      `/v1/endpoints/${endpoint.endpoint_id}/sessions`,
      {
        model: {
          provider,
          model: MODEL,
          provider_execution: {
            schema: "zode.provider-execution.v1",
            revision: 1,
            kind: "openai_compatible",
            base_url: `${harness.providerProxy.baseUrl}/v1`,
            options: {},
          },
          auth_profile_id: firstProfile.auth_profile_id,
          minimum_auth_revision: firstProfile.revision,
        },
        tools: [],
      },
      `ui-logic-session-${suffix}`,
    ),
    201,
    "create session",
  );
  return {
    endpoint,
    provider,
    firstProfile,
    alternateProfile,
    session,
    sessionPath: `/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions/${encodeURIComponent(session.session_id)}`,
    messagePath: `/v1/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions/${encodeURIComponent(session.session_id)}/messages`,
    eventsPath: `/v1/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/events`,
  };
}

async function openManagement(page, name) {
  const settingsLink = page.getByRole("link", { name, exact: true });
  if (await settingsLink.isVisible()) {
    await settingsLink.click();
    return;
  }
  let item = page.getByRole("menuitem", { name, exact: true });
  if (!(await item.isVisible())) {
    await page.getByRole("button", { name: "Manage Zode", exact: true }).click();
    item = page.getByRole("menuitem", { name, exact: true });
  }
  await item.click();
}

async function openSession(page, harness, product) {
  await page.goto(`${harness.managementUrl}${product.sessionPath}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(
    page.getByRole("button", { name: /^Choose (?:model|execution)$/u }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
    timeout: 20_000,
  });
}

async function expectSelectedExecutionProfile(page, triggerName, model, profileLabel) {
  await page.getByRole("button", { name: triggerName, exact: true }).click();
  await page.getByRole("menuitem", { name: "Show advanced options", exact: true }).click();
  await page.getByRole("menuitem", { name: /^Model\b/u }).hover();
  await page.locator(`[role="menuitem"][data-zode-model="${model}"]`).hover();
  await expect(
    page.locator('[role="menuitem"][data-zode-selected="true"]').filter({
      hasText: profileLabel,
    }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
}

async function startEndpointStreamProxy(targetBaseUrl) {
  const requests = [];
  const durableEvents = [];
  const activeStreams = new Set();
  let maximumActiveStreams = 0;
  const proxy = await startHttpServer((request, response) => {
    const target = new URL(request.url, targetBaseUrl);
    const isEventStream = request.method === "GET" && target.pathname === "/v1/events";
    const observation = isEventStream
      ? { headers: { ...request.headers }, pending: "", response }
      : null;
    if (observation) {
      requests.push(observation);
      activeStreams.add(response);
      maximumActiveStreams = Math.max(maximumActiveStreams, activeStreams.size);
      response.once("close", () => activeStreams.delete(response));
    }
    const upstream = http.request(
      target,
      {
        method: request.method,
        headers: { ...request.headers, host: target.host },
      },
      (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.on("data", (chunk) => {
          if (observation) {
            observation.pending += chunk.toString("utf8");
            const frames = observation.pending.split(/\r?\n\r?\n/);
            observation.pending = frames.pop() ?? "";
            for (const frame of frames) {
              const id = frame.match(/^id:\s?(.*)$/m)?.[1] ?? "";
              const data = frame.match(/^data:\s?(.*)$/m)?.[1] ?? "";
              if (!id || !data) continue;
              try {
                const payload = JSON.parse(data);
                durableEvents.push({ id, sessionId: payload.session_id, kind: payload.kind });
              } catch {
                // Product validation owns malformed-frame handling.
              }
            }
          }
          if (!response.destroyed) response.write(chunk);
        });
        upstreamResponse.once("end", () => {
          if (!response.destroyed) response.end();
        });
        upstreamResponse.once("error", () => {
          if (!response.destroyed) response.destroy();
        });
      },
    );
    request.pipe(upstream);
    request.once("aborted", () => upstream.destroy());
    response.once("close", () => upstream.destroy());
    upstream.once("error", () => {
      if (!response.headersSent) response.writeHead(502);
      if (!response.destroyed) response.end();
    });
  });
  return {
    ...proxy,
    requests,
    durableEvents,
    get maximumActiveStreams() {
      return maximumActiveStreams;
    },
    disconnectStreams() {
      for (const response of [...activeStreams]) response.destroy();
    },
  };
}

async function startConfirmedProjectionFailureProxy(targetBaseUrl, provider) {
  const mutationPath = `/v1/providers/${encodeURIComponent(provider)}/default-auth-profile`;
  const projectionPath = `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`;
  const mutations = [];
  let projectionFailures = 0;
  let projectionFailureArmed = false;
  const proxy = await startHttpServer((request, response) => {
    const target = new URL(request.url, targetBaseUrl);
    const isMutation = request.method === "PUT" && target.pathname === mutationPath;
    const isProjection = request.method === "GET" && target.pathname === projectionPath;
    if (projectionFailureArmed && isProjection) {
      projectionFailureArmed = false;
      projectionFailures += 1;
      response.writeHead(503, { "content-type": "application/json" });
      response.end(
        JSON.stringify({ error: { code: "management_unavailable", retryable: true } }),
      );
      return;
    }
    const upstream = http.request(
      target,
      { method: request.method, headers: request.headers },
      (upstreamResponse) => {
        if (isMutation) {
          mutations.push({
            status: upstreamResponse.statusCode ?? 0,
            idempotencyKey: request.headers["idempotency-key"] ?? "",
          });
          if (upstreamResponse.statusCode === 200) projectionFailureArmed = true;
        }
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      },
    );
    request.pipe(upstream);
    request.once("aborted", () => upstream.destroy());
    response.once("close", () => upstream.destroy());
    upstream.once("error", () => {
      if (!response.headersSent) response.writeHead(502);
      if (!response.writableEnded) response.end();
    });
  });
  return {
    ...proxy,
    mutations,
    get projectionFailures() {
      return projectionFailures;
    },
  };
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function matchingCassettes(testCase) {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === testCase.name && value.classification === testCase.classification;
      } catch {
        return false;
      }
    });
}

function failureRecord(records, testCase) {
  if (testCase === CASES.session) {
    return records.findLast((record) => record.method === "POST" && record.path.endsWith("/messages"));
  }
  if (testCase === CASES.endpoint) {
    return records.findLast(
      (record) => record.method === "GET" && record.path.includes("/sessions/") && !record.path.endsWith("/events"),
    );
  }
  if (testCase === CASES.endpointStream) {
    return records.findLast(
      (record) => record.method === "GET" && record.path.endsWith("/events"),
    );
  }
  if (testCase === CASES.sessionSwitch) {
    return records.findLast(
      (record) =>
        record.boundary === "management-access-edge" &&
        record.method === "GET" &&
        record.path.includes("/sessions/") &&
        !record.path.endsWith("/events"),
    );
  }
  if (testCase === CASES.inventory) {
    return records.find(
      (record) =>
        record.boundary === "management-access-edge" &&
        record.method === "GET" &&
        record.path === "/v1/endpoints",
    );
  }
  if (testCase === CASES.confirmedManagementMutation) {
    return records.findLast(
      (record) =>
        record.boundary === "management-access-edge" &&
        record.method === "GET" &&
        record.path.endsWith("/auth-profiles") &&
        record.response?.status === 503,
    );
  }
  return records.find(
    (record) => record.method === "PUT" && record.path.endsWith("/default-auth-profile"),
  );
}

async function finishCase(page, harness, captureSetId, primaryError, testCase) {
  let error = primaryError;
  try {
    if (!page.isClosed()) await page.close();
    await harness.journal.waitForIdle(15_000);
    const records = recordsFor(harness, captureSetId);
    if (records.length === 0) throw new Error(`${testCase.name} retained no public exchange`);
    if (error) {
      const firstFailure = failureRecord(records, testCase);
      if (!firstFailure) throw new Error(`${testCase.name} retained no failure-boundary exchange`);
      const captureCase = Object.entries(CASES).find(([, candidate]) => candidate === testCase)?.[0];
      if (process.env[CAPTURE_CASE_ENV] === captureCase && testCase.captureSet) {
        const promoted = await harness.promoteCaptureSet(captureSetId, {
          e2eName: testCase.name,
          classification: testCase.classification,
          firstObserved: testCase.firstObserved,
          firstFailureRecordingId: firstFailure.recordingId,
          destinationDirectory: INCIDENT_DIRECTORY,
        });
        error = new ProductBehaviorFailure(
          testCase.classification,
          `${testCase.firstObserved}; cassette=${promoted.cassettePath}`,
          { captureSetId, recordingId: firstFailure.recordingId },
        );
      } else {
        harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        if (process.env[CAPTURE_CASE_ENV] === captureCase) {
          const promoted = await harness.journal.promote(firstFailure, {
            e2eName: testCase.name,
            classification: testCase.classification,
            firstObserved: testCase.firstObserved,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: async (envelope) => ({
              ok: true,
              results: await harness.journal.replay(envelope, {
                baseUrl: harness.managementUrl,
                boundaryBaseUrls: { "management-access-edge": harness.managementUrl },
              }),
            }),
          });
          error = new ProductBehaviorFailure(
            testCase.classification,
            `${testCase.firstObserved}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: firstFailure.recordingId },
          );
        }
      }
    } else {
      harness.journal.flushCaptureSet(captureSetId);
    }
  } catch (captureError) {
    error = captureError;
  }
  try {
    await harness.close();
  } catch (cleanupError) {
    error ||= cleanupError;
  }
  if (error) throw error;
}

test(CASES.session.name, async ({ page }) => {
  test.setTimeout(180_000);
  if (process.env[CAPTURE_CASE_ENV] !== "session") expect(matchingCassettes(CASES.session)).toHaveLength(1);
  const harness = await createWebE2EHarness({
    e2eName: CASES.session.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "session");
    captureSetId = harness.beginCaptureSet({ e2eName: CASES.session.name, maxMembers: 128 });
    await openSession(page, harness, product);
    const draft = "draft survives shell navigation";
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await composer.fill(draft);
    await openManagement(page, "Providers");
    await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expect(composer).toHaveValue(draft);

    const keys = [];
    const bodies = [];
    let firstRequestResolved;
    let releaseFirstResponse;
    const firstRequest = new Promise((resolve) => {
      firstRequestResolved = resolve;
    });
    const firstResponseRelease = new Promise((resolve) => {
      releaseFirstResponse = resolve;
    });
    await page.route(`**${product.messagePath}`, async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      keys.push(route.request().headers()["idempotency-key"]);
      bodies.push(route.request().postData());
      if (keys.length === 1) {
        const response = await route.fetch();
        expect(response.status()).toBe(202);
        firstRequestResolved();
        await firstResponseRelease;
        await route.abort("failed");
        return;
      }
      await route.continue();
    });
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await firstRequest;
    const nextDraft = "next draft after the admitted message";
    await composer.fill(nextDraft);
    releaseFirstResponse();
    await expect(page.getByText("The Server could not be reached.", { exact: true })).toBeVisible();
    await expect(composer).toHaveAttribute("readonly", "");
    await expect(composer).toHaveValue(draft);
    await openManagement(page, "Providers");
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expect(composer).toHaveValue(draft);
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
      timeout: 20_000,
    });
    const secondResponse = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        new URL(response.url()).pathname === product.messagePath,
      { timeout: 20_000 },
    );
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect.poll(() => keys.length, { timeout: 20_000 }).toBe(2);
    expect((await secondResponse).status()).toBe(202);
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]);
    expect(bodies[1]).toBe(bodies[0]);
    await expect(composer).toHaveValue(nextDraft);
    await expect(page.getByLabel("You").filter({ hasText: draft })).toHaveCount(1, {
      timeout: 30_000,
    });
    await expect(page.getByLabel("Agent").filter({ hasText: "E2E_OK" })).toHaveCount(1, {
      timeout: 30_000,
    });
  } catch (error) {
    primaryError = new ProductBehaviorFailure(
      CASES.session.classification,
      CASES.session.firstObserved,
      { cause: error instanceof Error ? error.message : String(error) },
    );
  } finally {
    if (captureSetId) {
      await finishCase(page, harness, captureSetId, primaryError, CASES.session);
    } else {
      await harness.close();
    }
  }
});

test(CASES.sessionSwitch.name, async ({ page }) => {
  test.setTimeout(180_000);
  const harness = await createWebE2EHarness({
    e2eName: CASES.sessionSwitch.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "session-switch");
    const secondSession = requireStatus(
      await managementJson(
        page,
        "POST",
        `/v1/endpoints/${product.endpoint.endpoint_id}/sessions`,
        {
          model: {
            provider: product.provider,
            model: MODEL,
            provider_execution: {
              schema: "zode.provider-execution.v1",
              revision: 1,
              kind: "openai_compatible",
              base_url: `${harness.providerProxy.baseUrl}/v1`,
              options: {},
            },
            auth_profile_id: product.firstProfile.auth_profile_id,
            minimum_auth_revision: product.firstProfile.revision,
          },
          tools: [],
        },
        "ui-logic-session-switch-second",
      ),
      201,
      "create second session",
    );
    const secondSessionPath = `/endpoints/${encodeURIComponent(product.endpoint.endpoint_id)}/sessions/${encodeURIComponent(secondSession.session_id)}`;
    await page.reload({ waitUntil: "domcontentloaded" });
    const secondLink = page.locator(`a.sidebar-session-row[href="${secondSessionPath}"]`);
    const firstLink = page.locator(`a.sidebar-session-row[href="${product.sessionPath}"]`);
    await expect(secondLink).toBeVisible({ timeout: 20_000 });
    await expect(firstLink).toBeVisible();
    captureSetId = harness.beginCaptureSet({
      e2eName: CASES.sessionSwitch.name,
      maxMembers: 128,
    });
    await firstLink.click();
    await expect(page).toHaveURL(new RegExp(`${product.sessionPath.replaceAll("/", "\\/")}$`));
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
      timeout: 20_000,
    });
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    const unsentDraft = "this draft belongs only to the first session";
    await composer.fill(unsentDraft);
    const messagePosts = [];
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname.endsWith("/messages")) {
        messagePosts.push(request);
      }
    });
    await secondLink.click();
    await expect(page).toHaveURL(new RegExp(`${secondSessionPath.replaceAll("/", "\\/")}$`));
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
      timeout: 20_000,
    });
    await expect(firstLink).toBeVisible();
    await firstLink.click();
    await expect(page).toHaveURL(new RegExp(`${product.sessionPath.replaceAll("/", "\\/")}$`));
    await expect(composer).toHaveValue("");
    expect(messagePosts).toHaveLength(0);
  } catch (error) {
    const cause = error instanceof Error ? error.message : String(error);
    primaryError = new ProductBehaviorFailure(
      CASES.sessionSwitch.classification,
      `${CASES.sessionSwitch.firstObserved}; cause=${cause}`,
      { cause },
    );
  } finally {
    if (captureSetId) {
      await finishCase(page, harness, captureSetId, primaryError, CASES.sessionSwitch);
    } else {
      await harness.close();
    }
  }
});

test(CASES.endpoint.name, async ({ page }) => {
  test.setTimeout(180_000);
  if (process.env[CAPTURE_CASE_ENV] !== "endpoint") expect(matchingCassettes(CASES.endpoint)).toHaveLength(1);
  const harness = await createWebE2EHarness({
    e2eName: CASES.endpoint.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "endpoint");
    const streamRequests = [];
    page.on("request", (request) => {
      if (request.method() === "GET" && new URL(request.url()).pathname === product.eventsPath) {
        streamRequests.push(request);
      }
    });
    captureSetId = harness.beginCaptureSet({ e2eName: CASES.endpoint.name, maxMembers: 128 });
    await openSession(page, harness, product);
    await expect.poll(() => streamRequests.length, { timeout: 20_000 }).toBe(1);
    const selected = page.locator(
      `a.sidebar-session-row[href="${product.sessionPath}"][aria-current="page"]`,
    );
    await expect(selected).toHaveCount(1);
    await selected.click();
    await expect(page).toHaveURL(new RegExp(`${product.sessionPath.replaceAll("/", "\\/")}$`));
    await expect(page.locator(`a.sidebar-session-row[href="${product.sessionPath}"]`)).toHaveCount(1);
    await expect.poll(() => streamRequests.length, { timeout: 2_000 }).toBe(1);
  } catch (error) {
    primaryError = new ProductBehaviorFailure(
      CASES.endpoint.classification,
      CASES.endpoint.firstObserved,
      { cause: error instanceof Error ? error.message : String(error) },
    );
  } finally {
    if (captureSetId) {
      await finishCase(page, harness, captureSetId, primaryError, CASES.endpoint);
    } else {
      await harness.close();
    }
  }
});

test(CASES.endpointStream.name, async ({ page }) => {
  test.setTimeout(180_000);
  const harness = await createWebE2EHarness({
    e2eName: CASES.endpointStream.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let endpointProxy;
  let captureSetId;
  let primaryError;
  try {
    endpointProxy = await startEndpointStreamProxy(harness.endpoint.baseUrl);
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "endpoint-stream", {
      endpointBaseUrl: endpointProxy.baseUrl,
    });
    const secondSession = requireStatus(
      await managementJson(
        page,
        "POST",
        `/v1/endpoints/${product.endpoint.endpoint_id}/sessions`,
        {
          model: {
            provider: product.provider,
            model: MODEL,
            provider_execution: {
              schema: "zode.provider-execution.v1",
              revision: 1,
              kind: "openai_compatible",
              base_url: `${harness.providerProxy.baseUrl}/v1`,
              options: {},
            },
            auth_profile_id: product.firstProfile.auth_profile_id,
            minimum_auth_revision: product.firstProfile.revision,
          },
          tools: [],
        },
        "ui-logic-endpoint-stream-second",
      ),
      201,
      "create second Endpoint-stream session",
    );
    const secondSessionPath = `/endpoints/${encodeURIComponent(product.endpoint.endpoint_id)}/sessions/${encodeURIComponent(secondSession.session_id)}`;
    const managementStreams = [];
    page.on("request", (request) => {
      if (request.method() === "GET" && new URL(request.url()).pathname === product.eventsPath) {
        managementStreams.push(request);
      }
    });
    captureSetId = harness.beginCaptureSet({
      e2eName: CASES.endpointStream.name,
      maxMembers: 192,
    });
    await openSession(page, harness, product);
    await expect.poll(() => managementStreams.length, { timeout: 20_000 }).toBe(1);
    await expect.poll(() => endpointProxy.requests.length, { timeout: 20_000 }).toBe(1);
    expect(endpointProxy.maximumActiveStreams).toBe(1);

    const firstMessage = "first session through one Endpoint stream";
    await page.getByRole("textbox", { name: "Message", exact: true }).fill(firstMessage);
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByLabel("Agent").filter({ hasText: "E2E_OK" })).toHaveCount(1, {
      timeout: 30_000,
    });

    const secondLink = page.locator(`a.sidebar-session-row[href="${secondSessionPath}"]`);
    await expect(secondLink).toBeVisible({ timeout: 20_000 });
    await secondLink.click();
    await expect(page).toHaveURL(new RegExp(`${secondSessionPath.replaceAll("/", "\\/")}$`));
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
      timeout: 20_000,
    });
    expect(managementStreams).toHaveLength(1);
    expect(endpointProxy.requests).toHaveLength(1);

    endpointProxy.disconnectStreams();
    await expect.poll(() => managementStreams.length, { timeout: 20_000 }).toBe(2);
    await expect.poll(() => endpointProxy.requests.length, { timeout: 20_000 }).toBe(2);
    expect(endpointProxy.maximumActiveStreams).toBe(1);
    const browserCursor = managementStreams[1].headers()["last-event-id"] ?? "";
    const endpointCursor = endpointProxy.requests[1].headers["last-event-id"] ?? "";
    expect(browserCursor).toMatch(/^\d+$/);
    expect(endpointCursor).toBe(browserCursor);
    expect(endpointProxy.durableEvents.some((event) => event.id === browserCursor)).toBe(true);

    const secondMessage = "second session after Endpoint stream reconnect";
    await page.getByRole("textbox", { name: "Message", exact: true }).fill(secondMessage);
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByLabel("Agent").filter({ hasText: "E2E_OK" })).toHaveCount(1, {
      timeout: 30_000,
    });

    const firstLink = page.locator(`a.sidebar-session-row[href="${product.sessionPath}"]`);
    await firstLink.click();
    await expect(page).toHaveURL(new RegExp(`${product.sessionPath.replaceAll("/", "\\/")}$`));
    await expect(page.getByLabel("Agent").filter({ hasText: "E2E_OK" })).toHaveCount(1);
    expect(managementStreams).toHaveLength(2);
    expect(endpointProxy.requests).toHaveLength(2);
    const visibleSessions = new Set(
      endpointProxy.durableEvents.map((event) => event.sessionId).filter(Boolean),
    );
    expect(visibleSessions.has(product.session.session_id)).toBe(true);
    expect(visibleSessions.has(secondSession.session_id)).toBe(true);
  } catch (error) {
    primaryError = new ProductBehaviorFailure(
      CASES.endpointStream.classification,
      CASES.endpointStream.firstObserved,
      { cause: error instanceof Error ? error.message : String(error) },
    );
  } finally {
    try {
      if (!page.isClosed()) await page.close();
      await endpointProxy?.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
    if (captureSetId) {
      await finishCase(page, harness, captureSetId, primaryError, CASES.endpointStream);
    } else {
      await harness.close();
    }
  }
});

test(CASES.authority.name, async ({ page }) => {
  test.setTimeout(180_000);
  if (process.env[CAPTURE_CASE_ENV] !== "authority") expect(matchingCassettes(CASES.authority)).toHaveLength(1);
  const harness = await createWebE2EHarness({
    e2eName: CASES.authority.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "authority", { secondProfile: true });
    captureSetId = harness.beginCaptureSet({ e2eName: CASES.authority.name, maxMembers: 128 });
    requireStatus(
      await managementJson(
        page,
        "PUT",
        `/v1/providers/${product.provider}/default-auth-profile`,
        { profile_id: product.alternateProfile.profile_id },
        "ui-logic-authority-default",
      ),
      200,
      "change Server default profile",
    );
    await openManagement(page, "Providers");
    const alternate = page.locator(".profile-row").filter({
      hasText: product.alternateProfile.label,
    });
    await expect(alternate).toContainText("Default profile");
    await openManagement(page, "Endpoints");
    const endpointCard = page.getByRole("article").filter({ hasText: product.endpoint.label });
    const probeButton = endpointCard.getByRole("button", {
      name: "Refresh Endpoint status",
      exact: true,
    });
    await expect(probeButton).toBeEnabled({ timeout: 20_000 });
    const [probeResponse] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname ===
            `/v1/endpoints/${product.endpoint.endpoint_id}/probe`,
        { timeout: 20_000 },
      ),
      probeButton.click(),
    ]);
    expect(probeResponse.status()).toBe(200);
    await expect(endpointCard).toContainText("online");
    await openManagement(page, "Settings");
    await expect(page.getByText("Server only", { exact: true })).toBeVisible();
    await page.getByRole("navigation", { name: "Primary", exact: true })
      .getByRole("link", { name: "New session", exact: true }).click();
    await expectSelectedExecutionProfile(
      page,
      "Choose model and reasoning",
      MODEL,
      product.alternateProfile.label,
    );
  } catch (error) {
    primaryError = new ProductBehaviorFailure(
      CASES.authority.classification,
      CASES.authority.firstObserved,
      { cause: error instanceof Error ? error.message : String(error) },
    );
  } finally {
    if (captureSetId) {
      await finishCase(page, harness, captureSetId, primaryError, CASES.authority);
    } else {
      await harness.close();
    }
  }
});

test(CASES.confirmedManagementMutation.name, async ({ page }) => {
  test.setTimeout(180_000);
  const harness = await createWebE2EHarness({
    e2eName: CASES.confirmedManagementMutation.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let projectionProxy;
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "confirmed-management", {
      secondProfile: true,
    });
    await harness.edge.close();
    projectionProxy = await startConfirmedProjectionFailureProxy(
      harness.server.baseUrl,
      product.provider,
    );
    harness.edge = await harness.access.startEdge(projectionProxy.baseUrl, {
      canonicalOrigin: harness.managementOrigin,
    });
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await openManagement(page, "Providers");
    const providerCard = page.getByRole("article").filter({ hasText: product.provider });
    const alternate = providerCard.locator(".profile-row").filter({
      hasText: product.alternateProfile.label,
    });
    await expect(alternate.getByRole("button", { name: "Set as default", exact: true })).toBeVisible();
    captureSetId = harness.beginCaptureSet({
      e2eName: CASES.confirmedManagementMutation.name,
      maxMembers: 32,
    });
    await alternate.getByRole("button", { name: "Set as default", exact: true }).click();
    await expect.poll(() => projectionProxy.projectionFailures, { timeout: 20_000 }).toBe(1);
    expect(projectionProxy.mutations).toHaveLength(1);
    expect(projectionProxy.mutations[0].status).toBe(200);
    expect(projectionProxy.mutations[0].idempotencyKey).toBeTruthy();
    await expect(
      page.locator(".notice-status").filter({
        hasText: `${product.alternateProfile.label} is now the default profile.`,
      }),
    ).toBeVisible();
    await expect(providerCard.getByText("Provider profiles are temporarily unavailable.", {
      exact: true,
    })).toBeVisible();
    await providerCard.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(alternate).toContainText("Default profile");
    expect(projectionProxy.mutations).toHaveLength(1);
  } catch (error) {
    primaryError = new ProductBehaviorFailure(
      CASES.confirmedManagementMutation.classification,
      CASES.confirmedManagementMutation.firstObserved,
      { cause: error instanceof Error ? error.message : String(error) },
    );
  } finally {
    try {
      await projectionProxy?.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
    if (captureSetId) {
      await finishCase(
        page,
        harness,
        captureSetId,
        primaryError,
        CASES.confirmedManagementMutation,
      );
    } else {
      await harness.close();
    }
  }
});

test(CASES.inventory.name, async ({ page }) => {
  test.setTimeout(180_000);
  if (process.env[CAPTURE_CASE_ENV] !== "inventory") {
    expect(matchingCassettes(CASES.inventory)).toHaveLength(1);
  }
  const harness = await createWebE2EHarness({
    e2eName: CASES.inventory.name,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-ui-logic",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const product = await seedProduct(page, harness, "inventory");
    captureSetId = harness.beginCaptureSet({ e2eName: CASES.inventory.name, maxMembers: 64 });
    await page.reload({ waitUntil: "domcontentloaded" });
    const recent = page.locator(`a.sidebar-session-row[href="${product.sessionPath}"]`);
    await expect(recent).toBeVisible();
    await expect(recent).toHaveCount(1);
  } catch (error) {
    primaryError = new ProductBehaviorFailure(
      CASES.inventory.classification,
      CASES.inventory.firstObserved,
      { cause: error instanceof Error ? error.message : String(error) },
    );
  } finally {
    if (captureSetId) {
      await finishCase(page, harness, captureSetId, primaryError, CASES.inventory);
    } else {
      await harness.close();
    }
  }
});
