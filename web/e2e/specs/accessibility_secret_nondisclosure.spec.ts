import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import {
  expect,
  test,
  type BrowserContext,
  type Download,
  type Locator,
  type Page,
  type TestInfo,
} from "@playwright/test";

const require = createRequire(import.meta.url);
const {
  createWebE2EHarness,
  HarnessFailure,
  ProductBehaviorFailure,
  ProductRouteMissing,
} = require("../support/harness.cjs") as {
  createWebE2EHarness: () => Promise<RealWebE2EHarness>;
  HarnessFailure: new (...args: never[]) => Error;
  ProductBehaviorFailure: new (
    classification: string,
    message: string,
    details?: Record<string, unknown>,
  ) => Error;
  ProductRouteMissing: new (details: {
    path: string;
    status: number;
    surface: string;
  }) => Error;
};

// This is deliberately a synthetic value.  It is entered into a write-only
// field and is never used as an assertion payload or emitted in diagnostics.
const SYNTHETIC_SECRET_MARKER =
  process.env.ZODE_E2E_SYNTHETIC_SECRET_MARKER ??
  "zode-e2e-synthetic-api-key-7f3c1d9a8b5e";
const EXPECTED_ASSISTANT_TEXT =
  process.env.ZODE_E2E_ASSISTANT_TEXT ?? "E2E_OK";
const PROFILE_LABEL = "keyboard-only browser profile";
const ENDPOINT_LABEL = "keyboard-only remote Endpoint";
const PROVIDER_ID = "browser-e2e-provider";
const PROVIDER_MODEL = "browser-e2e-model";
const NAMED_E2E =
  "e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure";
const INCIDENT_FIXTURE = fileURLToPath(
  new URL(
    "../fixtures/accessibility_secret_nondisclosure/first-failure.v1.json",
    import.meta.url,
  ),
);

type FocusTarget = {
  name: RegExp;
  role?: string;
};

type BrowserEvidence = {
  console: string[];
  requestUrls: string[];
  responseUrls: string[];
  navigationUrls: string[];
  history: string[];
  serverResponseBodies: Promise<string>[];
  downloads: Array<{
    download: Download;
    filename: string;
  }>;
  managementOrigin: string;
};

type SecretSurface = {
  renderedText: string[];
  accessibleNames: string[];
  domAttributes: string[];
  storage: string[];
  urlHistory: string[];
};

type RealWebE2EHarness = {
  managementUrl: string;
  endpoint: { baseUrl: string };
  providerProxy: { baseUrl: string };
  controllerSecret: string;
  providerSecret: string;
  ledger: { add: (label: string, value: string) => void };
  captureAndReplayFailure: (
    error: Error,
    e2eName: string,
  ) => Promise<unknown>;
  close: () => Promise<void>;
};

let activeSecretMarkers = [SYNTHETIC_SECRET_MARKER];

function valueText(value: unknown): string {
  if (Buffer.isBuffer(value)) return value.toString("latin1");
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
}

function assertMarkerAbsent(label: string, values: unknown[]): void {
  if (
    values.some((value) =>
      activeSecretMarkers.some((marker) => valueText(value).includes(marker)),
    )
  ) {
    // Never include the received value in this error.  Playwright may surface
    // the error in a report that is itself part of the secret-scan boundary.
    throw new Error(`${label} contained the synthetic secret marker`);
  }
}

async function activeElementDescriptor(page: Page): Promise<{
  name: string;
  role: string;
}> {
  return page.evaluate(() => {
    const element = document.activeElement as HTMLElement | null;
    if (!element) return { name: "", role: "" };

    const labelledBy = element
      .getAttribute("aria-labelledby")
      ?.split(/\s+/)
      .map((id) => document.getElementById(id)?.textContent ?? "")
      .join(" ");
    const label = Array.from(
      (element as HTMLInputElement).labels ?? [],
      (item) => item.textContent ?? "",
    ).join(" ");
    const name = [
      element.getAttribute("aria-label"),
      labelledBy,
      label,
      element.getAttribute("title"),
      element.getAttribute("placeholder"),
      element.textContent,
    ]
      .filter(Boolean)
      .join(" ")
      .replace(/\s+/g, " ")
      .trim();

    const explicitRole = element.getAttribute("role");
    const implicitRole =
      element.tagName === "A"
        ? "link"
        : element.tagName === "BUTTON"
          ? "button"
          : element.tagName === "SELECT"
            ? "combobox"
            : element.tagName === "TEXTAREA" ||
                (element.tagName === "INPUT" &&
                  !["checkbox", "radio", "button", "submit"].includes(
                    (element as HTMLInputElement).type,
                  ))
              ? "textbox"
              : element.tagName === "INPUT" &&
                  (element as HTMLInputElement).type === "checkbox"
                ? "checkbox"
                : "";

    return { name, role: explicitRole ?? implicitRole };
  });
}

async function assertVisibleFocus(page: Page, label: string): Promise<void> {
  const state = await page.evaluate(() => {
    const element = document.activeElement as HTMLElement | null;
    if (!element || element === document.body) {
      return { focused: false, visible: false, focusVisible: false, styled: false };
    }
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    const textCaretVisible =
      (element instanceof HTMLTextAreaElement ||
        (element instanceof HTMLInputElement &&
          !["checkbox", "radio", "button", "submit"].includes(element.type))) &&
      !element.hasAttribute("readonly") &&
      !element.hasAttribute("disabled");
    const styled =
      (style.outlineStyle !== "none" && style.outlineWidth !== "0px") ||
      style.boxShadow !== "none" ||
      textCaretVisible;
    return {
      focused: true,
      visible:
        rect.width > 0 &&
        rect.height > 0 &&
        style.visibility !== "hidden" &&
        style.display !== "none",
      focusVisible: element.matches(":focus-visible"),
      styled,
    };
  });

  if (!state.focused || !state.visible || !state.focusVisible || !state.styled) {
    throw new Error(`${label} did not expose a visible keyboard focus ring`);
  }
}

function targetMatches(
  descriptor: { name: string; role: string },
  target: FocusTarget,
): boolean {
  return (
    target.name.test(descriptor.name) &&
    (target.role === undefined || target.role === descriptor.role)
  );
}

async function tabTo(
  page: Page,
  target: FocusTarget,
  label: string,
  maxTabs = 80,
  key = "Tab",
): Promise<void> {
  const current = await activeElementDescriptor(page);
  if (targetMatches(current, target)) {
    await assertVisibleFocus(page, label);
    return;
  }
  for (let index = 0; index < maxTabs; index += 1) {
    await page.keyboard.press(key);
    await assertVisibleFocus(page, label);
    if (targetMatches(await activeElementDescriptor(page), target)) return;
  }
  throw new Error(`${label} was not reachable from the keyboard`);
}

async function tabToWithin(
  page: Page,
  scope: Locator,
  target: FocusTarget,
  label: string,
  maxTabs = 40,
): Promise<void> {
  for (let index = 0; index < maxTabs; index += 1) {
    await page.keyboard.press("Tab");
    await assertVisibleFocus(page, label);
    const inside = await scope.evaluate((node) =>
      node.contains(document.activeElement),
    );
    if (inside && targetMatches(await activeElementDescriptor(page), target)) {
      return;
    }
  }
  throw new Error(`${label} was not reachable inside its dialog`);
}

async function navigateToManagementPage(
  page: Page,
  destination: "Endpoints" | "Providers",
  key: "Tab" | "Shift+Tab" | null = "Tab",
  setSafeStage?: (stage: string) => void,
): Promise<void> {
  setSafeStage?.(`${destination.toLowerCase()}-navigation-trigger`);
  if (key) {
    await tabTo(
      page,
      { role: "button", name: /^zode\b/i },
      "management menu trigger",
      80,
      key,
    );
  } else {
    await page.getByRole("button", { name: /^zode\b/i }).focus();
    await assertVisibleFocus(page, "management menu trigger");
  }
  await page.keyboard.press("Enter");
  setSafeStage?.(`${destination.toLowerCase()}-navigation-menu`);
  const menu = page.getByRole("menu");
  await expect(menu).toBeVisible();
  setSafeStage?.(`${destination.toLowerCase()}-navigation-item`);
  for (let index = 0; index < 8; index += 1) {
    const inside = await menu.evaluate((node) => node.contains(document.activeElement));
    const descriptor = await activeElementDescriptor(page);
    if (
      inside &&
      targetMatches(descriptor, {
        role: "menuitem",
        name: new RegExp(`^${destination}$`, "i"),
      })
    ) {
      await page.keyboard.press("Enter");
      return;
    }
    await page.keyboard.press("ArrowDown");
  }
  throw new Error(`${destination} was not reachable in the management menu`);
}

async function assertDialogFocusTrap(
  page: Page,
  dialog: Locator,
  label: string,
): Promise<void> {
  const initiallyInside = await dialog.evaluate((node) =>
    node.contains(document.activeElement),
  );
  if (!initiallyInside) throw new Error(`${label} did not move focus into the dialog`);
  await assertVisibleFocus(page, `${label} initial focus`);
  for (let index = 0; index < 8; index += 1) {
    await page.keyboard.press("Tab");
    await assertVisibleFocus(page, label);
    const inside = await dialog.evaluate((node) =>
      node.contains(document.activeElement),
    );
    if (!inside) throw new Error(`${label} allowed focus to escape the dialog`);
  }
  for (let index = 0; index < 4; index += 1) {
    await page.keyboard.press("Shift+Tab");
    await assertVisibleFocus(page, label);
    const inside = await dialog.evaluate((node) =>
      node.contains(document.activeElement),
    );
    if (!inside) throw new Error(`${label} allowed reverse focus to escape the dialog`);
  }
}

async function pageSecretSurface(page: Page): Promise<SecretSurface> {
  return page.evaluate(async () => {
    const renderedText = [
      document.body?.innerText ?? "",
      document.body?.textContent ?? "",
    ];
    const accessibleNames: string[] = [];
    const domAttributes: string[] = [];
    const elements = Array.from(document.querySelectorAll<HTMLElement>("*"));

    for (const element of elements) {
      for (const attribute of Array.from(element.attributes)) {
        domAttributes.push(attribute.value);
      }
      domAttributes.push(element.outerHTML);

      const labelledBy = element
        .getAttribute("aria-labelledby")
        ?.split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent ?? "")
        .join(" ");
      const labels = element.matches("input, textarea, select")
        ? Array.from(
            (element as HTMLInputElement).labels ?? [],
            (label) => label.textContent ?? "",
          ).join(" ")
        : "";
      accessibleNames.push(
        element.getAttribute("aria-label") ?? "",
        labelledBy ?? "",
        element.getAttribute("title") ?? "",
        element.getAttribute("alt") ?? "",
        element.getAttribute("placeholder") ?? "",
        labels,
        element.textContent ?? "",
      );

      if (
        element instanceof HTMLInputElement ||
        element instanceof HTMLTextAreaElement ||
        element instanceof HTMLSelectElement
      ) {
        // Secret values are DOM properties as well as possible attributes.
        domAttributes.push(element.value);
      }
    }

    const storage: string[] = [];
    const readStorage = (store: Storage) => {
      for (let index = 0; index < store.length; index += 1) {
        const key = store.key(index);
        if (key !== null) {
          storage.push(key, store.getItem(key) ?? "");
        }
      }
    };
    try {
      readStorage(localStorage);
    } catch {
      storage.push("localStorage-unavailable");
    }
    try {
      readStorage(sessionStorage);
    } catch {
      storage.push("sessionStorage-unavailable");
    }
    try {
      storage.push(document.cookie);
    } catch {
      storage.push("cookie-unavailable");
    }

    if (typeof indexedDB.databases === "function") {
      try {
        const databases = await indexedDB.databases();
        for (const entry of databases) {
          if (!entry.name) continue;
          storage.push(entry.name);
          const database = await new Promise<IDBDatabase | null>((resolve) => {
            const request = indexedDB.open(entry.name as string);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => resolve(null);
          });
          if (!database) continue;
          for (const storeName of Array.from(database.objectStoreNames)) {
            storage.push(storeName);
            try {
              const records = await new Promise<unknown[]>((resolve) => {
                const request = database
                  .transaction(storeName, "readonly")
                  .objectStore(storeName)
                  .getAll();
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => resolve([]);
              });
              storage.push(
                ...records.map((record) => {
                  try {
                    return JSON.stringify(record);
                  } catch {
                    return String(record);
                  }
                }),
              );
            } catch {
              storage.push("indexeddb-record-read-failed");
            }
          }
          database.close();
        }
      } catch {
        storage.push("indexeddb-unavailable");
      }
    }

    const urlHistory = [
      location.href,
      document.referrer,
      window.name,
      (() => {
        try {
          return JSON.stringify(history.state);
        } catch {
          return "history-state-unserializable";
        }
      })(),
      ...performance
        .getEntriesByType("navigation")
        .map((entry) => (entry as PerformanceNavigationTiming).name),
    ];

    return { renderedText, accessibleNames, domAttributes, storage, urlHistory };
  });
}

async function installBrowserEvidence(
  page: Page,
  managementOrigin: string,
): Promise<BrowserEvidence> {
  const evidence: BrowserEvidence = {
    console: [],
    requestUrls: [],
    responseUrls: [],
    navigationUrls: [],
    history: [],
    serverResponseBodies: [],
    downloads: [],
    managementOrigin,
  };

  page.on("console", (message) => {
    evidence.console.push(`${message.type()}: ${message.text()}`);
  });
  page.on("pageerror", (error) => {
    evidence.console.push(`pageerror: ${error.message}`);
  });
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) evidence.navigationUrls.push(frame.url());
  });
  page.on("request", (request) => {
    evidence.requestUrls.push(request.url());
    if (request.isNavigationRequest() || request.resourceType() === "document") {
      evidence.navigationUrls.push(request.url());
    }
  });
  page.on("response", (response) => {
    evidence.responseUrls.push(response.url());
    let isManagementResponse = false;
    try {
      isManagementResponse = new URL(response.url()).origin === managementOrigin;
    } catch {
      return;
    }
    if (!isManagementResponse) return;
    evidence.serverResponseBodies.push(readBoundedResponseBody(response));
  });
  page.on("download", (download) => {
    evidence.downloads.push({
      download,
      filename: download.suggestedFilename(),
    });
  });

  return evidence;
}

function readBoundedResponseBody(response: {
  body: () => Promise<Buffer>;
}): Promise<string> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(""), 2_000);
    response
      .body()
      .then((body) => resolve(body.toString("utf8")))
      .catch(() => resolve(""))
      .finally(() => clearTimeout(timeout));
  });
}

async function recordHistory(page: Page, evidence: BrowserEvidence): Promise<void> {
  evidence.history.push(
    await page.evaluate(() => {
      try {
        return JSON.stringify({
          href: location.href,
          state: history.state,
          length: history.length,
        });
      } catch {
        return "history-state-unserializable";
      }
    }),
  );
}

async function flushEvidence(evidence: BrowserEvidence): Promise<string[]> {
  const values = await Promise.all(evidence.serverResponseBodies);
  for (const item of evidence.downloads) {
    values.push(item.filename);
    try {
      const path = await item.download.path();
      if (path) values.push((await readFile(path)).toString("utf8"));
    } catch {
      // A failed download has no readable artifact to scan.
    }
  }
  return values;
}

async function assertNoSecretMarker(
  page: Page,
  evidence: BrowserEvidence,
  phase: string,
): Promise<void> {
  const surface = await pageSecretSurface(page);
  assertSecretSurfaceAbsent(phase, surface);
  assertMarkerAbsent(
    `${phase}: browser cookies`,
    await page.context().cookies(),
  );
  assertMarkerAbsent(`${phase}: URL/history`, [
    ...surface.urlHistory,
    ...evidence.requestUrls,
    ...evidence.responseUrls,
    ...evidence.navigationUrls,
    ...evidence.history,
  ]);
  assertMarkerAbsent(`${phase}: console`, evidence.console);
  assertMarkerAbsent(`${phase}: Server responses/downloads`, await flushEvidence(evidence));
}

function assertSecretSurfaceAbsent(phase: string, surface: SecretSurface): void {
  assertMarkerAbsent(`${phase}: rendered text`, surface.renderedText);
  assertMarkerAbsent(`${phase}: accessible names`, surface.accessibleNames);
  assertMarkerAbsent(`${phase}: DOM attributes/properties`, surface.domAttributes);
  assertMarkerAbsent(`${phase}: browser storage`, surface.storage);
}

function assertBrowserStayedOnManagementServer(
  evidence: BrowserEvidence,
  harness: RealWebE2EHarness,
): void {
  const directBoundaryRequest = evidence.requestUrls.some(
    (url) =>
      url.startsWith(harness.endpoint.baseUrl) ||
      url.startsWith(harness.providerProxy.baseUrl),
  );
  if (directBoundaryRequest) {
    throw new Error("the browser called Endpoint/provider instead of the management Server");
  }
}

async function assertWriteOnlySecretControls(page: Page): Promise<void> {
  const values = await page.locator(
    [
      'input[type="password"]',
      'input[autocomplete="new-password"]',
      'input[data-secret-field]',
      'input[name*="api-key" i]',
      'input[name*="api_key" i]',
      'input[name*="secret" i]',
      'input[name*="credential" i]',
      'input[name*="control" i]',
      'input[aria-label*="credential" i]',
      'input[aria-label*="control" i]',
      'input[placeholder*="credential" i]',
      'input[placeholder*="control" i]',
      'textarea[data-secret-field]',
      'textarea[name*="secret" i]',
      'textarea[name*="credential" i]',
      'textarea[aria-label*="credential" i]',
      'textarea[aria-label*="control" i]',
    ].join(", "),
  ).evaluateAll((elements) =>
    elements.map((element) => (element as HTMLInputElement).value),
  );
  if (values.some((value) => value.length > 0)) {
    throw new Error("a submitted write-only secret control retained a value");
  }
}

async function assertTextStatus(page: Page, phase: string): Promise<void> {
  const statusFacts = await page.evaluate(() => {
    const selector =
      '[role="status"], [role="alert"], [role="log"], [data-status], [aria-live], [class*="status" i]';
    return Array.from(document.querySelectorAll<HTMLElement>(selector))
      .filter((element) => {
        const rect = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return (
          rect.width > 0 &&
          rect.height > 0 &&
          style.display !== "none" &&
          style.visibility !== "hidden"
        );
      })
      .map((element) => ({
        text: element.innerText.trim(),
        aria: element.getAttribute("aria-label") ?? "",
        title: element.getAttribute("title") ?? "",
        role: element.getAttribute("role") ?? "",
        live: element.getAttribute("aria-live") ?? "",
      }));
  });
  if (statusFacts.length === 0) {
    throw new Error(`${phase} did not expose a semantic status region`);
  }
  const statusPattern =
    /ready|added|installed|distributed|pending|online|connected|sending|streaming|sent|saved|created|updated|configured|available|active|queued|success|complete|done|stale|unreachable|failed|error/i;
  const labeledStatus = statusFacts.find(
    (fact) =>
      (fact.text || fact.aria || fact.title) &&
      statusPattern.test(`${fact.text} ${fact.aria} ${fact.title}`),
  );
  if (!labeledStatus) {
    throw new Error(`${phase} exposed a color-only or unlabeled status`);
  }
}

async function attachLiveRegionObserver(page: Page): Promise<void> {
  await page.evaluate(() => {
    const state = {
      updates: 0,
      nonEmpty: 0,
      regions: 0,
      snapshots: [] as string[],
    };
    const record = (element: Element | null) => {
      const region = element?.closest(
        '[aria-live], [role="status"], [role="alert"], [role="log"]',
      );
      if (!region) return;
      state.regions += 1;
      state.updates += 1;
      const text = (region.textContent ?? "").replace(/\s+/g, " ").trim();
      if (text) {
        state.nonEmpty += 1;
        if (state.snapshots[state.snapshots.length - 1] !== text) {
          state.snapshots.push(text);
        }
      }
    };
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData") {
          record(mutation.target.parentElement);
        } else {
          record(mutation.target instanceof Element ? mutation.target : null);
          for (const node of Array.from(mutation.addedNodes)) {
            if (node instanceof Element) record(node);
          }
        }
      }
    });
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
    });
    (window as typeof window & {
      __zodeLiveObserver?: { state: typeof state; observer: MutationObserver };
    }).__zodeLiveObserver = { state, observer };
  });
}

async function finishLiveRegionObserver(page: Page): Promise<{
  updates: number;
  nonEmpty: number;
  regions: number;
  snapshots: string[];
}> {
  return page.evaluate(() => {
    const handle = (window as typeof window & {
      __zodeLiveObserver?: {
        state: {
          updates: number;
          nonEmpty: number;
          regions: number;
          snapshots: string[];
        };
        observer: MutationObserver;
      };
    }).__zodeLiveObserver;
    handle?.observer.disconnect();
    const currentRegions = document.querySelectorAll(
      '[aria-live], [role="status"], [role="alert"], [role="log"]',
    ).length;
    return (
      handle
        ? { ...handle.state, regions: Math.max(handle.state.regions, currentRegions) }
        : { updates: 0, nonEmpty: 0, regions: currentRegions, snapshots: [] }
    );
  });
}

async function captureSecretSafeArtifacts(
  page: Page,
  context: BrowserContext,
  testInfo: TestInfo,
  blankPage = true,
): Promise<void> {
  if (blankPage) {
    try {
      await page.goto("about:blank", { waitUntil: "domcontentloaded" });
    } catch {
      return;
    }
  }

  const screenshot = await page.screenshot({ animations: "disabled" });
  assertSecretSurfaceAbsent(
    "screenshot page surface",
    await pageSecretSurface(page),
  );
  assertMarkerAbsent("failure screenshot", [screenshot]);
  await testInfo.attach("secret-safe-screenshot", {
    body: screenshot,
    contentType: "image/png",
  });

  const tracePath = testInfo.outputPath("secret-safe-trace.zip");
  await context.tracing.start({
    screenshots: true,
    snapshots: true,
    sources: false,
  });
  await page.screenshot({ animations: "disabled" });
  await context.tracing.stop({ path: tracePath });
  const trace = await readFile(tracePath);
  assertMarkerAbsent("failure trace", [trace]);
  await testInfo.attach("secret-safe-trace", {
    path: tracePath,
    contentType: "application/zip",
  });
}

async function loadIncidentFixture(): Promise<{
  schema: string;
  recording_id: string;
  owning_e2e: string;
  request: { method: string; path: string };
  first_observed: { status: number };
  expected_after_fix: { status: number };
}> {
  const fixture = JSON.parse(await readFile(INCIDENT_FIXTURE, "utf8")) as {
    schema: string;
    recording_id: string;
    e2e_name: string;
    boundary: string;
    first_observed: string;
    exchanges: Array<{
      method: string;
      path: string;
      response: { status: number };
    }>;
    synthetic_secret_slots: string[];
    expected_after_fix: { status: number };
    integrity_sha256?: string;
  };
  const exchange = fixture.exchanges?.[0];
  if (
    fixture.schema !== "zode.http-incident-cassette.v1" ||
    fixture.e2e_name !== NAMED_E2E ||
    fixture.boundary !== "management-access-edge" ||
    typeof fixture.first_observed !== "string" ||
    !exchange ||
    fixture.exchanges.length !== 1 ||
    exchange.method !== "GET" ||
    exchange.path !== "/" ||
    exchange.response.status !== 404 ||
    !fixture.synthetic_secret_slots.includes("<secret:synthetic_api_key>")
  ) {
    throw new Error("the first-failure cassette metadata is invalid");
  }
  const withoutDigest = JSON.parse(JSON.stringify(fixture)) as Record<string, unknown>;
  const expectedDigest = withoutDigest.integrity_sha256;
  delete withoutDigest.integrity_sha256;
  const actualDigest = createHash("sha256")
    .update(JSON.stringify(withoutDigest))
    .digest("hex");
  if (expectedDigest !== actualDigest) {
    throw new Error("the first-failure cassette integrity check failed");
  }
  return {
    schema: fixture.schema,
    recording_id: fixture.recording_id,
    owning_e2e: fixture.e2e_name,
    request: { method: exchange.method, path: exchange.path },
    first_observed: { status: exchange.response.status },
    expected_after_fix: fixture.expected_after_fix,
  };
}

function toSafeHarnessFailure(error: unknown): Error {
  if (error instanceof HarnessFailure) return error;
  return new ProductBehaviorFailure(
    "BROWSER_UI_BEHAVIOR_FAILURE",
    "the named browser scenario failed through the real management Server",
  );
}

async function replayTrackedCassette(
  harness: RealWebE2EHarness,
): Promise<void> {
  const cassette = await loadIncidentFixture();
  const response = await fetch(
    new URL(cassette.request.path, harness.managementUrl),
    { headers: { accept: "text/html" } },
  );
  await response.arrayBuffer();
  if (response.status === cassette.first_observed.status) {
    throw new ProductBehaviorFailure(
      "PRODUCT_ROUTE_MISSING_SHALLOW_404",
      "the retained browser-entry failure still reproduces through the public management origin",
    );
  }
  if (response.status !== cassette.expected_after_fix.status) {
    throw new ProductBehaviorFailure(
      "BROWSER_BOOTSTRAP_BEHAVIOR_FAILURE",
      "the retained browser-entry request returned an unexpected status",
    );
  }
}

async function withRealServerBrowserHarness<T>(
  page: Page,
  run: (
    harness: RealWebE2EHarness,
    evidence: BrowserEvidence,
    setSafeStage: (stage: string) => void,
  ) => Promise<T>,
): Promise<T> {
  let harness: RealWebE2EHarness | undefined;
  let primaryFailure: unknown;
  let safeStage = "harness-start";
  try {
    harness = await createWebE2EHarness({
      e2eName: NAMED_E2E,
      uiMode: "assets",
      authorityId: "web-e2e-accessibility-secret",
    });
    harness.ledger.add("synthetic_api_key", SYNTHETIC_SECRET_MARKER);
    activeSecretMarkers = [
      SYNTHETIC_SECRET_MARKER,
      harness.controllerSecret,
      harness.providerSecret,
    ];
    const evidence = await installBrowserEvidence(
      page,
      new URL(harness.managementUrl).origin,
    );
    return await run(harness, evidence, (stage) => {
      safeStage = stage;
    });
  } catch (error) {
    primaryFailure = error;
    if (!harness) throw error;

    let replayStage = "runtime-cassette";
    try {
      await harness.captureAndReplayFailure(
        toSafeHarnessFailure(error),
        NAMED_E2E,
      );
      replayStage = "tracked-cassette";
      await replayTrackedCassette(harness);
    } catch (replayError) {
      // Do not expose a request, response, or secret-bearing error.  The
      // first failure remains the primary browser assertion below.
      const classification =
        replayError &&
        typeof replayError === "object" &&
        "classification" in replayError &&
        typeof replayError.classification === "string"
          ? replayError.classification
          : replayError instanceof Error
            ? `NATIVE_${replayError.name}_${
                "code" in replayError && typeof replayError.code === "string"
                  ? replayError.code
                  : "NO_CODE"
              }`
            : "UNKNOWN_REPLAY_FAILURE";
      throw new Error(`the first browser failure could not be replayed safely (${replayStage}:${classification})`);
    }
    throw new Error(
      `the named browser scenario failed during ${safeStage}; its first real exchange was retained and replayed`,
    );
  } finally {
    try {
      await harness?.close();
    } catch (error) {
      if (!primaryFailure) throw error;
    } finally {
      activeSecretMarkers = [SYNTHETIC_SECRET_MARKER];
    }
  }
}

async function openApiKeyEditor(page: Page): Promise<{
  trigger: Locator;
  editor: Locator;
}> {
  const trigger = page.getByRole("button", {
    name: /add (an? )?(api[ -]?key )?profile|new (api[ -]?key )?profile/i,
  }).first();
  await tabTo(
    page,
    { role: "button", name: /add (an? )?(api[ -]?key )?profile|new (api[ -]?key )?profile/i },
    "API-key profile trigger",
  );
  await page.keyboard.press("Enter");
  const editor = page
    .locator("form.nested-editor")
    .filter({ hasText: /add api[ -]?key profile/i });
  await expect(editor).toBeVisible();
  await expect(trigger).toHaveAttribute("aria-expanded", "true");
  return { trigger, editor };
}

test.describe(
  NAMED_E2E,
  () => {
    test.afterEach(async ({ page, context }, testInfo) => {
      await captureSecretSafeArtifacts(page, context, testInfo);
    });

    test("e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure__first_failure_replay", async ({
      page,
    }, testInfo) => {
      await withRealServerBrowserHarness(page, async (harness, evidence) => {
        const cassette = await loadIncidentFixture();

        const response = await page.goto(
          new URL(cassette.request.path, harness.managementUrl).toString(),
          { waitUntil: "domcontentloaded" },
        );
        const status = response?.status() ?? 0;
        if (status !== cassette.expected_after_fix.status) {
          if (status === cassette.first_observed.status) {
            throw new ProductRouteMissing({
              path: cassette.request.path,
              status,
              surface: "real management Server browser entry",
            });
          }
          throw new ProductBehaviorFailure(
            "BROWSER_BOOTSTRAP_BEHAVIOR_FAILURE",
            "the real management Server browser entry returned an unexpected status",
          );
        }
        await replayTrackedCassette(harness);
        await expect(page.getByRole("navigation")).toBeVisible();
        await assertNoSecretMarker(page, evidence, "after first-failure replay");
        await captureSecretSafeArtifacts(page, page.context(), testInfo, false);
      });
    });

    test(
      "e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure__write_only_provider_profile_distribution_session_create_and_chat",
      async ({ page }, testInfo) => {
        await withRealServerBrowserHarness(page, async (harness, evidence, setSafeStage) => {
          setSafeStage("browser-bootstrap");
          const cassette = await loadIncidentFixture();
          expect(cassette.request.path).toBe("/");
          expect(cassette.first_observed.status).toBeLessThan(500);
          expect(cassette.expected_after_fix.status).toBe(200);

          const response = await page.goto(
            new URL("/", harness.managementUrl).toString(),
            { waitUntil: "domcontentloaded" },
          );
          const status = response?.status() ?? 0;
          if (status === cassette.first_observed.status) {
            throw new ProductRouteMissing({
              path: "/",
              status,
              surface: "real management Server browser entry",
            });
          }
          if (status !== cassette.expected_after_fix.status) {
            throw new ProductBehaviorFailure(
              "BROWSER_BOOTSTRAP_BEHAVIOR_FAILURE",
              "the real management Server browser entry returned an unexpected status",
            );
          }
          await replayTrackedCassette(harness);
          await expect(page.getByRole("navigation")).toBeVisible();
          await recordHistory(page, evidence);

          setSafeStage("endpoint-navigation-tab");
          await navigateToManagementPage(page, "Endpoints", "Tab", setSafeStage);
          setSafeStage("endpoint-navigation-activate");
          setSafeStage("endpoint-page");
          await expect(
            page.getByRole("heading", { name: "Endpoints", exact: true }),
          ).toBeVisible();
          setSafeStage("endpoint-trigger-tab");
          const endpointTrigger = page.getByRole("button", {
            name: /add remote endpoint|add endpoint|new endpoint/i,
          }).first();
          await tabTo(
            page,
            { role: "button", name: /add remote endpoint|add endpoint|new endpoint/i },
            "remote Endpoint creation trigger",
          );
          setSafeStage("endpoint-trigger-activate");
          await page.keyboard.press("Enter");
          setSafeStage("endpoint-dialog");
          const endpointDialog = page.getByRole("dialog").last();
          await expect(endpointDialog).toBeVisible();
          await tabToWithin(
            page,
            endpointDialog,
            { role: "textbox", name: /endpoint label|label/i },
            "Endpoint label field",
          );
          await page.keyboard.type(ENDPOINT_LABEL);
          setSafeStage("endpoint-url");
          await tabToWithin(
            page,
            endpointDialog,
            { role: "textbox", name: /endpoint url|base url|url/i },
            "Endpoint URL field",
          );
          await page.keyboard.type(harness.endpoint.baseUrl);
          setSafeStage("endpoint-credential");
          await tabToWithin(
            page,
            endpointDialog,
            {
              role: "textbox",
              name: /controller credential|control secret|credential.*write-only/i,
            },
            "Endpoint control credential field",
          );
          await expect(
            endpointDialog.getByRole("textbox", {
              name: /controller credential|control secret|credential.*write-only/i,
            }).first(),
          ).toHaveAttribute("type", "password");
          await page.keyboard.type(harness.controllerSecret);
          setSafeStage("endpoint-submit");
          await tabToWithin(
            page,
            endpointDialog,
            { role: "button", name: /add endpoint|create endpoint|save endpoint/i },
            "Endpoint creation submit",
          );
          await page.keyboard.press("Enter");
          setSafeStage("endpoint-submit-result");
          await expect(endpointDialog).toBeHidden({ timeout: 30_000 });
          await expect(endpointTrigger).toBeFocused();
          await assertVisibleFocus(page, "restored Endpoint trigger focus");
          await assertWriteOnlySecretControls(page);
          await assertTextStatus(page, "Endpoint control credential submission");
          await assertNoSecretMarker(page, evidence, "after Endpoint control credential submission");
          assertBrowserStayedOnManagementServer(evidence, harness);
          await recordHistory(page, evidence);

          setSafeStage("provider-navigation");
          await navigateToManagementPage(page, "Providers", null, setSafeStage);
          setSafeStage("provider-page");
          await expect(
            page.getByRole("heading", { name: "Providers", exact: true }),
          ).toBeVisible();

          setSafeStage("provider-trigger");
          await tabTo(
            page,
            { role: "button", name: /configure provider|add provider/i },
            "provider descriptor configuration trigger",
          );
          const providerTrigger = page.getByRole("button", {
            name: /configure provider|add provider/i,
          }).first();
          await page.keyboard.press("Enter");
          const providerForm = page
            .locator("form.editor-panel")
            .filter({ hasText: "Configure provider" });
          await expect(providerForm).toBeVisible();
          setSafeStage("provider-id");
          await tabToWithin(
            page,
            providerForm,
            { role: "textbox", name: /provider name|provider id|name/i },
            "provider name field",
          );
          await page.keyboard.type(PROVIDER_ID);
          await expect(
            providerForm.getByText("OpenAI compatible", { exact: true }),
          ).toBeVisible();
          setSafeStage("provider-base-url");
          await tabToWithin(
            page,
            providerForm,
            { role: "textbox", name: /execution base url|base url/i },
            "provider execution base URL field",
          );
          await page.keyboard.type(`${harness.providerProxy.baseUrl}/v1`);
          setSafeStage("provider-model");
          await tabToWithin(
            page,
            providerForm,
            { role: "textbox", name: /models?|model catalog/i },
            "provider model field",
          );
          await page.keyboard.type(PROVIDER_MODEL);
          setSafeStage("provider-submit");
          await tabToWithin(
            page,
            providerForm,
            { role: "button", name: /save provider|create provider/i },
            "provider descriptor submit",
          );
          await page.keyboard.press("Enter");
          await expect(providerForm).toBeHidden({ timeout: 30_000 });
          await expect(providerTrigger).toBeFocused();
          await assertVisibleFocus(page, "restored provider trigger focus");
          await assertTextStatus(page, "provider descriptor submission");
          await assertNoSecretMarker(page, evidence, "after provider descriptor submission");
          assertBrowserStayedOnManagementServer(evidence, harness);

          setSafeStage("profile-creation");
          const firstEditor = await openApiKeyEditor(page);
          setSafeStage("profile-cancel-keyboard");
          await tabToWithin(
            page,
            firstEditor.editor,
            { role: "button", name: /^cancel$/i },
            "API-key profile cancel",
          );
          await page.keyboard.press("Enter");
          await expect(firstEditor.editor).toBeHidden();
          await expect(firstEditor.trigger).toBeFocused();
          await assertVisibleFocus(page, "restored API-key trigger focus");

          setSafeStage("profile-editor-reopen");
          const { trigger: profileTrigger, editor } = await openApiKeyEditor(page);
          setSafeStage("profile-label");
          await tabToWithin(
            page,
            editor,
            { role: "textbox", name: /label|profile name/i },
            "profile label field",
          );
          await page.keyboard.type(PROFILE_LABEL);

          setSafeStage("profile-secret");
          await tabToWithin(
            page,
            editor,
            { role: "textbox", name: /api[ -]?key|secret/i },
            "provider API-key field",
          );
          await expect(
            editor.getByRole("textbox", { name: /api[ -]?key|secret/i }).first(),
          ).toHaveAttribute("type", "password");
          await page.keyboard.type(SYNTHETIC_SECRET_MARKER);

          setSafeStage("profile-sharing");
          await tabToWithin(
            page,
            editor,
            { role: "checkbox", name: /this machine|built-in|local endpoint|share with|remote endpoint/i },
            "Endpoint distribution target",
          );
          await page.keyboard.press("Space");

          setSafeStage("profile-submit");
          await tabToWithin(
            page,
            editor,
            { role: "button", name: /create|save|add profile/i },
            "API-key profile submit",
          );
          await page.keyboard.press("Enter");
          setSafeStage("profile-submit-result");
          await expect(editor).toBeHidden({ timeout: 30_000 });
          await expect(profileTrigger).toBeFocused();
          await assertVisibleFocus(page, "restored API-key profile trigger focus");
          await assertWriteOnlySecretControls(page);
          await assertTextStatus(page, "profile distribution");
          await assertNoSecretMarker(page, evidence, "after API-key profile submission");
          assertBrowserStayedOnManagementServer(evidence, harness);
          await recordHistory(page, evidence);

          setSafeStage("session-creation");
          await page.getByRole("link", { name: /^new session$/i }).focus();
          await assertVisibleFocus(page, "New session navigation");
          await page.keyboard.press("Enter");
          setSafeStage("session-composer");
          const sessionComposer = page.locator("form#home-session-composer");
          await expect(sessionComposer).toBeVisible();
          await expect(
            sessionComposer.getByRole("combobox", { name: "Environment", exact: true }),
          ).toContainText(ENDPOINT_LABEL);
          await expect(
            sessionComposer.getByRole("button", {
              name: "Choose model and reasoning",
              exact: true,
            }),
          ).toContainText(PROVIDER_MODEL);

          setSafeStage("session-message");
          await tabTo(
            page,
            { role: "textbox", name: /new session message/i },
            "new session composer",
          );
          setSafeStage("session-message-entry");
          await page.keyboard.type(`Reply with exactly ${EXPECTED_ASSISTANT_TEXT}`);
          setSafeStage("session-submit-focus");
          await expect(
            sessionComposer.getByRole("button", { name: /start session/i }),
          ).toBeEnabled({ timeout: 30_000 });
          await tabTo(
            page,
            { role: "button", name: /start session/i },
            "session create submit",
          );
          setSafeStage("session-live-observer");
          await attachLiveRegionObserver(page);
          setSafeStage("session-submit");
          await page.keyboard.press("Enter");

          setSafeStage("session-create-result");
          await expect(page).toHaveURL(
            /\/endpoints\/[^/]+\/sessions\/[^/]+(?:$|[?#])/,
            { timeout: 30_000 },
          );
          const sessionPath = new URL(page.url()).pathname;
          if (!/^\/endpoints\/[^/]+\/sessions\/[^/]+$/.test(sessionPath)) {
            throw new Error("the browser did not use the Endpoint-scoped session route");
          }
          await assertNoSecretMarker(page, evidence, "after session creation");
          assertBrowserStayedOnManagementServer(evidence, harness);

          setSafeStage("session-chat");
          await expect(
            page.getByText(EXPECTED_ASSISTANT_TEXT, { exact: false }).last(),
          ).toBeVisible({ timeout: 45_000 });
          const live = await finishLiveRegionObserver(page);
          if (live.regions === 0 || live.snapshots.length === 0) {
            throw new Error("the session did not expose an ARIA live region announcement");
          }
          if (
            live.nonEmpty > 12 ||
            live.snapshots.length > 12 ||
            live.snapshots.length > EXPECTED_ASSISTANT_TEXT.length / 2 + 3
          ) {
            throw new Error("the live region announced token-sized updates too often");
          }
          assertMarkerAbsent("live-region snapshots", live.snapshots);
          await assertTextStatus(page, "session completion");
          await assertNoSecretMarker(page, evidence, "after session chat");
          assertBrowserStayedOnManagementServer(evidence, harness);
          await recordHistory(page, evidence);
          await captureSecretSafeArtifacts(page, page.context(), testInfo, false);
        });
      },
    );
  },
);
