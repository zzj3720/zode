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
  createWebE2EHarness: (options?: { includeServerOrigins?: boolean }) => Promise<RealWebE2EHarness>;
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
const LATER_REPRODUCTION_RELATION = "later_test_reproduction_of_gap";
const HTTP_REPLAYABLE_FAILURE_CLASSIFICATIONS = new Set([
  "PRODUCT_ROUTE_MISSING_SHALLOW_404",
  "BROWSER_BOOTSTRAP_BEHAVIOR_FAILURE",
  "ENDPOINT_CREATE_RESPONSE_FAILURE",
  "PROVIDER_DESCRIPTOR_RESPONSE_FAILURE",
  "PROVIDER_PROFILE_RESPONSE_FAILURE",
]);
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
  beginCaptureSet: (options: {
    e2eName: string;
    maxMembers: number;
  }) => string;
  captureAndReplayFailure: (
    error: Error,
    e2eName: string,
    options?: { relation?: typeof LATER_REPRODUCTION_RELATION },
  ) => Promise<unknown>;
  journal: {
    replay: (
      cassettePath: string,
      options: { baseUrl: string; headers?: Record<string, string> },
    ) => Promise<unknown>;
  };
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
    throw new ProductBehaviorFailure(
      "SECRET_MARKER_EXPOSED",
      "a public browser or Server surface contained a synthetic secret marker",
      { label },
    );
  }
}

async function activeElementDescriptor(page: Page): Promise<{
  name: string;
  role: string;
}> {
  return page.evaluate(() => {
    const element = document.activeElement as HTMLElement | null;
    if (!element || element === document.body) return { name: "", role: "" };

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
      .map((value) => value?.replace(/\s+/g, " ").trim() ?? "")
      .find(Boolean) ?? "";

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
    const styled =
      (style.outlineStyle !== "none" && style.outlineWidth !== "0px") ||
      style.boxShadow !== "none";
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
    const active = await activeElementDescriptor(page);
    throw new ProductBehaviorFailure(
      "KEYBOARD_FOCUS_VISIBILITY_FAILURE",
      "the current keyboard target did not expose the required visible focus ring",
      {
        label,
        active_role: /^[a-z][a-z0-9_-]{0,31}$/.test(active.role)
          ? active.role
          : "unavailable",
      },
    );
  }
}

async function assertFocusRestored(
  page: Page,
  trigger: Locator,
  details: {
    label: string;
    method?: string;
    path?: string;
    stage: string;
    status?: number;
  },
): Promise<void> {
  let focused = false;
  try {
    if (await trigger.count() === 1) {
      focused = await trigger.evaluate((node) => node === document.activeElement);
    }
  } catch {
    focused = false;
  }
  if (!focused) {
    const active = await activeElementDescriptor(page);
    throw new ProductBehaviorFailure(
      "KEYBOARD_FOCUS_RESTORATION_FAILURE",
      "a completed or cancelled keyboard action did not restore focus to its trigger",
      {
        ...details,
        active_role: /^[a-z][a-z0-9_-]{0,31}$/.test(active.role)
          ? active.role
          : "unavailable",
      },
    );
  }
  try {
    await assertVisibleFocus(page, details.label);
  } catch {
    throw new ProductBehaviorFailure(
      "KEYBOARD_FOCUS_RESTORATION_FAILURE",
      "the restored keyboard trigger did not expose its visible focus indication",
      details,
    );
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
): Promise<void> {
  for (let index = 0; index < maxTabs; index += 1) {
    await page.keyboard.press("Tab");
    const descriptor = await activeElementDescriptor(page);
    // Chromium may briefly return keyboard focus from browser chrome to the
    // document body.  Body is not a user-operable target; keep traversing and
    // require every actual control we encounter to expose its focus ring.
    if (descriptor.role === "" && descriptor.name === "") continue;
    await assertVisibleFocus(page, label);
    if (targetMatches(descriptor, target)) return;
  }
  throw new ProductBehaviorFailure(
    "KEYBOARD_TARGET_UNREACHABLE",
    "the expected public control was not reachable from the keyboard",
    { label },
  );
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
  throw new ProductBehaviorFailure(
    "KEYBOARD_EDITOR_TARGET_UNREACHABLE",
    "the expected public editor control was not reachable from the keyboard",
    { label },
  );
}

async function assertDialogFocusTrap(
  page: Page,
  dialog: Locator,
  label: string,
): Promise<void> {
  const initiallyInside = await dialog.evaluate((node) =>
    node.contains(document.activeElement),
  );
  if (!initiallyInside) {
    throw new ProductBehaviorFailure(
      "KEYBOARD_DIALOG_FOCUS_FAILURE",
      "keyboard activation did not move focus into the opened dialog",
      { label },
    );
  }
  await assertVisibleFocus(page, `${label} initial focus`);
  for (let index = 0; index < 8; index += 1) {
    await page.keyboard.press("Tab");
    await assertVisibleFocus(page, label);
    const inside = await dialog.evaluate((node) =>
      node.contains(document.activeElement),
    );
    if (!inside) {
      throw new ProductBehaviorFailure(
        "KEYBOARD_DIALOG_FOCUS_TRAP_FAILURE",
        "forward keyboard traversal escaped the opened dialog",
        { label },
      );
    }
  }
  for (let index = 0; index < 4; index += 1) {
    await page.keyboard.press("Shift+Tab");
    await assertVisibleFocus(page, label);
    const inside = await dialog.evaluate((node) =>
      node.contains(document.activeElement),
    );
    if (!inside) {
      throw new ProductBehaviorFailure(
        "KEYBOARD_DIALOG_FOCUS_TRAP_FAILURE",
        "reverse keyboard traversal escaped the opened dialog",
        { label },
      );
    }
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

async function readSecretScanSurface<T>(
  label: string,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof HarnessFailure
      || (error && typeof error === "object" && "classification" in error)
    ) {
      throw error;
    }
    throw new ProductBehaviorFailure(
      "SECRET_SCAN_READ_FAILURE",
      "a required secret-scan surface could not be read",
      { label },
    );
  }
}

async function assertNoSecretMarker(
  page: Page,
  evidence: BrowserEvidence,
  phase: string,
): Promise<void> {
  const surface = await readSecretScanSurface(
    `${phase}: page surface`,
    () => pageSecretSurface(page),
  );
  assertSecretSurfaceAbsent(phase, surface);
  const cookies = await readSecretScanSurface(
    `${phase}: browser cookies`,
    () => page.context().cookies(),
  );
  assertMarkerAbsent(
    `${phase}: browser cookies`,
    cookies,
  );
  assertMarkerAbsent(`${phase}: URL/history`, [
    ...surface.urlHistory,
    ...evidence.requestUrls,
    ...evidence.responseUrls,
    ...evidence.navigationUrls,
    ...evidence.history,
  ]);
  assertMarkerAbsent(`${phase}: console`, evidence.console);
  const responseEvidence = await readSecretScanSurface(
    `${phase}: Server responses/downloads`,
    () => flushEvidence(evidence),
  );
  assertMarkerAbsent(`${phase}: Server responses/downloads`, responseEvidence);
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
    throw new ProductBehaviorFailure(
      "BROWSER_BYPASSED_MANAGEMENT_SERVER",
      "the browser called an Endpoint or provider boundary instead of the management Server",
    );
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
    fixture.schema !== "zode.http-incident-recording.v1" ||
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

function safeErrorClassification(error: unknown): string {
  if (
    error
    && typeof error === "object"
    && "classification" in error
    && typeof error.classification === "string"
    && /^[A-Z][A-Z0-9_]{0,95}$/.test(error.classification)
  ) {
    return error.classification;
  }
  if (error instanceof Error) {
    const name = error.name.replace(/[^A-Za-z0-9_]/g, "_").slice(0, 64);
    return `NATIVE_${name || "ERROR"}`;
  }
  return "UNKNOWN_BROWSER_FAILURE";
}

function safeErrorContext(error: unknown): string {
  if (!error || typeof error !== "object" || !("details" in error)) return "";
  const details = error.details;
  if (!details || typeof details !== "object") return "";
  const fields: string[] = [];
  if (
    "label" in details
    && typeof details.label === "string"
    && /^[A-Za-z0-9][A-Za-z0-9 .:/_-]{0,95}$/.test(details.label)
    && !activeSecretMarkers.some((marker) => details.label.includes(marker))
  ) {
    fields.push(`label=${details.label}`);
  }
  if (
    "stage" in details
    && typeof details.stage === "string"
    && /^[a-z][a-z0-9-]{0,63}$/.test(details.stage)
  ) {
    fields.push(`stage=${details.stage}`);
  }
  if (
    "status" in details
    && typeof details.status === "number"
    && Number.isInteger(details.status)
    && details.status >= 100
    && details.status <= 599
  ) {
    fields.push(`status=${details.status}`);
  }
  if (
    "active_role" in details
    && typeof details.active_role === "string"
    && /^[a-z][a-z0-9_-]{0,31}$/.test(details.active_role)
  ) {
    fields.push(`active_role=${details.active_role}`);
  }
  if (
    "count" in details
    && typeof details.count === "number"
    && Number.isInteger(details.count)
    && details.count >= 0
    && details.count <= 99
  ) {
    fields.push(`count=${details.count}`);
  }
  return fields.length === 0 ? "" : ` [${fields.join(", ")}]`;
}

function toSafeHarnessFailure(error: unknown, stage: string): Error {
  const classification = safeErrorClassification(error);
  const sourceDetails = error && typeof error === "object" && "details" in error
    && error.details && typeof error.details === "object"
    ? error.details
    : undefined;
  const details: Record<string, unknown> = {
    stage,
  };
  if (
    sourceDetails
    && "method" in sourceDetails
    && typeof sourceDetails.method === "string"
    && /^[A-Z]{3,10}$/.test(sourceDetails.method)
  ) {
    details.method = sourceDetails.method;
  }
  if (
    sourceDetails
    && "path" in sourceDetails
    && typeof sourceDetails.path === "string"
    && /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,511}$/.test(sourceDetails.path)
    && !activeSecretMarkers.some((marker) => sourceDetails.path.includes(marker))
  ) {
    details.path = sourceDetails.path;
  }
  if (
    sourceDetails
    && "status" in sourceDetails
    && typeof sourceDetails.status === "number"
    && Number.isInteger(sourceDetails.status)
    && sourceDetails.status >= 100
    && sourceDetails.status <= 599
  ) {
    details.status = sourceDetails.status;
  }
  if (
    details.method === undefined
    && classification === "PRODUCT_ROUTE_MISSING_SHALLOW_404"
    && details.path !== undefined
    && details.status !== undefined
  ) {
    details.method = "GET";
  }
  details.browserBehaviorReplayRequired = !(
    HTTP_REPLAYABLE_FAILURE_CLASSIFICATIONS.has(classification)
    && typeof details.method === "string"
    && typeof details.path === "string"
    && typeof details.status === "number"
  );
  return new ProductBehaviorFailure(
    classification,
    "the named browser scenario failed through the real management Server",
    details,
  );
}

async function replayTrackedCassette(
  harness: RealWebE2EHarness,
): Promise<void> {
  try {
    await harness.journal.replay(INCIDENT_FIXTURE, {
      baseUrl: harness.managementUrl,
    });
  } catch (error) {
    const details =
      error && typeof error === "object" && "details" in error
        ? error.details
        : undefined;
    if (
      error &&
      typeof error === "object" &&
      "classification" in error &&
      (error.classification === "REPLAY_MISMATCH" ||
        error.classification === "REPLAY_RESPONSE_HEADER_MISMATCH") &&
      (error.classification === "REPLAY_RESPONSE_HEADER_MISMATCH" ||
        (details &&
          typeof details === "object" &&
          "actualStatus" in details &&
          details.actualStatus === 200))
    ) {
      // The retained cassette is the pre-fix 404.  The public browser
      // assertion above already proved the repaired route is 200; a strict
      // replay therefore fails at the first differing response field (status
      // or headers), both of which are valid evidence that the old exchange
      // no longer matches.
      return;
    }
    throw error;
  }
}

async function withRealServerBrowserHarness<T>(
  page: Page,
  run: (
    harness: RealWebE2EHarness,
    evidence: BrowserEvidence,
    setStage: (stage: string) => void,
  ) => Promise<T>,
  { failureRelation }: {
    failureRelation?: typeof LATER_REPRODUCTION_RELATION;
  } = {},
): Promise<T> {
  let harness: RealWebE2EHarness | undefined;
  let primaryFailure: unknown;
  let currentStage = "harness-startup";
  try {
    harness = await createWebE2EHarness({ includeServerOrigins: true });
    if (failureRelation !== undefined) {
      harness.beginCaptureSet({
        e2eName: `${NAMED_E2E}__${failureRelation}`,
        maxMembers: 64,
      });
    }
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
      if (!/^[a-z][a-z0-9-]{0,63}$/.test(stage)) {
        throw new Error("browser evidence stage is invalid");
      }
      currentStage = stage;
    });
  } catch (error) {
    primaryFailure = error;
    if (!harness) throw error;

    const safeFailure = toSafeHarnessFailure(error, currentStage);
    let captured: unknown;
    try {
      captured = await harness.captureAndReplayFailure(
        safeFailure,
        NAMED_E2E,
        { relation: failureRelation },
      );
    } catch (captureError) {
      const classification =
        captureError &&
        typeof captureError === "object" &&
        "classification" in captureError &&
        typeof captureError.classification === "string"
          ? captureError.classification
          : captureError instanceof Error
            ? `NATIVE_${captureError.name}_${
                "code" in captureError && typeof captureError.code === "string"
                  ? captureError.code
                  : "NO_CODE"
              }`
            : "UNKNOWN_CAPTURE_FAILURE";
      throw new Error(`the browser failure context could not be durably sealed (${classification})`);
    }
    if (!captured || typeof captured !== "object") {
      throw new Error(
        `the browser failure evidence remained incomplete (BROWSER_FAILURE_EVIDENCE_GAP:${currentStage})`,
      );
    }
    if (
      "browserBehaviorReplayRequired" in captured
      && captured.browserBehaviorReplayRequired === true
    ) {
      if (
        !("captureSet" in captured)
        || !captured.captureSet
        || typeof captured.captureSet !== "object"
        || !("records" in captured.captureSet)
        || !Array.isArray(captured.captureSet.records)
        || captured.captureSet.records.length === 0
      ) {
        throw new Error(
          `the browser failure evidence remained incomplete (BROWSER_FAILURE_EVIDENCE_GAP:${currentStage})`,
        );
      }
      throw new Error(
        `the named browser scenario failed at ${currentStage} (${safeErrorClassification(error)})${safeErrorContext(error)}; its public context was durably sealed but same-entry Chromium replay is still required before product repair`,
      );
    }
    if (
      !("record" in captured)
      || !captured.record
      || !("captureSet" in captured)
      || !captured.captureSet
      || !("cassettePath" in captured)
      || typeof captured.cassettePath !== "string"
    ) {
      throw new Error(
        `the browser HTTP failure evidence remained incomplete (BROWSER_FAILURE_EVIDENCE_GAP:${currentStage})`,
      );
    }
    throw new Error(
      `the named browser scenario failed at ${currentStage} (${safeErrorClassification(error)})${safeErrorContext(error)}; its exact public HTTP exchange was retained and same-entry replayed`,
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

async function resolveKeyboardEditor(
  page: Page,
  headingName: string,
  label: string,
  activationTrigger: Locator,
): Promise<{ editor: Locator }> {
  const heading = page.getByRole("heading", { name: headingName, exact: true });
  await expect(heading).toHaveCount(1);
  await expect(heading).toBeVisible();

  const dialogs = page.getByRole("dialog").filter({ has: heading });
  const dialogCount = await dialogs.count();
  if (dialogCount > 1) {
    throw new ProductBehaviorFailure(
      "KEYBOARD_EDITOR_NOT_UNIQUE",
      "keyboard activation exposed more than one matching dialog",
      { label, count: dialogCount },
    );
  }
  if (dialogCount === 1) {
    const dialog = dialogs.first();
    await expect(dialog).toBeVisible();
    await assertDialogFocusTrap(page, dialog, label);
    return { editor: dialog };
  }

  const forms = page.locator("form:visible").filter({ has: heading });
  const formCount = await forms.count();
  if (formCount !== 1) {
    throw new ProductBehaviorFailure(
      "KEYBOARD_EDITOR_NOT_UNIQUE",
      "keyboard activation did not expose exactly one matching semantic editor",
      { label, count: formCount },
    );
  }
  const form = forms.first();
  await expect(form).toBeVisible();
  const focusEnteredForm = await form.evaluate((node) =>
    node.contains(document.activeElement),
  );
  let triggerRetainedFocus = false;
  try {
    if (await activationTrigger.count() === 1) {
      triggerRetainedFocus = await activationTrigger.evaluate((node) =>
        node === document.activeElement,
      );
    }
  } catch {
    triggerRetainedFocus = false;
  }
  if (!focusEnteredForm && !triggerRetainedFocus) {
    throw new ProductBehaviorFailure(
      "KEYBOARD_EDITOR_FOCUS_FAILURE",
      "keyboard activation left neither the trigger nor the opened semantic form focused",
      { label },
    );
  }
  await assertVisibleFocus(page, `${label} initial focus`);
  return { editor: form };
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
  const result = await resolveKeyboardEditor(
    page,
    "Add API key profile",
    "API-key profile editor",
    trigger,
  );
  return { trigger, ...result };
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
            { method: "GET", path: cassette.request.path, status },
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
        await withRealServerBrowserHarness(page, async (harness, evidence, setStage) => {
          setStage("browser-bootstrap");
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
              { method: "GET", path: "/", status },
            );
          }
          await replayTrackedCassette(harness);
          await expect(page.getByRole("navigation")).toBeVisible();
          await recordHistory(page, evidence);

          setStage("endpoint-navigation");
          await tabTo(page, { name: /^endpoints$/i }, "Endpoints navigation");
          setStage("endpoint-navigation-activate");
          await page.keyboard.press("Enter");
          setStage("endpoint-navigation-render");
          await expect(page.getByRole("heading", { name: "Endpoints", exact: true, level: 1 })).toBeVisible();
          const endpointTrigger = page.getByRole("button", {
            name: /add remote endpoint|add endpoint|new endpoint/i,
          }).first();
          await tabTo(
            page,
            { role: "button", name: /add remote endpoint|add endpoint|new endpoint/i },
            "remote Endpoint creation trigger",
          );
          await page.keyboard.press("Enter");
          setStage("endpoint-dialog");
          const endpointDialog = page.getByRole("dialog").last();
          await expect(endpointDialog).toBeVisible();
          await tabToWithin(
            page,
            endpointDialog,
            { role: "textbox", name: /endpoint label|label/i },
            "Endpoint label field",
          );
          await page.keyboard.type(ENDPOINT_LABEL);
          await tabToWithin(
            page,
            endpointDialog,
            { role: "textbox", name: /endpoint url|base url|url/i },
            "Endpoint URL field",
          );
          await page.keyboard.type(harness.endpoint.baseUrl);
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
          await tabToWithin(
            page,
            endpointDialog,
            { role: "button", name: /add endpoint|create endpoint|save endpoint/i },
            "Endpoint creation submit",
          );
          setStage("endpoint-submit");
          const endpointResponsePromise = page.waitForResponse(
            (candidate) => candidate.request().method() === "POST"
              && new URL(candidate.url()).pathname === "/v1/endpoints",
          );
          await page.keyboard.press("Enter");
          const endpointResponse = await endpointResponsePromise;
          if (endpointResponse.status() !== 201) {
            throw new ProductBehaviorFailure(
              "ENDPOINT_CREATE_RESPONSE_FAILURE",
              "the public Endpoint create command returned an unexpected status",
              {
                method: "POST",
                path: "/v1/endpoints",
                stage: "endpoint-submit",
                status: endpointResponse.status(),
              },
            );
          }
          setStage("endpoint-post-submit");
          await expect(endpointDialog).toBeHidden({ timeout: 30_000 });
          await assertFocusRestored(page, endpointTrigger, {
            label: "restored Endpoint trigger focus",
            method: "POST",
            path: "/v1/endpoints",
            stage: "endpoint-post-submit",
            status: 201,
          });
          await assertWriteOnlySecretControls(page);
          await assertTextStatus(page, "Endpoint control credential submission");
          await assertNoSecretMarker(page, evidence, "after Endpoint control credential submission");
          assertBrowserStayedOnManagementServer(evidence, harness);
          await recordHistory(page, evidence);

          setStage("provider-navigation");
          await tabTo(page, { name: /^providers$/i }, "Providers navigation");
          setStage("provider-navigation-activate");
          await page.keyboard.press("Enter");
          setStage("provider-navigation-render");
          await expect(page.getByRole("heading", { name: "Providers", exact: true, level: 1 })).toBeVisible();

          setStage("provider-trigger");
          await tabTo(
            page,
            { role: "button", name: /configure provider|add provider/i },
            "provider descriptor configuration trigger",
          );
          const providerTrigger = page.getByRole("button", {
            name: /configure provider|add provider/i,
          }).first();
          await page.keyboard.press("Enter");
          setStage("provider-form-visible");
          const { editor: providerEditor } = await resolveKeyboardEditor(
            page,
            "Configure provider",
            "provider configuration editor",
            providerTrigger,
          );
          setStage("provider-name-field");
          await tabToWithin(
            page,
            providerEditor,
            { role: "textbox", name: /provider name|provider id|name/i },
            "provider name field",
          );
          await page.keyboard.type(PROVIDER_ID);
          setStage("provider-kind-field");
          await tabToWithin(
            page,
            providerEditor,
            { role: "combobox", name: /provider kind|adapter/i },
            "provider kind selector",
          );
          await page.keyboard.type("openai_compatible");
          await expect(
            providerEditor.getByRole("combobox", { name: "Provider kind", exact: true }),
          ).toHaveValue("openai_compatible");
          setStage("provider-base-url-field");
          await tabToWithin(
            page,
            providerEditor,
            { role: "textbox", name: /execution base url|base url/i },
            "provider execution base URL field",
          );
          await page.keyboard.type(`${harness.providerProxy.baseUrl}/v1`);
          setStage("provider-model-field");
          await tabToWithin(
            page,
            providerEditor,
            { role: "textbox", name: /^models?$|model catalog/i },
            "provider model field",
          );
          await page.keyboard.type(PROVIDER_MODEL);
          await tabToWithin(
            page,
            providerEditor,
            { role: "button", name: /save provider|create provider/i },
            "provider descriptor submit",
          );
          setStage("provider-submit");
          const providerResponsePromise = page.waitForResponse(
            (candidate) => candidate.request().method() === "PUT"
              && new URL(candidate.url()).pathname === `/v1/providers/${PROVIDER_ID}`,
          );
          await page.keyboard.press("Enter");
          const providerResponse = await providerResponsePromise;
          if (providerResponse.status() !== 200) {
            throw new ProductBehaviorFailure(
              "PROVIDER_DESCRIPTOR_RESPONSE_FAILURE",
              "the public provider descriptor command returned an unexpected status",
              {
                method: "PUT",
                path: `/v1/providers/${PROVIDER_ID}`,
                stage: "provider-submit",
                status: providerResponse.status(),
              },
            );
          }
          setStage("provider-form-close");
          await expect(providerEditor).toBeHidden({ timeout: 30_000 });
          setStage("provider-focus-restore");
          await assertFocusRestored(page, providerTrigger, {
            label: "restored provider trigger focus",
            method: "PUT",
            path: `/v1/providers/${PROVIDER_ID}`,
            stage: "provider-focus-restore",
            status: 200,
          });
          setStage("provider-status");
          await assertTextStatus(page, "provider descriptor submission");
          setStage("provider-secret-scan");
          await assertNoSecretMarker(page, evidence, "after provider descriptor submission");
          setStage("provider-boundary-check");
          assertBrowserStayedOnManagementServer(evidence, harness);

          setStage("provider-open-cancel");
          await page.keyboard.press("Enter");
          const { editor: providerCancelEditor } = await resolveKeyboardEditor(
            page,
            "Configure provider",
            "provider configuration editor",
            providerTrigger,
          );
          await tabToWithin(
            page,
            providerCancelEditor,
            { role: "button", name: /^cancel$/i },
            "provider configuration cancel",
          );
          setStage("provider-cancel");
          await page.keyboard.press("Enter");
          await expect(providerCancelEditor).toBeHidden();
          setStage("provider-cancel-focus-restore");
          await assertFocusRestored(page, providerTrigger, {
            label: "restored provider trigger focus after cancel",
            stage: "provider-cancel-focus-restore",
          });

          setStage("profile-open-cancel");
          const firstEditor = await openApiKeyEditor(page);
          await tabToWithin(
            page,
            firstEditor.editor,
            { role: "button", name: /^cancel$/i },
            "API-key profile cancel",
          );
          setStage("profile-cancel");
          await page.keyboard.press("Enter");
          await expect(firstEditor.editor).toBeHidden();
          setStage("profile-cancel-focus-restore");
          await assertFocusRestored(page, firstEditor.trigger, {
            label: "restored API-key trigger focus",
            stage: "profile-cancel-focus-restore",
          });

          setStage("profile-open-submit");
          await page.keyboard.press("Enter");
          const { editor: profileEditor } = await resolveKeyboardEditor(
            page,
            "Add API key profile",
            "API-key profile editor",
            firstEditor.trigger,
          );
          const profileTrigger = firstEditor.trigger;
          setStage("profile-create");
          await tabToWithin(
            page,
            profileEditor,
            { role: "textbox", name: /label|profile name/i },
            "profile label field",
          );
          await page.keyboard.type(PROFILE_LABEL);

          await tabToWithin(
            page,
            profileEditor,
            { role: "textbox", name: /api[ -]?key|secret/i },
            "provider API-key field",
          );
          await expect(
            profileEditor.getByRole("textbox", { name: /api[ -]?key|secret/i }).first(),
          ).toHaveAttribute("type", "password");
          await page.keyboard.type(SYNTHETIC_SECRET_MARKER);

          await tabToWithin(
            page,
            profileEditor,
            { role: "checkbox", name: /this machine|built-in|local endpoint|share with|remote endpoint/i },
            "Endpoint distribution target",
          );
          await page.keyboard.press("Space");

          await tabToWithin(
            page,
            profileEditor,
            { role: "button", name: /create|save|add profile/i },
            "API-key profile submit",
          );
          const profilePath = `/v1/providers/${PROVIDER_ID}/auth-profiles`;
          const profileResponsePromise = page.waitForResponse(
            (candidate) => candidate.request().method() === "POST"
              && new URL(candidate.url()).pathname === profilePath,
          );
          await page.keyboard.press("Enter");
          const profileResponse = await profileResponsePromise;
          if (profileResponse.status() !== 201) {
            throw new ProductBehaviorFailure(
              "PROVIDER_PROFILE_RESPONSE_FAILURE",
              "the public API-key profile command returned an unexpected status",
              {
                method: "POST",
                path: profilePath,
                stage: "profile-create",
                status: profileResponse.status(),
              },
            );
          }
          await expect(profileEditor).toBeHidden({ timeout: 30_000 });
          await assertFocusRestored(page, profileTrigger, {
            label: "restored API-key profile trigger focus",
            method: "POST",
            path: profilePath,
            stage: "profile-create",
            status: 201,
          });
          await assertWriteOnlySecretControls(page);
          await assertTextStatus(page, "profile distribution");
          await assertNoSecretMarker(page, evidence, "after API-key profile submission");
          assertBrowserStayedOnManagementServer(evidence, harness);
          await recordHistory(page, evidence);

          setStage("session-create");
          await tabTo(page, { name: /^sessions$/i }, "Sessions navigation");
          await page.keyboard.press("Enter");
          await expect(page.getByRole("heading", { name: "Sessions", exact: true, level: 1 })).toBeVisible();
          await tabTo(
            page,
            { role: "button", name: /new session|create session|start session/i },
            "session creation trigger",
          );
          await page.keyboard.press("Enter");

          const sessionDialog = page.getByRole("dialog").last();
          await expect(sessionDialog).toBeVisible();
          await tabToWithin(
            page,
            sessionDialog,
            { role: "combobox", name: /endpoint|device/i },
            "session Endpoint selector",
          );
          await page.keyboard.type(ENDPOINT_LABEL);
          await page.keyboard.press("Enter");
          await tabToWithin(
            page,
            sessionDialog,
            { role: "combobox", name: /provider/i },
            "session provider selector",
          );
          await page.keyboard.type(PROVIDER_ID);
          await page.keyboard.press("Enter");
          await tabToWithin(
            page,
            sessionDialog,
            { role: "combobox", name: /profile|credential|auth/i },
            "session auth-profile selector",
          );
          await page.keyboard.type(PROFILE_LABEL);
          await page.keyboard.press("Enter");
          await tabToWithin(
            page,
            sessionDialog,
            { role: "combobox", name: /model/i },
            "session model selector",
          );
          await page.keyboard.press("Home");
          await page.keyboard.press("Enter");
          await tabToWithin(
            page,
            sessionDialog,
            { role: "button", name: /create|start session/i },
            "session create submit",
          );
          await page.keyboard.press("Enter");

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
          await attachLiveRegionObserver(page);

          setStage("session-chat");
          await tabTo(
            page,
            { role: "textbox", name: /message|send a message|chat|prompt/i },
            "session composer",
          );
          await page.keyboard.type(
            `Reply with exactly ${EXPECTED_ASSISTANT_TEXT}`,
          );
          await tabTo(
            page,
            { role: "button", name: /send message|send|submit/i },
            "session send button",
          );
          await page.keyboard.press("Enter");

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
        }, { failureRelation: LATER_REPRODUCTION_RELATION });
      },
    );
  },
);
