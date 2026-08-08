import "@phosphor-icons/web/regular";
import "./styles.css";

import {
  createApiKeyProfile,
  createEndpoint,
  createSession,
  deleteProfile,
  eventStreamUrl,
  getSession,
  getSystem,
  listEndpoints,
  listProfiles,
  listProviders,
  listSessions,
  putProvider,
  probeEndpoint,
  selectSessionModel,
  setDefaultProfile,
  sendMessage,
  ServerClientError,
  type AuthProfile,
  type Endpoint,
  type Provider,
  type PublicEvent,
  type Session,
  type SystemResponse,
} from "./api/server";

type View = "sessions" | "endpoints" | "providers" | "settings" | "session";
type Panel = "endpoint" | "provider" | "profile" | "session" | null;

const appRoot = document.querySelector<HTMLDivElement>("#app");
if (!appRoot) throw new Error("application root is missing");
const root = appRoot;

const state: {
  system: SystemResponse | null;
  endpoints: Endpoint[];
  providers: Provider[];
  profiles: Map<string, AuthProfile[]>;
  sessions: Map<string, Session[]>;
  sessionErrors: Map<string, string>;
  activeSession: Session | null;
  activeEndpointId: string | null;
  view: View;
  panel: Panel;
  panelProvider: string | null;
  busy: boolean;
  notice: string | null;
  deletingProfile: { profile: AuthProfile; idempotencyKey: string } | null;
  connection: "Connecting" | "Live" | "Reconnecting" | "Disconnected";
} = {
  system: null,
  endpoints: [],
  providers: [],
  profiles: new Map(),
  sessions: new Map(),
  sessionErrors: new Map(),
  activeSession: null,
  activeEndpointId: null,
  view: "sessions",
  panel: null,
  panelProvider: null,
  busy: false,
  notice: null,
  deletingProfile: null,
  connection: "Disconnected",
};

let eventSource: EventSource | null = null;
let eventSourceKey: string | null = null;
let restoreFocusId: string | null = null;

const viewPaths: Record<Exclude<View, "session">, string> = {
  sessions: "/",
  endpoints: "/endpoints",
  providers: "/providers",
  settings: "/settings",
};

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}

function icon(name: string): HTMLElement {
  const value = node("i", `ph ph-${name}`);
  value.setAttribute("aria-hidden", "true");
  return value;
}

function action(
  label: string,
  iconName: string,
  run: () => void | Promise<void>,
  style: "primary" | "quiet" | "danger" = "quiet",
): HTMLButtonElement {
  const button = node("button", `button button-${style}`);
  button.type = "button";
  button.append(icon(iconName), node("span", undefined, label));
  button.addEventListener("click", () => void run());
  return button;
}

function field(labelText: string, control: HTMLElement): HTMLLabelElement {
  const label = node("label", "field");
  label.append(node("span", "field-label", labelText), control);
  return label;
}

function textInput(
  label: string,
  options: { type?: string; placeholder?: string } = {},
): HTMLInputElement {
  const input = node("input", "input");
  input.type = options.type ?? "text";
  input.setAttribute("aria-label", label);
  if (options.type === "password") input.setAttribute("role", "textbox");
  if (options.placeholder) input.placeholder = options.placeholder;
  input.autocomplete = options.type === "password" ? "new-password" : "off";
  return input;
}

function selectInput(
  label: string,
  values: Array<{ value: string; label: string }>,
): HTMLSelectElement {
  const select = node("select", "select");
  select.setAttribute("aria-label", label);
  for (const item of values) {
    const option = node("option", undefined, item.label);
    option.value = item.value;
    select.append(option);
  }
  return select;
}

function setRoute(path: string): void {
  history.pushState(null, "", path);
  void routeFromLocation();
}

function closeEventStream(): void {
  eventSource?.close();
  eventSource = null;
  eventSourceKey = null;
  state.connection = "Disconnected";
}

function navigationItem(
  label: string,
  view: Exclude<View, "session">,
  iconName: string,
): HTMLAnchorElement {
  const selected = state.view === view || (view === "sessions" && state.view === "session");
  const link = node("a", `nav-item${selected ? " is-selected" : ""}`);
  link.href = viewPaths[view];
  if (selected) link.setAttribute("aria-current", "page");
  link.append(icon(iconName), node("span", undefined, label));
  link.addEventListener("click", (event) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    event.preventDefault();
    history.pushState(null, "", viewPaths[view]);
    void routeFromLocation().catch(showError);
  });
  return link;
}

function renderShell(content: HTMLElement, title: string, subtitle?: string): void {
  root.replaceChildren();
  const shell = node("div", "app-shell");
  const sidebar = node("aside", "sidebar");
  const brand = node("div", "brand");
  brand.append(node("span", "brand-name", "Zode"), node("span", "brand-caption", "Durable agents"));
  const navigation = node("nav", "primary-nav");
  navigation.setAttribute("aria-label", "Primary");
  navigation.append(
    navigationItem("Sessions", "sessions", "chats-circle"),
    navigationItem("Endpoints", "endpoints", "devices"),
    navigationItem("Providers", "providers", "key"),
    navigationItem("Settings", "settings", "sliders-horizontal"),
  );
  const sidebarStatus = node("div", "sidebar-status");
  sidebarStatus.append(
    icon(state.system?.deployment === "all_in_one" ? "desktop" : "cloud"),
    node(
      "span",
      undefined,
      state.system?.deployment === "all_in_one" ? "All-in-one ready" : "Server ready",
    ),
  );
  sidebar.append(brand, navigation, sidebarStatus);

  const main = node("main", "main-surface");
  const header = node("header", "main-header");
  const heading = node("div", "header-copy");
  const h1 = node("h1", undefined, title);
  heading.append(h1);
  if (subtitle) heading.append(node("p", undefined, subtitle));
  header.append(heading);
  main.append(header, content);
  shell.append(sidebar, main);
  root.append(shell);
  if (restoreFocusId) {
    const focusId = restoreFocusId;
    restoreFocusId = null;
    queueMicrotask(() => document.getElementById(focusId)?.focus());
  }
}

function notice(): HTMLElement | null {
  if (!state.notice) return null;
  const value = node("div", "notice");
  value.setAttribute("role", "status");
  value.append(icon("info"), node("span", undefined, state.notice));
  return value;
}

function render(): void {
  if (!state.system) {
    const loading = node("section", "center-state");
    loading.setAttribute("aria-live", "polite");
    loading.append(icon("spinner-gap"), node("h1", undefined, "Opening Zode"));
    root.replaceChildren(loading);
    return;
  }
  if (state.view === "providers") renderProviders();
  else if (state.view === "endpoints") renderEndpoints();
  else if (state.view === "settings") renderSettings();
  else if (state.view === "session") renderSession();
  else renderSessions();
}

function renderProviders(): void {
  const page = node("section", "content-page");
  const toolbar = node("div", "page-toolbar");
  toolbar.append(
    node(
      "p",
      "page-intro",
      "Configure execution once, then share write-only profiles to selected Endpoints.",
    ),
    action(
      "Configure provider",
      "plus",
      () => {
        state.panel = "provider";
        state.notice = null;
        render();
      },
      "primary",
    ),
  );
  page.append(toolbar);
  const message = notice();
  if (message) page.append(message);
  if (state.panel === "provider") page.append(providerForm());
  if (state.providers.length === 0) {
    page.append(
      emptyState(
        "key",
        "No providers configured",
        "Add an OpenAI-compatible endpoint to start a session.",
      ),
    );
  }
  for (const provider of state.providers) page.append(providerCard(provider));
  renderShell(page, "Providers", `${state.providers.length} configured`);
}

function providerForm(): HTMLFormElement {
  const form = node("form", "editor-panel");
  const title = node("div", "panel-title");
  title.append(
    node("h2", undefined, "Configure provider"),
    node("p", undefined, "Store only non-secret execution details here."),
  );
  const provider = textInput("Provider ID", { placeholder: "openai-compatible" });
  const kind = selectInput("Provider kind", [
    { value: "openai_compatible", label: "OpenAI compatible" },
  ]);
  const baseUrl = textInput("Base URL", { placeholder: "https://provider.example/v1" });
  const models = textInput("Models", { placeholder: "model-a, model-b" });
  const actions = node("div", "panel-actions");
  actions.append(
    action("Cancel", "x", () => {
      state.panel = null;
      render();
    }),
    submitButton("Save provider"),
  );
  form.append(
    title,
    node("div", "form-grid").appendChild(field("Provider ID", provider)).parentElement!,
  );
  const grid = form.querySelector(".form-grid")!;
  grid.append(field("Provider kind", kind), field("Base URL", baseUrl), field("Models", models));
  form.append(actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await withBusy(async () => {
      const id = provider.value.trim();
      const modelList = models.value
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      await putProvider(id, {
        kind: "openai_compatible",
        base_url: baseUrl.value.trim(),
        models: modelList,
        options: {},
      });
      state.panel = null;
      state.notice = `${id} is ready for an auth profile.`;
      await refreshProviders();
    });
  });
  return form;
}

function providerCard(provider: Provider): HTMLElement {
  const card = node("article", "resource-card");
  const heading = node("div", "resource-heading");
  const copy = node("div");
  copy.append(
    node("h2", undefined, provider.provider),
    node("p", undefined, provider.descriptor.base_url),
  );
  heading.append(copy, statusBadge(provider.auth_status));
  const facts = node("dl", "facts");
  fact(facts, "Adapter", provider.descriptor.kind);
  fact(facts, "Revision", String(provider.descriptor.revision));
  fact(facts, "Models", provider.descriptor.models.join(", "));
  const profiles = state.profiles.get(provider.provider) ?? [];
  const controls = node("div", "resource-actions");
  controls.append(
    action(
      "Add API key profile",
      "key",
      () => {
        state.panel = "profile";
        state.panelProvider = provider.provider;
        state.notice = null;
        render();
      },
      "primary",
    ),
  );
  card.append(heading, facts, controls);
  if (state.panel === "profile" && state.panelProvider === provider.provider) {
    card.append(profileForm(provider));
  }
  if (profiles.length === 0) {
    card.append(node("p", "inline-empty", "No auth profiles yet."));
  } else {
    const list = node("div", "profile-list");
    for (const profile of profiles) list.append(profileRow(profile));
    card.append(list);
  }
  if (state.deletingProfile?.profile.provider === provider.provider) {
    card.append(profileDeleteDialog(state.deletingProfile));
  }
  return card;
}

function profileForm(provider: Provider): HTMLFormElement {
  const form = node("form", "nested-editor");
  form.append(node("h3", undefined, "Add API key profile"));
  const labelInput = textInput("Profile label", { placeholder: "Production key" });
  const apiKey = textInput("API key", { type: "password" });
  const defaultRow = node("label", "checkbox-row");
  const defaultCheckbox = node("input") as HTMLInputElement;
  defaultCheckbox.type = "checkbox";
  defaultCheckbox.checked = true;
  defaultCheckbox.setAttribute("aria-label", "Make this the default profile");
  defaultRow.append(defaultCheckbox, node("span", undefined, "Make this the default profile"));
  const targets = node("fieldset", "endpoint-choices");
  const legend = node("legend", undefined, "Share with Endpoints");
  targets.append(legend);
  for (const endpoint of state.endpoints) {
    const row = node("label", "checkbox-row");
    const checkbox = node("input");
    checkbox.type = "checkbox";
    checkbox.value = endpoint.endpoint_id;
    checkbox.setAttribute(
      "aria-label",
      endpoint.kind === "local" ? "Share with this machine" : `Share with ${endpoint.label}`,
    );
    row.append(
      checkbox,
      node("span", undefined, endpoint.kind === "local" ? "This machine" : endpoint.label),
    );
    targets.append(row);
  }
  const actions = node("div", "panel-actions");
  actions.append(
    action("Cancel", "x", () => {
      apiKey.value = "";
      state.panel = null;
      render();
    }),
    submitButton("Create profile"),
  );
  form.append(
    node("div", "form-grid").appendChild(field("Profile label", labelInput)).parentElement!,
  );
  const grid = form.querySelector(".form-grid")!;
  grid.append(field("API key", apiKey));
  form.append(defaultRow, targets, actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const endpointIds = Array.from(
      targets.querySelectorAll<HTMLInputElement>('input[type="checkbox"]:checked'),
    ).map((input) => input.value);
    const secret = apiKey.value;
    apiKey.value = "";
    await withBusy(async () => {
      await createApiKeyProfile(provider.provider, {
        label: labelInput.value.trim(),
        apiKey: secret,
        endpointIds,
        makeDefault: defaultCheckbox.checked,
      });
      state.panel = null;
      state.notice =
        endpointIds.length > 0
          ? "Profile installed on the selected Endpoint."
          : "Profile saved without Endpoint sharing.";
      await refreshProviders();
    });
  });
  return form;
}

function profileRow(profile: AuthProfile): HTMLElement {
  const row = node("div", "profile-row");
  const copy = node("div");
  copy.append(
    node("strong", undefined, profile.label),
    node("span", undefined, `${profile.kind.replace("_", " ")} · revision ${profile.revision}`),
  );
  const targets = profile.sharing.endpoint_ids
    .map((id) => state.endpoints.find((endpoint) => endpoint.endpoint_id === id)?.label ?? id)
    .join(", ");
  const controls = node("div", "profile-actions");
  if (!profile.is_default) {
    const makeDefault = action("Set as default", "star", async () => {
      await withBusy(async () => {
        await setDefaultProfile(profile.provider, profile.profile_id);
        state.notice = `${profile.label} is now the default profile.`;
        await refreshProviders();
      });
    });
    makeDefault.disabled = state.busy;
    controls.append(makeDefault);
  }
  const remove = action("Delete profile", "trash", () => {
    state.deletingProfile = { profile, idempotencyKey: crypto.randomUUID() };
    state.notice = null;
    render();
  });
  remove.disabled = state.busy;
  controls.append(remove);
  row.append(
    copy,
    node("span", "profile-default", profile.is_default ? "Default profile" : "Not default"),
    node("span", "profile-targets", targets || "Not shared"),
    statusBadge(profile.status),
    controls,
  );
  return row;
}

function profileDeleteDialog(entry: { profile: AuthProfile; idempotencyKey: string }): HTMLElement {
  const profile = entry.profile;
  const dialog = node("section", "dialog-panel");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-label", "Delete profile");
  const title = node("div", "panel-title");
  title.append(
    node("h2", undefined, "Delete profile"),
    node(
      "p",
      undefined,
      "Removing the copied API key from an Endpoint is best-effort; complete provider-side revocation may require key rotation.",
    ),
  );
  const acknowledgement = node("label", "checkbox-row");
  const checkbox = node("input") as HTMLInputElement;
  checkbox.type = "checkbox";
  checkbox.setAttribute("aria-label", "I understand the revocation warning");
  acknowledgement.append(
    checkbox,
    node("span", undefined, "I understand that provider-side revocation may require key rotation."),
  );
  const actions = node("div", "panel-actions");
  const cancel = action("Cancel", "x", () => {
    state.deletingProfile = null;
    render();
  });
  const confirm = action("Delete profile permanently", "trash", async () => {
    await withBusy(async () => {
      const result = await deleteProfile(
        profile.provider,
        profile.profile_id,
        entry.idempotencyKey,
      );
      state.deletingProfile = null;
      state.notice =
        result.status === "deleted"
          ? `${profile.label} was deleted and Endpoint revocation was acknowledged.`
          : `${profile.label} was deleted; Endpoint revocation is still pending.`;
      await refreshProviders();
    });
  });
  confirm.disabled = true;
  checkbox.addEventListener("change", () => {
    confirm.disabled = !checkbox.checked || state.busy;
  });
  actions.append(cancel, confirm);
  dialog.append(title, acknowledgement, actions);
  return dialog;
}

function renderEndpoints(): void {
  const page = node("section", "content-page");
  const toolbar = node("div", "page-toolbar");
  const trigger = action(
    "Add remote Endpoint",
    "plus",
    () => {
      state.panel = "endpoint";
      state.notice = null;
      render();
    },
    "primary",
  );
  trigger.id = "add-remote-endpoint";
  toolbar.append(
    node(
      "p",
      "page-intro",
      "Connect a remote device through its reachable Endpoint URL and write-only controller credential.",
    ),
    trigger,
  );
  page.append(toolbar);
  const message = notice();
  if (message) page.append(message);
  if (state.panel === "endpoint") page.append(endpointDialog());
  if (state.endpoints.length === 0) {
    page.append(
      emptyState("devices", "No Endpoints", "Connect a device before creating a session."),
    );
  }
  for (const endpoint of state.endpoints) {
    const card = node("article", "resource-card");
    const heading = node("div", "resource-heading");
    const copy = node("div");
    copy.append(
      node("h2", undefined, endpoint.label),
      node(
        "p",
        undefined,
        endpoint.kind === "local" ? "Built-in local Endpoint" : "Remote Endpoint",
      ),
    );
    heading.append(copy, statusBadge(endpoint.status));
    const facts = node("dl", "facts");
    fact(facts, "Protocol", endpoint.capabilities.protocol_version);
    fact(facts, "Providers", endpoint.capabilities.providers.join(", ") || "None");
    fact(facts, "Tools", endpoint.capabilities.tools.join(", ") || "None");
    const actions = node("div", "card-actions");
    actions.append(
      action("Refresh Endpoint status", "arrows-clockwise", async () => {
        await withBusy(async () => {
          try {
            const observed = await probeEndpoint(endpoint.endpoint_id);
            state.endpoints = state.endpoints.map((item) =>
              item.endpoint_id === observed.endpoint_id ? observed : item,
            );
            state.notice = `${endpoint.label} is reachable.`;
          } catch (error) {
            if (error instanceof ServerClientError && error.code === "endpoint_unavailable") {
              state.endpoints = state.endpoints.map((item) =>
                item.endpoint_id === endpoint.endpoint_id
                  ? { ...item, status: "unreachable" }
                  : item,
              );
              state.notice = "Endpoint unavailable; state is non-authoritative.";
              return;
            }
            throw error;
          }
        });
      }),
    );
    card.append(heading, facts, actions);
    page.append(card);
  }
  renderShell(page, "Endpoints", `${state.endpoints.length} available`);
}

function endpointDialog(): HTMLElement {
  const dialog = node("section", "dialog-panel");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-label", "Add remote Endpoint");
  const form = node("form", "editor-panel");
  const title = node("div", "panel-title");
  title.append(
    node("h2", undefined, "Add remote Endpoint"),
    node("p", undefined, "The credential is sent once and is never rendered back."),
  );
  const label = textInput("Endpoint label", { placeholder: "Studio machine" });
  const baseUrl = textInput("Endpoint URL", { placeholder: "https://device.example" });
  const credential = textInput("Controller credential", { type: "password" });
  const grid = node("div", "form-grid");
  grid.append(
    field("Endpoint label", label),
    field("Endpoint URL", baseUrl),
    field("Controller credential", credential),
  );
  const actions = node("div", "panel-actions");
  actions.append(
    action("Cancel", "x", () => {
      credential.value = "";
      state.panel = null;
      restoreFocusId = "add-remote-endpoint";
      render();
    }),
    submitButton("Add Endpoint"),
  );
  form.append(title, grid, actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const request = {
      label: label.value.trim(),
      baseUrl: baseUrl.value.trim(),
      controllerCredential: credential.value,
    };
    credential.value = "";
    await withBusy(async () => {
      await createEndpoint(request);
      state.endpoints = await listEndpoints();
      state.panel = null;
      state.notice = `${request.label} is connected.`;
      restoreFocusId = "add-remote-endpoint";
    });
  });
  dialog.append(form);
  return dialog;
}

function renderSessions(): void {
  const page = node("section", "content-page");
  const toolbar = node("div", "page-toolbar");
  const allEndpointsUnavailable =
    state.endpoints.length > 0 &&
    state.endpoints.every((endpoint) => state.sessionErrors.has(endpoint.endpoint_id));
  const newSession = action(
    "New session",
    "plus",
    () => {
      state.panel = "session";
      state.notice = null;
      render();
    },
    "primary",
  );
  newSession.disabled = allEndpointsUnavailable;
  toolbar.append(
    node(
      "p",
      "page-intro",
      "Sessions stay on their creating Endpoint and stream durable state here.",
    ),
    newSession,
  );
  page.append(toolbar);
  const message = notice();
  if (message) page.append(message);
  if (state.panel === "session") page.append(sessionForm());
  let count = 0;
  let hasUnavailableEndpoint = false;
  for (const endpoint of state.endpoints) {
    const sessions = state.sessions.get(endpoint.endpoint_id) ?? [];
    const errorCode = state.sessionErrors.get(endpoint.endpoint_id);
    if (errorCode) hasUnavailableEndpoint = true;
    count += sessions.length;
    if (sessions.length === 0 && !errorCode) continue;
    const group = node("section", "session-group");
    group.append(
      node("h2", undefined, endpoint.kind === "local" ? "This machine" : endpoint.label),
    );
    if (errorCode) {
      group.append(
        emptyState(
          "warning",
          "Endpoint unavailable",
          "Session history is non-authoritative until the Endpoint reconnects.",
        ),
      );
    }
    for (const session of sessions) {
      const row = node("a", "session-row");
      row.href = `/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions/${encodeURIComponent(session.session_id)}`;
      const main = node("span", "session-row-main");
      main.append(
        node("span", undefined, session.model?.model ?? "Unconfigured session"),
        node("span", "session-row-id", session.session_id),
      );
      row.append(icon("chat-circle"), main, node("span", "session-row-state", session.status));
      row.addEventListener("click", (event) => {
        if (
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey
        ) {
          return;
        }
        event.preventDefault();
        setRoute(row.getAttribute("href")!);
      });
      group.append(row);
    }
    page.append(group);
  }
  if (count === 0 && !hasUnavailableEndpoint && state.panel !== "session") {
    page.append(
      emptyState(
        "chats-circle",
        "No sessions yet",
        "Choose an Endpoint, provider, model, and profile to begin.",
      ),
    );
  }
  renderShell(page, "Sessions", `${count} available`);
}

function sessionForm(): HTMLFormElement {
  const form = node("form", "editor-panel");
  const title = node("div", "panel-title");
  title.append(
    node("h2", undefined, "New session"),
    node("p", undefined, "The selected Endpoint will own this session."),
  );
  const endpoint = selectInput(
    "Endpoint",
    state.endpoints.map((item) => ({
      value: item.endpoint_id,
      label: item.kind === "local" ? "This machine" : item.label,
    })),
  );
  const provider = selectInput(
    "Provider",
    state.providers.map((item) => ({ value: item.provider, label: item.provider })),
  );
  const model = selectInput("Model", []);
  const profile = selectInput("Auth profile", []);
  const profileHint = node("p", "inline-empty");
  profileHint.hidden = true;
  let submit: HTMLButtonElement | undefined;
  const updateChoices = (): void => {
    const current = state.providers.find((item) => item.provider === provider.value);
    model.replaceChildren(
      ...(current?.descriptor.models ?? []).map((value) => {
        const option = node("option", undefined, value);
        option.value = value;
        return option;
      }),
    );
    const availableProfiles = (state.profiles.get(provider.value) ?? []).filter(
      (item) =>
        item.status === "ready" &&
        item.sharing.mode === "selected" &&
        item.sharing.endpoint_ids.includes(endpoint.value),
    );
    profile.replaceChildren(
      ...availableProfiles.map((item) => {
        const option = node("option", undefined, item.label);
        option.value = item.profile_id;
        option.selected = item.is_default;
        return option;
      }),
    );
    profileHint.hidden = availableProfiles.length > 0;
    profileHint.textContent =
      availableProfiles.length > 0 ? "" : "No shared profile is available for this Endpoint.";
    if (submit) {
      submit.disabled =
        state.busy || availableProfiles.length === 0 || state.sessionErrors.has(endpoint.value);
    }
  };
  provider.addEventListener("change", updateChoices);
  endpoint.addEventListener("change", updateChoices);
  const grid = node("div", "form-grid");
  grid.append(
    field("Endpoint", endpoint),
    field("Provider", provider),
    field("Model", model),
    field("Auth profile", profile),
  );
  const actions = node("div", "panel-actions");
  submit = submitButton("Start session");
  actions.append(
    action("Cancel", "x", () => {
      state.panel = null;
      render();
    }),
    submit,
  );
  form.append(title, grid, actions);
  form.insertBefore(profileHint, actions);
  updateChoices();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await withBusy(async () => {
      const selectedProvider = state.providers.find((item) => item.provider === provider.value);
      const selectedProfile = (state.profiles.get(provider.value) ?? []).find(
        (item) => item.profile_id === profile.value,
      );
      if (!selectedProvider || !selectedProfile) throw new Error("session selection is incomplete");
      let created: { session_id: string };
      try {
        created = await createSession(endpoint.value, {
          provider: selectedProvider,
          model: model.value,
          profile: selectedProfile,
        });
      } catch (error) {
        if (!(error instanceof ServerClientError) || error.code !== "invalid_request") {
          throw error;
        }

        // The request body is intentionally frozen for this admission. A
        // concurrent provider update can make that concrete selection stale;
        // refresh only after the failed admission and keep the form open so
        // the user can review the newly authoritative descriptor/profile.
        await refreshProviders();
        const latestProvider = state.providers.find(
          (item) => item.provider === selectedProvider.provider,
        );
        if (
          !latestProvider ||
          latestProvider.descriptor.revision <= selectedProvider.descriptor.revision
        ) {
          throw error;
        }
        state.panel = "session";
        state.notice =
          "The provider configuration changed while this form was open. The latest selection is loaded; review it and try again.";
        return;
      }
      state.panel = null;
      history.pushState(null, "", `/endpoints/${endpoint.value}/sessions/${created.session_id}`);
      await openSession(endpoint.value, created.session_id);
    });
  });
  return form;
}

function renderSession(): void {
  const session = state.activeSession;
  const endpoint = state.endpoints.find((item) => item.endpoint_id === state.activeEndpointId);
  const workspace = node("section", "session-workspace");
  if (!session || !endpoint) {
    workspace.append(
      emptyState("warning", "Session unavailable", "The Endpoint could not provide this session."),
    );
    renderShell(workspace, "Session");
    return;
  }
  const meta = node("div", "session-meta");
  meta.append(
    statusBadge(state.connection),
    node("span", undefined, endpoint.kind === "local" ? "This machine" : endpoint.label),
    node(
      "span",
      undefined,
      session.model ? `${session.model.provider} · ${session.model.model}` : "No model",
    ),
  );
  workspace.append(meta);
  const message = notice();
  if (message) workspace.append(message);
  const transcript = node("div", "transcript");
  transcript.setAttribute("aria-live", "polite");
  if (session.transcript.length === 0) {
    transcript.append(
      emptyState(
        "chat-circle",
        "Ready when you are",
        "Send a message to start this durable session.",
      ),
    );
  }
  for (const message of session.transcript) {
    const article = node("article", `message message-${message.role}`);
    article.append(
      node(
        "span",
        "message-role",
        message.role === "assistant" ? "Agent" : message.role === "user" ? "You" : message.role,
      ),
      node("p", undefined, message.content),
    );
    transcript.append(article);
  }
  workspace.append(
    transcript,
    runtimeActivity(session),
    sessionExecutionRecovery(endpoint, session),
    composer(endpoint.endpoint_id, session.session_id),
  );
  renderShell(
    workspace,
    session.model?.model ?? "Session",
    `${endpoint.label} · ${session.status}`,
  );
}

function sessionExecutionRecovery(endpoint: Endpoint, session: Session): HTMLFormElement {
  const form = node("form", "editor-panel session-execution-recovery");
  const title = node("div", "panel-title");
  title.append(
    node("h2", undefined, "Recover session execution"),
    node(
      "p",
      undefined,
      "Keep this Endpoint-owned session and history, then choose a current provider, model, and profile for the next activation.",
    ),
  );
  const endpointLabel = node("p", "selection-fact", `Endpoint: ${endpoint.label}`);
  const provider = selectInput(
    "Provider",
    state.providers.map((item) => ({ value: item.provider, label: item.provider })),
  );
  const model = selectInput("Model", []);
  const profile = selectInput("Auth profile", []);
  const profileHint = node("p", "inline-empty");
  let submit: HTMLButtonElement | undefined;
  let preferredModel = session.model?.model;
  let preferredProfileId = session.model?.auth_profile_id;

  const updateChoices = (): void => {
    const current = state.providers.find((item) => item.provider === provider.value);
    const models = current?.descriptor.models ?? [];
    const selectedModel =
      preferredModel && models.includes(preferredModel) ? preferredModel : models[0];
    model.replaceChildren(
      ...models.map((value) => {
        const option = node("option", undefined, value);
        option.value = value;
        option.selected = value === selectedModel;
        return option;
      }),
    );
    const availableProfiles = (state.profiles.get(provider.value) ?? []).filter(
      (item) =>
        item.status === "ready" &&
        item.sharing.mode === "selected" &&
        item.sharing.endpoint_ids.includes(endpoint.endpoint_id),
    );
    const selectedProfile =
      availableProfiles.find((item) => item.profile_id === preferredProfileId) ??
      availableProfiles.find((item) => item.is_default) ??
      availableProfiles[0];
    profile.replaceChildren(
      ...availableProfiles.map((item) => {
        const option = node("option", undefined, item.label);
        option.value = item.profile_id;
        option.selected = item.profile_id === selectedProfile?.profile_id;
        return option;
      }),
    );
    profileHint.hidden = availableProfiles.length > 0;
    profileHint.textContent =
      availableProfiles.length > 0
        ? ""
        : "No current shared profile is available for this Endpoint.";
    if (submit) {
      submit.disabled = state.busy || models.length === 0 || availableProfiles.length === 0;
    }
  };
  provider.addEventListener("change", () => {
    preferredModel = undefined;
    preferredProfileId = undefined;
    updateChoices();
  });
  endpointLabel.setAttribute("aria-label", "Selected Endpoint");
  const grid = node("div", "form-grid");
  grid.append(field("Provider", provider), field("Model", model), field("Auth profile", profile));
  const actions = node("div", "panel-actions");
  submit = submitButton("Apply execution", "arrows-clockwise");
  actions.append(submit);
  form.append(title, endpointLabel, grid, profileHint, actions);
  updateChoices();
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void withBusy(async () => {
      const selectedProvider = state.providers.find((item) => item.provider === provider.value);
      const selectedProfile = (state.profiles.get(provider.value) ?? []).find(
        (item) => item.profile_id === profile.value,
      );
      if (!selectedProvider || !selectedProfile || !model.value) {
        throw new ServerClientError("invalid_request", 422);
      }
      await selectSessionModel(endpoint.endpoint_id, session.session_id, {
        provider: selectedProvider,
        model: model.value,
        profile: selectedProfile,
      });
      state.notice = "Session execution updated. Existing history was preserved.";
      await loadActiveSession();
    });
  });
  return form;
}

function runtimeActivity(session: Session): HTMLElement {
  const activity = node("aside", "runtime-activity");
  activity.setAttribute("aria-label", "Runtime activity");
  if (session.wait) {
    activity.append(
      statusLine("clock", "Waiting", session.wait.reason ?? "Awaiting an external result"),
    );
  }
  for (const tool of session.tool_calls ?? []) {
    activity.append(statusLine("wrench", tool.name ?? "Tool", tool.status.replaceAll("_", " ")));
  }
  if (session.active_activation) {
    activity.append(statusLine("spinner-gap", "Working", "Model activation in progress"));
  }
  if (!session.wait && (session.tool_calls?.length ?? 0) === 0 && !session.active_activation) {
    activity.append(statusLine("check-circle", "Up to date", "Durable events are connected"));
  }
  return activity;
}

function composer(endpointId: string, sessionId: string): HTMLFormElement {
  const form = node("form", "composer");
  const input = node("textarea", "composer-input");
  input.rows = 2;
  input.placeholder = "Message Zode";
  input.setAttribute("aria-label", "Message");
  const footer = node("div", "composer-footer");
  footer.append(
    node(
      "span",
      "composer-hint",
      state.busy ? "Submitting…" : "Enter to send · Shift+Enter for a new line",
    ),
    submitButton("Send", "arrow-up"),
  );
  form.append(input, footer);
  const submit = async (): Promise<void> => {
    const content = input.value.trim();
    if (!content || state.busy) return;
    await withBusy(async () => {
      await sendMessage(endpointId, sessionId, content);
      input.value = "";
      state.notice = "Message accepted; waiting for durable completion.";
      await loadActiveSession();
    });
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit();
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      form.requestSubmit();
    }
  });
  return form;
}

function renderSettings(): void {
  const page = node("section", "content-page");
  const card = node("article", "resource-card");
  card.append(node("h2", undefined, "Deployment"));
  const facts = node("dl", "facts");
  fact(facts, "Mode", state.system?.deployment ?? "Unavailable");
  fact(facts, "Management admission", "Cloudflare Access");
  fact(facts, "Local Endpoint", state.system?.local_endpoint_id ? "Available" : "Not configured");
  card.append(facts);
  page.append(card);
  renderShell(page, "Settings", "Safe deployment details");
}

function emptyState(iconName: string, title: string, detail: string): HTMLElement {
  const value = node("div", "empty-state");
  value.append(icon(iconName), node("h2", undefined, title), node("p", undefined, detail));
  return value;
}

function statusBadge(value: string): HTMLElement {
  const badge = node(
    "span",
    `status-badge status-${value.toLowerCase().replaceAll(" ", "-")}`,
    value,
  );
  return badge;
}

function statusLine(iconName: string, title: string, detail: string): HTMLElement {
  const line = node("div", "status-line");
  const copy = node("div");
  copy.append(node("strong", undefined, title), node("span", undefined, detail));
  line.append(icon(iconName), copy);
  return line;
}

function fact(list: HTMLDListElement, label: string, value: string): void {
  list.append(node("dt", undefined, label), node("dd", undefined, value));
}

function submitButton(label: string, iconName = "check"): HTMLButtonElement {
  const button = node("button", "button button-primary");
  button.type = "submit";
  button.disabled = state.busy;
  button.append(icon(iconName), node("span", undefined, label));
  return button;
}

async function refreshProviders(): Promise<void> {
  state.providers = await listProviders();
  const profiles = await Promise.all(
    state.providers.map(
      async (provider) => [provider.provider, await listProfiles(provider.provider)] as const,
    ),
  );
  state.profiles = new Map(profiles);
}

async function refreshSessions(): Promise<void> {
  const nextSessions = new Map<string, Session[]>();
  const nextErrors = new Map<string, string>();
  let nextNotice: string | null = null;
  const sessions = await Promise.all(
    state.endpoints.map(async (endpoint) => {
      try {
        return [endpoint.endpoint_id, await listSessions(endpoint.endpoint_id)] as const;
      } catch (error) {
        const code = error instanceof ServerClientError ? error.code : "network_error";
        if (error instanceof ServerClientError && error.status === 401) throw error;
        if (code === "endpoint_unavailable") {
          nextErrors.set(endpoint.endpoint_id, code);
        } else if (!nextNotice) {
          nextNotice =
            code === "network_error"
              ? "Server unavailable. Session history is not authoritative."
              : "The Server could not load session history. Try again when it is available.";
        }
        return [endpoint.endpoint_id, state.sessions.get(endpoint.endpoint_id) ?? []] as const;
      }
    }),
  );
  for (const [endpointId, endpointSessions] of sessions)
    nextSessions.set(endpointId, endpointSessions);
  state.sessions = nextSessions;
  state.sessionErrors = nextErrors;
  state.notice = nextNotice;
}

async function openSession(endpointId: string, sessionId: string): Promise<void> {
  state.activeEndpointId = endpointId;
  state.activeSession = await getSession(endpointId, sessionId);
  state.view = "session";
  state.notice = null;
  connectEventStream(endpointId, sessionId);
  render();
}

async function loadActiveSession(): Promise<void> {
  if (!state.activeEndpointId || !state.activeSession) return;
  state.activeSession = await getSession(state.activeEndpointId, state.activeSession.session_id);
  render();
}

function connectEventStream(endpointId: string, sessionId: string): void {
  const key = `${endpointId}:${sessionId}`;
  if (eventSourceKey === key && eventSource) return;
  closeEventStream();
  state.connection = "Connecting";
  const stream = new EventSource(eventStreamUrl(endpointId, sessionId), { withCredentials: true });
  eventSource = stream;
  eventSourceKey = key;
  stream.onopen = () => {
    state.connection = "Live";
    render();
  };
  stream.onerror = () => {
    state.connection = "Reconnecting";
    render();
  };
  const kinds = [
    "assistant_message_committed",
    "message_appended",
    "status_changed",
    "activation_started",
    "activation_finished",
    "wait_set",
    "wait_cleared",
    "wait_expired",
    "async_tool_call_started",
    "async_tool_call_running",
    "async_tool_call_completed",
    "async_tool_call_failed",
    "async_tool_call_unknown_outcome",
  ];
  for (const kind of kinds) {
    stream.addEventListener(kind, (event) => {
      const message = event as MessageEvent<string>;
      try {
        const payload = JSON.parse(message.data) as PublicEvent;
        if (payload.session_id !== sessionId) return;
        void loadActiveSession().catch(showError);
      } catch {
        state.notice = "A durable event could not be read.";
        render();
      }
    });
  }
}

async function routeFromLocation(): Promise<void> {
  const match = /^\/endpoints\/([^/]+)\/sessions\/([^/]+)$/.exec(location.pathname);
  if (match) {
    await openSession(decodeURIComponent(match[1]), decodeURIComponent(match[2]));
    return;
  }
  closeEventStream();
  state.panel = null;
  state.notice = null;
  if (location.pathname === "/endpoints") state.view = "endpoints";
  else if (location.pathname === "/providers") state.view = "providers";
  else if (location.pathname === "/settings") state.view = "settings";
  else state.view = "sessions";
  if (state.view === "providers") await refreshProviders();
  else if (state.view === "sessions") await refreshSessions();
  render();
}

async function withBusy(operation: () => Promise<void>): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.notice = null;
  render();
  try {
    await operation();
  } catch (error) {
    showError(error);
  } finally {
    state.busy = false;
    render();
  }
}

function showError(error: unknown): void {
  if (error instanceof ServerClientError && error.status === 401) {
    location.assign(location.href);
    return;
  }
  const code = error instanceof ServerClientError ? error.code : "request_failed";
  state.notice = friendlyError(code);
  render();
}

function friendlyError(code: string): string {
  const messages: Record<string, string> = {
    endpoint_unavailable:
      "The Endpoint is unavailable. Existing content is not an offline Server copy.",
    auth_replica_unavailable: "The selected profile is not installed on this Endpoint yet.",
    conflict:
      "This action conflicts with an earlier command. Review the current state and try again.",
    operation_conflict: "This action conflicts with an earlier management change.",
    network_error: "The Server could not be reached.",
    invalid_request: "Check the requested values and try again.",
  };
  return messages[code] ?? "The request could not be completed.";
}

async function initialize(): Promise<void> {
  render();
  try {
    const [system, endpoints, providers] = await Promise.all([
      getSystem(),
      listEndpoints(),
      listProviders(),
    ]);
    state.system = system;
    state.endpoints = endpoints;
    state.providers = providers;
    await refreshProviders();
    await refreshSessions();
    await routeFromLocation();
  } catch (error) {
    state.system = {
      schema: "zode.system.v1",
      deployment: "server_only",
      local_endpoint_id: null,
      ingress: { management_auth: "cloudflare_access", callback_origin: "separate" },
      features: { remote_endpoints: true, provider_auth: true },
    };
    showError(error);
  }
}

window.addEventListener("popstate", () => void routeFromLocation().catch(showError));
void initialize();
