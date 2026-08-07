import { getSystem, ServerClientError, type SystemResponse } from "./api/server";

const appRoot = document.querySelector<HTMLDivElement>("#app");

if (!appRoot) {
  throw new Error("application root is missing");
}

const root: HTMLDivElement = appRoot;

function renderStatus(label: string, detail?: string): void {
  root.replaceChildren();

  const main = document.createElement("main");
  main.setAttribute("aria-live", "polite");

  const heading = document.createElement("h1");
  heading.textContent = label;
  main.append(heading);

  if (detail) {
    const paragraph = document.createElement("p");
    paragraph.textContent = detail;
    main.append(paragraph);
  }

  root.append(main);
}

function renderSystem(system: SystemResponse): void {
  root.replaceChildren();

  const main = document.createElement("main");
  main.setAttribute("aria-live", "polite");

  const heading = document.createElement("h1");
  heading.textContent = "System ready";
  main.append(heading);

  const details = document.createElement("dl");
  const values: Array<[string, string]> = [
    ["Deployment", system.deployment],
    ["Local Endpoint", system.local_endpoint_id ?? "none"],
    ["Remote Endpoints", system.features.remote_endpoints ? "available" : "unavailable"],
    ["Provider auth", system.features.provider_auth ? "available" : "unavailable"],
  ];

  for (const [label, value] of values) {
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = value;
    details.append(term, description);
  }

  main.append(details);
  root.append(main);
}

async function loadSystem(): Promise<void> {
  renderStatus("Loading system");

  try {
    renderSystem(await getSystem());
  } catch (error) {
    const code = error instanceof ServerClientError ? error.code : "network_error";
    renderStatus("System unavailable", code);
  }
}

void loadSystem();
