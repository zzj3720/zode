type JsonObject = Record<string, unknown>;

export type SystemResponse = {
  schema: "zode.system.v1";
  deployment: "server_only" | "all_in_one";
  local_endpoint_id: string | null;
  ingress: {
    management_auth: "cloudflare_access";
    callback_origin: "separate";
  };
  features: {
    remote_endpoints: boolean;
    provider_auth: boolean;
  };
};

export type Endpoint = {
  endpoint_id: string;
  label: string;
  kind: "local" | "remote";
  status: string;
  disabled: boolean;
  capabilities: {
    providers: string[];
    tools: string[];
    protocol_version: string;
  };
  auth_replica_summary: {
    ready: number;
    pending: number;
    stale: number;
  };
};

export type ProviderDescriptor = {
  revision: number;
  kind: "openai_compatible";
  base_url: string;
  models: string[];
  options: Record<string, unknown>;
};

export type Provider = {
  provider: string;
  descriptor: ProviderDescriptor;
  default_profile_id: string | null;
  auth_status: string;
  auth_profile_count: number;
};

export type Replica = {
  auth_profile_id: string;
  endpoint_id: string;
  revision: number;
  installed_revision: number | null;
  status: string;
};

export type AuthProfile = {
  auth_profile_id: string;
  profile_id: string;
  provider: string;
  kind: "api_key";
  label: string;
  status: string;
  revision: number;
  descriptor_revision: number;
  is_default: boolean;
  sharing: {
    mode: string;
    endpoint_ids: string[];
  };
  distribution: Replica[];
};

export type TranscriptMessage = {
  message_id?: string;
  role: "user" | "assistant" | "tool" | "system";
  content: string;
};

export type Session = {
  schema: "zode.session.v1";
  session_id: string;
  version: number;
  status: string;
  model: {
    provider: string;
    model: string;
    auth_profile_id: string;
  } | null;
  transcript: TranscriptMessage[];
  wait: { reason?: string; deadline_ms?: number } | null;
  tool_calls: Array<{ tool_call_id: string; name?: string; status: string }>;
  active_activation: { activation_id?: string } | null;
};

export type PublicEvent = {
  schema: "zode.event.v1";
  id: string;
  session_id: string;
  version: number;
  kind: string;
  data: Record<string, unknown>;
};

type PublicError = {
  error: {
    code: string;
    message: string;
    retryable: boolean;
  };
};

export class ServerClientError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
  ) {
    super(code);
    this.name = "ServerClientError";
  }
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPublicError(value: unknown): value is PublicError {
  if (!isJsonObject(value) || !isJsonObject(value.error)) return false;
  return (
    typeof value.error.code === "string" &&
    typeof value.error.message === "string" &&
    typeof value.error.retryable === "boolean"
  );
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  } catch {
    throw new ServerClientError("network_error", 0);
  }

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // A typed public error is returned below for a non-JSON response.
  }
  if (!response.ok) {
    const code = isPublicError(body) ? body.error.code : `http_${response.status}`;
    throw new ServerClientError(code, response.status);
  }
  return body as T;
}

function idempotent(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "Idempotency-Key": crypto.randomUUID() },
    body: JSON.stringify(body),
  };
}

export function getSystem(): Promise<SystemResponse> {
  return requestJson<SystemResponse>("/v1/system");
}

export async function listEndpoints(): Promise<Endpoint[]> {
  const response = await requestJson<{ items: Endpoint[] }>("/v1/endpoints");
  return response.items;
}

export function probeEndpoint(endpointId: string): Promise<Endpoint> {
  return requestJson<Endpoint>(`/v1/endpoints/${encodeURIComponent(endpointId)}/probe`, {
    method: "POST",
  });
}

export function createEndpoint(body: {
  label: string;
  baseUrl: string;
  controllerCredential: string;
}): Promise<Endpoint> {
  return requestJson<Endpoint>(
    "/v1/endpoints",
    idempotent("POST", {
      label: body.label,
      base_url: body.baseUrl,
      control_auth: {
        kind: "bearer",
        secret: body.controllerCredential,
      },
    }),
  );
}

export async function listProviders(): Promise<Provider[]> {
  const response = await requestJson<{ providers: Provider[] }>("/v1/providers");
  return response.providers;
}

export function putProvider(
  provider: string,
  descriptor: Omit<ProviderDescriptor, "revision">,
): Promise<unknown> {
  return requestJson(
    `/v1/providers/${encodeURIComponent(provider)}`,
    idempotent("PUT", descriptor),
  );
}

export async function listProfiles(provider: string): Promise<AuthProfile[]> {
  const response = await requestJson<{ items: AuthProfile[] }>(
    `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`,
  );
  return response.items;
}

export function setDefaultProfile(provider: string, profileId: string): Promise<AuthProfile> {
  return requestJson<AuthProfile>(
    `/v1/providers/${encodeURIComponent(provider)}/default-auth-profile`,
    idempotent("PUT", { profile_id: profileId }),
  );
}

export function createApiKeyProfile(
  provider: string,
  body: {
    label: string;
    apiKey: string;
    endpointIds: string[];
    makeDefault: boolean;
  },
): Promise<AuthProfile> {
  return requestJson<AuthProfile>(
    `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`,
    idempotent("POST", {
      kind: "api_key",
      label: body.label,
      api_key: body.apiKey,
      make_default: body.makeDefault,
      sharing:
        body.endpointIds.length > 0
          ? { mode: "selected", endpoint_ids: body.endpointIds }
          : { mode: "none", endpoint_ids: [] },
    }),
  );
}

export async function listReplicas(profileId: string): Promise<Replica[]> {
  const response = await requestJson<{ items: Replica[] }>(
    `/v1/auth-profiles/${encodeURIComponent(profileId)}/replicas`,
  );
  return response.items;
}

export async function listSessions(endpointId: string): Promise<Session[]> {
  const response = await requestJson<{ items: Session[] }>(
    `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions`,
  );
  return response.items;
}

export async function createSession(
  endpointId: string,
  body: {
    provider: Provider;
    model: string;
    profile: AuthProfile;
  },
): Promise<{ session_id: string }> {
  return requestJson(
    `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions`,
    idempotent("POST", {
      model: {
        provider: body.provider.provider,
        model: body.model,
        provider_execution: {
          schema: "zode.provider-execution.v1",
          revision: body.provider.descriptor.revision,
          kind: body.provider.descriptor.kind,
          base_url: body.provider.descriptor.base_url,
          options: body.provider.descriptor.options,
        },
        auth_profile_id: body.profile.auth_profile_id,
        minimum_auth_revision: body.profile.revision,
      },
      tools: [],
    }),
  );
}

export function getSession(endpointId: string, sessionId: string): Promise<Session> {
  return requestJson(
    `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}`,
  );
}

export function sendMessage(
  endpointId: string,
  sessionId: string,
  content: string,
): Promise<unknown> {
  return requestJson(
    `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/messages`,
    idempotent("POST", { content }),
  );
}

export function eventStreamUrl(endpointId: string, sessionId: string): string {
  return `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/events`;
}
