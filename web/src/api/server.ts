type JsonObject = Record<string, unknown>;

const REQUEST_TIMEOUT_MS = 10_000;

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
  last_observed_at_ms?: number;
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
  auth_methods: Array<"api_key" | "oauth">;
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

export type ProfileSharingMode = "none" | "selected" | "all_current";

export type AuthProfile = {
  auth_profile_id: string;
  profile_id: string;
  provider: string;
  kind: "api_key" | "oauth";
  label: string;
  status: string;
  revision: number;
  descriptor_revision: number;
  is_default: boolean;
  sharing: {
    mode: ProfileSharingMode;
    endpoint_ids: string[];
  };
  expires_at_ms?: number | null;
  refresh_state: "ready" | "reauth_required";
  allowed_actions: Array<"refresh" | "relogin">;
  distribution: Replica[];
};

export type OAuthAttempt = {
  schema: "zode.oauth-attempt.v1";
  attempt_id: string;
  provider: string;
  auth_profile_id: string;
  profile_id: string;
  replace_auth_profile_id: string | null;
  label: string;
  status: "active" | "succeeded" | "failed" | "cancelled";
  safe_code: string | null;
  sharing: { mode: string; endpoint_ids: string[] };
  make_default: boolean;
  created_at_ms: number;
  updated_at_ms: number;
  expires_at_ms: number;
  allowed_actions: Array<"authorize" | "cancel">;
};

export type AuthRefreshOperation = {
  schema: "zode.auth-refresh-operation.v1";
  operation_id: string;
  auth_profile_id: string;
  provider: string;
  status: "prepared" | "dispatching" | "succeeded" | "refresh_unknown" | "failed";
  safe_code: string | null;
  source_revision: number;
  reserved_revision: number;
  recovery: "same_operation_id_idempotent" | "none";
  created_at_ms: number;
  updated_at_ms: number;
  allowed_actions: Array<"relogin">;
};

export type TranscriptMessage = {
  message_id?: string;
  role: "user" | "assistant" | "tool" | "system" | "runtime";
  content: string;
  tool_call_id?: string | null;
  tool_calls?: Array<{ tool_call_id: string; tool_name: string }>;
};

export type ToolCallProjection = {
  schema?: "zode.tool-call.v1";
  session_id?: string;
  tool_call_id: string;
  tool_name?: string;
  name?: string;
  status: string;
  completion_mode?: string;
  allowed_actions: Array<"cancel" | "retry_dispatch">;
  result?: unknown;
  reconciliation?: {
    reason?: string;
  } | null;
  error?: { class?: string; message?: string } | null;
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
    auth_authority_id?: string;
    auth_revision?: number;
    provider_execution_schema?: string;
    provider_execution_revision?: number;
    provider_execution_kind?: string;
    provider_execution_base_url?: string;
    provider_execution_options?: Record<string, unknown>;
  } | null;
  transcript: TranscriptMessage[];
  wait: { reason?: string; deadline_ms?: number } | null;
  tool_calls: ToolCallProjection[];
  active_activation: { activation_id?: string } | null;
  active_model_round?: {
    attempt?: { attempt_number?: number; outcome?: string } | null;
    retry?: {
      next_attempt_number?: number;
      maximum_attempts?: number;
      error_class?: string;
    } | null;
  } | null;
  last_model_attempts_exhausted?: {
    attempt_number?: number;
    maximum_attempts?: number;
    reason?: string;
  } | null;
};

export type SessionSummary = {
  session_id: string;
  version: number;
  status: string;
  created_at_ms: number;
  updated_at_ms?: number;
  model: Session["model"];
};

export type SessionListPage = {
  schema: "zode.session-list.v1";
  items: SessionSummary[];
  next_cursor: string | null;
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
    public readonly retryable = false,
    message?: string,
  ) {
    super(message ?? code);
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

export type EndpointCreateRequest = {
  label: string;
  baseUrl: string;
  controllerCredential: string;
};

export type ApiKeyProfileCreateRequest = {
  label: string;
  apiKey: string;
  endpointIds: string[];
  makeDefault: boolean;
};

export type OAuthAttemptCreateRequest = {
  label: string;
  endpointIds: string[];
  makeDefault: boolean;
  replaceAuthProfileId?: string;
};

export type SessionExecutionRequest = {
  provider: Provider;
  model: string;
  profile: AuthProfile;
};

export class ServerClient {
  constructor(
    private readonly request: typeof fetch = globalThis.fetch.bind(globalThis),
    private readonly timeoutMs = REQUEST_TIMEOUT_MS,
  ) {}

  private async requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = new Headers(init.headers);
      headers.set("Accept", "application/json");
      if (init.body !== undefined) headers.set("Content-Type", "application/json");
      const response = await this.request(path, {
        ...init,
        headers,
        credentials: "same-origin",
        signal: controller.signal,
      });
      let body: unknown = null;
      try {
        body = await response.json();
      } catch {
        // Non-JSON failures map to the bounded status code below.
      }
      if (!response.ok) {
        if (isPublicError(body)) {
          throw new ServerClientError(
            body.error.code,
            response.status,
            body.error.retryable,
            body.error.message,
          );
        }
        throw new ServerClientError(
          `http_${response.status}`,
          response.status,
          response.status === 408 || response.status === 429 || response.status >= 500,
        );
      }
      return body as T;
    } catch (error) {
      if (error instanceof ServerClientError) throw error;
      throw new ServerClientError(
        controller.signal.aborted ? "request_timeout" : "network_error",
        0,
        true,
      );
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }

  private command(method: string, body: unknown, idempotencyKey: string): RequestInit {
    return {
      method,
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify(body),
    };
  }

  getSystem(): Promise<SystemResponse> {
    return this.requestJson<SystemResponse>("/v1/system");
  }

  async listEndpoints(): Promise<Endpoint[]> {
    const response = await this.requestJson<{ items: Endpoint[] }>("/v1/endpoints");
    return response.items;
  }

  getEndpoint(endpointId: string): Promise<Endpoint> {
    return this.requestJson<Endpoint>(`/v1/endpoints/${encodeURIComponent(endpointId)}`);
  }

  probeEndpoint(endpointId: string): Promise<Endpoint> {
    return this.requestJson<Endpoint>(`/v1/endpoints/${encodeURIComponent(endpointId)}/probe`, {
      method: "POST",
    });
  }

  createEndpoint(body: EndpointCreateRequest, idempotencyKey: string): Promise<Endpoint> {
    return this.requestJson<Endpoint>(
      "/v1/endpoints",
      this.command(
        "POST",
        {
          label: body.label,
          base_url: body.baseUrl,
          control_auth: { kind: "bearer", secret: body.controllerCredential },
        },
        idempotencyKey,
      ),
    );
  }

  async listProviders(): Promise<Provider[]> {
    const response = await this.requestJson<{ providers: Provider[] }>("/v1/providers");
    return response.providers;
  }

  putProvider(
    provider: string,
    descriptor: Omit<ProviderDescriptor, "revision">,
    idempotencyKey: string,
  ): Promise<unknown> {
    return this.requestJson(
      `/v1/providers/${encodeURIComponent(provider)}`,
      this.command("PUT", descriptor, idempotencyKey),
    );
  }

  async listProfiles(provider: string): Promise<AuthProfile[]> {
    const response = await this.requestJson<{ items: AuthProfile[] }>(
      `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`,
    );
    return response.items;
  }

  setDefaultProfile(
    provider: string,
    profileId: string,
    idempotencyKey: string,
  ): Promise<AuthProfile> {
    return this.requestJson<AuthProfile>(
      `/v1/providers/${encodeURIComponent(provider)}/default-auth-profile`,
      this.command("PUT", { profile_id: profileId }, idempotencyKey),
    );
  }

  updateProfileSharing(
    profileId: string,
    sharing: { mode: ProfileSharingMode; endpoint_ids: string[] },
    idempotencyKey: string,
  ): Promise<AuthProfile> {
    return this.requestJson<AuthProfile>(
      `/v1/auth-profiles/${encodeURIComponent(profileId)}/sharing`,
      this.command("PUT", sharing, idempotencyKey),
    );
  }

  deleteProfile(
    provider: string,
    profileId: string,
    idempotencyKey: string,
  ): Promise<{
    auth_profile_id: string;
    provider: string;
    status: string;
    distribution: Replica[];
  }> {
    return this.requestJson(
      `/v1/providers/${encodeURIComponent(provider)}/auth-profiles/${encodeURIComponent(profileId)}`,
      { method: "DELETE", headers: { "Idempotency-Key": idempotencyKey } },
    );
  }

  createApiKeyProfile(
    provider: string,
    body: ApiKeyProfileCreateRequest,
    idempotencyKey: string,
  ): Promise<AuthProfile> {
    return this.requestJson<AuthProfile>(
      `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`,
      this.command(
        "POST",
        {
          kind: "api_key",
          label: body.label,
          api_key: body.apiKey,
          make_default: body.makeDefault,
          sharing:
            body.endpointIds.length > 0
              ? { mode: "selected", endpoint_ids: body.endpointIds }
              : { mode: "none", endpoint_ids: [] },
        },
        idempotencyKey,
      ),
    );
  }

  replaceApiKeyProfile(
    provider: string,
    profileId: string,
    apiKey: string,
    idempotencyKey: string,
  ): Promise<AuthProfile> {
    return this.requestJson<AuthProfile>(
      `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`,
      this.command(
        "POST",
        {
          kind: "api_key",
          api_key: apiKey,
          replace_auth_profile_id: profileId,
        },
        idempotencyKey,
      ),
    );
  }

  startOAuthAttempt(
    provider: string,
    body: OAuthAttemptCreateRequest,
    idempotencyKey: string,
  ): Promise<OAuthAttempt> {
    return this.requestJson<OAuthAttempt>(
      `/v1/providers/${encodeURIComponent(provider)}/auth-attempts`,
      this.command(
        "POST",
        {
          label: body.label,
          make_default: body.makeDefault,
          sharing:
            body.endpointIds.length > 0
              ? { mode: "selected", endpoint_ids: body.endpointIds }
              : { mode: "none", endpoint_ids: [] },
          ...(body.replaceAuthProfileId
            ? { replace_auth_profile_id: body.replaceAuthProfileId }
            : {}),
        },
        idempotencyKey,
      ),
    );
  }

  getOAuthAttempt(attemptId: string): Promise<OAuthAttempt> {
    return this.requestJson<OAuthAttempt>(`/v1/auth-attempts/${encodeURIComponent(attemptId)}`);
  }

  mintOAuthAuthorizeTicket(
    attemptId: string,
    idempotencyKey: string,
  ): Promise<{ schema: "zode.oauth-authorize-ticket.v1"; attempt_id: string; ticket: string }> {
    return this.requestJson(
      `/v1/auth-attempts/${encodeURIComponent(attemptId)}/authorize-tickets`,
      { method: "POST", headers: { "Idempotency-Key": idempotencyKey } },
    );
  }

  cancelOAuthAttempt(attemptId: string, idempotencyKey: string): Promise<OAuthAttempt> {
    return this.requestJson<OAuthAttempt>(
      `/v1/auth-attempts/${encodeURIComponent(attemptId)}/cancel`,
      { method: "POST", headers: { "Idempotency-Key": idempotencyKey } },
    );
  }

  oauthAttemptEvents(
    attemptId: string,
    lastEventId: string,
    signal: AbortSignal,
  ): Promise<Response> {
    return this.controlEvents(
      `/v1/auth-attempts/${encodeURIComponent(attemptId)}/events`,
      lastEventId,
      signal,
    );
  }

  startAuthRefresh(profileId: string, idempotencyKey: string): Promise<AuthRefreshOperation> {
    return this.requestJson<AuthRefreshOperation>(
      `/v1/auth-profiles/${encodeURIComponent(profileId)}/refresh-operations`,
      { method: "POST", headers: { "Idempotency-Key": idempotencyKey } },
    );
  }

  getAuthRefresh(operationId: string): Promise<AuthRefreshOperation> {
    return this.requestJson<AuthRefreshOperation>(
      `/v1/auth-refresh-operations/${encodeURIComponent(operationId)}`,
    );
  }

  authRefreshEvents(
    operationId: string,
    lastEventId: string,
    signal: AbortSignal,
  ): Promise<Response> {
    return this.controlEvents(
      `/v1/auth-refresh-operations/${encodeURIComponent(operationId)}/events`,
      lastEventId,
      signal,
    );
  }

  async listReplicas(profileId: string): Promise<Replica[]> {
    const response = await this.requestJson<{ items: Replica[] }>(
      `/v1/auth-profiles/${encodeURIComponent(profileId)}/replicas`,
    );
    return response.items;
  }

  listSessions(endpointId: string, cursor?: string): Promise<SessionListPage> {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return this.requestJson<SessionListPage>(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions?${query.toString()}`,
    );
  }

  createSession(
    endpointId: string,
    body: SessionExecutionRequest,
    idempotencyKey: string,
  ): Promise<{ session_id: string }> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions`,
      this.command("POST", { model: executionBody(body), tools: [] }, idempotencyKey),
    );
  }

  getSession(endpointId: string, sessionId: string): Promise<Session> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}`,
    );
  }

  selectSessionModel(
    endpointId: string,
    sessionId: string,
    body: SessionExecutionRequest,
    idempotencyKey: string,
  ): Promise<unknown> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/model`,
      this.command("PUT", executionBody(body), idempotencyKey),
    );
  }

  sendMessage(
    endpointId: string,
    sessionId: string,
    content: string,
    idempotencyKey: string,
  ): Promise<unknown> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/messages`,
      this.command("POST", { content }, idempotencyKey),
    );
  }

  getToolCall(
    endpointId: string,
    sessionId: string,
    toolCallId: string,
  ): Promise<ToolCallProjection> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/tool-calls/${encodeURIComponent(toolCallId)}`,
    );
  }

  cancelToolCall(
    endpointId: string,
    sessionId: string,
    toolCallId: string,
    idempotencyKey: string,
  ): Promise<ToolCallProjection> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/tool-calls/${encodeURIComponent(toolCallId)}/cancel`,
      this.command("POST", { reason: "user requested cancellation" }, idempotencyKey),
    );
  }

  reconcileToolCall(
    endpointId: string,
    sessionId: string,
    toolCallId: string,
    idempotencyKey: string,
  ): Promise<ToolCallProjection> {
    return this.requestJson(
      `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/tool-calls/${encodeURIComponent(toolCallId)}/reconcile`,
      this.command("POST", { action: "retry_dispatch" }, idempotencyKey),
    );
  }

  endpointEvents(endpointId: string, lastEventId: string, signal: AbortSignal): Promise<Response> {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (lastEventId) headers["Last-Event-ID"] = lastEventId;
    return this.request(`/v1/endpoints/${encodeURIComponent(endpointId)}/events`, {
      headers,
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  }

  private controlEvents(path: string, lastEventId: string, signal: AbortSignal): Promise<Response> {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (lastEventId) headers["Last-Event-ID"] = lastEventId;
    return this.request(path, {
      headers,
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  }
}

function executionBody(body: SessionExecutionRequest) {
  return {
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
  };
}
