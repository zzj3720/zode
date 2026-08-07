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

function isSystemResponse(value: unknown): value is SystemResponse {
  if (!isJsonObject(value)) return false;
  if (value.schema !== "zode.system.v1") return false;
  if (value.deployment !== "server_only" && value.deployment !== "all_in_one") return false;
  if (typeof value.local_endpoint_id !== "string" && value.local_endpoint_id !== null) return false;

  const ingress = value.ingress;
  if (!isJsonObject(ingress)) return false;
  if (ingress.management_auth !== "cloudflare_access" || ingress.callback_origin !== "separate") {
    return false;
  }

  const features = value.features;
  return (
    isJsonObject(features) &&
    typeof features.remote_endpoints === "boolean" &&
    typeof features.provider_auth === "boolean"
  );
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function getSystem(): Promise<SystemResponse> {
  let response: Response;

  try {
    response = await fetch("/v1/system", {
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new ServerClientError("network_error", 0);
  }

  const body = await readJson(response);

  if (!response.ok) {
    const code = isPublicError(body) ? body.error.code : `http_${response.status}`;
    throw new ServerClientError(code, response.status);
  }

  if (!isSystemResponse(body)) {
    throw new ServerClientError("invalid_system_response", response.status);
  }

  return body;
}
