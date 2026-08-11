import { ServerClientError } from "../api/server";

export type ConnectionState =
  | "Connecting"
  | "Live"
  | "Reconnecting"
  | "Unavailable"
  | "Stopped"
  | "Disconnected";
export type LoadState = "idle" | "loading" | "ready" | "stale" | "error";
export type MutationState = "idle" | "submitting" | "unknown" | "accepted" | "error";
export type NoticeKind = "status" | "error";

export interface NoticeSink {
  set(message: string | null, kind?: NoticeKind): void;
  error(error: unknown): string;
}

export interface CursorStore {
  read(endpointId: string): string;
  write(endpointId: string, cursor: string): void;
}

export interface BrowserNavigationPort {
  readonly path: string;
  push(path: string): void;
  replace(path: string): void;
  assignCurrent(): void;
  back(): void;
  forward(): void;
  onPopState(listener: () => void): () => void;
}

export interface ClockPort {
  setTimeout(operation: () => void, delayMs: number): number;
  clearTimeout(handle: number): void;
}

export function friendlyErrorCode(error: unknown): string {
  return friendlyError(error instanceof ServerClientError ? error.code : "request_failed");
}

export function friendlyError(code: string): string {
  if (/^http_5\d\d$/.test(code)) return "The management Server is unavailable. Try again.";
  const messages: Record<string, string> = {
    endpoint_unavailable:
      "The Endpoint is unavailable. Existing content is not an offline Server copy.",
    auth_replica_unavailable: "The selected profile is not installed on this Endpoint yet.",
    conflict:
      "This action conflicts with an earlier command. Review the current state and try again.",
    operation_conflict: "This action conflicts with an earlier management change.",
    network_error: "The Server could not be reached.",
    request_timeout: "The Server did not respond in time.",
    not_found: "The session could not be found on this Endpoint.",
    route_not_found: "The Endpoint event stream route is unavailable.",
    endpoint_unreachable: "The Endpoint is unreachable; its session state is not authoritative.",
    server_offline: "The management Server is offline.",
    capability_mismatch: "This Endpoint does not support the requested capability.",
    auth_profile_pending: "The selected auth profile is still being installed.",
    auth_profile_stale: "The selected auth profile is stale on this Endpoint.",
    provider_unavailable: "The provider is unavailable.",
    provider_auth_rejected: "The provider rejected the configured auth profile.",
    invalid_request: "Check the selected Endpoint, provider, model, and auth profile.",
    idempotency_conflict: "This action was already admitted with different values.",
    model_attempts_exhausted: "The model could not complete the requested activation.",
    tool_unknown_outcome: "Tool delivery is unknown; reconcile it before retrying.",
    wait_timeout: "The session wait timed out.",
    endpoint_stream_unavailable: "The Endpoint event stream is unavailable.",
  };
  return messages[code] ?? "The request could not be completed.";
}

export function isAccessRequired(error: unknown): boolean {
  return error instanceof ServerClientError && error.status === 401;
}

export function isRetryable(error: unknown): boolean {
  return error instanceof ServerClientError && error.retryable;
}
