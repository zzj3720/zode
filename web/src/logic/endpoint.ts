import { batch, computed, signal, type ReadonlySignal, type Signal } from "@preact/signals-core";

import {
  ServerClient,
  ServerClientError,
  type Endpoint as EndpointDto,
  type PublicEvent,
  type SessionSummary,
} from "../api/server";
import {
  friendlyErrorCode,
  isAccessRequired,
  type ClockPort,
  type ConnectionState,
  type CursorStore,
  type LoadState,
  type MutationState,
  type NoticeSink,
} from "./ports";
import { Session, type SessionServices } from "./session";

export type EndpointSnapshot = Readonly<EndpointDto>;
type Command<T> = { key: string; body: T; state: MutationState };
const EVENT_STREAM_IDLE_TIMEOUT_MS = 20_000;

export class Endpoint {
  private readonly dataSignal: Signal<EndpointSnapshot>;
  private readonly sessionsSignal = signal<readonly Session[]>([]);
  private readonly sessionsStateSignal = signal<LoadState>("idle");
  private readonly sessionsErrorSignal = signal<string | null>(null);
  private readonly mutationSignal = signal<MutationState>("idle");
  private readonly connectionSignal = signal<ConnectionState>("Stopped");
  private readonly streamErrorSignal = signal<string | null>(null);
  private readonly sessionRegistry = new Map<string, Session>();
  private sessionsGeneration = 0;
  private streamGeneration = 0;
  private streamController: AbortController | null = null;
  private reconnectTimer: number | null = null;
  private reconnectAttempt = 0;
  private streamEnabled = false;

  readonly data: ReadonlySignal<EndpointSnapshot>;
  readonly environmentLabel: ReadonlySignal<string>;
  readonly sessions: ReadonlySignal<readonly Session[]> = this.sessionsSignal;
  readonly sessionsState: ReadonlySignal<LoadState> = this.sessionsStateSignal;
  readonly sessionsError: ReadonlySignal<string | null> = this.sessionsErrorSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly connection: ReadonlySignal<ConnectionState> = this.connectionSignal;
  readonly streamError: ReadonlySignal<string | null> = this.streamErrorSignal;
  readonly commandAvailable: ReadonlySignal<boolean>;

  constructor(
    initial: EndpointDto,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly cursor: CursorStore,
    private readonly clock: ClockPort,
    sessionServices: Omit<SessionServices, "refreshSessionList">,
  ) {
    this.dataSignal = signal(initial);
    this.data = this.dataSignal;
    this.environmentLabel = computed(() =>
      this.dataSignal.value.kind === "local" ? "This machine" : this.dataSignal.value.label,
    );
    this.commandAvailable = computed(() => {
      const data = this.dataSignal.value;
      return (
        this.sessionsStateSignal.value === "ready" &&
        !data.disabled &&
        !/offline|unreachable|unavailable|disconnected|error|failed|stale|pending|connecting|unknown|unconfigured/.test(
          data.status.toLowerCase(),
        )
      );
    });
    this.sessionServices = {
      ...sessionServices,
      refreshSessionList: (_endpointId, background) => this.refreshSessions(background),
    };
  }

  private readonly sessionServices: SessionServices;

  get id(): string {
    return this.dataSignal.value.endpoint_id;
  }

  reconcile(data: EndpointDto): void {
    this.dataSignal.value = data;
  }

  markReachable(): void {
    if (/unreachable|unavailable/.test(this.dataSignal.value.status.toLowerCase())) {
      this.dataSignal.value = { ...this.dataSignal.value, status: "online" };
    }
  }

  start(): void {
    if (this.streamEnabled) return;
    this.streamEnabled = true;
    this.connect();
  }

  reconnect(): void {
    this.streamEnabled = true;
    this.stopStream("Reconnecting");
    this.connect();
  }

  toggleConnection(): void {
    if (
      this.connectionSignal.value === "Connecting" ||
      this.connectionSignal.value === "Reconnecting"
    ) {
      this.stop();
    } else {
      this.reconnect();
    }
  }

  stop(): void {
    this.streamEnabled = false;
    this.stopStream("Stopped");
  }

  getSession(sessionId: string): Session | undefined {
    return this.sessionRegistry.get(sessionId);
  }

  getOrCreateSession(sessionId: string, summary?: SessionSummary): Session {
    let session = this.sessionRegistry.get(sessionId);
    if (!session) {
      const current = summary ?? {
        session_id: sessionId,
        version: 0,
        status: "loading",
        created_at_ms: 0,
        model: null,
      };
      session = new Session(this, sessionId, current, this.sessionServices);
      this.sessionRegistry.set(sessionId, session);
    } else if (summary) {
      session.reconcileSummary(summary);
    }
    return session;
  }

  private exposeSession(session: Session): void {
    if (this.sessionsSignal.value.includes(session)) return;
    this.sessionsSignal.value = [...this.sessionsSignal.value, session];
  }

  async loadSession(sessionId: string): Promise<Session> {
    const session = this.getOrCreateSession(sessionId);
    await session.refresh();
    this.exposeSession(session);
    return session;
  }

  async refreshSessions(background = false): Promise<void> {
    const generation = ++this.sessionsGeneration;
    this.sessionsStateSignal.value = this.sessionsSignal.value.length > 0 ? "stale" : "loading";
    this.sessionsErrorSignal.value = null;
    try {
      const summaries = [];
      let cursor: string | undefined;
      for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
        const page = await this.client.listSessions(this.id, cursor);
        summaries.push(...page.items);
        if (!page.next_cursor) break;
        cursor = page.next_cursor;
      }
      if (generation !== this.sessionsGeneration) return;
      const sessions = summaries.map((summary) =>
        this.getOrCreateSession(summary.session_id, summary),
      );
      sessions.sort((left, right) => {
        const leftData = left.summary.value;
        const rightData = right.summary.value;
        const time =
          (rightData.updated_at_ms ?? rightData.created_at_ms) -
          (leftData.updated_at_ms ?? leftData.created_at_ms);
        return time || right.id.localeCompare(left.id);
      });
      batch(() => {
        this.sessionsSignal.value = sessions;
        this.sessionsStateSignal.value = "ready";
        this.sessionsErrorSignal.value = null;
      });
      await Promise.all(
        sessions.slice(0, 20).map((session) => session.refresh(true).catch(() => undefined)),
      );
    } catch (error) {
      if (generation !== this.sessionsGeneration) return;
      const message = background ? friendlyErrorCode(error) : this.notices.error(error);
      if (background && isAccessRequired(error)) this.notices.error(error);
      batch(() => {
        this.sessionsStateSignal.value = this.sessionsSignal.value.length > 0 ? "stale" : "error";
        this.sessionsErrorSignal.value = message;
      });
      throw error;
    }
  }

  async probe(background = false): Promise<void> {
    if (this.mutationSignal.value === "submitting") return;
    this.mutationSignal.value = "submitting";
    try {
      const endpoint = await this.client.probeEndpoint(this.id);
      this.reconcile(endpoint);
      if (!background) {
        await Promise.all([
          this.refreshSessions(),
          ...this.sessionServices.providers().map((p) => p.refresh()),
        ]);
        this.notices.set(
          this.sessionsErrorSignal.value
            ? `${endpoint.label} is reachable; sessions are unavailable.`
            : `${endpoint.label} is reachable.`,
        );
      }
      this.mutationSignal.value = "idle";
    } catch (error) {
      if (error instanceof ServerClientError && error.code === "endpoint_unavailable") {
        this.dataSignal.value = { ...this.dataSignal.value, status: "unreachable" };
        if (!background)
          this.notices.set("Endpoint unavailable; state is non-authoritative.", "error");
        this.mutationSignal.value = "error";
        return;
      }
      this.mutationSignal.value = "error";
      if (!background) this.notices.error(error);
      throw error;
    }
  }

  dispose(): void {
    this.stop();
  }

  private connect(): void {
    if (!this.streamEnabled || this.streamController || this.reconnectTimer !== null) return;
    const generation = ++this.streamGeneration;
    const controller = new AbortController();
    this.streamController = controller;
    this.connectionSignal.value = this.reconnectAttempt > 0 ? "Reconnecting" : "Connecting";
    void this.consumeStream(generation, controller);
  }

  private async consumeStream(generation: number, controller: AbortController): Promise<void> {
    let retry = false;
    try {
      const response = await this.client.endpointEvents(
        this.id,
        this.cursor.read(this.id),
        controller.signal,
      );
      if (response.status === 401) {
        this.notices.error(new ServerClientError("access_required", 401));
        this.streamEnabled = false;
        return;
      }
      if (!response.ok) {
        let code: string | null = null;
        try {
          const body = (await response.clone().json()) as { error?: { code?: unknown } };
          code = typeof body.error?.code === "string" ? body.error.code : null;
        } catch {
          // The bounded status remains authoritative when no public error is readable.
        }
        const retryable =
          response.status === 408 || response.status === 429 || response.status >= 500;
        if (!retryable) {
          const message = this.notices.error(
            new ServerClientError(code ?? "endpoint_stream_unavailable", response.status),
          );
          batch(() => {
            this.connectionSignal.value = "Unavailable";
            this.streamErrorSignal.value = message;
          });
          return;
        }
        throw new ServerClientError(code ?? `http_${response.status}`, response.status, true);
      }
      if (!response.body) throw new ServerClientError("network_error", 0, true);
      if (!this.isCurrentStream(generation, controller)) return;
      batch(() => {
        this.markReachable();
        this.connectionSignal.value = "Live";
        this.streamErrorSignal.value = null;
      });
      this.reconnectAttempt = 0;
      void this.refreshSessions(true).catch(() => undefined);
      await this.readStream(response.body, generation, controller);
      retry = true;
    } catch (error) {
      if (controller.signal.aborted || !this.isCurrentStream(generation, controller)) return;
      retry = true;
      if (error instanceof ServerClientError && error.code === "endpoint_unavailable") {
        this.dataSignal.value = { ...this.dataSignal.value, status: "unreachable" };
      }
    } finally {
      if (this.streamController === controller) this.streamController = null;
    }
    if (retry && generation === this.streamGeneration && this.streamEnabled) {
      void this.probe(true).catch(() => undefined);
      void this.refreshSessions(true).catch(() => undefined);
      this.connectionSignal.value = "Reconnecting";
      this.scheduleReconnect();
    }
  }

  private async readStream(
    body: ReadableStream<Uint8Array>,
    generation: number,
    controller: AbortController,
  ): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (this.isCurrentStream(generation, controller)) {
        let timeout: number | null = null;
        const result = await Promise.race([
          reader.read(),
          new Promise<never>((_, reject) => {
            timeout = this.clock.setTimeout(
              () => reject(new Error("Endpoint event stream idle timeout")),
              EVENT_STREAM_IDLE_TIMEOUT_MS,
            );
          }),
        ]).finally(() => {
          if (timeout !== null) this.clock.clearTimeout(timeout);
        });
        if (result.done) break;
        buffer += decoder.decode(result.value, { stream: true });
        const frames = buffer.split(/\r?\n\r?\n/);
        buffer = frames.pop() ?? "";
        for (const frame of frames) this.handleFrame(frame);
      }
      buffer += decoder.decode();
      if (buffer.trim()) this.handleFrame(buffer);
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  }

  private handleFrame(frame: string): void {
    let eventName = "message";
    let eventId = "";
    const data: string[] = [];
    for (const line of frame.split(/\r?\n/)) {
      if (!line || line.startsWith(":")) continue;
      const separator = line.indexOf(":");
      const field = separator === -1 ? line : line.slice(0, separator);
      const value = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
      if (field === "event") eventName = value;
      else if (field === "id") eventId = value;
      else if (field === "data") data.push(value);
    }
    if (eventName === "assistant_message_delta") {
      this.handleTransient(data);
      return;
    }
    if (!eventId || data.length === 0) return;
    try {
      const payload = JSON.parse(data.join("\n")) as PublicEvent;
      if (
        payload.schema !== "zode.event.v1" ||
        payload.id !== eventId ||
        payload.kind !== eventName ||
        typeof payload.session_id !== "string" ||
        payload.session_id.length === 0 ||
        typeof payload.data !== "object" ||
        payload.data === null
      ) {
        throw new Error("invalid durable Endpoint event");
      }
      const ordering = compareCursor(eventId, this.cursor.read(this.id));
      if (ordering === null) throw new Error("invalid durable Endpoint cursor");
      if (ordering <= 0) return;
      const session = this.getOrCreateSession(payload.session_id);
      this.exposeSession(session);
      session.acceptDurableEvent(eventName, payload);
      this.cursor.write(this.id, eventId);
    } catch {
      this.streamErrorSignal.value = "A durable Endpoint event could not be read.";
      throw new Error("durable Endpoint event validation failed");
    }
  }

  private handleTransient(data: readonly string[]): void {
    try {
      const payload = JSON.parse(data.join("\n")) as {
        schema?: string;
        session_id?: string;
        text?: string;
      };
      if (
        payload.schema !== "zode.transient-event.v1" ||
        !payload.session_id ||
        typeof payload.text !== "string" ||
        payload.text.length === 0
      ) {
        return;
      }
      const session = this.getOrCreateSession(payload.session_id);
      this.exposeSession(session);
      session.acceptTransientText(payload.text);
    } catch {
      this.notices.set("A transient Endpoint event could not be read.", "error");
    }
  }

  private isCurrentStream(generation: number, controller: AbortController): boolean {
    return (
      generation === this.streamGeneration &&
      this.streamController === controller &&
      !controller.signal.aborted
    );
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;
    const delay = Math.min(1000 * 2 ** this.reconnectAttempt, 10_000);
    this.reconnectAttempt += 1;
    this.reconnectTimer = this.clock.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private stopStream(state: ConnectionState): void {
    this.streamGeneration += 1;
    this.streamController?.abort();
    this.streamController = null;
    if (this.reconnectTimer !== null) {
      this.clock.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.connectionSignal.value = state;
  }
}

function compareCursor(candidate: string, current: string): number | null {
  if (!/^\d+$/.test(candidate) || (current && !/^\d+$/.test(current))) return null;
  if (!current) return 1;
  const candidateValue = BigInt(candidate);
  const currentValue = BigInt(current);
  return candidateValue > currentValue ? 1 : candidateValue < currentValue ? -1 : 0;
}

export class EndpointRegistrationWorkflow {
  private readonly labelSignal = signal("");
  private readonly baseUrlSignal = signal("");
  private readonly credentialSignal = signal("");
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: Command<{
    label: string;
    baseUrl: string;
    controllerCredential: string;
  }> | null = null;

  readonly label: ReadonlySignal<string> = this.labelSignal;
  readonly baseUrl: ReadonlySignal<string> = this.baseUrlSignal;
  readonly controllerCredential: ReadonlySignal<string> = this.credentialSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly progress: ReadonlySignal<string | null> = computed(() =>
    this.mutationSignal.value === "submitting" ? "Checking Endpoint…" : null,
  );

  constructor(
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
    private readonly refreshEndpoints: () => Promise<void>,
  ) {}

  setLabel(value: string): void {
    this.labelSignal.value = value;
    this.invalidateCommand();
  }

  setBaseUrl(value: string): void {
    this.baseUrlSignal.value = value;
    this.invalidateCommand();
  }

  setControllerCredential(value: string): void {
    this.credentialSignal.value = value;
    this.invalidateCommand();
  }

  reset(): void {
    if (this.command?.state === "unknown") return;
    batch(() => {
      this.labelSignal.value = "";
      this.baseUrlSignal.value = "";
      this.credentialSignal.value = "";
      this.mutationSignal.value = "idle";
    });
    this.command = null;
  }

  async submit(): Promise<void> {
    const label = this.labelSignal.value.trim();
    const baseUrl = this.baseUrlSignal.value.trim();
    const credential = this.credentialSignal.value;
    if (!this.command && (!label || !baseUrl || !credential)) return;
    const command = this.command ?? {
      key: this.nextId(),
      body: { label, baseUrl, controllerCredential: credential },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    batch(() => {
      this.credentialSignal.value = "";
      this.mutationSignal.value = "submitting";
    });
    try {
      await this.client.createEndpoint(command.body, command.key);
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.command = null;
    this.mutationSignal.value = "accepted";
    await this.refreshEndpoints().catch(() => undefined);
    this.notices.set(`${command.body.label} was added through the management Server.`);
    this.reset();
  }

  private invalidateCommand(): void {
    if (this.command?.state !== "unknown") this.command = null;
  }
}

export function endpointIsUsable(endpoint: Endpoint): boolean {
  return endpoint.commandAvailable.value;
}
