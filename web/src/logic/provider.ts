import { batch, computed, signal, type ReadonlySignal, type Signal } from "@preact/signals-core";

import {
  ServerClient,
  ServerClientError,
  type AuthProfile as AuthProfileDto,
  type AuthRefreshOperation as AuthRefreshOperationDto,
  type OAuthAttempt as OAuthAttemptDto,
  type ProfileSharingMode,
  type Provider as ProviderDto,
  type ProviderDescriptor,
} from "../api/server";
import type {
  BrowserNavigationPort,
  ClockPort,
  ConnectionState,
  LoadState,
  MutationState,
  NoticeSink,
} from "./ports";
import { friendlyErrorCode } from "./ports";

const PROFILE_DISTRIBUTION_REFRESH_MS = 500;
const CONTROL_STREAM_RECONNECT_MAX_MS = 10_000;

export type ProviderSnapshot = Readonly<ProviderDto>;
export type AuthProfileSnapshot = Readonly<AuthProfileDto>;
type Command<T> = { key: string; body: T; state: MutationState };

class ControlResourceStream {
  private controller: AbortController | null = null;
  private reconnectTimer: number | null = null;
  private reconnectAttempt = 0;
  private generation = 0;
  private cursor = "";
  private enabled = false;

  constructor(
    private readonly eventName: string,
    private readonly open: (lastEventId: string, signal: AbortSignal) => Promise<Response>,
    private readonly reconcile: () => Promise<void>,
    private readonly updateConnection: (state: ConnectionState, error: string | null) => void,
    private readonly notices: NoticeSink,
    private readonly clock: ClockPort,
  ) {}

  start(): void {
    if (this.enabled) return;
    this.enabled = true;
    this.connect();
  }

  stop(): void {
    this.enabled = false;
    this.generation += 1;
    this.controller?.abort();
    this.controller = null;
    if (this.reconnectTimer !== null) {
      this.clock.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.updateConnection("Stopped", null);
  }

  private connect(): void {
    if (!this.enabled || this.controller || this.reconnectTimer !== null) return;
    const generation = ++this.generation;
    const controller = new AbortController();
    this.controller = controller;
    this.updateConnection(this.reconnectAttempt > 0 ? "Reconnecting" : "Connecting", null);
    void this.consume(generation, controller);
  }

  private async consume(generation: number, controller: AbortController): Promise<void> {
    let retry = false;
    try {
      const response = await this.open(this.cursor, controller.signal);
      if (!response.ok) {
        const retryable =
          response.status === 408 || response.status === 429 || response.status >= 500;
        throw new ServerClientError(`http_${response.status}`, response.status, retryable);
      }
      if (!response.body) throw new ServerClientError("network_error", 0, true);
      if (!this.isCurrent(generation, controller)) return;
      this.reconnectAttempt = 0;
      this.updateConnection("Live", null);
      await this.read(response.body, generation, controller);
      retry = true;
    } catch (error) {
      if (controller.signal.aborted || !this.isCurrent(generation, controller)) return;
      retry = true;
      if (error instanceof ServerClientError && error.status === 401) this.notices.error(error);
      this.updateConnection("Reconnecting", friendlyErrorCode(error));
    } finally {
      if (this.controller === controller) this.controller = null;
    }
    if (retry && generation === this.generation && this.enabled) this.scheduleReconnect();
  }

  private async read(
    body: ReadableStream<Uint8Array>,
    generation: number,
    controller: AbortController,
  ): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (this.isCurrent(generation, controller)) {
        const result = await reader.read();
        if (result.done) break;
        buffer += decoder.decode(result.value, { stream: true });
        const frames = buffer.split(/\r?\n\r?\n/);
        buffer = frames.pop() ?? "";
        for (const frame of frames) await this.handleFrame(frame);
      }
      buffer += decoder.decode();
      if (buffer.trim()) await this.handleFrame(buffer);
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  }

  private async handleFrame(frame: string): Promise<void> {
    let eventName = "message";
    let eventId = "";
    for (const line of frame.split(/\r?\n/)) {
      if (!line || line.startsWith(":")) continue;
      const separator = line.indexOf(":");
      const field = separator === -1 ? line : line.slice(0, separator);
      const value = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
      if (field === "event") eventName = value;
      else if (field === "id") eventId = value;
    }
    if (eventName !== this.eventName || !/^\d+$/.test(eventId)) return;
    if (this.cursor && BigInt(eventId) <= BigInt(this.cursor)) return;
    this.cursor = eventId;
    await this.reconcile();
  }

  private isCurrent(generation: number, controller: AbortController): boolean {
    return (
      generation === this.generation && this.controller === controller && !controller.signal.aborted
    );
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;
    const delay = Math.min(1000 * 2 ** this.reconnectAttempt, CONTROL_STREAM_RECONNECT_MAX_MS);
    this.reconnectAttempt += 1;
    this.reconnectTimer = this.clock.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}

export class ProfileSharingWorkflow {
  private readonly modeSignal = signal<ProfileSharingMode>("none");
  private readonly endpointIdsSignal = signal<readonly string[]>([]);
  private readonly mutationSignal = signal<MutationState>("idle");
  private readonly dirtySignal = signal(false);
  private command: Command<{
    profileId: string;
    mode: ProfileSharingMode;
    endpointIds: string[];
  }> | null = null;

  readonly mode: ReadonlySignal<ProfileSharingMode> = this.modeSignal;
  readonly endpointIds: ReadonlySignal<readonly string[]> = this.endpointIdsSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly dirty: ReadonlySignal<boolean> = this.dirtySignal;

  constructor(
    private readonly owner: AuthProfile,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
  ) {
    this.prepare();
  }

  prepare(): this {
    if (this.command?.state === "unknown") return this;
    this.command = null;
    const sharing = this.owner.data.value.sharing;
    batch(() => {
      this.modeSignal.value = sharing.mode;
      this.endpointIdsSignal.value = [...sharing.endpoint_ids].sort();
      this.mutationSignal.value = "idle";
      this.dirtySignal.value = false;
    });
    return this;
  }

  reconcile(mode: ProfileSharingMode, endpointIds: readonly string[]): void {
    if (this.command || this.dirtySignal.value) return;
    batch(() => {
      this.modeSignal.value = mode;
      this.endpointIdsSignal.value = [...endpointIds].sort();
    });
  }

  setMode(mode: ProfileSharingMode): void {
    if (this.command?.state === "unknown") return;
    this.modeSignal.value = mode;
    if (mode === "none") this.endpointIdsSignal.value = [];
    this.command = null;
    this.dirtySignal.value = true;
  }

  setEndpoint(endpointId: string, selected: boolean): void {
    if (this.command?.state === "unknown") return;
    const next = new Set(this.endpointIdsSignal.value);
    if (selected) next.add(endpointId);
    else next.delete(endpointId);
    this.endpointIdsSignal.value = [...next].sort();
    this.modeSignal.value = next.size > 0 ? "selected" : "none";
    this.command = null;
    this.dirtySignal.value = true;
  }

  async submit(): Promise<void> {
    if (!this.command && !this.dirtySignal.value) return;
    const mode = this.modeSignal.value;
    const endpointIds = mode === "all_current" ? [] : [...this.endpointIdsSignal.value];
    if (mode === "selected" && endpointIds.length === 0) return;
    const command = this.command ?? {
      key: this.nextId(),
      body: { profileId: this.owner.id, mode, endpointIds },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      const data = await this.client.updateProfileSharing(
        command.body.profileId,
        { mode: command.body.mode, endpoint_ids: command.body.endpointIds },
        command.key,
      );
      command.state = "accepted";
      this.command = null;
      this.owner.reconcile(data);
      batch(() => {
        this.modeSignal.value = data.sharing.mode;
        this.endpointIdsSignal.value = [...data.sharing.endpoint_ids].sort();
        this.mutationSignal.value = "accepted";
        this.dirtySignal.value = false;
      });
      this.notices.set(`Sharing for ${data.label} was accepted.`);
      await this.owner.owner.refresh(true).catch(() => undefined);
      this.mutationSignal.value = "idle";
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
  }
}

export class ApiKeyRotationWorkflow {
  private readonly apiKeySignal = signal("");
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: Command<{ profileId: string; apiKey: string }> | null = null;

  readonly apiKey: ReadonlySignal<string> = this.apiKeySignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;

  constructor(
    private readonly owner: AuthProfile,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
  ) {}

  setApiKey(value: string): void {
    if (this.command?.state === "unknown") return;
    this.apiKeySignal.value = value;
    this.command = null;
  }

  reset(): void {
    if (this.command?.state === "unknown") return;
    this.command = null;
    batch(() => {
      this.apiKeySignal.value = "";
      this.mutationSignal.value = "idle";
    });
  }

  async submit(): Promise<void> {
    const profile = this.owner.data.value;
    if (profile.kind !== "api_key") return;
    const apiKey = this.apiKeySignal.value;
    if (!this.command && !apiKey) return;
    const command = this.command ?? {
      key: this.nextId(),
      body: { profileId: profile.auth_profile_id, apiKey },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    batch(() => {
      this.apiKeySignal.value = "";
      this.mutationSignal.value = "submitting";
    });
    try {
      const data = await this.client.replaceApiKeyProfile(
        profile.provider,
        command.body.profileId,
        command.body.apiKey,
        command.key,
      );
      command.state = "accepted";
      this.command = null;
      this.owner.reconcile(data);
      this.mutationSignal.value = "accepted";
      this.notices.set(`API key replacement for ${profile.label} was accepted.`);
      await this.owner.owner.refresh(true).catch(() => undefined);
      this.mutationSignal.value = "idle";
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
  }
}

export class AuthProfile {
  private readonly dataSignal: Signal<AuthProfileSnapshot>;
  private readonly mutationSignal = signal<MutationState>("idle");
  private readonly refreshMutationSignal = signal<MutationState>("idle");
  private readonly refreshOperationSignal = signal<AuthRefreshOperation | null>(null);
  private readonly deleteAcknowledgedSignal = signal(false);
  private defaultCommand: Command<{ profileId: string }> | null = null;
  private deleteCommand: Command<{ profileId: string }> | null = null;
  private refreshCommand: Command<{ profileId: string }> | null = null;

  readonly data: ReadonlySignal<AuthProfileSnapshot>;
  readonly displayLabel: ReadonlySignal<string>;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly refreshMutation: ReadonlySignal<MutationState> = this.refreshMutationSignal;
  readonly refreshOperation: ReadonlySignal<AuthRefreshOperation | null> =
    this.refreshOperationSignal;
  readonly deleteAcknowledged: ReadonlySignal<boolean> = this.deleteAcknowledgedSignal;
  readonly sharing: ProfileSharingWorkflow;
  readonly apiKeyRotation: ApiKeyRotationWorkflow;

  constructor(
    readonly owner: Provider,
    initial: AuthProfileDto,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
  ) {
    this.dataSignal = signal(initial);
    this.data = this.dataSignal;
    this.displayLabel = computed(() => this.owner.profileDisplayLabel(this));
    this.sharing = new ProfileSharingWorkflow(this, client, notices, nextId);
    this.apiKeyRotation = new ApiKeyRotationWorkflow(this, client, notices, nextId);
  }

  get id(): string {
    return this.dataSignal.value.auth_profile_id;
  }

  reconcile(data: AuthProfileDto): void {
    this.dataSignal.value = data;
    this.sharing.reconcile(data.sharing.mode, data.sharing.endpoint_ids);
  }

  reconcileRefreshOperation(data: AuthRefreshOperationDto): AuthRefreshOperation {
    let operation = this.refreshOperationSignal.value;
    if (!operation || operation.id !== data.operation_id) {
      operation?.dispose();
      operation = new AuthRefreshOperation(this, data, this.client, this.notices, this.owner.clock);
      this.refreshOperationSignal.value = operation;
      operation.start();
    } else {
      operation.reconcile(data);
    }
    return operation;
  }

  async refreshCredential(): Promise<AuthRefreshOperation | null> {
    const profile = this.dataSignal.value;
    if (!profile.allowed_actions.includes("refresh")) return null;
    const command = this.refreshCommand ?? {
      key: this.nextId(),
      body: { profileId: profile.auth_profile_id },
      state: "idle" as MutationState,
    };
    this.refreshCommand = command;
    command.state = "submitting";
    this.refreshMutationSignal.value = "submitting";
    let operation: AuthRefreshOperation;
    try {
      const data = await this.client.startAuthRefresh(command.body.profileId, command.key);
      operation = this.reconcileRefreshOperation(data);
    } catch (error) {
      command.state = "unknown";
      this.refreshMutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.refreshCommand = null;
    this.refreshMutationSignal.value = "accepted";
    this.notices.set(`Refresh admitted for ${profile.label}.`);
    await this.owner.refresh(true).catch(() => undefined);
    this.refreshMutationSignal.value = "idle";
    return operation;
  }

  prepareRelogin(): OAuthAttemptCreationWorkflow {
    return this.owner.oauthAttemptCreation.prepareReplacement(this);
  }

  dispose(): void {
    this.refreshOperationSignal.value?.dispose();
  }

  acknowledgeDelete(acknowledged: boolean): void {
    this.deleteAcknowledgedSignal.value = acknowledged;
  }

  resetDelete(): void {
    this.deleteAcknowledgedSignal.value = false;
    if (this.deleteCommand?.state !== "unknown") this.deleteCommand = null;
  }

  async setDefault(): Promise<void> {
    const profile = this.dataSignal.value;
    const command =
      this.defaultCommand?.body.profileId === profile.profile_id
        ? this.defaultCommand
        : {
            key: this.nextId(),
            body: { profileId: profile.profile_id },
            state: "idle" as MutationState,
          };
    this.defaultCommand = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      await this.client.setDefaultProfile(profile.provider, command.body.profileId, command.key);
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.defaultCommand = null;
    this.mutationSignal.value = "accepted";
    this.notices.set(`${profile.label} is now the default profile.`);
    await this.owner.refresh(true).catch(() => undefined);
    this.mutationSignal.value = "idle";
  }

  async delete(): Promise<void> {
    if (!this.deleteAcknowledgedSignal.value) return;
    const profile = this.dataSignal.value;
    const command =
      this.deleteCommand?.body.profileId === profile.profile_id
        ? this.deleteCommand
        : {
            key: this.nextId(),
            body: { profileId: profile.profile_id },
            state: "idle" as MutationState,
          };
    this.deleteCommand = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    let result: Awaited<ReturnType<ServerClient["deleteProfile"]>>;
    try {
      result = await this.client.deleteProfile(
        profile.provider,
        command.body.profileId,
        command.key,
      );
    } catch (error) {
      command.state = "unknown";
      batch(() => {
        this.mutationSignal.value = "unknown";
        this.deleteAcknowledgedSignal.value = false;
      });
      this.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.deleteCommand = null;
    this.notices.set(
      result.status === "deleted"
        ? `${profile.label} was deleted and Endpoint revocation was acknowledged.`
        : `${profile.label} was deleted; Endpoint revocation is still pending.`,
    );
    batch(() => {
      this.mutationSignal.value = "accepted";
      this.deleteAcknowledgedSignal.value = false;
    });
    await this.owner.refresh(true).catch(() => undefined);
    this.mutationSignal.value = "idle";
  }
}

export class ProfileCreationWorkflow {
  private readonly labelSignal = signal("");
  private readonly apiKeySignal = signal("");
  private readonly endpointIdsSignal = signal<readonly string[]>([]);
  private readonly makeDefaultSignal = signal(false);
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: Command<{
    label: string;
    apiKey: string;
    endpointIds: string[];
    makeDefault: boolean;
  }> | null = null;

  readonly label: ReadonlySignal<string> = this.labelSignal;
  readonly apiKey: ReadonlySignal<string> = this.apiKeySignal;
  readonly endpointIds: ReadonlySignal<readonly string[]> = this.endpointIdsSignal;
  readonly makeDefault: ReadonlySignal<boolean> = this.makeDefaultSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;

  constructor(
    private readonly owner: Provider,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
  ) {}

  setLabel(value: string): void {
    this.labelSignal.value = value;
    this.invalidateCommand();
  }

  setApiKey(value: string): void {
    this.apiKeySignal.value = value;
    this.invalidateCommand();
  }

  setEndpoint(endpointId: string, selected: boolean): void {
    const next = new Set(this.endpointIdsSignal.value);
    if (selected) next.add(endpointId);
    else next.delete(endpointId);
    this.endpointIdsSignal.value = [...next].sort();
    this.invalidateCommand();
  }

  setMakeDefault(value: boolean): void {
    this.makeDefaultSignal.value = value;
    this.invalidateCommand();
  }

  reset(): void {
    if (this.command?.state === "unknown") return;
    batch(() => {
      this.labelSignal.value = "";
      this.apiKeySignal.value = "";
      this.endpointIdsSignal.value = [];
      this.makeDefaultSignal.value = false;
      this.mutationSignal.value = "idle";
    });
    this.command = null;
  }

  async submit(): Promise<void> {
    const label = this.labelSignal.value.trim();
    const apiKey = this.apiKeySignal.value;
    if (!this.command && (!label || !apiKey)) return;
    const command = this.command ?? {
      key: this.nextId(),
      body: {
        label,
        apiKey,
        endpointIds: [...this.endpointIdsSignal.value],
        makeDefault: this.makeDefaultSignal.value,
      },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    batch(() => {
      this.apiKeySignal.value = "";
      this.mutationSignal.value = "submitting";
    });
    try {
      await this.client.createApiKeyProfile(this.owner.name, command.body, command.key);
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.command = null;
    this.mutationSignal.value = "accepted";
    this.notices.set(`${command.body.label} is ready for distribution.`);
    await this.owner.refresh(true).catch(() => undefined);
    batch(() => {
      this.labelSignal.value = "";
      this.endpointIdsSignal.value = [];
      this.makeDefaultSignal.value = false;
      this.mutationSignal.value = "idle";
    });
  }

  private invalidateCommand(): void {
    if (this.command?.state !== "unknown") this.command = null;
  }
}

export class AuthRefreshOperation {
  private readonly dataSignal: Signal<Readonly<AuthRefreshOperationDto>>;
  private readonly connectionSignal = signal<ConnectionState>("Stopped");
  private readonly errorSignal = signal<string | null>(null);
  private readonly stream: ControlResourceStream;

  readonly data: ReadonlySignal<Readonly<AuthRefreshOperationDto>>;
  readonly connection: ReadonlySignal<ConnectionState> = this.connectionSignal;
  readonly error: ReadonlySignal<string | null> = this.errorSignal;

  constructor(
    readonly owner: AuthProfile,
    initial: AuthRefreshOperationDto,
    private readonly client: ServerClient,
    notices: NoticeSink,
    clock: ClockPort,
  ) {
    this.dataSignal = signal(initial);
    this.data = this.dataSignal;
    this.stream = new ControlResourceStream(
      "auth_refresh",
      (cursor, abortSignal) => this.client.authRefreshEvents(this.id, cursor, abortSignal),
      () => this.refresh(),
      (state, error) =>
        batch(() => {
          this.connectionSignal.value = state;
          this.errorSignal.value = error;
        }),
      notices,
      clock,
    );
  }

  get id(): string {
    return this.dataSignal.value.operation_id;
  }

  start(): void {
    if (this.isTerminal()) return;
    this.stream.start();
  }

  reconcile(data: AuthRefreshOperationDto): void {
    const previous = this.dataSignal.value.status;
    this.dataSignal.value = data;
    if (this.isTerminal()) {
      this.stream.stop();
      if (previous !== data.status) void this.owner.owner.refresh(true).catch(() => undefined);
    }
  }

  prepareRelogin(): OAuthAttemptCreationWorkflow {
    return this.owner.prepareRelogin();
  }

  dispose(): void {
    this.stream.stop();
  }

  private async refresh(): Promise<void> {
    this.reconcile(await this.client.getAuthRefresh(this.id));
  }

  private isTerminal(): boolean {
    return !["prepared", "dispatching"].includes(this.dataSignal.value.status);
  }
}

export class OAuthAttempt {
  private readonly dataSignal: Signal<Readonly<OAuthAttemptDto>>;
  private readonly mutationSignal = signal<MutationState>("idle");
  private readonly connectionSignal = signal<ConnectionState>("Stopped");
  private readonly errorSignal = signal<string | null>(null);
  private readonly stream: ControlResourceStream;
  private authorizeCommand: Command<Record<string, never>> | null = null;
  private cancelCommand: Command<Record<string, never>> | null = null;
  private authorizeTicket: string | null = null;

  readonly data: ReadonlySignal<Readonly<OAuthAttemptDto>>;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly connection: ReadonlySignal<ConnectionState> = this.connectionSignal;
  readonly error: ReadonlySignal<string | null> = this.errorSignal;

  constructor(
    readonly owner: Provider,
    initial: OAuthAttemptDto,
    private readonly client: ServerClient,
    private readonly browser: BrowserNavigationPort,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
    clock: ClockPort,
  ) {
    this.dataSignal = signal(initial);
    this.data = this.dataSignal;
    this.stream = new ControlResourceStream(
      "oauth_attempt",
      (cursor, abortSignal) => this.client.oauthAttemptEvents(this.id, cursor, abortSignal),
      () => this.refresh(),
      (state, error) =>
        batch(() => {
          this.connectionSignal.value = state;
          this.errorSignal.value = error;
        }),
      notices,
      clock,
    );
  }

  get id(): string {
    return this.dataSignal.value.attempt_id;
  }

  start(): void {
    if (this.isTerminal()) return;
    this.stream.start();
  }

  reconcile(data: OAuthAttemptDto): void {
    const previous = this.dataSignal.value.status;
    this.dataSignal.value = data;
    if (this.isTerminal()) {
      this.authorizeTicket = null;
      this.stream.stop();
      if (previous !== data.status && data.status === "succeeded") {
        void this.owner.refresh(true).catch(() => undefined);
      }
    }
  }

  async authorize(): Promise<void> {
    if (!this.dataSignal.value.allowed_actions.includes("authorize")) return;
    await this.prepareAuthorization();
    const ticket = this.authorizeTicket;
    if (!ticket) return;
    this.authorizeTicket = null;
    this.browser.replace(
      `/v1/auth-attempts/${encodeURIComponent(this.id)}/authorize?ticket=${encodeURIComponent(ticket)}`,
    );
  }

  async prepareAuthorization(): Promise<void> {
    if (this.authorizeTicket || !this.dataSignal.value.allowed_actions.includes("authorize")) {
      return;
    }
    const command = this.authorizeCommand ?? {
      key: this.nextId(),
      body: {},
      state: "idle" as MutationState,
    };
    this.authorizeCommand = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      const { ticket } = await this.client.mintOAuthAuthorizeTicket(this.id, command.key);
      this.authorizeTicket = ticket;
      command.state = "accepted";
      this.authorizeCommand = null;
      this.mutationSignal.value = "accepted";
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
  }

  async cancel(): Promise<void> {
    if (!this.dataSignal.value.allowed_actions.includes("cancel")) return;
    const command = this.cancelCommand ?? {
      key: this.nextId(),
      body: {},
      state: "idle" as MutationState,
    };
    this.cancelCommand = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      this.reconcile(await this.client.cancelOAuthAttempt(this.id, command.key));
      this.authorizeTicket = null;
      command.state = "accepted";
      this.cancelCommand = null;
      this.mutationSignal.value = "idle";
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
  }

  dispose(): void {
    this.stream.stop();
  }

  private async refresh(): Promise<void> {
    this.reconcile(await this.client.getOAuthAttempt(this.id));
  }

  private isTerminal(): boolean {
    return this.dataSignal.value.status !== "active";
  }
}

export class OAuthAttemptCreationWorkflow {
  private readonly labelSignal = signal("");
  private readonly endpointIdsSignal = signal<readonly string[]>([]);
  private readonly makeDefaultSignal = signal(false);
  private readonly replacementSignal = signal<AuthProfile | null>(null);
  private readonly mutationSignal = signal<MutationState>("idle");
  private readonly attemptSignal = signal<OAuthAttempt | null>(null);
  private command: Command<{
    label: string;
    endpointIds: string[];
    makeDefault: boolean;
    replaceAuthProfileId?: string;
  }> | null = null;

  readonly label: ReadonlySignal<string> = this.labelSignal;
  readonly endpointIds: ReadonlySignal<readonly string[]> = this.endpointIdsSignal;
  readonly makeDefault: ReadonlySignal<boolean> = this.makeDefaultSignal;
  readonly replacement: ReadonlySignal<AuthProfile | null> = this.replacementSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly attempt: ReadonlySignal<OAuthAttempt | null> = this.attemptSignal;

  constructor(
    private readonly owner: Provider,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
  ) {}

  prepareNew(): this {
    if (this.command?.state === "unknown") return this;
    this.reset();
    return this;
  }

  prepareReplacement(profile: AuthProfile): this {
    if (this.command?.state === "unknown") return this;
    const data = profile.data.value;
    this.command = null;
    batch(() => {
      this.labelSignal.value = data.label;
      this.endpointIdsSignal.value = [...data.sharing.endpoint_ids].sort();
      this.makeDefaultSignal.value = data.is_default;
      this.replacementSignal.value = profile;
      this.mutationSignal.value = "idle";
      this.attemptSignal.value = null;
    });
    return this;
  }

  setLabel(value: string): void {
    this.labelSignal.value = value;
    this.invalidateCommand();
  }

  setEndpoint(endpointId: string, selected: boolean): void {
    const next = new Set(this.endpointIdsSignal.value);
    if (selected) next.add(endpointId);
    else next.delete(endpointId);
    this.endpointIdsSignal.value = [...next].sort();
    this.invalidateCommand();
  }

  setMakeDefault(value: boolean): void {
    this.makeDefaultSignal.value = value;
    this.invalidateCommand();
  }

  reset(): void {
    if (this.command?.state === "unknown") return;
    this.command = null;
    batch(() => {
      this.labelSignal.value = "";
      this.endpointIdsSignal.value = [];
      this.makeDefaultSignal.value = false;
      this.replacementSignal.value = null;
      this.mutationSignal.value = "idle";
      this.attemptSignal.value = null;
    });
  }

  async submit(): Promise<OAuthAttempt | null> {
    if (!this.owner.data.value.auth_methods.includes("oauth")) return null;
    const existing = this.attemptSignal.value;
    if (existing) {
      await existing.prepareAuthorization();
      return existing;
    }
    const label = this.labelSignal.value.trim();
    if (!this.command && !label) return null;
    const replacement = this.replacementSignal.value;
    const command = this.command ?? {
      key: this.nextId(),
      body: {
        label,
        endpointIds: [...this.endpointIdsSignal.value],
        makeDefault: this.makeDefaultSignal.value,
        ...(replacement ? { replaceAuthProfileId: replacement.id } : {}),
      },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    let attempt: OAuthAttempt;
    try {
      const data = await this.client.startOAuthAttempt(this.owner.name, command.body, command.key);
      attempt = this.owner.reconcileOAuthAttempt(data);
      command.state = "accepted";
      this.command = null;
      batch(() => {
        this.attemptSignal.value = attempt;
        this.mutationSignal.value = "accepted";
      });
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
    await attempt.prepareAuthorization();
    this.notices.set(`OAuth sign-in is ready for ${command.body.label}.`);
    return attempt;
  }

  private invalidateCommand(): void {
    if (this.command?.state !== "unknown") this.command = null;
  }
}

export class Provider {
  private readonly dataSignal: Signal<ProviderSnapshot>;
  private readonly profilesSignal = signal<readonly AuthProfile[]>([]);
  private readonly authAttemptsSignal = signal<readonly OAuthAttempt[]>([]);
  private readonly stateSignal = signal<LoadState>("idle");
  private readonly errorSignal = signal<string | null>(null);
  private readonly profileRegistry = new Map<string, AuthProfile>();
  private readonly authAttemptRegistry = new Map<string, OAuthAttempt>();
  private generation = 0;
  private refreshTimer: number | null = null;

  readonly data: ReadonlySignal<ProviderSnapshot>;
  readonly profiles: ReadonlySignal<readonly AuthProfile[]> = this.profilesSignal;
  readonly authAttempts: ReadonlySignal<readonly OAuthAttempt[]> = this.authAttemptsSignal;
  readonly state: ReadonlySignal<LoadState> = this.stateSignal;
  readonly error: ReadonlySignal<string | null> = this.errorSignal;
  readonly profileCreation: ProfileCreationWorkflow;
  readonly oauthAttemptCreation: OAuthAttemptCreationWorkflow;
  readonly oauthAvailable: ReadonlySignal<boolean>;
  readonly defaultProfile: ReadonlySignal<AuthProfile | null>;

  constructor(
    initial: ProviderDto,
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
    readonly clock: ClockPort,
    private readonly browser: BrowserNavigationPort,
  ) {
    this.dataSignal = signal(initial);
    this.data = this.dataSignal;
    this.profileCreation = new ProfileCreationWorkflow(this, client, notices, nextId);
    this.oauthAttemptCreation = new OAuthAttemptCreationWorkflow(this, client, notices, nextId);
    this.oauthAvailable = computed(() => this.dataSignal.value.auth_methods.includes("oauth"));
    this.defaultProfile = computed(() => {
      const id = this.dataSignal.value.default_profile_id;
      return (
        this.profilesSignal.value.find(
          (profile) =>
            profile.data.value.auth_profile_id === id || profile.data.value.profile_id === id,
        ) ?? null
      );
    });
  }

  get name(): string {
    return this.dataSignal.value.provider;
  }

  profileDisplayLabel(profile: AuthProfile): string {
    const data = profile.data.value;
    const duplicates = this.profilesSignal.value.filter(
      (candidate) => candidate.data.value.label === data.label,
    );
    if (duplicates.length < 2) return data.label;
    const sameKind = duplicates.filter((candidate) => candidate.data.value.kind === data.kind);
    const ordinal =
      sameKind.length > 1
        ? ` ${sameKind.findIndex((candidate) => candidate.id === profile.id) + 1}`
        : "";
    return `${data.label} · ${data.kind === "api_key" ? "API key" : "OAuth"}${ordinal}`;
  }

  reconcile(data: ProviderDto): void {
    this.dataSignal.value = data;
  }

  reconcileOAuthAttempt(data: OAuthAttemptDto): OAuthAttempt {
    if (data.provider !== this.name) throw new Error("OAuth attempt belongs to another provider");
    let attempt = this.authAttemptRegistry.get(data.attempt_id);
    if (!attempt) {
      attempt = new OAuthAttempt(
        this,
        data,
        this.client,
        this.browser,
        this.notices,
        this.nextId,
        this.clock,
      );
      this.authAttemptRegistry.set(data.attempt_id, attempt);
      this.authAttemptsSignal.value = [...this.authAttemptsSignal.value, attempt];
      attempt.start();
    } else {
      attempt.reconcile(data);
    }
    return attempt;
  }

  async loadOAuthAttempt(attemptId: string): Promise<OAuthAttempt> {
    return this.reconcileOAuthAttempt(await this.client.getOAuthAttempt(attemptId));
  }

  dispose(): void {
    this.generation += 1;
    this.cancelRefreshTimer();
    for (const profile of this.profileRegistry.values()) profile.dispose();
    for (const attempt of this.authAttemptRegistry.values()) attempt.dispose();
  }

  async refresh(silent = false): Promise<void> {
    this.cancelRefreshTimer();
    const generation = ++this.generation;
    this.stateSignal.value = this.profilesSignal.value.length > 0 ? "stale" : "loading";
    this.errorSignal.value = null;
    try {
      const profiles = await this.client.listProfiles(this.name);
      if (generation !== this.generation) return;
      const next: AuthProfile[] = [];
      for (const dto of profiles) {
        let profile = this.profileRegistry.get(dto.auth_profile_id);
        if (!profile) {
          profile = new AuthProfile(this, dto, this.client, this.notices, this.nextId);
          this.profileRegistry.set(dto.auth_profile_id, profile);
        } else {
          profile.reconcile(dto);
        }
        next.push(profile);
      }
      const present = new Set(next.map((profile) => profile.id));
      for (const [id, profile] of this.profileRegistry) {
        if (present.has(id)) continue;
        profile.dispose();
        this.profileRegistry.delete(id);
      }
      batch(() => {
        this.profilesSignal.value = next;
        this.stateSignal.value = "ready";
        this.errorSignal.value = null;
      });
      this.scheduleDistributionRefresh();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = silent
        ? "Provider profiles are temporarily unavailable."
        : this.notices.error(error);
      batch(() => {
        this.stateSignal.value = this.profilesSignal.value.length > 0 ? "stale" : "error";
        this.errorSignal.value = message;
      });
      this.scheduleDistributionRefresh();
      throw error;
    }
  }

  private scheduleDistributionRefresh(): void {
    if (
      this.refreshTimer !== null ||
      !this.profilesSignal.value.some((profile) =>
        ["pending", "unreachable", "stale"].includes(profile.data.value.status),
      )
    ) {
      return;
    }
    this.refreshTimer = this.clock.setTimeout(() => {
      this.refreshTimer = null;
      void this.refresh(true).catch(() => undefined);
    }, PROFILE_DISTRIBUTION_REFRESH_MS);
  }

  private cancelRefreshTimer(): void {
    if (this.refreshTimer === null) return;
    this.clock.clearTimeout(this.refreshTimer);
    this.refreshTimer = null;
  }
}

export class ProviderConfigurationWorkflow {
  private readonly providerSignal = signal("");
  private readonly baseUrlSignal = signal("");
  private readonly modelsSignal = signal("");
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: Command<{
    provider: string;
    descriptor: Omit<ProviderDescriptor, "revision">;
  }> | null = null;

  readonly provider: ReadonlySignal<string> = this.providerSignal;
  readonly baseUrl: ReadonlySignal<string> = this.baseUrlSignal;
  readonly models: ReadonlySignal<string> = this.modelsSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;

  constructor(
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
    private readonly nextId: () => string,
    private readonly refreshProviders: () => Promise<void>,
  ) {}

  setProvider(value: string): void {
    this.providerSignal.value = value;
    this.invalidateCommand();
  }

  setBaseUrl(value: string): void {
    this.baseUrlSignal.value = value;
    this.invalidateCommand();
  }

  setModels(value: string): void {
    this.modelsSignal.value = value;
    this.invalidateCommand();
  }

  reset(): void {
    if (this.command?.state === "unknown") return;
    batch(() => {
      this.providerSignal.value = "";
      this.baseUrlSignal.value = "";
      this.modelsSignal.value = "";
      this.mutationSignal.value = "idle";
    });
    this.command = null;
  }

  async submit(): Promise<void> {
    const provider = this.providerSignal.value.trim();
    const models = this.modelsSignal.value
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (!this.command && (!provider || !this.baseUrlSignal.value.trim() || models.length === 0))
      return;
    const command = this.command ?? {
      key: this.nextId(),
      body: {
        provider,
        descriptor: {
          kind: "openai_compatible" as const,
          base_url: this.baseUrlSignal.value.trim(),
          models,
          options: {},
        },
      },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      await this.client.putProvider(command.body.provider, command.body.descriptor, command.key);
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.command = null;
    this.mutationSignal.value = "accepted";
    await this.refreshProviders().catch(() => undefined);
    this.notices.set(`${command.body.provider} is ready for an auth profile.`);
    this.reset();
  }

  private invalidateCommand(): void {
    if (this.command?.state !== "unknown") this.command = null;
  }
}

export function profileIsUsableOnEndpoint(profile: AuthProfile, endpointId: string): boolean {
  const data = profile.data.value;
  if (
    data.status !== "ready" ||
    data.sharing.mode === "none" ||
    !data.sharing.endpoint_ids.includes(endpointId)
  ) {
    return false;
  }
  const replica = data.distribution.find((candidate) => candidate.endpoint_id === endpointId);
  return (
    replica?.status === "ready" &&
    replica.installed_revision !== null &&
    replica.installed_revision >= data.revision
  );
}
