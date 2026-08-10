import { batch, computed, signal, type ReadonlySignal, type Signal } from "@preact/signals-core";

import {
  ServerClient,
  type PublicEvent,
  type Session as SessionDto,
  type SessionSummary,
  type ToolCallProjection,
} from "../api/server";
import {
  profileIsUsableOnEndpoint,
  type AuthProfile,
  type AuthProfileSnapshot,
  type Provider,
  type ProviderSnapshot,
} from "./provider";
import {
  executionChoiceMatches,
  modelExecutionGroups,
  type ExecutionChoice,
  type ModelExecutionGroup,
} from "./execution";
import type { ConnectionState, LoadState, MutationState, NoticeSink } from "./ports";
import { isAccessRequired } from "./ports";
import type { Endpoint } from "./endpoint";

export type SessionSnapshot = Readonly<SessionDto>;
export type SessionSummarySnapshot = Readonly<SessionSummary>;
export type TranscriptMessage = SessionDto["transcript"][number];
export type ToolCallSnapshot = ToolCallProjection;
export type WaitOutcome = Readonly<{
  status: "timed_out";
  waitId: string;
  reason: string;
}>;
export type SessionVisualState =
  | "streaming"
  | "waiting"
  | "tool"
  | "error"
  | "connecting"
  | "reconnecting"
  | "disconnected"
  | undefined;
export type RuntimeActivity = Readonly<{
  key: string;
  icon: string;
  title: string;
  detail: string;
  ariaLabel?: string;
  attention?: boolean;
  alert?: boolean;
  tool?: ToolCall;
}>;

type Command<T> = { key: string; body: T; state: MutationState };

const PROVISIONAL_TERMINALS = new Set([
  "assistant_message_committed",
  "model_step_retrying",
  "model_attempt_failed",
  "model_attempt_interrupted",
  "model_attempts_exhausted",
  "activation_finished",
]);

export interface SessionServices {
  client: ServerClient;
  notices: NoticeSink;
  nextId(): string;
  providers(): readonly Provider[];
  providersState(): LoadState;
  refreshSessionList(endpointId: string, background?: boolean): Promise<void>;
}

export type ToolCallAction = "cancel" | "reconcile";

export class ToolCall {
  private readonly dataSignal: Signal<ToolCallSnapshot>;
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: Command<{ action: ToolCallAction }> | null = null;

  readonly data: ReadonlySignal<ToolCallSnapshot>;
  readonly id: string;
  readonly rawStatus: ReadonlySignal<string>;
  readonly name: ReadonlySignal<string>;
  readonly status: ReadonlySignal<string>;
  readonly description: ReadonlySignal<string>;
  readonly availableActions: ReadonlySignal<readonly ToolCallAction[]>;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;

  constructor(
    readonly session: Session,
    initial: ToolCallSnapshot,
  ) {
    this.dataSignal = signal(initial);
    this.data = this.dataSignal;
    this.id = initial.tool_call_id;
    this.rawStatus = computed(() => this.dataSignal.value.status);
    this.name = computed(() => {
      const data = this.dataSignal.value;
      return data.tool_name?.trim() || data.name?.trim() || `Tool call ${data.tool_call_id}`;
    });
    this.status = computed(() => this.dataSignal.value.status.replaceAll("_", " "));
    this.description = computed(() => {
      const data = this.dataSignal.value;
      if (data.error?.message) return data.error.message;
      if (data.reconciliation?.reason === "unknown_outcome") {
        return "Unable to determine tool outcome";
      }
      if (data.reconciliation?.reason) {
        return data.reconciliation.reason.replaceAll("_", " ");
      }
      return this.status.value;
    });
    this.availableActions = computed(() => {
      const data = this.dataSignal.value;
      const actions: ToolCallAction[] = [];
      if (data.allowed_actions.includes("cancel")) actions.push("cancel");
      if (data.allowed_actions.includes("retry_dispatch")) actions.push("reconcile");
      return actions;
    });
  }

  reconcile(data: ToolCallSnapshot): void {
    this.dataSignal.value = data;
  }

  async refresh(): Promise<void> {
    const data = await this.session.services.client.getToolCall(
      this.session.endpoint.id,
      this.session.id,
      this.dataSignal.value.tool_call_id,
    );
    this.reconcile(data);
  }

  cancel(): Promise<void> {
    return this.mutate("cancel");
  }

  reconcileOutcome(): Promise<void> {
    return this.mutate("reconcile");
  }

  private async mutate(action: ToolCallAction): Promise<void> {
    if (this.mutationSignal.value === "submitting") return;
    if (!this.availableActions.value.includes(action) && this.command?.body.action !== action)
      return;
    const command =
      this.command?.body.action === action
        ? this.command
        : {
            key: this.session.services.nextId(),
            body: { action },
            state: "idle" as MutationState,
          };
    this.command = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      const data =
        action === "cancel"
          ? await this.session.services.client.cancelToolCall(
              this.session.endpoint.id,
              this.session.id,
              this.dataSignal.value.tool_call_id,
              command.key,
            )
          : await this.session.services.client.reconcileToolCall(
              this.session.endpoint.id,
              this.session.id,
              this.dataSignal.value.tool_call_id,
              command.key,
            );
      command.state = "accepted";
      batch(() => {
        this.dataSignal.value = data;
        this.mutationSignal.value = "accepted";
      });
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.session.services.notices.error(error);
      throw error;
    }
    this.command = null;
    this.mutationSignal.value = "idle";
  }
}

export class SessionExecutionWorkflow {
  private readonly providerSignal = signal("");
  private readonly modelSignal = signal("");
  private readonly profileSignal = signal("");
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: Command<{
    provider: ProviderSnapshot;
    model: string;
    profile: AuthProfileSnapshot;
  }> | null = null;

  readonly provider: ReadonlySignal<string> = this.providerSignal;
  readonly model: ReadonlySignal<string> = this.modelSignal;
  readonly profile: ReadonlySignal<string> = this.profileSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly providerOptions: ReadonlySignal<readonly { value: string; label: string }[]>;
  readonly modelOptions: ReadonlySignal<readonly { value: string; label: string }[]>;
  readonly profileOptions: ReadonlySignal<readonly { value: string; label: string }[]>;
  readonly executionGroups: ReadonlySignal<readonly ModelExecutionGroup[]>;
  readonly selectedExecution: ReadonlySignal<ExecutionChoice | null>;
  readonly selectedProvider: ReadonlySignal<Provider | null>;
  readonly selectedProfile: ReadonlySignal<AuthProfile | null>;
  readonly available: ReadonlySignal<boolean>;
  readonly interactionAvailable: ReadonlySignal<boolean>;
  readonly recoveryVisible: ReadonlySignal<boolean>;
  readonly contextLabel: ReadonlySignal<string>;
  readonly summary: ReadonlySignal<string>;
  readonly unavailableMessage: ReadonlySignal<string | null>;
  readonly canApply: ReadonlySignal<boolean>;

  constructor(readonly session: Session) {
    this.providerOptions = computed(() =>
      session.services.providers().map((provider) => ({
        value: provider.name,
        label: provider.name,
      })),
    );
    this.selectedProvider = computed(
      () =>
        session.services
          .providers()
          .find((provider) => provider.name === this.providerSignal.value) ?? null,
    );
    this.modelOptions = computed(() =>
      (this.selectedProvider.value?.data.value.descriptor.models ?? []).map((model) => ({
        value: model,
        label: model,
      })),
    );
    this.profileOptions = computed(() =>
      (this.selectedProvider.value?.profiles.value ?? [])
        .filter((profile) => profileIsUsableOnEndpoint(profile, session.endpoint.id))
        .map((profile) => ({
          value: profile.data.value.auth_profile_id,
          label: profile.displayLabel.value,
        })),
    );
    this.selectedProfile = computed(
      () =>
        this.selectedProvider.value?.profiles.value.find((profile) => {
          const data = profile.data.value;
          return (
            data.auth_profile_id === this.profileSignal.value ||
            data.profile_id === this.profileSignal.value
          );
        }) ?? null,
    );
    this.executionGroups = computed(() =>
      modelExecutionGroups(session.services.providers(), session.endpoint.id),
    );
    this.selectedExecution = computed(
      () =>
        this.executionGroups.value
          .flatMap((group) => group.choices)
          .find((choice) =>
            executionChoiceMatches(
              choice,
              this.providerSignal.value,
              this.modelSignal.value,
              this.profileSignal.value,
            ),
          ) ?? null,
    );
    this.interactionAvailable = computed(
      () =>
        session.services.providersState() !== "loading" &&
        session.services.providersState() !== "error" &&
        session.connection.value === "Live",
    );
    this.available = computed(
      () =>
        this.interactionAvailable.value &&
        this.selectedProvider.value !== null &&
        this.selectedProfile.value !== null &&
        this.modelOptions.value.some((option) => option.value === this.modelSignal.value),
    );
    this.recoveryVisible = computed(
      () =>
        session.services.providersState() !== "loading" &&
        session.executionNeedsRecovery.value &&
        !session.executionAcknowledged.value,
    );
    this.contextLabel = computed(() =>
      this.recoveryVisible.value
        ? "Choose execution"
        : (session.data.value?.model?.model ?? "Execution"),
    );
    this.summary = computed(() => {
      const model = session.data.value?.model;
      return `${model?.provider ?? "Provider unavailable"} · ${model?.model ?? "Model unavailable"} · ${session.profileName.value}`;
    });
    this.unavailableMessage = computed(() => {
      if (this.interactionAvailable.value) return null;
      return session.connection.value !== "Live"
        ? "Reconnect to the Endpoint before applying a change."
        : "Execution details are unavailable. Try again from Manage before applying a change.";
    });
    this.canApply = computed(
      () => this.available.value && this.mutationSignal.value !== "submitting",
    );
  }

  open(): void {
    this.reset();
  }

  reset(): void {
    if (this.command?.state === "unknown") return;
    const model = this.session.data.value?.model;
    batch(() => {
      this.providerSignal.value = model?.provider ?? "";
      this.modelSignal.value = model?.model ?? "";
      this.profileSignal.value = model?.auth_profile_id ?? "";
      this.mutationSignal.value = "idle";
    });
    this.command = null;
  }

  setProvider(value: string): void {
    const provider = this.session.services
      .providers()
      .find((candidate) => candidate.name === value);
    const data = this.session.data.value?.model;
    batch(() => {
      this.providerSignal.value = value;
      this.modelSignal.value =
        provider?.data.value.descriptor.models.find((model) => model === data?.model) ??
        provider?.data.value.descriptor.models[0] ??
        "";
      this.profileSignal.value = defaultProfileId(
        provider,
        this.session.endpoint.id,
        data?.auth_profile_id,
      );
    });
    this.invalidateCommand();
  }

  setModel(value: string): void {
    if (!this.modelOptions.value.some((option) => option.value === value)) return;
    batch(() => {
      this.modelSignal.value = value;
    });
    this.invalidateCommand();
  }

  setProfile(value: string): void {
    if (!this.profileOptions.value.some((option) => option.value === value)) return;
    batch(() => {
      this.profileSignal.value = value;
    });
    this.invalidateCommand();
  }

  selectExecution(choice: ExecutionChoice): void {
    batch(() => {
      this.providerSignal.value = choice.provider.name;
      this.modelSignal.value = choice.model;
      this.profileSignal.value = choice.profile.data.value.auth_profile_id;
    });
    this.invalidateCommand();
  }

  async apply(): Promise<void> {
    const snapshot = this.session.data.value;
    const provider = this.selectedProvider.value;
    const profile = this.selectedProfile.value;
    if (!snapshot || !provider || !profile || !this.modelSignal.value) return;
    const current =
      snapshot.model?.provider === provider.name &&
      snapshot.model.model === this.modelSignal.value &&
      snapshot.model.auth_profile_id === profile.data.value.auth_profile_id;
    if (current) {
      this.session.acknowledgeExecution(provider.data.value.descriptor.revision);
      this.session.services.notices.set(
        "Session execution is already current. Existing history was preserved.",
      );
      this.reset();
      return;
    }
    const command = this.command ?? {
      key: this.session.services.nextId(),
      body: {
        provider: provider.data.value,
        model: this.modelSignal.value,
        profile: profile.data.value,
      },
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      await this.session.services.client.selectSessionModel(
        this.session.endpoint.id,
        this.session.id,
        command.body,
        command.key,
      );
    } catch (error) {
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.session.services.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    this.command = null;
    this.mutationSignal.value = "accepted";
    this.session.clearExecutionAcknowledgement();
    await Promise.allSettled([
      this.session.refresh(true),
      this.session.services.refreshSessionList(this.session.endpoint.id, true),
    ]);
    this.session.services.notices.set(
      "Execution updated. This session and its history were preserved.",
    );
    this.reset();
  }

  private invalidateCommand(): void {
    if (this.command?.state !== "unknown") this.command = null;
  }
}

export class Session {
  private readonly dataSignal = signal<SessionSnapshot | null>(null);
  private readonly summarySignal: Signal<SessionSummarySnapshot>;
  private readonly toolCallsSignal = signal<readonly ToolCall[]>([]);
  private readonly draftSignal = signal("");
  private readonly provisionalSignal = signal("");
  private readonly waitOutcomeSignal = signal<WaitOutcome | null>(null);
  private readonly stateSignal = signal<LoadState>("idle");
  private readonly errorSignal = signal<string | null>(null);
  private readonly sendMutationSignal = signal<MutationState>("idle");
  private readonly executionAcknowledgementSignal = signal<number | null>(null);
  private readonly toolRegistry = new Map<string, ToolCall>();
  private refreshGeneration = 0;
  private projectionRefresh: Promise<void> | null = null;
  private projectionRefreshDirty = false;
  private sendCommand: Command<{ content: string }> | null = null;

  readonly data: ReadonlySignal<SessionSnapshot | null> = this.dataSignal;
  readonly summary: ReadonlySignal<SessionSummarySnapshot>;
  readonly toolCalls: ReadonlySignal<readonly ToolCall[]> = this.toolCallsSignal;
  readonly draft: ReadonlySignal<string> = this.draftSignal;
  readonly provisionalAssistant: ReadonlySignal<string> = this.provisionalSignal;
  readonly waitOutcome: ReadonlySignal<WaitOutcome | null> = this.waitOutcomeSignal;
  readonly connection: ReadonlySignal<ConnectionState>;
  readonly connectionMessage: ReadonlySignal<string>;
  readonly state: ReadonlySignal<LoadState> = this.stateSignal;
  readonly error: ReadonlySignal<string | null> = this.errorSignal;
  readonly streamError: ReadonlySignal<string | null>;
  readonly sendMutation: ReadonlySignal<MutationState> = this.sendMutationSignal;
  readonly title: ReadonlySignal<string>;
  readonly environmentLabel: ReadonlySignal<string>;
  readonly modelLabel: ReadonlySignal<string>;
  readonly sidebarAccessibleName: ReadonlySignal<string>;
  readonly transcriptLength: ReadonlySignal<number>;
  readonly visualState: ReadonlySignal<SessionVisualState>;
  readonly executionNeedsRecovery: ReadonlySignal<boolean>;
  readonly executionUnavailableForSending: ReadonlySignal<boolean>;
  readonly executionAcknowledged: ReadonlySignal<boolean>;
  readonly profileName: ReadonlySignal<string>;
  readonly runtimeActivities: ReadonlySignal<readonly RuntimeActivity[]>;
  readonly canSend: ReadonlySignal<boolean>;
  readonly execution: SessionExecutionWorkflow;

  constructor(
    readonly endpoint: Endpoint,
    readonly id: string,
    summary: SessionSummary,
    readonly services: SessionServices,
  ) {
    this.summarySignal = signal(summary);
    this.summary = this.summarySignal;
    this.connection = endpoint.connection;
    this.streamError = endpoint.streamError;
    this.title = computed(() => {
      const first = this.dataSignal.value?.transcript.find((message) => message.role === "user");
      return first?.content.replace(/\s+/g, " ").trim() || "New session";
    });
    this.environmentLabel = this.endpoint.environmentLabel;
    this.modelLabel = computed(
      () =>
        this.dataSignal.value?.model?.model ??
        this.summarySignal.value.model?.model ??
        "Model unavailable",
    );
    this.sidebarAccessibleName = computed(
      () =>
        `${this.title.value}; environment: ${this.environmentLabel.value}; model: ${this.modelLabel.value}`,
    );
    this.transcriptLength = computed(() => this.dataSignal.value?.transcript.length ?? 0);
    this.visualState = computed(() => sessionVisualState(this));
    this.executionNeedsRecovery = computed(() => this.needsExecutionRecovery());
    this.executionUnavailableForSending = computed(() => this.sendingExecutionUnavailable());
    this.connectionMessage = computed(() => {
      const endpointStatus = this.endpoint.data.value.status.toLowerCase();
      if (/unreachable|unavailable/.test(endpointStatus)) {
        return "Endpoint unavailable; session state is non-authoritative.";
      }
      if (/^(?:online|degraded)$/.test(endpointStatus) && this.connection.value !== "Live") {
        return "Endpoint online; reconnecting event stream.";
      }
      return this.streamError.value ?? this.connection.value;
    });
    this.executionAcknowledged = computed(() => {
      const model = this.dataSignal.value?.model;
      const provider = this.services
        .providers()
        .find((candidate) => candidate.name === model?.provider);
      return (
        provider !== undefined &&
        this.executionAcknowledgementSignal.value === provider.data.value.descriptor.revision
      );
    });
    this.profileName = computed(() => this.resolveProfileName());
    this.runtimeActivities = computed(() => sessionRuntimeActivities(this));
    this.canSend = computed(
      () =>
        this.sendMutationSignal.value !== "submitting" &&
        !this.executionUnavailableForSending.value &&
        this.connection.value === "Live",
    );
    this.execution = new SessionExecutionWorkflow(this);
  }

  reconcileSummary(summary: SessionSummary): void {
    if (summary.version >= this.summarySignal.value.version) this.summarySignal.value = summary;
  }

  reconcile(snapshot: SessionDto): void {
    const current = this.dataSignal.value;
    if (current && snapshot.version <= current.version) return;
    const tools: ToolCall[] = [];
    for (const data of snapshot.tool_calls) {
      let tool = this.toolRegistry.get(data.tool_call_id);
      if (!tool) {
        tool = new ToolCall(this, data);
        this.toolRegistry.set(data.tool_call_id, tool);
      } else {
        tool.reconcile(data);
      }
      tools.push(tool);
    }
    batch(() => {
      this.dataSignal.value = snapshot;
      this.toolCallsSignal.value = tools;
      this.stateSignal.value = "ready";
      this.errorSignal.value = null;
    });
    this.execution.reset();
    this.reconcileSummary({
      session_id: snapshot.session_id,
      version: snapshot.version,
      status: snapshot.status,
      created_at_ms: this.summarySignal.value.created_at_ms,
      updated_at_ms: this.summarySignal.value.updated_at_ms,
      model: snapshot.model,
    });
  }

  setDraft(text: string): void {
    this.draftSignal.value = text;
  }

  async refresh(background = false): Promise<void> {
    const generation = ++this.refreshGeneration;
    if (!background) {
      this.stateSignal.value = this.dataSignal.value ? "stale" : "loading";
      this.errorSignal.value = null;
    }
    try {
      const snapshot = await this.services.client.getSession(this.endpoint.id, this.id);
      const current = this.dataSignal.value;
      if (generation !== this.refreshGeneration && current && current.version >= snapshot.version)
        return;
      this.reconcile(snapshot);
    } catch (error) {
      if (generation !== this.refreshGeneration) return;
      if (background) {
        this.stateSignal.value = this.dataSignal.value ? "stale" : "error";
        if (isAccessRequired(error)) this.services.notices.error(error);
      } else {
        const message = this.services.notices.error(error);
        batch(() => {
          this.stateSignal.value = this.dataSignal.value ? "stale" : "error";
          this.errorSignal.value = message;
        });
      }
      throw error;
    }
  }

  toggleConnection(): void {
    this.endpoint.toggleConnection();
  }

  async send(): Promise<void> {
    const content = this.draftSignal.value.trim();
    if (!content || this.sendMutationSignal.value === "submitting") return;
    if (this.executionUnavailableForSending.value || this.connection.value !== "Live") return;
    if (this.sendCommand && this.sendCommand.body.content !== content) this.sendCommand = null;
    const command = this.sendCommand ?? {
      key: this.services.nextId(),
      body: { content },
      state: "idle" as MutationState,
    };
    this.sendCommand = command;
    command.state = "submitting";
    this.sendMutationSignal.value = "submitting";
    try {
      await this.services.client.sendMessage(
        this.endpoint.id,
        this.id,
        command.body.content,
        command.key,
      );
    } catch (error) {
      command.state = "unknown";
      this.sendMutationSignal.value = "unknown";
      this.services.notices.error(error);
      throw error;
    }
    command.state = "accepted";
    batch(() => {
      if (this.draftSignal.value.trim() === command.body.content) this.draftSignal.value = "";
      this.sendMutationSignal.value = "accepted";
    });
    await Promise.allSettled([
      this.refresh(true),
      this.services.refreshSessionList(this.endpoint.id, true),
    ]);
    this.sendCommand = null;
    this.sendMutationSignal.value = "idle";
  }

  async admitInitialMessage(content: string, idempotencyKey: string): Promise<void> {
    this.draftSignal.value = content;
    if (!this.sendCommand) {
      this.sendCommand = {
        key: idempotencyKey,
        body: { content: content.trim() },
        state: "idle",
      };
    }
    await this.send();
  }

  private resolveProfileName(): string {
    const model = this.dataSignal.value?.model;
    if (!model) return "Profile unavailable";
    const profile = this.services
      .providers()
      .find((provider) => provider.name === model.provider)
      ?.profiles.value.find((candidate) => {
        const data = candidate.data.value;
        return (
          data.auth_profile_id === model.auth_profile_id ||
          data.profile_id === model.auth_profile_id
        );
      });
    return profile?.displayLabel.value ?? "Profile";
  }

  acknowledgeExecution(revision: number): void {
    this.executionAcknowledgementSignal.value = revision;
  }

  clearExecutionAcknowledgement(): void {
    this.executionAcknowledgementSignal.value = null;
  }

  private needsExecutionRecovery(): boolean {
    const snapshot = this.dataSignal.value;
    const model = snapshot?.model;
    if (!model || this.services.providersState() === "error") return true;
    const provider = this.services
      .providers()
      .find((candidate) => candidate.name === model.provider);
    if (
      !provider ||
      provider.error.value ||
      !provider.data.value.descriptor.models.includes(model.model)
    ) {
      return true;
    }
    const descriptor = provider.data.value.descriptor;
    const hasDescriptor =
      model.provider_execution_schema !== undefined ||
      model.provider_execution_revision !== undefined ||
      model.provider_execution_kind !== undefined ||
      model.provider_execution_base_url !== undefined ||
      model.provider_execution_options !== undefined;
    if (
      hasDescriptor &&
      (model.provider_execution_schema !== "zode.provider-execution.v1" ||
        model.provider_execution_revision !== descriptor.revision ||
        model.provider_execution_kind !== descriptor.kind ||
        model.provider_execution_base_url !== descriptor.base_url ||
        JSON.stringify(model.provider_execution_options ?? {}) !==
          JSON.stringify(descriptor.options))
    ) {
      return true;
    }
    return this.sendingExecutionUnavailable();
  }

  private sendingExecutionUnavailable(): boolean {
    const model = this.dataSignal.value?.model;
    if (!model || this.services.providersState() === "error") return true;
    const provider = this.services
      .providers()
      .find((candidate) => candidate.name === model.provider);
    if (
      !provider ||
      provider.error.value ||
      !provider.data.value.descriptor.models.includes(model.model)
    ) {
      return true;
    }
    const profile = provider.profiles.value.find((candidate) => {
      const data = candidate.data.value;
      return (
        data.auth_profile_id === model.auth_profile_id || data.profile_id === model.auth_profile_id
      );
    });
    return !profile || !profileIsUsableOnEndpoint(profile, this.endpoint.id);
  }

  acceptTransientText(text: string): void {
    this.provisionalSignal.value += text;
  }

  acceptDurableEvent(eventName: string, payload: PublicEvent): void {
    if (payload.session_id !== this.id) return;
    const message = payload.data?.message;
    if (eventName === "wait_expired") {
      const waitId = typeof payload.data.wait_id === "string" ? payload.data.wait_id : "";
      if (waitId) {
        this.waitOutcomeSignal.value = {
          status: "timed_out",
          waitId,
          reason: this.dataSignal.value?.wait?.reason ?? "Wait deadline reached",
        };
      }
    } else if (
      eventName === "wait_set" ||
      eventName === "wait_cleared" ||
      (eventName === "message_appended" &&
        typeof message === "object" &&
        message !== null &&
        "role" in message &&
        (message as { role?: unknown }).role === "user")
    ) {
      this.waitOutcomeSignal.value = null;
    }
    const assistantAppended =
      eventName === "message_appended" &&
      typeof message === "object" &&
      message !== null &&
      "role" in message &&
      (message as { role?: unknown }).role === "assistant";
    if (PROVISIONAL_TERMINALS.has(eventName) || assistantAppended) {
      this.provisionalSignal.value = "";
    }
    this.queueProjectionRefresh();
  }

  private queueProjectionRefresh(): void {
    this.projectionRefreshDirty = true;
    if (this.projectionRefresh) return;
    this.projectionRefresh = Promise.resolve()
      .then(async () => {
        while (this.projectionRefreshDirty) {
          this.projectionRefreshDirty = false;
          await this.refresh(true).catch(() => undefined);
        }
      })
      .finally(() => {
        this.projectionRefresh = null;
        if (this.projectionRefreshDirty) this.queueProjectionRefresh();
      });
  }
}

function defaultProfileId(
  provider: Provider | undefined,
  endpointId: string,
  currentProfileId?: string,
): string {
  if (!provider) return "";
  const available = provider.profiles.value.filter((profile) =>
    profileIsUsableOnEndpoint(profile, endpointId),
  );
  return (
    available.find((profile) => {
      const data = profile.data.value;
      return data.auth_profile_id === currentProfileId || data.profile_id === currentProfileId;
    })?.data.value.auth_profile_id ??
    available.find((profile) => {
      const data = profile.data.value;
      return (
        data.auth_profile_id === provider.data.value.default_profile_id ||
        data.profile_id === provider.data.value.default_profile_id
      );
    })?.data.value.auth_profile_id ??
    available.find((profile) => profile.data.value.is_default)?.data.value.auth_profile_id ??
    available[0]?.data.value.auth_profile_id ??
    ""
  );
}

function sessionVisualState(session: Session): SessionVisualState {
  if (session.connection.value === "Connecting") return "connecting";
  if (session.connection.value === "Reconnecting") return "reconnecting";
  if (session.connection.value !== "Live") return "disconnected";
  const snapshot = session.data.value;
  if (!snapshot) return undefined;
  if (snapshot.last_model_attempts_exhausted) return "error";
  if (snapshot.tool_calls.some((tool) => ["failed", "unknown_outcome"].includes(tool.status))) {
    return "error";
  }
  if (snapshot.wait) return "waiting";
  if (
    snapshot.tool_calls.some(
      (tool) => !["completed", "failed", "cancelled", "unknown_outcome"].includes(tool.status),
    )
  ) {
    return "tool";
  }
  if (snapshot.active_activation) return "streaming";
  return undefined;
}

function sessionRuntimeActivities(session: Session): readonly RuntimeActivity[] {
  const snapshot = session.data.value;
  if (!snapshot) return [];
  const declaredToolCallIds = new Set(
    snapshot.transcript.flatMap((message) => [
      ...(message.tool_calls ?? []).map((call) => call.tool_call_id),
      ...(message.tool_call_id ? [message.tool_call_id] : []),
    ]),
  );
  const activities: RuntimeActivity[] = [];
  if (snapshot.last_model_attempts_exhausted) {
    const exhausted = snapshot.last_model_attempts_exhausted;
    activities.push({
      key: "model-attempts-exhausted",
      icon: "warning",
      title: "Activation failed",
      detail: `Model attempts exhausted (${exhausted.attempt_number ?? "?"}/${exhausted.maximum_attempts ?? "?"})`,
      attention: true,
      alert: true,
    });
  } else if (snapshot.active_model_round?.attempt?.outcome === "failed") {
    const retry = snapshot.active_model_round.retry;
    activities.push({
      key: "model-retrying",
      icon: "arrows-clockwise",
      title: "Retrying",
      detail: retry
        ? `${retry.error_class ?? "Model error"} · attempt ${retry.next_attempt_number ?? "?"}/${retry.maximum_attempts ?? "?"}`
        : "Model request failed; preparing a retry",
      attention: true,
      alert: true,
    });
  }
  if (snapshot.wait) {
    activities.push({
      key: "wait",
      icon: "clock",
      title: "Waiting",
      detail: snapshot.wait.deadline_ms
        ? `${snapshot.wait.reason ?? "Awaiting an external result"} · until ${new Date(snapshot.wait.deadline_ms).toLocaleTimeString()}`
        : (snapshot.wait.reason ?? "Awaiting an external result"),
    });
  } else if (session.waitOutcome.value?.status === "timed_out") {
    activities.push({
      key: `wait:${session.waitOutcome.value.waitId}`,
      icon: "clock",
      title: "Wait timed out",
      detail: session.waitOutcome.value.reason,
      attention: true,
    });
  }
  for (const tool of session.toolCalls.value) {
    const status = tool.rawStatus.value;
    if (
      status === "completed" ||
      (declaredToolCallIds.has(tool.id) && !["failed", "unknown_outcome"].includes(status))
    )
      continue;
    const attention = status === "unknown_outcome" || status === "failed";
    activities.push({
      key: `tool:${tool.id}`,
      icon: status === "unknown_outcome" ? "warning" : "wrench",
      title: tool.name.value,
      detail: tool.description.value,
      ariaLabel: `${tool.name.value} ${tool.status.value}`,
      attention,
      alert: attention,
      tool,
    });
  }
  if (snapshot.active_activation && !snapshot.last_model_attempts_exhausted) {
    activities.push({
      key: "activation",
      icon: "spinner-gap",
      title: "Working",
      detail: "Model activation in progress",
    });
  }
  return activities;
}
