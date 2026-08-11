import { batch, computed, signal, type ReadonlySignal } from "@preact/signals-core";

import {
  ServerClient,
  ServerClientError,
  type AuthProfile as AuthProfileDto,
  type Provider as ProviderDto,
} from "../api/server";
import { endpointIsUsable, type Endpoint } from "./endpoint";
import {
  executionChoiceMatches,
  modelExecutionGroups,
  type ExecutionChoice,
  type ModelExecutionGroup,
} from "./execution";
import type { LoadState, MutationState, NoticeSink } from "./ports";
import { profileIsUsableOnEndpoint, type AuthProfile, type Provider } from "./provider";
import type { Session } from "./session";

type CreateCommand = {
  key: string;
  body: {
    endpointId: string;
    provider: ProviderDto;
    model: string;
    profile: AuthProfileDto;
  };
  message: string;
  messageKey: string | null;
  state: MutationState;
};

export interface NewSessionServices {
  client: ServerClient;
  notices: NoticeSink;
  nextId(): string;
  endpoints(): readonly Endpoint[];
  providers(): readonly Provider[];
  endpointsState(): LoadState;
  providersState(): LoadState;
  endpointError(): string | null;
  providerError(): string | null;
  refreshProviders(): Promise<void>;
  openCreatedSession(endpointId: string, sessionId: string): Promise<Session>;
}

export class NewSessionWorkflow {
  private readonly endpointSignal = signal("");
  private readonly providerSignal = signal("");
  private readonly modelSignal = signal("");
  private readonly profileSignal = signal("");
  private readonly messageSignal = signal("");
  private readonly mutationSignal = signal<MutationState>("idle");
  private command: CreateCommand | null = null;

  readonly endpoint: ReadonlySignal<string> = this.endpointSignal;
  readonly provider: ReadonlySignal<string> = this.providerSignal;
  readonly model: ReadonlySignal<string> = this.modelSignal;
  readonly profile: ReadonlySignal<string> = this.profileSignal;
  readonly message: ReadonlySignal<string> = this.messageSignal;
  readonly mutation: ReadonlySignal<MutationState> = this.mutationSignal;
  readonly endpointOptions: ReadonlySignal<
    readonly { value: string; label: string; disabled: boolean }[]
  >;
  readonly providerOptions: ReadonlySignal<readonly { value: string; label: string }[]>;
  readonly modelOptions: ReadonlySignal<readonly { value: string; label: string }[]>;
  readonly profileOptions: ReadonlySignal<readonly { value: string; label: string }[]>;
  readonly executionGroups: ReadonlySignal<readonly ModelExecutionGroup[]>;
  readonly selectedExecution: ReadonlySignal<ExecutionChoice | null>;
  readonly selectedEndpoint: ReadonlySignal<Endpoint | null>;
  readonly selectedProvider: ReadonlySignal<Provider | null>;
  readonly selectedProfile: ReadonlySignal<AuthProfile | null>;
  readonly ready: ReadonlySignal<boolean>;
  readonly setupHint: ReadonlySignal<string | null>;

  constructor(private readonly services: NewSessionServices) {
    this.endpointOptions = computed(() =>
      services.endpoints().map((endpoint) => ({
        value: endpoint.id,
        label: `${endpoint.data.value.kind === "local" ? "This machine" : endpoint.data.value.label}${
          endpointIsUsable(endpoint) ? "" : " · unavailable"
        }`,
        disabled: !endpointIsUsable(endpoint),
      })),
    );
    this.providerOptions = computed(() =>
      services.providers().map((provider) => ({ value: provider.name, label: provider.name })),
    );
    this.selectedEndpoint = computed(
      () =>
        services
          .endpoints()
          .find(
            (endpoint) => endpoint.id === this.endpointSignal.value && endpointIsUsable(endpoint),
          ) ??
        services.endpoints().find(endpointIsUsable) ??
        null,
    );
    this.selectedProvider = computed(
      () =>
        services.providers().find((provider) => provider.name === this.providerSignal.value) ??
        services.providers()[0] ??
        null,
    );
    this.modelOptions = computed(() =>
      (this.selectedProvider.value?.data.value.descriptor.models ?? []).map((model) => ({
        value: model,
        label: model,
      })),
    );
    this.profileOptions = computed(() =>
      (this.selectedProvider.value?.profiles.value ?? [])
        .filter(
          (profile) =>
            this.selectedEndpoint.value !== null &&
            profileIsUsableOnEndpoint(profile, this.selectedEndpoint.value.id),
        )
        .map((profile) => ({
          value: profile.data.value.profile_id,
          label: profile.displayLabel.value,
        })),
    );
    this.selectedProfile = computed(() => {
      const provider = this.selectedProvider.value;
      const endpoint = this.selectedEndpoint.value;
      if (!provider || !endpoint) return null;
      const available = provider.profiles.value.filter((profile) =>
        profileIsUsableOnEndpoint(profile, endpoint.id),
      );
      return (
        available.find((profile) => {
          const data = profile.data.value;
          return (
            data.profile_id === this.profileSignal.value ||
            data.auth_profile_id === this.profileSignal.value
          );
        }) ??
        available.find((profile) => {
          const data = profile.data.value;
          return (
            data.profile_id === provider.data.value.default_profile_id ||
            data.auth_profile_id === provider.data.value.default_profile_id
          );
        }) ??
        available.find((profile) => profile.data.value.is_default) ??
        available[0] ??
        null
      );
    });
    this.executionGroups = computed(() =>
      modelExecutionGroups(services.providers(), this.selectedEndpoint.value?.id ?? ""),
    );
    this.selectedExecution = computed(
      () =>
        this.executionGroups.value
          .flatMap((group) => group.choices)
          .find((choice) =>
            executionChoiceMatches(
              choice,
              this.currentProvider(),
              this.currentModel(),
              this.currentProfile(),
            ),
          ) ?? null,
    );
    this.setupHint = computed(() => {
      const endpoints = services.endpoints();
      const providers = services.providers();
      const endpoint = this.selectedEndpoint.value;
      const provider = this.selectedProvider.value;
      if (services.endpointsState() === "loading") return "Loading Endpoints…";
      if (services.endpointError() && endpoints.length === 0) {
        return "Endpoint inventory is unavailable. Try again from Manage.";
      }
      if (services.providersState() === "loading") return "Loading providers…";
      if (services.providerError()) {
        return "Provider inventory is unavailable. Try again from Manage.";
      }
      if (provider?.error.value) return "Auth profiles are unavailable. Try again from Manage.";
      if (endpoints.length === 0) return "Add an Endpoint from Manage to start a session.";
      if (!endpoint) return "No reachable Endpoint is available.";
      if (providers.length === 0) {
        return "Configure a provider from Manage to start a session.";
      }
      if (this.modelOptions.value.length === 0) {
        return "The selected provider has no available models.";
      }
      if (this.profileOptions.value.length > 0) return null;
      const pending = provider?.profiles.value.find((profile) => {
        const data = profile.data.value;
        return data.sharing.mode !== "none" && data.sharing.endpoint_ids.includes(endpoint.id);
      });
      const data = pending?.data.value;
      const replica = data?.distribution.find((candidate) => candidate.endpoint_id === endpoint.id);
      return pending
        ? `${data?.label ?? "The shared profile"} is ${(
            replica?.status ??
            data?.status ??
            "not ready"
          ).replaceAll("_", " ")} on this Endpoint.`
        : "Share a ready auth profile with this Endpoint to start a session.";
    });
    this.ready = computed(() => this.setupHint.value === null);
  }

  currentEndpoint(): string {
    return this.selectedEndpoint.value?.id ?? "";
  }

  currentProvider(): string {
    return this.selectedProvider.value?.name ?? "";
  }

  currentModel(): string {
    const models = this.selectedProvider.value?.data.value.descriptor.models ?? [];
    return models.includes(this.modelSignal.value) ? this.modelSignal.value : (models[0] ?? "");
  }

  currentProfile(): string {
    return this.selectedProfile.value?.data.value.profile_id ?? "";
  }

  setEndpoint(value: string): void {
    batch(() => {
      this.endpointSignal.value = value;
      this.profileSignal.value = "";
    });
    this.invalidateCommand();
  }

  setProvider(value: string): void {
    batch(() => {
      this.providerSignal.value = value;
      this.modelSignal.value = "";
      this.profileSignal.value = "";
    });
    this.invalidateCommand();
  }

  setModel(value: string): void {
    this.modelSignal.value = value;
    this.invalidateCommand();
  }

  setProfile(value: string): void {
    this.profileSignal.value = value;
    this.invalidateCommand();
  }

  selectExecution(choice: ExecutionChoice): void {
    batch(() => {
      this.providerSignal.value = choice.provider.name;
      this.modelSignal.value = choice.model;
      this.profileSignal.value = choice.profile.data.value.profile_id;
    });
    this.invalidateCommand();
  }

  setMessage(value: string): void {
    this.messageSignal.value = value;
    if (this.command?.state !== "unknown") this.invalidateCommand();
  }

  async submit(): Promise<void> {
    const endpoint = this.selectedEndpoint.value;
    const provider = this.selectedProvider.value;
    const profile = this.selectedProfile.value;
    const model = this.currentModel();
    if (!this.command && (!endpoint || !provider || !profile || !model)) return;
    const message = this.messageSignal.value.trim();
    const command = this.command ?? {
      key: this.services.nextId(),
      body: {
        endpointId: endpoint?.id ?? "",
        provider: provider?.data.value as ProviderDto,
        model,
        profile: profile?.data.value as AuthProfileDto,
      },
      message,
      messageKey: message ? this.services.nextId() : null,
      state: "idle" as MutationState,
    };
    this.command = command;
    command.state = "submitting";
    this.mutationSignal.value = "submitting";
    try {
      const created = await this.services.client.createSession(
        command.body.endpointId,
        command.body,
        command.key,
      );
      command.state = "accepted";
      const session = await this.services.openCreatedSession(
        command.body.endpointId,
        created.session_id,
      );
      this.command = null;
      batch(() => {
        this.messageSignal.value = "";
        this.mutationSignal.value = "idle";
      });
      if (command.message && command.messageKey) {
        await session.admitInitialMessage(command.message, command.messageKey);
      }
    } catch (error) {
      let failure = error;
      if (error instanceof ServerClientError && error.code === "invalid_request") {
        try {
          await this.services.refreshProviders();
          const latest = this.services
            .providers()
            .find((provider) => provider.name === command.body.provider.provider);
          if (
            latest &&
            latest.data.value.descriptor.revision > command.body.provider.descriptor.revision
          ) {
            this.command = null;
            this.mutationSignal.value = "idle";
            this.services.notices.set(
              "The provider configuration changed while this form was open. The latest selection is loaded; review it and try again.",
            );
            return;
          }
        } catch (refreshError) {
          failure = refreshError;
        }
      }
      command.state = "unknown";
      this.mutationSignal.value = "unknown";
      this.services.notices.error(failure);
      throw failure;
    }
  }

  private invalidateCommand(): void {
    if (this.command?.state !== "unknown") this.command = null;
  }
}
