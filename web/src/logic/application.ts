import { batch, computed, signal, type ReadonlySignal } from "@preact/signals-core";

import { ServerClient } from "../api/server";
import { Endpoint, EndpointRegistrationWorkflow } from "./endpoint";
import { Navigation, type Route } from "./navigation";
import {
  friendlyErrorCode,
  isAccessRequired,
  type BrowserNavigationPort,
  type ClockPort,
  type CursorStore,
  type LoadState,
  type NoticeKind,
  type NoticeSink,
} from "./ports";
import { Provider, ProviderConfigurationWorkflow } from "./provider";
import { type Session, type SessionServices } from "./session";
import { Settings } from "./settings";
import { NewSessionWorkflow } from "./workflows";

export type RecentSession = { endpoint: Endpoint; session: Session };

export class ZodeApplication implements NoticeSink {
  private readonly endpointsSignal = signal<readonly Endpoint[]>([]);
  private readonly providersSignal = signal<readonly Provider[]>([]);
  private readonly endpointsStateSignal = signal<LoadState>("idle");
  private readonly providersStateSignal = signal<LoadState>("idle");
  private readonly endpointErrorSignal = signal<string | null>(null);
  private readonly providerErrorSignal = signal<string | null>(null);
  private readonly readySignal = signal(false);
  private readonly bootstrapErrorSignal = signal<string | null>(null);
  private readonly noticeSignal = signal<string | null>(null);
  private readonly noticeKindSignal = signal<NoticeKind>("status");
  private readonly activeEndpointSignal = signal<Endpoint | null>(null);
  private readonly activeSessionSignal = signal<Session | null>(null);
  private readonly endpointRegistry = new Map<string, Endpoint>();
  private readonly providerRegistry = new Map<string, Provider>();
  private routeGeneration = 0;
  private endpointsGeneration = 0;
  private providersGeneration = 0;
  private accessReentryStarted = false;
  private started = false;

  readonly endpoints: ReadonlySignal<readonly Endpoint[]> = this.endpointsSignal;
  readonly providers: ReadonlySignal<readonly Provider[]> = this.providersSignal;
  readonly endpointsState: ReadonlySignal<LoadState> = this.endpointsStateSignal;
  readonly providersState: ReadonlySignal<LoadState> = this.providersStateSignal;
  readonly endpointError: ReadonlySignal<string | null> = this.endpointErrorSignal;
  readonly providerError: ReadonlySignal<string | null> = this.providerErrorSignal;
  readonly ready: ReadonlySignal<boolean> = this.readySignal;
  readonly bootstrapError: ReadonlySignal<string | null> = this.bootstrapErrorSignal;
  readonly notice: ReadonlySignal<string | null> = this.noticeSignal;
  readonly noticeKind: ReadonlySignal<NoticeKind> = this.noticeKindSignal;
  readonly activeEndpoint: ReadonlySignal<Endpoint | null> = this.activeEndpointSignal;
  readonly activeSession: ReadonlySignal<Session | null> = this.activeSessionSignal;
  readonly recentSessions: ReadonlySignal<readonly RecentSession[]>;
  readonly sessionsLoading: ReadonlySignal<boolean>;
  readonly settings: Settings;
  readonly navigation: Navigation;
  readonly providerConfiguration: ProviderConfigurationWorkflow;
  readonly endpointRegistration: EndpointRegistrationWorkflow;
  readonly newSession: NewSessionWorkflow;

  constructor(
    private readonly client: ServerClient,
    private readonly browser: BrowserNavigationPort,
    private readonly cursor: CursorStore,
    private readonly clock: ClockPort,
    private readonly nextId: () => string,
  ) {
    this.settings = new Settings(client, this);
    this.navigation = new Navigation(browser, (route) => {
      void this.applyRoute(route);
    });
    this.providerConfiguration = new ProviderConfigurationWorkflow(client, this, nextId, () =>
      this.refreshProviders(),
    );
    this.endpointRegistration = new EndpointRegistrationWorkflow(client, this, nextId, () =>
      this.refreshEndpoints(),
    );
    this.newSession = new NewSessionWorkflow({
      client,
      notices: this,
      nextId,
      endpoints: () => this.endpointsSignal.value,
      providers: () => this.providersSignal.value,
      endpointsState: () => this.endpointsStateSignal.value,
      providersState: () => this.providersStateSignal.value,
      endpointError: () => this.endpointErrorSignal.value,
      providerError: () => this.providerErrorSignal.value,
      refreshProviders: () => this.refreshProviders(),
      openCreatedSession: (endpointId, sessionId) => this.openCreatedSession(endpointId, sessionId),
    });
    this.recentSessions = computed(() =>
      this.endpointsSignal.value
        .flatMap((endpoint) => endpoint.sessions.value.map((session) => ({ endpoint, session })))
        .sort((left, right) => {
          const leftSummary = left.session.summary.value;
          const rightSummary = right.session.summary.value;
          const time =
            (rightSummary.updated_at_ms ?? rightSummary.created_at_ms) -
            (leftSummary.updated_at_ms ?? leftSummary.created_at_ms);
          return time || right.session.id.localeCompare(left.session.id);
        })
        .slice(0, 20),
    );
    this.sessionsLoading = computed(() =>
      this.endpointsSignal.value.some((endpoint) => endpoint.sessionsState.value === "loading"),
    );
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.bootstrapErrorSignal.value = null;
    void this.bootstrap();
  }

  dispose(): void {
    this.navigation.dispose();
    for (const endpoint of this.endpointRegistry.values()) endpoint.dispose();
    for (const provider of this.providerRegistry.values()) provider.dispose();
  }

  async retryBootstrap(): Promise<void> {
    this.bootstrapErrorSignal.value = null;
    await this.bootstrap();
  }

  set(message: string | null, kind: NoticeKind = "status"): void {
    batch(() => {
      this.noticeSignal.value = message;
      this.noticeKindSignal.value = kind;
    });
  }

  error(error: unknown): string {
    if (isAccessRequired(error)) {
      if (!this.accessReentryStarted) {
        this.accessReentryStarted = true;
        for (const endpoint of this.endpointRegistry.values()) endpoint.dispose();
        for (const provider of this.providerRegistry.values()) provider.dispose();
        this.browser.assignCurrent();
      }
      return "Access re-entry required.";
    }
    const message = friendlyErrorCode(error);
    this.set(message, "error");
    return message;
  }

  clearNotice(): void {
    this.set(null);
  }

  provider(name: string): Provider | undefined {
    return this.providerRegistry.get(name);
  }

  endpoint(id: string): Endpoint | undefined {
    return this.endpointRegistry.get(id);
  }

  async refreshEndpoints(): Promise<void> {
    const generation = ++this.endpointsGeneration;
    this.endpointsStateSignal.value = this.endpointsSignal.value.length > 0 ? "stale" : "loading";
    this.endpointErrorSignal.value = null;
    try {
      const records = await this.client.listEndpoints();
      if (generation !== this.endpointsGeneration) return;
      const endpoints: Endpoint[] = [];
      for (const record of records) {
        let endpoint = this.endpointRegistry.get(record.endpoint_id);
        if (!endpoint) {
          endpoint = new Endpoint(
            record,
            this.client,
            this,
            this.cursor,
            this.clock,
            this.sessionServices(),
          );
          this.endpointRegistry.set(record.endpoint_id, endpoint);
          endpoint.start();
        } else {
          endpoint.reconcile(record);
        }
        endpoints.push(endpoint);
      }
      batch(() => {
        this.endpointsSignal.value = endpoints;
        this.endpointsStateSignal.value = "ready";
        this.endpointErrorSignal.value = null;
      });
    } catch (error) {
      if (generation !== this.endpointsGeneration) return;
      const message = this.error(error);
      batch(() => {
        this.endpointsStateSignal.value = this.endpointsSignal.value.length > 0 ? "stale" : "error";
        this.endpointErrorSignal.value = message;
      });
      throw error;
    }
  }

  async refreshProviders(): Promise<void> {
    const generation = ++this.providersGeneration;
    this.providersStateSignal.value = this.providersSignal.value.length > 0 ? "stale" : "loading";
    this.providerErrorSignal.value = null;
    try {
      const records = await this.client.listProviders();
      if (generation !== this.providersGeneration) return;
      const providers: Provider[] = [];
      for (const record of records) {
        let provider = this.providerRegistry.get(record.provider);
        if (!provider) {
          provider = new Provider(record, this.client, this, this.nextId, this.clock, this.browser);
          this.providerRegistry.set(record.provider, provider);
        } else {
          provider.reconcile(record);
        }
        providers.push(provider);
      }
      const present = new Set(providers.map((provider) => provider.name));
      for (const [name, provider] of this.providerRegistry) {
        if (present.has(name)) continue;
        provider.dispose();
        this.providerRegistry.delete(name);
      }
      this.providersSignal.value = providers;
      const results = await Promise.allSettled(providers.map((provider) => provider.refresh()));
      if (generation !== this.providersGeneration) return;
      const failed = results.some((result) => result.status === "rejected");
      batch(() => {
        this.providersStateSignal.value = failed ? "stale" : "ready";
        this.providerErrorSignal.value = null;
      });
    } catch (error) {
      if (generation !== this.providersGeneration) return;
      const message = this.error(error);
      batch(() => {
        this.providersStateSignal.value = this.providersSignal.value.length > 0 ? "stale" : "error";
        this.providerErrorSignal.value = message;
      });
      throw error;
    }
  }

  async refreshSessions(endpointId?: string): Promise<void> {
    const endpoints = endpointId
      ? this.endpointsSignal.value.filter((endpoint) => endpoint.id === endpointId)
      : this.endpointsSignal.value;
    await Promise.allSettled(endpoints.map((endpoint) => endpoint.refreshSessions()));
  }

  async retryRoute(): Promise<void> {
    await this.applyRoute(this.navigation.route.value);
  }

  async openCreatedSession(endpointId: string, sessionId: string): Promise<Session> {
    let endpoint = this.endpointRegistry.get(endpointId);
    if (!endpoint) {
      const record = await this.client.getEndpoint(endpointId);
      endpoint = new Endpoint(
        record,
        this.client,
        this,
        this.cursor,
        this.clock,
        this.sessionServices(),
      );
      this.endpointRegistry.set(endpointId, endpoint);
      this.endpointsSignal.value = [...this.endpointsSignal.value, endpoint];
      endpoint.start();
    }
    const session = endpoint.getOrCreateSession(sessionId);
    this.navigation.navigate(
      `/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}`,
    );
    await session.refresh();
    batch(() => {
      this.activeEndpointSignal.value = endpoint;
      this.activeSessionSignal.value = session;
    });
    await endpoint.refreshSessions().catch(() => undefined);
    return session;
  }

  private async bootstrap(): Promise<void> {
    try {
      await this.settings.refresh();
      this.readySignal.value = true;
      this.navigation.start();
    } catch (error) {
      if (!isAccessRequired(error)) this.bootstrapErrorSignal.value = friendlyErrorCode(error);
    }
  }

  private async applyRoute(route: Route): Promise<void> {
    const generation = ++this.routeGeneration;
    const previousSession = this.activeSessionSignal.value;
    if (
      route.view === "session" &&
      route.endpointId &&
      route.sessionId &&
      previousSession &&
      (previousSession.endpoint.id !== route.endpointId || previousSession.id !== route.sessionId)
    ) {
      previousSession.setDraft("");
    }
    if (route.view !== "session") {
      batch(() => {
        this.activeEndpointSignal.value = null;
        this.activeSessionSignal.value = null;
      });
    }
    try {
      if (route.view === "session" && route.endpointId && route.sessionId) {
        await Promise.allSettled([this.refreshProviders(), this.ensureEndpoint(route.endpointId)]);
        if (generation !== this.routeGeneration) return;
        const endpoint = await this.ensureEndpoint(route.endpointId);
        if (generation !== this.routeGeneration) return;
        const session = endpoint.getOrCreateSession(route.sessionId);
        batch(() => {
          this.activeEndpointSignal.value = endpoint;
          this.activeSessionSignal.value = session;
        });
        await endpoint.loadSession(route.sessionId);
        return;
      }
      if (
        route.view === "sessions" ||
        route.view === "endpoints" ||
        route.view === "providers" ||
        route.view === "settings"
      ) {
        await Promise.allSettled([
          this.refreshEndpoints(),
          this.refreshProviders(),
          ...(route.view === "settings" ? [this.settings.refresh()] : []),
        ]);
        if (generation !== this.routeGeneration) return;
        if (route.view === "providers") await this.restoreOAuthAttempt(route.path);
        if (generation !== this.routeGeneration) return;
        await this.refreshSessions();
      }
    } catch (error) {
      this.error(error);
    }
  }

  private async ensureEndpoint(endpointId: string): Promise<Endpoint> {
    const known = this.endpointRegistry.get(endpointId);
    if (known) return known;
    const record = await this.client.getEndpoint(endpointId);
    const endpoint = new Endpoint(
      record,
      this.client,
      this,
      this.cursor,
      this.clock,
      this.sessionServices(),
    );
    this.endpointRegistry.set(endpointId, endpoint);
    this.endpointsSignal.value = [...this.endpointsSignal.value, endpoint];
    endpoint.start();
    return endpoint;
  }

  private async restoreOAuthAttempt(path: string): Promise<void> {
    const attemptId = new URL(path, "http://zode.invalid").searchParams.get("oauth_attempt");
    if (!attemptId) return;
    const data = await this.client.getOAuthAttempt(attemptId);
    const provider = this.providerRegistry.get(data.provider);
    if (!provider) throw new Error("OAuth attempt provider is not configured");
    provider.reconcileOAuthAttempt(data);
  }

  private sessionServices(): Omit<SessionServices, "refreshSessionList"> {
    return {
      client: this.client,
      notices: this,
      nextId: this.nextId,
      providers: () => this.providersSignal.value,
      providersState: () => this.providersStateSignal.value,
    };
  }
}
