import { signal } from "@preact/signals-react";

import type {
  AuthProfile,
  Endpoint,
  Provider,
  Session,
  SessionSummary,
  SystemResponse,
} from "./api/server";

export type View = "sessions" | "endpoints" | "providers" | "settings" | "session" | "not_found";
export type Panel = "endpoint" | "provider" | "profile" | null;
export type Connection = "Connecting" | "Live" | "Reconnecting" | "Disconnected";

export const system = signal<SystemResponse | null>(null);
export const endpoints = signal<Endpoint[]>([]);
export const providers = signal<Provider[]>([]);
export const providersLoading = signal(false);
export const providerListError = signal<string | null>(null);
export const profiles = signal<Map<string, AuthProfile[]>>(new Map());
export const profileListErrors = signal<Map<string, string>>(new Map());
export const sessions = signal<Map<string, SessionSummary[]>>(new Map());
export const sessionsLoading = signal(false);
export const sessionLoadingByEndpoint = signal<Map<string, number>>(new Map());
export const sessionTitles = signal<Map<string, string>>(new Map());
export const sessionTitleErrors = signal<Map<string, string>>(new Map());
export const sessionListErrors = signal<Map<string, string>>(new Map());
export const endpointsLoading = signal(false);
export const endpointInventoryError = signal<string | null>(null);
export const activeSession = signal<Session | null>(null);
export const activeEndpointId = signal<string | null>(null);
export const activeSessionId = signal<string | null>(null);
export const sessionLoading = signal(false);
export const sessionError = signal<string | null>(null);
export const view = signal<View>("sessions");
export const panel = signal<Panel>(null);
export const panelProvider = signal<string | null>(null);
export const managementMenuOpen = signal(false);
export const sidebarCollapsed = signal(window.matchMedia("(max-width: 760px)").matches);
export const homeEndpointSelection = signal<string | null>(
  new URLSearchParams(window.location.search).get("endpoint"),
);
export const canGoBack = signal(false);
export const canGoForward = signal(false);
export const busy = signal(false);
export const notice = signal<string | null>(null);
export const retryActions = signal<Map<string, () => void>>(new Map());
export const connection = signal<Connection>("Disconnected");
export const sessionRetryAvailable = signal(false);
export const bootstrapError = signal<string | null>(null);
export const bootstrapReady = signal(false);
export const executionRecoveryAcknowledgement = signal<{
  sessionKey: string;
  providerRevision: number;
} | null>(null);
export const composerDraft = signal<{
  endpointId: string;
  sessionId: string;
  text: string;
} | null>(null);
export const provisionalAssistant = signal<{ sessionId: string; text: string } | null>(null);
