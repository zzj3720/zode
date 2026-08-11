import { batch, signal, type ReadonlySignal, type Signal } from "@preact/signals-core";

import type { BrowserNavigationPort } from "./ports";

export type View = "sessions" | "endpoints" | "providers" | "settings" | "session" | "not_found";

export type Route = {
  view: View;
  endpointId: string | null;
  sessionId: string | null;
  path: string;
};

export class Navigation {
  private readonly routeSignal: Signal<Route>;
  private readonly canGoBackSignal = signal(false);
  private readonly canGoForwardSignal = signal(false);
  private readonly entries: string[];
  private index = 0;
  private removePopState: (() => void) | null = null;

  readonly route: ReadonlySignal<Route>;
  readonly canGoBack: ReadonlySignal<boolean> = this.canGoBackSignal;
  readonly canGoForward: ReadonlySignal<boolean> = this.canGoForwardSignal;

  constructor(
    private readonly browser: BrowserNavigationPort,
    private readonly onRoute: (route: Route) => void,
  ) {
    const route = parseRoute(browser.path);
    this.routeSignal = signal(route);
    this.route = this.routeSignal;
    this.entries = [route.path];
  }

  start(): void {
    if (this.removePopState) return;
    this.removePopState = this.browser.onPopState(() => {
      const path = this.browser.path;
      const known = this.entries.indexOf(path);
      if (known >= 0) this.index = known;
      else {
        this.entries.push(path);
        this.index = this.entries.length - 1;
      }
      this.apply(path);
    });
    this.onRoute(this.routeSignal.value);
  }

  navigate(path: string): void {
    if (this.browser.path === path) {
      this.updateHistoryState();
      return;
    }
    this.entries.splice(this.index + 1);
    this.entries.push(path);
    this.index = this.entries.length - 1;
    this.browser.push(path);
    this.apply(path);
  }

  back(): void {
    this.browser.back();
  }

  forward(): void {
    this.browser.forward();
  }

  dispose(): void {
    this.removePopState?.();
    this.removePopState = null;
  }

  private apply(path: string): void {
    batch(() => {
      this.routeSignal.value = parseRoute(path);
      this.updateHistoryState();
    });
    this.onRoute(this.routeSignal.value);
  }

  private updateHistoryState(): void {
    this.canGoBackSignal.value = this.index > 0;
    this.canGoForwardSignal.value = this.index < this.entries.length - 1;
  }
}

export function parseRoute(path: string): Route {
  const pathname = path.split(/[?#]/, 1)[0];
  const session = /^\/endpoints\/([^/]+)\/sessions\/([^/]+)$/.exec(pathname);
  if (session) {
    return {
      view: "session",
      endpointId: decodeURIComponent(session[1]),
      sessionId: decodeURIComponent(session[2]),
      path,
    };
  }
  if (pathname === "/") return { view: "sessions", endpointId: null, sessionId: null, path };
  if (pathname === "/endpoints") {
    return { view: "endpoints", endpointId: null, sessionId: null, path };
  }
  if (pathname === "/providers") {
    return { view: "providers", endpointId: null, sessionId: null, path };
  }
  if (pathname === "/settings") {
    return { view: "settings", endpointId: null, sessionId: null, path };
  }
  return { view: "not_found", endpointId: null, sessionId: null, path };
}
