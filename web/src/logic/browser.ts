import type { BrowserNavigationPort, ClockPort, CursorStore } from "./ports";

export class BrowserCursorStore implements CursorStore {
  private readonly memory = new Map<string, string>();

  read(endpointId: string): string {
    return this.memory.get(endpointId) ?? "";
  }

  write(endpointId: string, cursor: string): void {
    if (!cursor) return;
    this.memory.set(endpointId, cursor);
  }
}

export class BrowserNavigation implements BrowserNavigationPort {
  get path(): string {
    return location.pathname + location.search + location.hash;
  }

  push(path: string): void {
    history.pushState(null, "", path);
  }

  replace(path: string): void {
    location.replace(path);
  }

  assignCurrent(): void {
    location.assign(location.href);
  }

  back(): void {
    history.back();
  }

  forward(): void {
    history.forward();
  }

  onPopState(listener: () => void): () => void {
    window.addEventListener("popstate", listener);
    return () => window.removeEventListener("popstate", listener);
  }
}

export const browserClock: ClockPort = {
  setTimeout(operation, delayMs) {
    return window.setTimeout(operation, delayMs);
  },
  clearTimeout(handle) {
    window.clearTimeout(handle);
  },
};
