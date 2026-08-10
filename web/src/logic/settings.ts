import { batch, signal, type ReadonlySignal } from "@preact/signals-core";

import { ServerClient, type SystemResponse } from "../api/server";
import type { LoadState, NoticeSink } from "./ports";

export class Settings {
  private readonly dataSignal = signal<SystemResponse | null>(null);
  private readonly stateSignal = signal<LoadState>("idle");
  private readonly errorSignal = signal<string | null>(null);
  private generation = 0;

  readonly data: ReadonlySignal<SystemResponse | null> = this.dataSignal;
  readonly state: ReadonlySignal<LoadState> = this.stateSignal;
  readonly error: ReadonlySignal<string | null> = this.errorSignal;

  constructor(
    private readonly client: ServerClient,
    private readonly notices: NoticeSink,
  ) {}

  async refresh(): Promise<void> {
    const generation = ++this.generation;
    this.stateSignal.value = this.dataSignal.value ? "stale" : "loading";
    this.errorSignal.value = null;
    try {
      const data = await this.client.getSystem();
      if (generation !== this.generation) return;
      batch(() => {
        this.dataSignal.value = data;
        this.stateSignal.value = "ready";
        this.errorSignal.value = null;
      });
    } catch (error) {
      if (generation !== this.generation) return;
      const message = this.notices.error(error);
      batch(() => {
        this.stateSignal.value = this.dataSignal.value ? "stale" : "error";
        this.errorSignal.value = message;
      });
      throw error;
    }
  }
}
