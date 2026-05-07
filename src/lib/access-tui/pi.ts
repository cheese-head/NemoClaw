// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  approveAccessRequest,
  denyAccessRequest,
  readAllAccessRequests,
  revokeAccessRequest,
  verifyAccessAudit,
} from "./actions";
import {
  clampCursor,
  DEFAULT_STATE,
  isPendingStatus,
  isRevocableStatus,
  selectedItem,
  type AccessTuiScreen,
  type AccessTuiState,
} from "./model";
import { ansiStyle, renderAccessTuiLines } from "./render";

type PiModule = {
  Key: Record<string, string> & {
    ctrl: (key: string) => string;
  };
  ProcessTerminal: new () => unknown;
  TUI: new (
    terminal: unknown,
    showHardwareCursor?: boolean,
  ) => {
    addChild(component: PiComponent): void;
    setFocus(component: PiComponent | null): void;
    requestRender(force?: boolean): void;
    start(): void;
    stop(): void;
  };
  matchesKey(data: string, key: string): boolean;
};

type PiComponent = {
  render(width: number): string[];
  handleInput?(data: string): void;
  invalidate(): void;
};

type Deps = {
  readItems?: () => AccessTuiState["items"];
  now?: () => Date;
  setInterval?: typeof setInterval;
  clearInterval?: typeof clearInterval;
};

function dynamicImport<T>(specifier: string): Promise<T> {
  const importer = new Function("specifier", "return import(specifier)");
  return importer(specifier) as Promise<T>;
}

function isPrintable(data: string): boolean {
  return data.length === 1 && data >= " " && data !== "\x7f";
}

class AccessTuiApp implements PiComponent {
  private state: AccessTuiState;
  private readonly pi: PiModule;
  private readonly requestRender: () => void;
  private readonly stop: () => void;
  private readonly readItems: () => AccessTuiState["items"];
  private readonly now: () => Date;

  constructor(pi: PiModule, requestRender: () => void, stop: () => void, deps: Deps = {}) {
    this.pi = pi;
    this.requestRender = requestRender;
    this.stop = stop;
    this.readItems = deps.readItems ?? readAllAccessRequests;
    this.now = deps.now ?? (() => new Date());
    this.state = {
      ...DEFAULT_STATE,
      now: this.now(),
      lastRefreshAt: this.now(),
      items: this.readItems(),
    };
    this.state = clampCursor(this.state);
  }

  invalidate(): void {
    return;
  }

  render(width: number): string[] {
    return renderAccessTuiLines(this.state, width, ansiStyle(!process.env.NO_COLOR));
  }

  handleInput(data: string): void {
    const { Key, matchesKey } = this.pi;
    if (matchesKey(data, Key.ctrl("c") as string) || data === "q" || data === "Q") {
      this.stop();
      return;
    }
    if (matchesKey(data, Key.escape as string)) {
      this.handleEscape();
      return;
    }

    if (this.state.screen.name === "confirm" && this.state.screen.action === "deny") {
      if (matchesKey(data, Key.backspace as string)) {
        const reason = this.state.screen.reason ?? "";
        this.setScreen({ ...this.state.screen, reason: Array.from(reason).slice(0, -1).join("") });
        return;
      }
      if (isPrintable(data)) {
        this.setScreen({ ...this.state.screen, reason: (this.state.screen.reason ?? "") + data });
        return;
      }
    }

    if (matchesKey(data, Key.up as string) || data === "k") {
      this.move(-1);
    } else if (matchesKey(data, Key.down as string) || data === "j") {
      this.move(1);
    } else if (matchesKey(data, Key.enter as string)) {
      this.handleEnter();
    } else if (matchesKey(data, Key.ctrl("r") as string)) {
      this.refresh();
    } else if (data === "f" || data === "F") {
      this.state = clampCursor({
        ...this.state,
        filter: this.state.filter === "pending" ? "all" : "pending",
        cursor: 0,
      });
      this.requestRender();
    } else if (data === "/") {
      this.setScreen({
        name: "message",
        title: "Search",
        body: "Type a search query after returning to the inbox. Search input is intentionally minimal in this first Pi milestone.",
      });
    } else if (data === "?") {
      this.setScreen({ name: "help" });
    } else if (data === "a" || data === "A") {
      this.openConfirm("approve");
    } else if (data === "d" || data === "D") {
      this.openConfirm("deny");
    } else if (data === "r" || data === "R") {
      this.openConfirm("revoke");
    } else if (data === "v" || data === "V") {
      this.openAudit();
    }
  }

  refresh(): void {
    this.state = clampCursor({
      ...this.state,
      items: this.readItems(),
      now: this.now(),
      lastRefreshAt: this.now(),
    });
    this.requestRender();
  }

  private move(delta: number): void {
    if (this.state.screen.name !== "inbox") return;
    const length = Math.max(1, this.state.items.length);
    this.state = clampCursor({
      ...this.state,
      cursor: (this.state.cursor + delta + length) % length,
    });
    this.requestRender();
  }

  private handleEscape(): void {
    if (this.state.screen.name === "inbox") {
      if (this.state.query) {
        this.state = clampCursor({ ...this.state, query: "", cursor: 0 });
        this.requestRender();
      }
      return;
    }
    this.setScreen({ name: "inbox" });
  }

  private handleEnter(): void {
    if (this.state.screen.name === "inbox") {
      if (selectedItem(this.state)) this.setScreen({ name: "detail" });
      return;
    }
    if (this.state.screen.name !== "confirm") return;
    const item = selectedItem(this.state);
    if (!item) return;
    try {
      const action = this.state.screen.action;
      const message =
        action === "approve"
          ? approveAccessRequest(item)
          : action === "deny"
            ? denyAccessRequest(item, this.state.screen.reason ?? "")
            : revokeAccessRequest(item);
      this.refresh();
      this.setScreen({ name: "message", title: "Done", body: message });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.refresh();
      this.setScreen({ name: "message", title: "Action Failed", body: message });
    }
  }

  private openConfirm(action: "approve" | "deny" | "revoke"): void {
    const item = selectedItem(this.state);
    if (!item) return;
    if ((action === "approve" || action === "deny") && !isPendingStatus(item.status)) {
      this.setScreen({
        name: "message",
        title: "Not Pending",
        body: `Request status is ${item.status}.`,
      });
      return;
    }
    if (action === "revoke" && !isRevocableStatus(item.status)) {
      this.setScreen({
        name: "message",
        title: "Not Revocable",
        body: `Request status is ${item.status}.`,
      });
      return;
    }
    this.setScreen({ name: "confirm", action, reason: "" });
  }

  private openAudit(): void {
    const item = selectedItem(this.state);
    if (!item) return;
    this.setScreen({ name: "audit", result: verifyAccessAudit(item.sandbox_id) });
  }

  private setScreen(screen: AccessTuiScreen): void {
    this.state = { ...this.state, screen };
    this.requestRender();
  }
}

export async function runPiAccessTui(deps: Deps = {}): Promise<void> {
  const pi = await dynamicImport<PiModule>("@mariozechner/pi-tui");
  const terminal = new pi.ProcessTerminal();
  let tui: InstanceType<PiModule["TUI"]>;
  let refreshTimer: ReturnType<typeof setInterval> | null = null;
  await new Promise<void>((resolve) => {
    const stop = () => {
      if (refreshTimer) (deps.clearInterval ?? clearInterval)(refreshTimer);
      tui.stop();
      resolve();
    };
    tui = new pi.TUI(terminal, false);
    const app = new AccessTuiApp(pi, () => tui.requestRender(true), stop, deps);
    tui.addChild(app);
    tui.setFocus(app);
    refreshTimer = (deps.setInterval ?? setInterval)(() => app.refresh(), 2000);
    tui.start();
  });
}
