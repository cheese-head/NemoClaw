// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  actionLabel,
  formatRelativeTime,
  formatRemainingTime,
  isPendingStatus,
  selectedItem,
  statusLabel,
  visibleItems,
  type AccessTuiRecord,
  type AccessTuiState,
} from "./model";

type Style = {
  accent: (text: string) => string;
  dim: (text: string) => string;
  error: (text: string) => string;
  success: (text: string) => string;
  warning: (text: string) => string;
  bold: (text: string) => string;
  selected: (text: string) => string;
};

export const plainStyle: Style = {
  accent: (text) => text,
  dim: (text) => text,
  error: (text) => text,
  success: (text) => text,
  warning: (text) => text,
  bold: (text) => text,
  selected: (text) => text,
};

export function ansiStyle(enabled: boolean): Style {
  if (!enabled) return plainStyle;
  return {
    accent: (text) => `\x1b[38;5;148m${text}\x1b[0m`,
    dim: (text) => `\x1b[2m${text}\x1b[0m`,
    error: (text) => `\x1b[31m${text}\x1b[0m`,
    success: (text) => `\x1b[32m${text}\x1b[0m`,
    warning: (text) => `\x1b[33m${text}\x1b[0m`,
    bold: (text) => `\x1b[1m${text}\x1b[0m`,
    selected: (text) => `\x1b[7m${text}\x1b[27m`,
  };
}

function stripAnsi(text: string): string {
  return text.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "");
}

function visibleWidth(text: string): number {
  return Array.from(stripAnsi(text)).length;
}

function truncate(text: string, width: number): string {
  if (width <= 0) return "";
  if (visibleWidth(text) <= width) return text;
  const clean = stripAnsi(text);
  return (
    Array.from(clean)
      .slice(0, Math.max(0, width - 1))
      .join("") + "…"
  );
}

function pad(text: string, width: number): string {
  return truncate(text, width).padEnd(width);
}

function section(title: string, style: Style): string {
  return style.bold(title);
}

function statusStyle(status: string, style: Style): (text: string) => string {
  if (status === "applied") return style.success;
  if (status === "failed" || status === "denied_by_ceiling") return style.error;
  if (status === "pending_activation") return style.warning;
  if (status === "pending") return style.accent;
  return style.dim;
}

function renderInboxRow(
  item: AccessTuiRecord,
  selected: boolean,
  width: number,
  now: Date,
  style: Style,
): string {
  const agent = item.identity_hints?.agent_id || item.identity_hints?.plugin_id || "agent";
  const status = statusStyle(item.status, style)(statusLabel(item.status));
  const line =
    `${selected ? ">" : " "} ` +
    `${pad(formatRelativeTime(item.updated_at, now), 8)} ` +
    `${pad(item.sandbox_id, 14)} ` +
    `${pad(agent, 12)} ` +
    `${pad(item.preset, 10)} ` +
    `${pad(item.access, 10)} ` +
    `${pad(stripAnsi(status), 16)} ` +
    `${item.task_id || "(none)"}`;
  const rendered = selected ? style.selected(truncate(line, width)) : truncate(line, width);
  return rendered;
}

export function renderAccessTuiLines(
  state: AccessTuiState,
  width: number,
  style: Style = plainStyle,
): string[] {
  const safeWidth = Math.max(40, width);
  switch (state.screen.name) {
    case "detail":
      return renderDetailLines(state, safeWidth, style);
    case "confirm":
      return renderConfirmLines(state, safeWidth, style);
    case "audit":
      return renderAuditLines(state, safeWidth, style);
    case "help":
      return renderHelpLines(safeWidth, style);
    case "message":
      return renderMessageLines(state.screen.title, state.screen.body, safeWidth, style);
    case "inbox":
    default:
      return renderInboxLines(state, safeWidth, style);
  }
}

function renderInboxLines(state: AccessTuiState, width: number, style: Style): string[] {
  const items = visibleItems(state);
  const lines: string[] = [];
  lines.push(style.bold("NemoClaw Access"));
  const filter = state.filter === "pending" ? "pending only" : "all requests";
  const refreshed = state.lastRefreshAt ? state.lastRefreshAt.toISOString().slice(11, 19) : "never";
  lines.push(
    style.dim(`Filter: ${filter}  Search: ${state.query || "(none)"}  Refreshed: ${refreshed}`),
  );
  lines.push("");
  lines.push(
    style.dim(
      `${pad("AGE", 8)} ${pad("SANDBOX", 14)} ${pad("AGENT", 12)} ${pad("PRESET", 10)} ${pad("ACCESS", 10)} ${pad("STATUS", 16)} TASK`,
    ),
  );
  lines.push(style.dim("─".repeat(Math.min(width, 96))));
  if (items.length === 0) {
    lines.push("");
    lines.push("No access requests match this view.");
    lines.push(style.dim("Press Ctrl-r to refresh, f to toggle filters, or q to quit."));
  } else {
    for (const [index, item] of items.entries()) {
      lines.push(renderInboxRow(item, index === state.cursor, width, state.now, style));
    }
  }
  lines.push("");
  lines.push(
    style.dim(
      "↑/↓ j/k move  Enter details  a approve  d deny  r revoke  v audit  f filter  Ctrl-r refresh  ? help  q quit",
    ),
  );
  return lines.map((line) => truncate(line, width));
}

function renderDetailLines(state: AccessTuiState, width: number, style: Style): string[] {
  const item = selectedItem(state);
  if (!item)
    return renderMessageLines(
      "No request selected",
      "Return to the inbox and select a request.",
      width,
      style,
    );
  const lines = [
    section("Request Details", style),
    "",
    section("Verified by NemoClaw", style),
    `Sandbox      ${item.sandbox_id}`,
    `Status       ${statusLabel(item.status)}`,
    `Preset       ${item.preset}`,
    `Access       ${item.access}`,
    `Duration     ${item.duration}`,
    `Created      ${item.created_at}`,
    `Expires      ${formatRemainingTime(item.expires_at, state.now)}`,
    "",
    section("Policy Change Preview", style),
    `Will apply preset: ${item.preset}`,
    item.preset === "github"
      ? "Opens: github.com, api.github.com"
      : "Opens: preset-defined network endpoints",
    "Filesystem changes: none",
    "",
    section("Agent-Claimed Context [untrusted]", style),
    `Intent       ${item.user_intent || "(none)"}`,
    `Reason       ${item.reason || "(none)"}`,
    "",
    style.dim("a approve  d deny  r revoke  v audit  Esc back"),
  ];
  return lines.map((line) => truncate(line, width));
}

function renderConfirmLines(state: AccessTuiState, width: number, style: Style): string[] {
  const item = selectedItem(state);
  if (!item || state.screen.name !== "confirm") {
    return renderMessageLines(
      "No request selected",
      "Return to the inbox and select a request.",
      width,
      style,
    );
  }
  const verb = actionLabel(state.screen.action);
  const danger =
    state.screen.action === "approve" && (item.access === "read_write" || item.access === "write");
  const lines = [
    section(`${verb} Access?`, style),
    "",
    `${verb} ${item.preset} ${item.access} access for sandbox ${item.sandbox_id}.`,
    `Request ${item.id}`,
    "",
    section("Verified Change", style),
    `Preset       ${item.preset}`,
    `Duration     ${item.duration}`,
    item.preset === "github"
      ? "Opens        github.com, api.github.com"
      : "Opens        preset-defined endpoints",
    danger
      ? style.warning("Write-capable access requested.")
      : "Scope        read-oriented preset access",
    "",
    state.screen.action === "deny" ? "Reason: " + (state.screen.reason || "(none)") : "",
    style.dim(
      "Enter confirm  Esc cancel" +
        (state.screen.action === "deny" ? "  type reason before Enter" : ""),
    ),
  ].filter((line) => line !== "");
  return lines.map((line) => truncate(line, width));
}

function renderAuditLines(state: AccessTuiState, width: number, style: Style): string[] {
  if (state.screen.name !== "audit") return [];
  const item = selectedItem(state);
  const result = state.screen.result;
  const lines = [section("Audit", style), ""];
  if (item) lines.push(`Sandbox      ${item.sandbox_id}`, `Request      ${item.id}`, "");
  if (result.ok) {
    lines.push(style.success("Chain status verified"));
    lines.push(`Records      ${result.records}`);
    lines.push(`Head hash    ${result.head_hash ?? "none"}`);
  } else {
    lines.push(style.error("Chain status failed"));
    lines.push(`Records      ${result.records}`);
    lines.push(`Error        ${result.error}`);
  }
  lines.push("", style.dim("Esc back"));
  return lines.map((line) => truncate(line, width));
}

function renderHelpLines(width: number, style: Style): string[] {
  return [
    section("Keys", style),
    "",
    "↑/↓ j/k     Move",
    "Enter       Details / confirm",
    "a           Approve selected pending request",
    "d           Deny selected pending request",
    "r           Revoke pending or applied request",
    "v           Verify audit chain for selected sandbox",
    "f           Toggle pending/all",
    "Ctrl-r      Refresh now",
    "Esc         Back / clear search",
    "q           Quit",
  ].map((line) => truncate(line, width));
}

function renderMessageLines(title: string, body: string, width: number, style: Style): string[] {
  return [section(title, style), "", body, "", style.dim("Esc back")].map((line) =>
    truncate(line, width),
  );
}
