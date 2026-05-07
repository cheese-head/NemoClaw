// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export type AccessTuiStatus =
  | "pending"
  | "pending_activation"
  | "applied"
  | "denied"
  | "denied_by_ceiling"
  | "failed"
  | "expired"
  | "revoked"
  | string;

export type AccessTuiRecord = {
  id: string;
  sandbox_id: string;
  status: AccessTuiStatus;
  preset: string;
  access: string;
  duration: string;
  task_id: string;
  user_intent?: string;
  reason?: string;
  ceiling_reason?: string;
  status_reason?: string;
  created_at: string;
  updated_at: string;
  expires_at?: string;
  identity_hints?: Record<string, string | undefined>;
};

export type AuditResult =
  | { ok: true; records: number; head_hash: string | null }
  | { ok: false; records: number; error: string };

export type AccessTuiScreen =
  | { name: "inbox" }
  | { name: "detail" }
  | { name: "confirm"; action: "approve" | "deny" | "revoke"; reason?: string }
  | { name: "audit"; result: AuditResult }
  | { name: "help" }
  | { name: "message"; title: string; body: string };

export type AccessTuiState = {
  items: AccessTuiRecord[];
  cursor: number;
  screen: AccessTuiScreen;
  filter: "pending" | "all";
  query: string;
  now: Date;
  lastRefreshAt: Date | null;
};

export const DEFAULT_STATE: AccessTuiState = {
  items: [],
  cursor: 0,
  screen: { name: "inbox" },
  filter: "pending",
  query: "",
  now: new Date(0),
  lastRefreshAt: null,
};

export function isPendingStatus(status: string): boolean {
  return status === "pending" || status === "pending_activation";
}

export function isRevocableStatus(status: string): boolean {
  return status === "pending" || status === "pending_activation" || status === "applied";
}

export function statusLabel(status: string): string {
  switch (status) {
    case "pending":
      return "Needs approval";
    case "pending_activation":
      return "Applying";
    case "applied":
      return "Approved";
    case "denied":
      return "Denied";
    case "denied_by_ceiling":
      return "Blocked by policy";
    case "failed":
      return "Apply failed";
    case "expired":
      return "Expired";
    case "revoked":
      return "Revoked";
    default:
      return status;
  }
}

export function actionLabel(action: "approve" | "deny" | "revoke"): string {
  switch (action) {
    case "approve":
      return "Approve";
    case "deny":
      return "Deny";
    case "revoke":
      return "Revoke";
  }
}

export function formatRelativeTime(iso: string, now: Date): string {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "unknown";
  const deltaSeconds = Math.max(0, Math.floor((now.getTime() - then) / 1000));
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`;
  const deltaMinutes = Math.floor(deltaSeconds / 60);
  if (deltaMinutes < 60) return `${deltaMinutes}m ago`;
  const deltaHours = Math.floor(deltaMinutes / 60);
  if (deltaHours < 48) return `${deltaHours}h ago`;
  return `${Math.floor(deltaHours / 24)}d ago`;
}

export function formatRemainingTime(iso: string | undefined, now: Date): string {
  if (!iso) return "session";
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "unknown";
  const deltaSeconds = Math.floor((then - now.getTime()) / 1000);
  if (deltaSeconds <= 0) return "expired";
  if (deltaSeconds < 60) return `${deltaSeconds}s`;
  const deltaMinutes = Math.floor(deltaSeconds / 60);
  if (deltaMinutes < 60) return `${deltaMinutes}m`;
  const deltaHours = Math.floor(deltaMinutes / 60);
  if (deltaHours < 48) return `${deltaHours}h`;
  return `${Math.floor(deltaHours / 24)}d`;
}

export function sortAccessItems(items: AccessTuiRecord[]): AccessTuiRecord[] {
  return [...items].sort((a, b) => {
    const pendingDelta = Number(isPendingStatus(b.status)) - Number(isPendingStatus(a.status));
    if (pendingDelta !== 0) return pendingDelta;
    return Date.parse(b.updated_at) - Date.parse(a.updated_at);
  });
}

export function visibleItems(state: AccessTuiState): AccessTuiRecord[] {
  const query = state.query.trim().toLowerCase();
  return sortAccessItems(state.items)
    .filter((item) => state.filter === "all" || isPendingStatus(item.status))
    .filter((item) => {
      if (!query) return true;
      return [
        item.id,
        item.sandbox_id,
        item.status,
        item.preset,
        item.access,
        item.task_id,
        item.identity_hints?.agent_id,
        item.identity_hints?.plugin_id,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));
    });
}

export function selectedItem(state: AccessTuiState): AccessTuiRecord | null {
  return visibleItems(state)[state.cursor] ?? null;
}

export function clampCursor(state: AccessTuiState): AccessTuiState {
  const max = Math.max(0, visibleItems(state).length - 1);
  return { ...state, cursor: Math.min(Math.max(0, state.cursor), max) };
}
