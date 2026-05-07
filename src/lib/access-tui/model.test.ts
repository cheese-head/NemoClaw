// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  DEFAULT_STATE,
  formatRelativeTime,
  sortAccessItems,
  statusLabel,
  type AccessTuiRecord,
} from "./model";
import { renderAccessTuiLines } from "./render";

function record(overrides: Partial<AccessTuiRecord>): AccessTuiRecord {
  return {
    id: "req-1",
    sandbox_id: "demo",
    status: "pending",
    preset: "github",
    access: "read",
    duration: "session",
    task_id: "inspect",
    created_at: "2026-05-06T14:00:00.000Z",
    updated_at: "2026-05-06T14:00:00.000Z",
    user_intent: "Inspect the repository",
    reason: "Need GitHub metadata",
    identity_hints: { agent_id: "openclaw" },
    ...overrides,
  };
}

describe("access TUI model", () => {
  it("maps internal statuses to operator-facing labels", () => {
    expect(statusLabel("pending")).toBe("Needs approval");
    expect(statusLabel("pending_activation")).toBe("Applying");
    expect(statusLabel("denied_by_ceiling")).toBe("Blocked by policy");
  });

  it("sorts pending requests before resolved requests", () => {
    const sorted = sortAccessItems([
      record({ id: "old", status: "applied", updated_at: "2026-05-06T14:10:00.000Z" }),
      record({ id: "new", status: "pending", updated_at: "2026-05-06T14:00:00.000Z" }),
    ]);
    expect(sorted.map((item) => item.id)).toEqual(["new", "old"]);
  });

  it("formats relative age", () => {
    expect(
      formatRelativeTime("2026-05-06T14:00:00.000Z", new Date("2026-05-06T14:01:30.000Z")),
    ).toBe("1m ago");
  });
});

describe("access TUI rendering", () => {
  it("renders inbox lines within the requested width", () => {
    const lines = renderAccessTuiLines(
      {
        ...DEFAULT_STATE,
        now: new Date("2026-05-06T14:01:00.000Z"),
        lastRefreshAt: new Date("2026-05-06T14:01:00.000Z"),
        items: [record({})],
      },
      80,
    );
    expect(lines.join("\n")).toContain("NemoClaw Access");
    expect(lines.join("\n")).toContain("Needs approval");
    expect(lines.every((line) => line.length <= 80)).toBe(true);
  });

  it("keeps verified request fields above untrusted agent text in detail view", () => {
    const lines = renderAccessTuiLines(
      {
        ...DEFAULT_STATE,
        screen: { name: "detail" },
        now: new Date("2026-05-06T14:01:00.000Z"),
        items: [record({})],
      },
      100,
    );
    const text = lines.join("\n");
    expect(text.indexOf("Verified by NemoClaw")).toBeLessThan(
      text.indexOf("Agent-Claimed Context [untrusted]"),
    );
    expect(text).toContain("Policy Change Preview");
  });
});
