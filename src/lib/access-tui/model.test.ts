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

  it("shows current sandbox access and net-new access in detail view", () => {
    const lines = renderAccessTuiLines(
      {
        ...DEFAULT_STATE,
        screen: { name: "detail" },
        now: new Date("2026-05-06T14:01:00.000Z"),
        items: [
          record({
            preset: "slack",
            current_access: {
              sandbox_id: "demo",
              registry_presets: ["github"],
              gateway_presets: ["github", "slack"],
              effective_presets: ["github", "slack"],
              drift: true,
              requested_preset_already_active: true,
            },
          }),
        ],
      },
      120,
    );

    const text = lines.join("\n");
    expect(text).toContain("Current Access");
    expect(text).toContain("Active presets       github, slack");
    expect(text).toContain("Gateway verified     yes");
    expect(text).toContain("State drift           registry differs from live gateway");
    expect(text).toContain("Net new access       none, already active");
  });

  it("renders an advisor result without implying approval was applied", () => {
    const lines = renderAccessTuiLines(
      {
        ...DEFAULT_STATE,
        screen: {
          name: "advisor",
          requestId: "req-1",
          result: {
            recommendation: "needs_review",
            confidence: "medium",
            summary: "Slack is new access; verify the workspace.",
            risks: ["External messaging access"],
            missing_context: ["Workspace id"],
          },
        },
        now: new Date("2026-05-06T14:01:00.000Z"),
        items: [record({ preset: "slack" })],
      },
      120,
    );

    const text = lines.join("\n");
    expect(text).toContain("LLM Advisor");
    expect(text).toContain("Advisory only. Operator approval is still required.");
    expect(text).toContain("Recommendation needs_review");
    expect(text).toContain("External messaging access");
  });
});
