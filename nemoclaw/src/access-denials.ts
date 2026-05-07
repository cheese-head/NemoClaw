// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

export type NemoClawAccessSuggestion = {
  resource: string;
  access: "read" | "read_write";
  duration: "session";
};

export type NemoClawAccessDenial = {
  version: "nemoclaw.denial.v1";
  id: string;
  kind: "network_policy_denial";
  observed_at: string;
  observed: {
    method?: string;
    url?: string;
    host?: string;
    port?: number;
    protocol?: string;
  };
  openshell?: {
    policy?: string;
    rule?: string;
    detail?: string;
  };
  suggested_access?: NemoClawAccessSuggestion;
  user_message: string;
};

export const ACCESS_DENIAL_LOG =
  process.env.NEMOCLAW_ACCESS_DENIAL_LOG || "/sandbox/.nemoclaw/access-denials.jsonl";

const MAX_RECORDS = 100;

function readJsonl(filePath: string): unknown[] {
  if (!fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, "utf-8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        return null;
      }
    })
    .filter((value) => value !== null);
}

function isDenial(value: unknown): value is NemoClawAccessDenial {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { version?: unknown }).version === "nemoclaw.denial.v1" &&
    (value as { kind?: unknown }).kind === "network_policy_denial" &&
    typeof (value as { id?: unknown }).id === "string"
  );
}

export function readRecentAccessDenials(
  options: { filePath?: string; limit?: number } = {},
): NemoClawAccessDenial[] {
  const filePath = options.filePath ?? ACCESS_DENIAL_LOG;
  const limit = Math.max(1, Math.min(options.limit ?? 10, MAX_RECORDS));
  return readJsonl(filePath).filter(isDenial).slice(-limit).reverse();
}

export function findRecentAccessDenial(
  id: string,
  options: { filePath?: string } = {},
): NemoClawAccessDenial | null {
  return (
    readRecentAccessDenials({ filePath: options.filePath, limit: MAX_RECORDS }).find(
      (denial) => denial.id === id,
    ) ?? null
  );
}

export function writeAccessDenialForTest(denial: NemoClawAccessDenial, filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(denial)}\n`, { mode: 0o600 });
}
