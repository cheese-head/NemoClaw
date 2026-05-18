// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";

const ROOT = path.resolve(__dirname, "..", "..", "..");

type RunOpenshell = (
  args: string[],
  opts?: {
    ignoreError?: boolean;
    stdio?: Array<"ignore" | "pipe" | "inherit">;
    suppressOutput?: boolean;
    timeout?: number;
  },
) => { status?: number | null; stdout?: string | Buffer | null; stderr?: string | Buffer | null };

export type ProviderProfileImportResult =
  | { status: "missing-directory"; imported: string[]; skipped: string[] }
  | { status: "unsupported"; imported: string[]; skipped: string[]; message: string }
  | { status: "already-present"; imported: string[]; skipped: string[] }
  | { status: "imported"; imported: string[]; skipped: string[] };

export const NEMOCLAW_PROVIDER_PROFILES_DIR = path.join(
  ROOT,
  "nemoclaw-blueprint",
  "provider-profiles",
);

function outputText(value: string | Buffer | null | undefined): string {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString("utf-8");
  return "";
}

function isUnsupportedProviderProfileCommand(result: {
  stdout?: string | Buffer | null;
  stderr?: string | Buffer | null;
}): boolean {
  const text = `${outputText(result.stderr)}\n${outputText(result.stdout)}`.toLowerCase();
  return (
    text.includes("unrecognized subcommand") ||
    text.includes("unknown command") ||
    text.includes("invalid subcommand")
  );
}

function parseProfileIds(raw: string): Set<string> {
  if (!raw.trim()) return new Set();
  try {
    const parsed = JSON.parse(raw);
    const candidates = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === "object" && Array.isArray(parsed.profiles)
        ? parsed.profiles
        : [];
    return new Set(
      candidates
        .map((profile: unknown) =>
          profile && typeof profile === "object" && typeof (profile as { id?: unknown }).id === "string"
            ? (profile as { id: string }).id
            : null,
        )
        .filter((id: string | null): id is string => Boolean(id)),
    );
  } catch {
    return new Set();
  }
}

function readProfileId(filePath: string): string | null {
  try {
    const parsed = YAML.parse(fs.readFileSync(filePath, "utf-8"));
    return parsed && typeof parsed === "object" && typeof parsed.id === "string"
      ? parsed.id
      : null;
  } catch {
    return null;
  }
}

function providerProfileFiles(dir: string): Array<{ id: string; path: string }> {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".yaml") || file.endsWith(".yml"))
    .map((file) => {
      const filePath = path.join(dir, file);
      const id = readProfileId(filePath);
      return id ? { id, path: filePath } : null;
    })
    .filter((item): item is { id: string; path: string } => item !== null)
    .sort((left, right) => left.id.localeCompare(right.id));
}

export function ensureNemoClawProviderProfiles(
  runOpenshell: RunOpenshell,
  options: { profilesDir?: string; log?: (message: string) => void } = {},
): ProviderProfileImportResult {
  const profilesDir = options.profilesDir || NEMOCLAW_PROVIDER_PROFILES_DIR;
  const log = options.log || (() => {});
  const profiles = providerProfileFiles(profilesDir);
  if (profiles.length === 0) {
    return { status: "missing-directory", imported: [], skipped: [] };
  }

  const list = runOpenshell(["provider", "list-profiles", "-o", "json"], {
    ignoreError: true,
    stdio: ["ignore", "pipe", "pipe"],
    suppressOutput: true,
    timeout: 10_000,
  });
  if (list.status !== 0) {
    return {
      status: "unsupported",
      imported: [],
      skipped: [],
      message: "OpenShell provider profiles are not available; using local preset fallbacks.",
    };
  }

  const existing = parseProfileIds(outputText(list.stdout));
  const missing = profiles.filter((profile) => !existing.has(profile.id));
  const skipped = profiles
    .filter((profile) => existing.has(profile.id))
    .map((profile) => profile.id);
  if (missing.length === 0) {
    return { status: "already-present", imported: [], skipped };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-provider-profiles-"));
  try {
    for (const profile of missing) {
      fs.copyFileSync(profile.path, path.join(tempDir, path.basename(profile.path)));
    }

    const lint = runOpenshell(["provider", "profile", "lint", "--from", tempDir], {
      ignoreError: true,
      stdio: ["ignore", "pipe", "pipe"],
      suppressOutput: true,
      timeout: 10_000,
    });
    if (lint.status !== 0) {
      if (isUnsupportedProviderProfileCommand(lint)) {
        return {
          status: "unsupported",
          imported: [],
          skipped,
          message: "OpenShell provider profile import is not available; using local preset fallbacks.",
        };
      }
      const details =
        outputText(lint.stderr) || outputText(lint.stdout) || "provider profile lint failed";
      throw new Error(`NemoClaw provider profile lint failed: ${details.trim()}`);
    }

    const importedIds = missing.map((profile) => profile.id);
    const imported = runOpenshell(["provider", "profile", "import", "--from", tempDir], {
      ignoreError: true,
      stdio: ["ignore", "pipe", "pipe"],
      suppressOutput: true,
      timeout: 10_000,
    });
    if (imported.status !== 0) {
      if (isUnsupportedProviderProfileCommand(imported)) {
        return {
          status: "unsupported",
          imported: [],
          skipped,
          message: "OpenShell provider profile import is not available; using local preset fallbacks.",
        };
      }
      const details =
        outputText(imported.stderr) || outputText(imported.stdout) || "provider profile import failed";
      throw new Error(`NemoClaw provider profile import failed: ${details.trim()}`);
    }

    log(`  Imported NemoClaw provider profiles: ${importedIds.join(", ")}`);
    return { status: "imported", imported: importedIds, skipped };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}
