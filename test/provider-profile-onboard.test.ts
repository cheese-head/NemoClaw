// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

import {
  ensureNemoClawProviderProfiles,
  NEMOCLAW_PROVIDER_PROFILES_DIR,
} from "../src/lib/onboard/provider-profiles";

function writeProfile(dir: string, id: string): void {
  fs.writeFileSync(
    path.join(dir, `${id}.yaml`),
    [
      `id: ${id}`,
      `display_name: ${id}`,
      "description: fixture profile",
      "category: other",
      "endpoints:",
      "  - host: example.com",
      "    port: 443",
      "binaries:",
      "  - /usr/bin/curl",
      "",
    ].join("\n"),
  );
}

describe("NemoClaw provider profile onboarding", () => {
  it("ships provider profiles for NemoClaw presets not built into OpenShell", () => {
    const ids = fs
      .readdirSync(NEMOCLAW_PROVIDER_PROFILES_DIR)
      .filter((file) => file.endsWith(".yaml"))
      .map((file) => {
        const parsed = YAML.parse(
          fs.readFileSync(path.join(NEMOCLAW_PROVIDER_PROFILES_DIR, file), "utf-8"),
        );
        return parsed.id;
      })
      .sort();

    expect(ids).toEqual([
      "brave",
      "brew",
      "discord",
      "huggingface",
      "jira",
      "local-inference",
      "npm",
      "pypi",
      "slack",
      "telegram",
    ]);
  });

  it("imports only profiles missing from OpenShell", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-provider-profile-test-"));
    const calls: string[][] = [];
    try {
      writeProfile(tmp, "brave");
      writeProfile(tmp, "npm");
      const result = ensureNemoClawProviderProfiles(
        (args) => {
          calls.push(args);
          if (args.join(" ") === "provider list-profiles -o json") {
            return {
              status: 0,
              stdout: JSON.stringify({ profiles: [{ id: "brave" }] }),
              stderr: "",
            };
          }
          return { status: 0, stdout: "", stderr: "" };
        },
        { profilesDir: tmp },
      );

      expect(result).toMatchObject({
        status: "imported",
        imported: ["npm"],
        skipped: ["brave"],
      });
      expect(calls).toEqual([
        ["provider", "list-profiles", "-o", "json"],
        ["provider", "profile", "lint", "--from", expect.any(String)],
        ["provider", "profile", "import", "--from", expect.any(String)],
      ]);
      const importDir = calls[2][4];
      expect(fs.existsSync(importDir)).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("skips import when all profiles already exist", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-provider-profile-test-"));
    const calls: string[][] = [];
    try {
      writeProfile(tmp, "brave");
      const result = ensureNemoClawProviderProfiles(
        (args) => {
          calls.push(args);
          return {
            status: 0,
            stdout: JSON.stringify({ profiles: [{ id: "brave" }] }),
            stderr: "",
          };
        },
        { profilesDir: tmp },
      );

      expect(result).toMatchObject({
        status: "already-present",
        imported: [],
        skipped: ["brave"],
      });
      expect(calls).toEqual([["provider", "list-profiles", "-o", "json"]]);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("falls back when OpenShell does not support provider profiles", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-provider-profile-test-"));
    try {
      writeProfile(tmp, "brave");
      const result = ensureNemoClawProviderProfiles(
        () => ({
          status: 2,
          stdout: "",
          stderr: "error: unrecognized subcommand 'profile'",
        }),
        { profilesDir: tmp },
      );

      expect(result.status).toBe("unsupported");
      expect(result.imported).toEqual([]);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
