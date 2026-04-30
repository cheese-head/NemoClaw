// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  cleanupSandboxControlPlaneIdentity,
  createSandboxControlPlaneIdentity,
  ensureControlPlaneServerIdentity,
  readSandboxControlPlaneIdentity,
  sandboxControlPlaneDir,
  sandboxControlPlaneEnv,
} from "../../dist/lib/control-plane-identity";

const tmpDirs: string[] = [];

function makeTempHome(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-control-plane-"));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("control-plane identity", () => {
  it("issues per-sandbox mTLS material and plugin attestation", () => {
    const homeDir = makeTempHome();
    const identity = createSandboxControlPlaneIdentity("sandbox-a", {
      controlUrl: "https://nemoclaw-control.local:9443",
      servername: "nemoclaw-control.local",
      deps: {
        homeDir,
        now: () => new Date("2026-04-30T00:00:00.000Z"),
        randomBytes: (size) => Buffer.alloc(size, 7),
      },
    });

    expect(identity.controlUrl).toBe("https://nemoclaw-control.local:9443");
    expect(identity.expiresAt).toBe("2026-05-01T00:00:00.000Z");
    expect(identity.caPem).toContain("BEGIN CERTIFICATE");
    expect(identity.certPem).toContain("BEGIN CERTIFICATE");
    expect(identity.keyPem).toContain("BEGIN PRIVATE KEY");
    expect(identity.pluginAttestationToken).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(fs.statSync(identity.keyPath).mode & 0o077).toBe(0);

    const reloaded = readSandboxControlPlaneIdentity("sandbox-a", { homeDir });
    expect(reloaded?.certPem).toBe(identity.certPem);

    const env = sandboxControlPlaneEnv(identity);
    expect(env.NEMOCLAW_CONTROL_URL).toBe("https://nemoclaw-control.local:9443");
    expect(Buffer.from(env.NEMOCLAW_CONTROL_CERT_PEM_B64, "base64").toString("utf-8")).toBe(
      identity.certPem,
    );
    expect(env.NEMOCLAW_CONTROL_KEY_PEM_B64).toBeTruthy();
    expect(env.NEMOCLAW_CONTROL_CA_PEM_B64).toBeTruthy();
    expect(env.NEMOCLAW_PLUGIN_ATTESTATION).toBe(identity.pluginAttestationToken);
  });

  it("issues server identity from the same control-plane CA", () => {
    const homeDir = makeTempHome();
    const server = ensureControlPlaneServerIdentity({ homeDir });
    const sandbox = createSandboxControlPlaneIdentity("sandbox-a", {
      controlUrl: "https://host.openshell.internal:19443",
      servername: "nemoclaw-control.local",
      deps: { homeDir },
    });

    expect(server.certPem).toContain("BEGIN CERTIFICATE");
    expect(server.keyPem).toContain("BEGIN PRIVATE KEY");
    expect(server.caPem).toBe(sandbox.caPem);
    expect(fs.statSync(server.keyPath).mode & 0o077).toBe(0);
  });

  it("rejects non-HTTPS control URLs and removes identity material on cleanup", () => {
    const homeDir = makeTempHome();
    expect(() =>
      createSandboxControlPlaneIdentity("sandbox-a", {
        controlUrl: "http://nemoclaw-control.local",
        deps: { homeDir },
      }),
    ).toThrow(/HTTPS with mTLS/);

    createSandboxControlPlaneIdentity("sandbox-a", {
      controlUrl: "https://nemoclaw-control.local",
      deps: { homeDir },
    });
    expect(fs.existsSync(sandboxControlPlaneDir("sandbox-a", { homeDir }))).toBe(true);
    cleanupSandboxControlPlaneIdentity("sandbox-a", { homeDir });
    expect(fs.existsSync(sandboxControlPlaneDir("sandbox-a", { homeDir }))).toBe(false);
  });
});
