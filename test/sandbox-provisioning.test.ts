// @ts-nocheck
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Regression guards for sandbox image provisioning.
//
// Verifies that the image-build sources (Dockerfile and Dockerfile.base)
// preserve the runtime-writable symlink layout introduced by #1027/#1519
// and the root-owned read-only config invariants from #514.
//
// These are static regression guards over the Dockerfile text — they fail
// immediately if a future refactor drops one of the baked-in provisioning
// steps, even before a full image build runs in CI.

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const DOCKERFILE = path.join(ROOT, "Dockerfile");
const DOCKERFILE_BASE = path.join(ROOT, "Dockerfile.base");
const DOCKERFILE_SANDBOX = path.join(ROOT, "test", "Dockerfile.sandbox");

describe("sandbox provisioning: exec-approvals / update-check symlinks (#1027, #1519)", () => {
  const src = fs.readFileSync(DOCKERFILE_BASE, "utf-8");

  it("Dockerfile.base creates the exec-approvals.json backing file in .openclaw-data", () => {
    // The data file has to exist before the symlink target resolves, so the
    // OpenClaw gateway can read+write through .openclaw/exec-approvals.json
    // without hitting EACCES.
    expect(src).toMatch(/touch \/sandbox\/\.openclaw-data\/exec-approvals\.json/);
  });

  it("Dockerfile.base symlinks .openclaw/exec-approvals.json -> .openclaw-data/exec-approvals.json", () => {
    expect(src).toContain(
      "ln -s /sandbox/.openclaw-data/exec-approvals.json /sandbox/.openclaw/exec-approvals.json",
    );
  });

  it("Dockerfile.base creates the update-check.json backing file in .openclaw-data", () => {
    expect(src).toMatch(/touch \/sandbox\/\.openclaw-data\/update-check\.json/);
  });

  it("Dockerfile.base symlinks .openclaw/update-check.json -> .openclaw-data/update-check.json", () => {
    expect(src).toContain(
      "ln -s /sandbox/.openclaw-data/update-check.json /sandbox/.openclaw/update-check.json",
    );
  });

  it("the exec-approvals data file is created before the symlink that points at it", () => {
    const dataIdx = src.indexOf("touch /sandbox/.openclaw-data/exec-approvals.json");
    const linkIdx = src.indexOf(
      "ln -s /sandbox/.openclaw-data/exec-approvals.json /sandbox/.openclaw/exec-approvals.json",
    );
    expect(dataIdx).toBeGreaterThanOrEqual(0);
    expect(linkIdx).toBeGreaterThan(dataIdx);
  });
});

describe("sandbox provisioning: procps debug tools (#2343)", () => {
  const baseSrc = fs.readFileSync(DOCKERFILE_BASE, "utf-8");
  const mainSrc = fs.readFileSync(DOCKERFILE, "utf-8");

  it("Dockerfile.base installs procps in the apt-get layer", () => {
    expect(baseSrc).toMatch(/apt-get.*install.*procps/s);
  });

  it("Dockerfile has a procps fallback for stale GHCR base images", () => {
    // The hardening step must protect procps from autoremove and install it
    // if the base image predates the procps addition.
    expect(mainSrc).toMatch(/command -v ps/);
    expect(mainSrc).toMatch(/install.*procps/);
  });
});

describe("sandbox provisioning: stale base writable OpenClaw dirs", () => {
  const src = fs.readFileSync(DOCKERFILE, "utf-8");

  it("repairs stale-base writable dirs before installing the NemoClaw plugin", () => {
    const repairIdx = src.indexOf("Repair writable OpenClaw state symlinks before switching");
    const installIdx = src.indexOf(
      "openclaw plugins install --force /sandbox/.openclaw/extensions/nemoclaw",
    );
    expect(repairIdx).toBeGreaterThanOrEqual(0);
    expect(installIdx).toBeGreaterThan(repairIdx);
  });

  it("stages NemoClaw plugin inside extensions before installing it", () => {
    const stageIdx = src.indexOf("cp -a /opt/nemoclaw /sandbox/.openclaw-data/extensions/nemoclaw");
    const installIdx = src.indexOf(
      "openclaw plugins install --force /sandbox/.openclaw/extensions/nemoclaw",
    );
    expect(stageIdx).toBeGreaterThanOrEqual(0);
    expect(installIdx).toBeGreaterThan(stageIdx);
  });

  it("Dockerfile fallback covers extensions and devices before gateway startup", () => {
    expect(src).toMatch(/for dir in agents extensions workspace skills hooks identity devices canvas cron memory logs credentials flows sandbox telegram plugin-runtime-deps/);
  });

  it("Dockerfile fallback creates .openclaw-data/workspace before linking workspace/media", () => {
    const workspaceIdx = src.indexOf("/sandbox/.openclaw-data/workspace");
    const mediaLinkIdx = src.indexOf(
      "ln -sfn /sandbox/.openclaw-data/media /sandbox/.openclaw-data/workspace/media",
    );
    expect(workspaceIdx).toBeGreaterThanOrEqual(0);
    expect(mediaLinkIdx).toBeGreaterThan(workspaceIdx);
  });

  it("does not hide NemoClaw plugin install failures", () => {
    expect(src).toContain("openclaw plugins install --force /sandbox/.openclaw/extensions/nemoclaw");
    expect(src).not.toContain("openclaw plugins install /opt/nemoclaw > /dev/null 2>&1 || true");
  });

  it("does not bypass OpenClaw plugin scanner for NemoClaw", () => {
    expect(src).not.toContain(
      'Plugin "nemoclaw" installation blocked: dangerous code patterns detected',
    );
    expect(src).not.toContain("treating built-in NemoClaw plugin scanner block");
  });
});

describe("Hermes provisioning: writable prompt history", () => {
  const baseSrc = fs.readFileSync(path.join(ROOT, "agents", "hermes", "Dockerfile.base"), "utf-8");
  const imageSrc = fs.readFileSync(path.join(ROOT, "agents", "hermes", "Dockerfile"), "utf-8");

  it("Hermes base image stores prompt history in writable .hermes-data", () => {
    expect(baseSrc).toContain("touch /sandbox/.hermes-data/.hermes_history");
    expect(baseSrc).toContain(
      "ln -s /sandbox/.hermes-data/.hermes_history /sandbox/.hermes/.hermes_history",
    );
  });

  it("Hermes final image repairs stale bases without a writable history symlink", () => {
    expect(imageSrc).toContain("touch /sandbox/.hermes-data/.hermes_history");
    expect(imageSrc).toContain(
      "ln -s /sandbox/.hermes-data/.hermes_history /sandbox/.hermes/.hermes_history",
    );
  });
});

describe("Hermes startup: access-control environment", () => {
  const startSrc = fs.readFileSync(path.join(ROOT, "agents", "hermes", "start.sh"), "utf-8");

  it("persists NemoClaw control-plane env vars for interactive Hermes sessions", () => {
    expect(startSrc).toContain("_PROXY_ENV_FILE=\"/tmp/nemoclaw-proxy-env.sh\"");
    for (const key of [
      "NEMOCLAW_CONTROL_URL",
      "NEMOCLAW_CONTROL_SERVERNAME",
      "NEMOCLAW_CONTROL_CA_PEM_B64",
      "NEMOCLAW_CONTROL_CERT_PEM_B64",
      "NEMOCLAW_CONTROL_KEY_PEM_B64",
      "NEMOCLAW_PLUGIN_ATTESTATION",
    ]) {
      expect(startSrc).toContain(key);
    }
    expect(startSrc).toContain("printf 'export %s=%q\\n'");
  });

  it("sources the generated env file from Hermes interactive shell startup files", () => {
    expect(startSrc).toContain(
      "[ -f /tmp/nemoclaw-proxy-env.sh ] && . /tmp/nemoclaw-proxy-env.sh",
    );
  });
});

describe("sandbox provisioning: root-owned read-only config (#514)", () => {
  const src = fs.readFileSync(DOCKERFILE, "utf-8");

  it("openclaw.json stays mode 0444 (agent cannot tamper with auth token / CORS)", () => {
    expect(src).toContain("chmod 444 /sandbox/.openclaw/openclaw.json");
  });

  it(".config-hash stays root:root 0444 (agent cannot forge a matching integrity hash)", () => {
    expect(src).toContain("chown root:root /sandbox/.openclaw/.config-hash");
    expect(src).toContain("chmod 444 /sandbox/.openclaw/.config-hash");
  });

  it(".openclaw directory stays root:root 0755 (agent cannot add or replace symlinks)", () => {
    expect(src).toContain("chown root:root /sandbox/.openclaw");
    expect(src).toContain("chmod 755 /sandbox/.openclaw");
  });
});

describe("sandbox provisioning: codex-acp wrapper (#2484)", () => {
  const dockerSrc = fs.readFileSync(DOCKERFILE, "utf-8");
  const wrapperSrc = fs.readFileSync(path.join(ROOT, "scripts", "codex-acp-wrapper.sh"), "utf-8");

  it("copies the wrapper into the sandbox image", () => {
    expect(dockerSrc).toContain(
      "COPY scripts/codex-acp-wrapper.sh /usr/local/bin/nemoclaw-codex-acp",
    );
    expect(dockerSrc).toContain("/usr/local/bin/nemoclaw-codex-acp");
  });

  it("runs codex-acp with writable Codex and XDG state", () => {
    expect(wrapperSrc).toContain("export CODEX_HOME=");
    expect(wrapperSrc).toContain("export XDG_CONFIG_HOME=");
    expect(wrapperSrc).toContain("export HOME=");
    expect(wrapperSrc).toContain("exec /usr/local/bin/codex-acp");
  });
});

describe("sandbox test image fixtures", () => {
  const src = fs.readFileSync(DOCKERFILE_SANDBOX, "utf-8");

  it("clears production config recovery artifacts after writing the legacy fixture", () => {
    expect(src).toContain("/sandbox/.openclaw/openclaw.json.bak*");
    expect(src).toContain("/sandbox/.openclaw/openclaw.json.last-good");
    expect(src).toContain("/sandbox/.openclaw-data/logs/config-health.json");
  });
});

describe("sandbox operations E2E harness", () => {
  const src = fs.readFileSync(
    path.join(ROOT, "test", "e2e", "test-sandbox-operations.sh"),
    "utf-8",
  );

  it("resumes onboard when OpenShell resets after importing the image", () => {
    expect(src).toContain("is_onboard_import_stream_reset");
    expect(src).toContain("Connection reset by peer (os error 104)");
    expect(src).toContain("nemoclaw onboard --resume --non-interactive");
  });
});
