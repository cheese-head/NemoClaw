// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ensureConfigDir, readConfigFile, writeConfigFile } from "./config-io";

export type ControlPlaneIdentityDeps = {
  homeDir?: string;
  now?: () => Date;
  randomBytes?: (size: number) => Buffer;
  execFileSync?: typeof execFileSync;
};

export type SandboxControlPlaneIdentity = {
  sandboxName: string;
  controlUrl: string;
  servername?: string;
  caPath: string;
  certPath: string;
  keyPath: string;
  caPem: string;
  certPem: string;
  keyPem: string;
  pluginAttestationToken: string;
  expiresAt: string;
};

export type ControlPlaneServerIdentity = {
  caPath: string;
  certPath: string;
  keyPath: string;
  caPem: string;
  certPem: string;
  keyPem: string;
};

const CERT_TTL_DAYS = 1;
const CONTROL_HOST_DEFAULT = "nemoclaw-control.local";

function depsOrDefault(deps: ControlPlaneIdentityDeps): Required<ControlPlaneIdentityDeps> {
  return {
    homeDir: deps.homeDir ?? process.env.HOME ?? os.homedir(),
    now: deps.now ?? (() => new Date()),
    randomBytes: deps.randomBytes ?? crypto.randomBytes,
    execFileSync: deps.execFileSync ?? execFileSync,
  };
}

function fileStem(sandboxName: string): string {
  const encoded = encodeURIComponent(sandboxName);
  if (!encoded) {
    throw new Error("Sandbox name is required for NemoClaw control-plane identity.");
  }
  return encoded;
}

export function controlPlaneStateDir(deps: ControlPlaneIdentityDeps = {}): string {
  const resolved = depsOrDefault(deps);
  return path.join(resolved.homeDir, ".nemoclaw", "state", "control-plane");
}

export function sandboxControlPlaneDir(
  sandboxName: string,
  deps: ControlPlaneIdentityDeps = {},
): string {
  return path.join(controlPlaneStateDir(deps), fileStem(sandboxName));
}

function controlPlaneCaDir(deps: ControlPlaneIdentityDeps = {}): string {
  return path.join(controlPlaneStateDir(deps), "ca");
}

function controlPlaneServerDir(deps: ControlPlaneIdentityDeps = {}): string {
  return path.join(controlPlaneStateDir(deps), "server");
}

function openssl(args: string[], cwd: string, deps: Required<ControlPlaneIdentityDeps>): void {
  deps.execFileSync("openssl", args, { cwd, stdio: "ignore" });
}

function writeFile0600(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content, { mode: 0o600 });
}

function createCaIfMissing(dir: string, deps: Required<ControlPlaneIdentityDeps>): void {
  const keyPath = path.join(dir, "ca.key");
  const certPath = path.join(dir, "ca.crt");
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return;
  }
  openssl(["genrsa", "-out", "ca.key", "3072"], dir, deps);
  openssl(
    [
      "req",
      "-x509",
      "-new",
      "-nodes",
      "-key",
      "ca.key",
      "-sha256",
      "-days",
      String(CERT_TTL_DAYS),
      "-subj",
      "/CN=NemoClaw Control CA",
      "-out",
      "ca.crt",
    ],
    dir,
    deps,
  );
  fs.chmodSync(keyPath, 0o600);
  fs.chmodSync(certPath, 0o600);
}

function issueSandboxClientCert(
  dir: string,
  sandboxName: string,
  deps: Required<ControlPlaneIdentityDeps>,
): void {
  writeFile0600(
    path.join(dir, "client.ext"),
    `subjectAltName=URI:nemoclaw:sandbox:${encodeURIComponent(sandboxName)}\nextendedKeyUsage=clientAuth\n`,
  );
  openssl(["genrsa", "-out", "client.key", "3072"], dir, deps);
  openssl(
    [
      "req",
      "-new",
      "-key",
      "client.key",
      "-subj",
      `/CN=sandbox:${sandboxName}`,
      "-out",
      "client.csr",
    ],
    dir,
    deps,
  );
  openssl(
    [
      "x509",
      "-req",
      "-in",
      "client.csr",
      "-CA",
      "ca.crt",
      "-CAkey",
      "ca.key",
      "-CAcreateserial",
      "-out",
      "client.crt",
      "-days",
      String(CERT_TTL_DAYS),
      "-sha256",
      "-extfile",
      "client.ext",
    ],
    dir,
    deps,
  );
  fs.chmodSync(path.join(dir, "client.key"), 0o600);
  fs.chmodSync(path.join(dir, "client.crt"), 0o600);
}

function metadataPath(dir: string): string {
  return path.join(dir, "identity.json");
}

function b64(value: string): string {
  return Buffer.from(value, "utf-8").toString("base64");
}

export function createSandboxControlPlaneIdentity(
  sandboxName: string,
  options: { controlUrl: string; servername?: string; deps?: ControlPlaneIdentityDeps },
): SandboxControlPlaneIdentity {
  const deps = depsOrDefault(options.deps ?? {});
  const url = new URL(options.controlUrl);
  if (url.protocol !== "https:") {
    throw new Error("NemoClaw control URL must use HTTPS with mTLS.");
  }

  const dir = sandboxControlPlaneDir(sandboxName, deps);
  const caDir = controlPlaneCaDir(deps);
  ensureConfigDir(caDir);
  createCaIfMissing(caDir, deps);
  ensureConfigDir(dir);
  for (const file of ["ca.crt", "ca.key", "ca.srl"]) {
    const source = path.join(caDir, file);
    if (fs.existsSync(source)) {
      fs.copyFileSync(source, path.join(dir, file));
      fs.chmodSync(path.join(dir, file), 0o600);
    }
  }
  issueSandboxClientCert(dir, sandboxName, deps);

  const caPath = path.join(dir, "ca.crt");
  const certPath = path.join(dir, "client.crt");
  const keyPath = path.join(dir, "client.key");
  const identity: SandboxControlPlaneIdentity = {
    sandboxName,
    controlUrl: options.controlUrl,
    ...(options.servername ? { servername: options.servername } : {}),
    caPath,
    certPath,
    keyPath,
    caPem: fs.readFileSync(caPath, "utf-8"),
    certPem: fs.readFileSync(certPath, "utf-8"),
    keyPem: fs.readFileSync(keyPath, "utf-8"),
    pluginAttestationToken: deps.randomBytes(32).toString("base64url"),
    expiresAt: new Date(deps.now().getTime() + CERT_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString(),
  };
  writeConfigFile(metadataPath(dir), {
    sandboxName: identity.sandboxName,
    controlUrl: identity.controlUrl,
    servername: identity.servername ?? null,
    caPath: identity.caPath,
    certPath: identity.certPath,
    keyPath: identity.keyPath,
    pluginAttestationToken: identity.pluginAttestationToken,
    expiresAt: identity.expiresAt,
  });
  return identity;
}

export function ensureControlPlaneServerIdentity(
  depsInput: ControlPlaneIdentityDeps = {},
): ControlPlaneServerIdentity {
  const deps = depsOrDefault(depsInput);
  const caDir = controlPlaneCaDir(deps);
  const serverDir = controlPlaneServerDir(deps);
  ensureConfigDir(caDir);
  ensureConfigDir(serverDir);
  createCaIfMissing(caDir, deps);

  const caPath = path.join(caDir, "ca.crt");
  const keyPath = path.join(serverDir, "server.key");
  const certPath = path.join(serverDir, "server.crt");
  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    writeFile0600(
      path.join(serverDir, "server.ext"),
      [
        "subjectAltName=DNS:nemoclaw-control.local,DNS:host.openshell.internal,DNS:localhost,IP:127.0.0.1",
        "extendedKeyUsage=serverAuth",
        "",
      ].join("\n"),
    );
    openssl(["genrsa", "-out", keyPath, "3072"], serverDir, deps);
    openssl(
      [
        "req",
        "-new",
        "-key",
        keyPath,
        "-subj",
        "/CN=nemoclaw-control.local",
        "-out",
        "server.csr",
      ],
      serverDir,
      deps,
    );
    openssl(
      [
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        path.join(caDir, "ca.crt"),
        "-CAkey",
        path.join(caDir, "ca.key"),
        "-CAcreateserial",
        "-out",
        certPath,
        "-days",
        String(CERT_TTL_DAYS),
        "-sha256",
        "-extfile",
        "server.ext",
      ],
      serverDir,
      deps,
    );
    fs.chmodSync(keyPath, 0o600);
    fs.chmodSync(certPath, 0o600);
  }

  return {
    caPath,
    certPath,
    keyPath,
    caPem: fs.readFileSync(caPath, "utf-8"),
    certPem: fs.readFileSync(certPath, "utf-8"),
    keyPem: fs.readFileSync(keyPath, "utf-8"),
  };
}

export function readSandboxControlPlaneIdentity(
  sandboxName: string,
  deps: ControlPlaneIdentityDeps = {},
): SandboxControlPlaneIdentity | null {
  const dir = sandboxControlPlaneDir(sandboxName, deps);
  const metadata = readConfigFile<Partial<SandboxControlPlaneIdentity> | null>(
    metadataPath(dir),
    null,
  );
  if (!metadata?.controlUrl || !metadata.pluginAttestationToken) {
    return null;
  }
  const caPath = metadata.caPath ?? path.join(dir, "ca.crt");
  const certPath = metadata.certPath ?? path.join(dir, "client.crt");
  const keyPath = metadata.keyPath ?? path.join(dir, "client.key");
  if (!fs.existsSync(caPath) || !fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    return null;
  }
  return {
    sandboxName,
    controlUrl: metadata.controlUrl,
    ...(metadata.servername ? { servername: metadata.servername } : {}),
    caPath,
    certPath,
    keyPath,
    caPem: fs.readFileSync(caPath, "utf-8"),
    certPem: fs.readFileSync(certPath, "utf-8"),
    keyPem: fs.readFileSync(keyPath, "utf-8"),
    pluginAttestationToken: metadata.pluginAttestationToken,
    expiresAt: metadata.expiresAt ?? "",
  };
}

export function sandboxControlPlaneEnv(
  identity: SandboxControlPlaneIdentity,
): Record<string, string> {
  return {
    NEMOCLAW_CONTROL_URL: identity.controlUrl,
    NEMOCLAW_CONTROL_CA_PEM_B64: b64(identity.caPem),
    NEMOCLAW_CONTROL_CERT_PEM_B64: b64(identity.certPem),
    NEMOCLAW_CONTROL_KEY_PEM_B64: b64(identity.keyPem),
    NEMOCLAW_PLUGIN_ATTESTATION: identity.pluginAttestationToken,
    ...(identity.servername ? { NEMOCLAW_CONTROL_SERVERNAME: identity.servername } : {}),
  };
}

export function cleanupSandboxControlPlaneIdentity(
  sandboxName: string,
  deps: ControlPlaneIdentityDeps = {},
): void {
  fs.rmSync(sandboxControlPlaneDir(sandboxName, deps), { recursive: true, force: true });
}

export function defaultControlPlaneServername(controlUrl: string): string {
  try {
    return new URL(controlUrl).hostname || CONTROL_HOST_DEFAULT;
  } catch {
    return CONTROL_HOST_DEFAULT;
  }
}
