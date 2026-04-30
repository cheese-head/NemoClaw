// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createAccessControlServer } from "./access-control-server";
import {
  ensureControlPlaneServerIdentity,
  readSandboxControlPlaneIdentity,
} from "./control-plane-identity";

const DEFAULT_HOST = "0.0.0.0";
const DEFAULT_PORT = 19443;

function parsePort(value: string | undefined): number {
  const parsed = Number(value ?? "");
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535 ? parsed : DEFAULT_PORT;
}

function allowedHosts(): string[] {
  const raw = process.env.NEMOCLAW_CONTROL_ALLOWED_HOSTS;
  const configured = raw
    ?.split(",")
    .map((host) => host.trim())
    .filter(Boolean);
  return configured && configured.length > 0
    ? configured
    : ["nemoclaw-control.local", "host.openshell.internal", "localhost", "127.0.0.1"];
}

export function runAccessControlService(): void {
  const identity = ensureControlPlaneServerIdentity();
  const host = process.env.NEMOCLAW_ACCESS_CONTROL_HOST || DEFAULT_HOST;
  const port = parsePort(process.env.NEMOCLAW_ACCESS_CONTROL_PORT);
  const server = createAccessControlServer({
    tls: {
      key: identity.keyPem,
      cert: identity.certPem,
      ca: identity.caPem,
    },
    allowedHosts: allowedHosts(),
    verifyPluginAttestation: (token, authenticated) => {
      const sandboxIdentity = readSandboxControlPlaneIdentity(authenticated.sandboxId);
      return sandboxIdentity?.pluginAttestationToken === token;
    },
  });

  server.listen(port, host, () => {
    process.stdout.write(`NemoClaw access control listening on https://${host}:${port}\n`);
  });

  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2_000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (require.main === module) {
  runAccessControlService();
}
