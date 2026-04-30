// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { createAccessControlServer } from "../../dist/lib/access-control-server";
import type { AccessRequestDeps } from "../../dist/lib/access-requests";

type CertBundle = {
  ca: Buffer;
  serverKey: Buffer;
  serverCert: Buffer;
  clientKey: Buffer;
  clientCert: Buffer;
};

const tmpDirs: string[] = [];
let certs: CertBundle;

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmpDirs.push(dir);
  return dir;
}

function openssl(args: string[], cwd: string): void {
  execFileSync("openssl", args, { cwd, stdio: "ignore" });
}

function generateCerts(): CertBundle {
  const dir = makeTempDir("nemoclaw-access-control-certs-");
  fs.writeFileSync(
    path.join(dir, "server.ext"),
    "subjectAltName=DNS:nemoclaw-control.local\nextendedKeyUsage=serverAuth\n",
  );
  fs.writeFileSync(
    path.join(dir, "client.ext"),
    "subjectAltName=URI:nemoclaw:sandbox:sandbox-a\nextendedKeyUsage=clientAuth\n",
  );

  openssl(["genrsa", "-out", "ca.key", "2048"], dir);
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
      "1",
      "-subj",
      "/CN=NemoClawTestCA",
      "-out",
      "ca.crt",
    ],
    dir,
  );
  openssl(["genrsa", "-out", "server.key", "2048"], dir);
  openssl(
    [
      "req",
      "-new",
      "-key",
      "server.key",
      "-subj",
      "/CN=nemoclaw-control.local",
      "-out",
      "server.csr",
    ],
    dir,
  );
  openssl(
    [
      "x509",
      "-req",
      "-in",
      "server.csr",
      "-CA",
      "ca.crt",
      "-CAkey",
      "ca.key",
      "-CAcreateserial",
      "-out",
      "server.crt",
      "-days",
      "1",
      "-sha256",
      "-extfile",
      "server.ext",
    ],
    dir,
  );
  openssl(["genrsa", "-out", "client.key", "2048"], dir);
  openssl(
    [
      "req",
      "-new",
      "-key",
      "client.key",
      "-subj",
      "/CN=sandbox:sandbox-a",
      "-out",
      "client.csr",
    ],
    dir,
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
      "1",
      "-sha256",
      "-extfile",
      "client.ext",
    ],
    dir,
  );

  return {
    ca: fs.readFileSync(path.join(dir, "ca.crt")),
    serverKey: fs.readFileSync(path.join(dir, "server.key")),
    serverCert: fs.readFileSync(path.join(dir, "server.crt")),
    clientKey: fs.readFileSync(path.join(dir, "client.key")),
    clientCert: fs.readFileSync(path.join(dir, "client.crt")),
  };
}

function makeDeps(homeDir = makeTempDir("nemoclaw-access-control-state-")): Required<AccessRequestDeps> {
  let nextId = 1;
  return {
    homeDir,
    now: () => new Date("2026-04-30T00:00:00.000Z"),
    id: () => `req-${nextId++}`,
    hash: (input: string) => crypto.createHash("sha256").update(input).digest("hex"),
  };
}

async function withServer<T>(deps: Required<AccessRequestDeps>, fn: (port: number) => Promise<T>): Promise<T> {
  const server = createAccessControlServer({
    tls: {
      key: certs.serverKey,
      cert: certs.serverCert,
      ca: certs.ca,
    },
    allowedHosts: ["nemoclaw-control.local"],
    pluginAttestationToken: "builtin-openclaw",
    deps,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("server did not bind to a TCP port");
  }
  try {
    return await fn(address.port);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

function request(
  port: number,
  method: "GET" | "POST",
  requestPath: string,
  body?: unknown,
  overrides: Partial<https.RequestOptions> = {},
): Promise<{ statusCode: number; body: string }> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "127.0.0.1",
        port,
        method,
        path: requestPath,
        servername: "nemoclaw-control.local",
        ca: certs.ca,
        key: certs.clientKey,
        cert: certs.clientCert,
        headers: {
          Host: "nemoclaw-control.local",
          "X-NemoClaw-Plugin-Attestation": "builtin-openclaw",
          ...(payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {}),
        },
        ...overrides,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            statusCode: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf-8"),
          }),
        );
      },
    );
    req.on("error", reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

beforeAll(() => {
  certs = generateCerts();
});

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("access control server", () => {
  it("creates and reads access requests using mTLS sandbox identity", async () => {
    const deps = makeDeps();
    await withServer(deps, async (port) => {
      const created = await request(port, "POST", "/v1/access-requests", {
        version: "nemoclaw.access.v1",
        task_id: "task-1",
        user_intent: "Need GitHub metadata",
        llm_proposal: {
          resource_type: "network",
          preset: "github",
          access: "read",
          duration: "session",
          reason: "Fetch issue metadata",
        },
      });
      expect(created.statusCode).toBe(201);
      const createdBody = JSON.parse(created.body);
      expect(createdBody).toMatchObject({
        request_id: "req-1",
        status: "pending",
        canonical_request: {
          preset: "github",
          access: "read",
          identity_hints: { sandbox_id: "sandbox-a" },
        },
      });

      const fetched = await request(port, "GET", "/v1/access-requests/req-1");
      expect(fetched.statusCode).toBe(200);
      expect(JSON.parse(fetched.body).request_id).toBe("req-1");
    });
  });

  it("rejects conflicting body identity, bad host, and bad plugin attestation", async () => {
    const deps = makeDeps();
    await withServer(deps, async (port) => {
      const conflict = await request(port, "POST", "/v1/access-requests", {
        sandbox_id: "sandbox-b",
        llm_proposal: { preset: "github", access: "read", duration: "session" },
      });
      expect(conflict.statusCode).toBe(403);
      expect(conflict.body).toMatch(/conflicts with mTLS identity/);

      const badHost = await request(port, "GET", "/v1/access-requests/req-1", undefined, {
        headers: {
          Host: "evil.example",
          "X-NemoClaw-Plugin-Attestation": "builtin-openclaw",
        },
      });
      expect(badHost.statusCode).toBe(421);

      const badToken = await request(port, "GET", "/v1/access-requests/req-1", undefined, {
        headers: {
          Host: "nemoclaw-control.local",
          "X-NemoClaw-Plugin-Attestation": "wrong-token",
        },
      });
      expect(badToken.statusCode).toBe(401);
    });
  });

  it("rejects clients without an mTLS certificate during TLS negotiation", async () => {
    const deps = makeDeps();
    await withServer(deps, async (port) => {
      await expect(
        request(port, "GET", "/v1/access-requests/req-1", undefined, {
          key: undefined,
          cert: undefined,
        }),
      ).rejects.toThrow();
    });
  });
});
