// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import {
  clearAccessPresetCache,
  createAccessRequest,
  createProviderAccessRequest,
  getAccessRequest,
  getProviderAccess,
  listAccessPresets,
  listProviderAccess,
  waitAccessRequest,
} from "./access-client.js";

function withServer(
  handler: http.RequestListener,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", async () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("test server did not bind to a TCP port"));
        return;
      }
      try {
        await fn(`http://127.0.0.1:${address.port}`);
        server.close((err) => (err ? reject(err) : resolve()));
      } catch (err) {
        server.close(() => reject(err));
      }
    });
  });
}

describe("access client", () => {
  afterEach(() => {
    delete process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON;
    delete process.env.GITHUB_TOKEN;
    delete process.env.GH_TOKEN;
    delete process.env.GITLAB_TOKEN;
    delete process.env.GLAB_TOKEN;
    delete process.env.ACME_API_TOKEN;
    clearAccessPresetCache();
  });

  it("rejects non-HTTP policy.local URLs", () => {
    expect(() =>
      createAccessRequest(
        {
          version: "nemoclaw.access.v1",
          user_intent: "Need GitHub",
          llm_proposal: {
            resource_type: "network",
            preset: "github",
            access: "read",
            duration: "session",
            reason: "Inspect a repository.",
          },
        },
        { policyLocalUrl: "https://policy.local" },
      ),
    ).toThrow(/must use HTTP inside the sandbox/);
  });

  it("lists OpenShell-backed provider presets", async () => {
    await expect(listAccessPresets()).resolves.toMatchObject({
      presets: expect.arrayContaining([
        expect.objectContaining({ name: "github", provider_profile: "github" }),
        expect.objectContaining({ name: "outlook", provider_profile: "outlook" }),
      ]),
    });
  });

  it("adds dynamic OpenShell provider profiles to the access preset list", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = JSON.stringify({
      profiles: [
        {
          id: "gitlab",
          display_name: "GitLab",
          description: "GitLab API and Git operations",
          endpoints: [{ host: "gitlab.com", port: 443, protocol: "rest" }],
          binaries: ["/usr/bin/git"],
        },
        {
          id: "empty-provider",
          display_name: "Empty",
          endpoints: [],
        },
      ],
    });

    await expect(listAccessPresets()).resolves.toMatchObject({
      presets: expect.arrayContaining([
        expect.objectContaining({
          name: "gitlab",
          description: "GitLab API and Git operations",
          provider_profile: "gitlab",
        }),
      ]),
    });
    const response = await listAccessPresets();
    expect(response.presets.some((preset) => preset.name === "empty-provider")).toBe(false);
  });

  it("ignores malformed provider profile overrides", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = "{not-json";

    await expect(listAccessPresets()).resolves.toMatchObject({
      presets: expect.arrayContaining([expect.objectContaining({ name: "github" })]),
    });
  });

  it("ignores blank provider profile overrides", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = "   ";

    await expect(listAccessPresets()).resolves.toMatchObject({
      presets: expect.arrayContaining([expect.objectContaining({ name: "github" })]),
    });
  });

  it("ignores provider profile override objects without profiles arrays", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = JSON.stringify({ profiles: null });

    const response = await listAccessPresets();
    expect(response.presets.some((preset) => preset.name === "mixed-provider")).toBe(false);
  });

  it("merges dynamic profiles into existing built-in presets", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = JSON.stringify([
      {
        id: "github",
        description: "Gateway GitHub profile",
        endpoints: [{ host: "api.github.com", port: 443 }],
        binaries: ["/usr/bin/gh"],
      },
    ]);

    await expect(listAccessPresets()).resolves.toMatchObject({
      presets: expect.arrayContaining([
        expect.objectContaining({
          name: "github",
          provider_profile: "github",
        }),
      ]),
    });
  });

  it("drops invalid provider profile endpoints and binary entries", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = JSON.stringify({
      profiles: [
        {
          id: "mixed-provider",
          display_name: "Mixed Provider",
          endpoints: [
            { host: "api.mixed.example", port: 443 },
            { host: "bad.example", port: 0 },
          ],
          binaries: ["/usr/bin/curl", { path: "/usr/bin/node" }, { path: 42 }],
        },
      ],
    });

    let captured = "";
    await withServer(
      (req, res) => {
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
          captured += chunk;
        });
        req.on("end", () => {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({ accepted_chunk_ids: ["chunk_mixed"] }));
        });
      },
      async (baseUrl) => {
        await expect(
          createAccessRequest(
            {
              version: "nemoclaw.access.v1",
              user_intent: "Inspect mixed provider",
              llm_proposal: {
                resource_type: "network",
                preset: "mixed-provider",
                access: "read",
                duration: "session",
                reason: "Exercise profile cleanup.",
              },
            },
            { policyLocalUrl: baseUrl },
          ),
        ).resolves.toMatchObject({ request_id: "chunk_mixed" });
      },
    );

    const rule = JSON.parse(captured).operations[0].addRule.rule;
    expect(rule.endpoints).toHaveLength(1);
    expect(rule.binaries).toEqual([{ path: "/usr/bin/curl" }, { path: "/usr/bin/node" }]);
  });

  it("submits provider-profile-backed proposals", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = JSON.stringify([
      {
        id: "gitlab",
        description: "GitLab access",
        endpoints: [
          {
            host: "gitlab.com",
            port: 443,
            protocol: "rest",
            enforcement: "enforce",
          },
        ],
        binaries: ["/usr/bin/git"],
      },
    ]);

    let captured = "";
    await withServer(
      (req, res) => {
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
          captured += chunk;
        });
        req.on("end", () => {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({ accepted_chunk_ids: ["chunk_gitlab"] }));
        });
      },
      async (baseUrl) => {
        await expect(
          createAccessRequest(
            {
              version: "nemoclaw.access.v1",
              user_intent: "Inspect merge requests",
              llm_proposal: {
                resource_type: "network",
                preset: "gitlab",
                access: "read",
                duration: "session",
                reason: "Need GitLab API metadata.",
              },
            },
            { policyLocalUrl: baseUrl },
          ),
        ).resolves.toMatchObject({ request_id: "chunk_gitlab", status: "pending_approval" });
      },
    );

    const body = JSON.parse(captured);
    expect(body.operations[0].addRule.ruleName).toBe("gitlab");
    expect(body.operations[0].addRule.rule).toMatchObject({
      name: "gitlab",
      endpoints: [
        {
          host: "gitlab.com",
          port: 443,
          protocol: "rest",
          enforcement: "enforce",
        },
      ],
      binaries: [{ path: "/usr/bin/git" }],
    });
    expect(body.operations[0].addRule.rule.endpoints[0].rules).toEqual([
      { allow: { method: "GET", path: "/**" } },
      { allow: { method: "HEAD", path: "/**" } },
    ]);
  });

  it("rejects unknown access presets before submitting proposals", () => {
    expect(() =>
      createAccessRequest({
        version: "nemoclaw.access.v1",
        user_intent: "Need an unknown service",
        llm_proposal: {
          resource_type: "network",
          preset: "missing-service",
          access: "read",
          duration: "session",
          reason: "Exercise validation.",
        },
      }),
    ).toThrow("Unknown access preset 'missing-service'.");
  });

  it("normalizes URL resources and expands read-write methods", async () => {
    let captured = "";
    await withServer(
      (req, res) => {
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
          captured += chunk;
        });
        req.on("end", () => {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({ accepted_chunk_ids: ["chunk_rw"] }));
        });
      },
      async (baseUrl) => {
        await expect(
          createAccessRequest(
            {
              version: "nemoclaw.access.v1",
              user_intent: "Update an issue",
              llm_proposal: {
                resource_type: "network",
                preset: "https://api.github.com/repos/example/repo",
                access: "read_write",
                duration: "session",
                reason: "Need GitHub API writes.",
              },
            },
            { policyLocalUrl: baseUrl },
          ),
        ).resolves.toMatchObject({ request_id: "chunk_rw" });
      },
    );

    const rule = JSON.parse(captured).operations[0].addRule.rule;
    expect(rule.name).toBe("github");
    expect(rule.endpoints[0].rules).toEqual([
      { allow: { method: "GET", path: "/**" } },
      { allow: { method: "HEAD", path: "/**" } },
      { allow: { method: "POST", path: "/**" } },
      { allow: { method: "PUT", path: "/**" } },
      { allow: { method: "PATCH", path: "/**" } },
      { allow: { method: "DELETE", path: "/**" } },
    ]);
  });

  it("preserves full-access endpoint policy without synthesized method rules", async () => {
    process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON = JSON.stringify([
      {
        id: "full-provider",
        endpoints: [{ host: "full.example", port: 443, access: "full", tls: "skip" }],
        binaries: ["/usr/bin/curl"],
      },
    ]);

    let captured = "";
    await withServer(
      (req, res) => {
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
          captured += chunk;
        });
        req.on("end", () => {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({ accepted_chunk_ids: ["chunk_npm"] }));
        });
      },
      async (baseUrl) => {
        await expect(
          createAccessRequest(
            {
              version: "nemoclaw.access.v1",
              user_intent: "Install packages",
              llm_proposal: {
                resource_type: "network",
                preset: "full-provider",
                access: "read",
                duration: "session",
                reason: "Need full tunnel reachability.",
              },
            },
            { policyLocalUrl: baseUrl },
          ),
        ).resolves.toMatchObject({ request_id: "chunk_npm" });
      },
    );

    const endpoint = JSON.parse(captured).operations[0].addRule.rule.endpoints.find(
      (candidate: { access?: string }) => candidate.access === "full",
    );
    expect(endpoint).toBeDefined();
    expect(endpoint.access).toBe("full");
    expect(endpoint.rules).toBeUndefined();
  });

  it("rejects non-2xx and non-object policy.local responses", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "bad" }));
      },
      async (baseUrl) => {
        await expect(getAccessRequest("chunk", { policyLocalUrl: baseUrl })).rejects.toThrow(
          /failed with HTTP 500/,
        );
      },
    );

    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify([]));
      },
      async (baseUrl) => {
        await expect(getAccessRequest("chunk", { policyLocalUrl: baseUrl })).rejects.toThrow(
          /non-object response/,
        );
      },
    );
  });

  it("does not report approved requests as applied until policy reloads", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            chunk_id: "chunk_wait",
            status: "approved",
            policy_reloaded: false,
          }),
        );
      },
      async (baseUrl) => {
        await expect(getAccessRequest("chunk_wait", { policyLocalUrl: baseUrl })).resolves.toEqual({
          request_id: "chunk_wait",
          status: "pending_approval",
          message: undefined,
          canonical_request: {
            chunk_id: "chunk_wait",
            status: "approved",
            policy_reloaded: false,
          },
        });
      },
    );
  });

  it("maps pending, rejected, and unknown proposal states", async () => {
    await withServer(
      (req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        if (req.url?.includes("rejected")) {
          res.end(
            JSON.stringify({
              chunk_id: "rejected",
              status: "rejected",
              rejection_reason: "Operator denied.",
            }),
          );
          return;
        }
        if (req.url?.includes("pending")) {
          res.end(JSON.stringify({ chunk_id: "pending", status: "pending" }));
          return;
        }
        res.end(JSON.stringify({ chunk_id: "weird", status: "unexpected" }));
      },
      async (baseUrl) => {
        await expect(getAccessRequest("rejected", { policyLocalUrl: baseUrl })).resolves.toEqual(
          expect.objectContaining({
            request_id: "rejected",
            status: "denied",
            message: "Operator denied.",
          }),
        );
        await expect(getAccessRequest("pending", { policyLocalUrl: baseUrl })).resolves.toEqual(
          expect.objectContaining({
            request_id: "pending",
            status: "pending_approval",
          }),
        );
        await expect(getAccessRequest("weird", { policyLocalUrl: baseUrl })).resolves.toEqual(
          expect.objectContaining({
            request_id: "weird",
            status: "failed",
          }),
        );
      },
    );
  });

  it("returns failed status when OpenShell rejects a proposal", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ rejection_reasons: ["provider missing"] }));
      },
      async (baseUrl) => {
        await expect(
          createProviderAccessRequest(
            {
              version: "nemoclaw.provider_access.v1",
              user_intent: "Review pull requests",
              provider_name: "github",
              reason: "Need provider access.",
            },
            { policyLocalUrl: baseUrl },
          ),
        ).resolves.toEqual({
          request_id: "",
          status: "failed",
          message: 'OpenShell rejected the proposal: ["provider missing"]',
        });
      },
    );
  });

  it("waits for access requests with bounded timeout seconds", async () => {
    let observedUrl = "";
    await withServer(
      (req, res) => {
        observedUrl = req.url ?? "";
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ chunk_id: "chunk_wait", status: "approved", policy_reloaded: true }),
        );
      },
      async (baseUrl) => {
        await expect(
          waitAccessRequest("chunk_wait", 350_000, { policyLocalUrl: baseUrl }),
        ).resolves.toMatchObject({
          request_id: "chunk_wait",
          status: "applied",
        });
      },
    );
    expect(observedUrl).toBe("/v1/proposals/chunk_wait/wait?timeout=300");
  });

  it("submits provider access requests", async () => {
    let captured = "";
    await withServer(
      (req, res) => {
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
          captured += chunk;
        });
        req.on("end", () => {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({ accepted_chunk_ids: ["chunk_provider"] }));
        });
      },
      async (baseUrl) => {
        await expect(
          createProviderAccessRequest(
            {
              version: "nemoclaw.provider_access.v1",
              user_intent: "Review pull requests",
              provider_name: "github",
              provider_type: "github",
              reason: "Need the host-managed GitHub token.",
            },
            { policyLocalUrl: baseUrl },
          ),
        ).resolves.toMatchObject({ request_id: "chunk_provider", status: "pending_approval" });
      },
    );

    expect(JSON.parse(captured)).toEqual({
      human_summary: "Attach provider github",
      intent_summary: "Review pull requests Need the host-managed GitHub token.",
      operations: [
        {
          requestProvider: {
            providerName: "github",
            providerType: "github",
          },
        },
      ],
    });
  });

  it("reports approved provider requests as applied without policy reload", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            chunk_id: "chunk_provider",
            status: "approved",
            request_type: "provider",
            policy_reloaded: false,
          }),
        );
      },
      async (baseUrl) => {
        await expect(
          getAccessRequest("chunk_provider", { policyLocalUrl: baseUrl }),
        ).resolves.toMatchObject({
          request_id: "chunk_provider",
          status: "applied",
        });
      },
    );
  });

  it("lists attached provider access from OpenShell credential placeholders", async () => {
    process.env.GITHUB_TOKEN = "openshell:resolve:env:v123_GITHUB_TOKEN";
    process.env.GITLAB_TOKEN = "openshell:resolve:env:v123_GITLAB_TOKEN";

    await expect(listProviderAccess()).resolves.toEqual({
      providers: [
        {
          provider_name: "github",
          provider_type: "github",
          status: "attached",
          credential_env: "GITHUB_TOKEN",
          credential_state: "attached_placeholder",
          usable_via_proxy: true,
          raw_secret_available: false,
          credential_available: true,
        },
        {
          provider_name: "gitlab",
          provider_type: "gitlab",
          status: "attached",
          credential_env: "GITLAB_TOKEN",
          credential_state: "attached_placeholder",
          usable_via_proxy: true,
          raw_secret_available: false,
          credential_available: true,
        },
      ],
    });
  });

  it("deduplicates placeholder aliases for the same provider", async () => {
    process.env.GITHUB_TOKEN = "openshell:resolve:env:v123_GITHUB_TOKEN";
    process.env.GH_TOKEN = "openshell:resolve:env:v123_GH_TOKEN";

    await expect(getProviderAccess("github")).resolves.toMatchObject({
      provider_name: "github",
      credential_env: "GH_TOKEN",
    });
  });

  it("infers provider names from unknown placeholder environment variables", async () => {
    process.env.ACME_API_TOKEN = "openshell:resolve:env:v123_ACME_API_TOKEN";

    await expect(getProviderAccess("acme")).resolves.toEqual({
      provider_name: "acme",
      status: "attached",
      credential_env: "ACME_API_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    });
  });

  it("lists attached provider access from policy.local provider state", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            providers: [
              {
                provider_name: "github",
                provider_type: "github",
                credential_keys: ["GITHUB_TOKEN"],
                config_keys: [],
              },
            ],
          }),
        );
      },
      async (baseUrl) => {
        await expect(listProviderAccess({ policyLocalUrl: baseUrl })).resolves.toEqual({
          providers: [
            {
              provider_name: "github",
              provider_type: "github",
              status: "attached",
              credential_env: "GITHUB_TOKEN",
              credential_state: "attached_placeholder",
              usable_via_proxy: true,
              raw_secret_available: false,
              credential_available: true,
            },
          ],
        });
      },
    );
  });

  it("reports attached providers without credential keys as unknown proxy state", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            providers: [
              {
                provider_name: "github",
                provider_type: "github",
                credential_keys: [],
              },
            ],
          }),
        );
      },
      async (baseUrl) => {
        await expect(listProviderAccess({ policyLocalUrl: baseUrl })).resolves.toEqual({
          providers: [
            {
              provider_name: "github",
              provider_type: "github",
              status: "attached",
              credential_state: "attached_unknown",
              usable_via_proxy: false,
              raw_secret_available: false,
              credential_available: false,
            },
          ],
        });
      },
    );
  });

  it("ignores blank provider records from policy.local provider state", async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            providers: [
              { provider_name: "   ", provider_type: "github", credential_keys: ["GITHUB_TOKEN"] },
              { provider_name: "github", provider_type: "github", credential_keys: [] },
            ],
          }),
        );
      },
      async (baseUrl) => {
        await expect(listProviderAccess({ policyLocalUrl: baseUrl })).resolves.toEqual({
          providers: [
            {
              provider_name: "github",
              provider_type: "github",
              status: "attached",
              credential_state: "attached_unknown",
              usable_via_proxy: false,
              raw_secret_available: false,
              credential_available: false,
            },
          ],
        });
      },
    );
  });

  it("merges policy.local provider state with visible credential placeholders", async () => {
    process.env.GITHUB_TOKEN = "openshell:resolve:env:v123_GITHUB_TOKEN";

    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            providers: [
              {
                provider_name: "github",
                provider_type: "github",
                credential_keys: ["GITHUB_TOKEN"],
                config_keys: [],
              },
            ],
          }),
        );
      },
      async (baseUrl) => {
        await expect(listProviderAccess({ policyLocalUrl: baseUrl })).resolves.toEqual({
          providers: [
            {
              provider_name: "github",
              provider_type: "github",
              status: "attached",
              credential_env: "GITHUB_TOKEN",
              credential_state: "attached_placeholder",
              usable_via_proxy: true,
              raw_secret_available: false,
              credential_available: true,
            },
          ],
        });
      },
    );
  });

  it("checks attached provider access by provider name", async () => {
    process.env.GITHUB_TOKEN = "openshell:resolve:env:v123_GITHUB_TOKEN";

    await expect(getProviderAccess("github")).resolves.toEqual({
      provider_name: "github",
      provider_type: "github",
      status: "attached",
      credential_env: "GITHUB_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    });
    await expect(getProviderAccess("missing")).resolves.toBeNull();
    await expect(getProviderAccess("   ")).resolves.toBeNull();
  });

  it("uses HTTP proxy transport for policy.local requests", async () => {
    const oldHttpProxy = process.env.HTTP_PROXY;
    const oldLowerHttpProxy = process.env.http_proxy;
    const observedRequests: string[] = [];
    const proxy = net.createServer((socket) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => {
        chunks.push(chunk);
        const raw = Buffer.concat(chunks).toString("utf8");
        if (!raw.includes("\r\n\r\n")) return;
        observedRequests.push(raw);
        socket.end(
          [
            "HTTP/1.1 202 Accepted",
            "Content-Type: application/json",
            "Connection: close",
            "",
            JSON.stringify({ accepted_chunk_ids: ["chunk_proxy"] }),
          ].join("\r\n"),
        );
      });
    });

    await new Promise<void>((resolve, reject) => {
      proxy.listen(0, "127.0.0.1", () => resolve());
      proxy.on("error", reject);
    });

    try {
      const address = proxy.address();
      if (!address || typeof address === "string") throw new Error("proxy did not bind");
      process.env.HTTP_PROXY = `http://127.0.0.1:${address.port}`;
      delete process.env.http_proxy;
      await expect(
        createProviderAccessRequest({
          version: "nemoclaw.provider_access.v1",
          user_intent: "Review pull requests",
          provider_name: "github",
          reason: "Need provider access.",
        }),
      ).resolves.toMatchObject({ request_id: "chunk_proxy", status: "pending_approval" });
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
      if (oldHttpProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = oldHttpProxy;
      if (oldLowerHttpProxy === undefined) delete process.env.http_proxy;
      else process.env.http_proxy = oldLowerHttpProxy;
    }

    expect(observedRequests[0]).toContain("POST http://policy.local:80/v1/proposals HTTP/1.1");
  });

  it("reports malformed and failed HTTP proxy responses", async () => {
    const oldHttpProxy = process.env.HTTP_PROXY;
    const oldLowerHttpProxy = process.env.http_proxy;
    const proxy = net.createServer((socket) => {
      socket.once("data", () => {
        socket.end("not-http");
      });
    });

    await new Promise<void>((resolve, reject) => {
      proxy.listen(0, "127.0.0.1", () => resolve());
      proxy.on("error", reject);
    });

    try {
      const address = proxy.address();
      if (!address || typeof address === "string") throw new Error("proxy did not bind");
      process.env.HTTP_PROXY = `http://127.0.0.1:${address.port}`;
      delete process.env.http_proxy;
      await expect(
        createProviderAccessRequest({
          version: "nemoclaw.provider_access.v1",
          user_intent: "Review pull requests",
          provider_name: "github",
          reason: "Need provider access.",
        }),
      ).rejects.toThrow(/malformed HTTP response/);
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
      if (oldHttpProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = oldHttpProxy;
      if (oldLowerHttpProxy === undefined) delete process.env.http_proxy;
      else process.env.http_proxy = oldLowerHttpProxy;
    }
  });

  it("reports non-2xx HTTP proxy responses", async () => {
    const oldHttpProxy = process.env.HTTP_PROXY;
    const oldLowerHttpProxy = process.env.http_proxy;
    const proxy = net.createServer((socket) => {
      socket.once("data", () => {
        socket.end(
          [
            "HTTP/1.1 403 Forbidden",
            "Content-Type: application/json",
            "Connection: close",
            "",
            JSON.stringify({ error: "blocked" }),
          ].join("\r\n"),
        );
      });
    });

    await new Promise<void>((resolve, reject) => {
      proxy.listen(0, "127.0.0.1", () => resolve());
      proxy.on("error", reject);
    });

    try {
      const address = proxy.address();
      if (!address || typeof address === "string") throw new Error("proxy did not bind");
      process.env.HTTP_PROXY = `http://127.0.0.1:${address.port}`;
      delete process.env.http_proxy;
      await expect(
        createProviderAccessRequest({
          version: "nemoclaw.provider_access.v1",
          user_intent: "Review pull requests",
          provider_name: "github",
          reason: "Need provider access.",
        }),
      ).rejects.toThrow(/failed with HTTP 403/);
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
      if (oldHttpProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = oldHttpProxy;
      if (oldLowerHttpProxy === undefined) delete process.env.http_proxy;
      else process.env.http_proxy = oldLowerHttpProxy;
    }
  });

  it("reports HTTP proxy responses with invalid status codes", async () => {
    const oldHttpProxy = process.env.HTTP_PROXY;
    const oldLowerHttpProxy = process.env.http_proxy;
    const proxy = net.createServer((socket) => {
      socket.once("data", () => {
        socket.end(["HTTP/1.1 nope Nope", "Connection: close", "", "bad status"].join("\r\n"));
      });
    });

    await new Promise<void>((resolve, reject) => {
      proxy.listen(0, "127.0.0.1", () => resolve());
      proxy.on("error", reject);
    });

    try {
      const address = proxy.address();
      if (!address || typeof address === "string") throw new Error("proxy did not bind");
      process.env.HTTP_PROXY = `http://127.0.0.1:${address.port}`;
      delete process.env.http_proxy;
      await expect(
        createProviderAccessRequest({
          version: "nemoclaw.provider_access.v1",
          user_intent: "Review pull requests",
          provider_name: "github",
          reason: "Need provider access.",
        }),
      ).rejects.toThrow(/failed with HTTP unknown/);
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
      if (oldHttpProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = oldHttpProxy;
      if (oldLowerHttpProxy === undefined) delete process.env.http_proxy;
      else process.env.http_proxy = oldLowerHttpProxy;
    }
  });
});
