// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import {
  clearAccessPresetCache,
  createAccessRequest,
  getAccessRequest,
  listAccessPresets,
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
});
