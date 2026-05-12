// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  adviseAccessRequest,
  buildAdvisorChatBody,
  normalizeAdvisorResult,
  type AccessAdvisorOptions,
  type ResolvedInferenceRoute,
} from "../../../dist/lib/access-tui/advisor";
import type { AccessTuiRecord } from "./model";

function record(): AccessTuiRecord {
  return {
    id: "req-1",
    sandbox_id: "demo",
    status: "pending",
    preset: "slack",
    access: "read",
    duration: "session",
    task_id: "notify",
    user_intent: "Send deployment updates",
    reason: "Need Slack API access",
    created_at: "2026-05-06T14:00:00.000Z",
    updated_at: "2026-05-06T14:00:00.000Z",
    current_access: {
      sandbox_id: "demo",
      registry_presets: ["github"],
      gateway_presets: ["github"],
      effective_presets: ["github"],
      drift: false,
      requested_preset_already_active: false,
    },
  };
}

describe("access advisor", () => {
  it("builds an advisory-only chat request with verified and untrusted sections", () => {
    const body = buildAdvisorChatBody(record(), "test-model");
    expect(body.model).toBe("test-model");
    expect(JSON.stringify(body)).toContain("operator remains the only authority");
    expect(JSON.stringify(body)).toContain("verified");
    expect(JSON.stringify(body)).toContain("untrusted_agent_claims");
  });

  it("normalizes malformed advisor output to safe defaults", () => {
    expect(normalizeAdvisorResult({ recommendation: "bad", confidence: "certain" })).toEqual({
      recommendation: "needs_review",
      confidence: "low",
      summary: "Advisor returned no summary.",
      risks: [],
      missing_context: [],
    });
  });

  it("uses the configured OpenShell provider/model but calls the host-reachable upstream", async () => {
    let capturedModel: unknown = null;
    let capturedUrl = "";
    const options: AccessAdvisorOptions = {
      getGatewayInference: () => ({ provider: "nvidia-prod", model: "configured-model" }),
      requestJson: async (url, body) => {
        capturedUrl = url.toString();
        capturedModel = body.model;
        return {
          choices: [
            {
              message: {
                content: JSON.stringify({
                  recommendation: "needs_review",
                  confidence: "medium",
                  summary: "Slack is new access; verify channel scope.",
                  risks: ["External messaging access"],
                  missing_context: ["Target workspace"],
                }),
              },
            },
          ],
        };
      },
    };

    const result = await adviseAccessRequest(record(), options);

    expect(capturedUrl).toBe("https://integrate.api.nvidia.com/v1");
    expect(capturedModel).toBe("configured-model");
    expect(result).toMatchObject({
      recommendation: "needs_review",
      confidence: "medium",
      summary: "Slack is new access; verify channel scope.",
    });
  });

  it("uses the resolved OpenShell inference route key by default", async () => {
    let capturedModel: unknown = null;
    let capturedUrl = "";
    let capturedApiKey: string | null = null;
    const route: ResolvedInferenceRoute = {
      name: "inference.local",
      base_url: "https://upstream.example/v1",
      protocols: ["chat"],
      api_key: "openshell-managed-key",
      model_id: "openshell-model",
      provider_type: "openai",
      timeout_secs: 12,
    };
    const options: AccessAdvisorOptions = {
      getResolvedRoute: async () => route,
      requestJson: async (url, body, resolved) => {
        capturedUrl = url.toString();
        capturedModel = body.model;
        capturedApiKey = resolved.apiKey;
        return {
          choices: [
            {
              message: {
                content: JSON.stringify({
                  recommendation: "approve",
                  confidence: "high",
                  summary: "The existing access context is verified and the request is narrow.",
                  risks: [],
                  missing_context: [],
                }),
              },
            },
          ],
        };
      },
    };

    const result = await adviseAccessRequest(record(), options);

    expect(capturedUrl).toBe("https://upstream.example/v1");
    expect(capturedModel).toBe("openshell-model");
    expect(capturedApiKey).toBe("openshell-managed-key");
    expect(result.recommendation).toBe("approve");
  });

  it("rewrites OpenShell container host aliases for host-side local inference", async () => {
    let capturedUrl = "";
    const route: ResolvedInferenceRoute = {
      name: "inference.local",
      base_url: "http://host.openshell.internal:11434/v1",
      protocols: ["chat"],
      api_key: "",
      model_id: "local-model",
      provider_type: "openai",
      timeout_secs: 0,
    };

    await adviseAccessRequest(record(), {
      getResolvedRoute: async () => route,
      requestJson: async (url) => {
        capturedUrl = url.toString();
        return {
          choices: [
            {
              message: {
                content: JSON.stringify({
                  recommendation: "needs_review",
                  confidence: "medium",
                  summary: "Local route was reached from the host.",
                  risks: [],
                  missing_context: [],
                }),
              },
            },
          ],
        };
      },
    });

    expect(capturedUrl).toBe("http://127.0.0.1:11434/v1");
  });

  it("supports Anthropic configured inference from the host side", async () => {
    let capturedModel: unknown = null;
    let capturedHasSystem = false;
    const options: AccessAdvisorOptions = {
      getGatewayInference: () => ({ provider: "anthropic-prod", model: "claude-test" }),
      requestJson: async (_url, body) => {
        capturedModel = body.model;
        capturedHasSystem = typeof body.system === "string";
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                recommendation: "deny",
                confidence: "high",
                summary: "The request lacks a clear task justification.",
                risks: ["Unclear external access"],
                missing_context: [],
                suggested_deny_reason: "Missing clear task justification.",
              }),
            },
          ],
        };
      },
    };

    const result = await adviseAccessRequest(record(), options);

    expect(capturedModel).toBe("claude-test");
    expect(capturedHasSystem).toBe(true);
    expect(result.recommendation).toBe("deny");
    expect(result.suggested_deny_reason).toBe("Missing clear task justification.");
  });
});
