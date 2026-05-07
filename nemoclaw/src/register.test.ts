// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { OpenClawPluginApi, PluginToolDefinition } from "./index.js";

vi.mock("./onboard/config.js", () => ({
  loadOnboardConfig: vi.fn(),
  describeOnboardEndpoint: vi.fn(() => "build.nvidia.com"),
  describeOnboardProvider: vi.fn(() => "NVIDIA Endpoint API"),
}));

vi.mock("./access-client.js", () => ({
  createAccessRequest: vi.fn(),
  getAccessRequest: vi.fn(),
  listAccessPresets: vi.fn(),
}));

vi.mock("./access-denials.js", () => ({
  readRecentAccessDenials: vi.fn(),
  findRecentAccessDenial: vi.fn(),
}));

import register, { getPluginConfig } from "./index.js";
import { loadOnboardConfig } from "./onboard/config.js";
import { createAccessRequest, getAccessRequest, listAccessPresets } from "./access-client.js";
import { findRecentAccessDenial, readRecentAccessDenials } from "./access-denials.js";

const mockedLoadOnboardConfig = vi.mocked(loadOnboardConfig);
const mockedCreateAccessRequest = vi.mocked(createAccessRequest);
const mockedGetAccessRequest = vi.mocked(getAccessRequest);
const mockedListAccessPresets = vi.mocked(listAccessPresets);
const mockedReadRecentAccessDenials = vi.mocked(readRecentAccessDenials);
const mockedFindRecentAccessDenial = vi.mocked(findRecentAccessDenial);
const CONTROL_OPTIONS = {
  controlUrl: "https://nemoclaw-control.local",
};

function createMockApi(): OpenClawPluginApi {
  return {
    id: "nemoclaw",
    name: "NemoClaw",
    version: "0.1.0",
    config: {},
    pluginConfig: {},
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
    registerCommand: vi.fn(),
    registerProvider: vi.fn(),
    registerService: vi.fn(),
    registerTool: vi.fn(),
    resolvePath: vi.fn((p: string) => p),
    on: vi.fn(),
  };
}

function getRegisteredTool(api: OpenClawPluginApi, name: string): PluginToolDefinition {
  const call = vi.mocked(api.registerTool).mock.calls.find(([tool]) => tool.name === name);
  expect(call).toBeDefined();
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- guarded by expect above
  return call![0];
}

describe("plugin registration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedLoadOnboardConfig.mockReturnValue(null);
    mockedCreateAccessRequest.mockReset();
    mockedGetAccessRequest.mockReset();
    mockedListAccessPresets.mockReset();
    mockedReadRecentAccessDenials.mockReset();
    mockedFindRecentAccessDenial.mockReset();
    process.env.NEMOCLAW_CONTROL_URL = CONTROL_OPTIONS.controlUrl;
    delete process.env.NEMOCLAW_CONTROL_CA_PEM_B64;
    delete process.env.NEMOCLAW_CONTROL_CERT_PEM_B64;
    delete process.env.NEMOCLAW_CONTROL_KEY_PEM_B64;
    delete process.env.NEMOCLAW_CONTROL_CA_PATH;
    delete process.env.NEMOCLAW_CONTROL_CERT_PATH;
    delete process.env.NEMOCLAW_CONTROL_KEY_PATH;
    delete process.env.NEMOCLAW_CONTROL_SERVERNAME;
    delete process.env.NEMOCLAW_PLUGIN_ATTESTATION;
  });

  it("registers a slash command", () => {
    const api = createMockApi();
    register(api);
    expect(api.registerCommand).toHaveBeenCalledWith(expect.objectContaining({ name: "nemoclaw" }));
  });

  it("registers an inference provider", () => {
    const api = createMockApi();
    register(api);
    expect(api.registerProvider).toHaveBeenCalledWith(expect.objectContaining({ id: "inference" }));
  });

  it("registers resource access tools", () => {
    const api = createMockApi();
    register(api);
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "request_resource_access" }),
    );
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "list_resource_access_presets" }),
    );
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "check_resource_access" }),
    );
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "get_recent_access_denials" }),
    );
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "request_access_for_denial" }),
    );
  });

  it("request_resource_access schema defaults to least-privilege read access", () => {
    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "request_resource_access");

    expect(tool.parameters).toMatchObject({
      required: ["user_intent", "resource", "reason"],
      properties: {
        access: {
          enum: ["read", "read_write"],
          default: "read",
        },
        wait_timeout_ms: {
          default: 90_000,
          maximum: 300_000,
        },
      },
    });
  });

  it("list_resource_access_presets returns presets from the host control plane", async () => {
    mockedListAccessPresets.mockResolvedValue({
      presets: [
        { name: "github", description: "GitHub access" },
        { name: "pypi", description: "Python Package Index access" },
      ],
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "list_resource_access_presets");
    const result = await tool.execute("call_1", {});

    expect(mockedListAccessPresets).toHaveBeenCalledWith(CONTROL_OPTIONS);
    expect(result).toEqual({
      presets: [
        { name: "github", description: "GitHub access" },
        { name: "pypi", description: "Python Package Index access" },
      ],
    });
  });

  it("request_resource_access posts a proposal and returns applied status only from NemoClaw", async () => {
    mockedCreateAccessRequest.mockResolvedValue({
      request_id: "req_123",
      status: "applied",
      message: "GitHub access applied.",
      canonical_request: {
        resource_type: "network",
        preset: "github",
        access: "read",
        duration: "session",
      },
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "request_resource_access");
    const result = await tool.execute("call_1", {
      user_intent: "I want access to GitHub",
      resource: "github",
      reason: "Inspect a repository.",
    });

    expect(mockedCreateAccessRequest).toHaveBeenCalledWith(
      {
        version: "nemoclaw.access.v1",
        user_intent: "I want access to GitHub",
        llm_proposal: {
          resource_type: "network",
          preset: "github",
          access: "read",
          duration: "session",
          reason: "Inspect a repository.",
        },
      },
      CONTROL_OPTIONS,
    );
    expect(mockedGetAccessRequest).not.toHaveBeenCalled();
    expect(result).toEqual({
      request_id: "req_123",
      status: "applied",
      message: "GitHub access applied.",
      canonical_request: {
        resource_type: "network",
        preset: "github",
        access: "read",
        duration: "session",
      },
    });
  });

  it("request_resource_access normalizes GitHub host aliases to the github preset", async () => {
    mockedCreateAccessRequest.mockResolvedValue({
      request_id: "req_123",
      status: "pending",
      canonical_request: {
        preset: "github",
      },
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "request_resource_access");
    await tool.execute("call_1", {
      user_intent: "I want access to GitHub",
      resource: "github.com",
      reason: "Inspect a repository.",
      wait_timeout_ms: 0,
    });

    expect(mockedCreateAccessRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        llm_proposal: expect.objectContaining({
          preset: "github",
        }),
      }),
      CONTROL_OPTIONS,
    );
  });

  it("request_resource_access returns pending with request_id when wait timeout is exhausted", async () => {
    mockedCreateAccessRequest.mockResolvedValue({
      request_id: "req_pending",
      status: "pending_approval",
      message: "Waiting for operator approval.",
      canonical_request: {
        preset: "github",
      },
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "request_resource_access");
    const result = await tool.execute("call_1", {
      user_intent: "I want access to GitHub",
      resource: "github",
      reason: "Inspect a repository.",
      wait_timeout_ms: 0,
    });

    expect(result).toEqual({
      request_id: "req_pending",
      status: "pending_approval",
      message: "Waiting for operator approval.",
      canonical_request: {
        preset: "github",
      },
    });
  });

  it("check_resource_access gets existing request status without approval controls", async () => {
    mockedGetAccessRequest.mockResolvedValue({
      request_id: "req_denied",
      status: "denied",
      message: "Operator denied this request.",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "check_resource_access");
    const result = await tool.execute("call_2", {
      request_id: "req_denied",
    });

    expect(mockedGetAccessRequest).toHaveBeenCalledWith("req_denied", CONTROL_OPTIONS);
    expect(mockedCreateAccessRequest).not.toHaveBeenCalled();
    expect(result).toEqual({
      request_id: "req_denied",
      status: "denied",
      message: "Operator denied this request.",
    });
  });

  it("get_recent_access_denials returns structured denials with suggested access", async () => {
    mockedReadRecentAccessDenials.mockReturnValue([
      {
        version: "nemoclaw.denial.v1",
        id: "denial-1",
        kind: "network_policy_denial",
        observed_at: "2026-05-06T14:00:00.000Z",
        observed: { method: "GET", host: "api.github.com" },
        suggested_access: { resource: "github", access: "read", duration: "session" },
        user_message: "GitHub access is blocked by the current sandbox policy.",
      },
    ]);

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "get_recent_access_denials");
    const result = await tool.execute("call_3", { limit: 1 });

    expect(mockedReadRecentAccessDenials).toHaveBeenCalledWith({ limit: 1 });
    expect(result).toEqual({
      denials: [
        expect.objectContaining({
          id: "denial-1",
          suggested_access: { resource: "github", access: "read", duration: "session" },
        }),
      ],
    });
  });

  it("request_access_for_denial uses suggested access from a structured denial", async () => {
    mockedFindRecentAccessDenial.mockReturnValue({
      version: "nemoclaw.denial.v1",
      id: "denial-1",
      kind: "network_policy_denial",
      observed_at: "2026-05-06T14:00:00.000Z",
      observed: { method: "GET", host: "api.github.com" },
      openshell: { detail: "request denied by policy" },
      suggested_access: { resource: "github", access: "read", duration: "session" },
      user_message: "GitHub access is blocked by the current sandbox policy.",
    });
    mockedCreateAccessRequest.mockResolvedValue({
      request_id: "req_from_denial",
      status: "pending_approval",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "request_access_for_denial");
    const result = await tool.execute("call_4", {
      denial_id: "denial-1",
      wait_timeout_ms: 0,
    });

    expect(mockedCreateAccessRequest).toHaveBeenCalledWith(
      {
        version: "nemoclaw.access.v1",
        task_id: "denial-1",
        user_intent: "GitHub access is blocked by the current sandbox policy.",
        llm_proposal: {
          resource_type: "network",
          preset: "github",
          access: "read",
          duration: "session",
          reason: "request denied by policy",
        },
      },
      CONTROL_OPTIONS,
    );
    expect(result).toEqual({
      request_id: "req_from_denial",
      status: "pending_approval",
      message:
        "Access request is still pending; call check_resource_access with the request_id to continue polling.",
    });
  });

  it("does NOT register CLI commands", () => {
    const api = createMockApi();
    // registerCli should not exist on the API interface after removal
    expect("registerCli" in api).toBe(false);
  });

  it("requires an HTTPS mTLS control URL before calling NemoClaw control", async () => {
    delete process.env.NEMOCLAW_CONTROL_URL;
    mockedCreateAccessRequest.mockResolvedValue({
      request_id: "req_123",
      status: "applied",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "request_resource_access");

    await expect(
      tool.execute("call_1", {
        user_intent: "I want access to GitHub",
        resource: "github",
        reason: "Inspect a repository.",
      }),
    ).rejects.toThrow(/NEMOCLAW_CONTROL_URL is required/);
    expect(mockedCreateAccessRequest).not.toHaveBeenCalled();
  });

  it("registers custom model when onboard config has a model", () => {
    mockedLoadOnboardConfig.mockReturnValue({
      endpointType: "build",
      endpointUrl: "https://api.build.nvidia.com/v1",
      ncpPartner: null,
      model: "nvidia/custom-model",
      profile: "default",
      credentialEnv: "NVIDIA_API_KEY",
      onboardedAt: "2026-03-01T00:00:00.000Z",
    });
    const api = createMockApi();
    register(api);
    const providerArg = vi.mocked(api.registerProvider).mock.calls[0][0];
    expect(providerArg.models?.chat).toEqual([
      expect.objectContaining({ id: "inference/nvidia/custom-model" }),
    ]);
  });

  it("uses OpenClaw config model when onboard config is unavailable", () => {
    const api = createMockApi();
    api.config = {
      agents: {
        defaults: {
          model: {
            primary: "inference/llama3.2:latest",
          },
        },
      },
    };
    register(api);

    const providerArg = vi.mocked(api.registerProvider).mock.calls[0][0];
    expect(providerArg.models?.chat).toEqual([
      expect.objectContaining({
        id: "inference/llama3.2:latest",
        label: "llama3.2:latest",
      }),
    ]);

    const logLines = vi.mocked(api.logger.info).mock.calls.map(([message]) => message);
    expect(logLines.some((line) => line.includes("Model:     llama3.2:latest"))).toBe(true);
  });

  it("prefers live gateway model over stale onboard config model after runtime switch (#2608)", () => {
    mockedLoadOnboardConfig.mockReturnValue({
      endpointType: "build",
      endpointUrl: "https://api.build.nvidia.com/v1",
      ncpPartner: null,
      model: "nvidia/nemotron-3-super-120b-a12b",
      profile: "default",
      credentialEnv: "NVIDIA_API_KEY",
      onboardedAt: "2026-03-01T00:00:00.000Z",
    });

    const api = createMockApi();
    api.config = {
      agents: {
        defaults: {
          model: {
            primary: "inference/nvidia/llama-3.3-nemotron-super-49b-v1.5",
          },
        },
      },
    };
    register(api);

    const providerArg = vi.mocked(api.registerProvider).mock.calls[0][0];
    expect(providerArg.models?.chat).toEqual([
      expect.objectContaining({ id: "inference/nvidia/llama-3.3-nemotron-super-49b-v1.5" }),
    ]);

    const logLines = vi.mocked(api.logger.info).mock.calls.map(([message]) => message);
    expect(
      logLines.some((line) => line.includes("Model:     nvidia/llama-3.3-nemotron-super-49b-v1.5")),
    ).toBe(true);
  });

  it("does not treat the provider name as a fallback endpoint", () => {
    const api = createMockApi();
    api.config = {
      agents: {
        defaults: {
          model: {
            primary: "inference/llama3.2:latest",
          },
        },
      },
    };
    register(api);

    const logLines = vi.mocked(api.logger.info).mock.calls.map(([message]) => message);
    expect(logLines.some((line) => line.includes("Endpoint:  build.nvidia.com"))).toBe(true);
    expect(logLines.some((line) => line.includes("Endpoint:  Ollama"))).toBe(false);
  });
});

describe("before_tool_call secret scanner hook (#1233)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedLoadOnboardConfig.mockReturnValue(null);
  });

  function getHookHandler(api: OpenClawPluginApi) {
    register(api);
    const onCalls = vi.mocked(api.on).mock.calls;
    const hookCall = onCalls.find(([name]) => name === "before_tool_call");
    expect(hookCall).toBeDefined();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- guarded by expect above
    return hookCall![1];
  }

  it("registers a before_tool_call hook", () => {
    const api = createMockApi();
    register(api);
    expect(api.on).toHaveBeenCalledWith("before_tool_call", expect.any(Function));
  });

  it("blocks write to memory path containing NVIDIA API key", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const fakeKey = "nvapi-" + "abcdefghijklmnopqrstuvwxyz";
    const result = handler({
      toolName: "write",
      params: {
        file_path: "/sandbox/.openclaw-data/memory/project.md",
        content: `api key: ${fakeKey}`,
      },
    });
    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toContain("NVIDIA API key");
  });

  it("blocks edit to memory path containing secrets", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const fakeToken = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
    const result = handler({
      toolName: "edit",
      params: {
        file_path: "/sandbox/.openclaw-data/memory/notes.md",
        new_string: `token: ${fakeToken}`,
      },
    });
    expect(result).toMatchObject({ block: true });
  });

  it("blocks apply_patch to memory path containing secrets", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const fakeKey = "sk-" + "abc123def456ghi789jkl012mno";
    const result = handler({
      toolName: "apply_patch",
      params: {
        file_path: "/sandbox/.openclaw-data/agents/config.json",
        patch: fakeKey,
      },
    });
    expect(result).toMatchObject({ block: true });
  });

  it("blocks notebook_edit to memory path containing secrets", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const fakeKey = "nvapi-" + "abcdefghijklmnopqrstuvwxyz";
    const result = handler({
      toolName: "notebook_edit",
      params: {
        file_path: "/sandbox/.openclaw-data/memory/notebook.ipynb",
        content: `api_key: ${fakeKey}`,
      },
    });
    expect(result).toMatchObject({ block: true });
  });

  it("allows write to memory path with clean content", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const result = handler({
      toolName: "write",
      params: {
        file_path: "/sandbox/.openclaw-data/memory/project.md",
        content: "# My Project\n\nThis is a regular memory note.",
      },
    });
    expect(result).toBeUndefined();
  });

  it("allows write to non-memory path even with secrets", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const fakeKey = "nvapi-" + "abcdefghijklmnopqrstuvwxyz";
    const result = handler({
      toolName: "write",
      params: {
        file_path: "/sandbox/project/src/config.ts",
        content: `const key = '${fakeKey}';`,
      },
    });
    expect(result).toBeUndefined();
  });

  it("allows non-write tools regardless of content", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const result = handler({
      toolName: "read",
      params: {
        file_path: "/sandbox/.openclaw-data/memory/project.md",
      },
    });
    expect(result).toBeUndefined();
  });

  it("handles missing event gracefully", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    expect(handler(undefined)).toBeUndefined();
    expect(handler({})).toBeUndefined();
    expect(handler({ toolName: "write" })).toBeUndefined();
  });

  it("logs a warning when blocking", () => {
    const api = createMockApi();
    const handler = getHookHandler(api);
    const fakeKey = "nvapi-" + "abcdefghijklmnopqrstuvwxyz";
    handler({
      toolName: "write",
      params: {
        file_path: "/sandbox/.openclaw-data/memory/creds.md",
        content: fakeKey,
      },
    });
    expect(api.logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("[SECURITY] Blocked memory write"),
    );
  });
});

describe("getPluginConfig", () => {
  it("returns defaults when pluginConfig is undefined", () => {
    const api = createMockApi();
    api.pluginConfig = undefined;
    const config = getPluginConfig(api);
    expect(config.blueprintVersion).toBe("latest");
    expect(config.blueprintRegistry).toBe("ghcr.io/nvidia/nemoclaw-blueprint");
    expect(config.sandboxName).toBe("openclaw");
    expect(config.inferenceProvider).toBe("nvidia");
  });

  it("returns defaults when pluginConfig has non-string values", () => {
    const api = createMockApi();
    api.pluginConfig = { blueprintVersion: 42, sandboxName: true };
    const config = getPluginConfig(api);
    expect(config.blueprintVersion).toBe("latest");
    expect(config.sandboxName).toBe("openclaw");
  });

  it("uses string values from pluginConfig", () => {
    const api = createMockApi();
    api.pluginConfig = {
      blueprintVersion: "2.0.0",
      blueprintRegistry: "ghcr.io/custom/registry",
      sandboxName: "custom-sandbox",
      inferenceProvider: "openai",
    };
    const config = getPluginConfig(api);
    expect(config.blueprintVersion).toBe("2.0.0");
    expect(config.blueprintRegistry).toBe("ghcr.io/custom/registry");
    expect(config.sandboxName).toBe("custom-sandbox");
    expect(config.inferenceProvider).toBe("openai");
  });
});
