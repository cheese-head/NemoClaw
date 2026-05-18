// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { OpenClawPluginApi, PluginToolDefinition } from "./index.js";

vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
  execFile: vi.fn(),
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn((path: string) =>
    ["/usr/bin/curl", "/usr/bin/git", "/usr/local/bin/node"].includes(path),
  ),
}));

vi.mock("./onboard/config.js", () => ({
  loadOnboardConfig: vi.fn(),
  describeOnboardEndpoint: vi.fn(() => "build.nvidia.com"),
  describeOnboardProvider: vi.fn(() => "NVIDIA Endpoint API"),
}));

vi.mock("./access-client.js", () => ({
  createAccessRequest: vi.fn(),
  createProviderAccessRequest: vi.fn(),
  getAccessRequest: vi.fn(),
  getProviderAccess: vi.fn(),
  listAccessPresets: vi.fn(),
  listProviderAccess: vi.fn(),
  waitAccessRequest: vi.fn(),
}));

import { execFileSync } from "node:child_process";
import register, { getPluginConfig } from "./index.js";
import { loadOnboardConfig } from "./onboard/config.js";
import {
  createAccessRequest,
  createProviderAccessRequest,
  getAccessRequest,
  getProviderAccess,
  listAccessPresets,
  listProviderAccess,
  waitAccessRequest,
} from "./access-client.js";

const mockedExecFileSync = vi.mocked(execFileSync);
const mockedLoadOnboardConfig = vi.mocked(loadOnboardConfig);
const mockedCreateAccessRequest = vi.mocked(createAccessRequest);
const mockedCreateProviderAccessRequest = vi.mocked(createProviderAccessRequest);
const mockedGetAccessRequest = vi.mocked(getAccessRequest);
const mockedGetProviderAccess = vi.mocked(getProviderAccess);
const mockedListAccessPresets = vi.mocked(listAccessPresets);
const mockedListProviderAccess = vi.mocked(listProviderAccess);
const mockedWaitAccessRequest = vi.mocked(waitAccessRequest);

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
  return call![0];
}

describe("plugin registration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedExecFileSync.mockReset();
    mockedLoadOnboardConfig.mockReturnValue(null);
    mockedCreateAccessRequest.mockReset();
    mockedCreateProviderAccessRequest.mockReset();
    mockedGetAccessRequest.mockReset();
    mockedGetProviderAccess.mockReset();
    mockedListAccessPresets.mockReset();
    mockedListProviderAccess.mockReset();
    mockedWaitAccessRequest.mockReset();
    delete process.env.OPENSHELL_POLICY_LOCAL_URL;
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

  it("registers OpenShell access tools", () => {
    const api = createMockApi();
    register(api);
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "openshell_provider_access" }),
    );
    expect(api.registerTool).toHaveBeenCalledWith(
      expect.objectContaining({ name: "openshell_network_access" }),
    );
  });

  it("openshell_network_access action=list_presets surfaces OpenShell provider profile backed presets", async () => {
    mockedListAccessPresets.mockResolvedValue({
      presets: [
        { name: "github", description: "GitHub access", provider_profile: "github" },
        { name: "outlook", description: "Outlook access", provider_profile: "outlook" },
      ],
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_network_access");
    const result = await tool.execute("call_1", { action: "list_presets" });

    expect(mockedListAccessPresets).toHaveBeenCalledWith({});
    expect(result).toEqual({
      presets: [
        { name: "github", description: "GitHub access", provider_profile: "github" },
        { name: "outlook", description: "Outlook access", provider_profile: "outlook" },
      ],
    });
  });

  it("openshell_network_access action=request submits an OpenShell proposal and waits for approval", async () => {
    mockedCreateAccessRequest.mockResolvedValue({
      request_id: "chunk_123",
      status: "pending_approval",
      message: "Proposal submitted.",
    });
    mockedWaitAccessRequest.mockResolvedValue({
      request_id: "chunk_123",
      status: "applied",
      message: "Approved.",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_network_access");
    const result = await tool.execute("call_1", {
      action: "request",
      user_intent: "Inspect a repo",
      resource: "github.com",
      reason: "Need repository metadata.",
    });

    expect(mockedCreateAccessRequest).toHaveBeenCalledWith(
      {
        version: "nemoclaw.access.v1",
        user_intent: "Inspect a repo",
        llm_proposal: {
          resource_type: "network",
          preset: "github",
          access: "read",
          duration: "session",
          reason: "Need repository metadata.",
        },
      },
      {},
    );
    expect(mockedWaitAccessRequest).toHaveBeenCalledWith("chunk_123", 90_000, {});
    expect(result).toEqual({
      request_id: "chunk_123",
      status: "applied",
      message: "Approved.",
    });
  });

  it("openshell_network_access action=check reads an existing OpenShell proposal status", async () => {
    mockedGetAccessRequest.mockResolvedValue({
      request_id: "chunk_123",
      status: "denied",
      message: "Rejected.",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_network_access");
    const result = await tool.execute("call_2", {
      action: "check",
      request_id: "chunk_123",
    });

    expect(mockedGetAccessRequest).toHaveBeenCalledWith("chunk_123", {});
    expect(result).toEqual({
      request_id: "chunk_123",
      status: "denied",
      message: "Rejected.",
    });
  });

  it("openshell_provider_access action=request submits a provider request and waits for approval", async () => {
    mockedGetProviderAccess.mockResolvedValue(null);
    mockedCreateProviderAccessRequest.mockResolvedValue({
      request_id: "chunk_provider",
      status: "pending_approval",
      message: "Proposal submitted.",
    });
    mockedWaitAccessRequest.mockResolvedValue({
      request_id: "chunk_provider",
      status: "applied",
      message: "Approved.",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider", {
      action: "request",
      user_intent: "Review PRs",
      provider_name: "github",
      provider_type: "github",
      reason: "Need a GitHub token.",
    });

    expect(mockedCreateProviderAccessRequest).toHaveBeenCalledWith(
      {
        version: "nemoclaw.provider_access.v1",
        user_intent: "Review PRs",
        provider_name: "github",
        provider_type: "github",
        reason: "Need a GitHub token.",
      },
      {},
    );
    expect(mockedWaitAccessRequest).toHaveBeenCalledWith("chunk_provider", 90_000, {});
    expect(result).toEqual({
      request_id: "chunk_provider",
      status: "applied",
      message: "Approved.",
    });
  });

  it("openshell_provider_access action=request returns attached provider without duplicate proposal", async () => {
    mockedGetProviderAccess.mockResolvedValue({
      provider_name: "github",
      provider_type: "github",
      status: "attached",
      credential_env: "GITHUB_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider", {
      action: "request",
      user_intent: "Review PRs",
      provider_name: "github",
      provider_type: "github",
      reason: "Need a GitHub token.",
    });

    expect(mockedGetProviderAccess).toHaveBeenCalledWith("github", {});
    expect(mockedCreateProviderAccessRequest).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      provider_name: "github",
      provider_type: "github",
      status: "applied",
      credential_env: "GITHUB_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
      credential_usage: expect.objectContaining({
        kind: "bearer_header",
        header: "Authorization",
        value: "Bearer $GITHUB_TOKEN",
        proxy_required: true,
      }),
      available_tools: ["curl", "git", "node"],
      missing_tools: ["gh"],
    });
  });

  it("openshell_provider_access action=list reports attached provider credentials without secret values", async () => {
    mockedListProviderAccess.mockResolvedValue({
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

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider_list", { action: "list" });

    expect(mockedListProviderAccess).toHaveBeenCalledWith({});
    expect(result).toMatchObject({
      credential_usage:
        "Provider credential environment values may be openshell:resolve:env:* placeholders. Use the per-provider credential_usage through the sandbox HTTP_PROXY/HTTPS_PROXY so OpenShell can resolve the placeholder at the proxy; do not decode, print, or treat it as a raw token.",
      providers: [
        expect.objectContaining({
          provider_name: "github",
          provider_type: "github",
          status: "attached",
          credential_env: "GITHUB_TOKEN",
          credential_state: "attached_placeholder",
          usable_via_proxy: true,
          raw_secret_available: false,
          credential_available: true,
          credential_usage: expect.objectContaining({
            kind: "bearer_header",
            value: "Bearer $GITHUB_TOKEN",
          }),
          available_tools: ["curl", "git", "node"],
          missing_tools: ["gh"],
        }),
      ],
    });
  });

  it("openshell_provider_access action=check checks an attached provider by name", async () => {
    mockedGetProviderAccess.mockResolvedValue({
      provider_name: "github",
      provider_type: "github",
      status: "attached",
      credential_env: "GITHUB_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider_check", {
      action: "check",
      provider_name: "github",
    });

    expect(mockedGetProviderAccess).toHaveBeenCalledWith("github", {});
    expect(result).toMatchObject({
      provider_name: "github",
      provider_type: "github",
      status: "applied",
      message:
        "Provider credential and provider policy are attached to this sandbox. Follow credential_usage and available_tools; do not request this provider again unless it is detached.",
      credential_env: "GITHUB_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
      credential_usage: expect.objectContaining({
        kind: "bearer_header",
        value: "Bearer $GITHUB_TOKEN",
      }),
      available_tools: ["curl", "git", "node"],
      missing_tools: ["gh"],
    });
  });

  it("openshell_provider_access action=check can poll a provider request by request id", async () => {
    mockedGetAccessRequest.mockResolvedValue({
      request_id: "chunk_provider",
      status: "pending_approval",
      message: "Proposal submitted.",
    });
    mockedWaitAccessRequest.mockResolvedValue({
      request_id: "chunk_provider",
      status: "applied",
      message: "Approved.",
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider_check", {
      action: "check",
      request_id: "chunk_provider",
      wait_timeout_ms: 1000,
    });

    expect(mockedGetAccessRequest).toHaveBeenCalledWith("chunk_provider", {});
    expect(mockedWaitAccessRequest).toHaveBeenCalledWith("chunk_provider", 1000, {});
    expect(result).toEqual({
      request_id: "chunk_provider",
      status: "applied",
      message: "Approved.",
    });
  });

  it("openshell_provider_access reports non-bearer provider credential guidance", async () => {
    mockedGetProviderAccess.mockResolvedValue({
      provider_name: "brave",
      provider_type: "brave",
      status: "attached",
      credential_env: "BRAVE_API_KEY",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider_check", {
      action: "check",
      provider_name: "brave",
    });

    expect(result).toMatchObject({
      provider_name: "brave",
      credential_usage: expect.objectContaining({
        kind: "api_key_header",
        header: "X-Subscription-Token",
        value: "$BRAVE_API_KEY",
      }),
    });
    expect(JSON.stringify(result)).not.toContain("Bearer $BRAVE_API_KEY");
  });

  it("openshell_provider_access uses conservative guidance when auth is provider-specific", async () => {
    mockedGetProviderAccess.mockResolvedValue({
      provider_name: "telegram",
      provider_type: "telegram",
      status: "attached",
      credential_env: "TELEGRAM_BOT_TOKEN",
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    });

    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider_check", {
      action: "check",
      provider_name: "telegram",
    });

    expect(result).toMatchObject({
      provider_name: "telegram",
      credential_usage: expect.objectContaining({
        kind: "provider_url_token",
      }),
    });
    expect(JSON.stringify(result)).not.toContain("Authorization");
    expect(JSON.stringify(result)).not.toContain("Bearer $TELEGRAM_BOT_TOKEN");
  });

  it("openshell_provider_access action=request validates required fields before client calls", async () => {
    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_provider_access");
    const result = await tool.execute("call_provider_invalid", {
      action: "request",
      provider_name: "github",
    });

    expect(result).toEqual({
      status: "failed",
      message: "For action=request, provide required field(s): user_intent, reason.",
    });
    expect(mockedGetProviderAccess).not.toHaveBeenCalled();
    expect(mockedCreateProviderAccessRequest).not.toHaveBeenCalled();
  });

  it("openshell_network_access action=request validates required fields before client calls", async () => {
    const api = createMockApi();
    register(api);
    const tool = getRegisteredTool(api, "openshell_network_access");
    const result = await tool.execute("call_network_invalid", {
      action: "request",
      resource: "github",
    });

    expect(result).toEqual({
      status: "failed",
      message: "For action=request, provide required field(s): user_intent, reason.",
    });
    expect(mockedCreateAccessRequest).not.toHaveBeenCalled();
  });

  it("continues registration when the runtime context hook is unsupported", () => {
    const api = createMockApi();
    vi.mocked(api.on).mockImplementation((hookName: string) => {
      if (hookName === "before_prompt_build") {
        throw new Error("unsupported hook");
      }
    });

    register(api);

    expect(api.logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("Could not register runtime context hook: unsupported hook"),
    );
    expect(api.registerProvider).toHaveBeenCalledWith(expect.objectContaining({ id: "inference" }));
  });

  it("does NOT register CLI commands", () => {
    const api = createMockApi();
    // registerCli should not exist on the API interface after removal
    expect("registerCli" in api).toBe(false);
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

  it("uses probed OpenShell provider and model when onboard config is unavailable", () => {
    mockedExecFileSync.mockReturnValue(
      JSON.stringify({
        provider: "Ollama",
        endpoint: "http://host.docker.internal:11434/v1",
        model: "llama3.2:latest",
      }),
    );

    const api = createMockApi();
    register(api);

    const providerArg = vi.mocked(api.registerProvider).mock.calls[0][0];
    expect(providerArg.models?.chat).toEqual([
      expect.objectContaining({
        id: "inference/llama3.2:latest",
        label: "llama3.2:latest",
      }),
    ]);

    const logLines = vi.mocked(api.logger.info).mock.calls.map(([message]) => message);
    expect(
      logLines.some((line) => line.includes("Endpoint:  http://host.docker.internal:11434/v1")),
    ).toBe(true);
    expect(logLines.some((line) => line.includes("Provider:  Ollama"))).toBe(true);
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
    mockedExecFileSync.mockReturnValue(
      JSON.stringify({
        provider: "NVIDIA",
        endpoint: "https://api.build.nvidia.com/v1",
        model: "nvidia/llama-3.3-nemotron-super-49b-v1.5",
      }),
    );

    const api = createMockApi();
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
    mockedExecFileSync.mockReturnValue(
      JSON.stringify({
        provider: "Ollama",
        model: "llama3.2:latest",
      }),
    );

    const api = createMockApi();
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
        file_path: "/sandbox/.openclaw/memory/project.md",
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
        file_path: "/sandbox/.openclaw/memory/notes.md",
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
        file_path: "/sandbox/.openclaw/agents/config.json",
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
        file_path: "/sandbox/.openclaw/memory/notebook.ipynb",
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
        file_path: "/sandbox/.openclaw/memory/project.md",
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
        file_path: "/sandbox/.openclaw/memory/project.md",
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
    void handler({
      toolName: "write",
      params: {
        file_path: "/sandbox/.openclaw/memory/creds.md",
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
