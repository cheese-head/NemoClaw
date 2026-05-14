// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import path from "node:path";

import { describe, expect, it } from "vitest";

const PLUGIN_PATH = path.join(import.meta.dirname, "..", "agents", "hermes", "plugin", "__init__.py");

function runPython(script: string): string {
  return execFileSync("python3", ["-c", script, PLUGIN_PATH], {
    encoding: "utf-8",
  });
}

describe("Hermes NemoClaw plugin handlers", () => {
  it("accepts Hermes dispatch kwargs for status, info, and reload handlers", () => {
    const output = runPython(`
import importlib.util
import json
import pathlib
import sys
import types

plugin_path = pathlib.Path(sys.argv[1])
yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *_args, **_kwargs: {}
sys.modules.setdefault("yaml", yaml_stub)
spec = importlib.util.spec_from_file_location("hermes_plugin", plugin_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

module._get_sandbox_info = lambda: {
    "agent": "hermes",
    "model": "nemotron",
    "provider": "nvidia",
    "base_url": "http://localhost:8642/v1",
    "gateway": "running",
    "port": 8642,
}
module._reload_skills = lambda: {
    "alpha": {"description": "First skill"},
    "beta": {"description": "Second skill"},
}

result = {
    "status": module._handle_status({}, None, task_id="t-123", session_id="s-456"),
    "info": json.loads(module._handle_info({}, None, task_id="t-123", user_task="inspect")),
    "reload": module._handle_reload_skills({}, None, task_id="t-123", session_id="s-456"),
}
print(json.dumps(result))
`);

    const result = JSON.parse(output) as {
      status: string;
      info: Record<string, unknown>;
      reload: string;
    };

    expect(result.status).toContain("NemoClaw Sandbox Status (Hermes)");
    expect(result.status).toContain("Gateway:  running");
    expect(result.info).toMatchObject({
      agent: "hermes",
      model: "nemotron",
      provider: "nvidia",
      gateway: "running",
      port: 8642,
    });
    expect(result.reload).toContain("Skill reload complete. 2 skill(s) discovered:");
    expect(result.reload).toContain("alpha: First skill");
    expect(result.reload).toContain("beta: Second skill");
  });

  it("registers Hermes resource-access tools and maps policy.local status", () => {
    const output = runPython(`
import importlib.util
import json
import pathlib
import sys
import types

plugin_path = pathlib.Path(sys.argv[1])
yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *_args, **_kwargs: {}
sys.modules.setdefault("yaml", yaml_stub)
spec = importlib.util.spec_from_file_location("hermes_plugin", plugin_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Ctx:
    def __init__(self):
        self.tools = {}
    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs
    def register_hook(self, *_args, **_kwargs):
        pass
    def inject_message(self, *_args, **_kwargs):
        pass

calls = []
def fake_policy(method, path, payload=None, timeout=310):
    calls.append({"method": method, "path": path, "payload": payload})
    if method == "POST":
        return {"accepted_chunk_ids": ["chunk-123"]}
    return {"chunk_id": "chunk-123", "status": "approved", "policy_reloaded": True}

module._policy_local_json = fake_policy
module._read_provider_profiles = lambda: [{
    "id": "github",
    "description": "OpenShell GitHub profile",
    "endpoints": [{"host": "api.github.com", "port": 443, "protocol": "rest", "enforcement": "enforce"}],
    "binaries": ["/usr/bin/git"],
}]
module._provider_preset_cache = {"loaded_at": 0, "presets": None}

ctx = Ctx()
module.register(ctx)
request = json.loads(ctx.tools["openshell_network_access"]["handler"]({
    "action": "request",
    "user_intent": "inspect a repo",
    "resource": "github.com",
    "access": "read",
    "reason": "need repository metadata",
    "wait_timeout_ms": 0,
}))
check = json.loads(ctx.tools["openshell_network_access"]["handler"]({
    "action": "check",
    "request_id": "chunk-123",
    "wait_timeout_ms": 1000,
}))
presets = json.loads(ctx.tools["openshell_network_access"]["handler"]({
    "action": "list_presets",
}))
invalid = json.loads(ctx.tools["openshell_network_access"]["handler"]({
    "action": "request",
    "resource": "github",
}))
print(json.dumps({
    "tool_names": sorted(ctx.tools.keys()),
    "request": request,
    "check": check,
    "presets": presets,
    "invalid": invalid,
    "calls": calls,
}))
`);

    const result = JSON.parse(output) as {
      tool_names: string[];
      request: Record<string, unknown>;
      check: Record<string, unknown>;
      presets: { presets: Array<Record<string, unknown>> };
      invalid: Record<string, unknown>;
      calls: Array<{ method: string; path: string; payload?: Record<string, unknown> }>;
    };

    expect(result.tool_names).toEqual(
      expect.arrayContaining([
        "openshell_network_access",
      ]),
    );
    expect(result.request).toMatchObject({
      request_id: "chunk-123",
      status: "pending_approval",
    });
    expect(result.check).toMatchObject({
      request_id: "chunk-123",
      status: "applied",
    });
    expect(result.presets.presets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "github", provider_profile: "github" }),
      ]),
    );
    expect(result.invalid).toEqual({
      status: "failed",
      message: "For action=request, provide required field(s): user_intent, reason.",
    });
    expect(result.calls[0]).toMatchObject({ method: "POST", path: "/v1/proposals" });
    expect(result.calls[0].payload?.operations).toHaveLength(1);
    expect(result.calls[1]).toMatchObject({
      method: "GET",
      path: "/v1/proposals/chunk-123/wait?timeout=1",
    });
  });
});
