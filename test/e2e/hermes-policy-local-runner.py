#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import json
import pathlib
import sys
import types


plugin_path = pathlib.Path("/sandbox/hermes-plugin/__init__.py")
yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *_args, **_kwargs: {}
sys.modules.setdefault("yaml", yaml_stub)
spec = importlib.util.spec_from_file_location("nemoclaw_hermes_plugin", plugin_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Context:
    def __init__(self):
        self.tools = {}

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs

    def register_hook(self, *_args, **_kwargs):
        pass

    def inject_message(self, *_args, **_kwargs):
        pass


ctx = Context()
module.register(ctx)


def call_tool(name, payload):
    if name not in ctx.tools:
        raise RuntimeError(f"tool not registered: {name}")
    result = ctx.tools[name]["handler"](payload)
    if isinstance(result, str):
        return json.loads(result)
    return result


command = sys.argv[1] if len(sys.argv) > 1 else ""
if command == "list":
    result = call_tool("openshell_network_access", {"action": "list_presets"})
elif command == "request":
    result = call_tool(
        "openshell_network_access",
        {
            "action": "request",
            "user_intent": "Verify Hermes NemoClaw access request integration",
            "resource": "github",
            "access": "read",
            "duration": "session",
            "reason": "The live e2e needs a deterministic provider-backed proposal.",
            "wait_timeout_ms": 0,
        },
    )
elif command == "check" and len(sys.argv) == 3:
    result = call_tool(
        "openshell_network_access",
        {
            "action": "check",
            "request_id": sys.argv[2],
            "wait_timeout_ms": 30000,
        },
    )
else:
    print("usage: hermes-policy-local-runner.py list|request|check <request_id>", file=sys.stderr)
    sys.exit(2)

print(json.dumps(result, separators=(",", ":")))
