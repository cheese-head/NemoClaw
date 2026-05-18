#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import register from "/sandbox/nemoclaw/dist/index.js";

const tools = new Map();
const api = {
  id: "nemoclaw",
  name: "NemoClaw",
  version: "0.1.0",
  config: {},
  pluginConfig: {},
  logger: {
    info() {},
    warn(message) {
      console.error(`[warn] ${message}`);
    },
    error(message) {
      console.error(`[error] ${message}`);
    },
    debug() {},
  },
  registerCommand() {},
  registerProvider() {},
  registerService() {},
  registerTool(tool) {
    tools.set(tool.name, tool);
  },
  resolvePath(input) {
    return input;
  },
  on() {},
};

function usage() {
  console.error("usage: nemoclaw-policy-local-runner.mjs list|request|check <request_id>");
  process.exit(2);
}

register(api);

const [command, requestId] = process.argv.slice(2);
if (!command) usage();

function tool(name) {
  const entry = tools.get(name);
  if (!entry) throw new Error(`tool not registered: ${name}`);
  return entry;
}

let result;
if (command === "list") {
  result = await tool("openshell_network_access").execute("call_list", {
    action: "list_presets",
  });
} else if (command === "request") {
  result = await tool("openshell_network_access").execute("call_request", {
    action: "request",
    user_intent: "Verify NemoClaw plugin access request integration",
    resource: "github",
    access: "read",
    duration: "session",
    reason: "The live e2e needs a deterministic provider-backed proposal.",
    wait_timeout_ms: 0,
  });
} else if (command === "check") {
  if (!requestId) usage();
  result = await tool("openshell_network_access").execute("call_check", {
    action: "check",
    request_id: requestId,
    wait_timeout_ms: 30_000,
  });
} else {
  usage();
}

console.log(JSON.stringify(result));
