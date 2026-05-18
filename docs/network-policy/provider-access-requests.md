---
title:
  page: "Provider and Network Access Requests"
  nav: "Provider Access Requests"
description:
  main: "How NemoClaw agents request provider-backed credentials and network-only access through OpenShell policy proposals."
  agent: "Explains the provider-first access workflow, including openshell_provider_access, openshell_network_access, operator approval, credential placeholders, and when to use provider access instead of network-only policy."
keywords: ["nemoclaw provider access", "openshell provider access", "openshell_network_access", "openshell_provider_access", "provider credential placeholder"]
tags: ["openclaw", "openshell", "network_policy", "provider_access", "security", "nemoclaw"]
content:
  type: how_to
  difficulty: intermediate
  audience: ["developer", "engineer", "security_engineer"]
status: published
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Provider and Network Access Requests

NemoClaw agents can ask OpenShell for additional access while they are running in
a sandbox. The sandbox can submit a request, but it cannot approve its own
request. OpenShell records the proposal, waits for operator approval, and only
then attaches provider credentials or updates network policy.

Use provider access when the task needs an account, token, OAuth identity, API
key, write permission, or service-specific CLI. Use network-only access when the
task only needs unauthenticated reachability.

## Access Types

| Type | Tool | What approval grants |
| ---- | ---- | -------------------- |
| Provider access | `openshell_provider_access` | A host-managed provider attachment, provider policy, and credential placeholders when the provider has credentials. |
| Network-only access | `openshell_network_access` | Network reachability for an approved preset. It does not attach credentials or account identity. |

## Provider Access Flow

1. The agent lists already attached providers:

   ```json
   {"action": "list"}
   ```

2. If the needed provider is missing, the agent requests it:

   ```json
   {
     "action": "request",
     "provider_name": "github",
     "provider_type": "github",
     "user_intent": "Review pull requests for the current task",
     "reason": "Use the host-managed GitHub provider without exposing a raw token",
     "wait_timeout_ms": 0
   }
   ```

3. OpenShell sends the provider proposal to the operator.

4. After approval, OpenShell attaches the provider to the sandbox. The provider
   can supply policy, credentials, and configuration.

5. The agent checks whether the provider is attached:

   ```json
   {
     "action": "check",
     "provider_name": "github"
   }
   ```

Provider requests return `pending_approval` while they wait. An approved provider
request is reported as `applied` when OpenShell has attached the provider.

## Network-Only Access Flow

1. The agent lists requestable network presets:

   ```json
   {"action": "list_presets"}
   ```

2. The agent requests a preset:

   ```json
   {
     "action": "request",
     "resource": "github",
     "access": "read",
     "duration": "session",
     "user_intent": "Fetch public repository metadata",
     "reason": "No account credential is needed",
     "wait_timeout_ms": 0
   }
   ```

3. OpenShell sends the network proposal to the operator.

4. After approval, OpenShell merges and reloads the sandbox policy.

5. The agent checks the request status:

   ```json
   {
     "action": "check",
     "request_id": "<request_id>",
     "wait_timeout_ms": 1000
   }
   ```

Network-only requests are reported as `applied` only after OpenShell confirms the
policy reload.

## Credential Placeholders

Provider credentials can appear in the sandbox as placeholders:

```text
GITHUB_TOKEN=openshell:resolve:env:...
```

These placeholders are not raw secrets. The sandbox should not print, decode, or
persist them. For direct API calls, the agent should follow the
`credential_usage` returned by `openshell_provider_access` and route requests
through `HTTP_PROXY` or `HTTPS_PROXY` so OpenShell can resolve placeholders at
egress.

Different providers use different authentication formats. Some use bearer
headers, some use service-specific headers, and some require provider-specific
URL or SDK behavior. Do not assume every provider uses
`Authorization: Bearer`.

## Operator Boundary

The agent can:

- Discover attached providers.
- Submit provider or network proposals.
- Check proposal status.
- Use approved access through the sandbox proxy.

The agent cannot:

- Approve its own proposal.
- Read raw host-managed provider secrets.
- Bypass OpenShell policy with an installed CLI.
- Use a provider endpoint before the provider or network policy is approved.

## Related Pages

- [Approve or Deny Network Requests](approve-network-requests.md) explains the operator approval workflow for access proposals.
- [Customize the Network Policy](customize-network-policy.md) explains persistent policy edits and presets.
- [NemoClaw Provider and Resource Access Flow](../reference/nemoclaw-openshell-integration.md) provides the architecture reference for this feature.
