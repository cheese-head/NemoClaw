# Policy Presets and Tiers

This directory contains the network policy presets used during NemoClaw onboarding. Presets are organized into three security tiers, each in its own subdirectory.

## Directory layout

```
presets/
├── README.md          ← this file
├── *.yaml             ← legacy flat presets (backward-compatible, not tier-aware)
├── t1/                ← Enterprise: read-only, minimal external access
├── t2/                ← Professional: bounded read + write to approved tools
└── t3/                ← Hobbyist: broad access, maximum capability
```

Each tier directory contains one YAML file per preset. Every tier contains the same set of presets — the difference is the HTTP methods and access level permitted within each one.

---

## Access model by tier

| Tier | HTTP methods | WebSocket | Intended for |
|------|-------------|-----------|--------------|
| **T1 Enterprise** | GET only | No | Regulated environments, compliance-focused operators |
| **T2 Professional** | GET + POST | Messaging services only | Internal teams, day-to-day agent workflows |
| **T3 Hobbyist** | Full (`access: full`) | Yes | Solo developers, home lab, open-source contributors |

---

## How to add a new preset

A preset is a YAML file that defines one or more `network_policies` entries to merge into the sandbox policy. You must add a version of the preset in **all three tier directories**.

### 1. Create the preset files

Create `t1/<name>.yaml`, `t2/<name>.yaml`, and `t3/<name>.yaml`. Each file must include:

- A `preset:` header with `name` and `description`
- A `network_policies:` block with at least one named entry

**T1 template** (read-only — GET only, no WebSocket):

```yaml
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

preset:
  name: myservice
  description: "MyService read-only access"

network_policies:
  myservice:
    name: myservice
    endpoints:
      - host: api.myservice.com
        port: 443
        protocol: rest
        enforcement: enforce
        tls: terminate
        rules:
          - allow: { method: GET, path: "/**" }
    binaries:
      - { path: /usr/local/bin/node }
```

**T2 template** (bounded read + write — GET + POST, WebSocket where needed):

```yaml
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

preset:
  name: myservice
  description: "MyService read and write access (no delete)"

network_policies:
  myservice:
    name: myservice
    endpoints:
      - host: api.myservice.com
        port: 443
        protocol: rest
        enforcement: enforce
        tls: terminate
        rules:
          - allow: { method: GET, path: "/**" }
          - allow: { method: POST, path: "/**" }
    binaries:
      - { path: /usr/local/bin/node }
```

**T3 template** (full access — `access: full`, no method filtering):

```yaml
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

preset:
  name: myservice
  description: "MyService full access (read, write, delete)"

network_policies:
  myservice:
    name: myservice
    endpoints:
      - host: api.myservice.com
        port: 443
        access: full
    binaries:
      - { path: /usr/local/bin/node }
```

### 2. Rules for YAML fields

| Field | Notes |
|-------|-------|
| `preset.name` | Must match the filename without `.yaml`. Used as the preset identifier in the CLI. |
| `network_policies.<key>` | Top-level key under `network_policies`. Must be unique within a policy. Use the service name (e.g. `myservice`). |
| `network_policies.<key>.name` | Must match the top-level key. |
| `endpoints[].host` | Supports `*` wildcards (e.g. `*.atlassian.net`). |
| `endpoints[].port` | Typically `443`. |
| `endpoints[].access` | Use `full` to bypass all HTTP filtering (required for WebSocket/CONNECT tunnels). |
| `endpoints[].protocol` | Use `rest` when you want to enforce method/path rules. |
| `endpoints[].enforcement` | Set to `enforce` when rules are active. |
| `endpoints[].tls` | Set to `terminate` so the proxy can inspect the request. |
| `endpoints[].rules` | List of `allow` entries. Only used with `protocol: rest`. |
| `binaries` | List of executable paths allowed to use this network policy. Supports `*` glob. |

### 3. WebSocket endpoints

WebSocket (and any long-lived CONNECT tunnel) must use `access: full` — you cannot filter WebSocket traffic with `protocol: rest` rules. Add a comment explaining why, following the pattern in `slack.yaml` and `discord.yaml`.

In T1, omit WebSocket endpoints entirely (read-only means no persistent outbound connections).
In T2 and T3, include them where the service requires real-time communication.

### 4. Verify

After adding the files, confirm the preset appears in the CLI:

```bash
# List available presets for a tier
node -e "const p = require('./bin/lib/policies'); console.log(p.listTierPresets('t1').map(x => x.name))"
node -e "const p = require('./bin/lib/policies'); console.log(p.listTierPresets('t2').map(x => x.name))"
node -e "const p = require('./bin/lib/policies'); console.log(p.listTierPresets('t3').map(x => x.name))"
```

The preset is auto-discovered — no registration step is needed.

---

## How to add a new tier

Tiers are defined in `bin/lib/policies.js` in the `TIERS` constant and in the onboarding wizard in `bin/lib/onboard.js`.

### 1. Create the preset directory

```bash
mkdir nemoclaw-blueprint/policies/presets/t4
```

Populate it with YAML files for each preset following the templates above.

### 2. Register the tier in `policies.js`

Open `bin/lib/policies.js` and add an entry to the `TIERS` object:

```js
const TIERS = {
  // ... existing tiers ...
  t4: {
    name: "t4",
    label: "YourLabel",
    description: "One-line description shown in the onboarding prompt",
    personas: "Typical users for this tier",
    dir: path.join(PRESETS_DIR, "t4"),
  },
};
```

The `dir` field must point to the directory you created in step 1.

### 3. Update the tier selector in `onboard.js`

Open `bin/lib/onboard.js` and update two places:

**`VALID_TIERS` constant** — add the new tier name:

```js
const VALID_TIERS = ["t1", "t2", "t3", "t4"];
```

**`buildTierSuggestions`** — add a branch that returns the default presets to suggest for this tier:

```js
function buildTierSuggestions(tier) {
  // ...
  } else if (tier === "t4") {
    suggestions.push("pypi", "npm");
    // add auto-detected suggestions here if needed
  }
  // ...
}
```

**`selectPolicyTier`** — update the `tierMap` to accept numeric input for the new tier:

```js
const tierMap = {
  "1": "t1", "t1": "t1",
  "2": "t2", "t2": "t2",
  "3": "t3", "t3": "t3",
  "4": "t4", "t4": "t4",   // ← add this
};
```

The interactive prompt and `NEMOCLAW_POLICY_TIER` env var support are updated automatically because they read from `policies.TIERS`.

### 4. Update the non-interactive default (optional)

If the new tier should be the default in non-interactive mode, change the fallback in `selectPolicyTier`:

```js
const tier = (process.env.NEMOCLAW_POLICY_TIER || "t4").trim().toLowerCase();
```

---

## Preset naming rules

- Filename and `preset.name` must match exactly (e.g. `slack.yaml` → `name: slack`).
- Use lowercase letters and hyphens only (`my-service`, not `MyService`).
- The `network_policies` key must be unique across the merged policy — if two presets use the same key, the second one applied will overwrite the first. Use a service-specific name (e.g. `atlassian`, not `api`).
