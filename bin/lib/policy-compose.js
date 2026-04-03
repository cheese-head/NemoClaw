// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// policy-compose.js — Static policy composition engine for NemoClaw.
//
// Replaces LLM-based policy generation with deterministic preset composition:
//
//   1. Load a preset YAML file from the presets library for each selected tool.
//   2. Filter endpoints and rules by the user's chosen access level (read / write).
//   3. Merge all per-tool network_policies sections into a single output document.
//   4. Serialize back to YAML with the standard NemoClaw header.
//
// No inference endpoint required. No network calls. Fully offline.
//
// Coverage gaps
// -------------
// Tools that do not yet have a preset file will be listed in the returned
// `missing` array. The caller should warn the user and skip those tools.
// Add a new <toolId>.yaml in nemoclaw-blueprint/policies/presets/ to fill a gap.

"use strict";

const fs   = require("fs");
const path = require("path");
const yaml = require("yaml");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PRESETS_DIR = path.resolve(__dirname, "../../nemoclaw-blueprint/policies/presets");

/** HTTP methods that constitute "write" access. */
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * NemoClaw-only annotation fields that are meaningful to this tooling but are
 * not valid OpenShell policy fields.  At serialisation time these are converted
 * to inline YAML comments so the information is preserved in the file without
 * causing OpenShell to reject the policy.
 *
 * Add new annotation field names here as the schema evolves.
 */
const ANNOTATION_FIELDS = [
  "exfil_risk",
];

// ---------------------------------------------------------------------------
// Preset loading
// ---------------------------------------------------------------------------

/**
 * Load and parse a preset YAML file for the given tool ID.
 * Returns the parsed object, or null if no preset file exists.
 *
 * @param {string} toolId  e.g. "slack", "jira"
 * @param {string} [dir]   override the default presets directory (for testing)
 * @returns {object|null}
 */
function loadPreset(toolId, dir = PRESETS_DIR) {
  const file = path.join(dir, `${toolId}.yaml`);
  if (!fs.existsSync(file)) return null;
  try {
    const raw = fs.readFileSync(file, "utf-8");
    return yaml.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse preset ${toolId}.yaml: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Rule-level filtering
// ---------------------------------------------------------------------------

/**
 * Return true if an allow-rule's method is a write method.
 * @param {{ allow: { method: string } }} rule
 */
function isWriteRule(rule) {
  return WRITE_METHODS.has((rule.allow?.method || "").toUpperCase());
}

/**
 * Filter an endpoint's rules by access level.
 *   access "read"  → keep only GET rules
 *   access "write" → keep all rules
 *
 * @param {object[]} rules
 * @param {"read"|"write"} access
 * @returns {object[]}
 */
function filterByAccess(rules, access) {
  if (!rules) return [];
  if (access === "read") return rules.filter(r => !isWriteRule(r));
  return rules; // write: keep all
}

// ---------------------------------------------------------------------------
// Endpoint-level filtering
// ---------------------------------------------------------------------------

/**
 * Filter the endpoint list for a single policy block.
 *
 * - Tunnel endpoints (`access: full`) are stripped for read access, kept for write.
 * - REST endpoints have their rules filtered by access level.
 * - Endpoints that end up with zero rules are dropped.
 *
 * @param {object[]} endpoints
 * @param {"read"|"write"} access
 * @returns {object[]}
 */
function filterEndpoints(endpoints, access) {
  if (!endpoints) return [];

  const result = [];

  for (const ep of endpoints) {
    // Tunnel endpoint (WebSocket CONNECT, etc.)
    if (ep.access === "full") {
      if (access === "read") continue; // strip tunnels for read-only
      result.push(ep);
      continue;
    }

    // REST endpoint
    const filtered = filterByAccess(ep.rules, access);
    if (filtered.length === 0) continue;

    result.push({ ...ep, rules: filtered });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/**
 * Compose a merged network_policies object from a list of tool selections.
 *
 * @param {Array<{ tool: object, level: "read"|"write" }>} toolSelections
 * @param {string} [presetsDir]  override for testing
 * @returns {{ policies: object, missing: string[], warnings: string[] }}
 *   policies — merged network_policies ready to embed in the output YAML
 *   missing  — tool IDs for which no preset file was found
 *   warnings — human-readable risk warnings generated during composition
 */
function composePresets(toolSelections, presetsDir = PRESETS_DIR) {
  const policies  = {};
  const missing   = [];
  const warnings  = [];

  // Deduplicate by tool.id, keeping the highest access level ("write" > "read").
  const levelRank = { read: 0, write: 1 };
  const deduped = Object.values(
    toolSelections.reduce((acc, sel) => {
      const existing = acc[sel.tool.id];
      if (!existing || (levelRank[sel.level] ?? 0) > (levelRank[existing.level] ?? 0)) {
        acc[sel.tool.id] = sel;
      }
      return acc;
    }, {}),
  );

  const multi = deduped.length > 1;

  for (const { tool, level } of deduped) {
    const preset = loadPreset(tool.id, presetsDir);
    if (!preset) {
      missing.push(tool.id);
      continue;
    }

    const networkPolicies = preset.network_policies || {};

    for (const [blockName, block] of Object.entries(networkPolicies)) {
      const filtered = filterEndpoints(block.endpoints, level);
      if (filtered.length === 0) {
        warnings.push(`${tool.id}: all endpoints removed after access filter — skipped`);
        continue;
      }

      // When multiple tools are merged, prefix the block name with the tool ID
      // to avoid collisions (e.g. both jira and confluence use "atlassian").
      const key = multi ? `${tool.id}-${blockName}` : blockName;

      policies[key] = {
        name: key,
        endpoints: filtered,
        ...(block.binaries ? { binaries: block.binaries } : {}),
      };
    }
  }

  return { policies, missing, warnings };
}

// ---------------------------------------------------------------------------
// YAML serialization
// ---------------------------------------------------------------------------

/**
 * Build the final preset YAML string from composed policies.
 *
 * @param {string}  presetName   slug used as the file name and preset.name
 * @param {object}  policies     merged network_policies object
 * @param {{ readOnly: string[], readWrite: string[] }} fsAccess  extra FS paths
 * @returns {string}
 */
function buildPresetYaml(presetName, policies, fsAccess) {
  const acc = fsAccess || {};

  // Re-stamp enforcement + tls on each REST endpoint (clone to avoid mutating input).
  for (const block of Object.values(policies)) {
    block.endpoints = (block.endpoints || []).map((ep) => {
      if (ep.access === "full") return ep; // tunnel — leave alone
      return { ...ep, enforcement: "enforce", tls: ep.tls ?? "terminate" };
    });
  }

  const doc = {
    preset: { name: presetName },

    filesystem_policy: {
      include_workdir: true,
      read_only:  ["/usr", "/lib", "/etc", "/app",    ...(acc.readOnly  || [])],
      read_write: ["/sandbox", "/tmp", "/dev/null",   ...(acc.readWrite || [])],
    },

    landlock: { compatibility: "best_effort" },

    process: {
      run_as_user:  "sandbox",
      run_as_group: "sandbox",
    },

    network_policies: policies,
  };

  const header = [
    "# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.",
    "# SPDX-License-Identifier: Apache-2.0",
    "#",
    `# Generated by nemoclaw policy-wizard (static) on ${new Date().toISOString()}`,
    "#",
    "# WHAT REMAINS BLOCKED (OpenShell allowlist — unlisted = denied):",
    "#   All hosts not listed in this policy",
    "#   All RFC1918 / loopback / link-local / CGNAT addresses",
    "#   All binaries not explicitly listed in 'binaries:'",
    "",
  ].join("\n");

  const raw = yaml.stringify(doc, { indent: 2, lineWidth: 0 });
  // Convert all NemoClaw annotation fields to inline YAML comments so they
  // survive in the generated file but are invisible to OpenShell's parser.
  const annotationRe = new RegExp(
    `^(\\s+)(${ANNOTATION_FIELDS.join("|")}): (.*)$`,
    "gm",
  );
  const annotated = raw.replace(annotationRe, "$1# $2: $3");
  return header + annotated;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  loadPreset,
  filterByAccess,
  filterEndpoints,
  composePresets,
  buildPresetYaml,
  PRESETS_DIR,
};
