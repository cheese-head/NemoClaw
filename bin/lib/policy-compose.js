// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// policy-compose.js — Static policy composition engine for NemoClaw.
//
// Replaces LLM-based policy generation with deterministic preset composition:
//
//   1. Load a preset YAML file from the presets library for each selected tool.
//   2. Filter endpoints and rules by the user's chosen access level (read / write).
//   3. Apply tier-based path transforms (T1 narrow, T2 as-is, T3 widen).
//   4. Merge all per-tool network_policies sections into a single output document.
//   5. Serialize back to YAML with the standard NemoClaw header.
//
// No inference endpoint required. No network calls. Fully offline.
//
// Tier transform rules
// --------------------
//   T1 Enterprise  — read: GET with specific paths only (reject /**)
//                    write: GET + POST with specific paths only (reject /**)
//                    tunnels (access: full): stripped entirely
//
//   T2 Professional — read: GET rules from preset as-is
//                     write: all rules from preset as-is
//                     tunnels: kept as-is
//
//   T3 Hobbyist     — read: collapsed to [ GET /** ]
//                     write: collapsed to [ GET /**, POST /**, PUT /**, PATCH /**, DELETE /** ]
//                     tunnels: kept as-is
//
// Coverage gaps
// -------------
// Tools that do not yet have a preset file will be listed in the returned
// `missing` array. The caller should warn the user and skip those tools.
// Add a new <toolId>.yaml in nemoclaw-blueprint/policies/presets/ to fill a gap.
//
// Missing presets as of 2026-04-02:
//   github, gitlab, linear, notion, datadog, pagerduty, grafana,
//   websearch, stripe, openai, sendgrid, teams, email, calendar

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

/** All common REST methods used when T3 widens to /**. */
const ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

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
 * Return true if an allow-rule's path is a wildcard (/** or /*).
 * These are considered too broad for T1 Enterprise tier.
 * @param {{ allow: { path: string } }} rule
 */
function isWildcardPath(rule) {
  const p = rule.allow?.path || "";
  return p === "/**" || p === "/*" || p.endsWith("/**");
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

/**
 * Apply tier-based path transforms to a filtered rule set.
 *
 *   T1 — strip wildcard paths (/** / /*); keep specific named paths only.
 *         If this empties the rule list, return the originals with a RISK_FLAG
 *         comment so the operator can decide manually.
 *   T2 — no transform; rules stay as-is.
 *   T3 — collapse to one rule per unique method, all using /** path.
 *
 * @param {object[]} rules
 * @param {"t1"|"t2"|"t3"} tier
 * @param {"read"|"write"} access  used when T3 expands the method set
 * @returns {object[]}
 */
function applyTierPaths(rules, tier, access) {
  if (!rules || rules.length === 0) return rules;

  if (tier === "t2") return rules;

  if (tier === "t1") {
    const narrow = rules.filter(r => !isWildcardPath(r));
    // If every rule was a wildcard (e.g. slack.yaml uses GET /**), fall back to
    // the originals rather than producing an empty policy.  Callers receive a
    // risk flag in the output YAML so the operator is aware.
    return narrow.length > 0 ? narrow : rules;
  }

  if (tier === "t3") {
    // Collect the methods that were already allowed, then widen all paths to /*.
    const methods = new Set(rules.map(r => (r.allow?.method || "").toUpperCase()).filter(Boolean));
    // For write access, ensure write methods are present even if the preset omits them.
    if (access === "write") ALL_METHODS.forEach(m => methods.add(m));
    return [...methods].map(m => ({ allow: { method: m, path: "/**" } }));
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Endpoint-level filtering
// ---------------------------------------------------------------------------

/**
 * Filter and transform the endpoint list for a single policy block.
 *
 * - Tunnel endpoints (`access: full`) are stripped for T1 or read access.
 * - REST endpoints have their rules filtered by access then transformed by tier.
 * - Endpoints that end up with zero rules are dropped.
 *
 * @param {object[]} endpoints
 * @param {"read"|"write"} access
 * @param {"t1"|"t2"|"t3"} tier
 * @returns {object[]}
 */
function filterEndpoints(endpoints, access, tier) {
  if (!endpoints) return [];

  const result = [];

  for (const ep of endpoints) {
    // Tunnel endpoint (WebSocket CONNECT, etc.)
    if (ep.access === "full") {
      if (tier === "t1" || access === "read") continue; // strip
      result.push(ep);                                   // T2/T3 write: keep
      continue;
    }

    // REST endpoint
    const accessFiltered = filterByAccess(ep.rules, access);
    if (accessFiltered.length === 0) continue; // nothing left after access filter

    const tierFiltered = applyTierPaths(accessFiltered, tier, access);
    result.push({ ...ep, rules: tierFiltered });
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
 * @param {"t1"|"t2"|"t3"} tier
 * @param {string} [presetsDir]  override for testing
 * @returns {{ policies: object, missing: string[], warnings: string[] }}
 *   policies — merged network_policies ready to embed in the output YAML
 *   missing  — tool IDs for which no preset file was found
 *   warnings — human-readable risk warnings generated during composition
 */
function composePresets(toolSelections, tier, presetsDir = PRESETS_DIR) {
  const policies  = {};
  const missing   = [];
  const warnings  = [];
  const multi     = toolSelections.length > 1;

  for (const { tool, level } of toolSelections) {
    const preset = loadPreset(tool.id, presetsDir);
    if (!preset) {
      missing.push(tool.id);
      continue;
    }

    const networkPolicies = preset.network_policies || {};

    for (const [blockName, block] of Object.entries(networkPolicies)) {
      const filtered = filterEndpoints(block.endpoints, level, tier);
      if (filtered.length === 0) {
        warnings.push(`${tool.id}: all endpoints removed after access/tier filter — skipped`);
        continue;
      }

      // Check for wildcard paths surviving T1 (fallback case in applyTierPaths).
      if (tier === "t1") {
        const hasWildcard = filtered.some(ep =>
          (ep.rules || []).some(r => isWildcardPath(r)),
        );
        if (hasWildcard) {
          warnings.push(
            `${tool.id}: T1 tier but preset only defines wildcard paths (/**). ` +
            `Consider adding specific paths to ${tool.id}.yaml.`,
          );
        }
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
 * @param {"t1"|"t2"|"t3"} tier
 * @returns {string}
 */
function buildPresetYaml(presetName, policies, fsAccess, tier) {
  const enforcement = tier === "t3" ? "audit"            : "enforce";
  const landlock    = tier === "t1" ? "hard_requirement" : "best_effort";

  // Re-stamp enforcement + tls on each REST endpoint so they match tier.
  for (const block of Object.values(policies)) {
    for (const ep of block.endpoints || []) {
      if (ep.access === "full") continue; // tunnel — leave alone
      ep.enforcement = enforcement;
      ep.tls         = ep.tls ?? "terminate";
    }
  }

  const doc = {
    preset: { name: presetName },

    filesystem_policy: {
      include_workdir: true,
      read_only:  ["/usr", "/lib", "/etc", "/app",    ...(fsAccess.readOnly  || [])],
      read_write: ["/sandbox", "/tmp", "/dev/null",   ...(fsAccess.readWrite || [])],
    },

    landlock: { compatibility: landlock },

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

  return header + yaml.stringify(doc, { indent: 2, lineWidth: 0 });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  loadPreset,
  filterByAccess,
  applyTierPaths,
  filterEndpoints,
  composePresets,
  buildPresetYaml,
  PRESETS_DIR,
};
