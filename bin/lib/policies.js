// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Policy preset management — list, load, merge, and apply presets.

const fs = require("fs");
const path = require("path");
const os = require("os");
const YAML = require("yaml");
const { ROOT, run, runCapture, shellQuote } = require("./runner");
const registry = require("./registry");

const PRESETS_DIR = path.join(ROOT, "nemoclaw-blueprint", "policies", "presets");
function getOpenshellCommand() {
  const binary = process.env.NEMOCLAW_OPENSHELL_BIN;
  if (!binary) return "openshell";
  return shellQuote(binary);
}

function listPresets() {
  if (!fs.existsSync(PRESETS_DIR)) return [];
  return fs
    .readdirSync(PRESETS_DIR)
    .filter((f) => f.endsWith(".yaml"))
    .map((f) => {
      const content = fs.readFileSync(path.join(PRESETS_DIR, f), "utf-8");
      const nameMatch = content.match(/^\s*name:\s*(.+)$/m);
      const descMatch = content.match(/^\s*description:\s*"?([^"]*)"?$/m);
      return {
        file: f,
        name: nameMatch ? nameMatch[1].trim() : f.replace(".yaml", ""),
        description: descMatch ? descMatch[1].trim() : "",
      };
    });
}

function loadPreset(name) {
  const file = path.resolve(PRESETS_DIR, `${name}.yaml`);
  if (!file.startsWith(PRESETS_DIR + path.sep) && file !== PRESETS_DIR) {
    console.error(`  Invalid preset name: ${name}`);
    return null;
  }
  if (fs.existsSync(file)) {
    return fs.readFileSync(file, "utf-8");
  }
  // Filename doesn't match — scan all presets for a matching name: field.
  if (fs.existsSync(PRESETS_DIR)) {
    for (const f of fs.readdirSync(PRESETS_DIR).filter((x) => x.endsWith(".yaml"))) {
      const content = fs.readFileSync(path.join(PRESETS_DIR, f), "utf-8");
      const m = content.match(/^\s*name:\s*(.+)$/m);
      if (m && m[1].trim() === name) return content;
    }
  }
  console.error(`  Preset not found: ${name}`);
  return null;
}

function getPresetEndpoints(content) {
  const hosts = [];
  const regex = /host:\s*([^\s,}]+)/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    hosts.push(match[1]);
  }
  return hosts;
}

/**
 * Extract just the network_policies entries (indented content under
 * the `network_policies:` key) from a preset file, stripping the
 * `preset:` metadata header.
 */
function extractPresetEntries(presetContent) {
  if (!presetContent) return null;
  const npMatch = presetContent.match(/^network_policies:\n([\s\S]*)$/m);
  if (!npMatch) return null;
  return npMatch[1].trimEnd();
}

/**
 * Parse the output of `openshell policy get --full` which has a metadata
 * header (Version, Hash, etc.) followed by `---` and then the actual YAML.
 */
function parseCurrentPolicy(raw) {
  if (!raw) return "";
  const sep = raw.indexOf("---");
  const candidate = (sep === -1 ? raw : raw.slice(sep + 3)).trim();
  if (!candidate) return "";
  if (/^(error|failed|invalid|warning|status)\b/i.test(candidate)) {
    return "";
  }
  if (!/^[a-z_][a-z0-9_]*\s*:/m.test(candidate)) {
    return "";
  }
  try {
    const parsed = YAML.parse(candidate);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return "";
    }
  } catch {
    return "";
  }
  return candidate;
}

/**
 * Build the openshell policy set command with properly quoted arguments.
 */
function buildPolicySetCommand(policyFile, sandboxName) {
  return `${getOpenshellCommand()} policy set --policy ${shellQuote(policyFile)} --wait ${shellQuote(sandboxName)}`;
}

/**
 * Build the openshell policy get command with properly quoted arguments.
 */
function buildPolicyGetCommand(sandboxName) {
  return `${getOpenshellCommand()} policy get --full ${shellQuote(sandboxName)} 2>/dev/null`;
}

/**
 * Text-based fallback for merging preset entries into policy YAML.
 * Used when preset entries cannot be parsed as structured YAML.
 */
function textBasedMerge(currentPolicy, presetEntries) {
  if (!currentPolicy) {
    return "version: 1\n\nnetwork_policies:\n" + presetEntries;
  }
  let merged;
  if (/^network_policies\s*:/m.test(currentPolicy)) {
    const lines = currentPolicy.split("\n");
    const result = [];
    let inNp = false;
    let inserted = false;
    for (const line of lines) {
      if (/^network_policies\s*:/.test(line)) {
        inNp = true;
        result.push(line);
        continue;
      }
      if (inNp && /^\S.*:/.test(line) && !inserted) {
        result.push(presetEntries);
        inserted = true;
        inNp = false;
      }
      result.push(line);
    }
    if (inNp && !inserted) result.push(presetEntries);
    merged = result.join("\n");
  } else {
    merged = currentPolicy.trimEnd() + "\n\nnetwork_policies:\n" + presetEntries;
  }
  if (!merged.trimStart().startsWith("version:")) merged = "version: 1\n\n" + merged;
  return merged;
}

/**
 * Merge preset entries into existing policy YAML using structured YAML
 * parsing. Replaces the previous text-based manipulation which could
 * produce invalid YAML when indentation or ordering varied.
 *
 * Behavior:
 *   - Parses both current policy and preset entries as YAML
 *   - Merges network_policies by name (preset overrides on collision)
 *   - Preserves all non-network sections (filesystem_policy, process, etc.)
 *   - Ensures version: 1 exists
 *
 * @param {string} currentPolicy - Existing policy YAML (may be empty/versionless)
 * @param {string} presetEntries - Indented network_policies entries from preset
 * @returns {string} Merged YAML
 */
function mergePresetIntoPolicy(currentPolicy, presetEntries) {
  const normalizedCurrentPolicy = parseCurrentPolicy(currentPolicy);
  if (!presetEntries) {
    return normalizedCurrentPolicy || "version: 1\n\nnetwork_policies:\n";
  }

  // Parse preset entries. They come as indented content under network_policies:,
  // so we wrap them to make valid YAML for parsing.
  let presetPolicies;
  try {
    const wrapped = "network_policies:\n" + presetEntries;
    const parsed = YAML.parse(wrapped);
    presetPolicies = parsed?.network_policies;
  } catch {
    presetPolicies = null;
  }

  // If YAML parsing failed or entries are not a mergeable object,
  // fall back to the text-based approach for backward compatibility.
  if (!presetPolicies || typeof presetPolicies !== "object" || Array.isArray(presetPolicies)) {
    return textBasedMerge(normalizedCurrentPolicy, presetEntries);
  }

  if (!normalizedCurrentPolicy) {
    return YAML.stringify({ version: 1, network_policies: presetPolicies });
  }

  // Parse the current policy as structured YAML
  let current;
  try {
    current = YAML.parse(normalizedCurrentPolicy);
  } catch {
    return textBasedMerge(normalizedCurrentPolicy, presetEntries);
  }

  if (!current || typeof current !== "object") current = {};

  // Structured merge: preset entries override existing on name collision.
  // Guard: network_policies may be an array in legacy policies — only
  // object-merge when both sides are plain objects.
  const existingNp = current.network_policies;
  let mergedNp;
  if (existingNp && typeof existingNp === "object" && !Array.isArray(existingNp)) {
    mergedNp = { ...existingNp, ...presetPolicies };
  } else {
    mergedNp = presetPolicies;
  }

  const output = { version: current.version || 1 };
  for (const [key, val] of Object.entries(current)) {
    if (key !== "version" && key !== "network_policies") output[key] = val;
  }
  output.network_policies = mergedNp;

  return YAML.stringify(output);
}
/**
 * Return a modified copy of preset YAML content with all write-method rules removed,
 * keeping only GET, HEAD, and OPTIONS. Used when the user selects "read" mode in the wizard.
 */
/**
 * Return all non-GET/HEAD/OPTIONS rules as { method, host, path } objects.
 * Used in the wizard confirmation to show what write access each preset grants.
 */
function getWriteRules(presetContent) {
  if (!presetContent) return [];
  const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
  const results = [];
  try {
    const parsed = YAML.parse(presetContent);
    const np = parsed?.network_policies;
    if (!np || typeof np !== "object") return [];
    for (const policy of Object.values(np)) {
      if (!Array.isArray(policy.endpoints)) continue;
      for (const ep of policy.endpoints) {
        if (!Array.isArray(ep.rules)) continue;
        for (const rule of ep.rules) {
          if (!rule || typeof rule !== "object") continue;
          const method = (rule.allow?.method || rule.deny?.method || "").toUpperCase();
          if (method && !READ_METHODS.has(method)) {
            results.push({ method, host: ep.host || "", path: rule.allow?.path || rule.deny?.path || "" });
          }
        }
      }
    }
  } catch { /* ignore parse errors */ }
  return results;
}

/**
 * Return all endpoint hosts in a preset as { host, hasWrites }.
 * Used by the wizard to build the per-endpoint configuration UI.
 */
function getEndpoints(presetContent) {
  if (!presetContent) return [];
  const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  try {
    const parsed = YAML.parse(presetContent);
    const np = parsed?.network_policies;
    if (!np || typeof np !== "object") return [];
    const results = [];
    for (const policy of Object.values(np)) {
      if (!Array.isArray(policy.endpoints)) continue;
      for (const ep of policy.endpoints) {
        // access: full means unrestricted (no rules array) — treat as having writes.
        const hasWrites = ep.access === "full" ||
          (Array.isArray(ep.rules) && ep.rules.some((r) => {
            const method = (r?.allow?.method || r?.deny?.method || "").toUpperCase();
            return WRITE_METHODS.has(method);
          }));
        results.push({ host: ep.host || "", hasWrites });
      }
    }
    return results;
  } catch {
    return [];
  }
}

/**
 * Apply a preset with per-endpoint settings:
 *   endpointSettings: { [host]: { enabled: bool, readOnly: bool } }
 * Disabled endpoints are dropped entirely; readOnly endpoints have write rules removed.
 * Endpoints left with no rules after filtering are also dropped to pass policy validation.
 */
function applyPresetFiltered(sandboxName, presetContent, endpointSettings) {
  if (!presetContent) throw new Error("Empty preset content");
  const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
  let filteredContent;
  try {
    const parsed = YAML.parse(presetContent);
    const np = parsed?.network_policies;
    if (np && typeof np === "object") {
      for (const policy of Object.values(np)) {
        if (!Array.isArray(policy.endpoints)) continue;
        policy.endpoints = policy.endpoints
          .filter((ep) => endpointSettings[ep.host]?.enabled !== false)
          .map((ep) => {
            if (!endpointSettings[ep.host]?.readOnly || !Array.isArray(ep.rules)) return ep;
            return {
              ...ep,
              rules: ep.rules.filter((r) => {
                const method = (r?.allow?.method || r?.deny?.method || "").toUpperCase();
                return !method || READ_METHODS.has(method);
              }),
            };
          })
          .filter((ep) => !Array.isArray(ep.rules) || ep.rules.length > 0);
      }
      filteredContent = YAML.stringify(parsed);
    } else {
      filteredContent = presetContent;
    }
  } catch {
    filteredContent = presetContent;
  }
  return applyPresetFromContent(sandboxName, filteredContent);
}

function filterReadOnly(presetContent) {
  if (!presetContent) return presetContent;
  const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
  try {
    const parsed = YAML.parse(presetContent);
    if (!parsed || typeof parsed !== "object") return presetContent;
    const np = parsed.network_policies;
    if (!np || typeof np !== "object") return presetContent;
    for (const policy of Object.values(np)) {
      if (!Array.isArray(policy.endpoints)) continue;
      policy.endpoints = policy.endpoints
        .map((ep) => {
          if (!Array.isArray(ep.rules)) return ep;
          return {
            ...ep,
            rules: ep.rules.filter((rule) => {
              if (!rule || typeof rule !== "object") return true;
              const method = (rule.allow?.method || rule.deny?.method || "").toUpperCase();
              return !method || READ_METHODS.has(method);
            }),
          };
        })
        .filter((ep) => !Array.isArray(ep.rules) || ep.rules.length > 0);
    }
    return YAML.stringify(parsed);
  } catch {
    return presetContent;
  }
}

function applyPresetFromContent(sandboxName, content) {
  const isRfc1123Label = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sandboxName);
  if (!sandboxName || sandboxName.length > 63 || !isRfc1123Label) {
    throw new Error(
      `Invalid or truncated sandbox name: '${sandboxName}'. ` +
        `Names must be 1-63 chars, lowercase alphanumeric, with optional internal hyphens.`,
    );
  }

  const presetEntries = extractPresetEntries(content);
  if (!presetEntries) throw new Error("Provided policy content has no network_policies section.");

  let rawPolicy = "";
  try {
    rawPolicy = runCapture(buildPolicyGetCommand(sandboxName), { ignoreError: true });
  } catch { /* ignored */ }

  const merged  = mergePresetIntoPolicy(rawPolicy, presetEntries);
  const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-policy-"));
  const tmpFile = path.join(tmpDir, "policy.yaml");
  fs.writeFileSync(tmpFile, merged, { encoding: "utf-8", mode: 0o600 });

  try {
    run(buildPolicySetCommand(tmpFile, sandboxName));

    const presetName = YAML.parse(content)?.preset?.name;
    if (presetName) {
      const sandbox = registry.getSandbox(sandboxName);
      if (sandbox) {
        const pols = sandbox.policies || [];
        if (!pols.includes(presetName)) {
          pols.push(presetName);
        }
        registry.updateSandbox(sandboxName, { policies: pols });
      }
    }
  } finally {
    try { fs.unlinkSync(tmpFile); } catch { /* ignored */ }
    try { fs.rmdirSync(tmpDir);   } catch { /* ignored */ }
  }
}

function applyPreset(sandboxName, presetName) {
  // Guard against truncated sandbox names — WSL can truncate hyphenated
  // names during argument parsing, e.g. "my-assistant" → "m"
  const isRfc1123Label = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sandboxName);
  if (!sandboxName || sandboxName.length > 63 || !isRfc1123Label) {
    throw new Error(
      `Invalid or truncated sandbox name: '${sandboxName}'. ` +
        `Names must be 1-63 chars, lowercase alphanumeric, with optional internal hyphens.`,
    );
  }

  const presetContent = loadPreset(presetName);
  if (!presetContent) {
    console.error(`  Cannot load preset: ${presetName}`);
    return false;
  }

  const presetEntries = extractPresetEntries(presetContent);
  if (!presetEntries) {
    console.error(`  Preset ${presetName} has no network_policies section.`);
    return false;
  }

  // Get current policy YAML from sandbox
  let rawPolicy = "";
  try {
    rawPolicy = runCapture(buildPolicyGetCommand(sandboxName), { ignoreError: true });
  } catch {
    /* ignored */
  }

  const currentPolicy = parseCurrentPolicy(rawPolicy);
  const merged = mergePresetIntoPolicy(currentPolicy, presetEntries);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-policy-"));
  const tmpFile = path.join(tmpDir, "policy.yaml");
  fs.writeFileSync(tmpFile, merged, { encoding: "utf-8", mode: 0o600 });

  try {
    run(buildPolicySetCommand(tmpFile, sandboxName));

    console.log(`  Applied preset: ${presetName}`);
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      /* ignored */
    }
    try {
      fs.rmdirSync(tmpDir);
    } catch {
      /* ignored */
    }
  }

  const sandbox = registry.getSandbox(sandboxName);
  if (sandbox) {
    const pols = sandbox.policies || [];
    if (!pols.includes(presetName)) {
      pols.push(presetName);
    }
    registry.updateSandbox(sandboxName, { policies: pols });
  }

  return true;
}

function getAppliedPresets(sandboxName) {
  const sandbox = registry.getSandbox(sandboxName);
  return sandbox ? sandbox.policies || [] : [];
}

/**
 * Return the names of network_policies entries in the sandbox's current policy
 * that were NOT applied by a known preset. These are custom/manually-managed policies.
 */
function getNonPresetPolicies(sandboxName) {
  let rawPolicy = "";
  try {
    rawPolicy = runCapture(buildPolicyGetCommand(sandboxName), { ignoreError: true });
  } catch { /* ignored */ }

  const currentYaml = parseCurrentPolicy(rawPolicy);
  if (!currentYaml) return [];

  let parsed;
  try { parsed = YAML.parse(currentYaml); } catch { return []; }

  const np = parsed?.network_policies;
  if (!np || typeof np !== "object" || Array.isArray(np)) return [];

  const presetNames = new Set(listPresets().map((p) => p.name));
  return Object.keys(np).filter((k) => !presetNames.has(k));
}

module.exports = {
  PRESETS_DIR,
  listPresets,
  loadPreset,
  getPresetEndpoints,
  extractPresetEntries,
  parseCurrentPolicy,
  buildPolicySetCommand,
  buildPolicyGetCommand,
  mergePresetIntoPolicy,
  getEndpoints,
  getWriteRules,
  filterReadOnly,
  applyPreset,
  applyPresetFromContent,
  applyPresetFiltered,
  getAppliedPresets,
  getNonPresetPolicies,
};
