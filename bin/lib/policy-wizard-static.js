// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// policy-wizard-static.js — Static policy wizard for NemoClaw.  No LLM required.
//
// Guided TUI for policy composition without an LLM:
//
//   Q1  Select presets              (checklist — browse all preset files)
//   Q2  Access level per preset     (read / write toggle grid)
//   Compose → exfil warning → review → name → save
//
// Missing presets: the wizard warns and skips tools with no preset file.
//   → Add <toolId>.yaml to nemoclaw-blueprint/policies/presets/ to fill gaps.

"use strict";

const fs       = require("fs");
const path     = require("path");
const readline = require("readline");
const yaml = require("yaml");
const {
  filterEndpoints,
  buildPresetYaml,
  PRESETS_DIR,
} = require("./policy-compose");

const CUSTOM_DIR = path.resolve(PRESETS_DIR, "../custom");

// ---------------------------------------------------------------------------
// Terminal colors  (respects NO_COLOR)
// ---------------------------------------------------------------------------

const _color = !process.env.NO_COLOR && !!process.stdout.isTTY;
const _tc    = _color && (process.env.COLORTERM === "truecolor" || process.env.COLORTERM === "24bit");

const C = {
  green:  _color ? (_tc ? "\x1b[38;2;118;185;0m" : "\x1b[38;5;148m") : "",
  yellow: _color ? "\x1b[33m" : "",
  red:    _color ? "\x1b[31m" : "",
  bold:   _color ? "\x1b[1m" : "",
  dim:    _color ? "\x1b[2m" : "",
  cyan:   _color ? "\x1b[36m" : "",
  reset:  _color ? "\x1b[0m" : "",
};

// ---------------------------------------------------------------------------
// Raw-mode TUI helpers
// ---------------------------------------------------------------------------

function rawInput(handler) {
  try { process.stdin.setRawMode(true); } catch { /* not a TTY */ }
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", handler);
}

function rawCleanup(handler) {
  try { process.stdin.setRawMode(false); } catch { /* ignore */ }
  process.stdin.pause();
  process.stdin.removeListener("data", handler);
}

const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]/g;
function writeLine(s, counter) {
  process.stdout.write(s + "\n");
  const cols = process.stdout.columns || 80;
  const visible = s.replace(ANSI_RE, "");
  return counter + Math.max(1, Math.ceil(visible.length / cols));
}

function isPrintable(key) {
  return key.length === 1 && key.charCodeAt(0) >= 32 && key.charCodeAt(0) < 127;
}

// ---------------------------------------------------------------------------
// Q1 — Use-case selector  (↑↓ · type to filter · Enter)
// ---------------------------------------------------------------------------

function promptArrowSelect(title, options, defaultIdx = 0) {
  return new Promise((resolve) => {
    let cursor = defaultIdx < options.length ? defaultIdx : 0;
    let filter = "";
    let lineCount = 0;

    function filtered() {
      if (!filter) return options.map((o, i) => ({ ...o, origIdx: i }));
      const lf = filter.toLowerCase();
      return options
        .map((o, i) => ({ ...o, origIdx: i }))
        .filter((o) => o.name.toLowerCase().includes(lf) || (o.desc || "").toLowerCase().includes(lf));
    }

    function render() {
      let n = 0;
      const vis = filtered();
      if (cursor >= vis.length) cursor = Math.max(0, vis.length - 1);
      n = writeLine(`  ${C.bold}${title}${C.reset}`, n);
      n = writeLine("", n);
      if (vis.length === 0) {
        n = writeLine(`  ${C.dim}No matches — press Enter to use "${filter}" as custom value${C.reset}`, n);
      } else {
        for (let i = 0; i < vis.length; i++) {
          const { name, desc } = vis[i];
          if (i === cursor) {
            n = writeLine(`  ${C.green}${C.bold}▶ ${name.padEnd(22)}${C.reset}  ${C.dim}${desc || ""}${C.reset}`, n);
          } else {
            n = writeLine(`    ${C.dim}${name.padEnd(22)}  ${desc || ""}${C.reset}`, n);
          }
        }
      }
      n = writeLine("", n);
      const hint = filter
        ? `  ${C.dim}Filter:${C.reset} ${filter}${C.dim}▌  Esc clear · Enter confirm${C.reset}`
        : `  ${C.dim}↑↓ cycle · Enter confirm · type to filter${C.reset}`;
      n = writeLine(hint, n);
      lineCount = n;
    }

    function renderConfirmed(name) {
      process.stdout.write(`\x1b[${lineCount}A\x1b[0J`);
      writeLine(`  ${C.bold}${title}${C.reset}`, 0);
      writeLine("", 0);
      writeLine(`  ${C.green}✓ ${name}${C.reset}`, 0);
      writeLine("", 0);
    }

    render();

    const handler = (key) => {
      const vis = filtered();
      if (key === "\x1b[A") {
        cursor = (cursor - 1 + Math.max(vis.length, 1)) % Math.max(vis.length, 1);
        redraw();
      } else if (key === "\x1b[B") {
        cursor = (cursor + 1) % Math.max(vis.length, 1);
        redraw();
      } else if (key === "\r" || key === "\n") {
        rawCleanup(handler);
        if (vis.length === 0 || (filter && vis[cursor]?.name.toLowerCase() !== filter.toLowerCase())) {
          const label = filter || (vis.length > 0 ? vis[cursor].name : "");
          renderConfirmed(label);
          resolve(filter ? { _freeText: filter } : vis.length > 0 ? vis[cursor].origIdx : null);
        } else {
          renderConfirmed(vis[cursor].name);
          resolve(vis[cursor].origIdx);
        }
      } else if (key === "\x1b") {
        filter = ""; cursor = 0; redraw();
      } else if (key === "\x7f" || key === "\b") {
        filter = filter.slice(0, -1); cursor = 0; redraw();
      } else if (isPrintable(key)) {
        filter += key; cursor = 0; redraw();
      } else if (key === "\u0003") {
        rawCleanup(handler);
        process.stderr.write(`\n  ${C.dim}Goodbye.${C.reset}\n\n`);
        process.exit(0);
      }
    };

    rawInput(handler);
    function redraw() { process.stdout.write(`\x1b[${lineCount}A\x1b[0J`); render(); }
  });
}

// ---------------------------------------------------------------------------
// Q3 — Access level grid  (↑↓ · ←→ or r/w · Enter confirm)
// ---------------------------------------------------------------------------

function promptAccessLevels(tools) {
  return new Promise((resolve) => {
    let cursor = 0;
    const access = Object.fromEntries(tools.map((t) => [t.id, "read"]));
    let lineCount = 0;

    function render() {
      let n = 0;
      n = writeLine(`  ${C.bold}Access levels${C.reset}`, n);
      n = writeLine("", n);
      for (let i = 0; i < tools.length; i++) {
        const t = tools[i];
        const isCurs  = i === cursor;
        const isWrite = access[t.id] === "write";
        const curs    = isCurs ? `${C.green}▶${C.reset}` : " ";
        const readLbl = !isWrite ? `${C.bold}${C.green}● Read only   ${C.reset}` : `${C.dim}○ Read only   ${C.reset}`;
        const wriLbl  =  isWrite ? `${C.bold}${C.green}● Read+write  ${C.reset}` : `${C.dim}○ Read+write  ${C.reset}`;
        n = writeLine(`  ${curs} ${t.name.padEnd(18)}  ${readLbl}  ${wriLbl}`, n);
      }
      n = writeLine("", n);
      n = writeLine(`  ${C.dim}↑↓ cycle · ←→ or r/w toggle · Enter confirm${C.reset}`, n);
      lineCount = n;
    }

    render();

    const handler = (key) => {
      if (key === "\x1b[A") {
        cursor = (cursor - 1 + tools.length) % tools.length; redraw();
      } else if (key === "\x1b[B") {
        cursor = (cursor + 1) % tools.length; redraw();
      } else if (key === "\x1b[C" || key === "\x1b[D" || key === "r" || key === "w" || key === "\t") {
        const t = tools[cursor];
        if (key === "r") access[t.id] = "read";
        else if (key === "w") access[t.id] = "write";
        else access[t.id] = access[t.id] === "read" ? "write" : "read";
        redraw();
      } else if (key === "\r" || key === "\n") {
        rawCleanup(handler); process.stdout.write("\n"); resolve(access);
      } else if (key === "\u0003") {
        rawCleanup(handler);
        process.stderr.write(`\n  ${C.dim}Goodbye.${C.reset}\n\n`);
        process.exit(0);
      }
    };

    rawInput(handler);
    function redraw() { process.stdout.write(`\x1b[${lineCount}A\x1b[0J`); render(); }
  });
}

// ---------------------------------------------------------------------------
// Q4 — Filesystem paths  (checklist + custom entry)
// ---------------------------------------------------------------------------

const FS_PRESETS = [
  { path: "/data",      access: "rw", desc: "General data directory"           },
  { path: "/workspace", access: "rw", desc: "Working directory / project root" },
  { path: "/models",    access: "ro", desc: "ML model weights (read-only)"     },
  { path: "/config",    access: "ro", desc: "App config files (read-only)"     },
  { path: "/secrets",   access: "ro", desc: "Secrets / credentials (read-only)"},
  { path: "/output",    access: "rw", desc: "Agent output directory"           },
  { path: "/repo",      access: "ro", desc: "Source code checkout (read-only)" },
  { path: "/logs",      access: "rw", desc: "Log files"                        },
];

async function promptFilesystemPaths() {
  process.stdout.write(`  ${C.bold}Q4  Additional filesystem access?${C.reset}\n`);
  process.stdout.write(`  ${C.dim}Defaults always included: /usr /lib /etc /app (ro) · /sandbox /tmp (rw)${C.reset}\n\n`);

  const items = FS_PRESETS.map((p) => ({
    id: p.path, name: p.path,
    desc: `${p.desc}  ${C.dim}[${p.access === "rw" ? "read+write" : "read-only"}]${C.reset}`,
    defaultAccess: p.access,
  }));

  const selected = await new Promise((resolve) => {
    let cursor = 0;
    let filter = "";
    const chosen = new Set();
    let lineCount = 0;
    const customPaths = [];

    function visItems() {
      const base = [...items, ...customPaths.map((p) => ({ id: p, name: p, desc: "custom", defaultAccess: "rw" }))];
      if (!filter) return base;
      const lf = filter.toLowerCase();
      return base.filter((it) => it.name.toLowerCase().includes(lf));
    }

    function render() {
      let n = 0;
      const vis = visItems();
      if (cursor >= vis.length && vis.length > 0) cursor = vis.length - 1;
      n = writeLine("", n);
      for (let i = 0; i < vis.length; i++) {
        const it = vis[i];
        const tick  = chosen.has(it.id) ? `${C.green}✓${C.reset}` : `${C.dim}○${C.reset}`;
        const arrow = i === cursor ? `${C.green}${C.bold}▶${C.reset}` : " ";
        n = writeLine(`  ${arrow} ${tick}  ${it.name.padEnd(14)}  ${C.dim}${it.desc}${C.reset}`, n);
      }
      n = writeLine("", n);
      const hint = filter
        ? `  ${C.dim}Filter:${C.reset} ${filter}${C.dim}▌  Enter to add as custom path · Esc clear${C.reset}`
        : `  ${C.dim}↑↓ move · Space toggle · Enter confirm · type to filter/add custom path${C.reset}`;
      n = writeLine(hint, n);
      lineCount = n;
    }

    render();

    const handler = (key) => {
      const vis = visItems();
      if (key === "\x1b[A") {
        cursor = (cursor - 1 + Math.max(vis.length, 1)) % Math.max(vis.length, 1); redraw();
      } else if (key === "\x1b[B") {
        cursor = (cursor + 1) % Math.max(vis.length, 1); redraw();
      } else if (key === " ") {
        const it = vis[cursor];
        if (it) { chosen.has(it.id) ? chosen.delete(it.id) : chosen.add(it.id); }
        redraw();
      } else if (key === "\r" || key === "\n") {
        if (filter) {
          const custom = filter.trim();
          if (custom.startsWith("/") && !items.find((it) => it.id === custom) && !customPaths.includes(custom)) {
            customPaths.push(custom);
            chosen.add(custom);
          }
          filter = ""; redraw();
        } else {
          rawCleanup(handler);
          process.stdout.write(`\x1b[${lineCount}A\x1b[0J`);
          const allItems = [...items, ...customPaths.map((p) => ({ id: p, name: p, defaultAccess: "rw" }))];
          const result = allItems.filter((it) => chosen.has(it.id));
          if (result.length > 0) {
            writeLine(`  ${C.green}✓ Filesystem paths${C.reset}  ${C.dim}${result.map((it) => it.name).join("  ")}${C.reset}`, 0);
          } else {
            writeLine(`  ${C.dim}✓ Filesystem paths  defaults only${C.reset}`, 0);
          }
          writeLine("", 0);
          resolve(result);
        }
      } else if (key === "\x1b") {
        filter = ""; redraw();
      } else if (key === "\x7f" || key === "\b") {
        filter = filter.slice(0, -1); redraw();
      } else if (isPrintable(key)) {
        filter += key; cursor = 0; redraw();
      } else if (key === "\u0003") {
        rawCleanup(handler);
        process.stderr.write(`\n  ${C.dim}Goodbye.${C.reset}\n\n`);
        process.exit(0);
      }
    };

    rawInput(handler);
    function redraw() { process.stdout.write(`\x1b[${lineCount}A\x1b[0J`); render(); }
  });

  const readOnly  = [];
  const readWrite = [];

  for (const it of selected) {
    if (it.defaultAccess === "ro") { readOnly.push(it.id); continue; }
    const answer = await new Promise((resolve) => {
      process.stdout.write(
        `  ${it.name}  ${C.dim}access: ${C.reset}${C.bold}[r]${C.reset}${C.dim}ead-only${C.reset}  /  ${C.bold}[w]${C.reset}${C.dim}rite  (r/w):${C.reset} `,
      );
      const handler = (key) => {
        if (key === "r" || key === "R") {
          rawCleanup(handler); process.stdout.write(`${C.dim}read-only${C.reset}\n`); resolve("ro");
        } else if (key === "w" || key === "W" || key === "\r" || key === "\n") {
          rawCleanup(handler); process.stdout.write(`${C.dim}read+write${C.reset}\n`); resolve("rw");
        } else if (key === "\u0003") {
          rawCleanup(handler);
          process.stderr.write(`\n  ${C.dim}Goodbye.${C.reset}\n\n`);
          process.exit(0);
        }
      };
      rawInput(handler);
    });
    (answer === "ro" ? readOnly : readWrite).push(it.id);
  }

  process.stdout.write("\n");
  return { readOnly, readWrite };
}

// ---------------------------------------------------------------------------
// Preset picker helpers
// ---------------------------------------------------------------------------

function loadAllPresets() {
  const files = fs.readdirSync(PRESETS_DIR).filter((f) => f.endsWith(".yaml")).sort();
  return files.map((file) => {
    const raw = fs.readFileSync(path.join(PRESETS_DIR, file), "utf-8");
    const doc = yaml.parse(raw);
    const name = doc?.preset?.name || file.replace(/\.yaml$/, "");
    const networkPolicies = doc?.network_policies || {};
    const hosts = Object.values(networkPolicies)
      .flatMap((b) => b.endpoints || [])
      .map((ep) => ep.host);
    return { file, name, id: name, doc, hosts: [...new Set(hosts)] };
  });
}

function promptPresetChecklist(presets) {
  const sorted = [...presets].sort((a, b) => a.name.localeCompare(b.name));

  return new Promise((resolve) => {
    let cursor = 0;
    const chosen = new Set(); // indices into sorted
    let filter = "";
    let searching = false;
    let lineCount = 0;

    function visible() {
      if (!filter) return sorted.map((p, i) => ({ p, i }));
      const lf = filter.toLowerCase();
      return sorted
        .map((p, i) => ({ p, i }))
        .filter(({ p }) => p.name.toLowerCase().includes(lf) || p.hosts.some((h) => h.toLowerCase().includes(lf)));
    }

    function render() {
      let n = 0;
      n = writeLine(`  ${C.bold}Select presets${C.reset}`, n);
      n = writeLine("", n);
      const vis = visible();
      if (cursor >= vis.length) cursor = Math.max(0, vis.length - 1);

      if (vis.length === 0) {
        n = writeLine(`  ${C.dim}No matches for "${filter}"${C.reset}`, n);
      } else {
        for (let j = 0; j < vis.length; j++) {
          const { p, i } = vis[j];
          const isSel  = chosen.has(i);
          const isCurs = j === cursor;
          const curs  = isCurs ? `${C.green}▶${C.reset}` : " ";
          const check = isSel  ? `${C.green}✓${C.reset}` : " ";
          const hosts = p.hosts.length ? `  ${C.dim}${p.hosts.join("  ")}${C.reset}` : "";
          n = writeLine(`  ${curs} [${check}] ${p.name}${hosts}`, n);
        }
      }

      n = writeLine("", n);
      const selHint = chosen.size === 0 ? "select at least one" : `${chosen.size} selected`;
      if (searching) {
        n = writeLine(`  ${C.dim}/${C.reset}${filter}${C.green}▌${C.reset}  ${C.dim}Esc clear · Enter confirm · ${selHint}${C.reset}`, n);
      } else {
        n = writeLine(`  ${C.dim}j/k move · Space toggle · / search · Enter confirm · ${selHint}${C.reset}`, n);
      }
      lineCount = n;
    }

    render();

    const handler = (key) => {
      const vis = visible();

      if (searching) {
        if (key === "\x1b" || key === "\x1b[") {
          filter = ""; searching = false; cursor = 0; redraw();
        } else if (key === "\x7f" || key === "\b") {
          filter = filter.slice(0, -1);
          if (filter === "") searching = false;
          cursor = 0; redraw();
        } else if (key === "\r" || key === "\n") {
          searching = false; redraw();
        } else if (isPrintable(key)) {
          filter += key; cursor = 0; redraw();
        } else if (key === "\x1b[A" || key === "k") {
          cursor = (cursor - 1 + Math.max(vis.length, 1)) % Math.max(vis.length, 1); redraw();
        } else if (key === "\x1b[B" || key === "j") {
          cursor = (cursor + 1) % Math.max(vis.length, 1); redraw();
        } else if (key === "\u0003") {
          rawCleanup(handler);
          process.stderr.write(`\n  ${C.dim}Goodbye.${C.reset}\n\n`);
          process.exit(0);
        }
        return;
      }

      if (key === "\x1b[A" || key === "k") { cursor = (cursor - 1 + Math.max(vis.length, 1)) % Math.max(vis.length, 1); redraw(); }
      else if (key === "\x1b[B" || key === "j") { cursor = (cursor + 1) % Math.max(vis.length, 1); redraw(); }
      else if (key === " ") {
        if (vis.length === 0) return;
        const { i } = vis[cursor];
        if (chosen.has(i)) chosen.delete(i); else chosen.add(i);
        redraw();
      } else if (key === "/") {
        searching = true; redraw();
      } else if (key === "\x1b") {
        filter = ""; cursor = 0; redraw();
      } else if (key === "\r" || key === "\n") {
        if (chosen.size === 0) return;
        rawCleanup(handler);
        process.stdout.write(`\x1b[${lineCount}A\x1b[0J`);
        const names = [...chosen].map((i) => sorted[i].name);
        writeLine(`  ${C.green}✓ ${names.join(", ")}${C.reset}`, 0);
        process.stdout.write("\n");
        resolve(sorted.filter((_, i) => chosen.has(i)));
      } else if (key === "\u0003") {
        rawCleanup(handler);
        process.stderr.write(`\n  ${C.dim}Goodbye.${C.reset}\n\n`);
        process.exit(0);
      }
    };

    rawInput(handler);
    let _redrawTimer = null;
    function redraw() {
      if (_redrawTimer) return;
      _redrawTimer = setTimeout(() => {
        _redrawTimer = null;
        process.stdout.write(`\x1b[${lineCount}A\x1b[0J`);
        render();
      }, 50);
    }
  });
}

function mergePresets(selections) {
  const policies = {};
  const multi = selections.length > 1;
  for (const { preset, level } of selections) {
    const networkPolicies = preset.doc?.network_policies || {};
    for (const [blockName, block] of Object.entries(networkPolicies)) {
      const filtered = filterEndpoints(block.endpoints, level);
      if (filtered.length === 0) continue;
      const key = multi ? `${preset.name}-${blockName}` : blockName;
      policies[key] = {
        name: key,
        endpoints: filtered,
        ...(block.binaries ? { binaries: block.binaries } : {}),
      };
    }
  }
  return policies;
}

// ---------------------------------------------------------------------------
// Exfiltration risk warnings
// ---------------------------------------------------------------------------

/**
 * Collect exfil_risk annotations from all rules across a merged policies object.
 * Returns an array of { policyName, host, method, path, risk } entries.
 */
function collectExfilRisks(policies) {
  const results = [];
  for (const [policyName, block] of Object.entries(policies)) {
    for (const ep of block.endpoints || []) {
      for (const rule of ep.rules || []) {
        if (rule.exfil_risk) {
          results.push({
            policyName,
            host: ep.host,
            method: rule.allow?.method,
            path: rule.allow?.path,
            risk: rule.exfil_risk,
          });
        }
      }
    }
  }
  return results;
}

async function warnExfil(policies) {
  const risks = collectExfilRisks(policies);

  if (risks.length === 0) return;

  process.stdout.write(`\n  ${C.yellow}${C.bold}⚠  EXFILTRATION RISK${C.reset}\n`);
  process.stdout.write(`  ${C.dim}The following rules can move data outside the sandbox:${C.reset}\n\n`);
  let lastPolicy = null;
  let lastHost = null;
  for (const { policyName, host, method, path, risk } of risks) {
    if (policyName !== lastPolicy) {
      process.stdout.write(`    ${C.yellow}●${C.reset}  ${C.bold}${policyName}${C.reset}\n`);
      lastPolicy = policyName;
      lastHost = null;
    }
    if (host !== lastHost) {
      process.stdout.write(`       ${C.cyan}${host}${C.reset}\n`);
      lastHost = host;
    }
    process.stdout.write(`         ${C.dim}${method} ${path}${C.reset} — ${risk}\n`);
  }

  process.stdout.write("\n");
  await new Promise((resolve) => {
    process.stdout.write(`  ${C.dim}Press Enter to acknowledge and continue, or Ctrl+C to abort.${C.reset} `);
    const handler = (key) => {
      if (key === "\u0003") { rawCleanup(handler); process.stderr.write("\n"); process.exit(0); }
      if (key === "\r" || key === "\n") { rawCleanup(handler); process.stdout.write("\n\n"); resolve(); }
    };
    rawInput(handler);
  });
}

function renderMergedReview(policies) {
  const allEndpoints = Object.values(policies).flatMap((b) => b.endpoints || []);
  process.stdout.write(`  ${C.bold}WHAT IS OPENED${C.reset}\n`);
  for (const ep of allEndpoints) {
    const methods = [...new Set((ep.rules || []).map((r) => r.allow?.method).filter(Boolean))];
    process.stdout.write(`    ${C.dim}${ep.host}:${ep.port}${C.reset}  ${methods.join(" ")}\n`);
  }
  process.stdout.write("\n");
  process.stdout.write(`  ${C.bold}WHAT REMAINS BLOCKED${C.reset}\n`);
  process.stdout.write(`  ${C.dim}  All hosts not listed above${C.reset}\n`);
  process.stdout.write(`  ${C.dim}  All RFC1918 / loopback / link-local / CGNAT addresses${C.reset}\n`);
  process.stdout.write(`  ${C.dim}  All binaries not explicitly listed in policies${C.reset}\n`);
  process.stdout.write("\n");
}

// ---------------------------------------------------------------------------
// Main wizard run
// ---------------------------------------------------------------------------

async function run() {
  process.stdout.write("\n");
  process.stdout.write(`  ${C.bold}${C.green}NemoClaw Policy Wizard${C.reset}  ${C.dim}(static — no inference required)${C.reset}\n\n`);

  const allPresets = loadAllPresets();
  if (allPresets.length === 0) {
    process.stderr.write(`  ${C.red}No preset files found in ${PRESETS_DIR}${C.reset}\n\n`);
    process.exit(1);
  }

  // ── Select presets ────────────────────────────────────────────────────────
  const selected = await promptPresetChecklist(allPresets);

  // ── Access level per preset ───────────────────────────────────────────────
  const accessMap = await promptAccessLevels(selected);
  const selections = selected.map((preset) => ({ preset, level: accessMap[preset.id] }));

  // ── Merge ─────────────────────────────────────────────────────────────────
  const policies = mergePresets(selections);

  if (Object.keys(policies).length === 0) {
    process.stderr.write(`  ${C.red}No endpoints remained after filtering. Try write access or check preset files.${C.reset}\n\n`);
    process.exit(1);
  }

  // ── Exfiltration warning ──────────────────────────────────────────────────
  await warnExfil(policies);

  renderMergedReview(policies);

  // ── Save to custom/ ───────────────────────────────────────────────────────
  fs.mkdirSync(CUSTOM_DIR, { recursive: true });
  const defaultName = selections.map(({ preset, level }) => `${preset.name}-${level[0]}`).join("--");
  const nameAnswer = await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`  Save as [${defaultName}]: `, (ans) => { rl.close(); resolve(ans.trim()); });
  });
  const outName = (nameAnswer || defaultName).toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 63) || defaultName;
  const content  = buildPresetYaml(outName, policies, { readOnly: [], readWrite: [] });
  const outPath  = path.join(CUSTOM_DIR, `${outName}.yaml`);
  fs.writeFileSync(outPath, content, "utf-8");

  process.stdout.write(`  ${C.green}✓${C.reset}  Saved to ${outPath}\n\n`);
  process.stdout.write(`  To apply to a sandbox:\n`);
  process.stdout.write(`    ${C.bold}nemoclaw policy apply <sandbox-name> --preset-file ${outPath}${C.reset}\n\n`);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Run just the TUI selection (checklist + access levels) and return the
 * merged policy YAML string.  No file is written; the caller decides what
 * to do with the content (e.g. apply directly to a sandbox).
 */
async function selectAndMerge() {
  const allPresets = loadAllPresets();
  if (allPresets.length === 0) throw new Error(`No preset files found in ${PRESETS_DIR}`);

  const selected  = await promptPresetChecklist(allPresets);
  const accessMap = await promptAccessLevels(selected);
  const selections = selected.map((preset) => ({ preset, level: accessMap[preset.id] }));

  const policies  = mergePresets(selections);

  if (Object.keys(policies).length === 0) {
    throw new Error("No endpoints remained after filtering. Try write access or check preset files.");
  }

  await warnExfil(policies);

  renderMergedReview(policies);

  const name = selections.map(({ preset, level }) => `${preset.name}-${level[0]}`).join("--");
  return buildPresetYaml(name, policies, { readOnly: [], readWrite: [] });
}

module.exports = { run, selectAndMerge };

if (require.main === module) {
  run().catch((err) => {
    console.error(`\n  Unexpected error: ${err.message}\n`);
    process.exit(1);
  });
}
