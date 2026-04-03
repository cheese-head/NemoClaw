// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// NemoClaw wizard command — full-screen TUI onboarding powered by pi-tui.
// A seamless interactive alternative to `nemoclaw onboard` for TTY terminals.

"use strict";

const { spawnSync } = require("child_process");
const { run, runCapture, shellQuote } = require("./runner");
const { checkPortAvailable, getMemoryInfo } = require("./preflight");
const { getCredential, saveCredential, prompt } = require("./credentials");
const {
  CLOUD_MODEL_OPTIONS,
  DEFAULT_CLOUD_MODEL,
  getProviderSelectionConfig,
} = require("./inference-config");
const { getOllamaModelOptions, getDefaultOllamaModel } = require("./local-inference");
const { resolveOpenshell } = require("./resolve-openshell");
const { getGatewayReuseState, createSandbox } = require("./onboard");
const policies = require("./policies");

// ── Color helpers ─────────────────────────────────────────────────
const _useColor = !process.env.NO_COLOR && !!process.stdout.isTTY;
const _tc =
  _useColor && (process.env.COLORTERM === "truecolor" || process.env.COLORTERM === "24bit");
const G  = _useColor ? (_tc ? "\x1b[38;2;118;185;0m" : "\x1b[38;5;148m") : "";
const B  = _useColor ? "\x1b[1m"    : "";
const D  = _useColor ? "\x1b[2m"    : "";
const R  = _useColor ? "\x1b[0m"    : "";
const RD = _useColor ? "\x1b[1;31m" : "";
const YW = _useColor ? "\x1b[1;33m" : "";

const GATEWAY_NAME = "nemoclaw";

// Sentinel returned by a step to signal the user pressed Back (ESC).
// The main loop decrements the step index when it sees this.
const BACK = Symbol("wizard:back");

// ── Named steps shown in the persistent header ────────────────────
// Indices 0-4 map to wizard steps 1-5 (step 0 is Welcome, step 6 is Done).
const HEADER_STEPS = ["System Checks", "Gateway", "Provider", "Sandbox", "Policies"];

// ── Inference provider menu ───────────────────────────────────────
const PROVIDERS = [
  { value: "nvidia-nim",                     label: "NVIDIA Endpoints",               description: "build.nvidia.com — Nemotron + hosted models" },
  { value: "openai-api",                     label: "OpenAI",                         description: "GPT-5.4 and later" },
  { value: "anthropic-prod",                label: "Anthropic",                      description: "Claude models" },
  { value: "gemini-api",                     label: "Google Gemini",                  description: "Gemini 2.5 Flash and later" },
  { value: "compatible-endpoint",           label: "OpenAI-compatible endpoint",      description: "Custom base URL, OpenAI-style API" },
  { value: "compatible-anthropic-endpoint", label: "Anthropic-compatible endpoint",   description: "Custom base URL, Anthropic-style API" },
  { value: "ollama-local",                  label: "Local Ollama",                   description: "Requires Ollama running on localhost" },
  { value: "vllm-local",                    label: "Local vLLM (experimental)",      description: "Requires vLLM on localhost:8000" },
];

// ── Curated model lists per provider ─────────────────────────────
// "__custom__" sentinel drops to free-text input.
const PROVIDER_MODELS = {
  "nvidia-nim": CLOUD_MODEL_OPTIONS.map((m) => ({ value: m.id, label: m.label })),
  "openai-api": [
    { value: "gpt-4.1",                  label: "GPT-4.1" },
    { value: "gpt-4o",                   label: "GPT-4o" },
    { value: "gpt-4o-mini",              label: "GPT-4o mini" },
    { value: "o3",                       label: "o3" },
    { value: "o4-mini",                  label: "o4-mini" },
    { value: "__custom__",               label: "Custom model ID…" },
  ],
  "anthropic-prod": [
    { value: "claude-opus-4-6",          label: "Claude Opus 4.6" },
    { value: "claude-sonnet-4-6",        label: "Claude Sonnet 4.6" },
    { value: "claude-haiku-4-5-20251001",label: "Claude Haiku 4.5" },
    { value: "__custom__",               label: "Custom model ID…" },
  ],
  "gemini-api": [
    { value: "gemini-2.5-pro",           label: "Gemini 2.5 Pro" },
    { value: "gemini-2.5-flash",         label: "Gemini 2.5 Flash" },
    { value: "gemini-2.0-flash",         label: "Gemini 2.0 Flash" },
    { value: "__custom__",               label: "Custom model ID…" },
  ],
  "compatible-endpoint":           [{ value: "__custom__", label: "Enter model ID…" }],
  "compatible-anthropic-endpoint": [{ value: "__custom__", label: "Enter model ID…" }],
};

// ── Live model fetch ──────────────────────────────────────────────

async function fetchModels(provider, credentialEnv, endpointUrl) {
  const apiKey = credentialEnv ? getCredential(credentialEnv) : null;
  if (!apiKey) return null;

  let url;
  const headers = { "Content-Type": "application/json" };

  switch (provider) {
    case "nvidia-nim":
    case "nvidia-prod":
      url = "https://integrate.api.nvidia.com/v1/models";
      headers["Authorization"] = `Bearer ${apiKey}`;
      break;
    case "openai-api":
      url = "https://api.openai.com/v1/models";
      headers["Authorization"] = `Bearer ${apiKey}`;
      break;
    case "compatible-endpoint":
      if (!endpointUrl) return null;
      url = `${endpointUrl.replace(/\/+$/, "")}/models`;
      headers["Authorization"] = `Bearer ${apiKey}`;
      break;
    case "anthropic-prod":
      url = "https://api.anthropic.com/v1/models";
      headers["x-api-key"] = apiKey;
      headers["anthropic-version"] = "2023-06-01";
      break;
    case "compatible-anthropic-endpoint":
      if (!endpointUrl) return null;
      url = `${endpointUrl.replace(/\/+$/, "")}/models`;
      headers["x-api-key"] = apiKey;
      headers["anthropic-version"] = "2023-06-01";
      break;
    case "gemini-api":
      url = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`;
      break;
    default:
      return null;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timeout);
    if (!resp.ok) return null;
    const json = await resp.json();
    if (Array.isArray(json?.data)) {
      return json.data.map((m) => m.id).filter(Boolean).sort();
    }
    if (Array.isArray(json?.models)) {
      return json.models
        .map((m) => (m.name || "").replace(/^models\//, "") || m.id)
        .filter(Boolean)
        .sort();
    }
    return null;
  } catch {
    return null;
  }
}

// ── Openshell helpers ─────────────────────────────────────────────

let _openshellBin = null;
function getOpenshellBin() {
  if (!_openshellBin) {
    _openshellBin = resolveOpenshell();
    if (!_openshellBin) {
      console.error("  openshell CLI not found. Install OpenShell before running the wizard.");
      process.exit(1);
    }
  }
  return _openshellBin;
}

function osCap(args) {
  const cmd = [shellQuote(getOpenshellBin()), ...args.map(shellQuote)].join(" ");
  return runCapture(cmd, { ignoreError: true }) || "";
}

function osRun(args, opts = {}) {
  const cmd = [shellQuote(getOpenshellBin()), ...args.map(shellQuote)].join(" ");
  return run(cmd, { ignoreError: false, ...opts });
}

// ── Search state (shared across all SelectList steps) ────────────
// Updated by renderStep whenever a SelectList is focused.

let _searchList  = null;  // currently visible SelectList
let _searchText  = null;  // Text component displaying the filter query
let _searchQuery = "";
let _searchActive = false;

function setSearchList(list, searchText) {
  _searchList   = list;
  _searchText   = searchText;
  _searchQuery  = "";
  _searchActive = false;
}

function clearSearchList() {
  _searchList = _searchText = null;
  _searchQuery = "";
  _searchActive = false;
}

function applySearchFilter(list, query) {
  const q = query.toLowerCase();
  list.filteredItems = q
    ? list.items.filter((item) =>
        item.value.toLowerCase().includes(q) ||
        (item.label || "").replace(/\x1b\[[0-9;]*m/g, "").toLowerCase().includes(q),
      )
    : [...list.items];
  list.selectedIndex = Math.max(0, Math.min(list.selectedIndex, list.filteredItems.length - 1));
  list.invalidate();
}

// ── pi-tui theme ──────────────────────────────────────────────────

function makeSelectTheme() {
  return {
    selectedText: (t) => `${G}${B}${t}${R}`,
    description : (t) => `${D}  ${t}${R}`,
    noMatch     : (t) => `${D}${t}${R}`,
    scrollInfo  : (t) => `${D}${t}${R}`,
  };
}

// ── Layout helpers ────────────────────────────────────────────────

/**
 * Persistent header showing all named steps with completion status.
 * wizardStep: 0 = Welcome (all pending), 1-5 = active step, 6 = Done (all done).
 */
function makeHeader(wizardStep, { Text }) {
  // Map wizard step index to header step index (0-4)
  const headerActive = wizardStep - 1; // -1 = welcome (no active), 0-4 = steps, 5+ = done

  const lines = HEADER_STEPS.map((name, i) => {
    if (i < headerActive)   return `  ${G}✓ ${name}${R}`;
    if (i === headerActive) return `  ${G}${B}● ${name}${R}`;
    return `  ${D}○ ${name}${R}`;
  });

  return new Text(`${G}${B}  NemoClaw Wizard${R}\n\n${lines.join("\n")}\n`, 0, 1);
}

function renderStep(tui, wizardStep, components, focusTarget, piTui) {
  tui.clear();
  tui.addChild(makeHeader(wizardStep, piTui));
  // Track the active SelectList for search (the first SelectList in the component list).
  clearSearchList();
  let foundList = null;
  for (const c of components) {
    tui.addChild(c);
    if (!foundList && c?.constructor?.name === "SelectList") foundList = c;
  }
  if (foundList) {
    // Append a search bar Text after the list components but before the hint
    const { Text } = piTui;
    const searchText = new Text("", 0, 0);
    tui.addChild(searchText);
    setSearchList(foundList, searchText);
  }
  if (focusTarget) tui.setFocus(focusTarget);
  tui.requestRender();
}

function makeHint(canGoBack, { Text }) {
  const back = canGoBack ? `  ${D}Esc back${R}` : "";
  return new Text(`${D}  ↵ confirm${R}${back}   ${D}Ctrl+C quit${R}`, 0, 0);
}

/** Spinner wrapper — stops cleanly on resolve. */
async function runWithLoader(tui, stepIdx, initialMsg, fn, piTui) {
  const { Loader } = piTui;
  const loader = new Loader(tui, (t) => `${G}${t}${R}`, (t) => t, initialMsg);
  renderStep(tui, stepIdx, [loader], null, piTui);
  try {
    return await fn((msg) => loader.setMessage(msg));
  } finally {
    loader.stop();
  }
}

/**
 * Stop TUI (restore terminal), run async fn (may emit console output),
 * then restart TUI with a clean full redraw.
 */
async function runHeavy(tui, fn) {
  tui.stop();
  try {
    return await fn();
  } finally {
    tui.previousLines = [];
    tui.start();
  }
}

// ── Step 0 — welcome (no back possible) ──────────────────────────

function stepWelcome(tui, piTui) {
  const { Text, Input } = piTui;
  return new Promise((resolve) => {
    const body = new Text(
      `${G}${B}  Welcome to NemoClaw Wizard${R}\n\n` +
        `  This wizard guides you through setting up a secure,\n` +
        `  always-on AI assistant inside an NVIDIA OpenShell sandbox.\n\n` +
        `${D}  Press ↵ to begin, or Ctrl+C to quit at any time.\n` +
        `  At each step, Esc goes back to the previous step.${R}\n`,
      0, 1,
    );
    const cont = new Input();
    cont.onSubmit = () => resolve();
    // ESC on welcome = no previous step, do nothing
    cont.onEscape = () => {};
    const hint = new Text(`${D}  ↵ begin   Ctrl+C quit${R}`, 0, 0);
    renderStep(tui, 0, [body, hint, cont], cont, piTui);
  });
}

// ── Step 1 — system checks ───────────────────────────────────────

async function stepPreflight(tui, piTui) {
  const { Text, Input } = piTui;

  const results = await runWithLoader(tui, 1, "Running system checks…", async () => {
    // Check gateway health first — used to reclassify port conflicts below
    const gwStatus   = osCap(["status"]);
    const gwInfo     = osCap(["gateway", "info", "-g", GATEWAY_NAME]);
    const activeInfo = osCap(["gateway", "info"]);
    const gatewayHealthy = getGatewayReuseState(gwStatus, gwInfo, activeInfo) === "healthy";

    const checks = [];

    const dockerOut = spawnSync("docker", ["info"], { stdio: "pipe", encoding: "utf-8" });
    checks.push({
      label: "Docker socket",
      ok: dockerOut.status === 0,
      detail: dockerOut.status !== 0 ? "daemon not running" : null,
    });

    const PORT_LABELS = { 8080: "OpenShell gateway", 18789: "NemoClaw dashboard" };
    for (const port of [8080, 18789]) {
      const portResult = await checkPortAvailable(port);
      if (portResult.ok) {
        checks.push({ label: `Port ${port}`, ok: true, detail: null });
      } else if (gatewayHealthy) {
        checks.push({ label: `Port ${port}`, ok: true, detail: `in use by ${PORT_LABELS[port]}` });
      } else {
        checks.push({ label: `Port ${port}`, ok: false, detail: portResult.reason });
      }
    }

    const mem = getMemoryInfo();
    const ramGiB = mem ? mem.totalRamMB / 1024 : 0;
    checks.push({
      label: "Memory",
      ok: ramGiB >= 8,
      detail: `${ramGiB.toFixed(1)} GiB${ramGiB < 8 ? " — 8 GB recommended" : ""}`,
    });

    let gpu = { available: false, totalMemoryMB: 0 };
    const gpuRaw = runCapture(
      "nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null",
      { ignoreError: true },
    );
    const gpuMb = parseInt((gpuRaw || "").trim().split("\n")[0], 10);
    if (Number.isFinite(gpuMb) && gpuMb > 0) {
      gpu = { available: true, totalMemoryMB: gpuMb };
    }

    return { checks, gpu, gatewayHealthy };
  }, piTui);

  const lines = results.checks.map((c) => {
    const detail = c.detail ? `  ${D}${c.detail}${R}` : "";
    return c.ok
      ? `  ${G}✓${R} ${c.label}${detail}`
      : `  ${RD}✗${R} ${c.label}  ${D}${c.detail}${R}`;
  });
  if (results.gatewayHealthy) lines.push(`  ${G}✓${R} Gateway  ${D}running${R}`);
  lines.push("");
  if (results.gpu.available) {
    lines.push(`  ${G}✓${R} GPU  ${D}${(results.gpu.totalMemoryMB / 1024).toFixed(1)} GB VRAM${R}`);
  } else {
    lines.push(`  ${D}○ GPU  not detected — CPU / cloud inference only${R}`);
  }
  if (results.checks.some((c) => !c.ok)) {
    lines.push(`\n  ${YW}⚠ Some checks failed. You may continue but issues could occur.${R}`);
  }

  const text = new Text(lines.join("\n"), 0, 1);
  return new Promise((resolve) => {
    const cont = new Input();
    cont.onSubmit = () => resolve({ gpu: results.gpu, gatewayHealthy: results.gatewayHealthy });
    cont.onEscape = () => resolve(BACK);
    renderStep(tui, 1, [text, makeHint(true, piTui), cont], cont, piTui);
  });
}

// ── Step 2 — gateway ─────────────────────────────────────────────

async function stepGateway(tui, state, piTui) {
  const { Text, Input } = piTui;

  const reuseState = state.gatewayHealthy
    ? "healthy"
    : await runWithLoader(tui, 2, "Checking gateway status…", async () => {
        const status     = osCap(["status"]);
        const gwInfo     = osCap(["gateway", "info", "-g", GATEWAY_NAME]);
        const activeInfo = osCap(["gateway", "info"]);
        return getGatewayReuseState(status, gwInfo, activeInfo);
      }, piTui);

  if (reuseState === "healthy") {
    return new Promise((resolve) => {
      const text = new Text(
        `  ${G}✓${R} Gateway already running — reusing existing instance.\n`,
        0, 1,
      );
      const cont = new Input();
      cont.onSubmit = () => resolve();
      cont.onEscape = () => resolve(BACK);
      renderStep(tui, 2, [text, makeHint(true, piTui), cont], cont, piTui);
    });
  }

  if (reuseState === "stale" || reuseState === "active-unnamed") {
    await runWithLoader(tui, 2, "Cleaning up previous session…", async () => {
      osRun(["forward", "stop", "18789"], { ignoreError: true });
      osRun(["gateway", "destroy", "-g", GATEWAY_NAME], { ignoreError: true });
    }, piTui);
  }

  return new Promise((resolve) => {
    const text = new Text(
      `  Starting OpenShell gateway…\n\n` +
        `${D}  Build output will appear below when you press ↵.${R}\n`,
      0, 1,
    );
    const cont = new Input();
    cont.onSubmit = async () => {
      await runHeavy(tui, async () => {
        console.log(`\n${G}${B}── Gateway Setup ${"─".repeat(40)}${R}`);
        osRun(["gateway", "start", "-g", GATEWAY_NAME]);
        console.log(`\n${G}${B}── Gateway Ready ─────────────────────────────────${R}\n`);
      });
      resolve();
    };
    cont.onEscape = () => resolve(BACK);
    const hint = new Text(
      `${D}  ↵ start gateway   Esc back   Ctrl+C quit${R}`,
      0, 0,
    );
    renderStep(tui, 2, [text, hint, cont], cont, piTui);
  });
}

// ── Step 3 — provider, model, credentials ────────────────────────

async function stepInference(tui, state, piTui) {
  const { SelectList, Text, Input } = piTui;
  const theme = makeSelectTheme();

  // Inner loop: ESC at model/endpoint goes back to provider; ESC at provider = BACK
  while (true) {
    // 3a. Provider
    const provider = await new Promise((resolve) => {
      const list = new SelectList(PROVIDERS, 8, theme);
      list.onSelect = (item) => resolve(item.value);
      list.onCancel  = () => resolve(BACK);
      const hint = new Text(
        `${D}  ↑↓ navigate   ↵ select   Esc back   Ctrl+C quit${R}`,
        0, 0,
      );
      renderStep(tui, 3, [list, hint], list, piTui);
    });
    if (provider === BACK) return BACK;

    state.provider = provider;
    const cfg = getProviderSelectionConfig(state.provider, null);
    state.credentialEnv = cfg?.credentialEnv ?? null;
    state.endpointUrl   = null;

    const isLocal        = provider === "ollama-local" || provider === "vllm-local";
    const needsCustomUrl = provider === "compatible-endpoint" || provider === "compatible-anthropic-endpoint";

    // 3b. Endpoint URL (must come before model fetch)
    if (needsCustomUrl) {
      const envUrl = (process.env.NEMOCLAW_ENDPOINT_URL || "").trim();
      const url = await new Promise((resolve) => {
        const envHint = envUrl ? `  ${D}Pre-filled from NEMOCLAW_ENDPOINT_URL${R}\n` : "";
        const label = new Text(
          `  ${B}Endpoint URL${R}  ${D}(https://…/v1)${R}\n${envHint}`,
          0, 1,
        );
        const input = new Input();
        if (envUrl) input.setValue(envUrl);
        input.onSubmit = (v) => resolve(v.trim());
        input.onEscape = () => resolve(BACK);
        renderStep(tui, 3, [label, makeHint(true, piTui), input], input, piTui);
      });
      if (url === BACK) continue; // restart at provider selection
      state.endpointUrl = url;
    }

    // 3c. Model — live API first, then curated list, then free-text
    const model = await (async () => {
      if (provider === "ollama-local") {
        let items = [];
        try {
          items = (getOllamaModelOptions(runCapture) || []).map((m) => ({ value: m, label: m }));
        } catch { /* offline */ }
        if (items.length > 0) {
          return new Promise((resolve) => {
            const list = new SelectList(items, 8, theme);
            list.onSelect = (item) => resolve(item.value);
            list.onCancel  = () => resolve(BACK);
            const hint = new Text(`${D}  ↑↓ navigate   ↵ select   Esc back${R}`, 0, 0);
            renderStep(tui, 3, [list, hint], list, piTui);
          });
        }
        return getDefaultOllamaModel(runCapture);
      }

      if (provider === "vllm-local") return cfg?.model ?? "vllm-local";

      const liveIds = await runWithLoader(
        tui, 3,
        `Fetching models from ${cfg?.providerLabel ?? provider}…`,
        () => fetchModels(provider, state.credentialEnv, state.endpointUrl),
        piTui,
      );

      let listItems, sourceNote;
      if (liveIds && liveIds.length > 0) {
        listItems  = [...liveIds.map((id) => ({ value: id, label: id })), { value: "__custom__", label: `${D}Custom model ID…${R}` }];
        sourceNote = `${D}  live from API · ↑↓ navigate   ↵ select   Esc back${R}`;
      } else {
        listItems  = PROVIDER_MODELS[provider] ?? null;
        sourceNote = `${D}  ↑↓ navigate   ↵ select   Esc back${R}`;
      }

      if (listItems) {
        const picked = await new Promise((resolve) => {
          const list = new SelectList(listItems, 10, theme);
          list.onSelect = (item) => resolve(item.value);
          list.onCancel  = () => resolve(BACK);
          renderStep(tui, 3, [list, new Text(sourceNote, 0, 0)], list, piTui);
        });
        if (picked === BACK) return BACK;
        if (picked !== "__custom__") return picked;
      }

      // Free-text fallback
      const defaultModel = cfg?.model ?? DEFAULT_CLOUD_MODEL;
      return new Promise((resolve) => {
        const label = new Text(`  ${B}Model ID${R}\n  ${D}Default: ${defaultModel}${R}\n`, 0, 1);
        const input = new Input();
        input.setValue(defaultModel);
        input.onSubmit = (v) => resolve(v.trim() || defaultModel);
        input.onEscape = () => resolve(BACK);
        renderStep(tui, 3, [label, makeHint(true, piTui), input], input, piTui);
      });
    })();

    if (model === BACK) continue; // restart at provider selection
    state.model = model;

    // 3d. API key — suspend TUI for masked prompt
    if (!isLocal && state.credentialEnv && !getCredential(state.credentialEnv)) {
      await runHeavy(tui, async () => {
        console.log(`\n${G}${B}── API Credentials ${"─".repeat(40)}${R}`);
        console.log(`  Provider: ${D}${cfg?.providerLabel ?? provider}${R}`);
        console.log(`  Key:      ${D}${state.credentialEnv}${R}\n`);
        try {
          const apiKey = await prompt(`  Enter API key: `, { secret: true });
          if (apiKey) saveCredential(state.credentialEnv, apiKey);
        } catch { /* Ctrl+C during prompt — wizard will exit via SIGINT */ }
        console.log("");
      });
    }

    break;
  }
}

// ── Step 4 — sandbox select or create ───────────────────────────

function listExistingSandboxes() {
  const raw = osCap(["sandbox", "list"]);
  if (!raw) return [];
  return raw
    .split("\n")
    .slice(1) // skip header
    .map((line) => {
      const cols = line.trim().split(/\s{2,}/);
      if (cols.length < 4) return null;
      const [name, , , phase] = cols;
      // strip ANSI color codes from phase
      return { name, phase: phase.replace(/\x1b\[[0-9;]*m/g, "") };
    })
    .filter(Boolean);
}

async function stepSandbox(tui, state, piTui) {
  const { SelectList, Text, Input } = piTui;
  const theme = makeSelectTheme();

  // Load existing sandboxes
  const existing = await runWithLoader(tui, 4, "Loading sandboxes…", async () => {
    return listExistingSandboxes();
  }, piTui);

  // Build selection list: existing sandboxes + "Create new…"
  const CREATE_NEW = "__create__";
  const sandboxItems = [
    ...existing.map((s) => ({
      value: s.name,
      label: s.name,
      description: s.phase,
    })),
    { value: CREATE_NEW, label: `${G}+ Create new sandbox…${R}` },
  ];

  // Pre-select previously chosen sandbox if navigating back
  const preselect = state.sandboxName
    ? sandboxItems.findIndex((i) => i.value === state.sandboxName)
    : sandboxItems.length - 1; // default to "Create new"

  const choice = await new Promise((resolve) => {
    const hint = new Text(
      `${D}  ↑↓ navigate   ↵ select   Esc back   Ctrl+C quit${R}`,
      0, 0,
    );
    const list = new SelectList(sandboxItems, 10, theme);
    if (preselect >= 0) list.selectedIndex = preselect;
    list.onSelect = (item) => resolve(item.value);
    list.onCancel  = () => resolve(BACK);
    renderStep(tui, 4, [list, hint], list, piTui);
  });

  if (choice === BACK) return BACK;

  if (choice !== CREATE_NEW) {
    // Reuse existing sandbox — skip build
    state.sandboxName = choice;
    return new Promise((resolve) => {
      const text = new Text(
        `  ${G}✓${R} Using existing sandbox ${B}${state.sandboxName}${R}\n`,
        0, 1,
      );
      const cont = new Input();
      cont.onSubmit = () => resolve();
      cont.onEscape = () => resolve(BACK);
      renderStep(tui, 4, [text, makeHint(true, piTui), cont], cont, piTui);
    });
  }

  // Create new — collect name
  const sandboxName = await new Promise((resolve) => {
    const label = new Text(
      `  ${B}Sandbox name${R}\n  ${D}lowercase letters, numbers, hyphens${R}\n`,
      0, 1,
    );
    const input = new Input();
    input.setValue(state.sandboxName && state.sandboxName !== choice ? state.sandboxName : "nemoclaw");
    input.onSubmit = (v) => {
      resolve((v.trim() || "nemoclaw").toLowerCase().replace(/[^a-z0-9-]/g, "-"));
    };
    input.onEscape = () => resolve(BACK);
    renderStep(tui, 4, [label, makeHint(true, piTui), input], input, piTui);
  });

  if (sandboxName === BACK) return BACK;
  state.sandboxName = sandboxName;

  await runHeavy(tui, async () => {
    console.log(`\n${G}${B}── Sandbox Build ${"─".repeat(42)}${R}`);
    await createSandbox(state.gpu, state.model, state.provider, null, state.sandboxName);
    console.log(`\n${G}${B}── Sandbox Ready ─────────────────────────────────${R}\n`);
  });

  return new Promise((resolve) => {
    const text = new Text(`  ${G}✓${R} Sandbox ${B}${state.sandboxName}${R} is ready.\n`, 0, 1);
    const cont = new Input();
    cont.onSubmit = () => resolve();
    cont.onEscape = () => resolve(BACK);
    renderStep(tui, 4, [text, makeHint(true, piTui), cont], cont, piTui);
  });
}

// ── Step 5 — policy presets (multi-select + per-preset mode) ─────

async function stepPolicies(tui, state, piTui) {
  const { SelectList, Text } = piTui;
  const theme = makeSelectTheme();

  const allPresets = policies.listPresets();
  if (allPresets.length === 0) {
    state.policies = [];
    return;
  }

  // On first visit, seed selections from presets already applied to this sandbox.
  // On revisit (navigating back), use whatever the user had selected.
  if (state.policies.length === 0 && state.sandboxName) {
    state.policies = policies.getAppliedPresets(state.sandboxName);
  }

  // Load non-preset policies once; cached in state so back-navigation doesn't re-fetch.
  if (state.customPolicies === null && state.sandboxName) {
    state.customPolicies = await runWithLoader(tui, 5, "Loading current policy…", async () => {
      return policies.getNonPresetPolicies(state.sandboxName);
    }, piTui);
  }
  if (state.customPolicies === null) state.customPolicies = [];

  // Build per-preset impact summary from raw YAML comments + structured rules.
  function presetImpact(name) {
    const raw = policies.loadPreset(name) || "";
    const hosts = [...new Set((raw.match(/host:\s*([^\s,}]+)/g) || [])
      .map((m) => m.replace(/^host:\s*/, "")))];
    const risks = [...new Set((raw.match(/# exfil_risk: (.+)/g) || [])
      .map((m) => m.replace(/^# exfil_risk: /, "").trim()))];
    const uniqRisks = [];
    const seen = new Set();
    for (const r of risks) {
      const key = r.slice(0, 60);
      if (!seen.has(key)) { seen.add(key); uniqRisks.push(r); }
    }
    // Collect write rules and deduplicate by method+host
    const writeRules = policies.getWriteRules(raw);
    const byHost = new Map();
    for (const { method, host } of writeRules) {
      if (!byHost.has(host)) byHost.set(host, new Set());
      byHost.get(host).add(method);
    }
    return { hosts, risks: uniqRisks, writesByHost: byHost };
  }

  // Only seed selections from names that have a matching YAML file.
  // Registry entries for deleted/renamed presets are silently dropped.
  const knownNames = new Set(allPresets.map((p) => p.name));
  let selected = new Set(state.policies.filter((n) => knownNames.has(n)));
  let phase = "select"; // "select" | "modes" | "confirm"

  while (true) {

    // ── Phase: preset selection ──────────────────────────────────────
    if (phase === "select") {
      const presetItems = allPresets
        .map((p) => ({
          value: p.name,
          label: `${selected.has(p.name) ? G + "●" + R : "○"} ${p.name}`,
          description: p.description,
        }))
        .sort((a, b) => {
          const asel = selected.has(a.value) ? 0 : 1;
          const bsel = selected.has(b.value) ? 0 : 1;
          return asel !== bsel ? asel - bsel : a.value.localeCompare(b.value);
        });
      const applyItem = { value: "__apply__", label: `${G}${B}→ Apply selection${R}` };

      const result = await new Promise((resolve) => {
        const allItems = [...presetItems, applyItem];
        const list = new SelectList(allItems, 10, theme);

        function toggleCurrent() {
          const item = list.filteredItems[list.selectedIndex];
          if (!item || item.value === "__apply__") { resolve("apply"); return; }
          if (selected.has(item.value)) { selected.delete(item.value); }
          else { selected.add(item.value); }
          for (const i of list.items) {
            if (i.value === "__apply__") continue;
            i.label = `${selected.has(i.value) ? G + "●" + R : "○"} ${i.value}`;
          }
          list.filteredItems = list.items;
          list.invalidate();
          tui.requestRender();
        }

        // Space → toggle; Enter → apply (proceed to next step).
        const { matchesKey: mk, isKeyRelease: ikr } = piTui;
        const removeEnterHook = tui.addInputListener((data) => {
          if (!ikr(data) && mk(data, "enter")) {
            removeEnterHook();
            resolve("apply");
            return { consume: true };
          }
        });

        list.onSelect = (item) => {
          if (item.value === "__apply__") { resolve("apply"); return; }
          toggleCurrent();
        };
        list.onCancel = () => { removeEnterHook(); resolve(BACK); };

        const hint = new Text(
          `${D}  ↑↓/j/k navigate   Space toggle   ↵ apply   Esc back   Ctrl+C quit${R}`,
          0, 0,
        );
        const components = [list, hint];
        if (state.customPolicies.length > 0) {
          components.push(new Text(
            `\n  ${D}Custom policies (read-only): ${state.customPolicies.join(", ")}\n` +
            `  Manage with: openshell policy set --policy <file> ${state.sandboxName}${R}`,
            0, 0,
          ));
        }
        renderStep(tui, 5, components, list, piTui);
      });

      if (result === BACK) return BACK;

      state.policies = [...selected];
      if (state.policies.length === 0) return; // nothing to confirm
      phase = "modes";
      continue;
    }

    // ── Phase: per-endpoint configuration ───────────────────────────
    if (phase === "modes") {
      // Build a flat row list: preset headers + their endpoints.
      const rows = [];
      for (const name of state.policies) {
        const raw = policies.loadPreset(name) || "";
        const endpoints = policies.getEndpoints(raw);
        rows.push({ type: "header", presetName: name });
        for (const ep of endpoints) {
          rows.push({ type: "endpoint", presetName: name, host: ep.host, hasWrites: ep.hasWrites });
        }
        // Seed defaults for any endpoint not yet configured.
        if (!state.endpointSettings[name]) state.endpointSettings[name] = {};
        for (const ep of endpoints) {
          if (!state.endpointSettings[name][ep.host]) {
            state.endpointSettings[name][ep.host] = { enabled: true, readOnly: false };
          }
        }
      }

      const focusable = rows.filter((r) => r.type === "endpoint");
      if (focusable.length === 0) { phase = "confirm"; continue; }

      let focusedIdx = 0;
      const { matchesKey: mk, isKeyRelease: ikr } = piTui;

      const modeResult = await new Promise((resolve) => {
        function render() {
          const focused = focusable[focusedIdx];
          const lines = [];
          for (const row of rows) {
            if (row.type === "header") {
              lines.push(`\n  ${B}${row.presetName}${R}`);
              continue;
            }
            const s = state.endpointSettings[row.presetName]?.[row.host] || { enabled: true, readOnly: false };
            const isFocused = row === focused;
            const cursor  = isFocused ? `${G}${B}▶${R}` : " ";
            const dot     = s.enabled ? `${G}●${R}` : `${D}○${R}`;
            const hostStr = s.enabled ? row.host : `${D}${row.host}${R}`;
            let modeStr = "";
            if (row.hasWrites && s.enabled) {
              const rTab  =  s.readOnly ? `${G}${B}[ read ]${R}` : `${D}[ read ]${R}`;
              const rwTab = !s.readOnly ? `${G}${B}[ rw   ]${R}` : `${D}[ rw   ]${R}`;
              modeStr = `  ${rTab}  ${rwTab}`;
            }
            lines.push(`  ${cursor} ${dot} ${hostStr.padEnd(42)}${modeStr}`);
          }
          const body = new Text(
            `  ${B}Configure endpoints for each preset:${R}\n` + lines.join("\n") + "\n",
            0, 1,
          );
          const hint = new Text(
            `${D}  ↑↓/j/k navigate   Space toggle endpoint   ←→ read/rw   ↵ continue   Esc back${R}`,
            0, 0,
          );
          renderStep(tui, 5, [body, hint], null, piTui);
        }

        render();

        const removeListener = tui.addInputListener((data) => {
          if (ikr(data)) return;
          if (mk(data, "up") || mk(data, "k")) {
            focusedIdx = Math.max(0, focusedIdx - 1);
            render();
            return { consume: true };
          }
          if (mk(data, "down") || mk(data, "j")) {
            focusedIdx = Math.min(focusable.length - 1, focusedIdx + 1);
            render();
            return { consume: true };
          }
          if (mk(data, "space") || mk(data, "tab")) {
            const row = focusable[focusedIdx];
            const s = state.endpointSettings[row.presetName]?.[row.host];
            if (s) { s.enabled = !s.enabled; render(); }
            return { consume: true };
          }
          if (mk(data, "left") || mk(data, "right")) {
            const row = focusable[focusedIdx];
            const s = state.endpointSettings[row.presetName]?.[row.host];
            if (s && row.hasWrites && s.enabled) { s.readOnly = !s.readOnly; render(); }
            return { consume: true };
          }
          if (mk(data, "enter")) {
            removeListener();
            resolve("continue");
            return { consume: true };
          }
          if (mk(data, "escape")) {
            removeListener();
            resolve(BACK);
            return { consume: true };
          }
        });
      });

      if (modeResult === BACK) { phase = "select"; continue; }
      phase = "confirm";
      continue;
    }

    // ── Phase: confirmation ──────────────────────────────────────────
    if (phase === "confirm") {
      const { SelectList: SL2, Text: T2 } = piTui;
      const theme2 = makeSelectTheme();
      const WRITE_RE = /^(POST|PUT|PATCH|DELETE)\b/i;

      let summaryLines = [`  ${B}Applying ${state.policies.length} preset${state.policies.length > 1 ? "s" : ""}:${R}\n`];
      for (const name of state.policies) {
        const { hosts, risks, writesByHost } = presetImpact(name);
        const epSettings = state.endpointSettings[name] || {};

        const included = hosts.filter((h) => epSettings[h]?.enabled !== false);
        const excluded = hosts.filter((h) => epSettings[h]?.enabled === false);

        summaryLines.push(`  ${G}●${R} ${B}${name}${R}  ${D}→ ${included.join(", ") || "(all excluded)"}${R}`);
        if (excluded.length > 0) {
          summaryLines.push(`    ${D}○ excluded: ${excluded.join(", ")}${R}`);
        }

        // Show risks: suppress write risks for hosts that are read-only or excluded.
        const rwHosts = new Set(included.filter((h) => !epSettings[h]?.readOnly));
        const hasActiveWrites = [...writesByHost.keys()].some((h) => rwHosts.has(h));
        const displayRisks = hasActiveWrites ? risks : risks.filter((r) => !WRITE_RE.test(r));
        for (const r of displayRisks) {
          summaryLines.push(`    ${WRITE_RE.test(r) ? RD : YW}⚠ ${r}${R}`);
        }

        // Show write targets only for enabled rw endpoints.
        for (const [host, methods] of writesByHost) {
          if (rwHosts.has(host)) {
            summaryLines.push(`    ${RD}${[...methods].join(" ")}${R} ${D}→ ${host}${R}`);
          }
        }
      }

      const confirmText = new T2(summaryLines.join("\n"), 0, 1);

      const confirmChoice = await new Promise((resolve) => {
        const items = [
          { value: "apply", label: `${G}${B}→ Apply${R}`,  description: "write policy to sandbox" },
          { value: "back",  label: `  Go back`,             description: "change endpoints or selection" },
        ];
        const list = new SL2(items, 4, theme2);
        list.onSelect = (item) => resolve(item.value);
        list.onCancel  = () => resolve("back");
        const hint = new T2(`${D}  ↑↓/j/k navigate   ↵ select   Esc back${R}`, 0, 0);
        renderStep(tui, 5, [confirmText, list, hint], list, piTui);
      });

      if (confirmChoice === "back") { phase = "modes"; continue; }

      await runHeavy(tui, async () => {
        console.log(`\n${G}${B}── Applying Policy Presets ${"─".repeat(32)}${R}`);
        for (const name of state.policies) {
          const epSettings = state.endpointSettings[name] || {};
          const allDisabled = Object.values(epSettings).length > 0 &&
            Object.values(epSettings).every((s) => !s.enabled);
          if (allDisabled) {
            console.log(`  Skipping: ${name} (all endpoints excluded)`);
            continue;
          }
          console.log(`  Applying: ${name}…`);
          const raw = policies.loadPreset(name);
          policies.applyPresetFiltered(state.sandboxName, raw, epSettings);
        }
        console.log(`\n${G}${B}── Policies Applied ──────────────────────────────${R}\n`);
      });

      return; // proceed to next wizard step
    }
  }
}

// ── Step 6 — done ─────────────────────────────────────────────────

async function stepDone(tui, state, piTui) {
  const { Text, SelectList } = piTui;
  const theme = makeSelectTheme();

  const presetLine = state.policies.length > 0
    ? `  Policies:   ${D}${state.policies.join(", ")}${R}\n`
    : `  Policies:   ${D}none${R}\n`;

  const custom = state.customPolicies || [];
  const customLines = custom.length > 0
    ? custom.map((p) => `              ${D}↳ ${p}   (not managed here)${R}`).join("\n") +
      `\n              ${D}openshell policy set --policy <file> ${state.sandboxName}${R}\n`
    : "";

  const summary = new Text(
    `  ${G}${B}✓ Setup complete!${R}\n\n` +
      `  Sandbox:    ${B}${state.sandboxName}${R}\n` +
      `  Provider:   ${D}${state.provider}${R}\n` +
      `  Model:      ${D}${state.model}${R}\n` +
      presetLine +
      customLines,
    0, 1,
  );

  const actions = [
    { value: "connect", label: `${G}${B}→ Enter sandbox${R}`,  description: `nemoclaw ${state.sandboxName} connect` },
    { value: "exit",    label: `  Exit wizard`,                description: "return to shell" },
  ];

  const choice = await new Promise((resolve) => {
    const list = new SelectList(actions, 4, theme);
    list.onSelect = (item) => resolve(item.value);
    list.onCancel  = () => resolve("exit");
    const hint = new Text(`${D}  ↑↓/j/k navigate   ↵ select   Ctrl+C quit${R}`, 0, 0);
    renderStep(tui, 6, [summary, list, hint], list, piTui);
  });

  if (choice === "connect") {
    await runHeavy(tui, async () => {
      const { spawnSync } = require("child_process");
      spawnSync(getOpenshellBin(), ["sandbox", "connect", state.sandboxName], {
        stdio: "inherit",
        env: process.env,
      });
    });
  }
}

// ── Main entry point ──────────────────────────────────────────────

async function wizard(_args) {
  const piTui = await import("@mariozechner/pi-tui");
  const { TUI, ProcessTerminal } = piTui;

  if (!process.stdout.isTTY) {
    console.error("  nemoclaw wizard requires an interactive terminal (TTY).");
    process.exit(1);
  }

  const terminal = new ProcessTerminal();
  const tui = new TUI(terminal);
  tui.start();

  // ── Keybindings: add j/k/space to all SelectLists ────────────────
  const {
    matchesKey, isKeyRelease,
    setEditorKeybindings, EditorKeybindingsManager,
    decodeKittyPrintable,
  } = piTui;

  setEditorKeybindings(new EditorKeybindingsManager({
    selectUp:      ["up",    "k"],
    selectDown:    ["down",  "j"],
    selectConfirm: ["enter", "space"],
    selectCancel:  ["escape"],           // ctrl+c handled by our own listener
  }));

  // ── Single exit path ──────────────────────────────────────────────
  let _exiting = false;
  let _quitTimer = null;

  function doExit() {
    if (_quitTimer) { clearTimeout(_quitTimer); _quitTimer = null; }
    try { tui.stop(); } catch { /* ignore */ }
    process.exit(0);
  }

  function quit() {
    if (_exiting) return;
    _exiting = true;
    // Disable Kitty keyboard protocol immediately so the terminal stops
    // encoding new keystrokes as Kitty sequences.
    try { process.stdout.write("\x1b[<u\x1b[>4;0m"); } catch { /* ignore */ }
    // Keep the TUI alive so the Ctrl+C key-RELEASE event (\x1b[99;5:3u
    // in Kitty mode) can travel back over SSH and be consumed by the
    // addInputListener below before we tear down stdin.
    // On release arrival the listener calls doExit() immediately.
    // 250 ms is a ceiling for high-latency SSH connections.
    _quitTimer = setTimeout(doExit, 250);
  }

  // Consume ALL key-release events before they reach any component.
  // In Kitty keyboard protocol (flag 2) every keypress produces a press AND
  // a release event. Without this guard the release event leaks into the next
  // step's focused component and fires onSubmit/onSelect prematurely, making
  // transitions feel instant/broken.
  // Exception: the Ctrl+C release is handled specially below (used to time doExit).
  tui.addInputListener((data) => {
    if (isKeyRelease(data)) {
      if (matchesKey(data, "ctrl+c") && _quitTimer) {
        doExit(); // Ctrl+C release → cancel wait timer, exit now
      }
      return { consume: true };
    }
    // Intercept Ctrl+C press — start quit sequence.
    if (matchesKey(data, "ctrl+c")) {
      quit();
      return { consume: true };
    }
  });

  // ── Search listener for all SelectList steps ─────────────────────
  // '/' activates search mode; typing filters the active list;
  // Backspace shrinks the query; Esc clears/exits search mode.
  // Key-release events are skipped so each keystroke fires once.
  tui.addInputListener((data) => {
    if (!_searchList || isKeyRelease(data)) return;

    function refreshSearchBar() {
      if (_searchText) {
        _searchText.setText(
          _searchActive
            ? `  ${D}/${R} ${_searchQuery}${G}▌${R}`
            : _searchQuery
            ? `  ${D}filter: ${_searchQuery}  (Esc to clear)${R}`
            : "",
        );
        tui.requestRender();
      }
    }

    if (_searchActive) {
      if (matchesKey(data, "escape")) {
        _searchActive = false;
        if (_searchQuery) {
          _searchQuery = "";
          applySearchFilter(_searchList, "");
        }
        refreshSearchBar();
        return { consume: true };
      }
      if (matchesKey(data, "backspace")) {
        _searchQuery = _searchQuery.slice(0, -1);
        applySearchFilter(_searchList, _searchQuery);
        refreshSearchBar();
        return { consume: true };
      }
      // Enter confirms selection — exit search mode but don't consume
      if (matchesKey(data, "enter") || matchesKey(data, "space")) {
        _searchActive = false;
        refreshSearchBar();
        return; // let the list handle the confirm
      }
      // Printable character — plain mode or Kitty mode
      const ch = data.length === 1 && data >= " " && data !== "\x7f"
        ? data
        : decodeKittyPrintable(data) ?? null;
      if (ch) {
        _searchQuery += ch;
        applySearchFilter(_searchList, _searchQuery);
        refreshSearchBar();
        return { consume: true };
      }
    } else {
      // '/' activates search
      const ch = data === "/" ? "/" : decodeKittyPrintable(data);
      if (ch === "/") {
        _searchActive = true;
        refreshSearchBar();
        return { consume: true };
      }
    }
  });

  // Cooked mode (runHeavy / API key prompt): Ctrl+C raises SIGINT normally.
  // SIGTERM is sent by `kill PID` — must also restore terminal.
  process.on("SIGINT", quit);
  process.on("SIGTERM", quit);
  process.once("exit", () => { try { tui.stop(); } catch { /* ignore */ } });

  const state = {
    gpu:            null,
    gatewayHealthy: false,
    provider:       null,
    model:          null,
    credentialEnv:  null,
    endpointUrl:    null,
    sandboxName:    null,
    policies:         [],
    endpointSettings: {}, // per-preset per-host { enabled, readOnly } — set in stepPolicies
    customPolicies: null, // non-preset network_policies already on the sandbox (null = not yet loaded)
  };

  // State machine — each step can return BACK to go to the previous step.
  const STEP_FNS = [
    () => stepWelcome(tui, piTui),
    () => stepPreflight(tui, piTui),
    () => stepGateway(tui, state, piTui),
    () => stepInference(tui, state, piTui),
    () => stepSandbox(tui, state, piTui),
    () => stepPolicies(tui, state, piTui),
    () => stepDone(tui, state, piTui),
  ];

  try {
    let step = 0;
    while (step < STEP_FNS.length) {
      const result = await STEP_FNS[step]();

      if (result === BACK) {
        step = Math.max(0, step - 1);
        // Reset preflight-derived state when going back past step 1
        if (step < 1) { state.gpu = null; state.gatewayHealthy = false; }
      } else {
        // Merge preflight result into state
        if (step === 1 && result && typeof result === "object") {
          state.gpu           = result.gpu;
          state.gatewayHealthy = result.gatewayHealthy;
        }
        step++;
      }
    }
  } finally {
    tui.stop();
  }
}

module.exports = { wizard };
