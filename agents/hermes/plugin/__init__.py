# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
NemoClaw plugin for Hermes Agent.

Provides sandbox status tools, skill hot-reload, and a startup banner when
Hermes runs inside an OpenShell sandbox managed by NemoClaw.

Skill hot-reload: Hermes caches its skill slash-command registry in a
module-global dict on first scan. New skills dropped on disk are invisible
until the cache is cleared. This plugin provides a nemoclaw_reload_skills
tool that clears the cache and re-scans, letting the agent pick up new
skills without a gateway restart. The on_session_start hook also refreshes
skills automatically at session boundaries.
"""

import json
import os
import socket
import subprocess
import time
from urllib.parse import quote, urlparse
import yaml

READ_METHODS = ["GET", "HEAD"]
READ_WRITE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
DEFAULT_ACCESS_WAIT_MS = 90000
MAX_ACCESS_WAIT_MS = 300000
TERMINAL_ACCESS_STATUSES = {"applied", "denied", "failed"}
PROVIDER_PROFILE_CACHE_SECONDS = 30
_provider_preset_cache = {"loaded_at": 0.0, "presets": None}

HERMES_BINARIES = [
    {"path": "/usr/local/bin/hermes"},
    {"path": "/opt/hermes/.venv/bin/python"},
    {"path": "/usr/bin/python3*"},
    {"path": "/usr/local/bin/python3*"},
]

FALLBACK_PRESETS = [
    {
        "name": "github",
        "description": "GitHub.com and GitHub API access",
        "provider_profile": "github",
        "rule": {
            "name": "github",
            "endpoints": [
                {"host": "github.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
                {"host": "api.github.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
            ],
            "binaries": HERMES_BINARIES + [{"path": "/usr/bin/git"}, {"path": "/usr/bin/curl"}],
        },
    },
    {
        "name": "outlook",
        "description": "Microsoft Outlook and Graph API access",
        "provider_profile": "outlook",
        "rule": {
            "name": "outlook_graph",
            "endpoints": [
                {"host": "graph.microsoft.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
                {"host": "login.microsoftonline.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
                {"host": "outlook.office365.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
                {"host": "outlook.office.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
            ],
            "binaries": HERMES_BINARIES,
        },
    },
    {
        "name": "pypi",
        "description": "Python Package Index (PyPI) access",
        "rule": {
            "name": "pypi",
            "endpoints": [
                {"host": "pypi.org", "port": 443, "protocol": "rest", "enforcement": "enforce"},
                {"host": "files.pythonhosted.org", "port": 443, "protocol": "rest", "enforcement": "enforce"},
            ],
            "binaries": HERMES_BINARIES + [{"path": "/usr/bin/pip*"}, {"path": "/usr/local/bin/pip*"}],
        },
    },
    {
        "name": "npm",
        "description": "npm and Yarn registry access",
        "rule": {
            "name": "npm_yarn",
            "endpoints": [
                {"host": "registry.npmjs.org", "port": 443, "protocol": "rest", "enforcement": "enforce"},
                {"host": "registry.yarnpkg.com", "port": 443, "protocol": "rest", "enforcement": "enforce"},
            ],
            "binaries": HERMES_BINARIES + [{"path": "/usr/local/bin/node*"}, {"path": "/usr/bin/node*"}],
        },
    },
    {
        "name": "brave",
        "description": "Brave Search API access",
        "rule": {
            "name": "brave",
            "endpoints": [
                {"host": "api.search.brave.com", "port": 443, "protocol": "rest", "enforcement": "enforce"}
            ],
            "binaries": HERMES_BINARIES + [{"path": "/usr/bin/curl"}],
        },
    },
    {
        "name": "local-inference",
        "description": "Local inference access via host gateway",
        "rule": {
            "name": "local_inference",
            "endpoints": [
                {"host": "host.openshell.internal", "port": 11434, "protocol": "rest", "enforcement": "enforce"},
                {"host": "host.openshell.internal", "port": 11435, "protocol": "rest", "enforcement": "enforce"},
                {"host": "host.openshell.internal", "port": 8000, "protocol": "rest", "enforcement": "enforce"},
            ],
            "binaries": HERMES_BINARIES + [{"path": "/usr/bin/curl"}],
        },
    },
]


def _normalize_preset_name(resource):
    normalized = str(resource or "").strip().lower()
    if "://" in normalized:
        try:
            normalized = urlparse(normalized).hostname or normalized
        except Exception:
            pass
    if normalized in {"github.com", "api.github.com"}:
        return "github"
    return normalized


def _rules_for_access(access):
    methods = READ_WRITE_METHODS if access == "read_write" else READ_METHODS
    return [{"allow": {"method": method, "path": "/**"}} for method in methods]


def _parse_provider_profiles_json(raw):
    try:
        parsed = json.loads(raw or "")
    except Exception:
        return []
    candidates = parsed if isinstance(parsed, list) else parsed.get("profiles", []) if isinstance(parsed, dict) else []
    return [p for p in candidates if isinstance(p, dict) and isinstance(p.get("id"), str)]


def _read_provider_profiles():
    raw = os.environ.get("NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON")
    if raw:
        return _parse_provider_profiles_json(raw)
    try:
        result = subprocess.run(
            [os.environ.get("NEMOCLAW_OPENSHELL_BIN", "openshell"), "provider", "list-profiles", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return _parse_provider_profiles_json(result.stdout)
    except Exception:
        pass
    return []


def _provider_profile_to_preset(profile):
    endpoints = []
    for endpoint in profile.get("endpoints", []):
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("host"), str):
            continue
        try:
            port = int(endpoint.get("port"))
        except Exception:
            continue
        if port <= 0:
            continue
        clean = {"host": endpoint["host"], "port": port}
        for key in [
            "protocol",
            "tls",
            "access",
            "enforcement",
            "rules",
            "allowed_ips",
            "ports",
            "deny_rules",
            "allow_encoded_slash",
            "websocket_credential_rewrite",
            "request_body_credential_rewrite",
            "persisted_queries",
            "graphql_persisted_queries",
            "graphql_max_body_bytes",
            "path",
        ]:
            value = endpoint.get(key)
            if value not in (None, "", []):
                clean[key] = value
        endpoints.append(clean)
    if not endpoints:
        return None

    binaries = []
    for binary in profile.get("binaries", []):
        path = binary if isinstance(binary, str) else binary.get("path") if isinstance(binary, dict) else None
        if isinstance(path, str) and path:
            binaries.append({"path": path})
    if not binaries:
        binaries = list(HERMES_BINARIES)
    return {
        "name": profile["id"],
        "description": profile.get("description") or profile.get("display_name") or f"{profile['id']} provider profile",
        "provider_profile": profile["id"],
        "rule": {
            "name": profile["id"].replace("-", "_"),
            "endpoints": endpoints,
            "binaries": binaries,
        },
    }


def _provider_presets():
    now = time.time()
    cached = _provider_preset_cache.get("presets")
    if cached is not None and now - _provider_preset_cache.get("loaded_at", 0) < PROVIDER_PROFILE_CACHE_SECONDS:
        return cached
    presets = [p for p in (_provider_profile_to_preset(profile) for profile in _read_provider_profiles()) if p]
    _provider_preset_cache["loaded_at"] = now
    _provider_preset_cache["presets"] = presets
    return presets


def _all_presets():
    by_name = {preset["name"]: dict(preset) for preset in FALLBACK_PRESETS}
    for preset in _provider_presets():
        existing = by_name.get(preset["name"])
        if existing:
            existing["provider_profile"] = preset.get("provider_profile")
        else:
            by_name[preset["name"]] = preset
    return [by_name[name] for name in sorted(by_name)]


def _rule_for_access_request(params):
    preset_name = _normalize_preset_name(params.get("resource"))
    preset = next((p for p in _all_presets() if p["name"] == preset_name), None)
    if not preset:
        raise ValueError(f"Unknown access preset '{params.get('resource')}'.")
    access = "read_write" if params.get("access") == "read_write" else "read"
    rule = json.loads(json.dumps(preset["rule"]))
    for endpoint in rule.get("endpoints", []):
        if endpoint.get("access") == "full" or endpoint.get("tls") == "skip":
            continue
        endpoint.pop("access", None)
        endpoint.setdefault("rules", _rules_for_access(access))
    return rule


def _proposal_body(params):
    rule = _rule_for_access_request(params)
    intent = " ".join(filter(None, [str(params.get("user_intent") or ""), str(params.get("reason") or "")]))
    return {"intent_summary": intent, "operations": [{"addRule": {"ruleName": rule["name"], "rule": rule}}]}


def _policy_local_base():
    return urlparse(os.environ.get("OPENSHELL_POLICY_LOCAL_URL", "http://policy.local"))


def _http_proxy():
    raw = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not raw:
        return None
    parsed = urlparse(raw)
    return parsed if parsed.scheme == "http" and parsed.hostname else None


def _decode_chunked(body):
    output = b""
    rest = body
    while True:
        marker = rest.find(b"\r\n")
        if marker < 0:
            return body
        size_text = rest[:marker].split(b";", 1)[0]
        try:
            size = int(size_text, 16)
        except Exception:
            return body
        rest = rest[marker + 2 :]
        if size == 0:
            return output
        output += rest[:size]
        rest = rest[size + 2 :]


def _policy_local_json(method, path, payload=None, timeout=310):
    base = _policy_local_base()
    if base.scheme != "http":
        raise RuntimeError("OpenShell policy.local URL must use HTTP inside the sandbox.")
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    proxy = _http_proxy() if base.hostname == "policy.local" else None
    host = proxy.hostname if proxy else base.hostname
    port = proxy.port if proxy and proxy.port else 80 if proxy else base.port or 80
    target = f"http://policy.local:80{(base.path or '').rstrip('/')}{path}" if proxy else f"{(base.path or '').rstrip('/')}{path}"
    headers = [
        f"{method} {target} HTTP/1.1",
        f"Host: {base.netloc or base.hostname}",
        "Accept: application/json",
        "Connection: close",
    ]
    if payload is not None:
        headers += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    request = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
    header_end = response.find(b"\r\n\r\n")
    if header_end < 0:
        raise RuntimeError(f"OpenShell policy.local {method} {path} returned malformed HTTP")
    header = response[:header_end].decode("iso-8859-1")
    raw_body = response[header_end + 4 :]
    status_line = header.splitlines()[0] if header else ""
    try:
        status = int(status_line.split()[1])
    except Exception:
        status = 0
    if "transfer-encoding: chunked" in header.lower():
        raw_body = _decode_chunked(raw_body)
    text = raw_body.decode("utf-8")
    if status < 200 or status >= 300:
        raise RuntimeError(f"OpenShell policy.local {method} {path} failed with HTTP {status}: {text}")
    return json.loads(text or "{}")


def _map_chunk_status(status, policy_reloaded):
    if status == "approved":
        return "applied" if policy_reloaded is True else "pending_approval"
    if status == "rejected":
        return "denied"
    if status == "pending":
        return "pending_approval"
    return "failed"


def _create_access_request(params):
    parsed = _policy_local_json("POST", "/v1/proposals", _proposal_body(params))
    accepted = parsed.get("accepted_chunk_ids") if isinstance(parsed.get("accepted_chunk_ids"), list) else []
    request_id = next((item for item in accepted if isinstance(item, str) and item), "")
    if not request_id:
        return {
            "request_id": "",
            "status": "failed",
            "message": f"OpenShell rejected the proposal: {json.dumps(parsed.get('rejection_reasons', []))}",
        }
    return {
        "request_id": request_id,
        "status": "pending_approval",
        "message": "Proposal submitted to OpenShell; waiting for operator approval.",
    }


def _get_access_request(request_id, wait_timeout_ms=0):
    suffix = f"/wait?timeout={max(1, min(300, int((wait_timeout_ms + 999) / 1000)))}" if wait_timeout_ms > 0 else ""
    parsed = _policy_local_json("GET", f"/v1/proposals/{quote(request_id)}{suffix}", timeout=max(310, int(wait_timeout_ms / 1000) + 10))
    request_id = parsed.get("chunk_id") if isinstance(parsed.get("chunk_id"), str) else request_id
    return {
        "request_id": request_id,
        "status": _map_chunk_status(parsed.get("status"), parsed.get("policy_reloaded")),
        "message": parsed.get("rejection_reason") or parsed.get("validation_result"),
        "canonical_request": parsed,
    }


def _clamp_wait_timeout(value, fallback):
    try:
        timeout = int(value)
    except Exception:
        timeout = fallback
    if timeout <= 0:
        return 0
    return min(timeout, MAX_ACCESS_WAIT_MS)


def _tool_result(response):
    result = {
        "request_id": response.get("request_id", ""),
        "status": response.get("status", "failed"),
        "message": response.get("message")
        or (
            "OpenShell returned a terminal access status."
            if response.get("status") in TERMINAL_ACCESS_STATUSES
            else "Access request is still pending; call openshell_network_access with action=check and this request_id to continue polling."
        ),
    }
    if response.get("canonical_request"):
        result["canonical_request"] = response["canonical_request"]
    return result


def _handle_list_access_presets(tool_input=None, context=None, **_kwargs):
    return json.dumps(
        {
            "presets": [
                {
                    "name": preset["name"],
                    "description": preset["description"],
                    **({"provider_profile": preset["provider_profile"]} if preset.get("provider_profile") else {}),
                }
                for preset in _all_presets()
            ]
        }
    )


def _missing_string_fields(params, fields):
    return [
        field
        for field in fields
        if not isinstance(params.get(field), str) or not params.get(field).strip()
    ]


def _handle_create_network_access_request(tool_input=None, context=None, **_kwargs):
    params = tool_input if isinstance(tool_input, dict) else {}
    response = _create_access_request(params)
    timeout = _clamp_wait_timeout(params.get("wait_timeout_ms"), DEFAULT_ACCESS_WAIT_MS)
    if response.get("status") not in TERMINAL_ACCESS_STATUSES and timeout > 0 and response.get("request_id"):
        response = _get_access_request(response["request_id"], timeout)
    return json.dumps(_tool_result(response))


def _handle_check_network_access(tool_input=None, context=None, **_kwargs):
    params = tool_input if isinstance(tool_input, dict) else {}
    request_id = params.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return json.dumps({"request_id": "", "status": "failed", "message": "Missing request_id."})
    timeout = _clamp_wait_timeout(params.get("wait_timeout_ms"), 0)
    return json.dumps(_tool_result(_get_access_request(request_id, timeout)))


def _handle_network_access(tool_input=None, context=None, **_kwargs):
    params = tool_input if isinstance(tool_input, dict) else {}
    action = params.get("action")
    action = action.strip().lower() if isinstance(action, str) else ""
    if action == "list_presets":
        return _handle_list_access_presets(params, context, **_kwargs)
    if action == "check":
        request_id = params.get("request_id")
        if not isinstance(request_id, str) or not request_id.strip():
            return json.dumps(
                {
                    "request_id": "",
                    "status": "failed",
                    "message": "For action=check, provide request_id.",
                }
            )
        return _handle_check_network_access(params, context, **_kwargs)
    if action == "request":
        missing = _missing_string_fields(params, ["resource", "user_intent", "reason"])
        if missing:
            return json.dumps(
                {
                    "status": "failed",
                    "message": f"For action=request, provide required field(s): {', '.join(missing)}.",
                }
            )
        return _handle_create_network_access_request(params, context, **_kwargs)
    return json.dumps(
        {
            "status": "failed",
            "message": "Unknown action. Use one of: list_presets, check, request.",
        }
    )


def _load_nemoclaw_config():
    """Load NemoClaw onboard config from ~/.nemoclaw/config.json."""
    config_path = os.path.expanduser("~/.nemoclaw/config.json")
    if not os.path.exists(config_path):
        return None
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception:
        return None


def _load_hermes_config():
    """Load Hermes config.yaml from the sandbox."""
    for path in [
        os.path.expanduser("~/.hermes/config.yaml"),
        "/sandbox/.hermes/config.yaml",
    ]:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return yaml.safe_load(f)
            except Exception:
                continue
    return None


def _get_sandbox_info():
    """Gather sandbox status information."""
    hermes_cfg = _load_hermes_config()
    nemoclaw_cfg = _load_nemoclaw_config()

    model = "unknown"
    provider = "custom"
    base_url = "unknown"

    if hermes_cfg:
        model_cfg = hermes_cfg.get("model", {})
        model = model_cfg.get("default", "unknown")
        provider = model_cfg.get("provider", "custom")
        base_url = model_cfg.get("base_url", "unknown")

    if nemoclaw_cfg:
        model = nemoclaw_cfg.get("model", model)
        provider = nemoclaw_cfg.get("provider", provider)

    # Check gateway health
    gateway_ok = False
    try:
        result = subprocess.run(
            ["curl", "-sf", "http://localhost:8642/health"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            gateway_ok = True
    except Exception:
        pass

    return {
        "agent": "hermes",
        "model": model,
        "provider": provider,
        "base_url": base_url,
        "gateway": "running" if gateway_ok else "stopped",
        "port": 8642,
    }


def _handle_status(tool_input=None, context=None, **_kwargs):
    """Handle the nemoclaw_status tool call."""
    info = _get_sandbox_info()
    lines = [
        "NemoClaw Sandbox Status (Hermes)",
        "\u2500" * 40,
        f"  Agent:    Hermes Agent",
        f"  Gateway:  {info['gateway']}",
        f"  Model:    {info['model']}",
        f"  Provider: {info['provider']}",
        f"  Endpoint: {info['base_url']}",
        f"  API:      http://localhost:{info['port']}/v1",
    ]
    return "\n".join(lines)


def _handle_info(tool_input=None, context=None, **_kwargs):
    """Handle the nemoclaw_info tool call — returns structured JSON."""
    return json.dumps(_get_sandbox_info(), indent=2)


def _reload_skills():
    """Clear the Hermes skill slash-command cache and re-scan skill directories.

    Hermes's ``agent.skill_commands`` module caches discovered skills in a
    module-global dict (``_skill_commands``).  ``get_skill_commands()`` only
    scans on first call, so skills installed after gateway startup are
    invisible.  We clear the dict and call ``scan_skill_commands()`` to force
    a fresh scan.

    Returns the dict of discovered skills, or None on failure.
    """
    try:
        import agent.skill_commands as sc

        sc._skill_commands.clear()
        return sc.scan_skill_commands()
    except ImportError:
        return None
    except Exception:
        return None


def _handle_reload_skills(tool_input=None, context=None, **_kwargs):
    """Handle the nemoclaw_reload_skills tool call."""
    commands = _reload_skills()
    if commands is None:
        return (
            "Failed to reload skills. The agent.skill_commands module may "
            "not be available in this Hermes version."
        )

    if not commands:
        return "Skill reload complete. No skills found in skill directories."

    names = sorted(commands.keys())
    lines = [f"Skill reload complete. {len(names)} skill(s) discovered:", ""]
    for name in names:
        info = commands[name]
        desc = info.get("description", "no description")
        lines.append(f"  {name}: {desc}")
    return "\n".join(lines)


def register(ctx):
    """Register NemoClaw tools and hooks with Hermes."""

    # Register status tool
    ctx.register_tool(
        name="nemoclaw_status",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "nemoclaw_status",
                "description": (
                    "Show NemoClaw sandbox status: agent type, gateway health, "
                    "model, provider, and inference endpoint."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        handler=_handle_status,
        description="NemoClaw sandbox status",
    )

    # Register info tool (structured JSON output)
    ctx.register_tool(
        name="nemoclaw_info",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "nemoclaw_info",
                "description": "Get NemoClaw sandbox info as structured JSON.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        handler=_handle_info,
        description="NemoClaw sandbox info (JSON)",
    )

    # Register skill reload tool
    ctx.register_tool(
        name="nemoclaw_reload_skills",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "nemoclaw_reload_skills",
                "description": (
                    "Reload and re-discover skills from the skill directories. "
                    "Call this after new skills have been installed to make them "
                    "available as slash commands without restarting the gateway."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        handler=_handle_reload_skills,
        description="Reload skills from disk without gateway restart",
    )

    ctx.register_tool(
        name="openshell_network_access",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "openshell_network_access",
                "description": (
                    "List, check, or request OpenShell network-only access for this sandbox. "
                    "Use this for unauthenticated network/resource reachability."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string", "enum": ["list_presets", "check", "request"]},
                        "user_intent": {"type": "string"},
                        "resource": {"type": "string"},
                        "access": {"type": "string", "enum": ["read", "read_write"], "default": "read"},
                        "reason": {"type": "string"},
                        "duration": {"type": "string", "enum": ["session", "persistent"], "default": "session"},
                        "request_id": {"type": "string"},
                        "task_id": {"type": "string"},
                        "wait_timeout_ms": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": MAX_ACCESS_WAIT_MS,
                            "default": DEFAULT_ACCESS_WAIT_MS,
                        },
                    },
                },
            },
        },
        handler=_handle_network_access,
        description="OpenShell network access",
    )

    # Startup banner on session start
    def _on_session_start(**kwargs):
        # Refresh skill cache so skills installed since last session are
        # immediately available as slash commands.
        _reload_skills()

        info = _get_sandbox_info()
        banner = (
            "\n"
            "  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n"
            "  \u2502  NemoClaw registered (Hermes)                       \u2502\n"
            "  \u2502                                                     \u2502\n"
            f"  \u2502  Model:     {info['model']:<40}\u2502\n"
            f"  \u2502  Provider:  {info['provider']:<40}\u2502\n"
            f"  \u2502  Gateway:   {info['gateway']:<40}\u2502\n"
            "  \u2502  Tools:     status/info/reload + resource access    \u2502\n"
            "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n"
        )
        try:
            ctx.inject_message(banner, role="system")
        except Exception:
            print(banner)

    ctx.register_hook("on_session_start", _on_session_start)
