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
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


ACCESS_TERMINAL_STATUSES = {
    "applied",
    "denied",
    "denied_by_ceiling",
    "failed",
    "expired",
    "revoked",
}


def _b64_to_text(value):
    import base64

    return base64.b64decode(value.encode("ascii")).decode("utf-8")


def _access_control_env():
    control_url = os.environ.get("NEMOCLAW_CONTROL_URL")
    if not control_url:
        raise RuntimeError("NEMOCLAW_CONTROL_URL is required for NemoClaw access tools.")
    return {
        "control_url": control_url.rstrip("/"),
        "servername": os.environ.get("NEMOCLAW_CONTROL_SERVERNAME"),
        "ca": _b64_to_text(os.environ["NEMOCLAW_CONTROL_CA_PEM_B64"])
        if os.environ.get("NEMOCLAW_CONTROL_CA_PEM_B64")
        else None,
        "cert": _b64_to_text(os.environ["NEMOCLAW_CONTROL_CERT_PEM_B64"])
        if os.environ.get("NEMOCLAW_CONTROL_CERT_PEM_B64")
        else None,
        "key": _b64_to_text(os.environ["NEMOCLAW_CONTROL_KEY_PEM_B64"])
        if os.environ.get("NEMOCLAW_CONTROL_KEY_PEM_B64")
        else None,
        "attestation": os.environ.get("NEMOCLAW_PLUGIN_ATTESTATION"),
    }


def _normalize_resource(resource):
    from urllib.parse import urlparse

    normalized = str(resource or "").strip().lower()
    parsed = urlparse(normalized)
    host = parsed.hostname.lower() if parsed.hostname else normalized
    if host in {"github", "github.com", "api.github.com"}:
        return "github"
    return normalized


def _access_request_json(method, path, body=None):
    env = _access_control_env()
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if env["attestation"]:
        headers["X-NemoClaw-Plugin-Attestation"] = env["attestation"]
    if env["servername"]:
        headers["Host"] = env["servername"]

    with tempfile.TemporaryDirectory(prefix="nemoclaw-hermes-mtls-") as tmp:
        ca_path = os.path.join(tmp, "ca.pem")
        cert_path = os.path.join(tmp, "client.crt")
        key_path = os.path.join(tmp, "client.key")
        if env["ca"]:
            with open(ca_path, "w", encoding="utf-8") as f:
                f.write(env["ca"])
        if env["cert"]:
            with open(cert_path, "w", encoding="utf-8") as f:
                f.write(env["cert"])
        if env["key"]:
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(env["key"])

        context = ssl.create_default_context(cafile=ca_path if env["ca"] else None)
        if env["servername"]:
            # Hermes/Python does not expose a clean way to set SNI separately
            # from the URL host while still using urllib proxy handling. The
            # control plane is authenticated by the private CA and client mTLS;
            # the HTTP Host header carries the stable control-plane name.
            context.check_hostname = False
        if env["cert"] and env["key"]:
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        request = urllib.request.Request(
            f"{env['control_url']}{path}",
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            with opener.open(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"NemoClaw control {method} {path} failed with HTTP {err.code}: {raw}"
            ) from err
    return json.loads(raw) if raw else {}


def _create_access_request_body(tool_input):
    tool_input = tool_input or {}
    resource = _normalize_resource(tool_input.get("resource", ""))
    return {
        "version": "nemoclaw.access.v1",
        **({"task_id": tool_input.get("task_id")} if tool_input.get("task_id") else {}),
        "user_intent": tool_input.get("user_intent", ""),
        "llm_proposal": {
            "resource_type": "network",
            "preset": resource,
            "access": "read_write" if tool_input.get("access") == "read_write" else "read",
            "duration": "persistent" if tool_input.get("duration") == "persistent" else "session",
            "reason": tool_input.get("reason", ""),
        },
    }


def _handle_list_resource_access_presets(tool_input=None, context=None, **_kwargs):
    """List currently accepted NemoClaw resource access presets."""
    return json.dumps(_access_request_json("GET", "/v1/access-presets"), indent=2)


def _handle_request_resource_access(tool_input=None, context=None, **_kwargs):
    """Submit a NemoClaw resource access request."""
    response = _access_request_json(
        "POST",
        "/v1/access-requests",
        _create_access_request_body(tool_input or {}),
    )
    return json.dumps(response, indent=2)


def _handle_check_resource_access(tool_input=None, context=None, **_kwargs):
    """Check a NemoClaw access request."""
    request_id = (tool_input or {}).get("request_id", "")
    if not request_id:
        return json.dumps({"request_id": "", "status": "failed", "message": "Missing request_id."})
    response = _access_request_json("GET", f"/v1/access-requests/{request_id}")
    return json.dumps(response, indent=2)


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
                    content = f.read()
                if yaml:
                    return yaml.safe_load(content)
                return _load_hermes_config_without_yaml(content)
            except Exception:
                continue
    return None


def _load_hermes_config_without_yaml(content):
    """Best-effort parser for the tiny config subset used in status output."""
    config = {}
    current_section = None
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")) and line.endswith(":"):
            current_section = line[:-1].strip()
            config.setdefault(current_section, {})
            continue
        if current_section and ":" in line:
            key, value = line.strip().split(":", 1)
            config[current_section][key.strip()] = value.strip().strip("\"'")
    return config


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
        name="list_resource_access_presets",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "list_resource_access_presets",
                "description": (
                    "List NemoClaw resource-access preset ids currently accepted "
                    "for access requests. Call this before request_resource_access "
                    "when the needed preset is unclear."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        handler=_handle_list_resource_access_presets,
        description="List NemoClaw access presets",
    )

    ctx.register_tool(
        name="request_resource_access",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "request_resource_access",
                "description": (
                    "Request least-privilege external resource access through "
                    "NemoClaw. The resource field must be a NemoClaw preset id, "
                    "not a hostname. Call list_resource_access_presets first if "
                    "you are unsure which preset to request."
                ),
                "parameters": {
                    "type": "object",
                    "required": ["user_intent", "resource", "reason"],
                    "properties": {
                        "user_intent": {"type": "string"},
                        "resource": {
                            "type": "string",
                            "description": "NemoClaw preset id to request.",
                        },
                        "access": {
                            "type": "string",
                            "enum": ["read", "read_write"],
                            "default": "read",
                        },
                        "duration": {
                            "type": "string",
                            "enum": ["session", "persistent"],
                            "default": "session",
                        },
                        "reason": {"type": "string"},
                        "task_id": {"type": "string"},
                    },
                },
            },
        },
        handler=_handle_request_resource_access,
        description="Request NemoClaw resource access",
    )

    ctx.register_tool(
        name="check_resource_access",
        toolset="nemoclaw",
        schema={
            "type": "function",
            "function": {
                "name": "check_resource_access",
                "description": "Check a NemoClaw access request status.",
                "parameters": {
                    "type": "object",
                    "required": ["request_id"],
                    "properties": {
                        "request_id": {"type": "string"},
                    },
                },
            },
        },
        handler=_handle_check_resource_access,
        description="Check NemoClaw resource access request",
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
            "  \u2502  Tools:     status, info, reload_skills, access      \u2502\n"
            "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n"
        )
        try:
            ctx.inject_message(banner, role="system")
        except Exception:
            print(banner)

    ctx.register_hook("on_session_start", _on_session_start)
