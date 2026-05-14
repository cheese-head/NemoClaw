# NemoClaw OpenShell Integration

```mermaid
flowchart LR
  user["User"] --> agent["Agent runtime"]
  agent --> adapter["NemoClaw agent adapter"]

  subgraph adapters["Current adapters"]
    openclaw["OpenClaw plugin"]
    hermes["Hermes plugin"]
  end

  subgraph plugin_tools["NemoClaw access tools"]
    list["list_resource_access_presets"]
    request["request_resource_access"]
    check["check_resource_access"]
  end

  adapter --> adapters
  adapters --> plugin_tools
  list --> profiles["OpenShell provider profiles"]
  profiles --> presets["Provider-backed access presets"]
  presets --> request

  request --> policy_local["policy.local HTTP API"]
  check --> policy_local

  subgraph sandbox["OpenShell sandbox"]
    policy_local
    proxy["Sandbox HTTP proxy"]
    policy_runtime["Sandbox policy runtime"]
  end

  policy_local --> proposals["OpenShell policy proposals"]
  proposals --> review["Operator review"]
  review --> approve["Approve or reject"]
  approve --> merge["Policy merge and reload"]
  merge --> policy_runtime
  policy_runtime --> check

  agent --> workload["Requested agent work"]
  workload --> proxy
  proxy --> policy_runtime
  policy_runtime --> external["Approved external resources"]
```

## Flow

1. The agent asks NemoClaw for allowed resource presets with `list_resource_access_presets`.
2. NemoClaw builds that list from OpenShell provider profiles, with built-in presets as fallback coverage.
3. The agent calls `request_resource_access` with a preset, access mode, reason, and optional wait timeout.
4. NemoClaw submits a least-privilege proposal to `policy.local`.
5. OpenShell surfaces the proposal for operator review.
6. After approval, OpenShell merges and reloads the sandbox policy.
7. The agent calls `check_resource_access`; NemoClaw reports `applied` only after OpenShell reports the policy reload is complete.

## Agent Tools

- `list_resource_access_presets`: discovers provider-backed preset ids.
- `request_resource_access`: submits a network access proposal through OpenShell.
- `check_resource_access`: polls an existing proposal until it is pending, denied, failed, or applied.

## Adapter Contract

Each agent adapter exposes the same tool names and response shape through the harness-native mechanism. OpenClaw uses its plugin API. Hermes uses its Python plugin API. Additional harnesses can implement the same contract without changing the OpenShell policy proposal flow.
