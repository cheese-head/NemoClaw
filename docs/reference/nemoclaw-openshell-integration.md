# NemoClaw Provider and Resource Access Flow

NemoClaw gives OpenClaw agents a provider-first way to get account-backed access
to external services. The important distinction is:

- **Provider access** attaches a host-managed credential and the matching
  provider policy to the sandbox.
- **Network access** only opens a resource path; it does not attach credentials.

Agents should prefer provider access whenever a task needs an account, token,
OAuth identity, API key, write operation, or service-specific CLI.

```text
                         Operator approval
                                  |
                                  v
        +-------------------------+-------------------------+
        |                     OpenShell                     |
        |                                                   |
        |  +-------------+   +-------------+   +----------+ |
        |  | Provider    |   | Policy      |   | L7 proxy | |
        |  | store       +-->| engine      +-->|          | |
        |  | credentials |   | rules       |   | egress   | |
        |  | config      |   | reloads     |   | rewrite  | |
        |  +-------------+   +-------------+   +----+-----+ |
        +---------------------------------------------|-----+
                                                      |
                                                      v
                                           External services
                                  GitHub, GitLab, APIs, registries

        +---------------------------------------------------+
        |                 OpenShell sandbox                 |
        |                                                   |
        |  +----------------+      +----------------------+ |
        |  | OpenClaw agent |<---->| NemoClaw plugin      | |
        |  |                |      |                      | |
        |  | plans task     |      | provider access     | |
        |  | chooses tool   |      | network access      | |
        |  | runs CLI/curl  |      +----------------------+ |
        |  +-------+--------+                               |
        |          |                                        |
        |          v                                        |
        |  +---------------------------------------------+  |
        |  | Installed tools                             |  |
        |  | gh, glab, claude, codex, opencode, copilot |  |
        |  | curl, git, node, python                     |  |
        |  +-------+-------------------------------------+  |
        |          |                                        |
        |          | HTTP_PROXY / HTTPS_PROXY               |
        |          v                                        |
        |  +---------------------------------------------+  |
        |  | Credential placeholders                     |  |
        |  | GITHUB_TOKEN=openshell:resolve:env:...      |  |
        |  | Proxy resolves placeholders at egress.      |  |
        |  +---------------------------------------------+  |
        +---------------------------------------------------+
```

## Access Types

### Provider Access

Gives the agent a credential placeholder, matching provider policy, and provider
endpoints. Use it for authenticated API calls, account-backed CLIs, writes,
OAuth flows, and API-key flows.

### Network Access

Gives the agent network reachability only. Use it for public or unauthenticated
resource access.

## Provider Workflow

1. Agent checks what is already attached.

   Tool: `openshell_provider_access`

   ```json
   {"action": "list"}
   ```

2. If the needed provider is missing, the agent requests it.

   Tool: `openshell_provider_access`

   ```json
   {
     "action": "request",
     "provider_name": "<provider>",
     "provider_type": "<provider_type>",
     "user_intent": "Describe the account-backed task",
     "reason": "Need account-backed access for the task"
   }
   ```

3. Operator approves the provider request.

4. OpenShell attaches the provider to this sandbox.

   ```text
   credential placeholder appears
   provider policy is composed into sandbox policy
   provider endpoints become reachable through the proxy
   provider tools become useful for that provider
   ```

5. Agent checks state.

   Tool: `openshell_provider_access`

   ```json
   {
     "action": "check",
     "provider_name": "<provider>"
   }
   ```

6. Agent uses an available tool through the proxy.

   ```text
   provider CLI when available
   curl/node/python fallback when appropriate
   ```

## Network-Only Workflow

Use network-only access when the task only needs unauthenticated reachability.

1. Agent lists available network presets.

   Tool: `openshell_network_access`

   ```json
   {"action": "list_presets"}
   ```

2. Agent requests a preset.

   Tool: `openshell_network_access`

   ```json
   {
     "action": "request",
     "resource": "<preset>",
     "access": "read",
     "user_intent": "Fetch public unauthenticated content",
     "reason": "Need this resource for the task"
   }
   ```

3. Operator approves the network request.

4. OpenShell reloads policy.

5. Agent checks the request.

   Tool: `openshell_network_access`

   ```json
   {
     "action": "check",
     "request_id": "<request_id>"
   }
   ```

Network-only access does not create token environment variables and does not
grant account identity.

## Credential Placeholder Behavior

Provider credentials can appear inside the sandbox as placeholder values:

```text
GITHUB_TOKEN=openshell:resolve:env:...
```

Those placeholders are intentional. They are not raw tokens. They only become
usable when the request goes through the sandbox HTTP(S) proxy:

```text
HTTP_PROXY=http://10.200.0.1:3128
HTTPS_PROXY=http://10.200.0.1:3128
```

For direct API calls, the agent should follow the `credential_usage` returned by
`openshell_provider_access`. Some providers use bearer headers, while others use
service-specific headers, URL token formats, SDK conventions, or CLIs. For
GitHub API calls, for example:

```bash
curl -x "$HTTPS_PROXY" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/user
```

The proxy resolves `openshell:resolve:env:*` at egress, enforces the approved
policy, and forwards the request to the external service.

## Why the CLIs Are in the Image

NemoClaw ships provider-related binaries in the sandbox image so an approved
provider is immediately usable. The presence of a binary is not the permission
boundary. OpenShell policy and provider attachment are the permission boundary.

Before approval:

```text
binary exists, but provider endpoint/credential use is blocked by policy
```

After approval:

```text
binary exists, matching provider policy is active, credential placeholder is
available, and proxy-mediated requests can succeed
```

This keeps the agent experience smooth without weakening the sandbox access
model.
