#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

export DEBIAN_FRONTEND=noninteractive
export NPM_CONFIG_AUDIT=false
export NPM_CONFIG_FUND=false
export NPM_CONFIG_UPDATE_NOTIFIER=false

needs_apt=0
for tool in gh glab jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        needs_apt=1
    fi
done

if [ "$needs_apt" = "1" ]; then
    apt-get update
    apt-get install -y --no-install-recommends \
        gh=2.46.0-3 \
        glab=1.53.0-1+b3 \
        jq=1.7.1-6+deb13u2
fi

needs_npm=0
for tool in claude codex opencode; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        needs_npm=1
    fi
done

if [ "$needs_npm" = "1" ]; then
    npm install -g --no-audit --no-fund --no-progress \
        '@anthropic-ai/claude-code@2.1.143' \
        '@openai/codex@0.130.0' \
        'opencode-ai@1.15.0'
fi

# GitHub Copilot is exposed through the GitHub CLI. Keep the binary path named
# by the OpenShell provider profile present, while letting provider policy
# control whether the wrapper can reach GitHub after approval.
cat > /usr/local/bin/copilot <<'EOF'
#!/bin/sh
exec gh copilot "$@"
EOF
chmod 755 /usr/local/bin/copilot

command -v gh >/dev/null
command -v glab >/dev/null
command -v jq >/dev/null
command -v claude >/dev/null
command -v codex >/dev/null
command -v opencode >/dev/null
command -v copilot >/dev/null

rm -rf /var/lib/apt/lists/*
