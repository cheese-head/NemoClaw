#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/openshell/repo" >&2
  exit 2
fi

OPEN_SHELL_ROOT="$1"
NEMOCLAW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPENSHELL_BIN="${OPEN_SHELL_ROOT}/target/debug/openshell"
SANDBOX="${SANDBOX:-nemoclaw-plugin-live-$(date +%Y%m%d-%H%M%S)}"
TMP_DIR="$(mktemp -d)"
UPLOAD_DIR="${TMP_DIR}/upload"

cleanup() {
  "${OPENSHELL_BIN}" sandbox delete "${SANDBOX}" >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

"${OPENSHELL_BIN}" settings set --global \
  --key agent_policy_proposals_enabled \
  --value true \
  --yes

mkdir -p "${UPLOAD_DIR}/nemoclaw"
cp -R "${NEMOCLAW_ROOT}/nemoclaw/dist" "${UPLOAD_DIR}/nemoclaw/dist"
cp "${NEMOCLAW_ROOT}/nemoclaw/package.json" "${UPLOAD_DIR}/nemoclaw/package.json"
cp -R "${NEMOCLAW_ROOT}/nemoclaw/node_modules" "${UPLOAD_DIR}/nemoclaw/node_modules"
cp "${NEMOCLAW_ROOT}/test/e2e/nemoclaw-policy-local-runner.mjs" "${UPLOAD_DIR}/runner.mjs"

"${OPENSHELL_BIN}" sandbox delete "${SANDBOX}" >/dev/null 2>&1 || true
"${OPENSHELL_BIN}" sandbox create \
  --name "${SANDBOX}" \
  --upload "${UPLOAD_DIR}:/sandbox" \
  --no-git-ignore \
  --keep \
  --no-auto-providers \
  --no-tty \
  -- bash -lc "if [ -d /sandbox/upload ]; then cp -R /sandbox/upload/. /sandbox/; fi && node --version && test -f /sandbox/nemoclaw/dist/index.js && test -d /sandbox/nemoclaw/node_modules && test -f /sandbox/runner.mjs && echo plugin sandbox ready"

"${OPENSHELL_BIN}" sandbox ssh-config "${SANDBOX}" >"${TMP_DIR}/ssh_config"
SSH_HOST="$(awk '/^Host / { print $2; exit }' "${TMP_DIR}/ssh_config")"
if [ -z "${SSH_HOST}" ]; then
  echo "failed to parse sandbox ssh host" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  if ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" true >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" true

LIST_JSON="$(ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" node /sandbox/runner.mjs list)"
printf "LIST_JSON=%s\n" "${LIST_JSON}"
printf "%s" "${LIST_JSON}" \
  | jq -e '.presets[] | select(.name == "github" and .provider_profile == "github")' \
    >/dev/null

REQUEST_JSON="$(ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" node /sandbox/runner.mjs request)"
printf "REQUEST_JSON=%s\n" "${REQUEST_JSON}"
REQ_ID="$(printf "%s" "${REQUEST_JSON}" | jq -r '.request_id')"
if [ -z "${REQ_ID}" ] || [ "${REQ_ID}" = "null" ]; then
  echo "openshell_network_access action=request did not return a request_id" >&2
  exit 1
fi
if [ "$(printf "%s" "${REQUEST_JSON}" | jq -r '.status')" != "pending_approval" ]; then
  echo "openshell_network_access action=request did not return pending_approval" >&2
  exit 1
fi

"${OPENSHELL_BIN}" rule approve "${SANDBOX}" --chunk-id "${REQ_ID}"

CHECK_JSON="$(ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" node /sandbox/runner.mjs check "${REQ_ID}")"
printf "CHECK_JSON=%s\n" "${CHECK_JSON}"
if [ "$(printf "%s" "${CHECK_JSON}" | jq -r '.status')" != "applied" ]; then
  echo "openshell_network_access action=check did not return applied" >&2
  exit 1
fi

printf "NemoClaw plugin live policy.local flow passed for request_id=%s\n" "${REQ_ID}"
