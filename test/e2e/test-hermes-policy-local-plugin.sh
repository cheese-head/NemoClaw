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
SANDBOX="${SANDBOX:-nemoclaw-hermes-plugin-live-$(date +%Y%m%d-%H%M%S)}"
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

mkdir -p "${UPLOAD_DIR}/hermes-plugin"
cp "${NEMOCLAW_ROOT}/agents/hermes/plugin/__init__.py" "${UPLOAD_DIR}/hermes-plugin/__init__.py"
cp "${NEMOCLAW_ROOT}/agents/hermes/plugin/plugin.yaml" "${UPLOAD_DIR}/hermes-plugin/plugin.yaml"
cp "${NEMOCLAW_ROOT}/test/e2e/hermes-policy-local-runner.py" "${UPLOAD_DIR}/runner.py"

"${OPENSHELL_BIN}" sandbox delete "${SANDBOX}" >/dev/null 2>&1 || true
"${OPENSHELL_BIN}" sandbox create \
  --name "${SANDBOX}" \
  --upload "${UPLOAD_DIR}:/sandbox" \
  --no-git-ignore \
  --keep \
  --no-auto-providers \
  --no-tty \
  -- bash -lc "if [ -d /sandbox/upload ]; then cp -R /sandbox/upload/. /sandbox/; fi && python3 --version && test -f /sandbox/hermes-plugin/__init__.py && test -f /sandbox/runner.py && echo hermes plugin sandbox ready"

"${OPENSHELL_BIN}" sandbox ssh-config "${SANDBOX}" > "${TMP_DIR}/ssh_config"
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

LIST_JSON="$(ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" python3 /sandbox/runner.py list)"
printf "HERMES_LIST_JSON=%s\n" "${LIST_JSON}"
printf "%s" "${LIST_JSON}" \
  | jq -e '.presets[] | select(.name == "github" and .provider_profile == "github")' \
  >/dev/null

REQUEST_JSON="$(ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" python3 /sandbox/runner.py request)"
printf "HERMES_REQUEST_JSON=%s\n" "${REQUEST_JSON}"
REQ_ID="$(printf "%s" "${REQUEST_JSON}" | jq -r '.request_id')"
if [ -z "${REQ_ID}" ] || [ "${REQ_ID}" = "null" ]; then
  echo "request_resource_access did not return a request_id" >&2
  exit 1
fi
if [ "$(printf "%s" "${REQUEST_JSON}" | jq -r '.status')" != "pending_approval" ]; then
  echo "request_resource_access did not return pending_approval" >&2
  exit 1
fi

"${OPENSHELL_BIN}" rule approve "${SANDBOX}" --chunk-id "${REQ_ID}"

CHECK_JSON="$(ssh -F "${TMP_DIR}/ssh_config" "${SSH_HOST}" python3 /sandbox/runner.py check "${REQ_ID}")"
printf "HERMES_CHECK_JSON=%s\n" "${CHECK_JSON}"
if [ "$(printf "%s" "${CHECK_JSON}" | jq -r '.status')" != "applied" ]; then
  echo "check_resource_access did not return applied" >&2
  exit 1
fi

printf "Hermes NemoClaw plugin live policy.local flow passed for request_id=%s\n" "${REQ_ID}"
