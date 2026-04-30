// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import https from "node:https";
import http from "node:http";
import tls from "node:tls";

import {
  AccessRequestValidationError,
  createAccessRequest,
  readAccessRequestState,
  type AccessRequestDeps,
  type AccessRequestProposal,
  type AccessRequestRecord,
} from "./access-requests";

export type AccessControlServerOptions = {
  tls: https.ServerOptions;
  allowedHosts: readonly string[];
  pluginAttestationToken?: string;
  verifyPluginAttestation?: (token: string, authenticated: AuthenticatedSandbox) => boolean;
  deps?: AccessRequestDeps;
};

export type AccessControlResponse = {
  request_id: string;
  status: AccessRequestRecord["status"];
  message?: string;
  canonical_request?: Omit<
    AccessRequestRecord,
    "id" | "version" | "sandbox_id" | "status" | "created_at" | "updated_at"
  >;
};

type AuthenticatedSandbox = {
  sandboxId: string;
  fingerprint?: string;
};

type JsonObject = Record<string, unknown>;

const MAX_BODY_BYTES = 64 * 1024;

function jsonResponse(res: http.ServerResponse, statusCode: number, body: JsonObject): void {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/:\d+$/u, "");
}

function verifyHost(req: http.IncomingMessage, allowedHosts: readonly string[]): void {
  const host = req.headers.host;
  if (typeof host !== "string" || host.trim().length === 0) {
    throw Object.assign(new Error("Missing Host header."), { statusCode: 400 });
  }

  const actual = normalizeHost(host);
  const allowed = new Set(allowedHosts.map(normalizeHost));
  if (!allowed.has(actual)) {
    throw Object.assign(new Error("Host header is not allowed."), { statusCode: 421 });
  }
}

function readAttestationToken(req: http.IncomingMessage): string {
  const actual = req.headers["x-nemoclaw-plugin-attestation"];
  return typeof actual === "string" ? actual : "";
}

function verifyAttestation(
  token: string,
  authenticated: AuthenticatedSandbox,
  options: AccessControlServerOptions,
): void {
  const ok =
    options.verifyPluginAttestation?.(token, authenticated) ??
    (typeof options.pluginAttestationToken === "string" && token === options.pluginAttestationToken);
  if (!ok) {
    throw Object.assign(new Error("Invalid plugin attestation."), { statusCode: 401 });
  }
}

function sandboxIdFromSubjectAltName(subjectaltname?: string): string | null {
  if (!subjectaltname) {
    return null;
  }
  const match = subjectaltname.match(/URI:nemoclaw:sandbox:([^,\s]+)/u);
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

function sandboxIdFromCommonName(commonName?: unknown): string | null {
  if (typeof commonName !== "string") {
    return null;
  }
  return commonName.startsWith("sandbox:") ? commonName.slice("sandbox:".length) : null;
}

function authenticateSandbox(req: http.IncomingMessage): AuthenticatedSandbox {
  const socket = req.socket as tls.TLSSocket;
  if (!socket.authorized) {
    throw Object.assign(new Error("A valid mTLS client certificate is required."), {
      statusCode: 401,
    });
  }

  const cert = socket.getPeerCertificate();
  const sandboxId =
    sandboxIdFromSubjectAltName(cert.subjectaltname) ?? sandboxIdFromCommonName(cert.subject?.CN);
  if (!sandboxId) {
    throw Object.assign(new Error("mTLS client certificate is missing sandbox identity."), {
      statusCode: 403,
    });
  }

  return {
    sandboxId,
    ...(cert.fingerprint256 ? { fingerprint: cert.fingerprint256 } : {}),
  };
}

function assertNoIdentityConflict(body: JsonObject, authenticated: AuthenticatedSandbox): void {
  const identity = typeof body.identity === "object" && body.identity !== null ? body.identity : {};
  const hintedSandboxId =
    typeof body.sandbox_id === "string"
      ? body.sandbox_id
      : typeof (identity as JsonObject).sandbox_id === "string"
        ? String((identity as JsonObject).sandbox_id)
        : undefined;
  if (hintedSandboxId && hintedSandboxId !== authenticated.sandboxId) {
    throw Object.assign(new Error("Request body sandbox identity conflicts with mTLS identity."), {
      statusCode: 403,
    });
  }
}

async function readJsonBody(req: http.IncomingMessage): Promise<JsonObject> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > MAX_BODY_BYTES) {
      throw Object.assign(new Error("Request body is too large."), { statusCode: 413 });
    }
    chunks.push(buffer);
  }

  const raw = Buffer.concat(chunks).toString("utf-8");
  const parsed: unknown = raw.length > 0 ? JSON.parse(raw) : {};
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw Object.assign(new Error("Request body must be a JSON object."), { statusCode: 400 });
  }
  return parsed as JsonObject;
}

function toProposal(body: JsonObject, authenticated: AuthenticatedSandbox): AccessRequestProposal {
  const proposal =
    typeof body.llm_proposal === "object" && body.llm_proposal !== null
      ? (body.llm_proposal as JsonObject)
      : body;
  return {
    resource: typeof proposal.preset === "string" ? proposal.preset : undefined,
    preset: typeof proposal.preset === "string" ? proposal.preset : undefined,
    host: typeof proposal.host === "string" ? proposal.host : undefined,
    access: typeof proposal.access === "string" ? proposal.access : undefined,
    duration: typeof proposal.duration === "string" ? proposal.duration : undefined,
    reason: typeof proposal.reason === "string" ? proposal.reason : undefined,
    task_id: typeof body.task_id === "string" ? body.task_id : undefined,
    user_intent: typeof body.user_intent === "string" ? body.user_intent : undefined,
    identity: {
      ...(typeof body.identity === "object" && body.identity !== null
        ? (body.identity as Record<string, string | undefined>)
        : {}),
      sandbox_id: authenticated.sandboxId,
      ...(authenticated.fingerprint ? { client_cert_fingerprint: authenticated.fingerprint } : {}),
    },
  };
}

function toResponse(request: AccessRequestRecord): AccessControlResponse {
  return {
    request_id: request.id,
    status: request.status,
    canonical_request: {
      resource_type: request.resource_type,
      preset: request.preset,
      access: request.access,
      duration: request.duration,
      task_id: request.task_id,
      user_intent: request.user_intent,
      reason: request.reason,
      identity_hints: request.identity_hints,
      request_hash: request.request_hash,
      ...(request.ceiling_reason ? { ceiling_reason: request.ceiling_reason } : {}),
      ...(request.status_reason ? { status_reason: request.status_reason } : {}),
    },
  };
}

async function handleAccessRequestPost(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  authenticated: AuthenticatedSandbox,
  deps?: AccessRequestDeps,
): Promise<void> {
  const body = await readJsonBody(req);
  assertNoIdentityConflict(body, authenticated);
  const result = createAccessRequest(authenticated.sandboxId, toProposal(body, authenticated), {
    deps,
  });
  jsonResponse(res, result.created ? 201 : 200, toResponse(result.request));
}

function handleAccessRequestGet(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  authenticated: AuthenticatedSandbox,
  deps?: AccessRequestDeps,
): void {
  const url = new URL(req.url ?? "/", "https://nemoclaw-control.local");
  const requestId = decodeURIComponent(url.pathname.slice("/v1/access-requests/".length));
  if (!requestId) {
    jsonResponse(res, 404, { error: "Not found." });
    return;
  }

  const request = readAccessRequestState(authenticated.sandboxId, deps).requests.find(
    (candidate) => candidate.id === requestId,
  );
  if (!request) {
    jsonResponse(res, 404, { error: "Access request not found." });
    return;
  }
  jsonResponse(res, 200, toResponse(request));
}

function handleError(res: http.ServerResponse, err: unknown): void {
  const statusCode =
    typeof err === "object" &&
    err !== null &&
    "statusCode" in err &&
    typeof err.statusCode === "number"
      ? err.statusCode
      : err instanceof AccessRequestValidationError
        ? 400
        : err instanceof SyntaxError
          ? 400
          : 500;
  const message = err instanceof Error ? err.message : "Internal server error.";
  jsonResponse(res, statusCode, { error: message });
}

export function createAccessControlServer(options: AccessControlServerOptions): https.Server {
  const serverOptions: https.ServerOptions = {
    ...options.tls,
    requestCert: true,
    rejectUnauthorized: true,
  };

  return https.createServer(serverOptions, (req, res) => {
    void (async () => {
      try {
        verifyHost(req, options.allowedHosts);
        const authenticated = authenticateSandbox(req);
        verifyAttestation(readAttestationToken(req), authenticated, options);
        const url = new URL(req.url ?? "/", "https://nemoclaw-control.local");

        if (req.method === "POST" && url.pathname === "/v1/access-requests") {
          await handleAccessRequestPost(req, res, authenticated, options.deps);
          return;
        }
        if (req.method === "GET" && url.pathname.startsWith("/v1/access-requests/")) {
          handleAccessRequestGet(req, res, authenticated, options.deps);
          return;
        }
        jsonResponse(res, 404, { error: "Not found." });
      } catch (err) {
        handleError(res, err);
      }
    })();
  });
}
