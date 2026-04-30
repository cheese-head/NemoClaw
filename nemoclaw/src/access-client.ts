// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";

export const DEFAULT_CONTROL_SOCKET_PATH = "/run/nemoclaw/control.sock";

export type AccessStatus =
  | "pending_approval"
  | "pending_activation"
  | "applied"
  | "denied"
  | "denied_by_ceiling"
  | "failed"
  | "expired"
  | "revoked"
  | "drifted";

export type AccessCanonicalRequest = {
  [key: string]: unknown;
};

export interface AccessRequestResponse {
  request_id: string;
  status: AccessStatus;
  message?: string;
  canonical_request?: AccessCanonicalRequest;
}

export interface CreateAccessRequestBody {
  version: "nemoclaw.access.v1";
  task_id?: string;
  user_intent: string;
  llm_proposal: {
    resource_type: "network";
    preset: string;
    access: "read" | "read_write";
    duration: "session" | "persistent";
    reason: string;
  };
}

export interface AccessClientOptions {
  socketPath?: string;
  attestationToken?: string;
  timeoutMs?: number;
}

function parseAccessResponse(raw: string): AccessRequestResponse {
  const parsed: unknown = raw.length > 0 ? JSON.parse(raw) : {};
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("NemoClaw control returned a non-object response");
  }

  const response = parsed as Partial<AccessRequestResponse>;
  if (typeof response.request_id !== "string" || response.request_id.length === 0) {
    throw new Error("NemoClaw control response is missing request_id");
  }
  if (typeof response.status !== "string" || response.status.length === 0) {
    throw new Error("NemoClaw control response is missing status");
  }

  return response as AccessRequestResponse;
}

function requestJson(
  method: "GET" | "POST",
  path: string,
  body: CreateAccessRequestBody | undefined,
  options: AccessClientOptions = {},
): Promise<AccessRequestResponse> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const headers: Record<string, string | number> = {
    Accept: "application/json",
  };
  if (payload !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = Buffer.byteLength(payload);
  }
  if (options.attestationToken) {
    headers["X-NemoClaw-Plugin-Attestation"] = options.attestationToken;
  }

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        method,
        path,
        socketPath: options.socketPath ?? DEFAULT_CONTROL_SOCKET_PATH,
        headers,
        timeout: options.timeoutMs ?? 30_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf-8");
          if (res.statusCode === undefined || res.statusCode < 200 || res.statusCode >= 300) {
            reject(
              new Error(
                `NemoClaw control ${method} ${path} failed with HTTP ${res.statusCode ?? "unknown"}: ${raw}`,
              ),
            );
            return;
          }

          try {
            resolve(parseAccessResponse(raw));
          } catch (err) {
            reject(err);
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error(`NemoClaw control ${method} ${path} timed out`));
    });
    req.on("error", reject);
    if (payload !== undefined) {
      req.write(payload);
    }
    req.end();
  });
}

export function createAccessRequest(
  body: CreateAccessRequestBody,
  options?: AccessClientOptions,
): Promise<AccessRequestResponse> {
  return requestJson("POST", "/v1/access-requests", body, options);
}

export function getAccessRequest(
  requestId: string,
  options?: AccessClientOptions,
): Promise<AccessRequestResponse> {
  return requestJson(
    "GET",
    `/v1/access-requests/${encodeURIComponent(requestId)}`,
    undefined,
    options,
  );
}
