// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import https from "node:https";

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

export interface AccessPresetInfo {
  name: string;
  description: string;
}

export interface AccessPresetsResponse {
  presets: AccessPresetInfo[];
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
  controlUrl: string;
  ca?: string | Buffer;
  caPath?: string;
  cert?: string | Buffer;
  certPath?: string;
  key?: string | Buffer;
  keyPath?: string;
  servername?: string;
  attestationToken?: string;
  timeoutMs?: number;
}

function parseJsonObject(raw: string): Record<string, unknown> {
  const parsed: unknown = raw.length > 0 ? JSON.parse(raw) : {};
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("NemoClaw control returned a non-object response");
  }
  return parsed as Record<string, unknown>;
}

function parseAccessResponse(raw: string): AccessRequestResponse {
  const parsed = parseJsonObject(raw);

  const response = parsed as Partial<AccessRequestResponse>;
  if (typeof response.request_id !== "string" || response.request_id.length === 0) {
    throw new Error("NemoClaw control response is missing request_id");
  }
  if (typeof response.status !== "string" || response.status.length === 0) {
    throw new Error("NemoClaw control response is missing status");
  }

  return response as AccessRequestResponse;
}

function parsePresetsResponse(raw: string): AccessPresetsResponse {
  const parsed = parseJsonObject(raw);
  if (!Array.isArray(parsed.presets)) {
    throw new Error("NemoClaw control response is missing presets");
  }
  return {
    presets: parsed.presets
      .filter(
        (preset): preset is AccessPresetInfo =>
          typeof preset === "object" &&
          preset !== null &&
          typeof (preset as Partial<AccessPresetInfo>).name === "string" &&
          typeof (preset as Partial<AccessPresetInfo>).description === "string",
      )
      .map((preset) => ({ name: preset.name, description: preset.description })),
  };
}

function requestJson<T>(
  method: "GET" | "POST",
  requestPath: string,
  body: CreateAccessRequestBody | undefined,
  options: AccessClientOptions,
  parseResponse: (raw: string) => T,
): Promise<T> {
  const controlUrl = new URL(options.controlUrl);
  if (controlUrl.protocol !== "https:") {
    throw new Error("NemoClaw control URL must use HTTPS with mTLS.");
  }

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
  if (options.servername && options.servername !== controlUrl.hostname) {
    headers.Host = options.servername;
  }

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method,
        protocol: controlUrl.protocol,
        hostname: controlUrl.hostname,
        port: controlUrl.port === "" ? undefined : Number(controlUrl.port),
        path: `${controlUrl.pathname.replace(/\/$/, "")}${requestPath}`,
        headers,
        ca: options.ca ?? (options.caPath ? fs.readFileSync(options.caPath) : undefined),
        cert: options.cert ?? (options.certPath ? fs.readFileSync(options.certPath) : undefined),
        key: options.key ?? (options.keyPath ? fs.readFileSync(options.keyPath) : undefined),
        servername: options.servername ?? controlUrl.hostname,
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
                `NemoClaw control ${method} ${requestPath} failed with HTTP ${res.statusCode ?? "unknown"}: ${raw}`,
              ),
            );
            return;
          }

          try {
            resolve(parseResponse(raw));
          } catch (err) {
            reject(err);
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error(`NemoClaw control ${method} ${requestPath} timed out`));
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
  options: AccessClientOptions,
): Promise<AccessRequestResponse> {
  return requestJson("POST", "/v1/access-requests", body, options, parseAccessResponse);
}

export function getAccessRequest(
  requestId: string,
  options: AccessClientOptions,
): Promise<AccessRequestResponse> {
  return requestJson(
    "GET",
    `/v1/access-requests/${encodeURIComponent(requestId)}`,
    undefined,
    options,
    parseAccessResponse,
  );
}

export function listAccessPresets(options: AccessClientOptions): Promise<AccessPresetsResponse> {
  return requestJson("GET", "/v1/access-presets", undefined, options, parsePresetsResponse);
}
