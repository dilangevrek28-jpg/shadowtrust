import type {
  AnalystCase,
  ApiErrorBody,
  CaseStatus,
  CaseQueueFilter,
  DetectionDecision,
  DecisionReplayResult,
  PaginatedSessionRisks,
  RiskLevel,
  SessionTimeline
} from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

export class ShadowTrustApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string
  ) {
    super(message);
    this.name = "ShadowTrustApiError";
  }
}

interface RequestOptions {
  method?: "GET" | "POST";
  analystId?: string;
  body?: unknown;
}

async function requestJson<T>(
  path: string,
  analystKey: string,
  options: RequestOptions = {}
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? "GET",
    headers: {
      Accept: "application/json",
      "X-Analyst-API-Key": analystKey,
      ...(options.analystId ? { "X-Analyst-ID": options.analystId } : {}),
      ...(options.body === undefined ? {} : { "Content-Type": "application/json" })
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });

  if (!response.ok) {
    let body: ApiErrorBody = {};
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      // A proxy may return a non-JSON error; the fallback below remains safe.
    }
    throw new ShadowTrustApiError(
      body.error?.message ?? `Request failed with status ${response.status}.`,
      response.status,
      body.error?.code ?? "request_failed"
    );
  }

  return (await response.json()) as T;
}

export interface SessionRiskQuery {
  minimumRisk: number;
  riskLevel: RiskLevel | "all";
  page: number;
  pageSize: number;
  caseStatus: CaseQueueFilter;
}

export function getSessionRisks(
  analystKey: string,
  query: SessionRiskQuery
): Promise<PaginatedSessionRisks> {
  const params = new URLSearchParams({
    minimum_risk: String(query.minimumRisk),
    page: String(query.page),
    page_size: String(query.pageSize)
  });
  if (query.riskLevel !== "all") {
    params.set("risk_level", query.riskLevel);
  }
  if (query.caseStatus !== "all") {
    params.set("case_status", query.caseStatus);
  }
  return requestJson(`/api/v1/analyst/sessions?${params}`, analystKey);
}

export function getDecision(
  analystKey: string,
  decisionId: string
): Promise<DetectionDecision> {
  return requestJson(`/api/v1/analyst/decisions/${decisionId}`, analystKey);
}

export function replayDecision(
  analystKey: string,
  decisionId: string
): Promise<DecisionReplayResult> {
  return requestJson(`/api/v1/analyst/decisions/${decisionId}/replay`, analystKey, {
    method: "POST"
  });
}

export function getTimeline(
  analystKey: string,
  sessionId: string
): Promise<SessionTimeline> {
  return requestJson(`/api/v1/sessions/${sessionId}/timeline`, analystKey);
}

export function getCaseForSession(
  analystKey: string,
  sessionId: string
): Promise<AnalystCase> {
  return requestJson(`/api/v1/analyst/sessions/${sessionId}/case`, analystKey);
}

export function openCase(
  analystKey: string,
  analystId: string,
  sessionId: string,
  note?: string
): Promise<AnalystCase> {
  return requestJson("/api/v1/analyst/cases", analystKey, {
    method: "POST",
    analystId,
    body: { session_id: sessionId, ...(note ? { note } : {}) }
  });
}

export function transitionCase(
  analystKey: string,
  analystId: string,
  caseId: string,
  expectedVersion: number,
  status: CaseStatus,
  note: string
): Promise<AnalystCase> {
  return requestJson(`/api/v1/analyst/cases/${caseId}/transitions`, analystKey, {
    method: "POST",
    analystId,
    body: { expected_version: expectedVersion, status, note }
  });
}
