import type {
  AnalystCase,
  CaseQueueFilter,
  DetectionDecision,
  DecisionReplayResult,
  PaginatedSessionRisks,
  RiskLevel,
  SessionRiskSummary,
  SessionTimeline
} from "./api/types";

const now = new Date("2026-10-26T10:40:00Z");
const atMinutesAgo = (minutes: number) =>
  new Date(now.getTime() - minutes * 60_000).toISOString();

export const demoSessions: SessionRiskSummary[] = [
  {
    session_id: "9ba17a98-2d31-4ea1-8219-8d16e34f9101",
    decision_id: "e05a1959-8a15-4f4f-a3fd-6448dc743101",
    trigger_event_id: "3e02cf97-af7a-451c-bf39-8a89613c2101",
    trigger_event_type: "transfer_initiated",
    occurred_at: atMinutesAgo(2),
    risk_before: 60,
    risk_after: 100,
    risk_delta: 40,
    risk_level: "critical",
    recommended_actions: ["hold_transaction", "restrict_session", "analyst_review"],
    explanation: "Recovery-registered device initiated a transfer inside the high-risk window.",
    matched_rules: ["RECOVERY_DEVICE_THEN_TRANSFER", "NEW_DEVICE"]
  },
  {
    session_id: "4ef6272f-a71d-4de2-af18-39e449c78202",
    decision_id: "45a018f2-cefc-4eb1-a83f-026e8251b202",
    trigger_event_id: "87c04bce-6f6b-48f5-ac93-38fcd92f8202",
    trigger_event_type: "mfa_challenge_completed",
    occurred_at: atMinutesAgo(7),
    risk_before: 50,
    risk_after: 85,
    risk_delta: 35,
    risk_level: "critical",
    recommended_actions: ["restrict_session", "analyst_review"],
    explanation: "Approval followed repeated denied MFA challenges from a new session context.",
    matched_rules: ["REPEATED_MFA_FAILURES_THEN_APPROVAL"]
  },
  {
    session_id: "fb395791-89dc-491e-90f7-2e4e3968b303",
    decision_id: "51f4d429-76c8-42e7-83c3-28e207134303",
    trigger_event_id: "fc1619e6-67f4-44ad-80fc-94fd0b2f3303",
    trigger_event_type: "transfer_initiated",
    occurred_at: atMinutesAgo(12),
    risk_before: 35,
    risk_after: 70,
    risk_delta: 35,
    risk_level: "high",
    recommended_actions: ["step_up_auth", "analyst_review"],
    explanation: "Session device and country changed before a transfer was initiated.",
    matched_rules: ["SESSION_CONTEXT_SWITCH_BEFORE_TRANSFER"]
  },
  {
    session_id: "e619b749-aea5-44ee-8ec2-32117393a404",
    decision_id: "4b582747-63ca-470e-b6f3-ffcc54fa9404",
    trigger_event_id: "497ba820-1986-46ba-89ba-9b2c8936f404",
    trigger_event_type: "login_succeeded",
    occurred_at: atMinutesAgo(21),
    risk_before: 0,
    risk_after: 35,
    risk_delta: 35,
    risk_level: "guarded",
    recommended_actions: ["monitor"],
    explanation: "Successful password-only login followed repeated invalid credentials.",
    matched_rules: ["REPEATED_INVALID_CREDENTIALS_THEN_SUCCESS"]
  }
];

const evaluations = [
  {
    rule_code: "NEW_DEVICE",
    rule_version: "1.0",
    category: "signal" as const,
    matched: true,
    score_delta: 15,
    reason: "Device has not appeared in the current user baseline.",
    evidence_event_ids: [demoSessions[0].trigger_event_id]
  },
  {
    rule_code: "RECOVERY_DEVICE_THEN_TRANSFER",
    rule_version: "1.0",
    category: "signal" as const,
    matched: true,
    score_delta: 40,
    reason: "A recovery-registered device initiated a transfer within 30 minutes.",
    evidence_event_ids: [
      "84ed5b80-cde7-43e0-a2fb-62ca85a9a901",
      demoSessions[0].trigger_event_id
    ]
  },
  {
    rule_code: "PASSWORD_CHANGE_BENEFICIARY_TRANSFER",
    rule_version: "1.0",
    category: "signal" as const,
    matched: false,
    score_delta: 0,
    reason: "No matching password-change and beneficiary sequence was found.",
    evidence_event_ids: []
  }
];

export const demoDecision: DetectionDecision = {
  id: demoSessions[0].decision_id,
  session_id: demoSessions[0].session_id,
  trigger_event_id: demoSessions[0].trigger_event_id,
  risk_before: 60,
  risk_after: 100,
  risk_delta: 40,
  risk_level: "critical",
  evaluations,
  recommended_actions: demoSessions[0].recommended_actions,
  explanation: demoSessions[0].explanation,
  rule_set_version: "2026.5",
  engine_version: "0.1.0",
  baseline_version: "baseline-2026-10-25"
};

export const demoTimeline: SessionTimeline = {
  session_id: demoSessions[0].session_id,
  items: [
    {
      event: {
        id: "84ed5b80-cde7-43e0-a2fb-62ca85a9a901",
        event_type: "device_registered",
        occurred_at: atMinutesAgo(18),
        user_id: "393d6a1a-e2af-4378-b257-7ff32e010501",
        session_id: demoSessions[0].session_id,
        device_id: "0f563731-3c53-4fdb-a4af-c15818c8d501",
        geo_country: "TR",
        payload: { registration_method: "recovery_flow" }
      },
      decision: { ...demoDecision, risk_before: 0, risk_after: 60, risk_delta: 60 }
    },
    {
      event: {
        id: "8a96e3ba-788b-4232-bd28-a9d5cd09a502",
        event_type: "login_succeeded",
        occurred_at: atMinutesAgo(14),
        user_id: "393d6a1a-e2af-4378-b257-7ff32e010501",
        session_id: demoSessions[0].session_id,
        device_id: "0f563731-3c53-4fdb-a4af-c15818c8d501",
        geo_country: "TR",
        payload: { authentication_method: "password", mfa_used: false }
      },
      decision: { ...demoDecision, risk_before: 60, risk_after: 60, risk_delta: 0 }
    },
    {
      event: {
        id: demoSessions[0].trigger_event_id,
        event_type: "transfer_initiated",
        occurred_at: demoSessions[0].occurred_at,
        user_id: "393d6a1a-e2af-4378-b257-7ff32e010501",
        session_id: demoSessions[0].session_id,
        device_id: "0f563731-3c53-4fdb-a4af-c15818c8d501",
        geo_country: "TR",
        payload: { currency: "TRY" }
      },
      decision: demoDecision
    }
  ]
};

export function getDemoDecision(summary: SessionRiskSummary): DetectionDecision {
  if (summary.decision_id === demoDecision.id) return demoDecision;
  return {
    ...demoDecision,
    id: summary.decision_id,
    session_id: summary.session_id,
    trigger_event_id: summary.trigger_event_id,
    risk_before: summary.risk_before,
    risk_after: summary.risk_after,
    risk_delta: summary.risk_delta,
    risk_level: summary.risk_level,
    recommended_actions: summary.recommended_actions,
    explanation: summary.explanation,
    evaluations: summary.matched_rules.map((ruleCode) => ({
      rule_code: ruleCode,
      rule_version: "1.0",
      category: "signal",
      matched: true,
      score_delta: summary.risk_delta,
      reason: summary.explanation,
      evidence_event_ids: [summary.trigger_event_id]
    }))
  };
}

export function replayDemoDecision(summary: SessionRiskSummary): DecisionReplayResult {
  const original = getDemoDecision(summary);
  return {
    status: "reproduced",
    original_decision: original,
    replayed_decision: { ...original, id: crypto.randomUUID() },
    differences: []
  };
}

export function getDemoTimeline(summary: SessionRiskSummary): SessionTimeline {
  if (summary.session_id === demoTimeline.session_id) return demoTimeline;
  return {
    session_id: summary.session_id,
    items: [
      {
        event: {
          id: summary.trigger_event_id,
          event_type: summary.trigger_event_type,
          occurred_at: summary.occurred_at,
          user_id: "393d6a1a-e2af-4378-b257-7ff32e010599",
          session_id: summary.session_id,
          device_id: null,
          geo_country: "TR",
          payload: {}
        },
        decision: getDemoDecision(summary)
      }
    ]
  };
}

export function getDemoSessions(
  minimumRisk: number,
  riskLevel: RiskLevel | "all",
  caseStatus: CaseQueueFilter,
  page: number,
  pageSize: number,
  cases: Record<string, AnalystCase> = {}
): PaginatedSessionRisks {
  const riskFiltered = demoSessions.map((item) => ({
    ...item,
    case_id: cases[item.session_id]?.id ?? null,
    case_status: cases[item.session_id]?.status ?? null,
    case_version: cases[item.session_id]?.version ?? null
  })).filter(
    (item) =>
      item.risk_after >= minimumRisk &&
      (riskLevel === "all" || item.risk_level === riskLevel)
  );
  const count = (status: CaseQueueFilter) => riskFiltered.filter((item) =>
    status === "unassigned" ? item.case_status === null : item.case_status === status
  ).length;
  const filtered = riskFiltered.filter((item) =>
    caseStatus === "all"
      || (caseStatus === "unassigned" ? item.case_status === null : item.case_status === caseStatus)
  );
  const offset = (page - 1) * pageSize;
  return {
    page,
    page_size: pageSize,
    total: filtered.length,
    items: filtered.slice(offset, offset + pageSize),
    case_counts: {
      unassigned: count("unassigned"),
      open: count("open"),
      investigating: count("investigating"),
      confirmed_takeover: count("confirmed_takeover"),
      false_positive: count("false_positive"),
      closed: count("closed")
    }
  };
}
