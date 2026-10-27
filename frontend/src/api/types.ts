export type RiskLevel = "low" | "guarded" | "elevated" | "high" | "critical";

export type RecommendedAction =
  | "allow"
  | "monitor"
  | "step_up_auth"
  | "hold_transaction"
  | "restrict_session"
  | "analyst_review";

export interface RuleEvaluation {
  rule_code: string;
  rule_version: string;
  category: "signal" | "contradiction" | "recovery";
  matched: boolean;
  score_delta: number;
  reason: string;
  evidence_event_ids: string[];
}

export interface DetectionDecision {
  id: string;
  session_id: string;
  trigger_event_id: string;
  risk_before: number;
  risk_after: number;
  risk_delta: number;
  risk_level: RiskLevel;
  evaluations: RuleEvaluation[];
  recommended_actions: RecommendedAction[];
  explanation: string;
  rule_set_version: string;
  engine_version: string;
  baseline_version: string | null;
}

export interface DecisionReplayResult {
  status: "reproduced" | "drifted" | "incompatible";
  original_decision: DetectionDecision;
  replayed_decision: DetectionDecision | null;
  differences: string[];
}

export interface SessionRiskSummary {
  session_id: string;
  decision_id: string;
  trigger_event_id: string;
  trigger_event_type: string;
  occurred_at: string;
  risk_before: number;
  risk_after: number;
  risk_delta: number;
  risk_level: RiskLevel;
  recommended_actions: RecommendedAction[];
  explanation: string;
  matched_rules: string[];
  case_id?: string | null;
  case_status?: CaseStatus | null;
  case_version?: number | null;
}

export interface SessionCaseCounts {
  unassigned: number;
  open: number;
  investigating: number;
  confirmed_takeover: number;
  false_positive: number;
  closed: number;
}

export interface PaginatedSessionRisks {
  page: number;
  page_size: number;
  total: number;
  items: SessionRiskSummary[];
  case_counts: SessionCaseCounts;
}

export interface SecurityEvent {
  id: string;
  event_type: string;
  occurred_at: string;
  user_id: string;
  session_id: string | null;
  device_id: string | null;
  geo_country: string | null;
  payload: Record<string, unknown>;
}

export interface SessionTimelineItem {
  event: SecurityEvent;
  decision: DetectionDecision | null;
}

export interface SessionTimeline {
  session_id: string;
  items: SessionTimelineItem[];
}

export type CaseStatus =
  | "open"
  | "investigating"
  | "confirmed_takeover"
  | "false_positive"
  | "closed";

export type CaseQueueFilter = CaseStatus | "unassigned" | "all";

export interface CaseAuditEntry {
  id: string;
  case_id: string;
  sequence: number;
  previous_status: CaseStatus | null;
  new_status: CaseStatus;
  actor_id: string;
  note: string | null;
  occurred_at: string;
}

export interface AnalystCase {
  id: string;
  session_id: string;
  status: CaseStatus;
  version: number;
  created_at: string;
  updated_at: string;
  audit_trail: CaseAuditEntry[];
}

export interface ApiErrorBody {
  error?: {
    code?: string;
    message?: string;
  };
}
