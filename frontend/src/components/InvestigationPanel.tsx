import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  CircleDashed,
  Fingerprint,
  RotateCcw,
  ShieldAlert
} from "lucide-react";
import type { CSSProperties } from "react";
import type {
  AnalystCase,
  CaseStatus,
  DetectionDecision,
  DecisionReplayResult,
  SessionRiskSummary,
  SessionTimeline
} from "../api/types";
import { CaseWorkflow } from "./CaseWorkflow";
import {
  actionLabels,
  formatEventName,
  formatTime,
  riskLabels,
  shortId
} from "../utils";

interface InvestigationPanelProps {
  summary?: SessionRiskSummary;
  decision?: DetectionDecision;
  replayResult?: DecisionReplayResult;
  timeline?: SessionTimeline;
  analystId: string;
  caseData?: AnalystCase;
  loading: boolean;
  replayLoading: boolean;
  caseLoading: boolean;
  caseSaving: boolean;
  onOpenCase: (note?: string) => Promise<void>;
  onTransitionCase: (status: CaseStatus, note: string) => Promise<void>;
  onReplayDecision: () => Promise<void>;
}

export function InvestigationPanel({
  summary,
  decision,
  replayResult,
  timeline,
  analystId,
  caseData,
  loading,
  replayLoading,
  caseLoading,
  caseSaving,
  onOpenCase,
  onTransitionCase,
  onReplayDecision
}: InvestigationPanelProps) {
  if (!summary) {
    return (
      <aside className="investigation-panel empty-investigation">
        <Fingerprint size={28} />
        <h2>Select a session</h2>
        <p>Choose a row from the risk queue to inspect its decision trace.</p>
      </aside>
    );
  }

  return (
    <aside className="investigation-panel" aria-labelledby="investigation-title">
      <header className="investigation-header">
        <div>
          <p className="eyebrow">Investigation</p>
          <h2 id="investigation-title">{shortId(summary.session_id)}</h2>
        </div>
        <span className={`risk-badge risk-${summary.risk_level}`}>
          {riskLabels[summary.risk_level]}
        </span>
      </header>

      <section className="risk-hero">
        <div
          className={`score-ring risk-${summary.risk_level}`}
          style={{ "--score": `${summary.risk_after * 3.6}deg` } as CSSProperties}
          aria-label={`Risk score ${summary.risk_after} out of 100`}
        >
          <span>{summary.risk_after}</span>
          <small>/100</small>
        </div>
        <div className="risk-hero-copy">
          <span className="delta-chip">
            <ArrowUpRight size={14} /> {summary.risk_delta >= 0 ? "+" : ""}{summary.risk_delta}
          </span>
          <p>{summary.explanation}</p>
        </div>
      </section>

      <section className="detail-section">
        <div className="section-title">
          <ShieldAlert size={16} /> <h3>Recommended response</h3>
        </div>
        <div className="action-list">
          {summary.recommended_actions.map((action) => (
            <span key={action}>{actionLabels[action]}</span>
          ))}
        </div>
      </section>

      <section className="detail-section replay-section">
        <div className="section-title">
          <RotateCcw size={16} /> <h3>Decision replay</h3>
        </div>
        <p className="replay-copy">
          Rebuild the historical context and verify this decision against its recorded engine and rule versions.
        </p>
        <button
          className="replay-button"
          type="button"
          disabled={replayLoading || !decision}
          onClick={() => void onReplayDecision()}
        >
          <RotateCcw size={14} className={replayLoading ? "spin" : ""} />
          {replayLoading ? "Replaying" : "Replay decision"}
        </button>
        {replayResult && (
          <div className={`replay-result replay-${replayResult.status}`} role="status">
            <strong>{replayResult.status.replaceAll("_", " ")}</strong>
            <span>
              {replayResult.status === "reproduced"
                ? "The score, rule trace, explanation, and actions match exactly."
                : replayResult.status === "incompatible"
                  ? "The active version cannot faithfully execute this historical decision."
                  : "The replay completed but produced semantic differences."}
            </span>
            {replayResult.differences.length > 0 && (
              <small>Differences: {replayResult.differences.join(", ")}</small>
            )}
          </div>
        )}
      </section>

      <CaseWorkflow
        analystId={analystId}
        caseData={caseData}
        loading={caseLoading}
        saving={caseSaving}
        onOpen={onOpenCase}
        onTransition={onTransitionCase}
      />

      <section className="detail-section">
        <div className="section-title">
          <Activity size={16} /> <h3>Rule trace</h3>
          {loading && <span className="inline-loader">Loading</span>}
        </div>
        <div className="rule-list">
          {(decision?.evaluations ?? []).map((rule) => (
            <article className={`rule-row${rule.matched ? " matched" : ""}`} key={rule.rule_code}>
              <div className="rule-icon" aria-hidden="true">
                {rule.matched ? <CheckCircle2 size={17} /> : <CircleDashed size={17} />}
              </div>
              <div>
                <div className="rule-heading">
                  <strong>{rule.rule_code}</strong>
                  <span>{rule.matched ? `${rule.score_delta > 0 ? "+" : ""}${rule.score_delta}` : "No match"}</span>
                </div>
                <p>{rule.reason}</p>
              </div>
            </article>
          ))}
          {!loading && !decision && (
            <p className="muted">Decision detail is unavailable.</p>
          )}
        </div>
      </section>

      <section className="detail-section timeline-section">
        <div className="section-title">
          <Fingerprint size={16} /> <h3>Session timeline</h3>
        </div>
        <ol className="timeline-list">
          {(timeline?.items ?? []).map((item, index) => (
            <li key={item.event.id}>
              <span className="timeline-node">{index + 1}</span>
              <div>
                <strong>{formatEventName(item.event.event_type)}</strong>
                <span>{formatTime(item.event.occurred_at)}</span>
                <small>
                  {item.event.geo_country ?? "Unknown region"}
                  {item.decision ? ` · risk ${item.decision.risk_after}` : ""}
                </small>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <footer className="evidence-footer">
        <span>Ruleset {decision?.rule_set_version ?? "—"}</span>
        <span>Engine {decision?.engine_version ?? "—"}</span>
      </footer>
    </aside>
  );
}
