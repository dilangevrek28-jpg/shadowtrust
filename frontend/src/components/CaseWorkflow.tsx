import { FormEvent, useEffect, useMemo, useState } from "react";
import { ClipboardCheck, History, Plus, Send } from "lucide-react";
import type { AnalystCase, CaseStatus } from "../api/types";
import { formatDateTime } from "../utils";

const statusLabels: Record<CaseStatus, string> = {
  open: "Open",
  investigating: "Investigating",
  confirmed_takeover: "Confirmed takeover",
  false_positive: "False positive",
  closed: "Closed"
};

const allowedTransitions: Record<CaseStatus, CaseStatus[]> = {
  open: ["investigating", "confirmed_takeover", "false_positive", "closed"],
  investigating: ["confirmed_takeover", "false_positive", "closed"],
  confirmed_takeover: ["investigating", "closed"],
  false_positive: ["investigating", "closed"],
  closed: ["investigating"]
};

interface CaseWorkflowProps {
  analystId: string;
  caseData?: AnalystCase;
  loading: boolean;
  saving: boolean;
  onOpen: (note?: string) => Promise<void>;
  onTransition: (status: CaseStatus, note: string) => Promise<void>;
}

export function CaseWorkflow({
  analystId,
  caseData,
  loading,
  saving,
  onOpen,
  onTransition
}: CaseWorkflowProps) {
  const [note, setNote] = useState("");
  const [nextStatus, setNextStatus] = useState<CaseStatus>("investigating");
  const transitions = useMemo(
    () => caseData ? allowedTransitions[caseData.status] : [],
    [caseData]
  );

  useEffect(() => {
    setNote("");
    setNextStatus(transitions[0] ?? "investigating");
  }, [caseData?.id, caseData?.version, transitions]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const normalized = note.trim();
    if (caseData) {
      if (!normalized) return;
      await onTransition(nextStatus, normalized);
    } else {
      await onOpen(normalized || undefined);
    }
  }

  return (
    <section className="detail-section case-section" aria-labelledby="case-workflow-title">
      <div className="section-title">
        <ClipboardCheck size={16} /> <h3 id="case-workflow-title">Case management</h3>
        {loading && <span className="inline-loader">Loading</span>}
      </div>

      {!loading && !caseData && (
        <form className="case-form" onSubmit={(event) => void submit(event)}>
          <div className="case-empty-copy">
            <strong>No case is open</strong>
            <span>Promote this session into a tracked analyst workflow.</span>
          </div>
          <label htmlFor="case-opening-note">Opening note <span>optional</span></label>
          <textarea
            id="case-opening-note"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            maxLength={500}
            placeholder="Why does this session need investigation?"
          />
          <button className="case-submit" type="submit" disabled={saving}>
            <Plus size={14} /> {saving ? "Opening…" : "Open case"}
          </button>
        </form>
      )}

      {caseData && (
        <>
          <div className="case-summary">
            <div>
              <span className={`case-status status-${caseData.status}`}>
                {statusLabels[caseData.status]}
              </span>
              <small>Version {caseData.version}</small>
            </div>
            <span>Assigned action by <strong>{analystId}</strong></span>
          </div>

          <form className="case-form transition-form" onSubmit={(event) => void submit(event)}>
            <label htmlFor="case-next-status">Next status</label>
            <select
              id="case-next-status"
              value={nextStatus}
              onChange={(event) => setNextStatus(event.target.value as CaseStatus)}
            >
              {transitions.map((status) => (
                <option value={status} key={status}>{statusLabels[status]}</option>
              ))}
            </select>
            <label htmlFor="case-transition-note">Decision note <span>required</span></label>
            <textarea
              id="case-transition-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              minLength={3}
              maxLength={500}
              placeholder="Record the evidence or reason for this change."
              required
            />
            <button className="case-submit" type="submit" disabled={saving || !note.trim()}>
              <Send size={14} /> {saving ? "Saving…" : "Apply transition"}
            </button>
          </form>

          <div className="case-history">
            <div className="case-history-title"><History size={14} /> Audit history</div>
            <ol>
              {[...caseData.audit_trail].reverse().map((entry) => (
                <li key={entry.id}>
                  <span className="audit-sequence">{entry.sequence}</span>
                  <div>
                    <strong>{statusLabels[entry.new_status]}</strong>
                    <span>{entry.actor_id} · {formatDateTime(entry.occurred_at)}</span>
                    {entry.note && <p>{entry.note}</p>}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </>
      )}
    </section>
  );
}
