import { ChevronLeft, ChevronRight, Clock3 } from "lucide-react";
import type { SessionRiskSummary } from "../api/types";
import { formatDateTime, formatEventName, riskLabels, shortId } from "../utils";

interface RiskQueueProps {
  items: SessionRiskSummary[];
  selectedId?: string;
  loading: boolean;
  page: number;
  pageSize: number;
  total: number;
  onSelect: (item: SessionRiskSummary) => void;
  onPageChange: (page: number) => void;
}

export function RiskQueue({
  items,
  selectedId,
  loading,
  page,
  pageSize,
  total,
  onSelect,
  onPageChange
}: RiskQueueProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section className="queue-panel" aria-labelledby="queue-title">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Live review queue</p>
          <h2 id="queue-title">Session risk</h2>
        </div>
        <span className="count-pill">{total} sessions</span>
      </div>

      <div className="queue-columns" aria-hidden="true">
        <span>Risk</span><span>Session & trigger</span><span>Signal</span><span>Time</span>
      </div>

      <div className={`queue-list${loading ? " loading" : ""}`}>
        {loading && items.length === 0
          ? Array.from({ length: 4 }, (_, index) => (
              <div className="queue-skeleton" key={index} />
            ))
          : items.map((item) => (
              <button
                type="button"
                className={`queue-row${selectedId === item.session_id ? " selected" : ""}`}
                key={item.session_id}
                onClick={() => onSelect(item)}
                aria-pressed={selectedId === item.session_id}
              >
                <span className={`risk-number risk-${item.risk_level}`}>
                  {item.risk_after}
                  <small>{riskLabels[item.risk_level]}</small>
                </span>
                <span className="session-cell">
                  <strong>{shortId(item.session_id)}</strong>
                  <small>{formatEventName(item.trigger_event_type)}</small>
                  <small className={`queue-case status-${item.case_status ?? "unassigned"}`}>
                    {item.case_status?.replaceAll("_", " ") ?? "unassigned"}
                  </small>
                </span>
                <span className="signal-cell">
                  <strong>{item.matched_rules[0] ?? "No matched rule"}</strong>
                  <small>{item.risk_delta >= 0 ? "+" : ""}{item.risk_delta} risk</small>
                </span>
                <span className="time-cell">
                  <Clock3 size={14} /> {formatDateTime(item.occurred_at)}
                </span>
              </button>
            ))}
        {!loading && items.length === 0 && (
          <div className="empty-state">
            <strong>No sessions match this view</strong>
            <span>Lower the minimum score or choose another risk level.</span>
          </div>
        )}
      </div>

      <footer className="pagination">
        <span>Page {page} of {totalPages}</span>
        <div>
          <button
            className="icon-button"
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            aria-label="Previous page"
          ><ChevronLeft size={17} /></button>
          <button
            className="icon-button"
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            aria-label="Next page"
          ><ChevronRight size={17} /></button>
        </div>
      </footer>
    </section>
  );
}
