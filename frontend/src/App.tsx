import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Bell,
  CircleUserRound,
  Filter,
  LogOut,
  RefreshCw,
  Search,
  ShieldCheck,
  TriangleAlert,
  Wifi
} from "lucide-react";
import {
  getCaseForSession,
  getDecision,
  getSessionRisks,
  getTimeline,
  openCase,
  replayDecision,
  ShadowTrustApiError,
  transitionCase
} from "./api/client";
import type {
  AnalystCase,
  CaseStatus,
  CaseQueueFilter,
  DetectionDecision,
  DecisionReplayResult,
  PaginatedSessionRisks,
  RiskLevel,
  SessionRiskSummary,
  SessionTimeline
} from "./api/types";
import { AccessGate } from "./components/AccessGate";
import { InvestigationPanel } from "./components/InvestigationPanel";
import { RiskQueue } from "./components/RiskQueue";
import { getDemoDecision, getDemoSessions, getDemoTimeline, replayDemoDecision } from "./demoData";
import { riskLabels } from "./utils";

type WorkspaceMode = "connected" | "demo";
const PAGE_SIZE = 25;

function readSessionKey(): string {
  return sessionStorage.getItem("shadowtrust.analystKey") ?? "";
}

function readAnalystId(): string {
  return sessionStorage.getItem("shadowtrust.analystId") ?? "";
}

export default function App() {
  const [analystKey, setAnalystKey] = useState(readSessionKey);
  const [analystId, setAnalystId] = useState(readAnalystId);
  const [mode, setMode] = useState<WorkspaceMode | null>(analystKey && analystId ? "connected" : null);
  const [minimumRisk, setMinimumRisk] = useState(1);
  const [riskLevel, setRiskLevel] = useState<RiskLevel | "all">("all");
  const [caseFilter, setCaseFilter] = useState<CaseQueueFilter>("all");
  const [page, setPage] = useState(1);
  const [queue, setQueue] = useState<PaginatedSessionRisks>({ page: 1, page_size: PAGE_SIZE, total: 0, items: [], case_counts: { unassigned: 0, open: 0, investigating: 0, confirmed_takeover: 0, false_positive: 0, closed: 0 } });
  const [selected, setSelected] = useState<SessionRiskSummary>();
  const [decision, setDecision] = useState<DetectionDecision>();
  const [replayResult, setReplayResult] = useState<DecisionReplayResult>();
  const [timeline, setTimeline] = useState<SessionTimeline>();
  const [caseData, setCaseData] = useState<AnalystCase>();
  const [demoCases, setDemoCases] = useState<Record<string, AnalystCase>>({});
  const [queueLoading, setQueueLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [replayLoading, setReplayLoading] = useState(false);
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseSaving, setCaseSaving] = useState(false);
  const [error, setError] = useState("");

  const loadQueue = useCallback(async () => {
    if (!mode) return;
    setQueueLoading(true);
    setError("");
    try {
      const result = mode === "demo"
        ? getDemoSessions(minimumRisk, riskLevel, caseFilter, page, PAGE_SIZE, demoCases)
        : await getSessionRisks(analystKey, { minimumRisk, riskLevel, caseStatus: caseFilter, page, pageSize: PAGE_SIZE });
      setQueue(result);
      setSelected((current) =>
        result.items.find((item) => item.session_id === current?.session_id) ?? result.items[0]
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load the analyst queue.");
      setQueue((current) => ({ ...current, items: [], total: 0 }));
      setSelected(undefined);
    } finally {
      setQueueLoading(false);
    }
  }, [analystKey, caseFilter, demoCases, minimumRisk, mode, page, riskLevel]);

  useEffect(() => { void loadQueue(); }, [loadQueue]);

  useEffect(() => {
    if (!selected || !mode) {
      setDecision(undefined);
      setTimeline(undefined);
      setReplayResult(undefined);
      return;
    }
    let active = true;
    setReplayResult(undefined);
    setDetailLoading(true);
    const detailRequest = mode === "demo"
      ? Promise.resolve([getDemoDecision(selected), getDemoTimeline(selected)] as const)
      : Promise.all([
          getDecision(analystKey, selected.decision_id),
          getTimeline(analystKey, selected.session_id)
        ]);
    void detailRequest
      .then(([nextDecision, nextTimeline]) => {
        if (!active) return;
        setDecision(nextDecision);
        setTimeline(nextTimeline);
      })
      .catch((caught) => {
        if (!active) return;
        setError(caught instanceof Error ? caught.message : "Unable to load investigation evidence.");
        setDecision(undefined);
        setTimeline(undefined);
      })
      .finally(() => { if (active) setDetailLoading(false); });
    return () => { active = false; };
  }, [analystKey, mode, selected]);

  useEffect(() => {
    if (!selected || !mode) {
      setCaseData(undefined);
      setCaseLoading(false);
      return;
    }
    if (mode === "demo") {
      setCaseData(demoCases[selected.session_id]);
      setCaseLoading(false);
      return;
    }
    let active = true;
    setCaseData(undefined);
    setCaseLoading(true);
    void getCaseForSession(analystKey, selected.session_id)
      .then((nextCase) => { if (active) setCaseData(nextCase); })
      .catch((caught) => {
        if (!active) return;
        if (caught instanceof ShadowTrustApiError && caught.code === "case_not_found") {
          setCaseData(undefined);
          return;
        }
        setError(caught instanceof Error ? caught.message : "Unable to load the analyst case.");
        setCaseData(undefined);
      })
      .finally(() => { if (active) setCaseLoading(false); });
    return () => { active = false; };
  }, [analystKey, demoCases, mode, selected]);

  const metrics = useMemo(() => {
    const items = queue.items;
    const critical = items.filter((item) => item.risk_level === "critical").length;
    const restricted = items.filter((item) => item.recommended_actions.includes("restrict_session")).length;
    const average = items.length
      ? Math.round(items.reduce((sum, item) => sum + item.risk_after, 0) / items.length)
      : 0;
    return { critical, restricted, average };
  }, [queue.items]);

  function connect(key: string, identity: string) {
    sessionStorage.setItem("shadowtrust.analystKey", key);
    sessionStorage.setItem("shadowtrust.analystId", identity);
    setAnalystKey(key);
    setAnalystId(identity);
    setMode("connected");
  }

  function disconnect() {
    sessionStorage.removeItem("shadowtrust.analystKey");
    sessionStorage.removeItem("shadowtrust.analystId");
    setAnalystKey("");
    setAnalystId("");
    setMode(null);
    setSelected(undefined);
    setCaseData(undefined);
  }

  async function handleOpenCase(note?: string) {
    if (!selected) return;
    setCaseSaving(true);
    setError("");
    try {
      let opened: AnalystCase;
      if (mode === "demo") {
        const now = new Date().toISOString();
        const caseId = crypto.randomUUID();
        opened = {
          id: caseId,
          session_id: selected.session_id,
          status: "open",
          version: 1,
          created_at: now,
          updated_at: now,
          audit_trail: [{
            id: crypto.randomUUID(),
            case_id: caseId,
            sequence: 1,
            previous_status: null,
            new_status: "open",
            actor_id: analystId,
            note: note ?? null,
            occurred_at: now
          }]
        };
        setDemoCases((current) => ({ ...current, [selected.session_id]: opened }));
      } else {
        opened = await openCase(analystKey, analystId, selected.session_id, note);
      }
      setCaseData(opened);
      if (mode === "connected") void loadQueue();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to open the analyst case.");
    } finally {
      setCaseSaving(false);
    }
  }

  async function handleTransitionCase(status: CaseStatus, note: string) {
    if (!caseData || !selected) return;
    setCaseSaving(true);
    setError("");
    try {
      let updated: AnalystCase;
      if (mode === "demo") {
        const now = new Date().toISOString();
        updated = {
          ...caseData,
          status,
          version: caseData.version + 1,
          updated_at: now,
          audit_trail: [...caseData.audit_trail, {
            id: crypto.randomUUID(),
            case_id: caseData.id,
            sequence: caseData.version + 1,
            previous_status: caseData.status,
            new_status: status,
            actor_id: analystId,
            note,
            occurred_at: now
          }]
        };
        setDemoCases((current) => ({ ...current, [selected.session_id]: updated }));
      } else {
        updated = await transitionCase(
          analystKey,
          analystId,
          caseData.id,
          caseData.version,
          status,
          note
        );
      }
      setCaseData(updated);
      if (mode === "connected") void loadQueue();
    } catch (caught) {
      if (
        mode === "connected"
        && caught instanceof ShadowTrustApiError
        && caught.code === "case_version_conflict"
      ) {
        try {
          const current = await getCaseForSession(analystKey, selected.session_id);
          setCaseData(current);
          setError("This case changed in another session. The latest version is now shown.");
        } catch (refreshError) {
          setError(refreshError instanceof Error ? refreshError.message : "Unable to refresh the conflicting case.");
        }
      } else {
        setError(caught instanceof Error ? caught.message : "Unable to update the analyst case.");
      }
    } finally {
      setCaseSaving(false);
    }
  }

  async function handleReplayDecision() {
    if (!selected || !mode) return;
    setReplayLoading(true);
    setError("");
    try {
      const result = mode === "demo"
        ? replayDemoDecision(selected)
        : await replayDecision(analystKey, selected.decision_id);
      setReplayResult(result);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to replay the decision.");
      setReplayResult(undefined);
    } finally {
      setReplayLoading(false);
    }
  }

  if (!mode) return <AccessGate onConnect={connect} onDemo={() => { setAnalystId("demo.analyst"); setMode("demo"); }} />;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><ShieldCheck size={21} /></div>
          <div><strong>ShadowTrust</strong><span>Analyst console</span></div>
        </div>
        <div className="topbar-status">
          <span className={`mode-pill ${mode}`}><Wifi size={13} />{mode === "demo" ? "Synthetic demo" : "API connected"}</span>
          <button className="icon-button" type="button" aria-label="Notifications"><Bell size={17} /></button>
          <button className="analyst-chip" type="button"><CircleUserRound size={18} /><span>{analystId}</span></button>
          <button className="icon-button" type="button" onClick={disconnect} aria-label="Leave workspace"><LogOut size={17} /></button>
        </div>
      </header>

      <aside className="sidebar" aria-label="Primary navigation">
        <button className="nav-button active" type="button" aria-label="Risk overview"><Activity size={19} /></button>
        <button className="nav-button" type="button" aria-label="Search"><Search size={19} /></button>
        <div className="sidebar-spacer" />
        <span className="environment-mark">ST</span>
      </aside>

      <main className="workspace">
        <section className="workspace-heading">
          <div>
            <p className="eyebrow">Account takeover detection</p>
            <h1>Risk operations</h1>
            <p>Prioritized sessions with evidence-backed, replayable decisions.</p>
          </div>
          <button className="refresh-button" type="button" onClick={() => void loadQueue()} disabled={queueLoading}>
            <RefreshCw size={16} className={queueLoading ? "spin" : ""} /> Refresh queue
          </button>
        </section>

        {error && <div className="error-banner" role="alert"><TriangleAlert size={17} /><span>{error}</span></div>}

        <section className="metric-grid" aria-label="Current queue metrics">
          <article><span>Open sessions</span><strong>{queue.total}</strong><small>current filter</small></article>
          <article><span>Critical in view</span><strong className="critical-text">{metrics.critical}</strong><small>immediate review</small></article>
          <article><span>Average risk</span><strong>{metrics.average}</strong><small>visible sessions</small></article>
          <article><span>Restricted</span><strong>{metrics.restricted}</strong><small>session action</small></article>
        </section>

        <section className="filterbar" aria-label="Risk filters">
          <div className="filter-label"><Filter size={15} /><span>Filter queue</span></div>
          <div className="risk-tabs">
            {(["all", "guarded", "elevated", "high", "critical"] as const).map((level) => (
              <button
                type="button"
                key={level}
                className={riskLevel === level ? "active" : ""}
                onClick={() => { setRiskLevel(level); setPage(1); }}
              >{level === "all" ? "All risk" : riskLabels[level]}</button>
            ))}
          </div>
          <label className="score-filter">
            <span>Minimum score <strong>{minimumRisk}</strong></span>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={minimumRisk}
              onChange={(event) => { setMinimumRisk(Number(event.target.value)); setPage(1); }}
            />
          </label>
        </section>

        <section className="case-filterbar" aria-label="Case status filters">
          <span>Case status</span>
          {(["all", "unassigned", "open", "investigating", "confirmed_takeover", "false_positive", "closed"] as const).map((status) => (
            <button
              type="button"
              key={status}
              className={caseFilter === status ? "active" : ""}
              onClick={() => { setCaseFilter(status); setPage(1); }}
            >
              {status === "all" ? "All cases" : status.replaceAll("_", " ")}
              {status !== "all" && <small>{queue.case_counts[status]}</small>}
            </button>
          ))}
        </section>

        <div className="console-grid">
          <RiskQueue
            items={queue.items}
            selectedId={selected?.session_id}
            loading={queueLoading}
            page={page}
            pageSize={PAGE_SIZE}
            total={queue.total}
            onSelect={setSelected}
            onPageChange={setPage}
          />
          <InvestigationPanel
            summary={selected}
            decision={decision}
            replayResult={replayResult}
            timeline={timeline}
            analystId={analystId}
            caseData={caseData}
            loading={detailLoading}
            replayLoading={replayLoading}
            caseLoading={caseLoading}
            caseSaving={caseSaving}
            onOpenCase={handleOpenCase}
            onTransitionCase={handleTransitionCase}
            onReplayDecision={handleReplayDecision}
          />
        </div>
      </main>
    </div>
  );
}
