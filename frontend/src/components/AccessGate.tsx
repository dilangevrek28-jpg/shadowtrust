import { FormEvent, useState } from "react";
import { ArrowRight, Eye, EyeOff, KeyRound, ShieldCheck } from "lucide-react";

interface AccessGateProps {
  onConnect: (key: string, analystId: string) => void;
  onDemo: () => void;
}

export function AccessGate({ onConnect, onDemo }: AccessGateProps) {
  const [key, setKey] = useState("");
  const [analystId, setAnalystId] = useState("");
  const [visible, setVisible] = useState(false);

  function submit(event: FormEvent) {
    event.preventDefault();
    const normalized = key.trim();
    const normalizedId = analystId.trim();
    if (normalized && normalizedId) onConnect(normalized, normalizedId);
  }

  return (
    <main className="access-shell">
      <section className="access-brand" aria-labelledby="access-title">
        <div className="brand-mark large" aria-hidden="true">
          <ShieldCheck size={30} strokeWidth={1.7} />
        </div>
        <div>
          <p className="eyebrow">Adaptive trust operations</p>
          <h1 id="access-title">ShadowTrust</h1>
        </div>
        <p className="access-statement">
          Trace every risk decision from signal to action. Built for analysts who
          need evidence, not a black-box score.
        </p>
        <div className="trust-principles" aria-label="Product principles">
          <span>Explainable</span>
          <span>Deterministic</span>
          <span>Auditable</span>
        </div>
      </section>

      <section className="access-card" aria-label="Analyst access">
        <div className="access-card-icon" aria-hidden="true">
          <KeyRound size={21} />
        </div>
        <p className="eyebrow">Protected workspace</p>
        <h2>Open analyst console</h2>
        <p className="muted">
          Use your analyst ID for the audit trail and the access key configured
          by your ShadowTrust operator. Both stay in this browser session and
          are never written to local storage.
        </p>
        <form onSubmit={submit}>
          <label htmlFor="analyst-id">Analyst ID</label>
          <input
            id="analyst-id"
            className="identity-field"
            type="text"
            value={analystId}
            onChange={(event) => setAnalystId(event.target.value)}
            placeholder="e.g. analyst.one"
            pattern="[A-Za-z0-9][A-Za-z0-9._@-]{2,63}"
            minLength={3}
            maxLength={64}
            autoComplete="username"
            spellCheck={false}
            required
          />
          <label htmlFor="analyst-key">Analyst API key</label>
          <div className="secret-field">
            <input
              id="analyst-key"
              type={visible ? "text" : "password"}
              value={key}
              onChange={(event) => setKey(event.target.value)}
              placeholder="Enter X-Analyst-API-Key"
              autoComplete="off"
              spellCheck={false}
            />
            <button
              type="button"
              className="icon-button"
              onClick={() => setVisible((current) => !current)}
              aria-label={visible ? "Hide API key" : "Show API key"}
            >
              {visible ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
          <button className="primary-button" type="submit" disabled={!key.trim() || !analystId.trim()}>
            Connect securely <ArrowRight size={17} />
          </button>
        </form>
        <div className="access-divider"><span>or inspect locally</span></div>
        <button className="secondary-button" type="button" onClick={onDemo}>
          Use synthetic demo workspace
        </button>
        <p className="demo-disclaimer">
          Demo mode is clearly marked and never sends data to the API.
        </p>
      </section>
    </main>
  );
}
