# ShadowTrust monitoring

The local monitoring stack turns the API's bounded Prometheus counters into
time-series history, visual panels, and starter alert states.

## Data path

1. The API exposes protected counters at `http://api:8000/metrics`.
2. Prometheus reads `X-Metrics-API-Key` from its Compose secret file and scrapes
   the API every 15 seconds.
3. Prometheus evaluates `prometheus/rules/shadowtrust-alerts.yml` every 15
   seconds and stores samples in its named volume for 15 days.
4. Grafana queries Prometheus over the internal Compose network and loads the
   version-controlled dashboard automatically.

Prometheus is not published to the host. Grafana binds only to `127.0.0.1`,
requires an administrator password, disables anonymous access and sign-up, and
stores its mutable state separately from the read-only dashboard definition.

## Alert meanings

- `ShadowTrustMetricsTargetDown`: the API could not be scraped for two minutes.
- `ShadowTrustCriticalDecisionBurst`: five critical decisions appeared within
  five minutes.
- `ShadowTrustConfirmedTakeoverBurst`: analysts confirmed three takeovers
  within ten minutes.
- `ShadowTrustEventReplaySpike`: twenty duplicate event deliveries occurred
  within ten minutes.
- `ShadowTrustDecisionReplayMismatch`: at least one historical decision drifted
  or could not run faithfully on the active engine within fifteen minutes.

These thresholds are defensible laboratory starting points, not production
truth. Tune them against a measured normal-traffic baseline and record every
change. Alert rules produce pending/firing state in Prometheus and Grafana;
external notification delivery requires a separately configured Alertmanager
or Grafana contact point.
