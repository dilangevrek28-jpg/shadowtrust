# Security policy

ShadowTrust is a synthetic defensive-security project. It must not be connected
to a real bank, customer account, production identity provider, or real customer
data source.

## Supported version

The latest revision of the default branch is supported. Earlier snapshots are
educational history and do not receive security fixes.

## Reporting a vulnerability

Use GitHub private vulnerability reporting when it is enabled for the
repository. Do not open a public issue for an unpatched vulnerability and do
not include credentials, API keys, customer information, or exploit data from
systems you do not own.

A useful report includes the affected component, reproduction steps using only
synthetic data, expected and observed behavior, security impact, and a proposed
mitigation when known. Do not perform denial-of-service testing or access any
system outside your own authorized laboratory.

## Secret handling

- Commit `.env.example`, never `.env`.
- Use separate ingestion, analyst, metrics, and Grafana credentials.
- Rotate a credential immediately if it appears in source, logs, screenshots,
  issues, or CI output.
- Treat the development API-key mechanism as an MVP boundary, not a replacement
  for production identity, short-lived tokens, RBAC, or a secrets manager.
