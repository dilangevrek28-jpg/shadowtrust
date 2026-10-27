import type { RecommendedAction, RiskLevel } from "./api/types";

export const riskLabels: Record<RiskLevel, string> = {
  low: "Low",
  guarded: "Guarded",
  elevated: "Elevated",
  high: "High",
  critical: "Critical"
};

export const actionLabels: Record<RecommendedAction, string> = {
  allow: "Allow",
  monitor: "Monitor",
  step_up_auth: "Step-up auth",
  hold_transaction: "Hold transaction",
  restrict_session: "Restrict session",
  analyst_review: "Analyst review"
};

export function formatEventName(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(value));
}

export function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

export function shortId(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}
