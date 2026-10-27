"""Thread-safe, dependency-free Prometheus counters."""

from __future__ import annotations

from collections import defaultdict
from threading import Lock


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class MetricsRegistry:
    def __init__(self) -> None:
        self._values: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._lock = Lock()

    def increment(self, name: str, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._values[key] += 1

    def render(self) -> str:
        descriptions = {
            "shadowtrust_events_processed_total": "Security events processed by outcome.",
            "shadowtrust_decisions_total": "Detection decisions produced by risk level.",
            "shadowtrust_cases_opened_total": "Analyst cases opened.",
            "shadowtrust_case_transitions_total": "Analyst case status transitions.",
            "shadowtrust_decision_replays_total": "Historical decision replay outcomes.",
        }
        with self._lock:
            snapshot = sorted(self._values.items())
        lines: list[str] = []
        for name, description in descriptions.items():
            lines.extend((f"# HELP {name} {description}", f"# TYPE {name} counter"))
            matching = [(labels, value) for (metric, labels), value in snapshot if metric == name]
            if not matching:
                lines.append(f"{name} 0")
            for labels, value in matching:
                suffix = ""
                if labels:
                    encoded = ",".join(
                        f'{key}="{_escape_label(label)}"'
                        for key, label in labels
                    )
                    suffix = "{" + encoded + "}"
                lines.append(f"{name}{suffix} {value}")
        return "\n".join(lines) + "\n"
