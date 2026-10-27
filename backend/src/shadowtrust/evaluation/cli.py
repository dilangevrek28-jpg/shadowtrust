"""Command-line evaluation report and quality-gate entry point."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from itertools import count
import json
from pathlib import Path
from uuid import UUID, uuid5

from shadowtrust.detection import build_default_detection_engine
from shadowtrust.evaluation.evaluator import evaluate_corpus
from shadowtrust.synthetic import DatasetSplit, generate_scenarios


EVALUATION_NAMESPACE = UUID("dadb339c-18a5-4e51-a4e8-402a49d11325")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowtrust-evaluate",
        description="Replay the deterministic synthetic corpus and emit JSON metrics.",
    )
    parser.add_argument(
        "--split",
        choices=("development", "evaluation", "all"),
        default="evaluation",
    )
    parser.add_argument("--alert-threshold", type=int, default=70)
    parser.add_argument("--minimum-recall", type=float)
    parser.add_argument("--maximum-false-positive-rate", type=float)
    parser.add_argument("--output", type=Path)
    return parser


def build_evaluation_payload(
    *,
    split: str,
    alert_threshold: int,
    minimum_recall: float | None,
    maximum_false_positive_rate: float | None,
) -> tuple[dict[str, object], bool]:
    scenarios = generate_scenarios()
    if split != "all":
        selected_split = DatasetSplit(split)
        scenarios = tuple(
            scenario for scenario in scenarios if scenario.split is selected_split
        )

    sequence = count(1)
    engine = build_default_detection_engine(
        decision_id_factory=lambda: uuid5(
            EVALUATION_NAMESPACE,
            str(next(sequence)),
        )
    )
    report = evaluate_corpus(
        scenarios,
        engine,
        alert_threshold=alert_threshold,
    )
    criteria: dict[str, float] = {}
    failures: list[str] = []
    if minimum_recall is not None:
        criteria["minimum_recall"] = minimum_recall
        if report.metrics.recall is None or report.metrics.recall < minimum_recall:
            failures.append("recall")
    if maximum_false_positive_rate is not None:
        criteria["maximum_false_positive_rate"] = maximum_false_positive_rate
        if (
            report.metrics.false_positive_rate is None
            or report.metrics.false_positive_rate > maximum_false_positive_rate
        ):
            failures.append("false_positive_rate")

    passed = not failures
    payload: dict[str, object] = {
        "metadata": {
            "corpus_version": "v1",
            "split": split,
            "scenario_count": len(scenarios),
            "engine_version": engine.engine_version,
            "rule_set_version": engine.rule_set_version,
        },
        "quality_gate": {
            "passed": passed,
            "criteria": criteria,
            "failures": failures,
        },
        "report": report.model_dump(mode="json"),
    }
    return payload, passed


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    for name in ("minimum_recall", "maximum_false_positive_rate"):
        value = getattr(args, name)
        if value is not None and not 0 <= value <= 1:
            _parser().error(f"--{name.replace('_', '-')} must be between 0 and 1")

    payload, passed = build_evaluation_payload(
        split=args.split,
        alert_threshold=args.alert_threshold,
        minimum_recall=args.minimum_recall,
        maximum_false_positive_rate=args.maximum_false_positive_rate,
    )
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0 if passed else 1


def run() -> None:
    raise SystemExit(main())
