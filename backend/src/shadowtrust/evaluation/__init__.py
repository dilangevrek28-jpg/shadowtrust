"""Detection-quality evaluation for ShadowTrust."""

from shadowtrust.evaluation.evaluator import (
    EvaluationMetrics,
    EvaluationReport,
    ScenarioEvaluation,
    evaluate_corpus,
    evaluate_scenario,
)

__all__ = [
    "EvaluationMetrics",
    "EvaluationReport",
    "ScenarioEvaluation",
    "evaluate_corpus",
    "evaluate_scenario",
]
