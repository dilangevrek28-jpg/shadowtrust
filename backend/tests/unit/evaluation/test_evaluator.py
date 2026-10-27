import pytest

from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.detection.rules.initial import (
    AccountRecoveryDeviceRegistrationRule,
    NewDeviceRule,
    PasswordBeneficiaryTransferRule,
    RecoveryDeviceThenTransferRule,
    RepeatedMfaFailuresThenApprovalRule,
    RepeatedInvalidCredentialsThenSuccessRule,
    SessionContextSwitchBeforeTransferRule,
    UnusualCountryRule,
)
from shadowtrust.domain.decisions import RiskLevel
from shadowtrust.evaluation.evaluator import evaluate_corpus, evaluate_scenario
from shadowtrust.synthetic.scenarios import (
    DatasetSplit,
    ScenarioGroundTruth,
    generate_scenarios,
)


def initial_engine() -> DetectionEngine:
    return DetectionEngine(
        rules=(
            NewDeviceRule(),
            UnusualCountryRule(),
            PasswordBeneficiaryTransferRule(),
            AccountRecoveryDeviceRegistrationRule(),
            RecoveryDeviceThenTransferRule(),
            RepeatedMfaFailuresThenApprovalRule(),
            RepeatedInvalidCredentialsThenSuccessRule(),
            SessionContextSwitchBeforeTransferRule(),
        ),
        rule_set_version="2026.5",
        engine_version="0.1.0",
    )


def scenarios_for(split: DatasetSplit):
    return tuple(
        scenario for scenario in generate_scenarios() if scenario.split is split
    )


def test_evaluation_split_exposes_current_rule_limitations() -> None:
    report = evaluate_corpus(
        scenarios_for(DatasetSplit.EVALUATION),
        initial_engine(),
    )

    assert report.metrics.true_positives == 2
    assert report.metrics.false_positives == 0
    assert report.metrics.true_negatives == 2
    assert report.metrics.false_negatives == 0
    assert report.metrics.precision == 1.0
    assert report.metrics.recall == 1.0
    assert report.metrics.false_positive_rate == 0.0
    assert report.metrics.average_detection_latency_seconds == 750.0
    assert report.metrics.unnecessary_step_up_count == 0
    assert report.metrics.total_decisions == 16


def test_full_corpus_metrics_are_reproducible() -> None:
    report = evaluate_corpus(generate_scenarios(), initial_engine())

    assert report.metrics.true_positives == 6
    assert report.metrics.false_positives == 0
    assert report.metrics.true_negatives == 5
    assert report.metrics.false_negatives == 0
    assert report.metrics.precision == 1.0
    assert report.metrics.recall == 1.0
    assert report.metrics.false_positive_rate == 0.0
    assert report.metrics.total_decisions == 40


def test_recovery_attack_timeline_carries_risk_without_double_scoring() -> None:
    scenario = next(
        item
        for item in generate_scenarios()
        if item.name == "ato_recovery_device_transfer"
    )

    outcome = evaluate_scenario(scenario, initial_engine())

    assert [decision.risk_after for decision in outcome.decisions] == [60, 60, 60, 100]
    assert outcome.predicted is ScenarioGroundTruth.ATO
    assert outcome.decisions[-1].risk_level is RiskLevel.CRITICAL
    assert outcome.first_alert_event_id == scenario.events[-1].id
    assert outcome.detection_latency_seconds == 1200.0


def test_trusted_device_sequence_is_now_detected() -> None:
    scenario = next(
        item
        for item in generate_scenarios()
        if item.name == "ato_trusted_device_misuse"
    )

    outcome = evaluate_scenario(scenario, initial_engine())

    assert outcome.ground_truth is ScenarioGroundTruth.ATO
    assert outcome.predicted is ScenarioGroundTruth.ATO
    assert [decision.risk_after for decision in outcome.decisions] == [0, 0, 0, 70]
    assert outcome.first_alert_event_id == scenario.events[-1].id
    assert outcome.detection_latency_seconds == 120.0


def test_metrics_are_undefined_when_their_denominator_is_zero() -> None:
    normal_only = tuple(
        scenario
        for scenario in generate_scenarios()
        if scenario.ground_truth is ScenarioGroundTruth.NORMAL
    )

    report = evaluate_corpus(normal_only, initial_engine())

    assert report.metrics.precision is None
    assert report.metrics.recall is None
    assert report.metrics.false_positive_rate == 0.0


def test_rejects_empty_or_duplicate_corpus() -> None:
    engine = initial_engine()
    scenario = generate_scenarios()[0]

    with pytest.raises(ValueError, match="cannot be empty"):
        evaluate_corpus((), engine)
    with pytest.raises(ValueError, match="duplicate scenarios"):
        evaluate_corpus((scenario, scenario), engine)


def test_rejects_alert_threshold_outside_risk_range() -> None:
    scenario = generate_scenarios()[0]

    with pytest.raises(ValueError, match="between 0 and 100"):
        evaluate_scenario(scenario, initial_engine(), alert_threshold=101)






def test_mfa_fatigue_holdout_is_detected() -> None:
    scenario = next(
        item
        for item in generate_scenarios()
        if item.name == "ato_mfa_fatigue_holdout"
    )

    outcome = evaluate_scenario(scenario, initial_engine())

    assert [decision.risk_after for decision in outcome.decisions] == [
        35,
        35,
        35,
        35,
        35,
        70,
        70,
        70,
    ]
    assert outcome.predicted is ScenarioGroundTruth.ATO
    assert outcome.first_alert_event_id == scenario.events[5].id
    assert outcome.detection_latency_seconds == 300.0


def test_credential_stuffing_development_scenario_is_detected() -> None:
    scenario = next(
        item
        for item in generate_scenarios()
        if item.name == "ato_credential_stuffing_transfer"
    )

    outcome = evaluate_scenario(scenario, initial_engine())

    assert [decision.risk_after for decision in outcome.decisions] == [
        35,
        35,
        35,
        70,
        70,
        70,
    ]
    assert outcome.predicted is ScenarioGroundTruth.ATO
    assert outcome.first_alert_event_id == scenario.events[3].id
    assert outcome.detection_latency_seconds == 180.0


def test_session_hijacking_development_scenario_is_detected() -> None:
    scenario = next(
        item
        for item in generate_scenarios()
        if item.name == "ato_session_hijacking"
    )

    outcome = evaluate_scenario(scenario, initial_engine())

    assert [decision.risk_after for decision in outcome.decisions] == [0, 70]
    assert outcome.predicted is ScenarioGroundTruth.ATO
    assert outcome.first_alert_event_id == scenario.events[1].id
    assert outcome.detection_latency_seconds == 0.0
