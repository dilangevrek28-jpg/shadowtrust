from collections import Counter

from shadowtrust.synthetic.scenarios import (
    DatasetSplit,
    ScenarioGroundTruth,
    generate_scenarios,
)


def test_generates_five_normal_and_six_ato_scenarios() -> None:
    scenarios = generate_scenarios()
    counts = Counter(scenario.ground_truth for scenario in scenarios)

    assert len(scenarios) == 11
    assert counts[ScenarioGroundTruth.NORMAL] == 5
    assert counts[ScenarioGroundTruth.ATO] == 6


def test_development_and_evaluation_splits_are_separate_and_balanced() -> None:
    scenarios = generate_scenarios()
    development = [
        scenario for scenario in scenarios if scenario.split is DatasetSplit.DEVELOPMENT
    ]
    evaluation = [
        scenario for scenario in scenarios if scenario.split is DatasetSplit.EVALUATION
    ]

    assert len(development) == 7
    assert len(evaluation) == 4
    assert {scenario.name for scenario in development}.isdisjoint(
        scenario.name for scenario in evaluation
    )
    assert Counter(item.ground_truth for item in development) == {
        ScenarioGroundTruth.NORMAL: 3,
        ScenarioGroundTruth.ATO: 4,
    }
    assert Counter(item.ground_truth for item in evaluation) == {
        ScenarioGroundTruth.NORMAL: 2,
        ScenarioGroundTruth.ATO: 2,
    }


def test_generation_is_deterministic() -> None:
    first = generate_scenarios()
    second = generate_scenarios()

    assert first == second
    assert [scenario.id for scenario in first] == [scenario.id for scenario in second]


def test_all_scenario_and_event_ids_are_globally_unique() -> None:
    scenarios = generate_scenarios()
    scenario_ids = [scenario.id for scenario in scenarios]
    event_ids = [event.id for scenario in scenarios for event in scenario.events]

    assert len(scenario_ids) == len(set(scenario_ids))
    assert len(event_ids) == len(set(event_ids))


def test_ground_truth_never_appears_inside_canonical_events() -> None:
    for scenario in generate_scenarios():
        for event in scenario.events:
            event_data = event.model_dump(mode="json")
            assert "ground_truth" not in event_data
            assert "label" not in event_data
            assert scenario.ground_truth.value not in event_data.values()


def test_ato_attack_start_references_its_own_event() -> None:
    for scenario in generate_scenarios():
        event_ids = {event.id for event in scenario.events}
        if scenario.ground_truth is ScenarioGroundTruth.ATO:
            assert scenario.attack_start_event_id in event_ids
        else:
            assert scenario.attack_start_event_id is None


def test_scenarios_are_chronological_and_match_their_baseline_user() -> None:
    for scenario in generate_scenarios():
        occurred_at = [event.occurred_at for event in scenario.events]

        assert occurred_at == sorted(occurred_at)
        assert all(
            event.user_id == scenario.baseline.user_id for event in scenario.events
        )


def test_corpus_contains_required_behaviour_families() -> None:
    scenarios = {scenario.name: scenario for scenario in generate_scenarios()}

    assert "normal_regular_login" in scenarios
    assert "normal_travel_with_mfa" in scenarios
    assert "normal_new_phone" in scenarios
    assert "normal_high_value_transfer" in scenarios
    assert "normal_password_change" in scenarios
    assert "ato_credential_stuffing_transfer" in scenarios
    assert "ato_session_hijacking" in scenarios
    assert "ato_mfa_fatigue" in scenarios
    assert "ato_mfa_fatigue_holdout" in scenarios
    assert "ato_trusted_device_misuse" in scenarios
    assert "ato_recovery_device_transfer" in scenarios
