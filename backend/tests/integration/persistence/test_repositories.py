from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from shadowtrust.detection.context import DetectionContext
from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.detection.rules.initial import (
    AccountRecoveryDeviceRegistrationRule,
    NewDeviceRule,
    UnusualCountryRule,
)
from shadowtrust.domain.baselines import UserBaseline
from shadowtrust.persistence import (
    DetectionDecisionRepository,
    SecurityEventRepository,
    UserBaselineRepository,
    build_session_factory,
    create_database_engine,
    create_schema,
    transactional_session,
)
from shadowtrust.persistence.models import RuleEvaluationRecord, SecurityEventRecord
from shadowtrust.synthetic import generate_scenarios


def persistence_stack():
    engine = create_database_engine()
    create_schema(engine)
    return engine, build_session_factory(engine)


def recovery_scenario():
    return next(
        scenario
        for scenario in generate_scenarios()
        if scenario.name == "ato_recovery_device_transfer"
    )


def detection_engine() -> DetectionEngine:
    return DetectionEngine(
        rules=(
            NewDeviceRule(),
            UnusualCountryRule(),
            AccountRecoveryDeviceRegistrationRule(),
        ),
        rule_set_version="2026.5",
        engine_version="0.1.0",
    )


def test_security_event_round_trip_preserves_exact_domain_model() -> None:
    engine, factory = persistence_stack()
    event = recovery_scenario().events[0]

    with transactional_session(factory) as session:
        SecurityEventRepository(session).add(event)

    with transactional_session(factory) as session:
        restored = SecurityEventRepository(session).get(event.id)

    assert restored == event
    engine.dispose()


def test_session_events_are_returned_in_occurrence_order() -> None:
    engine, factory = persistence_stack()
    scenario = recovery_scenario()

    with transactional_session(factory) as session:
        repository = SecurityEventRepository(session)
        for event in reversed(scenario.events):
            repository.add(event)

    with transactional_session(factory) as session:
        restored = SecurityEventRepository(session).list_for_session(
            scenario.events[0].session_id
        )

    assert [event.id for event in restored] == [
        event.id for event in scenario.events
    ]
    engine.dispose()


def test_baseline_versions_round_trip_and_latest_is_selected() -> None:
    engine, factory = persistence_stack()
    original = recovery_scenario().baseline
    newer = UserBaseline(
        user_id=original.user_id,
        version="baseline-2",
        generated_at=original.generated_at + timedelta(days=1),
        sample_size=150,
        known_device_ids=original.known_device_ids,
        known_countries=original.known_countries,
    )

    with transactional_session(factory) as session:
        repository = UserBaselineRepository(session)
        repository.add(original)
        repository.add(newer)

    with transactional_session(factory) as session:
        repository = UserBaselineRepository(session)
        restored_original = repository.get(original.user_id, original.version)
        restored_latest = repository.get_latest(original.user_id)

    assert restored_original == original
    assert restored_latest == newer
    engine.dispose()


def test_decision_and_rule_evaluations_round_trip() -> None:
    engine, factory = persistence_stack()
    scenario = recovery_scenario()
    trigger = scenario.events[0]
    decision = detection_engine().evaluate(
        DetectionContext(
            trigger_event=trigger,
            risk_before=0,
            baseline=scenario.baseline,
        )
    )

    with transactional_session(factory) as session:
        SecurityEventRepository(session).add(trigger)
        UserBaselineRepository(session).add(scenario.baseline)
        DetectionDecisionRepository(session).add(decision)

    with transactional_session(factory) as session:
        restored = DetectionDecisionRepository(session).get(decision.id)
        evaluation_rows = session.scalars(
            select(RuleEvaluationRecord)
            .where(RuleEvaluationRecord.decision_id == str(decision.id))
            .order_by(RuleEvaluationRecord.position)
        ).all()

    assert restored == decision
    assert [row.rule_code for row in evaluation_rows] == [
        evaluation.rule_code for evaluation in decision.evaluations
    ]
    assert [row.position for row in evaluation_rows] == list(
        range(len(decision.evaluations))
    )
    engine.dispose()


def test_decision_requires_persisted_trigger_event() -> None:
    engine, factory = persistence_stack()
    scenario = recovery_scenario()
    decision = detection_engine().evaluate(
        DetectionContext(
            trigger_event=scenario.events[0],
            risk_before=0,
            baseline=scenario.baseline,
        )
    )

    with pytest.raises(IntegrityError):
        with transactional_session(factory) as session:
            DetectionDecisionRepository(session).add(decision)

    with transactional_session(factory) as session:
        restored = DetectionDecisionRepository(session).get(decision.id)

    assert restored is None
    engine.dispose()


def test_duplicate_event_rolls_back_the_whole_transaction() -> None:
    engine, factory = persistence_stack()
    event = recovery_scenario().events[0]

    with pytest.raises(IntegrityError):
        with transactional_session(factory) as session:
            repository = SecurityEventRepository(session)
            repository.add(event)
            repository.add(event)

    with transactional_session(factory) as session:
        count = session.scalar(select(func.count()).select_from(SecurityEventRecord))
        restored = SecurityEventRepository(session).get(event.id)

    assert count == 0
    assert restored is None
    engine.dispose()
