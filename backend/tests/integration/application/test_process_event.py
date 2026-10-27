from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from shadowtrust.application import (
    EventConflictError,
    OutOfOrderEventError,
    ProcessSecurityEventService,
)
from shadowtrust.detection import build_default_detection_engine
from shadowtrust.domain.events import parse_security_event
from shadowtrust.persistence import (
    DetectionDecisionRepository,
    SecurityEventRepository,
    UserBaselineRepository,
    build_session_factory,
    create_database_engine,
    create_schema,
    transactional_session,
)
from shadowtrust.persistence.models import (
    DetectionDecisionRecord,
    SecurityEventRecord,
)
from shadowtrust.synthetic import generate_scenarios


def application_stack(*, decision_id_factory=None):
    database_engine = create_database_engine()
    create_schema(database_engine)
    factory = build_session_factory(database_engine)
    detection_engine = (
        build_default_detection_engine()
        if decision_id_factory is None
        else build_default_detection_engine(
            decision_id_factory=decision_id_factory
        )
    )
    service = ProcessSecurityEventService(factory, detection_engine)
    return database_engine, factory, service


def scenario_named(name: str):
    return next(item for item in generate_scenarios() if item.name == name)


def seed_baseline(factory, scenario) -> None:
    with transactional_session(factory) as session:
        UserBaselineRepository(session).add(scenario.baseline)


def test_processes_recovery_timeline_atomically_event_by_event() -> None:
    database_engine, factory, service = application_stack()
    scenario = scenario_named("ato_recovery_device_transfer")
    seed_baseline(factory, scenario)

    results = [service.process(event) for event in scenario.events]

    assert [result.created for result in results] == [True, True, True, True]
    assert [result.decision.risk_after for result in results] == [60, 60, 60, 100]
    with transactional_session(factory) as session:
        event_count = session.scalar(
            select(func.count()).select_from(SecurityEventRecord)
        )
        decision_count = session.scalar(
            select(func.count()).select_from(DetectionDecisionRecord)
        )
        stored_decisions = DetectionDecisionRepository(session).list_for_session(
            scenario.events[0].session_id
        )

    assert event_count == 4
    assert decision_count == 4
    assert [decision.risk_after for decision in stored_decisions] == [60, 60, 60, 100]
    database_engine.dispose()


def test_retrying_the_same_event_returns_the_existing_result() -> None:
    database_engine, factory, service = application_stack()
    scenario = scenario_named("normal_regular_login")
    seed_baseline(factory, scenario)
    event = scenario.events[0]

    first = service.process(event)
    retry = service.process(event)

    assert first.created is True
    assert retry.created is False
    assert retry.event == first.event
    assert retry.decision == first.decision
    with transactional_session(factory) as session:
        event_count = session.scalar(
            select(func.count()).select_from(SecurityEventRecord)
        )
        decision_count = session.scalar(
            select(func.count()).select_from(DetectionDecisionRecord)
        )
    assert event_count == 1
    assert decision_count == 1
    database_engine.dispose()


def test_same_event_id_with_different_content_is_rejected() -> None:
    database_engine, factory, service = application_stack()
    scenario = scenario_named("normal_regular_login")
    seed_baseline(factory, scenario)
    event = scenario.events[0]
    altered_data = event.model_dump(mode="json")
    altered_data["geo_country"] = "US"
    altered_event = parse_security_event(altered_data)
    service.process(event)

    with pytest.raises(EventConflictError, match="different content"):
        service.process(altered_event)

    with transactional_session(factory) as session:
        restored = SecurityEventRepository(session).get(event.id)
    assert restored == event
    database_engine.dispose()


def test_out_of_order_event_is_rejected_without_persistence() -> None:
    database_engine, factory, service = application_stack()
    scenario = scenario_named("ato_recovery_device_transfer")
    seed_baseline(factory, scenario)
    later_event = scenario.events[1]
    earlier_event = scenario.events[0]
    service.process(later_event)

    with pytest.raises(OutOfOrderEventError, match="occurred before"):
        service.process(earlier_event)

    with transactional_session(factory) as session:
        assert SecurityEventRepository(session).get(earlier_event.id) is None
        assert SecurityEventRepository(session).get(later_event.id) == later_event
    database_engine.dispose()


def test_sessionless_event_is_persisted_without_a_decision() -> None:
    database_engine, factory, service = application_stack()
    source = scenario_named("ato_credential_stuffing_transfer").events[0]
    event_data = source.model_dump(mode="json")
    event_data["session_id"] = None
    event = parse_security_event(event_data)

    result = service.process(event)

    assert result.created is True
    assert result.decision is None
    with transactional_session(factory) as session:
        restored = SecurityEventRepository(session).get(event.id)
        decision_count = session.scalar(
            select(func.count()).select_from(DetectionDecisionRecord)
        )
    assert restored == event
    assert decision_count == 0
    database_engine.dispose()


def test_event_without_baseline_still_receives_a_decision() -> None:
    database_engine, _factory, service = application_stack()
    event = scenario_named("normal_regular_login").events[0]

    result = service.process(event)

    assert result.decision is not None
    assert result.decision.risk_after == 0
    assert result.decision.baseline_version is None
    database_engine.dispose()


def test_decision_failure_rolls_back_the_trigger_event() -> None:
    fixed_decision_id = UUID("50000000-0000-4000-8000-000000000001")
    database_engine, factory, service = application_stack(
        decision_id_factory=lambda: fixed_decision_id
    )
    scenario = scenario_named("normal_travel_with_mfa")
    seed_baseline(factory, scenario)
    first_event, second_event = scenario.events
    service.process(first_event)

    with pytest.raises(IntegrityError):
        service.process(second_event)

    with transactional_session(factory) as session:
        assert SecurityEventRepository(session).get(first_event.id) == first_event
        assert SecurityEventRepository(session).get(second_event.id) is None
        decision_count = session.scalar(
            select(func.count()).select_from(DetectionDecisionRecord)
        )
    assert decision_count == 1
    database_engine.dispose()
