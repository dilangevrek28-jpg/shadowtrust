from shadowtrust.observability import MetricsRegistry


def test_registry_renders_declared_counters_with_zero_defaults() -> None:
    output = MetricsRegistry().render()

    assert "# TYPE shadowtrust_events_processed_total counter" in output
    assert "shadowtrust_events_processed_total 0" in output
    assert "shadowtrust_decisions_total 0" in output
    assert "shadowtrust_cases_opened_total 0" in output
    assert "shadowtrust_case_transitions_total 0" in output
    assert "shadowtrust_decision_replays_total 0" in output
    assert output.endswith("\n")


def test_registry_counts_sorted_labels_and_escapes_prometheus_text() -> None:
    registry = MetricsRegistry()

    registry.increment(
        "shadowtrust_case_transitions_total",
        previous_status='open\\review"queue\nnext',
        new_status="investigating",
    )
    registry.increment(
        "shadowtrust_case_transitions_total",
        new_status="investigating",
        previous_status='open\\review"queue\nnext',
    )

    assert (
        'shadowtrust_case_transitions_total{new_status="investigating",'
        'previous_status="open\\\\review\\"queue\\nnext"} 2'
        in registry.render()
    )
