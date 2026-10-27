import json

from shadowtrust.evaluation.cli import build_evaluation_payload, main


def test_evaluation_payload_is_deterministic_and_separates_holdout_split() -> None:
    first, first_passed = build_evaluation_payload(
        split="evaluation",
        alert_threshold=70,
        minimum_recall=1.0,
        maximum_false_positive_rate=0.0,
    )
    second, second_passed = build_evaluation_payload(
        split="evaluation",
        alert_threshold=70,
        minimum_recall=1.0,
        maximum_false_positive_rate=0.0,
    )

    assert first == second
    assert first_passed is second_passed is True
    assert first["metadata"]["scenario_count"] == 4
    assert first["quality_gate"] == {
        "passed": True,
        "criteria": {
            "minimum_recall": 1.0,
            "maximum_false_positive_rate": 0.0,
        },
        "failures": [],
    }


def test_cli_prints_json_report_to_stdout(capsys) -> None:
    exit_code = main(["--split", "evaluation"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["metadata"]["split"] == "evaluation"
    assert payload["report"]["metrics"]["precision"] == 1.0
    assert payload["report"]["metrics"]["recall"] == 1.0


def test_cli_writes_report_and_fails_an_unmet_quality_gate(tmp_path) -> None:
    output = tmp_path / "reports" / "evaluation.json"

    exit_code = main(
        [
            "--split",
            "evaluation",
            "--alert-threshold",
            "100",
            "--minimum-recall",
            "1.0",
            "--output",
            str(output),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 1
    assert payload["quality_gate"]["passed"] is False
    assert payload["quality_gate"]["failures"] == ["recall"]
