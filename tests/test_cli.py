from __future__ import annotations

import json
from pathlib import Path

from iam_lpa.cli import main


def test_cli_analyze_writes_policy_and_json(tmp_path: Path, capsys) -> None:
    events_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "cloudtrail"
        / "developer-events.json"
    )
    policy_output = tmp_path / "generated-policy.json"
    json_output = tmp_path / "analysis.json"

    exit_code = main(
        [
            "analyze",
            "--events",
            str(events_path),
            "--principal",
            "AppDeveloperRole",
            "--write-policy",
            str(policy_output),
            "--write-json",
            str(json_output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Observed actions:" in captured.out
    assert policy_output.exists()
    assert json.loads(json_output.read_text(encoding="utf-8"))["matched_event_count"] == 4


def test_cli_compare_policy_json_output(capsys) -> None:
    root = Path(__file__).resolve().parents[1]
    events_path = root / "samples" / "cloudtrail" / "developer-events.json"
    policy_path = root / "samples" / "policies" / "developer-broad-policy.json"

    exit_code = main(
        [
            "compare-policy",
            "--events",
            str(events_path),
            "--principal",
            "AppDeveloperRole",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["comparison"]["missing_actions"] == ["ec2:DescribeInstances"]
    assert payload["analysis"]["principal_query"] == "AppDeveloperRole"
