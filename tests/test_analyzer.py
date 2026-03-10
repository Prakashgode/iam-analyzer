from __future__ import annotations

import json
from pathlib import Path

from iam_lpa.analyzer import analyze_cloudtrail_paths, compare_against_policy
from iam_lpa.policy import generate_least_privilege_policy, load_policy_document


def test_analyze_cloudtrail_filters_principal_and_extracts_actions() -> None:
    fixture = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "cloudtrail"
        / "developer-events.json"
    )
    result = analyze_cloudtrail_paths([fixture], "AppDeveloperRole")

    assert result.event_count == 5
    assert result.matched_event_count == 4
    assert [action.action for action in result.observed_actions] == [
        "ec2:DescribeInstances",
        "iam:PassRole",
        "s3:GetObject",
        "s3:PutObject",
    ]
    assert any(finding.pattern == "iam:PassRole" for finding in result.risky_observed_actions)


def test_generate_least_privilege_policy_groups_actions_by_service() -> None:
    policy = generate_least_privilege_policy(
        ["s3:GetObject", "s3:PutObject", "iam:PassRole", "ec2:DescribeInstances"]
    )

    statements = policy["Statement"]
    assert len(statements) == 3
    assert statements[0]["Sid"] == "Ec2ObservedAccess"
    assert statements[1]["Action"] == ["iam:PassRole"]
    assert statements[2]["Action"] == ["s3:GetObject", "s3:PutObject"]


def test_compare_policy_identifies_missing_unused_and_overbroad_grants() -> None:
    events_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "cloudtrail"
        / "developer-events.json"
    )
    policy_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "policies"
        / "developer-broad-policy.json"
    )

    analysis = analyze_cloudtrail_paths([events_path], "AppDeveloperRole")
    comparison = compare_against_policy(analysis, load_policy_document(policy_path))

    assert comparison.missing_actions == ("ec2:DescribeInstances",)
    assert comparison.unused_grants == ("logs:CreateLogGroup",)
    assert comparison.overbroad_grants == ("iam:*", "s3:*")
    assert any(finding.pattern == "iam:*" for finding in comparison.risky_grants)


def test_compare_policy_marks_notaction_as_unsupported(tmp_path: Path) -> None:
    events_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "cloudtrail"
        / "developer-events.json"
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "NotAction": "iam:DeleteUser", "Resource": "*"}],
            }
        ),
        encoding="utf-8",
    )

    analysis = analyze_cloudtrail_paths([events_path], "AppDeveloperRole")
    comparison = compare_against_policy(analysis, load_policy_document(policy_path))

    assert comparison.unsupported_allow_statements == ("NotAction",)
