from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_cloudtrail_paths, compare_against_policy
from .formatter import render_analysis_text, render_comparison_text
from .policy import generate_least_privilege_policy, load_policy_document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-lpa",
        description="Generate tighter IAM policies from observed CloudTrail activity.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze CloudTrail logs for one principal.",
    )
    _add_common_arguments(analyze_parser)
    analyze_parser.add_argument(
        "--write-policy",
        type=Path,
        help="Write the generated least-privilege policy JSON to this path.",
    )

    compare_parser = subparsers.add_parser(
        "compare-policy",
        help="Compare observed actions against an existing IAM policy.",
    )
    _add_common_arguments(compare_parser)
    compare_parser.add_argument(
        "--policy",
        type=Path,
        required=True,
        help="Existing IAM policy JSON.",
    )

    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--events",
        type=Path,
        nargs="+",
        required=True,
        help=(
            "CloudTrail JSON file or directory. "
            "Directories are scanned recursively for .json files."
        ),
    )
    parser.add_argument(
        "--principal",
        required=True,
        help=(
            "Substring to match against CloudTrail principal fields "
            "such as ARN, role name, or user name."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--write-json",
        type=Path,
        help="Write the raw analysis or comparison result to this path as JSON.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    analysis = analyze_cloudtrail_paths(paths=args.events, principal_query=args.principal)
    if not analysis.observed_actions:
        parser.exit(2, f"No observed actions found for principal query '{args.principal}'.\n")

    if args.command == "analyze":
        result_payload = analysis.to_dict()
        if args.write_policy:
            policy = generate_least_privilege_policy(
                [action.action for action in analysis.observed_actions]
            )
            _write_json(args.write_policy, policy)
            result_payload["generated_policy_path"] = str(args.write_policy)
        _emit_output(args.format, render_analysis_text(analysis), result_payload, args.write_json)
        return 0

    policy_document = load_policy_document(args.policy)
    comparison = compare_against_policy(analysis, policy_document)
    result_payload = {
        "analysis": analysis.to_dict(),
        "comparison": comparison.to_dict(),
    }
    _emit_output(
        args.format,
        "\n\n".join([render_analysis_text(analysis), render_comparison_text(comparison)]),
        result_payload,
        args.write_json,
    )
    return 0


def _emit_output(
    output_format: str,
    text_payload: str,
    json_payload: dict[str, object],
    output_path: Path | None,
) -> None:
    if output_path is not None:
        _write_json(output_path, json_payload)

    if output_format == "json":
        print(json.dumps(json_payload, indent=2, sort_keys=True))
        return
    print(text_payload)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
