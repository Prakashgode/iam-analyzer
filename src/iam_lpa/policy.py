from __future__ import annotations

import fnmatch
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_policy_document(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("PolicyDocument"), dict):
        payload = payload["PolicyDocument"]
    if not isinstance(payload, dict):
        raise ValueError("IAM policy must be a JSON object")
    return payload


def extract_allow_action_patterns(
    policy_document: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    patterns: set[str] = set()
    unsupported: list[str] = []

    for statement in _iter_statements(policy_document):
        if str(statement.get("Effect", "")).casefold() != "allow":
            continue
        if "NotAction" in statement:
            unsupported.append("NotAction")
            continue

        action_field = statement.get("Action")
        for action in _normalize_action_field(action_field):
            patterns.add(action)

    return tuple(sorted(patterns)), tuple(sorted(set(unsupported)))


def generate_least_privilege_policy(actions: list[str]) -> dict[str, Any]:
    grouped_actions: dict[str, list[str]] = defaultdict(list)
    for action in sorted(set(actions)):
        service = action.split(":", maxsplit=1)[0]
        grouped_actions[service].append(action)

    statements: list[dict[str, Any]] = []
    for service, service_actions in sorted(grouped_actions.items()):
        statements.append(
            {
                "Sid": f"{_normalize_sid(service)}ObservedAccess",
                "Effect": "Allow",
                "Action": service_actions,
                "Resource": "*",
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


def action_matches_pattern(action: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(action.casefold(), pattern.casefold())


def is_wildcard_pattern(pattern: str) -> bool:
    return "*" in pattern or "?" in pattern


def _iter_statements(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _normalize_action_field(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item.strip()]
    return []


def _normalize_sid(service: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", service).title().replace(" ", "")
    return cleaned or "Observed"
