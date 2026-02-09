from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SERVICE_PREFIX_OVERRIDES: dict[str, str | None] = {
    "logs.amazonaws.com": "logs",
    "monitoring.amazonaws.com": "cloudwatch",
    "events.amazonaws.com": "events",
    "signin.amazonaws.com": None,
}


def discover_json_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(
                sorted(
                    candidate
                    for candidate in path.rglob("*.json")
                    if candidate.is_file()
                )
            )
            continue
        if path.is_file():
            files.append(path)
            continue
        raise FileNotFoundError(f"CloudTrail input not found: {path}")
    return files


def load_events(paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    scanned_files: list[str] = []
    for file_path in discover_json_files(paths):
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        events.extend(_normalize_payload(payload))
        scanned_files.append(str(file_path))
    return events, scanned_files


def _normalize_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("Records"), list):
            return [record for record in payload["Records"] if isinstance(record, dict)]
        return [payload]
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]
    raise ValueError("CloudTrail input must be a JSON object or list of objects")


def extract_principal_candidates(event: dict[str, Any]) -> tuple[str, ...]:
    identity = event.get("userIdentity")
    if not isinstance(identity, dict):
        return ()

    session_context = identity.get("sessionContext")
    issuer = session_context.get("sessionIssuer") if isinstance(session_context, dict) else {}
    if not isinstance(issuer, dict):
        issuer = {}

    values = {
        value.strip()
        for value in (
            _as_string(identity.get("arn")),
            _as_string(identity.get("userName")),
            _as_string(issuer.get("arn")),
            _as_string(issuer.get("userName")),
        )
        if value
    }
    return tuple(sorted(values))


def matches_principal(event: dict[str, Any], principal_query: str) -> bool:
    needle = principal_query.casefold()
    return any(needle in candidate.casefold() for candidate in extract_principal_candidates(event))


def event_to_action(event: dict[str, Any]) -> str | None:
    event_name = _as_string(event.get("eventName"))
    event_source = _as_string(event.get("eventSource"))
    if not event_name or not event_source:
        return None

    prefix = _SERVICE_PREFIX_OVERRIDES.get(event_source.casefold())
    if prefix is None and event_source.casefold() in _SERVICE_PREFIX_OVERRIDES:
        return None
    if prefix is None:
        prefix = event_source.split(".", maxsplit=1)[0]
    return f"{prefix}:{event_name}"


def event_timestamp(event: dict[str, Any]) -> str | None:
    return _as_string(event.get("eventTime"))


def extract_resources(event: dict[str, Any]) -> tuple[str, ...]:
    raw_resources = event.get("resources")
    if not isinstance(raw_resources, list):
        return ()

    values: set[str] = set()
    for resource in raw_resources:
        if not isinstance(resource, dict):
            continue
        for key in ("ARN", "arn"):
            resource_arn = _as_string(resource.get(key))
            if resource_arn:
                values.add(resource_arn)
    return tuple(sorted(values))


def _as_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
