from __future__ import annotations

from pathlib import Path

from .cloudtrail import (
    event_timestamp,
    event_to_action,
    extract_principal_candidates,
    extract_resources,
    load_events,
    matches_principal,
)
from .models import AnalysisResult, ComparisonResult, ObservedAction
from .policy import action_matches_pattern, extract_allow_action_patterns
from .risk import find_risky_patterns


def analyze_cloudtrail_paths(paths: list[Path], principal_query: str) -> AnalysisResult:
    events, scanned_files = load_events(paths)
    matched_events = [event for event in events if matches_principal(event, principal_query)]

    action_counts: dict[str, int] = {}
    action_last_seen: dict[str, str | None] = {}
    action_resources: dict[str, set[str]] = {}
    matched_principals: set[str] = set()

    for event in matched_events:
        matched_principals.update(extract_principal_candidates(event))
        action = event_to_action(event)
        if action is None:
            continue

        action_counts[action] = action_counts.get(action, 0) + 1
        seen_at = event_timestamp(event)
        previous_seen_at = action_last_seen.get(action)
        if seen_at and (previous_seen_at is None or seen_at > previous_seen_at):
            action_last_seen[action] = seen_at
        action_resources.setdefault(action, set()).update(extract_resources(event))

    observed_actions = tuple(
        ObservedAction(
            action=action,
            count=action_counts[action],
            last_seen=action_last_seen.get(action),
            resources=tuple(sorted(action_resources.get(action, set()))),
        )
        for action in sorted(action_counts)
    )

    risky_observed_actions = find_risky_patterns([action.action for action in observed_actions])

    return AnalysisResult(
        principal_query=principal_query,
        matched_principals=tuple(sorted(matched_principals)),
        scanned_files=tuple(scanned_files),
        event_count=len(events),
        matched_event_count=len(matched_events),
        observed_actions=observed_actions,
        risky_observed_actions=risky_observed_actions,
    )


def compare_against_policy(
    analysis: AnalysisResult,
    policy_document: dict[str, object],
) -> ComparisonResult:
    granted_patterns, unsupported_allow_statements = extract_allow_action_patterns(policy_document)
    observed_actions = [action.action for action in analysis.observed_actions]

    covered_actions = tuple(
        action
        for action in observed_actions
        if any(
            action_matches_pattern(action, pattern)
            for pattern in granted_patterns
        )
    )
    missing_actions = tuple(action for action in observed_actions if action not in covered_actions)
    unused_grants = tuple(
        pattern
        for pattern in granted_patterns
        if not any(
            action_matches_pattern(action, pattern)
            for action in observed_actions
        )
    )
    overbroad_grants = tuple(
        pattern
        for pattern in granted_patterns
        if "*" in pattern or "?" in pattern
    )
    risky_grants = find_risky_patterns(list(granted_patterns))

    return ComparisonResult(
        granted_patterns=granted_patterns,
        covered_actions=tuple(sorted(covered_actions)),
        missing_actions=tuple(sorted(missing_actions)),
        unused_grants=tuple(sorted(unused_grants)),
        overbroad_grants=tuple(sorted(overbroad_grants)),
        risky_grants=risky_grants,
        unsupported_allow_statements=unsupported_allow_statements,
    )
