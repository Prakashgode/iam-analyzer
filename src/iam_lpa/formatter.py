from __future__ import annotations

from .models import AnalysisResult, ComparisonResult


def render_analysis_text(result: AnalysisResult) -> str:
    lines = [
        f"Principal query: {result.principal_query}",
        f"Scanned files: {len(result.scanned_files)}",
        f"CloudTrail events scanned: {result.event_count}",
        f"Events matched: {result.matched_event_count}",
        f"Unique actions observed: {len(result.observed_actions)}",
    ]

    if result.matched_principals:
        lines.append("Matched principals:")
        lines.extend(f"  - {principal}" for principal in result.matched_principals)

    if result.observed_actions:
        lines.append("Observed actions:")
        for action in result.observed_actions:
            suffix = f" last_seen={action.last_seen}" if action.last_seen else ""
            lines.append(f"  - {action.action} x{action.count}{suffix}")
            for resource in action.resources[:3]:
                lines.append(f"      resource: {resource}")
    else:
        lines.append("Observed actions: none")

    if result.risky_observed_actions:
        lines.append("Sensitive observed actions:")
        for finding in result.risky_observed_actions:
            lines.append(f"  - [{finding.severity}] {finding.pattern}: {finding.reason}")

    return "\n".join(lines)


def render_comparison_text(result: ComparisonResult) -> str:
    lines = [
        f"Granted action patterns: {len(result.granted_patterns)}",
        f"Covered observed actions: {len(result.covered_actions)}",
        f"Missing observed actions: {len(result.missing_actions)}",
        f"Unused grants: {len(result.unused_grants)}",
        f"Overbroad grants: {len(result.overbroad_grants)}",
    ]

    if result.missing_actions:
        lines.append("Missing observed actions:")
        lines.extend(f"  - {action}" for action in result.missing_actions)

    if result.unused_grants:
        lines.append("Unused grants:")
        lines.extend(f"  - {pattern}" for pattern in result.unused_grants)

    if result.overbroad_grants:
        lines.append("Overbroad grants:")
        lines.extend(f"  - {pattern}" for pattern in result.overbroad_grants)

    if result.risky_grants:
        lines.append("Risky grants:")
        for finding in result.risky_grants:
            lines.append(f"  - [{finding.severity}] {finding.pattern}: {finding.reason}")

    if result.unsupported_allow_statements:
        lines.append("Unsupported allow statement features:")
        lines.extend(f"  - {feature}" for feature in result.unsupported_allow_statements)

    return "\n".join(lines)

