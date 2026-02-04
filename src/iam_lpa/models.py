from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ObservedAction:
    action: str
    count: int
    last_seen: str | None
    resources: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RiskFinding:
    severity: str
    pattern: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisResult:
    principal_query: str
    matched_principals: tuple[str, ...]
    scanned_files: tuple[str, ...]
    event_count: int
    matched_event_count: int
    observed_actions: tuple[ObservedAction, ...]
    risky_observed_actions: tuple[RiskFinding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_query": self.principal_query,
            "matched_principals": list(self.matched_principals),
            "scanned_files": list(self.scanned_files),
            "event_count": self.event_count,
            "matched_event_count": self.matched_event_count,
            "observed_actions": [action.to_dict() for action in self.observed_actions],
            "risky_observed_actions": [
                finding.to_dict() for finding in self.risky_observed_actions
            ],
        }


@dataclass(frozen=True)
class ComparisonResult:
    granted_patterns: tuple[str, ...]
    covered_actions: tuple[str, ...]
    missing_actions: tuple[str, ...]
    unused_grants: tuple[str, ...]
    overbroad_grants: tuple[str, ...]
    risky_grants: tuple[RiskFinding, ...]
    unsupported_allow_statements: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "granted_patterns": list(self.granted_patterns),
            "covered_actions": list(self.covered_actions),
            "missing_actions": list(self.missing_actions),
            "unused_grants": list(self.unused_grants),
            "overbroad_grants": list(self.overbroad_grants),
            "risky_grants": [finding.to_dict() for finding in self.risky_grants],
            "unsupported_allow_statements": list(self.unsupported_allow_statements),
        }
