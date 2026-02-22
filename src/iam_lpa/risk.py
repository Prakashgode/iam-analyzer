from __future__ import annotations

from .models import RiskFinding
from .policy import is_wildcard_pattern

_SENSITIVE_PATTERNS: dict[str, tuple[str, str]] = {
    "*": ("high", "Full administrator access across the account."),
    "iam:*": ("high", "Full IAM administration can lead to privilege escalation."),
    "iam:PassRole": ("high", "PassRole can let workloads inherit stronger permissions."),
    "sts:AssumeRole": ("high", "AssumeRole can pivot into more privileged roles."),
    "kms:Decrypt": ("high", "Decrypt grants access to protected data and secrets."),
    "secretsmanager:GetSecretValue": ("high", "Reads application secrets directly."),
    "ec2:AuthorizeSecurityGroupIngress": ("medium", "Can expose workloads to the internet."),
    "lambda:UpdateFunctionCode": ("medium", "Can replace deployed Lambda code."),
}

_NORMALIZED_SENSITIVE_PATTERNS = {
    pattern.casefold(): details for pattern, details in _SENSITIVE_PATTERNS.items()
}


def find_risky_patterns(patterns: list[str]) -> tuple[RiskFinding, ...]:
    findings: list[RiskFinding] = []
    for pattern in patterns:
        lowered = pattern.casefold()
        if lowered in _NORMALIZED_SENSITIVE_PATTERNS:
            severity, reason = _NORMALIZED_SENSITIVE_PATTERNS[lowered]
            findings.append(RiskFinding(severity=severity, pattern=pattern, reason=reason))
            continue
        if is_wildcard_pattern(pattern):
            severity = "medium"
            if lowered.endswith(":*"):
                severity = "high" if lowered.startswith(("iam:", "kms:", "sts:")) else "medium"
            findings.append(
                RiskFinding(
                    severity=severity,
                    pattern=pattern,
                    reason="Wildcard permissions make least-privilege review harder.",
                )
            )
    return tuple(findings)
