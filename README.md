# IAM Least-Privilege Analyzer

Analyzes CloudTrail activity to figure out what IAM permissions are actually being used, then generates a tighter policy based on real usage. Also compares existing policies against observed behavior to find unused grants and overly broad wildcards.

## Features

- Analyze one principal at a time using ARN, role name, or user name matching
- Read CloudTrail JSON from a file or recursively from a directory
- Generate a least-privilege policy grouped by AWS service
- Compare observed behavior against an existing IAM policy
- Flag risky permissions such as `iam:PassRole`, `sts:AssumeRole`, `kms:Decrypt`, and wildcard grants
- Export analysis or comparison output as JSON for CI or review workflows

## Quick Start

```bash
git clone https://github.com/Prakashgode/iam-analyzer.git
cd iam-analyzer
pip install -e .[dev]
```

## Analyze CloudTrail Usage

```bash
iam-lpa analyze \
--events .\samples\cloudtrail\developer-events.json \
--principal AppDeveloperRole \
--write-policy .\output\developer-least-privilege.json
```

Example output:

```text
Principal query: AppDeveloperRole
Scanned files: 1
CloudTrail events scanned: 5
Events matched: 4
Unique actions observed: 4
Matched principals:
  - AppDeveloperRole
  - arn:aws:iam::123456789012:role/AppDeveloperRole
  - arn:aws:sts::123456789012:assumed-role/AppDeveloperRole/alice
Observed actions:
  - ec2:DescribeInstances x1 last_seen=2026-03-18T11:04:00Z
  - iam:PassRole x1 last_seen=2026-03-18T11:05:00Z
  - s3:GetObject x1 last_seen=2026-03-18T11:01:00Z
  - s3:PutObject x1 last_seen=2026-03-18T11:02:00Z
Sensitive observed actions:
  - [high] iam:PassRole: PassRole can let workloads inherit stronger permissions.
```

## Compare Against an Existing Policy

```bash
iam-lpa compare-policy \
--events .\samples\cloudtrail\developer-events.json \
--principal AppDeveloperRole \
--policy .\samples\policies\developer-broad-policy.json
```

This call highlights:
- observed actions not allowed by the current policy
- unused grants in the current policy
- wildcard patterns that should be tightened
- risky permissions that deserve manual review

## Sample Data

- [developer-events.json](samples/cloudtrail/developer-events.json)
- [developer-broad-policy.json](samples/policies/developer-broad-policy.json)

## Local Quality Checks

```bash
ruff check .
pytest -v
```

## Limitations

- Resource-level scoping is not inferred yet; generated policies use `"Resource": "*"`
- `NotAction`, conditions, and SCP evaluation are not modeled
- CloudTrail only shows what was used, not everything a principal may still need during a rare workflow

