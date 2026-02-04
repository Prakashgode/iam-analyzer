"""IAM least-privilege analyzer."""

from .analyzer import analyze_cloudtrail_paths, compare_against_policy

__all__ = ["analyze_cloudtrail_paths", "compare_against_policy"]

