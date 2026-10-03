"""Verdict aggregation shared by paths and conditioned matrix queries."""
from collections import Counter
from collections.abc import Iterable

from .reachability_models import HopResult, PathResult, PublicVerdict


def aggregate_verdicts(values: Iterable[PublicVerdict], complete: bool = True) -> PublicVerdict:
    distinct = set(values)
    if not complete or len(distinct) > 1:
        return "PARTIAL"
    return next(iter(distinct), "UNKNOWN")


def path_verdict(steps: list[HopResult], routing_uncertain: bool) -> PublicVerdict:
    values = {step.result for step in steps}
    if routing_uncertain or "UNKNOWN" in values:
        return "UNKNOWN"
    if "PARTIAL" in values:
        return "PARTIAL"
    return "ALLOW"


def aggregate_paths(paths: list[PathResult], complete: bool) -> dict:
    """Keep legacy fields representative; only result aggregates all branches."""
    representative = paths[0]
    counts = Counter(path.result for path in paths)
    reason = representative.route_reason
    if not complete:
        reason = "経路探索の上限に達したため、未評価の候補があります"
    elif len(paths) > 1:
        reason = f"{len(paths)}経路を評価: " + ", ".join(f"{v} {counts[v]}" for v in sorted(counts))
    return {
        **representative.model_dump(),
        "result": aggregate_verdicts(counts, complete),
        "route_reason": reason,
        "paths": paths,
        "paths_complete": complete,
    }
