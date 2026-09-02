"""Backward-compatible public entry points for topology and path analysis."""

from .reachability import analyze_reachability
from .topology_graph import build_topology

__all__ = ["analyze_reachability", "build_topology"]
