"""Request-scoped immutable topology views, reused across matrix cells/ranges."""
from .models import CanonicalConfig
from .path_topology import PathTopology
from .topology_graph import build_topology_model


class AnalysisContext:
    def __init__(self, configs: list[CanonicalConfig]):
        self.topology = build_topology_model(configs)
        self.segments = {s.id: s for c in configs for s in c.segments}
        self.devices = {c.device.id: c for c in configs}
        self.configs = configs
        self.graphs: dict[int | None, PathTopology] = {}

    def graph(self, family: int | None) -> PathTopology:
        if family not in self.graphs:
            self.graphs[family] = PathTopology(self.configs, self.topology, family)
        return self.graphs[family]
