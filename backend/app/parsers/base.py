from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import CanonicalConfig, ParserCapabilities, Trace


class BaseConfigParser(ABC):
    parser_id: str
    capabilities: ParserCapabilities

    @classmethod
    @abstractmethod
    def detect(cls, config: str) -> float: ...

    def __init__(self, config: str, source_file: str):
        self.config = config
        self.source_file = Path(source_file).name
        self.lines = config.splitlines()

    def trace(self, line: int, raw: str, end: int | None = None) -> Trace:
        return Trace(source_file=self.source_file, line_start=line, line_end=end or line, raw_config=raw.strip())

    @abstractmethod
    def parse(self) -> CanonicalConfig: ...

