from __future__ import annotations

from dataclasses import dataclass

from .base import BaseConfigParser


@dataclass
class Detection:
    parser_id: str
    confidence: float
    parser: type[BaseConfigParser]


class ParserRegistry:
    _parsers: dict[str, type[BaseConfigParser]] = {}

    @classmethod
    def register(cls, parser: type[BaseConfigParser]):
        cls._parsers[parser.parser_id] = parser
        return parser

    @classmethod
    def detect(cls, config: str) -> list[Detection]:
        config = config.lstrip("\ufeff")
        return sorted(
            [Detection(pid, parser.detect(config), parser) for pid, parser in cls._parsers.items()],
            key=lambda x: x.confidence,
            reverse=True,
        )

    @classmethod
    def parse(cls, config: str, source_file: str, parser_id: str | None = None):
        config = config.lstrip("\ufeff")
        ranked = cls.detect(config)
        if parser_id:
            parser = cls._parsers.get(parser_id)
            confidence = parser.detect(config) if parser else 0
        else:
            parser = ranked[0].parser if ranked else None
            confidence = ranked[0].confidence if ranked else 0
        if parser is None or confidence < 0.25:
            raise ValueError("Network OSを特定できません。Network OSを指定してください。")
        result = parser(config, source_file).parse()
        result.device.confidence = round(confidence, 2)
        return result, ranked

    @classmethod
    def capabilities(cls):
        return [p.capabilities for p in cls._parsers.values()]
