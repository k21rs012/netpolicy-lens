from .registry import ParserRegistry
from . import campus, cisco, fortios, juniper, panos, phase4, vyos, yamaha  # noqa: F401

__all__ = ["ParserRegistry"]
