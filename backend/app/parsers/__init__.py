from .registry import ParserRegistry
from . import campus, cisco, fortios, juniper, panos, vyos, yamaha  # noqa: F401

__all__ = ["ParserRegistry"]
