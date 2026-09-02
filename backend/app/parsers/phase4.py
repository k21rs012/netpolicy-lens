"""Compatibility imports for parsers that originally shipped in phase four."""

from .asa import CiscoASABaseParser, CiscoASAParser, CiscoFTDParser
from .extreme import ExtremeBaseParser, ExtremeEXOSParser, ExtremeVOSSParser
from .routeros import MikroTikRouterOSParser

__all__ = [
    "CiscoASABaseParser",
    "CiscoASAParser",
    "CiscoFTDParser",
    "ExtremeBaseParser",
    "ExtremeEXOSParser",
    "ExtremeVOSSParser",
    "MikroTikRouterOSParser",
]
