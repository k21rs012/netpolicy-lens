from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class JunosSetLine:
    text: str
    source_line: int


def is_hierarchical_junos(config: str) -> bool:
    return bool(
        re.search(r"(?m)^system\s*\{", config)
        and re.search(r"(?m)^interfaces\s*\{", config)
        and re.search(r"(?m)^\s*host-name\s+\S+;", config)
    )


def hierarchical_to_set(config: str) -> list[JunosSetLine]:
    """Flatten brace-style Junos configuration without evaluating it.

    Junos emits one hierarchy statement per line in ``show configuration``.
    Keeping the original leaf line number lets the canonical trace point back
    to the uploaded file even though the parser consumes normalized set lines.
    Inactive subtrees are deliberately ignored rather than treated as active
    policy evidence.
    """
    output: list[JunosSetLine] = []
    stack: list[tuple[str, bool]] = []
    in_block_comment = False
    list_prefix: str | None = None
    list_inactive = False

    for source_line, raw in enumerate(config.splitlines(), 1):
        cleaned: list[str] = []
        index = 0
        while index < len(raw):
            if in_block_comment:
                end = raw.find("*/", index)
                if end < 0:
                    index = len(raw)
                else:
                    in_block_comment = False
                    index = end + 2
            else:
                start = raw.find("/*", index)
                if start < 0:
                    cleaned.append(raw[index:])
                    break
                cleaned.append(raw[index:start])
                in_block_comment = True
                index = start + 2

        line = "".join(cleaned).strip()
        if not line or line.startswith(("#", "version ")):
            continue

        while line.startswith("}"):
            if stack:
                stack.pop()
            line = line[1:].lstrip(" ;")
        if not line:
            continue

        inactive = False
        if line.startswith("inactive:"):
            inactive = True
            line = line.removeprefix("inactive:").strip()
        elif line.startswith("protect:"):
            line = line.removeprefix("protect:").strip()

        parent_inactive = any(value for _, value in stack)
        if list_prefix is not None:
            finished = line.endswith("];")
            values = line[:-2].strip() if finished else line
            if not list_inactive:
                path = " ".join(part for part, _ in stack)
                for value in values.split():
                    output.append(JunosSetLine(f"set {path} {list_prefix} {value}".strip(), source_line))
            if finished:
                list_prefix = None
                list_inactive = False
            continue
        if line.endswith("{"):
            stack.append((line[:-1].strip(), inactive or parent_inactive))
            continue
        if line.endswith("["):
            list_prefix = line[:-1].strip()
            list_inactive = inactive or parent_inactive
            continue
        if line.endswith(";") and not inactive and not parent_inactive:
            leaf = line[:-1].strip()
            if leaf:
                path = " ".join(part for part, _ in stack)
                output.append(JunosSetLine(f"set {path} {leaf}".strip(), source_line))

    return output
