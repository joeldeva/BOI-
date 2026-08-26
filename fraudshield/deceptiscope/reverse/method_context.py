from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from fraudshield.deceptiscope.reverse.sdk_classifier import CodeOwnership


class MethodMatchEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    signature_id: str
    signature_title: str
    category: str
    severity: str
    class_name: str
    method_name: str
    descriptor: str = ""
    source_file: str | None = None
    dex_source: str = "classes.dex"
    code_ownership: CodeOwnership = CodeOwnership.APPLICATION_CODE
    sdk_name: str | None = None
    matched_pattern: str
    call_site: str
    code_context: str
    risk_weight: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)


def extract_bounded_context(
    instructions: list[str],
    match_index: int,
    before: int = 3,
    after: int = 4,
    max_line_length: int = 200,
) -> tuple[str, str]:
    """
    Extracts a concise, bounded call-site string and surrounding code context.
    
    Returns:
    - call_site: The matched instruction line itself.
    - code_context: Formatted multi-line snippet with a `>` marker indicating the match.
    """
    if not instructions:
        return "", ""

    idx = max(0, min(match_index, len(instructions) - 1))
    call_site = _clean_instruction(instructions[idx], max_line_length)

    start_idx = max(0, idx - before)
    end_idx = min(len(instructions), idx + after + 1)

    context_lines: list[str] = []
    for i in range(start_idx, end_idx):
        prefix = "> " if i == idx else "  "
        clean = _clean_instruction(instructions[i], max_line_length)
        if clean:
            context_lines.append(f"{prefix}{clean}")

    return call_site, "\n".join(context_lines)


def _clean_instruction(line: str, max_length: int) -> str:
    cleaned = " ".join(line.strip().split())
    return cleaned[:max_length]
