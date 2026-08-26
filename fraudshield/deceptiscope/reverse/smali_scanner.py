from __future__ import annotations

import logging

from fraudshield.deceptiscope.reverse.behavior_registry import (
    BEHAVIOR_SIGNATURES,
    BehaviorRegistry,
)
from fraudshield.deceptiscope.reverse.disassembler import DisassembledMethod, DisassemblyResult
from fraudshield.deceptiscope.reverse.method_context import (
    MethodMatchEvidence,
    extract_bounded_context,
)
from fraudshield.deceptiscope.reverse.sdk_classifier import (
    SDKClassifier,
)


logger = logging.getLogger(__name__)


class SmaliScanner:
    """Scans disassembled Smali / DEX methods for behavioral signatures with bounded method context."""

    def __init__(
        self,
        registry: BehaviorRegistry | None = None,
        classifier: SDKClassifier | None = None,
        max_matches: int = 150,
    ) -> None:
        self.registry = registry or BehaviorRegistry(BEHAVIOR_SIGNATURES)
        self.classifier = classifier or SDKClassifier()
        self.max_matches = max_matches

    def scan_disassembly(
        self,
        disassembly: DisassemblyResult,
        app_package: str | None = None,
    ) -> list[MethodMatchEvidence]:
        """Scans all disassembled methods in an APK disassembler result."""
        matches: list[MethodMatchEvidence] = []
        seen: set[tuple[str, str, str]] = set()

        for method in disassembly.methods:
            if len(matches) >= self.max_matches:
                break
            method_matches = self._scan_method(method, app_package, seen)
            matches.extend(method_matches)

        return matches[: self.max_matches]

    def scan_smali_text(
        self,
        smali_text: str,
        class_name: str = "Lcom/example/App;",
        method_name: str = "run",
        descriptor: str = "()V",
        app_package: str | None = None,
    ) -> list[MethodMatchEvidence]:
        """Scans a raw Smali text snippet (ideal for unit testing and direct method evaluation)."""
        instructions = [line for line in smali_text.splitlines() if line.strip()]
        method = DisassembledMethod(
            class_name=class_name,
            method_name=method_name,
            descriptor=descriptor,
            source_file=None,
            dex_source="test.dex",
            instructions=instructions,
        )
        return self._scan_method(method, app_package, set())

    def _scan_method(
        self,
        method: DisassembledMethod,
        app_package: str | None,
        seen: set[tuple[str, str, str]],
    ) -> list[MethodMatchEvidence]:
        results: list[MethodMatchEvidence] = []
        ownership, _, sdk_name = self.classifier.classify(method.class_name, app_package)

        for line_idx, line in enumerate(method.instructions):
            matched_signatures = self.registry.match_line(line)
            for sig in matched_signatures:
                key = (sig.id, method.class_name, method.method_name)
                if key in seen:
                    continue
                seen.add(key)

                call_site, code_context = extract_bounded_context(
                    method.instructions,
                    line_idx,
                    before=3,
                    after=4,
                )

                # Identify which exact pattern matched
                matched_pattern = next(
                    (p for p in sig.patterns if p.lower() in line.lower()),
                    sig.patterns[0],
                )

                results.append(
                    MethodMatchEvidence(
                        signature_id=sig.id,
                        signature_title=sig.title,
                        category=sig.category.value,
                        severity=sig.severity,
                        class_name=method.class_name,
                        method_name=method.method_name,
                        descriptor=method.descriptor,
                        source_file=method.source_file,
                        dex_source=method.dex_source,
                        code_ownership=ownership,
                        sdk_name=sdk_name,
                        matched_pattern=matched_pattern,
                        call_site=call_site,
                        code_context=code_context,
                        risk_weight=sig.risk_weight,
                        metadata={
                            "description": sig.description,
                            "rationale": sig.rationale,
                            "instruction_index": line_idx,
                        },
                    )
                )

        return results
