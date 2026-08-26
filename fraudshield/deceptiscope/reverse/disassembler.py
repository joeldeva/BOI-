from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DisassembledMethod:
    class_name: str
    method_name: str
    descriptor: str
    source_file: str | None
    dex_source: str
    instructions: list[str]


@dataclass
class DisassemblyResult:
    status: str  # "completed", "unavailable", "partial"
    tool_used: str
    dex_count: int
    methods: list[DisassembledMethod]
    warnings: list[str]


class APKDisassembler:
    """
    Multi-tiered fail-safe Android APK disassembler.
    
    Fallback chain:
    1. Androguard Dalvik/DEX disassembler (primary resilient Python engine)
    2. Graceful degradation to UNAVAILABLE if DEX analysis cannot proceed.
    """

    def __init__(self, max_methods: int = 5000) -> None:
        self.max_methods = max_methods

    def disassemble(self, apk_path: Path) -> DisassemblyResult:
        if not apk_path.exists():
            return DisassemblyResult(
                status="unavailable",
                tool_used="none",
                dex_count=0,
                methods=[],
                warnings=[f"APK file not found: {apk_path}"],
            )

        try:
            return self._disassemble_androguard(apk_path)
        except Exception as exc:
            logger.warning("Androguard disassembly failed: %s", exc)
            return DisassemblyResult(
                status="unavailable",
                tool_used="androguard-failed",
                dex_count=0,
                methods=[],
                warnings=[f"Disassembly unavailable: {type(exc).__name__}: {str(exc)[:200]}"],
            )

    def _disassemble_androguard(self, apk_path: Path) -> DisassemblyResult:
        try:
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
        except ImportError as e:
            return DisassemblyResult(
                status="unavailable",
                tool_used="androguard-missing",
                dex_count=0,
                methods=[],
                warnings=[f"Androguard not installed: {e}"],
            )

        warnings: list[str] = []
        methods: list[DisassembledMethod] = []
        dex_list: list[bytes] = []
        if apk_path.suffix.lower() == ".dex":
            dex_list = [apk_path.read_bytes()]
        else:
            try:
                apk = APK(str(apk_path))
                dex_list = list(apk.get_all_dex())
            except Exception:
                raw = apk_path.read_bytes()
                if raw.startswith(b"dex\n"):
                    dex_list = [raw]
                else:
                    raise

        dex_count = len(dex_list)

        for idx, dex_bytes in enumerate(dex_list):
            dex_name = f"classes{idx + 1 if idx > 0 else ''}.dex"
            try:
                dex = DEX(dex_bytes)
            except Exception as e:
                warnings.append(f"Failed to parse {dex_name}: {e}")
                continue

            for cls in dex.get_classes():
                if len(methods) >= self.max_methods:
                    warnings.append(f"Method limit capped at {self.max_methods}")
                    break

                class_name = str(cls.get_name() or "Unknown")
                source_file = getattr(cls, "get_source_file", lambda: None)()

                for method in cls.get_methods():
                    if len(methods) >= self.max_methods:
                        break

                    method_name = str(method.get_name() or "unknown")
                    descriptor = str(method.get_descriptor() or "")

                    instructions: list[str] = []
                    try:
                        ins_list = method.get_instructions()
                        if ins_list:
                            for ins in ins_list:
                                ins_name = str(ins.get_name() or "")
                                output = getattr(ins, "get_output", lambda: "")()
                                line = f"{ins_name} {output}".strip() if output else ins_name
                                instructions.append(line)
                    except Exception:
                        pass

                    if instructions:
                        methods.append(
                            DisassembledMethod(
                                class_name=class_name,
                                method_name=method_name,
                                descriptor=descriptor,
                                source_file=source_file,
                                dex_source=dex_name,
                                instructions=instructions,
                            )
                        )

        return DisassemblyResult(
            status="completed" if methods else "unavailable",
            tool_used="androguard-dvm",
            dex_count=dex_count,
            methods=methods,
            warnings=warnings,
        )
