import logging
import os
from typing import Dict, List, Optional

from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig
from ofrak_type.architecture import ArchInfo, InstructionSet

# Espressif Xtensa codegen flags, validated against the rx2tx2rx ESP32 cave build
# (slim-patcher/cave/Makefile). The COMPILER is the ``xtensa-esp-elf-gcc`` driver, so these are
# GCC-style ``-m...`` flags. (They are NOT added to the assembler flags: the ASM path is the raw
# ``xtensa-esp-elf-as``, which spells these differently, e.g. ``--longcalls`` / ``--abi-windowed``.)
#   - ``-mlongcalls``: let the assembler relax an out-of-range CALL/J into L32R + CALLX/JX, so a
#     patch placed far from the symbols it calls still links.
#   - ``-mabi=windowed``: the ESP32/S2/S3 register-window ABI (ENTRY/RETW/CALL8). It is the GCC
#     default for these cores, but set explicitly so codegen is unambiguous.
#   - ``-mtext-section-literals``: keep L32R literal pools inside ``.text``. PatchMaker injects a
#     single ``.text`` segment at a fixed address, so the literals must travel inline with the
#     code (unlike rx2tx2rx, whose separate relocation step uses ``-mno-text-section-literals``).
_ESP_XTENSA_COMPILER_FLAGS = ["-mlongcalls", "-mabi=windowed", "-mtext-section-literals"]

# The unified Espressif ``xtensa-esp-elf`` GCC ships several Xtensa core overlays and selects one
# via ``$XTENSA_GNU_CONFIG``. With none set it falls back to a *big-endian* generic core, which
# silently mis-stores literal/data words for the little-endian ESP parts. Point it at the ESP32
# (LX6, little-endian) overlay by default; this also fixes the ABI/ISA core selection.
_XTENSA_ESP32_OVERLAY = "xtensa_esp32.so"


class GNU_XTENSA_ESP_Toolchain(GNU_10_Toolchain):
    """
    GNU toolchain for the Xtensa ESP parts (ESP8266, ESP32, ESP32-S2, ESP32-S3), using Espressif's
    ``xtensa-esp-elf`` GCC. The Xtensa core variant is selected by the unified toolchain via the
    ``$XTENSA_GNU_CONFIG`` overlay (default: the ESP32/LX6 core); no ``-march``/``-mcpu`` flag is
    emitted unless one is supplied via :class:`ToolchainConfig`.
    """

    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        self._compiler_flags.extend(_ESP_XTENSA_COMPILER_FLAGS)
        self._xtensa_gnu_config: Optional[str] = None

    @property
    def name(self) -> str:
        return "GNU_XTENSA_ESP_ELF"

    @property
    def segment_alignment(self) -> int:
        return 4

    def _esp32_core_overlay(self) -> Optional[str]:
        """Path to the ESP32 (little-endian) Xtensa core overlay shipped beside the compiler, or
        ``None`` if it can't be located (e.g. a per-core toolchain that needs no overlay)."""
        if self._xtensa_gnu_config is None:
            toolchain_root = os.path.dirname(os.path.dirname(self._compiler_path))
            overlay = os.path.join(toolchain_root, "lib", _XTENSA_ESP32_OVERLAY)
            self._xtensa_gnu_config = overlay if os.path.isfile(overlay) else ""
        return self._xtensa_gnu_config or None

    def _execute_tool(
        self,
        tool_path: str,
        flags: List[str],
        in_files: List[str],
        out_file: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> str:
        # Force the ESP32 (little-endian LX6) core for every tool invocation unless the caller (or
        # the ambient environment) already selected a core, so compiled literals/data are emitted
        # little-endian to match the ESP target.
        merged = dict(env) if env else {}
        overlay = self._esp32_core_overlay()
        if overlay is not None and "XTENSA_GNU_CONFIG" not in os.environ:
            merged.setdefault("XTENSA_GNU_CONFIG", overlay)
        return super()._execute_tool(
            tool_path, flags, in_files, out_file=out_file, env=merged or None
        )

    def _get_assembler_target(self, processor: ArchInfo) -> Optional[str]:
        if processor.isa is not InstructionSet.XTENSA:
            raise ValueError(
                f"The GNU Xtensa toolchain only supports the Xtensa ISA; given {processor.isa.name}"
            )
        # The Xtensa core variant is fixed by the toolchain build; only honor an explicit override.
        return self._config.assembler_target

    def _get_compiler_target(self, processor: ArchInfo) -> Optional[str]:
        return self._config.compiler_target
