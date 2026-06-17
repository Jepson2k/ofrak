import logging
from typing import Optional

from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig
from ofrak_type.architecture import ArchInfo, InstructionSet

# ESP RISC-V parts (ESP32-C2/C3/C6/H2/C5, ESP32-P4) are 32-bit with the ILP32 ABI. ``rv32imc`` is a
# safe baseline across the ESP RISC-V cores; override via ToolchainConfig.{assembler,compiler}_target
# for a core that supports more extensions (e.g. ``rv32imac``).
_DEFAULT_RISCV_MARCH = "rv32imc"
_RISCV_ABI = "ilp32"


class GNU_RISCV_ESP_Toolchain(GNU_10_Toolchain):
    """
    GNU toolchain for the RISC-V ESP parts, using Espressif's ``riscv32-esp-elf`` GCC.
    """

    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        # The ABI is not encoded in -march, so set it explicitly for the compiler and assembler
        # (the linker selects the emulation from the objects, so -mabi is not passed to ld).
        self._compiler_flags.append(f"-mabi={_RISCV_ABI}")
        self._assembler_flags.append(f"-mabi={_RISCV_ABI}")

    @property
    def name(self) -> str:
        return "GNU_RISCV32_ESP_ELF"

    @property
    def segment_alignment(self) -> int:
        return 4

    def _get_assembler_target(self, processor: ArchInfo) -> Optional[str]:
        if processor.isa is not InstructionSet.RISCV:
            raise ValueError(
                f"The GNU RISC-V toolchain only supports the RISC-V ISA; given {processor.isa.name}"
            )
        return self._config.assembler_target or _DEFAULT_RISCV_MARCH

    def _get_compiler_target(self, processor: ArchInfo) -> Optional[str]:
        return self._config.compiler_target or _DEFAULT_RISCV_MARCH
