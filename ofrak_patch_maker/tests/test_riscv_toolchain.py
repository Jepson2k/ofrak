"""
Test the Espressif RISC-V GNU toolchain (used for ESP32-C2/C3/C6, ESP32-H2, ESP32-C5, ESP32-P4).

Like the other architecture toolchain tests, these assume the ``riscv32-esp-elf`` GCC toolchain is
installed and configured in ``toolchain.conf`` (it is provided by the OFRAK Docker image).
"""
import os

import pytest

from ofrak_type import ArchInfo
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

from ofrak_patch_maker.toolchain.gnu_riscv import GNU_RISCV_ESP_Toolchain
from ofrak_patch_maker.toolchain.model import (
    BinFileType,
    CompilerOptimizationLevel,
    ToolchainConfig,
)
from .toolchain_under_test import ToolchainUnderTest, CURRENT_DIRECTORY
from .toolchain_asm import run_alignment_test, run_monkey_patch_test
from .toolchain_c import (
    run_bounds_check_test,
    run_hello_world_test,
    run_relocatable_test,
)

RISCV_EXTENSION = ".riscv"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_RISCV_ESP_Toolchain,
            ArchInfo(
                InstructionSet.RISCV,
                None,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                None,
            ),
            RISCV_EXTENSION,
        )
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# C Tests
def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)


def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


def test_relocatable(toolchain_under_test: ToolchainUnderTest, tmp_path):
    """
    PIE linking on the RISC-V ESP toolchain emits dynamic relocations (``.rela.dyn``) that do not
    fit the regions this pattern maps, so the link fails. Assert that documented failure mode.
    """
    with pytest.raises(ValueError, match="overflow"):
        run_relocatable_test(toolchain_under_test, tmp_path)


# ASM Tests
def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    """
    PIE "monkey patching" emits a GOT that does not fit the bare text/data regions this pattern
    maps for the RISC-V ESP toolchain, so the link fails. Assert that documented failure mode (the
    real ESP code-injection flow uses non-PIE segment injection, exercised by the ESPApp tests).
    """
    with pytest.raises(ValueError, match="overflow"):
        run_monkey_patch_test(toolchain_under_test)


def test_riscv_alignment(toolchain_under_test: ToolchainUnderTest):
    """
    Assemble a single RISC-V instruction and assert it lands as the expected little-endian bytes.
    ``lui a0, 1`` assembles to the 2-byte compressed form ``c.lui`` (``05 65`` little-endian).
    """
    patch_source = os.path.join(CURRENT_DIRECTORY, "test_alignment/patch_riscv.as")
    run_alignment_test(toolchain_under_test, patch_source, 0x10000, b"\x05\x65")


def test_wrong_isa(toolchain_under_test: ToolchainUnderTest):
    """The RISC-V toolchain must reject a non-RISC-V ArchInfo (covers the assembler-target guard)."""
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=False,
        relocatable=False,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=False,
        compiler_optimization_level=CompilerOptimizationLevel.NONE,
        debug_info=False,
    )
    wrong = ArchInfo(InstructionSet.XTENSA, None, BitWidth.BIT_32, Endianness.LITTLE_ENDIAN, None)
    with pytest.raises(ValueError, match="RISC-V"):
        GNU_RISCV_ESP_Toolchain(wrong, tc_config)
