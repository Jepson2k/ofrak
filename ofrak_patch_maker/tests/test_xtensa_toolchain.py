"""
Test the Espressif Xtensa GNU toolchain (used for ESP8266 / ESP32 / ESP32-S2 / ESP32-S3).

Like the other architecture toolchain tests, these assume the ``xtensa-esp-elf`` GCC toolchain is
installed and configured in ``toolchain.conf`` (it is provided by the OFRAK Docker image).
"""
import os

import pytest

from ofrak_type import ArchInfo
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

from ofrak_patch_maker.toolchain.gnu_xtensa import GNU_XTENSA_ESP_Toolchain
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

XTENSA_EXTENSION = ".xtensa"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_XTENSA_ESP_Toolchain,
            ArchInfo(
                InstructionSet.XTENSA,
                None,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                None,
            ),
            XTENSA_EXTENSION,
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
    run_relocatable_test(toolchain_under_test, tmp_path)


# ASM Tests
def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    """
    PIE "monkey patching" emits a GOT that does not fit the bare text/data regions this pattern
    maps for the Xtensa ESP toolchain, so the link fails. Assert that documented failure mode (the
    real ESP code-injection flow uses non-PIE segment injection, exercised by the ESPApp tests).
    """
    with pytest.raises(ValueError, match="overflow"):
        run_monkey_patch_test(toolchain_under_test)


def test_xtensa_alignment(toolchain_under_test: ToolchainUnderTest):
    """
    Assemble a single Xtensa instruction and assert it lands as the expected little-endian bytes.
    ``add a2, a2, a3`` assembles to the 2-byte narrow form ``add.n`` (``3a 22`` little-endian); if
    the little-endian core overlay were not applied the bytes would be emitted big-endian.
    """
    patch_source = os.path.join(CURRENT_DIRECTORY, "test_alignment/patch_xtensa.as")
    run_alignment_test(toolchain_under_test, patch_source, 0x10000, b"\x3a\x22")


def test_wrong_isa(toolchain_under_test: ToolchainUnderTest):
    """The Xtensa toolchain must reject a non-Xtensa ArchInfo (covers the assembler-target guard)."""
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
    wrong = ArchInfo(InstructionSet.ARM, None, BitWidth.BIT_32, Endianness.LITTLE_ENDIAN, None)
    with pytest.raises(ValueError, match="Xtensa"):
        GNU_XTENSA_ESP_Toolchain(wrong, tc_config)
