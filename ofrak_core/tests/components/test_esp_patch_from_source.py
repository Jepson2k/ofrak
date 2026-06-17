"""
Integration test for compiled-code injection into an ESP app image.

This is the end-to-end proof of the ESP PatchMaker path: a C patch is compiled with the Espressif
Xtensa or RISC-V toolchain and injected into a real ESP app image via ``PatchFromSourceModifier``,
then the image is repacked and confirmed still valid (our analyzer's checksum/SHA256 plus an
independent ``esptool image_info``, and a byte-for-byte comparison of the injected segment against
the same patch compiled standalone). It mirrors ``test_patch_from_source.py`` (the ELF equivalent)
but targets ``ESPApp`` and uses the explicit-segment injection path (no disassembly backend needed).

Like the architecture toolchain tests, this assumes the ``xtensa-esp-elf`` / ``riscv32-esp-elf``
toolchains and ``esptool`` are available (they are provided by the OFRAK Docker image).
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Type

from ofrak import OFRAKContext
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.esp import (
    ESPApp,
    ESPAppAddSegmentConfig,
    ESPAppAddSegmentModifier,
    ESPAppAttributes,
    ESPAppPacker,
)
from ofrak.core.patch_maker.modifiers import (
    PatchFromSourceModifier,
    PatchFromSourceModifierConfig,
    SourceBundle,
)
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.gnu_riscv import GNU_RISCV_ESP_Toolchain
from ofrak_patch_maker.toolchain.gnu_xtensa import GNU_XTENSA_ESP_Toolchain
from ofrak_patch_maker.toolchain.model import (
    BinFileType,
    CompilerOptimizationLevel,
    Segment,
    ToolchainConfig,
)
from ofrak_type import ArchInfo
from ofrak_type.memory_permissions import MemoryPermissions

ASSETS = Path(__file__).parent / "assets" / "esp"

_TC_CONFIG = ToolchainConfig(
    file_format=BinFileType.ELF,
    force_inlines=True,
    relocatable=False,
    no_std_lib=True,
    no_jump_tables=True,
    no_bss_section=True,
    create_map_files=True,
    compiler_optimization_level=CompilerOptimizationLevel.SPACE,
    debug_info=False,
    check_overlap=False,
)


def _esptool_validates(data: bytes) -> None:
    """Independently confirm the repacked image with esptool's ``image_info`` (a pinned test dep)."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        temp_path = f.name
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "esptool",
                "image_info",
                "--version",
                "2",
                temp_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"esptool rejected the repacked image:\n{result.stderr}"
        assert "Checksum:" in result.stdout
    finally:
        os.unlink(temp_path)


def _compile_patch_text(
    proc: ArchInfo,
    toolchain: Type[Toolchain],
    patch_dir: Path,
    patch_source: str,
    vm_address: int,
    length: int,
) -> bytes:
    """
    Compile ``patch_source`` standalone with the same toolchain/arch/address the modifier uses and
    return the placed ``.text`` bytes. Used to prove the injected segment holds the *actual* compiled
    code (not just any non-zero bytes).
    """
    build_dir = tempfile.mkdtemp()
    patch_maker = PatchMaker(toolchain=toolchain(proc, _TC_CONFIG), build_dir=build_dir)
    bom = patch_maker.make_bom("ref", [patch_source], [], [str(patch_dir)])
    obj = bom.object_map[patch_source]
    text = Segment(
        segment_name=".text",
        vm_address=vm_address,
        offset=0,
        is_entry=False,
        length=length,
        access_perms=MemoryPermissions.RX,
    )
    data_ph = Segment(".data", 0xFACE, 0, False, 0, MemoryPermissions.RW)
    bss_ph = Segment(".bss", 0xFEED, 0, False, 0, MemoryPermissions.RW, is_bss=True)
    exec_path = os.path.join(build_dir, "ref_exec")
    region = PatchRegionConfig(bom.name + "_patch", {obj.path: (text, data_ph, bss_ph)})
    fem = patch_maker.make_fem([(bom, region)], exec_path)
    code = [s for s in fem.executable.segments if s.access_perms == MemoryPermissions.RX][0]
    data = Path(exec_path).read_bytes()
    return data[code.offset : code.offset + code.length]


async def _run_esp_inject_test(
    ofrak_context: OFRAKContext,
    image_name: str,
    patch_dir: Path,
    toolchain: Type[Toolchain],
    patch_vaddr: int,
    has_hash: bool,
) -> None:
    data = (ASSETS / image_name).read_bytes()
    segment_size = 0x100  # comfortably larger than the compiled patch .text

    # Add a code segment to host the patch, then unpack so its ESPAppSection child exists.
    root = await ofrak_context.create_root_resource("patch_target.bin", data)
    await root.identify()
    assert root.has_tag(ESPApp)
    await root.run(
        ESPAppAddSegmentModifier,
        ESPAppAddSegmentConfig(virtual_address=patch_vaddr, size=segment_size),
    )
    await root.unpack()

    # The modifier derives the ISA from the image; capture it to compile an independent reference.
    proc = await root.analyze(ProgramAttributes)

    # Tell PatchMaker to compile patch.c and place its .text at the new segment's load address.
    text_segment = Segment(
        segment_name=".text",
        vm_address=patch_vaddr,
        offset=0,
        is_entry=False,
        length=segment_size,
        access_perms=MemoryPermissions.RX,
    )
    patch_source = str(patch_dir / "patch.c")
    config = PatchFromSourceModifierConfig(
        SourceBundle.slurp(str(patch_dir)),
        {patch_source: (text_segment,)},
        _TC_CONFIG,
        toolchain,
        patch_name="esp_patch",
    )
    await root.run(PatchFromSourceModifier, config)
    await root.run(ESPAppPacker)
    patched_data = await root.get_data()

    # Reload from scratch: the patch landed in the segment and the image is still valid.
    reloaded = await ofrak_context.create_root_resource("reloaded.bin", patched_data)
    await reloaded.identify()
    await reloaded.unpack()
    sections = list(await (await reloaded.view_as(ESPApp)).get_sections())
    injected = [s for s in sections if s.virtual_address == patch_vaddr]
    assert len(injected) == 1
    segment_bytes = await injected[0].resource.get_data()
    assert len(segment_bytes) == segment_size

    # The *actual* compiled code landed: the segment's leading bytes equal the same patch compiled
    # standalone, and the remainder is the fill byte.
    expected_text = _compile_patch_text(
        proc, toolchain, patch_dir, patch_source, patch_vaddr, segment_size
    )
    assert len(expected_text) > 0
    assert segment_bytes[: len(expected_text)] == expected_text
    assert set(segment_bytes[len(expected_text) :]) <= {0}

    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.checksum_valid is True
    if has_hash:
        assert attributes.hash_valid is True
    else:
        assert attributes.crc32_valid is True
    _esptool_validates(patched_data)


async def test_esp_app_patch_from_source_xtensa(ofrak_context: OFRAKContext):
    """Compile a C patch with the Xtensa toolchain and inject it into a real ESP32 image."""
    await _run_esp_inject_test(
        ofrak_context,
        "esp32_hello.bin",
        ASSETS / "xtensa_patch",
        GNU_XTENSA_ESP_Toolchain,
        patch_vaddr=0x40090000,  # ESP32 IRAM
        has_hash=True,
    )


async def test_esp_app_patch_from_source_riscv(ofrak_context: OFRAKContext):
    """Compile a C patch with the RISC-V toolchain and inject it into a real ESP32-C3 image."""
    await _run_esp_inject_test(
        ofrak_context,
        "esp32c3_hello.bin",
        ASSETS / "riscv_patch",
        GNU_RISCV_ESP_Toolchain,
        patch_vaddr=0x42010000,  # ESP32-C3 IROM
        has_hash=True,
    )
