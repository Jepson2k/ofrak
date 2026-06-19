"""
End-to-end behavioral test of the ESP PatchMaker path.

For each ESP architecture (Xtensa = esp32, RISC-V = esp32c3) this:

1. Extends the app's existing IROM code segment to create injectable free space (the bootloader maps
   only one segment per flash-mapped region, so injected code must join that segment).
2. Compiles a C patch (``esp_patch_entry``) with the Espressif toolchain and injects it there, and
   confirms the *actual* compiled bytes landed (byte-for-byte vs the same patch compiled standalone).
3. Boots the inject-only image in Espressif QEMU and confirms it still prints the original value
   (the injected code is dead until something calls it) -- the negative control.
4. Disassembles the image with OFRAK's native pipeline (``ESPAppUnpacker`` tags the IROM segment a
   ``CodeRegion``; the pyghidra backend unpacks it into ``ComplexBlock`` / ``Instruction`` resources),
   finds ``app_main``'s real call to ``target``, and rewrites it in place via
   ``Instruction.modify_assembly`` -- using a Ghidra-backed assembler for the ESP ISAs -- to point at
   the injected patch, then repacks.
5. Boots the redirected image and confirms the printed value changed to the patch's result.

This mirrors OFRAK's x86 patch test (which finds ``main``'s call instruction and ``modify_assembly``
rewrites it, then runs the binary to see the result change); for firmware "run the binary" means
booting the repacked image in QEMU. We start from the flash image and use ``ESPAppUnpacker`` /
``ESPAppPacker`` because that is the real device workflow (dump, patch, reflash) -- a stripped flash
image carries no symbols, so the one piece of prior-analysis knowledge we supply is the address of
``app_main`` / ``target`` (from ``symbols.json``). The bootable app assets are committed under
``assets/esp/boot`` (built by ``boot/build_assets.sh`` in the official ``espressif/idf`` image; see
``boot/README.md``).
"""
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Type

import pytest

from ofrak import OFRAKContext, ResourceFilter
from ofrak.core import ComplexBlock, Instruction
from ofrak.core.architecture import ProgramAttributes
from ofrak.service.assembler.assembler_service_i import AssemblerBackend
from ofrak.core.esp import (
    ESPApp,
    ESPAppExtendSegmentConfig,
    ESPAppExtendSegmentModifier,
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

from .esp_image_info import verify_with_esptool
from .esp_qemu import boot_result, RESULT_PREFIX

# These tests need the composed OFRAK image (Espressif QEMU + the ESP toolchains + pyghidra). Skip
# cleanly elsewhere rather than fail.
pytestmark = pytest.mark.skipif(
    shutil.which("qemu-system-xtensa") is None or shutil.which("qemu-system-riscv32") is None,
    reason="Espressif QEMU (qemu-system-xtensa/riscv32) is required; run in the composed OFRAK image",
)
pytest.importorskip("ofrak_pyghidra", reason="ESP redirect uses Ghidra disassembly/assembly")
import ofrak_pyghidra  # noqa: E402


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    """Discover the pyghidra backend so the IROM CodeRegion disassembles into Instructions."""
    ofrak_injector.discover(ofrak_pyghidra)


ASSETS = Path(__file__).parent / "assets" / "esp"
BOOT_ASSETS = ASSETS / "boot"
SEGMENT_SIZE = 0x100  # comfortably larger than the compiled patch .text

# app_main calls `target(TARGET_ARG)`; target(n) returns n, while the injected esp_patch_entry(n)
# returns sum(3*i + 1 for i in range(n)). Redirecting the call flips the printed value.
TARGET_ARG = 7

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


def _esp_patch_entry(n: int) -> int:
    """Python mirror of ``esp_patch_entry`` in the committed patch.c, for the expected boot result."""
    return sum(3 * i + 1 for i in range(n))


def _result_value(uart: str) -> Optional[int]:
    """The integer the app printed as ``ESP_PATCH_RESULT=<n>`` (or ``None`` if absent). Parsing the
    number -- rather than substring-matching ``ESP_PATCH_RESULT=7`` -- is what lets the negative
    control tell ``7`` from ``70`` (the former is a substring of the latter)."""
    match = re.search(rf"{re.escape(RESULT_PREFIX)}(\d+)", uart)
    return int(match.group(1)) if match else None


def _compile_patch_text(
    proc: ArchInfo,
    toolchain: Type[Toolchain],
    patch_dir: Path,
    vm_address: int,
    length: int,
) -> bytes:
    """
    Compile ``patch.c`` standalone with the same toolchain/arch/address the modifier uses and return
    the placed ``.text`` bytes -- so we can prove the injected segment holds the *actual* compiled
    code (not just any non-zero bytes).
    """
    patch_source = str(patch_dir / "patch.c")
    with tempfile.TemporaryDirectory() as build_dir:
        patch_maker = PatchMaker(toolchain=toolchain(proc, _TC_CONFIG), build_dir=build_dir)
        bom = patch_maker.make_bom("ref", [patch_source], [], [str(patch_dir)])
        obj = bom.object_map[patch_source]
        text = Segment(".text", vm_address, 0, False, length, MemoryPermissions.RX)
        data_ph = Segment(".data", 0xFACE, 0, False, 0, MemoryPermissions.RW)
        bss_ph = Segment(".bss", 0xFEED, 0, False, 0, MemoryPermissions.RW, is_bss=True)
        exec_path = os.path.join(build_dir, "ref_exec")
        region = PatchRegionConfig(bom.name + "_patch", {obj.path: (text, data_ph, bss_ph)})
        fem = patch_maker.make_fem([(bom, region)], exec_path)
        code = [s for s in fem.executable.segments if s.access_perms == MemoryPermissions.RX][0]
        return Path(exec_path).read_bytes()[code.offset : code.offset + code.length]


async def _code_section_containing(root, contains_vaddr: int):
    """Return the ``ESPAppSection`` whose load range contains ``contains_vaddr`` (the mapped code
    segment the patch is injected into and that ``app_main`` lives in)."""
    sections = await (await root.view_as(ESPApp)).get_sections()
    section = next(
        (s for s in sections if s.virtual_address <= contains_vaddr < s.virtual_address + s.size),
        None,
    )
    assert section is not None, f"no ESPAppSection contains load address 0x{contains_vaddr:x}"
    return section


async def _find_call_instruction(code_region, app_main_addr: int, target_addr: int) -> Instruction:
    """
    Natively disassemble ``code_region`` (the IROM ``CodeRegion``) with the pyghidra backend, then
    return the ``Instruction`` inside ``app_main`` that calls ``target_addr``.
    """
    await code_region.resource.unpack()  # CodeRegion -> ComplexBlocks (Ghidra analysis, ~10s)
    complex_blocks = await code_region.resource.get_children_as_view(
        ComplexBlock, r_filter=ResourceFilter(tags=(ComplexBlock,))
    )
    app_main_cb = next((c for c in complex_blocks if c.virtual_address == app_main_addr), None)
    assert app_main_cb is not None, f"no ComplexBlock at app_main 0x{app_main_addr:x}"
    await app_main_cb.resource.unpack_recursively()
    needle = f"0x{target_addr:x}"
    matches = [
        instruction
        for instruction in await app_main_cb.resource.get_descendants_as_view(
            Instruction, r_filter=ResourceFilter(tags=(Instruction,))
        )
        if needle in instruction.operands
        and (instruction.mnemonic.startswith("call") or instruction.mnemonic.startswith("j"))
    ]
    assert len(matches) == 1, (
        f"expected exactly one call to 0x{target_addr:x} in app_main, found {len(matches)}: "
        f"{[(i.mnemonic, i.operands) for i in matches]}"
    )
    return matches[0]


def _boot_value(chip: str, image: bytes) -> str:
    """Boot ``image`` in QEMU and return the captured UART text."""
    with tempfile.TemporaryDirectory() as d:
        app_bin = Path(d) / "app.bin"
        app_bin.write_bytes(image)
        return boot_result(chip, app_bin, BOOT_ASSETS / chip, Path(d), timeout=110)


async def _run_esp_redirect_boot_test(
    ofrak_context: OFRAKContext, chip: str, toolchain: Type[Toolchain]
) -> None:
    asset_dir = BOOT_ASSETS / chip
    # The C patch is architecture-agnostic; the toolchain (selected per chip) is what differs.
    patch_dir = ASSETS / "esp_patch"
    symbols = json.loads((asset_dir / "symbols.json").read_text())
    target_addr = symbols["target"]["addr"]
    app_main_addr = symbols["app_main"]["addr"]
    image = (asset_dir / "app.bin").read_bytes()

    # The patch must be reachable from app_main's call and live in the mapped code segment, so find
    # that segment, extend it, and place the patch in the new space at its end.
    probe = await ofrak_context.create_root_resource("probe.bin", image)
    await probe.unpack()
    irom = await _code_section_containing(probe, app_main_addr)
    irom_vaddr, irom_size = irom.virtual_address, irom.size
    patch_vaddr = irom_vaddr + irom_size

    root = await ofrak_context.create_root_resource("app.bin", image)
    await root.identify()
    assert root.has_tag(ESPApp)
    await root.run(
        ESPAppExtendSegmentModifier,
        ESPAppExtendSegmentConfig(segment_virtual_address=irom_vaddr, size=SEGMENT_SIZE),
    )
    await root.unpack()
    proc = await root.analyze(ProgramAttributes)

    text_segment = Segment(".text", patch_vaddr, 0, False, SEGMENT_SIZE, MemoryPermissions.RX)
    await root.run(
        PatchFromSourceModifier,
        PatchFromSourceModifierConfig(
            SourceBundle.slurp(str(patch_dir)),
            {str(patch_dir / "patch.c"): (text_segment,)},
            _TC_CONFIG,
            toolchain,
            patch_name="esp_patch",
        ),
    )
    await root.run(ESPAppPacker)
    injected = await root.get_data()

    # The actual compiled patch landed at the injection address, and the rest of the new space is
    # still the 0x00 fill.
    inject_root = await ofrak_context.create_root_resource("inj.bin", injected)
    await inject_root.identify()
    await inject_root.unpack()
    await inject_root.analyze(ProgramAttributes)
    host_section = await _code_section_containing(inject_root, app_main_addr)
    host_bytes = bytes(await host_section.resource.get_data())
    expected_text = _compile_patch_text(proc, toolchain, patch_dir, patch_vaddr, SEGMENT_SIZE)
    patch_off = patch_vaddr - host_section.virtual_address
    assert len(expected_text) > 0
    assert host_bytes[patch_off : patch_off + len(expected_text)] == expected_text
    assert set(host_bytes[patch_off + len(expected_text) : patch_off + SEGMENT_SIZE]) <= {0}
    verify_with_esptool(injected, chip=chip)

    # Negative control: with the patch injected but nothing calling it, the app still prints the
    # original value (and NOT the patch's) -- proving the injected code is dead until redirected.
    inject_uart = _boot_value(chip, injected)
    assert _result_value(inject_uart) == TARGET_ARG, inject_uart

    # Redirect app_main's real call to `target` over to the injected patch, natively: find the call
    # Instruction and rewrite its target in place via modify_assembly (Ghidra encodes the ESP ISA).
    call = await _find_call_instruction(host_section, app_main_addr, target_addr)
    new_operands = call.operands.replace(f"0x{target_addr:x}", f"0x{patch_vaddr:x}")
    assert (
        new_operands != call.operands
    ), f"call operands {call.operands!r} did not contain the target"
    await call.modify_assembly(operands=new_operands, assembler=AssemblerBackend.GHIDRA)

    await inject_root.run(ESPAppPacker)
    redirected = await inject_root.get_data()
    verify_with_esptool(redirected, chip=chip)

    # Behavioral proof: the booted, repacked image now runs the patch and prints its result.
    expected = _esp_patch_entry(TARGET_ARG)
    assert expected != TARGET_ARG
    redirect_uart = _boot_value(chip, redirected)
    assert _result_value(redirect_uart) == expected, redirect_uart


async def test_esp_redirect_boot_xtensa(ofrak_context: OFRAKContext):
    """Inject + redirect + boot an ESP32 (Xtensa) image; the printed value changes to the patch's."""
    await _run_esp_redirect_boot_test(ofrak_context, "esp32", GNU_XTENSA_ESP_Toolchain)


async def test_esp_redirect_boot_riscv(ofrak_context: OFRAKContext):
    """Inject + redirect + boot an ESP32-C3 (RISC-V) image; the printed value changes to the patch's."""
    await _run_esp_redirect_boot_test(ofrak_context, "esp32c3", GNU_RISCV_ESP_Toolchain)
