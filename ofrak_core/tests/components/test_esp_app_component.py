from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from ofrak.component.unpacker import UnpackerError
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.esp.app import _determine_chip, _parse_image
from ofrak.core.program import CodeRegion
from ofrak.core.patch_maker.modifiers import (
    SegmentInjectorModifier,
    SegmentInjectorModifierConfig,
)
from ofrak_patch_maker.toolchain.model import Segment
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.memory_permissions import MemoryPermissions

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.component.modifier import ModifierError
from ofrak.core.esp import (
    ESPApp,
    ESPAppAddSegmentConfig,
    ESPAppAddSegmentModifier,
    ESPAppExtendSegmentConfig,
    ESPAppExtendSegmentModifier,
    ESPAppAttributes,
    ESPAppFlashMode,
    ESPAppHeaderModifier,
    ESPAppHeaderModifierConfig,
    ESPAppPacker,
    ESPChip,
    ESP_APP_HEADER_SIZE,
    ESP_APP_SEGMENT_HEADER_SIZE,
)
from pytest_ofrak.patterns.modify import ModifyPattern
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

from .esp_image_info import verify_with_esptool


def load_esp_asset(filename: str) -> bytes:
    """Load an ESP binary from the test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


@dataclass
class ESPAppUnpackTestCase:
    label: str
    binary_path: str
    has_extended_header: bool
    has_hash: bool
    num_sections: int
    magic: int
    entry_point: int
    checksum: int
    chip: ESPChip
    # Expected names of the chip-aware decoded flash size / frequency (the analyzer turns the raw
    # nibbles into these so the breakdown is interpretable in the GUI).
    flash_size_decoded: str
    flash_frequency_decoded: str
    chip_id: Optional[int] = None
    stored_hash: Optional[bytes] = None


ESP_APP_TEST_CASES = [
    ESPAppUnpackTestCase(
        label="ESP32 App",
        binary_path="esp32_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=5,
        magic=0xE9,
        entry_point=0x400829AC,
        checksum=0xEA,
        chip=ESPChip.ESP32,
        flash_size_decoded="S_4MB",
        flash_frequency_decoded="ITFF_0MHz",
        chip_id=0x0000,  # ESP32
        stored_hash=bytes.fromhex(
            "0750ce50194e3125f218af81d7a07ad0f5c23500ac487f047d77e89acadb6300"
        ),
    ),
    ESPAppUnpackTestCase(
        label="ESP32-S3 App",
        binary_path="esp32s3_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=5,
        magic=0xE9,
        entry_point=0x40376EC4,
        checksum=0x70,
        chip=ESPChip.ESP32S3,
        flash_size_decoded="S_8MB",
        flash_frequency_decoded="ITFF_FMHz",
        chip_id=0x0009,  # ESP32-S3
        stored_hash=bytes.fromhex(
            "fec85e5eee92d767571cf058f150907c988c482cb2a71c0fc280f5202667832e"
        ),
    ),
    ESPAppUnpackTestCase(
        label="ESP8266 App",
        binary_path="esp8266_hello.bin",
        has_extended_header=False,
        has_hash=False,
        num_sections=2,
        magic=0xE9,
        entry_point=0x4010F480,
        checksum=0x2B,
        chip=ESPChip.ESP8266,
        flash_size_decoded="S_4MB",
        flash_frequency_decoded="F_40MHz",
    ),
    ESPAppUnpackTestCase(
        label="ESP32-C3 App (RISC-V)",
        binary_path="esp32c3_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=1,
        magic=0xE9,
        entry_point=0x4037C000,
        checksum=0x0F,
        chip=ESPChip.ESP32C3,
        flash_size_decoded="S_1MB",
        flash_frequency_decoded="ITFF_0MHz",
        chip_id=0x0005,  # ESP32-C3 (RISC-V)
        stored_hash=bytes.fromhex(
            "f4fff5fd5a1c7eaceeec150360b8e1ce94b231c74b3e5563d4dde2b43954a86e"
        ),
    ),
    ESPAppUnpackTestCase(
        label="ESP32-C6 App (RISC-V)",
        binary_path="esp32c6_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=1,
        magic=0xE9,
        entry_point=0x40800000,
        checksum=0x0F,
        chip=ESPChip.ESP32C6,
        flash_size_decoded="S_1MB",
        # C6 uses a chip-specific frequency table (raw 0 -> 80 MHz, not the ESP32 ITFF encoding).
        flash_frequency_decoded="F_80MHz",
        chip_id=0x000D,  # ESP32-C6 (RISC-V)
        stored_hash=bytes.fromhex(
            "1f018e001c9410499711dc01c89e0e0f5e44407108009d3d3a51a1cf40bb0f70"
        ),
    ),
]


@pytest.mark.parametrize("test_case", ESP_APP_TEST_CASES, ids=lambda tc: tc.label)
async def test_esp_app_unpack(ofrak_context: OFRAKContext, test_case: ESPAppUnpackTestCase):
    """Identify and unpack an ESP app, verifying its segments and parsed attributes."""
    root_resource = await ofrak_context.create_root_resource(
        test_case.label, load_esp_asset(test_case.binary_path)
    )
    await root_resource.identify()
    assert root_resource.has_tag(ESPApp), "Resource was not identified as an ESPApp"

    await root_resource.unpack()

    # Only the loadable segments become children.
    esp_app = await root_resource.view_as(ESPApp)
    sections = list(await esp_app.get_sections())
    assert len(sections) == test_case.num_sections

    # Header / extended header / checksum / hash are exposed as attributes, not children.
    attributes = await root_resource.analyze(ESPAppAttributes)
    assert attributes.magic == test_case.magic
    assert attributes.image_version == 1
    assert attributes.entry_point == test_case.entry_point
    assert attributes.num_segments == test_case.num_sections
    assert attributes.checksum == test_case.checksum
    assert attributes.chip == test_case.chip
    assert attributes.has_extended_header == test_case.has_extended_header

    # The raw flash size/frequency nibbles are decoded (chip-aware) so the breakdown is readable.
    # Compare names with ``is not None`` first -- the value-0 members (e.g. ITFF_0MHz) are falsy.
    assert attributes.flash_size_decoded is not None
    assert attributes.flash_size_decoded.name == test_case.flash_size_decoded
    assert attributes.flash_frequency_decoded is not None
    assert attributes.flash_frequency_decoded.name == test_case.flash_frequency_decoded

    # The unmodified images are valid.
    assert attributes.checksum_valid is True
    if test_case.has_extended_header:
        assert attributes.chip_id == test_case.chip_id
    if test_case.has_hash:
        assert attributes.hash_appended is True
        assert attributes.stored_hash == test_case.stored_hash
        assert attributes.hash_valid is True


class TestESPAppHeaderModification(ModifyPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        resource = await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp32_hello.bin")
        )
        await resource.identify()
        await resource.unpack()
        return resource

    async def modify(self, root_resource: Resource) -> None:
        attributes = await root_resource.analyze(ESPAppAttributes)
        self.original_entry_point = attributes.entry_point

        await root_resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=0x40080400)
        )

    async def verify(self, root_resource: Resource) -> None:
        attributes = await root_resource.analyze(ESPAppAttributes)
        assert attributes.entry_point == 0x40080400
        assert attributes.entry_point != self.original_entry_point


class TestESP32AppUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp32_hello.bin")
        )

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        attributes = await unpacked_root_resource.analyze(ESPAppAttributes)
        self.new_entry_point = 0x40080400 if attributes.entry_point != 0x40080400 else 0x40080500

        await unpacked_root_resource.run(
            ESPAppHeaderModifier,
            ESPAppHeaderModifierConfig(entry_point=self.new_entry_point),
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        attributes = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attributes.entry_point == self.new_entry_point
        assert attributes.checksum_valid is True
        assert attributes.hash_valid is True

        verify_with_esptool(await repacked_root_resource.get_data(), has_hash=True)


class TestESP8266AppUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp8266_hello.bin")
        )

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        attributes = await unpacked_root_resource.analyze(ESPAppAttributes)
        self.new_entry_point = 0x40080400 if attributes.entry_point != 0x40080400 else 0x40080500

        await unpacked_root_resource.run(
            ESPAppHeaderModifier,
            ESPAppHeaderModifierConfig(entry_point=self.new_entry_point),
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        attributes = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attributes.entry_point == self.new_entry_point
        assert attributes.checksum_valid is True

        verify_with_esptool(await repacked_root_resource.get_data(), has_hash=False)


# ---------------------------------------------------------------------------
# ESP8266 v2 (magic 0xEA) images
# ---------------------------------------------------------------------------
# Entry point of the committed esp8266v2_hello.bin fixture (its _start, in IRAM).
V2_ENTRY_POINT = 0x40100000


async def test_esp8266_v2_unpack(ofrak_context: OFRAKContext):
    """An ESP8266 v2 image is identified, unpacked into irom0 + segments, and validated."""
    data = load_esp_asset("esp8266v2_hello.bin")
    root_resource = await ofrak_context.create_root_resource("v2.bin", data)
    await root_resource.identify()
    assert root_resource.has_tag(ESPApp)

    await root_resource.unpack()
    esp_app = await root_resource.view_as(ESPApp)
    sections = list(await esp_app.get_sections())
    assert len(sections) == 3  # irom0 + iram + dram

    attributes = await root_resource.analyze(ESPAppAttributes)
    assert attributes.image_version == 2
    assert attributes.magic == 0xEA
    assert attributes.chip == ESPChip.ESP8266
    assert attributes.entry_point == V2_ENTRY_POINT
    assert attributes.has_extended_header is False
    assert attributes.hash_appended is False
    # v2 images carry a CRC32 footer (not a SHA256 digest); both checksum and CRC must be valid.
    assert attributes.checksum_valid is True
    assert attributes.crc32 is not None
    assert attributes.crc32_valid is True


class TestESP8266V2UnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource(
            "v2.bin", load_esp_asset("esp8266v2_hello.bin")
        )

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        self.new_entry_point = 0x40108000
        await unpacked_root_resource.run(
            ESPAppHeaderModifier,
            ESPAppHeaderModifierConfig(entry_point=self.new_entry_point),
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        attributes = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attributes.image_version == 2
        assert attributes.entry_point == self.new_entry_point
        # The packer must recompute both the XOR checksum and the trailing CRC32.
        assert attributes.checksum_valid is True
        assert attributes.crc32_valid is True


# ---------------------------------------------------------------------------
# Robustness: malformed / truncated input must fail cleanly, not crash
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("asset", ["esp32c3_hello.bin", "esp8266v2_hello.bin"])
def test_parse_image_truncation_never_crashes(asset: str):
    """
    Truncating a real image at any length must make ``_parse_image`` either parse it or raise a
    clean ``UnpackerError`` -- never an IndexError/struct.error. Sweeping the small ESP32-family
    image (extended header + appended SHA256) and the ESP8266 v2 image (CRC32 footer) exercises
    every truncation guard with real data.
    """
    data = load_esp_asset(asset)
    for n in range(len(data) + 1):
        try:
            _parse_image(data[:n])
        except UnpackerError:
            pass


def test_parse_image_rejects_unknown_magic():
    """A real image whose magic byte is corrupted is rejected, not misparsed."""
    data = bytearray(load_esp_asset("esp32_hello.bin"))
    data[0] = 0x00  # neither 0xE9 nor 0xEA
    with pytest.raises(UnpackerError):
        _parse_image(bytes(data))


def test_parse_image_rejects_bad_v2_second_header():
    """An ESP8266 v2 image whose second header lacks the 0xE9 magic is rejected."""
    data = bytearray(load_esp_asset("esp8266v2_hello.bin"))
    # The second header follows the 8-byte first header and the irom0 segment (8-byte header + data).
    irom_size = int.from_bytes(data[12:16], "little")
    second_header = ESP_APP_HEADER_SIZE + ESP_APP_SEGMENT_HEADER_SIZE + irom_size
    data[second_header] = 0x00  # corrupt the expected 0xE9 second-header magic
    with pytest.raises(UnpackerError):
        _parse_image(bytes(data))


def test_determine_chip_unknown_chip_id_is_esp8266():
    """
    An extended header carrying an *unrecognized* chip id falls back to ESP8266 (the
    ``_determine_chip`` UNKNOWN branch). Byte-patch a real ESP32 image's chip-id field.
    """
    data = bytearray(load_esp_asset("esp32_hello.bin"))
    data[12:14] = (0xABCD).to_bytes(2, "little")  # not a known IMAGE_CHIP_ID
    assert _determine_chip(bytes(data)) == ESPChip.ESP8266


async def test_identifier_ignores_short_resource(ofrak_context: OFRAKContext):
    """A 1-3 byte resource starting with 0xE9 must not crash the ESP app identifier."""
    root_resource = await ofrak_context.create_root_resource("tiny.bin", b"\xe9\x00")
    await root_resource.identify()  # must not raise IndexError
    assert not root_resource.has_tag(ESPApp)


# ---------------------------------------------------------------------------
# ProgramAttributes (ISA) derivation, used by PatchMaker
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "binary_path, expected_isa",
    [
        ("esp32_hello.bin", InstructionSet.XTENSA),  # ESP32
        ("esp32s3_hello.bin", InstructionSet.XTENSA),  # ESP32-S3
        ("esp32c3_hello.bin", InstructionSet.RISCV),  # ESP32-C3
    ],
    ids=["esp32", "esp32s3", "esp32c3"],
)
async def test_esp_app_program_attributes(
    ofrak_context: OFRAKContext, binary_path: str, expected_isa: InstructionSet
):
    """The analyzer derives the ISA from the chip id (Xtensa for ESP32/S2/S3, RISC-V for C/H/P)."""
    root_resource = await ofrak_context.create_root_resource(
        binary_path, load_esp_asset(binary_path)
    )
    await root_resource.identify()
    assert root_resource.has_tag(ESPApp)
    attributes = await root_resource.analyze(ProgramAttributes)
    assert attributes.isa == expected_isa
    assert attributes.bit_width == BitWidth.BIT_32
    assert attributes.endianness == Endianness.LITTLE_ENDIAN


async def test_esp8266_program_attributes_is_xtensa(ofrak_context: OFRAKContext):
    """A real ESP8266 image (no extended header) is detected as Xtensa."""
    root_resource = await ofrak_context.create_root_resource(
        "esp8266.bin", load_esp_asset("esp8266_hello.bin")
    )
    await root_resource.identify()
    attributes = await root_resource.analyze(ProgramAttributes)
    assert attributes.isa == InstructionSet.XTENSA
    assert attributes.bit_width == BitWidth.BIT_32


# ---------------------------------------------------------------------------
# Adding injectable free space (the basis for PatchMaker code injection)
# ---------------------------------------------------------------------------
async def test_esp_app_add_segment(ofrak_context: OFRAKContext):
    """
    Appending a loadable segment grows the image by one valid segment: the segment count, the XOR
    checksum, and the SHA256 digest are all recomputed so esptool still accepts the image. The
    modifier runs on the identified image (before unpacking its segments), which is the order the
    injection flow uses.
    """
    data = load_esp_asset("esp32_hello.bin")

    # Count the original segments via a separate unpack so the assertion isn't hard-coded.
    original = await ofrak_context.create_root_resource("orig.bin", data)
    await original.identify()
    await original.unpack()
    segments_before = len(list(await (await original.view_as(ESPApp)).get_sections()))

    new_vaddr = 0x40090000
    new_size = 64
    root_resource = await ofrak_context.create_root_resource("add_seg.bin", data)
    await root_resource.identify()
    assert root_resource.has_tag(ESPApp)
    await root_resource.run(
        ESPAppAddSegmentModifier,
        ESPAppAddSegmentConfig(virtual_address=new_vaddr, size=new_size),
    )
    modified_data = await root_resource.get_data()
    assert len(modified_data) > len(data)

    # Re-unpack the modified image from scratch to confirm the new segment is real and valid.
    reloaded = await ofrak_context.create_root_resource("reloaded.bin", modified_data)
    await reloaded.identify()
    assert reloaded.has_tag(ESPApp)
    await reloaded.unpack()

    sections = list(await (await reloaded.view_as(ESPApp)).get_sections())
    assert len(sections) == segments_before + 1
    assert any(s.virtual_address == new_vaddr and s.size == new_size for s in sections)

    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.num_segments == segments_before + 1
    assert attributes.checksum_valid is True
    assert attributes.hash_valid is True

    verify_with_esptool(modified_data, has_hash=True)


async def test_esp_app_inject_into_added_segment(ofrak_context: OFRAKContext):
    """
    Injecting bytes into a segment added by `ESPAppAddSegmentModifier` exercises the OFRAK
    injection path end to end *minus compilation*: `SegmentInjectorModifier` locates the new
    `ESPAppSection` `MemoryRegion` at its load address and patches it, and `ESPAppPacker`
    re-validates the image (checksum + SHA256). This is exactly the mechanism
    `PatchFromSourceModifier` drives once a toolchain has compiled the patch into bytes — so it can
    be proven without a cross-compiler installed.
    """
    data = load_esp_asset("esp32_hello.bin")
    new_vaddr = 0x40090000
    # A recognizable, non-trivial payload that fills the whole segment.
    payload = bytes((i * 7 + 1) & 0xFF for i in range(64))

    # Add a segment to hold the payload, then unpack so its `ESPAppSection` child exists.
    root = await ofrak_context.create_root_resource("inject.bin", data)
    await root.identify()
    await root.run(
        ESPAppAddSegmentModifier,
        ESPAppAddSegmentConfig(virtual_address=new_vaddr, size=len(payload)),
    )
    await root.unpack()

    # Inject the payload into the new segment at its load address, then re-validate the image.
    segment = Segment(
        segment_name=".text",
        vm_address=new_vaddr,
        offset=0,
        is_entry=False,
        length=len(payload),
        access_perms=MemoryPermissions.RX,
    )
    await root.run(
        SegmentInjectorModifier,
        SegmentInjectorModifierConfig(((segment, payload),)),
    )
    await root.run(ESPAppPacker)
    patched_data = await root.get_data()

    # Reload from scratch: the payload landed in the segment and the image is still esptool-valid.
    reloaded = await ofrak_context.create_root_resource("reloaded.bin", patched_data)
    await reloaded.identify()
    await reloaded.unpack()
    sections = list(await (await reloaded.view_as(ESPApp)).get_sections())
    injected = [s for s in sections if s.virtual_address == new_vaddr]
    assert len(injected) == 1
    assert await injected[0].resource.get_data() == payload

    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.checksum_valid is True
    assert attributes.hash_valid is True
    verify_with_esptool(patched_data, has_hash=True)


async def test_esp_app_extend_segment(ofrak_context: OFRAKContext):
    """
    Extending a segment grows it in place by the requested size, leaving the segment count unchanged
    and recomputing the checksum / SHA256 so esptool still accepts the image. This is how code is
    injected into a flash-memory-mapped (IROM/DROM) region, where the bootloader maps only one
    segment. The IROM code segment is followed only by load segments, so no alignment padding occurs.
    """
    data = load_esp_asset("esp32_hello.bin")
    original = await ofrak_context.create_root_resource("orig.bin", data)
    await original.identify()
    await original.unpack()
    sections_before = list(await (await original.view_as(ESPApp)).get_sections())
    irom = next(s for s in sections_before if "IROM" in s.name)
    grow = 64

    root = await ofrak_context.create_root_resource("extend.bin", data)
    await root.identify()
    assert root.has_tag(ESPApp)
    await root.run(
        ESPAppExtendSegmentModifier,
        ESPAppExtendSegmentConfig(segment_virtual_address=irom.virtual_address, size=grow),
    )
    modified = await root.get_data()
    assert len(modified) > len(data)

    reloaded = await ofrak_context.create_root_resource("reloaded.bin", modified)
    await reloaded.identify()
    await reloaded.unpack()
    sections_after = list(await (await reloaded.view_as(ESPApp)).get_sections())
    assert len(sections_after) == len(sections_before)  # extended in place, not added
    extended = next(s for s in sections_after if s.virtual_address == irom.virtual_address)
    assert extended.size == irom.size + grow

    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.checksum_valid is True
    assert attributes.hash_valid is True
    verify_with_esptool(modified, has_hash=True)


async def test_esp_app_extend_segment_aligns_following_mapped_segment(ofrak_context: OFRAKContext):
    """
    When a later segment is also flash-mapped, the growth is rounded up to a 64KB multiple so that
    segment's MMU alignment (flash offset congruent to load address mod 64KB) is preserved and the
    image stays bootable. Extending the first (DROM) segment -- which is followed by the mapped IROM
    segment -- exercises that path.
    """
    data = load_esp_asset("esp32_hello.bin")
    original = await ofrak_context.create_root_resource("orig.bin", data)
    await original.identify()
    await original.unpack()
    drom = next(
        s for s in await (await original.view_as(ESPApp)).get_sections() if "DROM" in s.name
    )

    root = await ofrak_context.create_root_resource("extend.bin", data)
    await root.identify()
    await root.run(
        ESPAppExtendSegmentModifier,
        ESPAppExtendSegmentConfig(segment_virtual_address=drom.virtual_address, size=1),
    )
    modified = await root.get_data()

    reloaded = await ofrak_context.create_root_resource("reloaded.bin", modified)
    await reloaded.identify()
    await reloaded.unpack()
    extended = next(
        s
        for s in await (await reloaded.view_as(ESPApp)).get_sections()
        if s.virtual_address == drom.virtual_address
    )
    # size=1 was rounded up to a full 64KB page so the following IROM segment stays aligned.
    assert extended.size == drom.size + 0x10000
    verify_with_esptool(modified, has_hash=True)


async def test_esp_app_extend_segment_missing_raises(ofrak_context: OFRAKContext):
    """Extending a load address that matches no segment is a clean ModifierError."""
    root = await ofrak_context.create_root_resource("extend.bin", load_esp_asset("esp32_hello.bin"))
    await root.identify()
    with pytest.raises(ModifierError):
        await root.run(
            ESPAppExtendSegmentModifier,
            ESPAppExtendSegmentConfig(segment_virtual_address=0x1, size=16),
        )


async def test_esp_app_extend_segment_preserves_trailing_data(ofrak_context: OFRAKContext):
    """An `ESPApp` carved from a flash dump fills its partition slot, so it carries padding past the
    footer. Extending a segment consumes that padding -- keeping the image the same total length so it
    still fits the slot -- rather than dropping it or refusing."""
    probe = await ofrak_context.create_root_resource("probe.bin", load_esp_asset("esp32_hello.bin"))
    await probe.identify()
    await probe.unpack()
    irom = next(s for s in await (await probe.view_as(ESPApp)).get_sections() if "IROM" in s.name)

    padded = load_esp_asset("esp32_hello.bin") + b"\xff" * 0x100  # simulate partition-slot padding
    root = await ofrak_context.create_root_resource("extend.bin", padded)
    await root.identify()
    await root.run(
        ESPAppExtendSegmentModifier,
        ESPAppExtendSegmentConfig(segment_virtual_address=irom.virtual_address, size=64),
    )
    modified = await root.get_data()
    assert len(modified) == len(padded)  # padding absorbed the growth; total length unchanged
    # Surviving partition padding past the rebuilt footer is preserved verbatim (not zeroed or
    # mis-spliced); the 0x80-byte tail is well within the padding left after the 64-byte growth.
    assert modified[-0x80:] == b"\xff" * 0x80

    reloaded = await ofrak_context.create_root_resource("reloaded.bin", modified)
    await reloaded.identify()
    await reloaded.unpack()
    extended = next(
        s
        for s in await (await reloaded.view_as(ESPApp)).get_sections()
        if s.virtual_address == irom.virtual_address
    )
    assert extended.size == irom.size + 64
    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.checksum_valid is True
    assert attributes.hash_valid is True


async def test_esp_app_extend_segment_too_large_for_padding_raises(ofrak_context: OFRAKContext):
    """When the growth exceeds the available trailing padding, the modifier raises rather than
    overrun the partition slot."""
    probe = await ofrak_context.create_root_resource("probe.bin", load_esp_asset("esp32_hello.bin"))
    await probe.identify()
    await probe.unpack()
    irom = next(s for s in await (await probe.view_as(ESPApp)).get_sections() if "IROM" in s.name)

    padded = load_esp_asset("esp32_hello.bin") + b"\xff" * 8  # only 8 bytes of slack
    root = await ofrak_context.create_root_resource("extend.bin", padded)
    await root.identify()
    with pytest.raises(ModifierError):
        await root.run(
            ESPAppExtendSegmentModifier,
            ESPAppExtendSegmentConfig(segment_virtual_address=irom.virtual_address, size=0x80),
        )


async def test_esp_app_extend_segment_v2_checksum(ofrak_context: OFRAKContext):
    """Extending the ESP8266-v2 irom0 segment -- which is NOT covered by the XOR checksum -- must
    still produce a valid checksum and CRC32: the fill bytes must not be folded into the checksum, and
    the chip must come from the parsed image (re-deriving it misreads a v2 header as ESP32 and would
    wrongly 64KB-align the growth)."""
    data = load_esp_asset("esp8266v2_hello.bin")
    probe = await ofrak_context.create_root_resource("v2_probe.bin", data)
    await probe.identify()
    await probe.unpack()
    irom0 = next(
        s for s in await (await probe.view_as(ESPApp)).get_sections() if s.section_index == 0
    )

    root = await ofrak_context.create_root_resource("v2_extend.bin", data)
    await root.identify()
    await root.run(
        ESPAppExtendSegmentModifier,
        ESPAppExtendSegmentConfig(segment_virtual_address=irom0.virtual_address, size=64),
    )
    modified = await root.get_data()

    reloaded = await ofrak_context.create_root_resource("v2_reloaded.bin", modified)
    await reloaded.identify()
    await reloaded.unpack()
    extended = next(
        s
        for s in await (await reloaded.view_as(ESPApp)).get_sections()
        if s.virtual_address == irom0.virtual_address
    )
    assert extended.size == irom0.size + 64  # grown by exactly 64 (no spurious 64KB rounding)
    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.checksum_valid is True
    assert attributes.crc32_valid is True


async def test_esp_app_header_modifier_flash_fields(ofrak_context: OFRAKContext):
    """ESPAppHeaderModifier rewrites flash mode/size/frequency in place (packer revalidates)."""
    root = await ofrak_context.create_root_resource("hdr.bin", load_esp_asset("esp32_hello.bin"))
    await root.identify()
    await root.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(
            flash_mode=ESPAppFlashMode.DIO,
            flash_size=0x20,  # high nibble
            flash_frequency=0x0F,  # low nibble
        ),
    )
    await root.run(ESPAppPacker)
    attributes = await root.analyze(ESPAppAttributes)
    assert attributes.flash_mode == ESPAppFlashMode.DIO.value
    assert attributes.flash_size == 0x20
    assert attributes.flash_frequency == 0x0F
    assert attributes.checksum_valid is True


async def test_esp_app_add_segment_v2(ofrak_context: OFRAKContext):
    """Adding a segment to an ESP8266 v2 image recomputes the XOR checksum and the CRC32 footer."""
    data = load_esp_asset("esp8266v2_hello.bin")
    new_vaddr = 0x40104000  # free ESP8266 IRAM address

    original = await ofrak_context.create_root_resource("v2_orig.bin", data)
    await original.identify()
    await original.unpack()
    segments_before = len(list(await (await original.view_as(ESPApp)).get_sections()))

    root = await ofrak_context.create_root_resource("v2_add.bin", data)
    await root.identify()
    await root.run(
        ESPAppAddSegmentModifier,
        ESPAppAddSegmentConfig(virtual_address=new_vaddr, size=0x40),
    )
    patched = await root.get_data()

    reloaded = await ofrak_context.create_root_resource("v2_reloaded.bin", patched)
    await reloaded.identify()
    await reloaded.unpack()
    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.image_version == 2
    assert attributes.num_segments == segments_before + 1
    assert attributes.checksum_valid is True
    assert attributes.crc32_valid is True


async def test_esp_app_add_segment_preserves_trailing_data(ofrak_context: OFRAKContext):
    """Adding a load segment to an image padded to a fixed slot consumes the padding, keeping the
    total length unchanged (so the patched app still fits the slot)."""
    padded = load_esp_asset("esp32_hello.bin") + b"\xff" * 0x200
    root = await ofrak_context.create_root_resource("add.bin", padded)
    await root.identify()
    assert root.has_tag(ESPApp)
    await root.run(
        ESPAppAddSegmentModifier,
        ESPAppAddSegmentConfig(
            virtual_address=0x40090000, size=64
        ),  # free ESP32 IRAM (load) address
    )
    modified = await root.get_data()
    assert len(modified) == len(padded)  # padding absorbed the new segment; total length unchanged
    # Surviving partition padding past the rebuilt footer is preserved verbatim (the 0x100-byte tail
    # is well within the padding left after the new segment was spliced in).
    assert modified[-0x100:] == b"\xff" * 0x100

    reloaded = await ofrak_context.create_root_resource("reloaded.bin", modified)
    await reloaded.identify()
    await reloaded.unpack()
    sections = list(await (await reloaded.view_as(ESPApp)).get_sections())
    assert any(s.virtual_address == 0x40090000 and s.size == 64 for s in sections)
    attributes = await reloaded.analyze(ESPAppAttributes)
    assert attributes.checksum_valid is True
    assert attributes.hash_valid is True


async def test_esp_app_add_segment_rejects_flash_mapped(ofrak_context: OFRAKContext):
    """A new flash-mapped (IROM/DROM) segment cannot be added -- the bootloader maps only one segment
    per such region. The modifier rejects it and points at ESPAppExtendSegmentModifier."""
    probe = await ofrak_context.create_root_resource("probe.bin", load_esp_asset("esp32_hello.bin"))
    await probe.identify()
    await probe.unpack()
    irom = next(s for s in await (await probe.view_as(ESPApp)).get_sections() if "IROM" in s.name)

    root = await ofrak_context.create_root_resource("add.bin", load_esp_asset("esp32_hello.bin"))
    await root.identify()
    with pytest.raises(ModifierError, match="ESPAppExtendSegmentModifier"):
        await root.run(
            ESPAppAddSegmentModifier,
            ESPAppAddSegmentConfig(virtual_address=irom.virtual_address, size=64),
        )


async def test_esp_app_get_section_by_name(ofrak_context: OFRAKContext):
    """ESPApp.get_section_by_name returns the loadable segment with the given name."""
    root = await ofrak_context.create_root_resource("byname.bin", load_esp_asset("esp32_hello.bin"))
    await root.identify()
    await root.unpack()
    esp_app = await root.view_as(ESPApp)
    names = [s.name for s in await esp_app.get_sections()]
    unique_name = next(n for n in names if names.count(n) == 1)
    section = await esp_app.get_section_by_name(unique_name)
    assert section.name == unique_name


async def test_flash_decode_handles_unknown_codes(ofrak_context: OFRAKContext):
    """
    A flash size/frequency code outside the chip's table decodes to None rather than crashing the
    analyzer -- real-world firmware can carry non-standard or modified flash bytes.
    """
    data = bytearray(load_esp_asset("esp32c6_hello.bin"))
    # High nibble 0x90 is not a valid ESP32 flash size; low nibble 0x1 is not a valid ESP32-C6
    # frequency. The low nibble (1) still passes the identifier's flash-frequency sanity check.
    data[3] = 0x91
    root = await ofrak_context.create_root_resource("weird_flash.bin", bytes(data))
    await root.identify()
    assert root.has_tag(ESPApp)
    attributes = await root.analyze(ESPAppAttributes)
    assert attributes.flash_size_decoded is None
    assert attributes.flash_frequency_decoded is None


async def test_esp_code_region_tagging(ofrak_context: OFRAKContext):
    """
    Loadable segments mapped to instruction memory are tagged CodeRegion, but a segment must NOT be
    tagged on the RISC-V parts where the IRAM and DRAM windows are the same address range (the bug
    `_classify_segment` guards against). ESP32-C6's only segment loads into that coincident window.
    """
    # ESP32: IRAM/IROM are distinct from DRAM/DROM, so at least one segment is genuinely code.
    esp32 = await ofrak_context.create_root_resource("esp32.bin", load_esp_asset("esp32_hello.bin"))
    await esp32.identify()
    await esp32.unpack()
    esp32_sections = list(await (await esp32.view_as(ESPApp)).get_sections())
    assert any(s.resource.has_tag(CodeRegion) for s in esp32_sections)

    # ESP32-C6: IRAM == DRAM window, so its RAM segment must NOT be mistagged as code.
    c6 = await ofrak_context.create_root_resource("c6.bin", load_esp_asset("esp32c6_hello.bin"))
    await c6.identify()
    await c6.unpack()
    c6_sections = list(await (await c6.view_as(ESPApp)).get_sections())
    coincident = [s for s in c6_sections if s.virtual_address == 0x40800000]
    assert coincident, "expected the ESP32-C6 segment in the coincident IRAM/DRAM window"
    assert all(not s.resource.has_tag(CodeRegion) for s in coincident)
