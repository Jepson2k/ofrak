import binascii
import functools
import hashlib
import operator
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.modifier import Modifier, ModifierError
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.binary import GenericBinary
from ofrak.core.program import CodeRegion
from ofrak.resource import Resource
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.range import Range

from ofrak.core.esp.flash_model import ESPFlashSection
from ofrak.core.esp.app_model import (
    ESPApp,
    ESPAppAddSegmentConfig,
    ESPAppExtendSegmentConfig,
    ESPAppAttributes,
    ESPAppHeaderModifierConfig,
    ESPAppSection,
    ESPChip,
    FlashFrequency,
    FlashSize,
    ESP_APP_CHECKSUM_MAGIC,
    ESP_APP_EXTENDED_HEADER_SIZE,
    ESP_APP_HEADER_SIZE,
    ESP_APP_MAGIC,
    ESP_APP_SEGMENT_HEADER_SIZE,
    ESP8266V2_APP_MAGIC,
)

# Per-chip memory maps, mirroring esptool's ``ROM_LOADER.MEMORY_MAP``. A segment's memory type is
# determined by the region its load address falls into (this is how esptool names segments). These
# are baked in so the component has no runtime dependency on esptool.
_ESP_MEMORY_MAP = {
    ESPChip.ESP8266: (
        (0x3FF00000, 0x3FF00010, "DPORT"),
        (0x3FFE8000, 0x40000000, "DRAM"),
        (0x40100000, 0x40108000, "IRAM"),
        (0x40201010, 0x402E1010, "IROM"),
    ),
    ESPChip.ESP32: (
        (0x3F400000, 0x3F800000, "DROM"),
        (0x3F800000, 0x3FC00000, "EXTRAM_DATA"),
        (0x3FFAE000, 0x40000000, "DRAM"),
        (0x40000000, 0x40070000, "IROM"),
        (0x40070000, 0x40078000, "CACHE_PRO"),
        (0x40078000, 0x40080000, "CACHE_APP"),
        (0x40080000, 0x400A0000, "IRAM"),
        (0x400A0000, 0x400BFFFC, "DIRAM_IRAM"),
        (0x400C0000, 0x400C2000, "RTC_IRAM"),
        (0x400D0000, 0x40400000, "IROM"),
        (0x50000000, 0x50002000, "RTC_DATA"),
    ),
    ESPChip.ESP32S2: (
        (0x3F000000, 0x3FF80000, "DROM"),
        (0x3FFB0000, 0x40000000, "DRAM"),
        (0x40020000, 0x40070000, "IRAM"),
        (0x40070000, 0x40072000, "RTC_IRAM"),
        (0x40080000, 0x40800000, "IROM"),
        (0x50000000, 0x50002000, "RTC_DATA"),
    ),
    ESPChip.ESP32S3: (
        (0x3C000000, 0x3D000000, "DROM"),
        (0x3FC88000, 0x3FD00000, "DRAM"),
        (0x40370000, 0x403E0000, "IRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x600FE000, 0x60100000, "RTC_IRAM"),
        (0x50000000, 0x50002000, "RTC_DATA"),
    ),
    ESPChip.ESP32C2: (
        (0x3C000000, 0x3C400000, "DROM"),
        (0x3FCA0000, 0x3FCE0000, "DRAM"),
        (0x42000000, 0x42400000, "IROM"),
        (0x4037C000, 0x403C0000, "IRAM"),
    ),
    ESPChip.ESP32C3: (
        (0x3C000000, 0x3C800000, "DROM"),
        (0x3FC80000, 0x3FCE0000, "DRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x4037C000, 0x403E0000, "IRAM"),
        (0x50000000, 0x50002000, "RTC_IRAM"),
    ),
    ESPChip.ESP32C6: (
        (0x42800000, 0x43000000, "DROM"),
        (0x40800000, 0x40880000, "DRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x40800000, 0x40880000, "IRAM"),
        (0x50000000, 0x50004000, "RTC_IRAM"),
    ),
    ESPChip.ESP32H2: (
        (0x42800000, 0x43000000, "DROM"),
        (0x40800000, 0x40880000, "DRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x40800000, 0x40880000, "IRAM"),
        (0x50000000, 0x50004000, "RTC_IRAM"),
    ),
    ESPChip.ESP32P4: (
        (0x40000000, 0x4C000000, "DROM"),
        (0x4FF00000, 0x4FFA0000, "DRAM"),
        (0x40000000, 0x4C000000, "IROM"),
        (0x4FF00000, 0x4FFA0000, "IRAM"),
        (0x50108000, 0x50110000, "RTC_IRAM"),
    ),
    ESPChip.ESP32C5: (
        (0x42800000, 0x43000000, "DROM"),
        (0x40800000, 0x40860000, "DRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x40800000, 0x40860000, "IRAM"),
        (0x50000000, 0x50004000, "RTC_IRAM"),
    ),
}


def _esp8266_crc32(data: bytes) -> int:
    """CRC32 variant used by the ESP8266 SDK bootloader for v2 images (matches esptool)."""
    crc = binascii.crc32(data, 0) & 0xFFFFFFFF
    return (crc ^ 0xFFFFFFFF) if crc & 0x80000000 else (crc + 1) & 0xFFFFFFFF


def _determine_chip(data: bytes) -> ESPChip:
    """
    Determine the ESP chip type by inspecting the (optional) extended header. ESP8266 images have
    no extended header, so this is a heuristic: an image is treated as ESP8266 unless the bytes
    where an ESP32-family extended header would sit carry a plausible ``hash_appended`` flag (0 or
    1) *and* a recognized chip id. The only case this can misread is a v1 ESP8266 image whose first
    segment happens to mimic both of those (unlikely in practice); callers that already know the
    target chip should not rely on this.

    :param data: the ESP app image bytes
    :return: the detected :class:`ESPChip` (``ESP8266`` when no extended header is present)
    """
    if len(data) < ESP_APP_HEADER_SIZE + ESP_APP_EXTENDED_HEADER_SIZE:
        return ESPChip.ESP8266
    if data[23] not in (0, 1):  # hash_appended flag (last byte of the extended header)
        return ESPChip.ESP8266
    (chip_id,) = struct.unpack_from("<H", data, 12)  # 16-bit chip id within the extended header
    chip = ESPChip.from_chip_id(chip_id)
    if chip is ESPChip.UNKNOWN:
        return ESPChip.ESP8266
    return chip


# ESP32-C* / H2 / P4 are RISC-V; ESP8266 and the original ESP32/S2/S3 are Xtensa.
_RISCV_CHIPS = frozenset(
    {
        ESPChip.ESP32C2,
        ESPChip.ESP32C3,
        ESPChip.ESP32C6,
        ESPChip.ESP32H2,
        ESPChip.ESP32C5,
        ESPChip.ESP32P4,
    }
)


def _chip_isa(chip: ESPChip) -> InstructionSet:
    return InstructionSet.RISCV if chip in _RISCV_CHIPS else InstructionSet.XTENSA


def _segment_memory_types(virtual_address: int, chip: ESPChip) -> List[str]:
    memory_map = _ESP_MEMORY_MAP.get(chip, ())
    return [name for start, end, name in memory_map if start <= virtual_address < end]


def _is_instruction_region(name: str) -> bool:
    """Whether a memory-map region name denotes instruction memory (IRAM / IROM)."""
    return "IRAM" in name or "IROM" in name


def _is_data_region(name: str) -> bool:
    """Whether a memory-map region name denotes data memory (DRAM / DROM / RTC_DATA / ...)."""
    return "DRAM" in name or "DROM" in name or "DATA" in name or "DPORT" in name


def _is_flash_mapped_region(name: str) -> bool:
    """
    Whether a region name denotes flash-cache-mapped memory (IROM / DROM). The bootloader maps these
    segments through the flash MMU rather than copying them to RAM, which requires the segment's data
    to be 64 KB-aligned with its load address (see :class:`ESPAppAddSegmentModifier`).
    """
    return "IROM" in name or "DROM" in name


# The flash MMU maps in 64 KB pages, so a memory-mapped (IROM/DROM) segment's flash offset must be
# congruent to its load address modulo this value or the bootloader rejects the image as unbootable.
_FLASH_MMU_ALIGN = 0x10000


def _classify_segment(
    virtual_address: int, chip: ESPChip, index: int, is_v2_irom: bool
) -> Tuple[str, bool]:
    """Return ``(name, is_code)`` for a segment based on its load address."""
    if is_v2_irom:
        return "irom0", True
    memory_types = _segment_memory_types(virtual_address, chip)
    name = ", ".join(memory_types) if memory_types else f"segment_{index}"
    # A segment is code only when its load address falls in instruction memory and *not* also in
    # data memory. On the RISC-V parts (ESP32-C6/H2/C5/P4) the IRAM and DRAM windows are the same
    # address range, so a pure-data segment there would otherwise be mistagged as a CodeRegion by a
    # plain "IRAM" substring match.
    is_code = any(_is_instruction_region(t) for t in memory_types) and not any(
        _is_data_region(t) for t in memory_types
    )
    return name, is_code


def _checksum_offset(end_of_segments: int) -> int:
    """The checksum is the last byte of the 16-byte-aligned block following the segments."""
    return ((end_of_segments + 16) // 16) * 16 - 1


@dataclass
class _Segment:
    index: int
    virtual_address: int
    data_offset: int
    size: int
    in_checksum: bool
    name: str
    is_code: bool


@dataclass
class _ParsedImage:
    """Stateless structural parse of an ESP app image, shared by the unpacker/analyzer/packer."""

    image_version: int  # 1 (ESP8266 v1 / ESP32 family) or 2 (ESP8266 v2)
    chip: ESPChip
    has_extended_header: bool
    primary_header_offset: int  # offset of the header whose entry_point/flash fields are used
    flash_mode: int
    flash_size_freq: int
    entry_point: int
    segments: List[_Segment] = field(default_factory=list)
    checksum_offset: int = 0
    stored_checksum: int = 0
    hash_appended: bool = False
    hash_offset: Optional[int] = None  # v1 SHA256 digest location (32 bytes)
    crc_offset: Optional[int] = None  # v2 CRC32 location (4 bytes)


def _read_segment(
    data: bytes,
    offset: int,
    index: int,
    chip: ESPChip,
    in_checksum: bool,
    is_v2_irom: bool,
) -> Tuple[_Segment, int]:
    """Parse one segment (8-byte header + data) at ``offset``, returning it and the next offset."""
    if offset + ESP_APP_SEGMENT_HEADER_SIZE > len(data):
        raise UnpackerError(f"ESP image truncated: segment {index} header past end of data")
    virtual_address, size = struct.unpack_from("<II", data, offset)
    data_offset = offset + ESP_APP_SEGMENT_HEADER_SIZE
    if data_offset + size > len(data):
        raise UnpackerError(
            f"ESP image truncated: segment {index} (size {size}) extends past end of data"
        )
    name, is_code = _classify_segment(virtual_address, chip, index, is_v2_irom)
    segment = _Segment(index, virtual_address, data_offset, size, in_checksum, name, is_code)
    return segment, data_offset + size


def _parse_image(data: bytes) -> _ParsedImage:
    """
    Statelessly parse an ESP app image (ESP8266 v1, ESP32 family, or ESP8266 v2) into a structural
    description. Raises :class:`UnpackerError` on a missing magic or a truncated/malformed image.
    """
    if len(data) < ESP_APP_HEADER_SIZE:
        raise UnpackerError("ESP image too small to contain a header")
    magic = data[0]
    if magic == ESP_APP_MAGIC:
        return _parse_v1_image(data)
    elif magic == ESP8266V2_APP_MAGIC:
        return _parse_v2_image(data)
    raise UnpackerError(f"This is not a valid ESP image (invalid magic number {magic:#x})")


def _parse_v1_image(data: bytes) -> _ParsedImage:
    chip = _determine_chip(data)
    has_extended_header = chip is not ESPChip.ESP8266
    # ``_determine_chip`` only returns an extended-header chip when at least the full extended header
    # is present, and ``_parse_image`` already guaranteed the 8-byte base header, so ``header_size``
    # bytes are always available here.
    header_size = ESP_APP_HEADER_SIZE + (ESP_APP_EXTENDED_HEADER_SIZE if has_extended_header else 0)

    num_segments = data[1]
    flash_mode = data[2]
    flash_size_freq = data[3]
    (entry_point,) = struct.unpack_from("<I", data, 4)

    segments: List[_Segment] = []
    offset = header_size
    for index in range(num_segments):
        segment, offset = _read_segment(data, offset, index, chip, True, False)
        segments.append(segment)

    checksum_offset = _checksum_offset(offset)
    if checksum_offset >= len(data):
        raise UnpackerError("ESP image truncated: checksum byte past end of data")
    stored_checksum = data[checksum_offset]

    hash_appended = has_extended_header and data[23] == 1
    hash_offset = None
    if hash_appended:
        hash_offset = checksum_offset + 1
        if hash_offset + 32 > len(data):
            raise UnpackerError("ESP image truncated: appended SHA256 digest past end of data")

    return _ParsedImage(
        image_version=1,
        chip=chip,
        has_extended_header=has_extended_header,
        primary_header_offset=0,
        flash_mode=flash_mode,
        flash_size_freq=flash_size_freq,
        entry_point=entry_point,
        segments=segments,
        checksum_offset=checksum_offset,
        stored_checksum=stored_checksum,
        hash_appended=hash_appended,
        hash_offset=hash_offset,
    )


def _parse_v2_image(data: bytes) -> _ParsedImage:
    # First header: magic (0xEA), constant segment marker, flash settings, entry point. The irom0
    # segment follows; the loadable segments and the authoritative flash/entry values live behind a
    # second (0xE9) header. The checksum covers only the post-second-header segments; a CRC32 of
    # the whole file is appended last.
    chip = ESPChip.ESP8266
    irom_segment, offset = _read_segment(data, ESP_APP_HEADER_SIZE, 0, chip, False, True)

    if offset + ESP_APP_HEADER_SIZE > len(data):
        raise UnpackerError("ESP8266 v2 image truncated: missing second header")
    if data[offset] != ESP_APP_MAGIC:
        raise UnpackerError(
            f"ESP8266 v2 image: expected second header magic {ESP_APP_MAGIC:#x}, "
            f"got {data[offset]:#x}"
        )
    second_header_offset = offset
    num_segments = data[offset + 1]
    flash_mode = data[offset + 2]
    flash_size_freq = data[offset + 3]
    (entry_point,) = struct.unpack_from("<I", data, offset + 4)

    segments: List[_Segment] = [irom_segment]
    offset += ESP_APP_HEADER_SIZE
    for index in range(num_segments):
        segment, offset = _read_segment(data, offset, index + 1, chip, True, False)
        segments.append(segment)

    checksum_offset = _checksum_offset(offset)
    if checksum_offset + 4 >= len(data):  # checksum byte + trailing 4-byte CRC32
        raise UnpackerError("ESP8266 v2 image truncated: checksum/CRC32 past end of data")
    stored_checksum = data[checksum_offset]
    crc_offset = checksum_offset + 1

    return _ParsedImage(
        image_version=2,
        chip=chip,
        has_extended_header=False,
        primary_header_offset=second_header_offset,
        flash_mode=flash_mode,
        flash_size_freq=flash_size_freq,
        entry_point=entry_point,
        segments=segments,
        checksum_offset=checksum_offset,
        stored_checksum=stored_checksum,
        crc_offset=crc_offset,
    )


def _calculate_checksum(data: bytes, parsed: _ParsedImage) -> int:
    checksum = ESP_APP_CHECKSUM_MAGIC
    for segment in parsed.segments:
        if segment.in_checksum:
            checksum = functools.reduce(
                operator.xor,
                data[segment.data_offset : segment.data_offset + segment.size],
                checksum,
            )
    return checksum & 0xFF


def _image_end_offset(parsed: _ParsedImage) -> int:
    """File offset one byte past the image footer (the checksum byte, or the appended SHA256/CRC32)."""
    if parsed.hash_appended and parsed.hash_offset is not None:
        return parsed.hash_offset + 32
    if parsed.crc_offset is not None:
        return parsed.crc_offset + 4
    return parsed.checksum_offset + 1


def _footer_bytes(core: bytes, parsed: _ParsedImage) -> bytes:
    """
    The footer that follows the checksum byte: the v1 SHA256 digest (32 bytes), the ESP8266-v2 CRC32
    (4 bytes), or nothing (ESP8266 v1). ``core`` is the image from its start up to and including the
    checksum byte -- exactly the bytes the digest / CRC32 is computed over. Shared by
    `_image_with_footer` (which appends it to a fresh, length-changing image) and `ESPAppPacker`
    (which rewrites it in place to preserve any trailing flash padding).
    """
    if parsed.hash_appended:
        return hashlib.sha256(core).digest()
    if parsed.crc_offset is not None:
        return struct.pack("<I", _esp8266_crc32(core))
    return b""


def _image_with_footer(body: bytes, checksum: int, parsed: _ParsedImage) -> bytes:
    """Append the 16-byte-aligned checksum byte and the format's SHA256 / CRC32 footer to ``body``
    (the segment bytes), returning the complete image. Mirrors the in-place footer recompute in
    `ESPAppPacker`, but builds a fresh image for modifiers that change the image length."""
    checksum_offset = _checksum_offset(len(body))
    core = bytes(body) + bytes(checksum_offset - len(body)) + bytes([checksum & 0xFF])
    return core + _footer_bytes(core, parsed)


def _rebuild_image(data: bytes, parsed: _ParsedImage, body: bytes, checksum: int) -> bytes:
    """
    Assemble the patched image from rebuilt segment `body` and recomputed `checksum`.

    A standalone image (nothing past the footer) simply grows. An image padded to a fixed-size region
    -- e.g. an `ESPApp` carved from a flash dump, which fills its partition slot -- keeps its total
    length: the new bytes consume the trailing padding, so the patched app still fits the slot and the
    surrounding flash layout is unchanged. The appended SHA256/CRC32 stays valid because it sits at its
    offset inside the rebuilt core, computed over the bytes before it; any padding after it is outside
    the declared image (exactly as in the original). Raise if the growth exceeds the padding.
    """
    new_core = _image_with_footer(body, checksum, parsed)
    image_end = _image_end_offset(parsed)
    trailing = len(data) - image_end
    if trailing <= 0:
        return new_core
    if len(new_core) > len(data):
        raise ModifierError(
            f"patched ESP image is {len(new_core)} bytes but only {len(data)} are available "
            f"(the original image plus its {trailing} trailing padding byte(s)); the injected "
            f"segment does not fit the available space"
        )
    # Both callers only grow the image, so the rebuilt core reaches at least the original image end
    # and the preserved tail is pure trailing padding. Guard that invariant with a raise (not a
    # strippable assert): a shrinking caller would otherwise splice stale original footer/segment
    # bytes after the freshly written footer.
    if len(new_core) < image_end:
        raise ModifierError(
            "_rebuild_image only supports growth; a shorter core would preserve stale image bytes "
            "instead of trailing padding"
        )
    return new_core + data[len(new_core) :]


####################
#    IDENTIFIER    #
####################
class ESPAppIdentifier(Identifier):
    """
    Identify ESP apps (ESP8266 v1/v2 and the ESP32 family) by their image magic and header fields.
    """

    targets = (GenericBinary, ESPFlashSection)

    async def identify(self, resource: Resource, config=None) -> None:
        """
        Identifies if the given resource is an ESP app.

        :param resource: The resource to identify
        :param config: Optional configuration for identification
        """
        data = await resource.get_data(range=Range(0, ESP_APP_HEADER_SIZE))
        if len(data) < ESP_APP_HEADER_SIZE:
            return
        magic_check = data[0] == ESP_APP_MAGIC or data[0] == ESP8266V2_APP_MAGIC
        flash_mode_check = data[2] in {0, 1, 2, 3}
        flash_freq_check = (data[3] & 0xF) in {0, 1, 2, 0xF}
        if magic_check and flash_mode_check and flash_freq_check:
            resource.add_tag(ESPApp)


####################
#    UNPACKER      #
####################
class ESPAppUnpacker(Unpacker[None]):
    """
    Unpacker for ESP apps (ESP8266 v1/v2 and the ESP32 family).

    Only the loadable segments are unpacked into child resources (`ESPAppSection`); the header,
    extended header, checksum, and SHA256/CRC32 footer are exposed as `ESPAppAttributes` via
    `ESPAppAnalyzer` rather than as tagged children. Segments mapped to instruction memory
    (IRAM / IROM) are additionally tagged as `CodeRegion`.
    """

    id = b"ESPAppUnpacker"
    targets = (ESPApp,)
    children = (ESPAppSection,)

    async def unpack(self, resource: Resource, config=None) -> None:
        data = bytes(await resource.get_data())
        parsed = _parse_image(data)

        for segment in parsed.segments:
            section = ESPAppSection(
                virtual_address=segment.virtual_address,
                size=segment.size,
                name=segment.name,
                section_index=segment.index,
            )
            data_range = (
                Range.from_size(segment.data_offset, segment.size) if segment.size > 0 else None
            )
            section_r = await resource.create_child_from_view(section, data_range=data_range)
            if segment.is_code:
                section_r.add_tag(CodeRegion)


####################
#    ANALYZER      #
####################
class ESPAppAnalyzer(Analyzer[None, ESPAppAttributes]):
    """
    Statelessly parse an ESP app's header, extended header, checksum, and SHA256/CRC32 footer into
    `ESPAppAttributes`. The checksum (XOR of all checksummed segment bytes with `0xEF`), the v1
    SHA256 digest, and the v2 CRC32 are recomputed and compared against the stored values to
    report validity.
    """

    targets = (ESPApp,)
    outputs = (ESPAppAttributes,)

    async def analyze(self, resource: Resource, config=None) -> ESPAppAttributes:
        data = bytes(await resource.get_data())
        parsed = _parse_image(data)

        chip_id = min_chip_rev_deprecated = min_chip_rev = max_chip_rev = None
        wp_pin = clk_drv = q_drv = d_drv = cs_drv = hd_drv = wp_drv = None
        if parsed.has_extended_header:
            ext = data[ESP_APP_HEADER_SIZE : ESP_APP_HEADER_SIZE + ESP_APP_EXTENDED_HEADER_SIZE]
            wp_pin = ext[0]
            # Drive strengths are packed two-per-byte as 4-bit nibbles (esptool's ``join_byte``):
            # ext[1] = clk_drv | q_drv << 4, ext[2] = d_drv | cs_drv << 4, ext[3] = hd_drv | wp_drv << 4.
            clk_drv = ext[1] & 0x0F
            q_drv = (ext[1] >> 4) & 0x0F
            d_drv = ext[2] & 0x0F
            cs_drv = (ext[2] >> 4) & 0x0F
            hd_drv = ext[3] & 0x0F
            wp_drv = (ext[3] >> 4) & 0x0F
            (
                chip_id,
                min_chip_rev_deprecated,
                min_chip_rev,
                max_chip_rev,
            ) = struct.unpack_from("<HBHH", ext, 4)

        calculated_checksum = _calculate_checksum(data, parsed)
        checksum_valid = parsed.stored_checksum == calculated_checksum

        stored_hash = calculated_hash = None
        hash_valid = False
        if parsed.hash_appended and parsed.hash_offset is not None:
            stored_hash = data[parsed.hash_offset : parsed.hash_offset + 32]
            calculated_hash = hashlib.sha256(data[: parsed.hash_offset]).digest()
            hash_valid = stored_hash == calculated_hash

        crc32 = None
        crc32_valid = False
        if parsed.crc_offset is not None:
            (crc32,) = struct.unpack_from("<I", data, parsed.crc_offset)
            crc32_valid = crc32 == _esp8266_crc32(data[: parsed.crc_offset])

        flash_size = parsed.flash_size_freq & 0xF0
        flash_frequency = parsed.flash_size_freq & 0x0F
        return ESPAppAttributes(
            magic=data[0],
            image_version=parsed.image_version,
            num_segments=len(parsed.segments),
            flash_mode=parsed.flash_mode,
            flash_size=flash_size,
            flash_frequency=flash_frequency,
            flash_size_decoded=FlashSize.from_value(flash_size, parsed.chip),
            flash_frequency_decoded=FlashFrequency.from_value(flash_frequency, parsed.chip),
            entry_point=parsed.entry_point,
            chip=parsed.chip,
            checksum=parsed.stored_checksum,
            calculated_checksum=calculated_checksum,
            checksum_valid=checksum_valid,
            has_extended_header=parsed.has_extended_header,
            hash_appended=parsed.hash_appended,
            hash_valid=hash_valid,
            chip_id=chip_id,
            min_chip_rev_deprecated=min_chip_rev_deprecated,
            min_chip_rev=min_chip_rev,
            max_chip_rev=max_chip_rev,
            wp_pin=wp_pin,
            clk_drv=clk_drv,
            q_drv=q_drv,
            d_drv=d_drv,
            cs_drv=cs_drv,
            hd_drv=hd_drv,
            wp_drv=wp_drv,
            stored_hash=stored_hash,
            calculated_hash=calculated_hash,
            crc32=crc32,
            crc32_valid=crc32_valid,
        )


class ESPAppProgramAttributesAnalyzer(Analyzer[None, ProgramAttributes]):
    """
    Derive the `ProgramAttributes` (ISA, bit width, endianness) of an ESP app from its chip type,
    so downstream tooling (e.g. PatchMaker) knows how to target it. ESP8266 and the original
    ESP32/S2/S3 are 32-bit little-endian Xtensa; the ESP32-C/H/P RISC-V parts are 32-bit
    little-endian RISC-V.
    """

    targets = (ESPApp,)
    outputs = (ProgramAttributes,)

    async def analyze(self, resource: Resource, config=None) -> ProgramAttributes:
        data = bytes(await resource.get_data())
        parsed = _parse_image(data)
        return ProgramAttributes(
            isa=_chip_isa(parsed.chip),
            sub_isa=None,
            bit_width=BitWidth.BIT_32,
            endianness=Endianness.LITTLE_ENDIAN,
            processor=None,
        )


####################
#    MODIFIERS     #
####################
class ESPAppHeaderModifier(Modifier[ESPAppHeaderModifierConfig]):
    """
    Edit the ESP app header in place (flash mode/size/frequency and entry point). For ESP8266 v2
    images the authoritative header is the second one, so that is the header edited. Run
    `ESPAppPacker` afterwards to recompute the checksum and SHA256/CRC32 footer for the image.
    """

    id = b"ESPAppHeaderModifier"
    targets = (ESPApp,)

    async def modify(self, resource: Resource, config: ESPAppHeaderModifierConfig) -> None:
        data = bytes(await resource.get_data())
        parsed = _parse_image(data)
        base = parsed.primary_header_offset
        header = bytearray(data[base : base + ESP_APP_HEADER_SIZE])
        if config.flash_mode is not None:
            header[2] = config.flash_mode.value
        if config.flash_size is not None or config.flash_frequency is not None:
            size_bits = config.flash_size if config.flash_size is not None else (header[3] & 0xF0)
            freq_bits = (
                config.flash_frequency if config.flash_frequency is not None else (header[3] & 0x0F)
            )
            header[3] = (size_bits & 0xF0) | (freq_bits & 0x0F)
        if config.entry_point is not None:
            struct.pack_into("<I", header, 4, config.entry_point)
        resource.queue_patch(Range.from_size(base, ESP_APP_HEADER_SIZE), bytes(header))


class ESPAppAddSegmentModifier(Modifier[ESPAppAddSegmentConfig]):
    """
    Append a new loadable segment (filled with `fill_byte`) to an ESP app image, recomputing the
    segment count and the trailing checksum / SHA256 / CRC32 so the image stays valid.

    ESP app images are tightly packed, so this is how injectable free space is created before
    running PatchMaker. Because adding a segment resizes the image, run this modifier on the
    identified `ESPApp` *before* unpacking its segments (otherwise the existing `ESPAppSection`
    children overlap the resize). A typical code-injection flow is: identify the `ESPApp`, run this
    modifier to add a segment at a free load address, unpack so the new `ESPAppSection` appears, tag
    it `FreeSpace` and the `ESPApp` `Allocatable`, then run `PatchFromSourceModifier` (which uses the
    `ProgramAttributes` from `ESPAppProgramAttributesAnalyzer` to pick the Xtensa/RISC-V toolchain)
    and finally `ESPAppPacker`.
    """

    id = b"ESPAppAddSegmentModifier"
    targets = (ESPApp,)

    async def modify(self, resource: Resource, config: ESPAppAddSegmentConfig) -> None:
        data = bytes(await resource.get_data())
        parsed = _parse_image(data)

        # Defensive guards against malformed images that real ESP toolchains never emit (0 segments,
        # or a segment count already at the 1-byte max); excluded from coverage accordingly.
        if not parsed.segments:  # pragma: no cover
            raise ModifierError("Cannot add a segment to an ESP image that has no segments")
        if data[parsed.primary_header_offset + 1] >= 0xFF:  # pragma: no cover
            raise ModifierError(
                "Cannot add a segment: the image already has the maximum of 255 segments"
            )

        # A new flash-mapped (IROM/DROM) segment cannot be added: the bootloader maps only one segment
        # per such region, so it would refuse to map a second. Grow the existing one instead.
        if any(
            _is_flash_mapped_region(name)
            for name in _segment_memory_types(config.virtual_address, parsed.chip)
        ):
            raise ModifierError(
                f"0x{config.virtual_address:x} is in a flash-mapped (IROM/DROM) region; the ESP "
                f"bootloader maps only one segment per such region. Use "
                f"ESPAppExtendSegmentModifier to grow the existing mapped segment instead."
            )

        last_segment = parsed.segments[-1]
        end_of_segments = last_segment.data_offset + last_segment.size
        segment_data = bytes([config.fill_byte & 0xFF]) * config.size
        new_segment = struct.pack("<II", config.virtual_address, config.size) + segment_data

        # Rebuild: header(s) + existing segments + the new segment, with the segment count bumped.
        body = bytearray(data[:end_of_segments]) + new_segment
        body[parsed.primary_header_offset + 1] += 1

        # Recompute the checksum over the existing checksummed segments plus the new one. The new
        # segment is a single repeated fill byte, so XORing it in depends only on the parity of the
        # count (an even count cancels out).
        checksum = _calculate_checksum(data, parsed)
        if config.size & 1:
            checksum ^= config.fill_byte & 0xFF

        resource.queue_patch(
            Range(0, len(data)), _rebuild_image(data, parsed, bytes(body), checksum)
        )


class ESPAppExtendSegmentModifier(Modifier[ESPAppExtendSegmentConfig]):
    """
    Grow an existing loadable segment in place by appending `fill_byte` bytes to its end, recomputing
    the trailing checksum / SHA256 / CRC32 so the image stays valid.

    This is the counterpart to `ESPAppAddSegmentModifier` for flash-memory-mapped (IROM / DROM)
    regions: the bootloader maps only one segment per such region, so injected code must extend the
    existing mapped segment rather than be added as a new one (which the bootloader would refuse to
    map). The new free space is contiguous with the segment at `segment_virtual_address + <old size>`.
    Run on the identified `ESPApp` before unpacking, then unpack, run PatchMaker against the new free
    space, and finally `ESPAppPacker` -- the same flow as `ESPAppAddSegmentModifier`.
    """

    id = b"ESPAppExtendSegmentModifier"
    targets = (ESPApp,)

    async def modify(self, resource: Resource, config: ESPAppExtendSegmentConfig) -> None:
        data = bytes(await resource.get_data())
        parsed = _parse_image(data)

        index = next(
            (
                i
                for i, segment in enumerate(parsed.segments)
                if segment.virtual_address == config.segment_virtual_address
            ),
            None,
        )
        if index is None:
            raise ModifierError(
                f"No segment with load address 0x{config.segment_virtual_address:x} to extend"
            )

        segment = parsed.segments[index]
        # Appending shifts every later segment in the file. A later *mapped* (IROM/DROM) segment must
        # keep `data_offset % 64KB == vaddr % 64KB`, so round the growth up to a 64KB multiple when
        # one exists; load segments (and the common case where the mapped segment is last) need none.
        chip = parsed.chip
        later_mapped = any(
            _is_flash_mapped_region(name)
            for later in parsed.segments[index + 1 :]
            for name in _segment_memory_types(later.virtual_address, chip)
        )
        grow = config.size
        if later_mapped and grow % _FLASH_MMU_ALIGN != 0:
            grow += _FLASH_MMU_ALIGN - (grow % _FLASH_MMU_ALIGN)
        fill = bytes([config.fill_byte & 0xFF]) * grow

        end_of_segments = parsed.segments[-1].data_offset + parsed.segments[-1].size
        segment_data_end = segment.data_offset + segment.size
        body = bytearray(data[:end_of_segments])
        # Insert the fill at the end of this segment's data. The grown segment's start (and thus its
        # own `data_offset % 64KB == vaddr % 64KB` flash-MMU congruence) is unchanged; only segments
        # that follow it shift, which is why the alignment rounding above targets a *later* mapped
        # segment, not this one.
        body[segment_data_end:segment_data_end] = fill
        # Bump the grown segment's size field (the second uint32 of its 8-byte header). The insertion
        # is at `segment_data_end`, after this header, so `segment.data_offset` (and the header offset
        # derived from it) is still valid in `body`.
        header_offset = segment.data_offset - ESP_APP_SEGMENT_HEADER_SIZE
        struct.pack_into("<I", body, header_offset + 4, segment.size + grow)

        # Recompute the checksum over the existing checksummed segments plus the appended fill -- but
        # only if this segment participates in the checksum (the ESP8266-v2 irom0 segment does not).
        # The fill is a single repeated byte, so its contribution depends only on the parity of the
        # count (an even count cancels out).
        checksum = _calculate_checksum(data, parsed)
        if segment.in_checksum and grow & 1:
            checksum ^= config.fill_byte & 0xFF

        resource.queue_patch(
            Range(0, len(data)), _rebuild_image(data, parsed, bytes(body), checksum)
        )


####################
#      PACKER      #
####################
class ESPAppPacker(Packer[None]):
    """
    Packer for ESP apps that recomputes the checksum and SHA256/CRC32 footer in place.

    Header / segment edits leave the trailing checksum byte and (depending on the format) the
    appended SHA256 digest or the v2 CRC32 stale; this packer recalculates all of them so the
    repacked image is valid.
    """

    id = b"ESPAppPacker"
    targets = (ESPApp,)

    async def pack(self, resource: Resource, config=None) -> None:
        # In-place counterpart to `_image_with_footer`: recompute the footer fields where they
        # already sit instead of rebuilding the image, so any bytes past the footer (e.g. flash
        # padding) are preserved rather than dropped.
        data = bytearray(await resource.get_data())
        parsed = _parse_image(bytes(data))

        data[parsed.checksum_offset] = _calculate_checksum(bytes(data), parsed)

        # The SHA256 / CRC32 (if any) is computed over everything up to and including the checksum
        # byte and written right after it -- the same core/footer split as `_image_with_footer`,
        # but in place so any trailing flash padding is preserved.
        footer = _footer_bytes(bytes(data[: parsed.checksum_offset + 1]), parsed)
        data[parsed.checksum_offset + 1 : parsed.checksum_offset + 1 + len(footer)] = footer

        resource.queue_patch(Range.from_size(0, len(data)), bytes(data))
