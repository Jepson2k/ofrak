"""
Unit tests for the Ghidra SLEIGH assembler service (:class:`PyGhidraAssemblerService`).

These cover both ESP ISAs that the keystone-based assembler cannot handle (Xtensa, RISC-V),
asserting exact PC-relative encodings -- so a regression in the Ghidra wiring is caught fast,
without having to boot QEMU.
"""
import pytest

from ofrak.core.architecture import ProgramAttributes
from ofrak_type import BitWidth, Endianness, InstructionSet
from ofrak_type.architecture import InstructionSetMode

pytest.importorskip("ofrak_pyghidra")
from ofrak_pyghidra.components.assembler import PyGhidraAssemblerService  # noqa: E402

_XTENSA = ProgramAttributes(
    isa=InstructionSet.XTENSA,
    sub_isa=None,
    bit_width=BitWidth.BIT_32,
    endianness=Endianness.LITTLE_ENDIAN,
    processor=None,
)
_RISCV = ProgramAttributes(
    isa=InstructionSet.RISCV,
    sub_isa=None,
    bit_width=BitWidth.BIT_32,
    endianness=Endianness.LITTLE_ENDIAN,
    processor=None,
)


async def test_assemble_xtensa_call8():
    """Xtensa ``call8`` to an absolute target encodes PC-relative (3 bytes) via Ghidra SLEIGH."""
    svc = PyGhidraAssemblerService()
    # 0x65ef06 is also the exact byte sequence the esp32 boot redirect writes in place.
    assert await svc.assemble("call8 0x400db9b0", 0x400D4AB9, _XTENSA) == bytes.fromhex("65ef06")
    # Same target from a call site 4 bytes later -> different relative offset, same length.
    assert await svc.assemble("call8 0x400db9b0", 0x400D4ABD, _XTENSA) == bytes.fromhex("25ef06")


async def test_assemble_riscv_jal():
    """RISC-V ``jal`` to an absolute target encodes PC-relative (4 bytes) via Ghidra SLEIGH."""
    svc = PyGhidraAssemblerService()
    assert await svc.assemble("jal ra,0x42000100", 0x42000000, _RISCV) == bytes.fromhex("ef000010")
    assert await svc.assemble("jal ra,0x42000100", 0x42000004, _RISCV) == bytes.fromhex("ef00c00f")


async def test_assemble_bad_instruction_raises_descriptive_error():
    """An instruction Ghidra cannot assemble surfaces a clear ValueError (naming the ISA and address),
    not an opaque Java exception or a ``NoneType`` error."""
    with pytest.raises(ValueError, match="could not assemble"):
        await PyGhidraAssemblerService().assemble("not_a_real_mnemonic a0, a1", 0x42000000, _RISCV)


async def test_assemble_unresolvable_language_raises_value_error():
    """A ProgramAttributes Ghidra has no language for (here 64-bit Xtensa, which does not exist)
    surfaces a descriptive ValueError rather than a raw exception: the language lookup runs inside
    the error-wrapping ``try`` (regression guard for that ordering)."""
    no_such_language = ProgramAttributes(
        isa=InstructionSet.XTENSA,
        sub_isa=None,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.LITTLE_ENDIAN,
        processor=None,
    )
    with pytest.raises(ValueError):
        await PyGhidraAssemblerService().assemble("nop", 0x40000000, no_such_language)


async def test_assemble_rejects_non_default_mode():
    """A non-default InstructionSetMode is refused rather than silently ignored."""
    with pytest.raises(NotImplementedError):
        await PyGhidraAssemblerService().assemble(
            "jal ra,0x42000100", 0x42000000, _RISCV, mode=InstructionSetMode.THUMB
        )
