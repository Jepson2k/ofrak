"""
Ghidra SLEIGH assembler service for OFRAK.

Ghidra's SLEIGH engine covers every architecture Ghidra ships a processor module for -- including
Xtensa and RISC-V, which the keystone-based :class:`KeystoneAssemblerService` does not support.
:class:`PyGhidraAssemblerService` implements :class:`AssemblerServiceInterface` and advertises
``backend = AssemblerBackend.GHIDRA``, so OFRAK components can assemble instructions for these ISAs
by selecting that backend (e.g. ``Instruction.modify_assembly(..., assembler=AssemblerBackend.GHIDRA)``);
the modifier resolves it from the discovered assembler services.
"""
from typing import Any, Dict

from ofrak.core.architecture import ProgramAttributes
from ofrak.service.assembler.assembler_service_i import (
    AssemblerBackend,
    AssemblerServiceInterface,
)
from ofrak_type.architecture import InstructionSetMode

from ofrak_pyghidra.components.pyghidra_components import _arch_info_to_processor_id


class PyGhidraAssemblerService(AssemblerServiceInterface):
    """Assemble assembly text to bytes via Ghidra's SLEIGH assembler."""

    backend = AssemblerBackend.GHIDRA

    def __init__(self):
        # Resolving the language id and building the SLEIGH assembler is expensive (it walks Ghidra's
        # ldefs and compiles the grammar); cache the (language, assembler) per language id so a
        # multi-instruction patch loop pays that cost once, mirroring
        # `KeystoneAssemblerService._ks_by_processor`.
        self._assembler_by_language: Dict[str, Any] = {}

    async def assemble(
        self,
        assembly: str,
        vm_addr: int,
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> bytes:
        if mode is not InstructionSetMode.NONE:
            # Ghidra's SLEIGH assembler is selected entirely by the program's language; there is no
            # mode knob. Refuse rather than silently ignore a mode the caller asked for.
            raise NotImplementedError(
                f"PyGhidraAssemblerService does not support InstructionSetMode.{mode.name}"
            )

        import pyghidra

        # Idempotent: starts the JVM once, then is a no-op (shared with the unpack/analysis path).
        pyghidra.start(verbose=False)
        from ghidra.program.util import DefaultLanguageService
        from ghidra.program.model.lang import LanguageID
        from ghidra.app.plugin.assembler import Assemblers

        try:
            # Resolve the language and build the assembler inside the try so a missing processor
            # module (e.g. Xtensa/RISC-V absent from this GHIDRA_INSTALL_DIR) surfaces as the
            # descriptive ValueError below rather than a raw FileNotFoundError / Java exception.
            language_id = _arch_info_to_processor_id(program_attributes)
            cached = self._assembler_by_language.get(language_id)
            if cached is None:
                language = DefaultLanguageService.getLanguageService().getLanguage(
                    LanguageID(language_id)
                )
                cached = (language, Assemblers.getAssembler(language))
                self._assembler_by_language[language_id] = cached
            language, assembler = cached
            address = language.getDefaultSpace().getAddress(vm_addr)
            machine_code = assembler.assembleLine(address, assembly)
        except Exception as error:
            # jpype surfaces Ghidra's checked AssemblySyntaxException / AssemblySemanticException
            # (bad mnemonic, or no encoding for the target/address, e.g. an out-of-range branch).
            raise ValueError(
                f"Ghidra could not assemble {assembly!r} for {program_attributes.isa.name} at "
                f"0x{vm_addr:x}: {error}"
            ) from error
        if machine_code is None:
            raise ValueError(
                f"Ghidra produced no encoding for {assembly!r} ({program_attributes.isa.name} at "
                f"0x{vm_addr:x}); the instruction may be unencodable or out of range"
            )
        return bytes(int(b) & 0xFF for b in machine_code)
