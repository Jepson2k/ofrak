"""
Assembler services used to assemble and disassemble code.
"""
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import ClassVar

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSetMode
from ofrak.service.abstract_ofrak_service import AbstractOfrakService


class AssemblerBackend(Enum):
    """
    Identifies which assembler implementation should encode an instruction. Selecting a backend by
    this serializable enum -- rather than passing a live service object on a component config --
    keeps configs plain data and lets the choice round-trip through serialization. Each
    :class:`AssemblerServiceInterface` advertises the backend it provides via its ``backend``
    attribute, so a consumer can resolve the requested backend from the discovered services.

    :ivar KEYSTONE: the keystone-engine assembler (default; ARM / AARCH64 / x86 / PPC)
    :ivar GHIDRA: the Ghidra SLEIGH assembler, for ISAs keystone does not support (e.g. Xtensa,
        RISC-V); provided by the optional ``ofrak_pyghidra`` backend
    """

    KEYSTONE = "keystone"
    GHIDRA = "ghidra"


class AssemblerServiceInterface(AbstractOfrakService):
    """An interface for assembler services."""

    __metaclass__ = ABCMeta

    #: The backend this implementation provides; used to select it via :class:`AssemblerBackend`.
    backend: ClassVar[AssemblerBackend]

    @abstractmethod
    async def assemble(
        self,
        assembly: str,
        vm_addr: int,
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> bytes:
        """
        Assemble the given assembly code.

        :param str assembly: The assembly to assemble
        :param int vm_addr: The virtual address at which the assembly should be assembled.
        :param ProgramAttributes program_attributes: The processor targeted by the assembly
        :param InstructionSetMode mode: The mode of the processor for the assembly

        :return: The assembled machine code
        """
        raise NotImplementedError
