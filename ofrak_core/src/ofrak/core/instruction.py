from abc import ABC
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier, ModifierError
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.assembler.assembler_service_i import (
    AssemblerBackend,
    AssemblerServiceInterface,
)
from ofrak.service.assembler.assembler_service_keystone import (
    KeystoneAssemblerService,
    KEYSTONE_INSTALL_WORKS,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type.architecture import InstructionSetMode
from ofrak_type.range import Range


class _KeystoneExternalTool(ComponentExternalTool):
    """
    Keystone (keystone-engine) installs from PyPI do not work on MacOS.
    To use keystone with OFRAK, do a "no-binary" install from PyPI (and make sure cmake is installed):
    `pip install --no-binary keystone-engine`
    """

    def __init__(self):
        super().__init__(
            "kstool",
            "https://www.keystone-engine.org/",
            install_check_arg="",
        )

    async def is_tool_installed(self) -> bool:
        return KEYSTONE_INSTALL_WORKS


KEYSTONE_TOOL = _KeystoneExternalTool()


@dataclass
class Instruction(MemoryRegion):
    """
    A single ISA instruction.

    :ivar virtual_address: the virtual address of the start of the instruction
    :ivar size: the size of the instruction
    :ivar mnemonic: the instruction's mnemonic
    :ivar operands: the instruction's operands
    :ivar mode: the instruction set mode of the instruction
    """

    mnemonic: str
    operands: str
    mode: InstructionSetMode

    @index
    def Mnemonic(self) -> str:
        return self.mnemonic

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            instruction_attributes = all_attributes[AttributesType[Instruction]]
        except KeyError:
            return super().caption(all_attributes)
        return f"{instruction_attributes.mnemonic} {instruction_attributes.operands}"

    def get_assembly(self) -> str:
        """
        Get the instruction as an assembly string.

        :return: the instruction as an assembly string
        """
        return f"{self.mnemonic} {self.operands}"

    async def modify_assembly(
        self,
        mnemonic: Optional[str] = None,
        operands: Optional[str] = None,
        mode: Optional[InstructionSetMode] = None,
        assembler: AssemblerBackend = AssemblerBackend.KEYSTONE,
    ) -> bytes:
        """
        Modify the instruction, changing it to an instruction of equal size.

        :param mnemonic: the modified instruction mnemonic
        :param operands: the modified instruction operands
        :param mode: the modified instruction's instruction set mode
        :param assembler: which assembler backend encodes the instruction; defaults to
            [AssemblerBackend.KEYSTONE][ofrak.service.assembler.assembler_service_i.AssemblerBackend].
            Pass [AssemblerBackend.GHIDRA][ofrak.service.assembler.assembler_service_i.AssemblerBackend]
            for ISAs Keystone does not support (e.g. Xtensa, RISC-V), which requires the optional
            ``ofrak_pyghidra`` backend to be discovered.

        :return: the instruction's machine code after modification
        """
        # ``is not None`` rather than ``or``: an explicitly-passed empty operand string (or mode
        # NONE, whose value is 0) is falsy and would otherwise silently revert to this instruction's
        # current value.
        modification_config = InstructionModifierConfig(
            mnemonic if mnemonic is not None else self.mnemonic,
            operands if operands is not None else self.operands,
            mode if mode is not None else self.mode,
            assembler,
        )
        await self.resource.run(InstructionModifier, modification_config)
        data_after_modification = await self.resource.get_data()

        return data_after_modification


@dataclass
class RegisterUsage(ResourceAttributes):
    """
    Information about the register usage in a Resource containing some assembly, such as an
    Instruction.

    :ivar registers_read: registers read from when the assembly executes
    :ivar registers_written: registers written to when the assembly executes
    """

    registers_read: Tuple[str, ...]
    registers_written: Tuple[str, ...]


class InstructionAnalyzer(Analyzer[None, Instruction], ABC):
    """
    Analyze an [instruction][ofrak.core.instruction.Instruction] and extract its attributes.
    """

    id = b"InstructionAnalyzer"
    targets = (Instruction,)
    outputs = (Instruction,)


class InstructionRegisterUsageAnalyzer(Analyzer[None, RegisterUsage], ABC):
    """
    Analyze an [instruction][ofrak.core.instruction.Instruction] and extract the list of registers
    read and written.
    """

    id = b"InstructionRegisterUsageAttributesAnalyzer"
    targets = (Instruction,)
    outputs = (RegisterUsage,)


@dataclass
class InstructionModifierConfig(ComponentConfig):
    """
    Config for the [InstructionModifier][ofrak.core.instruction.InstructionModifier].

    :ivar mnemonic: the modified instruction's mnemonic
    :ivar operands: the modified instruction's operands
    :ivar mode: the modified instruction's instruction set mode
    :ivar assembler: which assembler backend encodes the instruction (a serializable enum, so this
        config stays plain data); defaults to
        [AssemblerBackend.KEYSTONE][ofrak.service.assembler.assembler_service_i.AssemblerBackend]
    """

    mnemonic: str
    operands: str
    mode: InstructionSetMode
    assembler: AssemblerBackend = AssemblerBackend.KEYSTONE


class InstructionModifier(Modifier[InstructionModifierConfig]):
    """
    Modifies individual assembly instructions by changing their mnemonic (operation) and/or operands
    (arguments), enabling instruction-level binary patching. The replacement instruction must be the
    same size as the original to prevent corruption. Use for changing specific instructions,
    redirecting branches or calls, modifying instruction operands, implementing instruction-level
    patches, NOP-ing operations, or fine-tuning code behavior. Powerful but requires understanding
    of instruction encoding and size constraints.
    """

    targets = (Instruction,)
    # Declares the default (KEYSTONE) backend's tool. A run that selects AssemblerBackend.GHIDRA
    # uses the discovered ofrak_pyghidra service instead and does not need keystone, but
    # external_dependencies is a static class attribute, so it advertises the default's dependency.
    external_dependencies = (KEYSTONE_TOOL,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        assembler_services: List[AssemblerServiceInterface],
    ):
        super().__init__(
            resource_factory,
            data_service,
            resource_service,
        )
        # Map each discovered assembler service by the backend it advertises, so a run can select one
        # by the serializable `AssemblerBackend` on its config without ofrak_core importing optional
        # backends (e.g. ofrak_pyghidra registers its GHIDRA service via discovery). Services without
        # a `backend` (e.g. a bare interface instance) are ignored. Keystone is seeded directly so the
        # default backend is always available even if discovery is restricted.
        self._assemblers: Dict[AssemblerBackend, AssemblerServiceInterface] = {
            service.backend: service
            for service in assembler_services
            if getattr(service, "backend", None) is not None
        }
        # Keystone is always discovered (it is a concrete service in ofrak_core), so the dict above
        # normally already maps it; seed it lazily only as a fallback for a restricted/blacklisted
        # discovery, without constructing a throwaway service on the common path.
        if AssemblerBackend.KEYSTONE not in self._assemblers:
            self._assemblers[AssemblerBackend.KEYSTONE] = KeystoneAssemblerService()

    async def modify(self, resource: Resource, config: InstructionModifierConfig):
        """
        Modify an instruction.

        :param resource: the instruction resource to modify
        :param config:

        :raises AssertionError: if the modified instruction length does not match the length of
        the original instruction
        """
        resource_memory_region = await resource.view_as(MemoryRegion)

        modified_assembly = f"{config.mnemonic} {config.operands}"

        assembler_service = self._assemblers.get(config.assembler)
        if assembler_service is None:
            raise ModifierError(
                f"No assembler service is available for {config.assembler.name}. The "
                f"{config.assembler.name} backend is provided by an OFRAK package that is not "
                f"installed or not discovered (e.g. ofrak_pyghidra for GHIDRA)."
            )
        asm = await assembler_service.assemble(
            modified_assembly,
            resource_memory_region.virtual_address,
            await resource.analyze(ProgramAttributes),
            config.mode,
        )
        assert (
            len(asm) == resource_memory_region.size
        ), "The modified instruction length does not match the original instruction length"

        new_attributes = AttributesType[Instruction](
            mnemonic=config.mnemonic,
            operands=config.operands,
            mode=config.mode,
        )
        resource.queue_patch(Range.from_size(0, len(asm)), asm)
        resource.add_attributes(new_attributes)
