# coding=utf-8
# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import ctypes
from dataclasses import dataclass
from typing import Callable, Union, Optional
from .binaryview import BinaryView, Section, DataVariable
from .variable import RegisterValue
from .enums import (
    FirmwareNinjaMemoryHeuristic,
    FirmwareNinjaMemoryAccessType,
    FirmwareNinjaSectionAnalysisMode,
    FirmwareNinjaSectionType,
)
from .function import Function
from .project import ProjectFile
from . import _binaryninjacore as core


class FirmwareNinjaRelationship:
    """
    ``class FirmwareNinjaRelationship`` is a class for representing inter-binary and cross-binary relationships. This
    class is only available in the Ultimate Edition of Binary Ninja.
    """

    def __init__(self, view: BinaryView, handle=None) -> None:
        if handle is None:
            self.handle = core.BNCreateFirmwareNinjaRelationship(view.handle)
        else:
            self.handle = handle
        self._view = view

    def __del__(self):
        if core is not None:
            core.BNFreeFirmwareNinjaRelationship(self.handle)

    @property
    def _primary_data_variable(self) -> DataVariable:
        bn_data_var = core.BNDataVariable()
        if not core.BNFirmwareNinjaRelationshipGetPrimaryDataVariable(self.handle, ctypes.byref(bn_data_var)):
            return None

        result = None
        try:
            result = DataVariable.from_core_struct(bn_data_var, self._view)
        finally:
            core.BNFreeDataVariable(ctypes.byref(bn_data_var))

        return result

    @property
    def _primary_function(self) -> Function:
        bn_function = core.BNFirmwareNinjaRelationshipGetPrimaryFunction(self.handle)
        if not bn_function:
            return None

        return Function(handle=bn_function)

    @property
    def _primary_address(self) -> int:
        result = ctypes.c_uint64()
        if not core.BNFirmwareNinjaRelationshipGetPrimaryAddress(self.handle, ctypes.byref(result)):
            return None

        return result.value

    @property
    def primary(self) -> Union[DataVariable, Function, int]:
        """
        ``primary`` returns the primary function, data variable, or address of the relationship

        :return: Primary object of the relationship
        :rtype: Union[DataVariable, Function, int]
        """

        if core.BNFirmwareNinjaRelationshipPrimaryIsDataVariable(self.handle):
            return self._primary_data_variable
        elif core.BNFirmwareNinjaRelationshipPrimaryIsFunction(self.handle):
            return self._primary_function
        elif core.BNFirmwareNinjaRelationshipPrimaryIsAddress(self.handle):
            return self._primary_address
        else:
            return None

    @primary.setter
    def primary(self, obj: Union[DataVariable, Function, int]) -> None:
        if isinstance(obj, DataVariable):
            core.BNFirmwareNinjaRelationshipSetPrimaryDataVariable(self.handle, obj.address)
        elif isinstance(obj, Function):
            core.BNFirmwareNinjaRelationshipSetPrimaryFunction(self.handle, obj.handle)
        elif isinstance(obj, int):
            core.BNFirmwareNinjaRelationshipSetPrimaryAddress(self.handle, obj)
        else:
            raise ValueError("Primary object must be a DataVariable, Function, or integer address")

    @property
    def _secondary_data_variable(self) -> DataVariable:
        bn_data_var = core.BNDataVariable()
        if not core.BNFirmwareNinjaRelationshipGetSecondaryDataVariable(self.handle, ctypes.byref(bn_data_var)):
            return None

        result = None
        try:
            result = DataVariable.from_core_struct(bn_data_var, self._view)
        finally:
            core.BNFreeDataVariable(ctypes.byref(bn_data_var))

        return result

    @property
    def _secondary_function(self) -> Function:
        bn_function = core.BNFirmwareNinjaRelationshipGetSecondaryFunction(self.handle)
        if not bn_function:
            return None

        return Function(handle=bn_function)

    @property
    def _secondary_address(self) -> int:
        result = ctypes.c_uint64()
        if not core.BNFirmwareNinjaRelationshipGetSecondaryAddress(self.handle, ctypes.byref(result)):
            return None

        return result.value

    @property
    def _secondary_external_symbol(self) -> str:
        return core.BNFirmwareNinjaRelationshipGetSecondaryExternalSymbol(self.handle)

    @property
    def _secondary_external_project_file(self) -> ProjectFile:
        bn_project_file = core.BNFirmwareNinjaRelationshipGetSecondaryExternalProjectFile(self.handle)
        if not bn_project_file:
            return None

        return ProjectFile(bn_project_file)

    @property
    def secondary(self) -> Union[DataVariable, Function, int, tuple[int, ProjectFile], tuple[str, ProjectFile]]:
        """
        ``secondary`` returns the secondary function, data variable, address, external address, or external symbol of
        the relationship

        :return: Secondary object of the relationship
        :rtype: Union[DataVariable, Function, int, tuple[int, ProjectFile], tuple[str, ProjectFile]]
        """

        if core.BNFirmwareNinjaRelationshipSecondaryIsDataVariable(self.handle):
            return self._secondary_data_variable
        elif core.BNFirmwareNinjaRelationshipSecondaryIsFunction(self.handle):
            return self._secondary_function
        elif core.BNFirmwareNinjaRelationshipSecondaryIsAddress(self.handle):
            return self._secondary_address
        elif core.BNFirmwareNinjaRelationshipSecondaryIsExternalAddress(self.handle):
            return self._secondary_address, self._secondary_external_project_file
        elif core.BNFirmwareNinjaRelationshipSecondaryIsExternalSymbol(self.handle):
            return self._secondary_external_symbol, self._secondary_external_project_file
        else:
            return None

    @secondary.setter
    def secondary(
        self, obj: Union[DataVariable, Function, int, tuple[int, ProjectFile], tuple[str, ProjectFile]]) -> None:
        if isinstance(obj, tuple):
            if len(obj) != 2:
                raise ValueError("External object must be a tuple of (address, ProjectFile) or (symbol, ProjectFile)")

            if not isinstance(obj[0], int) and not isinstance(obj[0], str):
                raise ValueError("External object must be a tuple of (address, ProjectFile) or (symbol, ProjectFile)")

            if not isinstance(obj[1], ProjectFile):
                raise ValueError("External object must be a tuple of (address, ProjectFile) or (symbol, ProjectFile)")

        if isinstance(obj, DataVariable):
            core.BNFirmwareNinjaRelationshipSetSecondaryDataVariable(self.handle, obj.address)
        elif isinstance(obj, Function):
            core.BNFirmwareNinjaRelationshipSetSecondaryFunction(self.handle, obj.handle)
        elif isinstance(obj, int):
            core.BNFirmwareNinjaRelationshipSetSecondaryAddress(self.handle, obj)
        elif isinstance(obj, tuple):
            if isinstance(obj[0], int):
                core.BNFirmwareNinjaRelationshipSetSecondaryExternalAddress(self.handle, obj[1]._handle, obj[0])
            elif isinstance(obj[0], str):
                core.BNFirmwareNinjaRelationshipSetSecondaryExternalSymbol(self.handle, obj[1]._handle, obj[0])
        else:
            raise ValueError("Invalid secondary object type")

    @property
    def description(self) -> str:
        """
        ``description`` returns the description of the relationship

        :return: Description of the relationship
        :rtype: str
        """

        return core.BNFirmwareNinjaRelationshipGetDescription(self.handle)

    @description.setter
    def description(self, description: str) -> None:
        core.BNFirmwareNinjaRelationshipSetDescription(self.handle, description)

    @property
    def provenance(self) -> str:
        """
        ``provenance`` returns the provenance of the relationship

        :return: Provenance of the relationship
        :rtype: str
        """

        return core.BNFirmwareNinjaRelationshipGetProvenance(self.handle)

    @provenance.setter
    def provenance(self, provenance: str) -> None:
        core.BNFirmwareNinjaRelationshipSetProvenance(self.handle, provenance)

    @property
    def guid(self) -> str:
        """
        ``guid`` returns the GUID of the relationship

        :return: GUID of the relationship
        :rtype: str
        """

        return core.BNFirmwareNinjaRelationshipGetGuid(self.handle)


class FirmwareNinjaReferenceNode:
    """
    ``class FirmwareNinjaReferenceNode`` is a class for building reference trees for functions, data variables, and
    memory regions. This class is only available in the Ultimate Edition of Binary Ninja.
    """

    def __init__(self, handle=None, view=None):
        assert handle is not None, "Cannot create reference node directly, run `FirmwareNinja.get_reference_tree`"
        self._handle = handle
        self._view = view

    def __del__(self):
        if core is not None:
            core.BNFreeFirmwareNinjaReferenceNode(self._handle)

    @property
    def _function(self) -> Function:
        bn_function = core.BNFirmwareNinjaReferenceNodeGetFunction(self._handle)
        if not bn_function:
            return None

        return Function(handle=bn_function)

    @property
    def _data_variable(self) -> DataVariable:
        bn_data_var = core.BNDataVariable()
        if not core.BNFirmwareNinjaReferenceNodeGetDataVariable(self._handle, ctypes.byref(bn_data_var)):
            return None

        result = None
        try:
            result = DataVariable.from_core_struct(bn_data_var, self._view)
        finally:
            core.BNFreeDataVariable(ctypes.byref(bn_data_var))

        return result;

    @property
    def object(self) -> Union[Function, DataVariable]:
        """
        ``object`` returns the function or data variable contained in the reference tree node, or None if the object is
        a root node and only contains children

        :return: Object contained in the reference tree node
        :rtype: Union[Function, DataVariable]
        """

        if core.BNFirmwareNinjaReferenceNodeIsFunction(self._handle):
            return self._function
        elif core.BNFirmwareNinjaReferenceNodeIsDataVariable(self._handle):
            return self._data_variable
        else:
            return None

    @property
    def children(self) -> list["FirmwareNinjaReferenceNode"]:
        """
        ``children`` returns the child nodes contained in the reference tree node

        :return: Child nodes contained in the reference tree node
        :rtype: list[FirmwareNinjaReferenceNode]
        """

        if not core.BNFirmwareNinjaReferenceNodeHasChildren(self._handle):
            return []

        count = ctypes.c_ulonglong(0)
        nodes = []
        try:
            bn_nodes = core.BNFirmwareNinjaReferenceNodeGetChildren(self._handle, count)
            for i in range(count.value):
                nodes.append(
                    FirmwareNinjaReferenceNode(core.BNNewFirmwareNinjaReferenceNodeReference(bn_nodes[i]), self._view)
                )
        finally:
            core.BNFreeFirmwareNinjaReferenceNodes(bn_nodes, count.value)

        return nodes


@dataclass
class FirmwareNinjaDevice:
    """
    ``class FirmwareNinjaDevice`` is a class that stores information about a hardware device, including the device
    name, start address, size, and information about the device. This class is only available in the Ultimate Edition
    of Binary Ninja.
    """

    name: str
    start: int
    size: int
    info: str


@dataclass
class FirmwareNinjaSection:
    """
    ``class FirmwareNinjaSection`` is a class that stores information about a section identified with Firmware Ninja
    analysis, including the section type, start address, size, and entropy. This class is only available in the
    Ultimate Edition of Binary Ninja.
    """

    type: FirmwareNinjaSectionType
    start: int
    size: int
    entropy: float


@dataclass
class FirmwareNinjaMemoryAccess:
    """
    ``class FirmwareNinjaMemoryAccess`` is a class that stores information on instructions that access regions of
    memory that are not file-backed, such as memory-mapped I/O and RAM. This class is only available in the Ultimate
    Edition of Binary Ninja.
    """

    instr_address: int
    mem_address: RegisterValue
    heuristic: FirmwareNinjaMemoryHeuristic
    type: FirmwareNinjaMemoryAccessType
    value: RegisterValue

    @classmethod
    def from_BNFirmwareNinjaMemoryAccess(cls, access: core.BNFirmwareNinjaMemoryAccess) -> "FirmwareNinjaMemoryAccess":
        return cls(
            instr_address=access.instrAddress,
            mem_address=RegisterValue.from_BNRegisterValue(access.memAddress),
            heuristic=FirmwareNinjaMemoryHeuristic(access.heuristic),
            type=FirmwareNinjaMemoryAccessType(access.type),
            value=RegisterValue.from_BNRegisterValue(access.value),
        )

    @classmethod
    def to_BNFirmwareNinjaMemoryAccess(cls, access: "FirmwareNinjaMemoryAccess") -> core.BNFirmwareNinjaMemoryAccess:
        return core.BNFirmwareNinjaMemoryAccess(
            instrAddress=access.instr_address,
            memAddress=RegisterValue.to_BNRegisterValue(access.mem_address),
            heuristic=access.heuristic,
            type=access.type,
            value=RegisterValue.to_BNRegisterValue(access.value),
        )


@dataclass
class FirmwareNinjaFunctionMemoryAccesses:
    """
    ``class FirmwareNinjaFunctionMemoryAccesses`` is a class that stores information on accesses made by a function
    to memory regions that are not file-backed, such as memory-mapped I/O and RAM. This class is only available in the
    Ultimate Edition of Binary Ninja.
    """

    function: Function
    accesses: list[FirmwareNinjaMemoryAccess]

    @classmethod
    def from_BNFirmwareNinjaFunctionMemoryAccesses(
        cls,
        info: core.BNFirmwareNinjaFunctionMemoryAccesses,
        view: BinaryView,
    ) -> "FirmwareNinjaFunctionMemoryAccesses":
        accesses = []
        for i in range(info.count):
            access = info.accesses[i]
            accesses.append(FirmwareNinjaMemoryAccess.from_BNFirmwareNinjaMemoryAccess(access.contents))

        return cls(
            function=view.get_function_at(info.start),
            accesses=accesses,
        )


@dataclass
class FirmwareNinjaDeviceAccesses:
    """
    ``class FirmwareNinjaDeviceAccesses`` is a class that stores information on the number of accesses to hardware
    devices for each board that is compatible with the current architecture. This information can be used to identify
    a board based on the number of accesses to hardware devices. This class is only available in the Ultimate Edition
    of Binary Ninja.
    """

    board_name: str
    total: int
    unique: int


class FirmwareNinja:
    """
    ``class FirmwareNinja`` is a class that aids in analysis of firmware binaries. This class is only available in the
    Ultimate Edition of Binary Ninja.

    :Example:

        >>> from binaryninja import *
        >>> view = load("path/to/firmware.bin", options={"loader.imageBase": 0x100000})
        >>> fwn = FirmwareNinja(view)
        >>> fwn.get_function_memory_accesses()[0].accesses[0].mem_address
        <const ptr 0x40090028>
    """

    def __init__(self, view: BinaryView) -> None:
        self._view = view
        self._handle = core.BNCreateFirmwareNinja(view.handle)

    def __del__(self):
        if core is not None:
            core.BNFreeFirmwareNinja(self._handle)

    def store_custom_device(self, name: str, start: int, size: int, info: str) -> bool:
        """
        ``store_custom_device`` stores a user-defined Firmware Ninja device in the binary view metadata

        :param str name: Name of the device
        :param int start: Start address of the device
        :param int size: Size of the device memory region
        :param str info: Information about the device
        :return: True on success, False on failure
        :rtype: bool
        """

        return core.BNFirmwareNinjaStoreCustomDevice(self._handle, name, start, start + size, info)

    def remove_custom_device(self, name: str) -> bool:
        """
        ``remove_custom_device`` removes a user-defined Firmware Ninja device from the binary view metadata by device
        name

        :param str name: Name of the device
        :return: True on success, False on failure
        :rtype: bool
        """

        return core.BNFirmwareNinjaRemoveCustomDevice(self._handle, name)

    @property
    def user_devices(self) -> list[FirmwareNinjaDevice]:
        """
        ``user_devices`` queries user-defined Firmware Ninja devices from the binary view metadata

        :return: List of Firmware Ninja devices
        :rtype: list[FirmwareNinjaDevice]
        """

        devices = ctypes.POINTER(core.BNFirmwareNinjaDevice)()
        count = core.BNFirmwareNinjaQueryCustomDevices(self._handle, ctypes.byref(devices))
        if count == -1:
            raise RuntimeError("BNFirmwareNinjaQueryCustomDevices")

        try:
            device_list = []
            for i in range(count):
                device_list.append(
                    FirmwareNinjaDevice(
                        name=devices[i].name,
                        start=devices[i].start,
                        size=devices[i].end - devices[i].start,
                        info=devices[i].info,
                    )
                )

            return device_list
        finally:
            core.BNFirmwareNinjaFreeDevices(devices, count)

    @property
    def boards(self) -> list[str]:
        """
        ``boards`` queries the name of all boards that are compatible with the current architecture

        :return: List of board names
        :rtype: list[str]
        """

        boards = ctypes.POINTER(ctypes.c_char_p)()
        count = core.BNFirmwareNinjaQueryBoardNamesForArchitecture(
            self._handle, self._view.arch.handle, ctypes.byref(boards)
        )
        if count == -1:
            raise RuntimeError("BNFirmwareNinjaQueryBoardNamesForArchitecture")

        try:
            board_list = []
            for i in range(count):
                board_list.append(boards[i].decode("utf-8"))

            return board_list
        finally:
            core.BNFirmwareNinjaFreeBoardNames(boards, count)

    def get_devices_for_board(self, name: str) -> list[FirmwareNinjaDevice]:
        """
        ``get_devices_for_board`` queries the hardware device information for a specific board

        :Example:

            >>> fwn = FirmwareNinja(bv)
            >>> fwn.get_devices_for_board(fwn.boards[0])[0]
            FirmwareNinjaDevice(name='nand@12f', start=303, size=1024, info='marvell,orion-nand')

        :param str name: Name of the board
        :return: List of Firmware Ninja devices
        :rtype: list[FirmwareNinjaDevice]
        """

        devices = ctypes.POINTER(core.BNFirmwareNinjaDevice)()
        count = core.BNFirmwareNinjaQueryBoardDevices(self._handle, self._view.arch.handle, name, ctypes.byref(devices))
        if count == -1:
            raise RuntimeError("BNFirmwareNinjaQueryBoardDevices")

        try:
            device_list = []
            for i in range(count):
                device_list.append(
                    FirmwareNinjaDevice(
                        name=devices[i].name,
                        start=devices[i].start,
                        size=devices[i].end - devices[i].start,
                        info=devices[i].info,
                    )
                )

            return device_list
        finally:
            core.BNFirmwareNinjaFreeDevices(devices, count)

    def get_sections_from_entropy(
        self,
        high_code_entropy_threshold: float = 0.910,
        low_code_entropy_threshold: float = 0.500,
        block_size: int = 4096,
        mode: FirmwareNinjaSectionAnalysisMode = FirmwareNinjaSectionAnalysisMode.DetectStringsSectionAnalysisMode,
    ) -> list[FirmwareNinjaSection]:
        """
        ``get_sections_from_entropy`` uses entropy analysis and heuristics to identify code, data, padding, and
        compressed sections in the file-backed regions of the binary view

        :Example:

            >>> fwn = FirmwareNinja(bv)
            >>> fwn.get_sections_from_entropy(block_size=2048)[0].entropy
            0.48716872930526733
            >>> fwn.get_sections_from_entropy(block_size=2048)[0].type
            <FirmwareNinjaSectionType.DataSectionType: 1>

        :param float high_code_entropy_threshold: High code entropy threshold
        :param float low_code_entropy_threshold: Low code entropy threshold
        :param int block_size: Block size
        :param FirmwareNinjaSectionAnalysisMode mode: Analysis mode
        :return: List of sections
        :rtype: list[FirmwareNinjaSection]
        """

        sections = ctypes.POINTER(core.BNFirmwareNinjaSection)()
        count = core.BNFirmwareNinjaFindSectionsWithEntropy(
            self._handle,
            ctypes.byref(sections),
            high_code_entropy_threshold,
            low_code_entropy_threshold,
            block_size,
            mode,
        )
        if count == -1:
            raise RuntimeError("BNFirmwareNinjaFindSectionsWithEntropy")

        try:
            section_list = []
            for i in range(count):
                section_list.append(
                    FirmwareNinjaSection(
                        type=FirmwareNinjaSectionType(sections[i].type),
                        start=sections[i].start,
                        size=sections[i].end - sections[i].start,
                        entropy=sections[i].entropy,
                    )
                )

            return section_list
        finally:
            core.BNFirmwareNinjaFreeSections(sections, count)

    def get_function_memory_accesses(self, progress_func: Callable = None) -> list[FirmwareNinjaFunctionMemoryAccesses]:
        """
        ``get_function_memory_accesses`` runs analysis to find accesses to memory regions that are not file-backed, such
        as memory-mapped I/O and RAM

        :param callback progress_func: optional function to be called with the current progress and total count.
        :return: List of function memory accesses
        :rtype: list[FirmwareNinjaFunctionMemoryAccesses]
        """

        fma_info = ctypes.POINTER((ctypes.POINTER(core.BNFirmwareNinjaFunctionMemoryAccesses)))()
        if progress_func is None:
            progress_cfunc = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
                lambda ctxt, cur, total: True
            )
        else:
            progress_cfunc = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
                lambda ctxt, cur, total: progress_func(cur, total)
            )

        count = core.BNFirmwareNinjaGetFunctionMemoryAccesses(
            self._handle, ctypes.byref(fma_info), progress_cfunc, None
        )
        if count == -1:
            raise RuntimeError("BNFirmwareNinjaGetFunctionMemoryAccesses")

        try:
            fma_info_list = []
            for i in range(count):
                fma_info_list.append(
                    FirmwareNinjaFunctionMemoryAccesses.from_BNFirmwareNinjaFunctionMemoryAccesses(
                        fma_info[i].contents, self._view
                    )
                )

            return fma_info_list
        finally:
            core.BNFirmwareNinjaFreeFunctionMemoryAccesses(fma_info, count)

    def _fma_info_list_to_array(self, fma: list[FirmwareNinjaFunctionMemoryAccesses]) -> ctypes.POINTER:
        fma_info_ptr_array = (ctypes.POINTER(core.BNFirmwareNinjaFunctionMemoryAccesses) * len(fma))()
        for i, info in enumerate(fma):
            accesses_ptr_array = (ctypes.POINTER(core.BNFirmwareNinjaMemoryAccess) * len(info.accesses))()
            for j, access in enumerate(info.accesses):
                accesses_ptr_array[j] = ctypes.pointer(FirmwareNinjaMemoryAccess.to_BNFirmwareNinjaMemoryAccess(access))

            fma_info_struct = core.BNFirmwareNinjaFunctionMemoryAccesses(
                start=info.function.start,
                count=len(info.accesses),
                accesses=accesses_ptr_array,
            )

            fma_info_ptr_array[i] = ctypes.pointer(fma_info_struct)

        return fma_info_ptr_array

    def store_function_memory_accesses(self, fma: list[FirmwareNinjaFunctionMemoryAccesses]) -> None:
        """
        ``store_function_memory_accesses`` saves information on function memory accesses to binary view metadata

        :Example:

            >>> fwn = FirmwareNinja(bv)
            >>> fma = fwn.get_function_memory_accesses()
            >>> fwn.store_function_memory_accesses(fma)

        :param list[FirmwareNinjaFunctionMemoryAccesses] fma: List of function memory accesses
        """

        fma_info_ptr_array = self._fma_info_list_to_array(fma)
        core.BNFirmwareNinjaStoreFunctionMemoryAccessesToMetadata(self._handle, fma_info_ptr_array, len(fma))

    def query_function_memory_accesses(self) -> list[FirmwareNinjaFunctionMemoryAccesses]:
        """
        ``query_function_memory_accesses`` queries information on function memory accesses from binary view metadata

        :return: List of function memory accesses
        :rtype: list[FirmwareNinjaFunctionMemoryAccesses]
        """

        fma = ctypes.POINTER((ctypes.POINTER(core.BNFirmwareNinjaFunctionMemoryAccesses)))()
        count = core.BNFirmwareNinjaQueryFunctionMemoryAccessesFromMetadata(self._handle, ctypes.byref(fma))
        if count == -1:
            return None

        try:
            fma_info_list = []
            for i in range(count):
                fma_info_list.append(
                    FirmwareNinjaFunctionMemoryAccesses.from_BNFirmwareNinjaFunctionMemoryAccesses(
                        fma[i].contents, self._view
                    )
                )

            return fma_info_list
        finally:
            core.BNFirmwareNinjaFreeFunctionMemoryAccesses(fma, count)

    def get_board_device_accesses(
        self, fma: list[FirmwareNinjaFunctionMemoryAccesses]
    ) -> list[FirmwareNinjaDeviceAccesses]:
        """
        ``get_board_device_accesses`` counts accesses made to memory-mapped hardware devices for each board that is
        compatible with the current architecture. This function can be used to help identify a board.

        :Example:

            >>> fwn = FirmwareNinja(bv)
            >>> fma = fwn.get_function_memory_accesses()
            >>> fwn.get_board_device_accesses(fma)[0]
            FirmwareNinjaDeviceAccesses(board_name='stm32mp157c-dhcom-picoitx', total=414, unique=2)

        :param list[FirmwareNinjaFunctionMemoryAccesses] fma: List of function memory accesses
        :return: List of device accesses
        :rtype: list[FirmwareNinjaDeviceAccesses]
        """

        fma_info_ptr_array = self._fma_info_list_to_array(fma)
        device_accesses = ctypes.POINTER(core.BNFirmwareNinjaDeviceAccesses)()
        count = core.BNFirmwareNinjaGetBoardDeviceAccesses(
            self._handle, fma_info_ptr_array, len(fma), ctypes.byref(device_accesses), self._view.arch.handle
        )
        if count == -1:
            raise RuntimeError("BNFirmwareNinjaGetBoardDeviceAccesses")

        try:
            device_accesses_list = []
            for i in range(count):
                device_accesses_list.append(
                    FirmwareNinjaDeviceAccesses(
                        board_name=device_accesses[i].name,
                        total=device_accesses[i].total,
                        unique=device_accesses[i].unique,
                    )
                )

            return device_accesses_list
        finally:
            core.BNFirmwareNinjaFreeBoardDeviceAccesses(device_accesses, count)

    def get_reference_tree(
        self,
        location: Union[Section, FirmwareNinjaDevice, Function, DataVariable, int],
        fma: list[FirmwareNinjaFunctionMemoryAccesses],
        value: Optional[int] = None,
    ) -> FirmwareNinjaReferenceNode:
        """
        ``get_reference_tree`` returns a tree of reference nodes for a memory region, function, or address

        :param Union[Section, FirmwareNinjaDevice, DataVariable, Function, int] location: Memory location to build the
        reference tree for
        :param list[FirmwareNinjaFunctionMemoryAccesses] fma: List of function memory accesses or None to use cross
        references. None should only be supplied if location is a Function, DataVariable, or address.
        :param Optional[int] value: Only include the node in the tree if this value is written to the location
        :return: Root reference node containing the reference tree
        :rtype: FirmwareNinjaReferenceNode
        """

        if fma is None and (isinstance(location, Section) or isinstance(location, FirmwareNinjaDevice)):
            raise ValueError("Function memory accesses cannot be None for location type Section or FirmwareNinjaDevice")

        value = ctypes.pointer(ctypes.c_uint64(value)) if value is not None else None

        fma_info_ptr_array = None
        if fma is not None and len(fma) > 0:
            fma_info_ptr_array = self._fma_info_list_to_array(fma)

        if isinstance(location, FirmwareNinjaDevice):
            bn_node = core.BNFirmwareNinjaGetMemoryRegionReferenceTree(
                self._handle, location.start, location.start + location.size, fma_info_ptr_array, len(fma), value
            )
        elif isinstance(location, Function):
            bn_node = core.BNFirmwareNinjaGetAddressReferenceTree(
                self._handle, location.start, fma_info_ptr_array, len(fma), value
            )
        elif isinstance(location, Section):
            bn_node = core.BNFirmwareNinjaGetMemoryRegionReferenceTree(
                self._handle, location.start, location.start + location.length, fma_info_ptr_array, len(fma), value
            )
        elif isinstance(location, DataVariable):
            bn_node = core.BNFirmwareNinjaGetAddressReferenceTree(
                self._handle, location.address, fma_info_ptr_array, len(fma), value
            )
        elif isinstance(location, int):
            bn_node = core.BNFirmwareNinjaGetAddressReferenceTree(
                self._handle, location, fma_info_ptr_array, len(fma), value
            )
        else:
            raise ValueError("Invalid location type")

        if not bn_node:
            return None

        return FirmwareNinjaReferenceNode(handle=bn_node, view=self._view)

    @property
    def relationships(self) -> list[FirmwareNinjaRelationship]:
        """
        ``relationships`` queries all Firmware Ninja relationships from the binary view metadata

        :return: List of relationships
        :rtype: list[FirmwareNinjaRelationship]
        """

        count = ctypes.c_ulonglong(0)
        relationships = core.BNFirmwareNinjaQueryRelationships(self._handle, count)
        relationship_list = []
        for i in range(count.value):
            relationship_list.append(FirmwareNinjaRelationship(self._view, handle=relationships[i]))

        return relationship_list

    def add_relationship(self, relationship: FirmwareNinjaRelationship) -> None:
        """
        ``add_relationship`` adds a relationship to the binary view metadata

        :param FirmwareNinjaRelationship relationship: Relationship to add
        """

        if relationship.primary is None:
            raise ValueError("Primary object must be set")

        if relationship.secondary is None:
            raise ValueError("Secondary object must be set")

        core.BNFirmwareNinjaAddRelationship(self._handle, relationship.handle)

    def get_relationship_by_guid(self, guid: str) -> FirmwareNinjaRelationship:
        """
        ``get_relationship_by_guid`` queries a relationship from the binary view metadata by GUID

        :param str guid: GUID of the relationship
        :return: Relationship
        :rtype: FirmwareNinjaRelationship
        """

        relationship = core.BNFirmwareNinjaGetRelationshipByGuid(self._handle, guid)
        if not relationship:
            return None

        return FirmwareNinjaRelationship(self._view, handle=relationship)

    def remove_relationship_by_guid(self, guid: str) -> None:
        """
        ``remove_relationship_by_guid`` removes a relationship from the binary view metadata by GUID

        :param str guid: GUID of the relationship
        """

        core.BNFirmwareNinjaRemoveRelationshipByGuid(self._handle, guid)
