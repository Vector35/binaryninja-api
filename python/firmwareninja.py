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
from typing import Callable
from .binaryview import BinaryView
from .variable import RegisterValue
from .enums import (
    FirmwareNinjaMemoryHeuristic,
    FirmwareNinjaMemoryAccessType,
    FirmwareNinjaSectionAnalysisMode,
    FirmwareNinjaSectionType,
)
from .function import Function
from . import _binaryninjacore as core


@dataclass
class FirmwareNinjaDevice:
    """
    ``class FirmwareNinjaDevice`` is a class that stores information about a hardware device, including the device
    name, start address, size, and information about the device.
    """

    name: str
    start: int
    size: int
    info: str


@dataclass
class FirmwareNinjaSection:
    """
    ``class FirmwareNinjaSection`` is a class that stores information about a section identified with Firmware Ninja
    analysis, including the section type, start address, size, and entropy of the section.
    """

    type: FirmwareNinjaSectionType
    start: int
    size: int
    entropy: float


@dataclass
class FirmwareNinjaMemoryAccess:
    """
    ``class FirmwareNinjaMemoryAccess`` is a class that stores information on instructions that access regions of
    memory that are not file-backed, such as memory-mapped I/O and RAM.
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
    to memory regions that are not file-backed, such as memory-mapped I/O and RAM.
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
    a board based on the number of accesses to hardware devices.
    """

    board_name: str
    total: int
    unique: int


class FirmwareNinja:
    """
    ``class FirmwareNinja`` is a class that aids in analysis of embedded firmware images. This class is only available
    in the Ultimate Edition of Binary Ninja.

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
        ``store_custom_device`` store a user-defined Firmware Ninja device in the binary view metadata

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

    def query_custom_devices(self) -> list[FirmwareNinjaDevice]:
        """
        ``query_custom_devices`` queries user-defined Firmware Ninja devices from the binary view metadata

        :return: List of Firmware Ninja device objects
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

    def query_board_names(self) -> list[str]:
        """
        ``query_board_names`` queries the name of all boards that are compatible with the current architecture

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

    def query_devices_by_board_name(self, name: str) -> list[FirmwareNinjaDevice]:
        """
        ``query_devices_by_board_name`` queries the hardware device information for a specific board

        :Example:

            >>> fwn = FirmwareNinja(bv)
            >>> fwn.query_devices_by_board_name(fwn.query_board_names()[0])[0]
            FirmwareNinjaDevice(name='nand@12f', start=303, size=1024, info='marvell,orion-nand')

        :param str name: Name of the board
        :return: List of Firmware Ninja device objects
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

    def find_sections(
        self,
        high_code_entropy_threshold: float = 0.910,
        low_code_entropy_threshold: float = 0.500,
        block_size: int = 4096,
        mode: FirmwareNinjaSectionAnalysisMode = FirmwareNinjaSectionAnalysisMode.DetectStringsSectionAnalysisMode,
    ) -> list[FirmwareNinjaSection]:
        """
        ``find_sections`` finds sections with Firmware Ninja entropy analysis and heuristics

        :Example:

            >>> fwn = FirmwareNinja(bv)
            >>> fwn.find_sections(block_size=2048)[0].entropy
            0.48716872930526733
            >>> fwn.find_sections(block_size=2048)[0].type
            <FirmwareNinjaSectionType.DataSectionType: 1>

        :param float high_code_entropy_threshold: High code entropy threshold
        :param float low_code_entropy_threshold: Low code entropy threshold
        :param int block_size: Block size
        :param str mode: Analysis mode
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
        as memory-mapped I/O and RAM.

        :param callback progress_func: optional function to be called with the current progress and total count.
        :return: List of function memory accesses objects
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
                function=info.function.handle,
                accesses=accesses_ptr_array,
                count=len(info.accesses),
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

        :param list[FirmwareNinjaFunctionMemoryAccesses] fma: List of function memory accesses objects
        :return: None
        :rtype: None
        """

        fma_info_ptr_array = self._fma_info_list_to_array(fma)
        core.BNFirmwareNinjaStoreFunctionMemoryAccessesToMetadata(self._handle, fma_info_ptr_array, len(fma))

    def query_function_memory_accesses(self) -> list[FirmwareNinjaFunctionMemoryAccesses]:
        """
        ``query_function_memory_accesses`` queries information on function memory accesses from binary view metadata

        :return: List of function memory accesses objects
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

        :param list[FirmwareNinjaFunctionMemoryAccesses] fma: List of function memory accesses objects
        :return: List of device accesses objects
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
