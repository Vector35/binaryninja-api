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

import os
import ctypes
from typing import Optional, Union
from dataclasses import dataclass
from .enums import BaseAddressDetectionPOIType, BaseAddressDetectionConfidence, BaseAddressDetectionPOISetting
from .binaryview import BinaryView
from . import _binaryninjacore as core


@dataclass
class BaseAddressDetectionReason:
    """``class BaseAddressDetectionReason`` is a class that is used to store information about why a base address is a
    candidate"""

    pointer: int
    offset: int
    type: BaseAddressDetectionPOIType


class BaseAddressDetection:
    """
    ``class BaseAddressDetection`` is a class that is used to detect the base address of position-dependent raw binaries

    >>> from binaryninja import *
    >>> bad = BaseAddressDetection("firmware.bin")
    >>> bad.detect_base_address()
    True
    >>> hex(bad.preferred_base_address)
    '0x4000000'
    """

    def __init__(self, view: Union[str, os.PathLike, BinaryView]) -> None:
        if isinstance(view, str) or isinstance(view, os.PathLike):
            view = BinaryView.load(view, update_analysis=False)

        _handle = core.BNCreateBaseAddressDetection(view.handle)
        assert _handle is not None, "core.BNCreateBaseAddressDetection returned None"
        self._handle = _handle
        self._view_arch = view.arch

        self._scores = list()
        self._confidence = 0
        self._last_tested_base_address = None

    def __del__(self):
        if core is not None:
            core.BNFreeBaseAddressDetection(self._handle)

    @property
    def scores(self) -> list[tuple[int, int]]:
        """
        ``scores`` returns a list of base addresses and their scores

        :return: list of tuples containing each base address and score
        :rtype: OrderedDict
        """

        return self._scores

    @property
    def confidence(self) -> BaseAddressDetectionConfidence:
        """
        ``confidence`` returns an enum that indicates confidence that the top base address candidate is correct

        :return: confidence of the base address detection results
        :rtype: BaseAddressDetectionConfidenceEnum
        """

        return self._confidence

    @property
    def last_tested_base_address(self) -> int:
        """
        ``last_tested_base_address`` returns the last base address candidate that was tested

        :return: last base address tested
        :rtype: int
        """

        return self._last_tested_base_address

    @property
    def preferred_base_address(self) -> int:
        """
        ``preferred_base_address`` returns the base address that is preferred by analysis

        :return: preferred base address
        :rtype: int
        """

        if not self._scores:
            return None

        return self._scores[0][0]

    def detect_base_address(
        self,
        arch: Optional[str] = "",
        analysis: Optional[str] = "basic",
        minstrlen: Optional[int] = 10,
        alignment: Optional[int] = 1024,
        lowerboundary: Optional[int] = 0,
        upperboundary: Optional[int] = 0xFFFFFFFFFFFFFFFF,
        poi_analysis: Optional[BaseAddressDetectionPOISetting] = BaseAddressDetectionPOISetting.POIAnalysisAll,
        max_pointers: Optional[int] = 128,
    ) -> bool:
        """
        ``detect_base_address`` runs analysis and attempts to identify candidate base addresses

        :return: True if initial analysis is valid, False otherwise
        :rtype: bool
        """

        if not arch and self._view_arch:
            arch = str(self._view_arch)

        if analysis not in ["basic", "controlFlow", "full"]:
            raise ValueError("invalid analysis setting")

        if alignment <= 0:
            raise ValueError("alignment must be greater than 0")

        if max_pointers < 2:
            raise ValueError("max pointers must be at least 2")

        if upperboundary < lowerboundary:
            raise ValueError("upper boundary must be greater than lower boundary")

        settings = core.BNBaseAddressDetectionSettings(
            arch.encode(),
            analysis.encode(),
            minstrlen,
            alignment,
            lowerboundary,
            upperboundary,
            poi_analysis,
            max_pointers,
        )

        if not core.BNDetectBaseAddress(self._handle, settings):
            return False

        max_candidates = 10
        scores = (core.BNBaseAddressDetectionScore * max_candidates)()
        confidence = core.BaseAddressDetectionConfidenceEnum()
        last_base = ctypes.c_ulonglong()
        num_candidates = core.BNGetBaseAddressDetectionScores(
            self._handle, scores, max_candidates, ctypes.byref(confidence), ctypes.byref(last_base)
        )

        if num_candidates == 0:
            return False

        self._scores.clear()
        for i in range(num_candidates):
            self._scores.append((scores[i].BaseAddress, scores[i].Score))

        self._confidence = confidence.value
        self._last_tested_base_address = last_base.value
        return True

    def get_reasons_for_base_address(self, base_address: int) -> list[BaseAddressDetectionReason]:
        """
        ``get_reasons_for_base_address`` returns a list of reasons why the specified base address is a candidate

        :param int base_address: base address to get reasons for
        :return: list of reasons for the specified base address
        :rtype: list
        """

        count = ctypes.c_size_t()
        reasons = core.BNGetBaseAddressDetectionReasons(self._handle, base_address, ctypes.byref(count))
        if count.value == 0:
            return []

        result = list()
        for i in range(count.value):
            result.append(BaseAddressDetectionReason(reasons[i].Pointer, reasons[i].POIOffset, reasons[i].POIType))
        core.BNFreeBaseAddressDetectionReasons(reasons)
        return result

    def _get_data_hits_by_type(self, base_address: int, poi_type: int) -> int:
        reasons = self.get_reasons_for_base_address(base_address)
        if not reasons:
            return 0

        hits = 0
        for reason in reasons:
            if reason.type == poi_type:
                hits += 1

        return hits

    def get_string_hits_for_base_address(self, base_address: int) -> int:
        """
        ``get_string_hits_for_base_address`` returns the number of times a pointer pointed to a string at the specified
        base address

        :param int base_address: base address to get data hits for
        :return: number of string hits for the specified base address
        :rtype: int
        """

        return self._get_data_hits_by_type(base_address, BaseAddressDetectionPOIType.POIString)

    def get_function_hits_for_base_address(self, base_address: int) -> int:
        """
        ``get_function_hits_for_base_address`` returns the number of times a pointer pointed to a function at the
        specified base address

        :param int base_address: base address to get function hits for
        :return: number of function hits for the specified base address
        :rtype: int
        """

        return self._get_data_hits_by_type(base_address, BaseAddressDetectionPOIType.POIFunction)

    def get_data_hits_for_base_address(self, base_address: int) -> int:
        """
        ``get_data_hits_for_base_address`` returns the number of times a pointer pointed to a data variable at the
        specified base address

        :param int base_address: base address to get data hits for
        :return: number of data hits for the specified base address
        :rtype: int
        """

        return self._get_data_hits_by_type(base_address, BaseAddressDetectionPOIType.POIDataVariable)
