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
from typing import Optional, Union, Literal
from dataclasses import dataclass
from .enums import BaseAddressDetectionPOIType, BaseAddressDetectionConfidence, BaseAddressDetectionPOISetting
from .binaryview import BinaryView
from . import _binaryninjacore as core


@dataclass
class BaseAddressDetectionReason:
    """``class BaseAddressDetectionReason`` is a class that stores information used to understand why a base address
    is a candidate. It consists of a pointer, the offset of the point-of-interest that the pointer aligns with, and the
    type of point-of-interest (string, function, or data variable)"""

    pointer: int
    offset: int
    type: BaseAddressDetectionPOIType


class BaseAddressDetection:
    """
    ``class BaseAddressDetection`` is a class that is used to detect candidate base addresses for position-dependent
    raw binaries

    :Example:

        >>> from binaryninja import *
        >>> bad = BaseAddressDetection("firmware.bin")
        >>> bad.detect_base_address()
        True
        >>> hex(bad.preferred_base_address)
        '0x4000000'
    """

    def __init__(self, view: Union[str, os.PathLike, BinaryView]) -> None:
        if isinstance(view, str) or isinstance(view, os.PathLike):
            view = BinaryView.load(str(view), update_analysis=False)

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
        ``scores`` returns a list of candidate base addresses and their scores

        .. note:: The score is set to the number of times a pointer pointed to a point-of-interest at that base address

        :Example:

            >>> from binaryninja import *
            >>> bad = BaseAddressDetection("firmware.bin")
            >>> bad.detect_base_address()
            True
            >>> for addr, score in bad.scores:
            ...     print(f"0x{addr:x}: {score}")
            ...
            0x4000000: 7
            0x400dc00: 1
            0x400d800: 1
            0x400cc00: 1
            0x400c400: 1
            0x400bc00: 1
            0x400b800: 1
            0x3fffc00: 1

        :return: list of tuples containing each base address and score
        :rtype: list[tuple[int, int]]
        """

        return self._scores

    @property
    def confidence(self) -> BaseAddressDetectionConfidence:
        """
        ``confidence`` returns an enum that indicates confidence the preferred candidate base address is correct

        :return: confidence of the base address detection results
        :rtype: BaseAddressDetectionConfidence
        """

        return self._confidence

    @property
    def last_tested_base_address(self) -> int:
        """
        ``last_tested_base_address`` returns the last candidate base address that was tested

        .. note:: This is useful for situations where the user aborts the analysis and wants to restart from the last \
        tested base address by setting the ``low_boundary`` parameter in :py:func:`BaseAddressDetection.detect_base_address`

        :return: last candidate base address tested
        :rtype: int
        """

        return self._last_tested_base_address

    @property
    def preferred_base_address(self) -> Optional[int]:
        """
        ``preferred_base_address`` returns the candidate base address which contains the most amount of pointers that
        align with discovered points-of-interest in the binary

        .. note:: :py:attr:`BaseAddressDetection.confidence` reports a confidence level that the preferred base is correct

        .. note:: :py:attr:`BaseAddressDetection.scores` returns a list of the top 10 candidate base addresses and their \
        scores and can be used to discover other potential candidates

        :return: preferred candidate base address
        :rtype: int
        """

        if not self._scores:
            return None

        return self._scores[0][0]

    @property
    def aborted(self) -> bool:
        """
        ``aborted`` indicates whether or not base address detection analysis was aborted early

        :return: True if the analysis was aborted, False otherwise
        :rtype: bool
        """

        return core.BNIsBaseAddressDetectionAborted(self._handle)

    def detect_base_address(
        self,
        arch: Optional[str] = "",
        analysis: Optional[str] = Literal["basic", "controlFlow", "full"],
        min_strlen: Optional[int] = 10,
        alignment: Optional[int] = 1024,
        low_boundary: Optional[int] = 0,
        high_boundary: Optional[int] = 0xFFFFFFFFFFFFFFFF,
        poi_analysis: Optional[BaseAddressDetectionPOISetting] = BaseAddressDetectionPOISetting.POIAnalysisAll,
        max_pointers: Optional[int] = 128,
    ) -> bool:
        """
        ``detect_base_address`` runs initial analysis and attempts to identify candidate base addresses

        .. note:: This operation can take a long time to complete depending on the size and complexity of the binary \
        and the settings used

        :param str arch: CPU architecture of the binary (defaults to using auto-detection)
        :param str analysis: analysis mode (``basic``, ``controlFlow``, or ``full``)
        :param int min_strlen: minimum length of a string to be considered a point-of-interest
        :param int alignment: byte boundary to align the base address to while brute-forcing
        :param int low_boundary: lower boundary of the base address range to test
        :param int high_boundary: upper boundary of the base address range to test
        :param BaseAddressDetectionPOISetting poi_analysis: specifies types of points-of-interest to use for analysis
        :param int max_pointers: maximum number of candidate pointers to collect per pointer cluster
        :return: True if initial analysis completed with results, False otherwise
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

        if high_boundary < low_boundary:
            raise ValueError("upper boundary must be greater than lower boundary")

        settings = core.BNBaseAddressDetectionSettings(
            arch.encode(),
            analysis.encode(),
            min_strlen,
            alignment,
            low_boundary,
            high_boundary,
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

    def abort(self) -> None:
        """
        ``abort`` aborts base address detection analysis

        .. note:: ``abort`` does not stop base address detection until after initial analysis has completed and it is \
        in the base address enumeration phase

        :rtype: None
        """

        core.BNAbortBaseAddressDetection(self._handle)

    def get_reasons(self, base_address: int) -> list[BaseAddressDetectionReason]:
        """
        ``get_reasons`` returns a list of reasons that can be used to determine why a base address is a candidate

        :param int base_address: base address to get reasons for
        :return: list of reasons for the specified base address
        :rtype: list[BaseAddressDetectionReason]
        """

        count = ctypes.c_size_t()
        reasons = core.BNGetBaseAddressDetectionReasons(self._handle, base_address, ctypes.byref(count))
        if count.value == 0:
            return []

        try:
            result = list()
            for i in range(count.value):
                result.append(BaseAddressDetectionReason(reasons[i].Pointer, reasons[i].POIOffset, reasons[i].POIType))
            return result
        finally:
            core.BNFreeBaseAddressDetectionReasons(reasons)

    def _get_data_hits_by_type(self, base_address: int, poi_type: int) -> int:
        reasons = self.get_reasons(base_address)
        if not reasons:
            return 0

        hits = 0
        for reason in reasons:
            if reason.type == poi_type:
                hits += 1

        return hits

    def get_string_hits(self, base_address: int) -> int:
        """
        ``get_string_hits`` returns the number of times a pointer pointed to a string at the specified
        base address

        .. note:: Data variables are only used as points-of-interest if analysis doesn't discover enough strings and \
        functions

        :param int base_address: base address to get string hits for
        :return: number of string hits for the specified base address
        :rtype: int
        """

        return self._get_data_hits_by_type(base_address, BaseAddressDetectionPOIType.POIString)

    def get_function_hits(self, base_address: int) -> int:
        """
        ``get_function_hits`` returns the number of times a pointer pointed to a function at the
        specified base address

        :param int base_address: base address to get function hits for
        :return: number of function hits for the specified base address
        :rtype: int
        """

        return self._get_data_hits_by_type(base_address, BaseAddressDetectionPOIType.POIFunction)

    def get_data_hits(self, base_address: int) -> int:
        """
        ``get_data_hits`` returns the number of times a pointer pointed to a data variable at the
        specified base address

        :param int base_address: base address to get data hits for
        :return: number of data hits for the specified base address
        :rtype: int
        """

        return self._get_data_hits_by_type(base_address, BaseAddressDetectionPOIType.POIDataVariable)
