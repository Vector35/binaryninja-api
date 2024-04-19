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
from typing import Optional
from . import _binaryninjacore as core


class BaseAddressDetection:
    """
    ``class BaseAddressDetection`` is a class that is used to detect the base address of position-dependent raw binaries

    >>> from binaryninja import *
    >>> bv = load("firmware.bin")
    >>> bad = BaseAddressDetection(bv)
    >>> bad.detect_base_address()
    True
    >>> hex(bad.preferred_base_address)
    '0x4000000'
    """

    def __init__(self, view: "BinaryView") -> None:
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

    def detect_base_address(
        self,
        arch: Optional[str] = "",
        analysis: Optional[str] = "basic",
        minstrlen: Optional[int] = 10,
        alignment: Optional[int] = 1024,
        lowerboundary: Optional[int] = 0,
        upperboundary: Optional[int] = 0xFFFFFFFFFFFFFFFF,
        poi_analysis: Optional[int] = 0,
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
            arch.encode('utf-8'), analysis.encode('utf-8'), minstrlen, alignment, lowerboundary, upperboundary,
            poi_analysis, max_pointers
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

        self._scores.clear()
        for i in range(num_candidates):
            self._scores.append((scores[i].BaseAddress, scores[i].Score))

        self._confidence = confidence.value
        self._last_tested_base_address = last_base.value
        return True

    @property
    def scores(self) -> list[tuple[int, int]]:
        """
        ``get_scores`` returns a list of base addresses and their scores

        :return: list of tuples containing each base address and score
        :rtype: OrderedDict
        """

        return self._scores

    @property
    def confidence(self) -> "BaseAddressDetectionConfidenceEnum":
        """
        ``get_confidence`` returns an enum that indicates confidence that the top base address candidate is correct

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
