# Copyright (c) 2025 Vector 35 Inc
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
import traceback
from dataclasses import dataclass
from typing import List, Optional, Union

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import function
from . import highlevelil
from . import highlight
from . import languagerepresentation
from .log import log_error
from .enums import HighlightStandardColor


@dataclass(frozen=True)
class LineFormatterSettings:
    hlil: highlevelil.HighLevelILFunction
    desired_line_length: int
    minimum_content_length: int
    tab_width: int
    language_name: Optional[str]
    comment_start_string: str
    comment_end_string: str
    annotation_start_string: str
    annotation_end_string: str

    @staticmethod
    def default(settings: Optional['function.DisassemblySettings'], hlil: 'highlevelil.HighLevelILFunction') -> 'LineFormatterSettings':
        """
        Gets the default line formatter settings for High Level IL code.
        """
        if settings is not None:
            settings = settings.handle
        api_obj = core.BNGetDefaultLineFormatterSettings(settings, hlil.handle)
        result = LineFormatterSettings._from_core_struct(api_obj[0])
        core.BNFreeLineFormatterSettings(api_obj)
        return result

    @staticmethod
    def language_representation_settings(
            settings: Optional['function.DisassemblySettings'], func: 'languagerepresentation.LanguageRepresentationFunction'
    ) -> 'LineFormatterSettings':
        """
        Gets the default line formatter settings for a language representation function.
        """
        if settings is not None:
            settings = settings.handle
        api_obj = core.BNGetLanguageRepresentationLineFormatterSettings(settings, func.handle)
        result = LineFormatterSettings._from_core_struct(api_obj[0])
        core.BNFreeLineFormatterSettings(api_obj)
        return result

    @staticmethod
    def _from_core_struct(settings: core.BNLineFormatterSettings) -> 'LineFormatterSettings':
        if len(settings.languageName) == 0:
            language_name = None
        else:
            language_name = settings.languageName
        hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(settings.highLevelIL))
        return LineFormatterSettings(
            hlil, settings.desiredLineLength, settings.minimumContentLength, settings.tabWidth, language_name,
            settings.commentStartString, settings.commentEndString,
            settings.annotationStartString, settings.annotationEndString
        )

    def _to_core_struct(self) -> core.BNLineFormatterSettings:
        result = core.BNLineFormatterSettings()
        result.highLevelIL = self.hlil.handle
        result.desiredLineLength = self.desired_line_length
        result.minimumContentLength = self.minimum_content_length
        result.tabWidth = self.tab_width
        result.languageName = self.language_name if self.language_name is not None else ""
        result.commentStartString = self.comment_start_string
        result.commentEndString = self.comment_end_string
        result.annotationStartString = self.annotation_start_string
        result.annotationEndString = self.annotation_end_string
        return result


class _LineFormatterMetaClass(type):
    def __iter__(self):
        binaryninja._init_plugins()
        count = ctypes.c_ulonglong()
        types = core.BNGetLineFormatterList(count)
        assert types is not None, "core.BNGetLineFormatterList returned None"
        try:
            for i in range(0, count.value):
                yield CoreLineFormatter(handle=types[i])
        finally:
            core.BNFreeLineFormatterList(types)

    def __getitem__(cls, value):
        binaryninja._init_plugins()
        lang = core.BNGetLineFormatterByName(str(value))
        if lang is None:
            raise KeyError("'%s' is not a valid formatter" % str(value))
        return CoreLineFormatter(handle=lang)


class LineFormatter(metaclass=_LineFormatterMetaClass):
    """
    ``class LineFormatter`` represents a custom line formatter, which can reformat code in High Level IL
    and high level language representations.
    """
    _registered_formatters = []
    formatter_name = None

    def __init__(self, handle=None):
        if handle is not None:
            self.handle = core.handle_of_type(handle, core.BNLineFormatter)

    def register(self):
        """Registers the line formatter."""
        if self.__class__.formatter_name is None:
            raise ValueError("formatter_name is missing")
        self._cb = core.BNCustomLineFormatter()
        self._cb.context = 0
        self._cb.formatLines = self._cb.formatLines.__class__(self._format_lines)
        self._cb.freeLines = self._cb.freeLines.__class__(self._free_lines)
        self.handle = core.BNRegisterLineFormatter(self.__class__.formatter_name, self._cb)
        self.__class__._registered_formatters.append(self)

    def _format_lines(
            self, ctxt, in_lines, in_count: int, settings: core.BNLineFormatterSettingsHandle,
            out_count: ctypes.POINTER(ctypes.c_ulonglong)
    ):
        try:
            settings = settings[0]
            if len(settings.languageName) == 0:
                language_name = None
            else:
                language_name = settings.languageName
            hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(settings.highLevelIL))
            settings = LineFormatterSettings(
                hlil, settings.desiredLineLength, settings.minimumContentLength, settings.tabWidth, language_name,
                settings.commentStartString, settings.commentEndString,
                settings.annotationStartString, settings.annotationEndString
            )

            lines = []
            if in_lines is not None:
                for i in range(0, in_count):
                    addr = in_lines[i].addr
                    if in_lines[i].instrIndex != 0xffffffffffffffff:
                        il_instr = hlil[in_lines[i].instrIndex]  # type: ignore
                    else:
                        il_instr = None
                    color = highlight.HighlightColor._from_core_struct(in_lines[i].highlight)
                    tokens = function.InstructionTextToken._from_core_struct(in_lines[i].tokens, in_lines[i].count)
                    lines.append(function.DisassemblyTextLine(tokens, addr, il_instr, color))

            lines = self.format_lines(lines, settings)

            out_count[0] = len(lines)
            self.line_buf = (core.BNDisassemblyTextLine * len(lines))()
            for i in range(len(lines)):
                line = lines[i]
                color = line.highlight
                if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
                    raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
                if isinstance(color, HighlightStandardColor):
                    color = highlight.HighlightColor(color)
                self.line_buf[i].highlight = color._to_core_struct()
                if line.address is None:
                    if len(line.tokens) > 0:
                        self.line_buf[i].addr = line.tokens[0].address
                    else:
                        self.line_buf[i].addr = 0
                else:
                    self.line_buf[i].addr = line.address
                if line.il_instruction is not None:
                    self.line_buf[i].instrIndex = line.il_instruction.instr_index
                else:
                    self.line_buf[i].instrIndex = 0xffffffffffffffff

                self.line_buf[i].count = len(line.tokens)
                self.line_buf[i].tokens = function.InstructionTextToken._get_core_struct(line.tokens)

            return ctypes.cast(self.line_buf, ctypes.c_void_p).value
        except:
            log_error(traceback.format_exc())
            out_count[0] = 0
            return None

    def _free_lines(self, ctxt, lines, count):
        self.line_buf = None

    def format_lines(
            self, in_lines: List['function.DisassemblyTextLine'], settings: 'LineFormatterSettings'
    ) -> List['function.DisassemblyTextLine']:
        """
        Reformats the given list of lines. Returns a new list of lines containing the reformatted code.
        """
        raise NotImplementedError

    @property
    def name(self) -> str:
        if hasattr(self, 'handle'):
            return core.BNGetLineFormatterName(self.handle)
        return self.__class__.formatter_name

    def __repr__(self):
        return f"<LineFormatter: {self.name}>"


_formatter_cache = {}


class CoreLineFormatter(LineFormatter):
    def __init__(self, handle: core.BNLineFormatter):
        super(CoreLineFormatter, self).__init__(handle=handle)
        if type(self) is CoreLineFormatter:
            global _formatter_cache
            _formatter_cache[ctypes.addressof(handle.contents)] = self

    def format_lines(
            self, in_lines: List['function.DisassemblyTextLine'], settings: 'LineFormatterSettings'
    ) -> List['function.DisassemblyTextLine']:
        line_buf = (core.BNDisassemblyTextLine * len(in_lines))()
        for i in range(len(in_lines)):
            line = in_lines[i]
            color = line.highlight
            if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
                raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
            if isinstance(color, HighlightStandardColor):
                color = highlight.HighlightColor(color)
            line_buf[i].highlight = color._to_core_struct()
            if line.address is None:
                if len(line.tokens) > 0:
                    line_buf[i].addr = line.tokens[0].address
                else:
                    line_buf[i].addr = 0
            else:
                line_buf[i].addr = line.address
            if line.il_instruction is not None:
                line_buf[i].instrIndex = line.il_instruction.instr_index
            else:
                line_buf[i].instrIndex = 0xffffffffffffffff

            line_buf[i].count = len(line.tokens)
            line_buf[i].tokens = function.InstructionTextToken._get_core_struct(line.tokens)

        count = ctypes.c_ulonglong()
        lines = core.BNFormatLines(self.handle, line_buf, len(in_lines), settings._to_core_struct(), count)

        result = []
        if lines is not None:
            result = []
            for i in range(0, count.value):
                addr = lines[i].addr
                if lines[i].instrIndex != 0xffffffffffffffff:
                    il_instr = settings.hlil[lines[i].instrIndex]  # type: ignore
                else:
                    il_instr = None
                color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
                tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
                result.append(function.DisassemblyTextLine(tokens, addr, il_instr, color))
            core.BNFreeDisassemblyTextLines(lines, count.value)
        return result

    @classmethod
    def _from_cache(cls, handle) -> 'LineFormatter':
        """
        Look up a representation type from a given BNLineFormatter handle
        :param handle: BNLineFormatter pointer
        :return: Formatter instance responsible for this handle
        """
        global _formatter_cache
        return _formatter_cache.get(ctypes.addressof(handle.contents)) or cls(handle)
