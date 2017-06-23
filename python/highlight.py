# Copyright (c) 2015-2017 Vector 35 LLC
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


# Binary Ninja components
import _binaryninjacore as core
from enums import HighlightColorStyle, HighlightStandardColor


class HighlightColor(object):
	def __init__(self, color = None, mix_color = None, mix = None, red = None, green = None, blue = None, alpha = 255):
		if (red is not None) and (green is not None) and (blue is not None):
			self.style = HighlightColorStyle.CustomHighlightColor
			self.red = red
			self.green = green
			self.blue = blue
		elif (mix_color is not None) and (mix is not None):
			self.style = HighlightColorStyle.MixedHighlightColor
			if color is None:
				self.color = HighlightStandardColor.NoHighlightColor
			else:
				self.color = color
			self.mix_color = mix_color
			self.mix = mix
		else:
			self.style = HighlightColorStyle.StandardHighlightColor
			if color is None:
				self.color = HighlightStandardColor.NoHighlightColor
			else:
				self.color = color
		self.alpha = alpha

	def _standard_color_to_str(self, color):
		if color == HighlightStandardColor.NoHighlightColor:
			return "none"
		if color == HighlightStandardColor.BlueHighlightColor:
			return "blue"
		if color == HighlightStandardColor.GreenHighlightColor:
			return "green"
		if color == HighlightStandardColor.CyanHighlightColor:
			return "cyan"
		if color == HighlightStandardColor.RedHighlightColor:
			return "red"
		if color == HighlightStandardColor.MagentaHighlightColor:
			return "magenta"
		if color == HighlightStandardColor.YellowHighlightColor:
			return "yellow"
		if color == HighlightStandardColor.OrangeHighlightColor:
			return "orange"
		if color == HighlightStandardColor.WhiteHighlightColor:
			return "white"
		if color == HighlightStandardColor.BlackHighlightColor:
			return "black"
		return "%d" % color

	def __repr__(self):
		if self.style == HighlightColorStyle.StandardHighlightColor:
			if self.alpha == 255:
				return "<color: %s>" % self._standard_color_to_str(self.color)
			return "<color: %s, alpha %d>" % (self._standard_color_to_str(self.color), self.alpha)
		if self.style == HighlightColorStyle.MixedHighlightColor:
			if self.alpha == 255:
				return "<color: mix %s to %s factor %d>" % (self._standard_color_to_str(self.color),
					self._standard_color_to_str(self.mix_color), self.mix)
			return "<color: mix %s to %s factor %d, alpha %d>" % (self._standard_color_to_str(self.color),
				self._standard_color_to_str(self.mix_color), self.mix, self.alpha)
		if self.style == HighlightColorStyle.CustomHighlightColor:
			if self.alpha == 255:
				return "<color: #%.2x%.2x%.2x>" % (self.red, self.green, self.blue)
			return "<color: #%.2x%.2x%.2x, alpha %d>" % (self.red, self.green, self.blue, self.alpha)
		return "<color>"

	def _get_core_struct(self):
		result = core.BNHighlightColor()
		result.style = self.style
		result.color = HighlightStandardColor.NoHighlightColor
		result.mix_color = HighlightStandardColor.NoHighlightColor
		result.mix = 0
		result.r = 0
		result.g = 0
		result.b = 0
		result.alpha = self.alpha

		if self.style == HighlightColorStyle.StandardHighlightColor:
			result.color = self.color
		elif self.style == HighlightColorStyle.MixedHighlightColor:
			result.color = self.color
			result.mixColor = self.mix_color
			result.mix = self.mix
		elif self.style == HighlightColorStyle.CustomHighlightColor:
			result.r = self.red
			result.g = self.green
			result.b = self.blue

		return result
