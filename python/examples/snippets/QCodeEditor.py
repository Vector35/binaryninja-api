#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
Licensed under the terms of the MIT License
https://github.com/luchko/QCodeEditor
@author: Ivan Luchko (luchko.ivan@gmail.com)

Python Highlighting added by:
https://github.com/unihernandez22/QCodeEditor
@author: unihernandez22

Adapted to Binary Ninja by:
@author: Jordan Wiens (https://github.com/psifertex)

Integrating syntax highlighting from:
https://wiki.python.org/moin/PyQt/Python%20syntax%20highlighting
Released under the Modified BSD License: http://directory.fsf.org/wiki/License:BSD_3Clause

Note that this will not be merged back to the parent repositories as it's been
modified to be heavily dependent on the BN theme system.
'''

from PySide2.QtCore import Qt, QRect, QRegExp
from PySide2.QtWidgets import QWidget, QTextEdit, QPlainTextEdit
from PySide2.QtGui import (QPainter, QFont, QSyntaxHighlighter, QTextFormat, QTextCharFormat)
from binaryninjaui import (getMonospaceFont, getThemeColor, ThemeColor)


def format(color, style=''):
	"""Return a QTextCharFormat with the given attributes."""
	_color = eval('getThemeColor(ThemeColor.%s)' % color)

	_format = QTextCharFormat()
	_format.setForeground(_color)
	if 'bold' in style:
		_format.setFontWeight(QFont.Bold)
	if 'italic' in style:
		_format.setFontItalic(True)

	return _format

STYLES = {
	'keyword': format('StackVariableColor'),
	'operator': format('TokenHighlightColor'),
	'brace': format('LinearDisassemblySeparatorColor'),
	'defclass': format('DataSymbolColor'),
	'string': format('StringColor'),
	'string2': format('TypeNameColor'),
	'comment': format('AnnotationColor', 'italic'),
	'self': format('KeywordColor', 'italic'),
	'numbers': format('NumberColor'),
	'numberbar': getThemeColor(ThemeColor.BackgroundHighlightDarkColor),
	'blockselected': getThemeColor(ThemeColor.TokenHighlightColor),
	'blocknormal': getThemeColor(ThemeColor.TokenSelectionColor)
}

class PythonHighlighter (QSyntaxHighlighter):
	"""Syntax highlighter for the Python language.
	"""
	# Python keywords
	keywords = [
		'and', 'assert', 'break', 'class', 'continue', 'def',
		'del', 'elif', 'else', 'except', 'exec', 'finally',
		'for', 'from', 'global', 'if', 'import', 'in',
		'is', 'lambda', 'not', 'or', 'pass', 'print',
		'raise', 'return', 'try', 'while', 'yield',
		'None', 'True', 'False',
	]

	# Python operators
	operators = [
		'=',
		# Comparison
		'==', '!=', '<', '<=', '>', '>=',
		# Arithmetic
		'\+', '-', '\*', '/', '//', '\%', '\*\*',
		# In-place
		'\+=', '-=', '\*=', '/=', '\%=',
		# Bitwise
		'\^', '\|', '\&', '\~', '>>', '<<',
	]

	# Python braces
	braces = [
		'\{', '\}', '\(', '\)', '\[', '\]',
	]
	def __init__(self, document):
		QSyntaxHighlighter.__init__(self, document)

		# Multi-line strings (expression, flag, style)
		# FIXME: The triple-quotes in these two lines will mess up the
		# syntax highlighting from this point onward
		self.tri_single = (QRegExp("'''"), 1, STYLES['string2'])
		self.tri_double = (QRegExp('"""'), 2, STYLES['string2'])

		rules = []

		# Keyword, operator, and brace rules
		rules += [(r'\b%s\b' % w, 0, STYLES['keyword'])
			for w in PythonHighlighter.keywords]
		rules += [(r'%s' % o, 0, STYLES['operator'])
			for o in PythonHighlighter.operators]
		rules += [(r'%s' % b, 0, STYLES['brace'])
			for b in PythonHighlighter.braces]

		# All other rules
		rules += [
			# 'self'
			(r'\bself\b', 0, STYLES['self']),

			# Double-quoted string, possibly containing escape sequences
			(r'"[^"\\]*(\\.[^"\\]*)*"', 0, STYLES['string']),
			# Single-quoted string, possibly containing escape sequences
			(r"'[^'\\]*(\\.[^'\\]*)*'", 0, STYLES['string']),

			# 'def' followed by an identifier
			(r'\bdef\b\s*(\w+)', 1, STYLES['defclass']),
			# 'class' followed by an identifier
			(r'\bclass\b\s*(\w+)', 1, STYLES['defclass']),

			# From '#' until a newline
			(r'#[^\n]*', 0, STYLES['comment']),

			# Numeric literals
			(r'\b[+-]?[0-9]+[lL]?\b', 0, STYLES['numbers']),
			(r'\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b', 0, STYLES['numbers']),
			(r'\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b', 0, STYLES['numbers']),
		]

		# Build a QRegExp for each pattern
		self.rules = [(QRegExp(pat), index, fmt)
			for (pat, index, fmt) in rules]


	def highlightBlock(self, text):
		"""Apply syntax highlighting to the given block of text.
		"""
		# Do other syntax formatting
		for expression, nth, format in self.rules:
			index = expression.indexIn(text, 0)

			while index >= 0:
				# We actually want the index of the nth match
				index = expression.pos(nth)
				length = len(expression.cap(nth))
				self.setFormat(index, length, format)
				index = expression.indexIn(text, index + length)

		self.setCurrentBlockState(0)

		# Do multi-line strings
		in_multiline = self.match_multiline(text, *self.tri_single)
		if not in_multiline:
			in_multiline = self.match_multiline(text, *self.tri_double)


	def match_multiline(self, text, delimiter, in_state, style):
		"""Do highlighting of multi-line strings. ``delimiter`` should be a
		``QRegExp`` for triple-single-quotes or triple-double-quotes, and
		``in_state`` should be a unique integer to represent the corresponding
		state changes when inside those strings. Returns True if we're still
		inside a multi-line string when this function is finished.
		"""
		# If inside triple-single quotes, start at 0
		if self.previousBlockState() == in_state:
			start = 0
			add = 0
		# Otherwise, look for the delimiter on this line
		else:
			start = delimiter.indexIn(text)
			# Move past this match
			add = delimiter.matchedLength()

		# As long as there's a delimiter match on this line...
		while start >= 0:
			# Look for the ending delimiter
			end = delimiter.indexIn(text, start + add)
			# Ending delimiter on this line?
			if end >= add:
				length = end - start + add + delimiter.matchedLength()
				self.setCurrentBlockState(0)
			# No; multi-line string
			else:
				self.setCurrentBlockState(in_state)
				length = len(text) - start + add
			# Apply formatting
			self.setFormat(start, length, style)
			# Look for the next match
			start = delimiter.indexIn(text, start + length)

		# Return True if still inside a multi-line string, False otherwise
		if self.currentBlockState() == in_state:
			return True
		else:
			return False


class QCodeEditor(QPlainTextEdit):
	'''
	QCodeEditor inherited from QPlainTextEdit providing:

		numberBar - set by DISPLAY_LINE_NUMBERS flag equals True
		curent line highligthing - set by HIGHLIGHT_CURRENT_LINE flag equals True
		setting up QSyntaxHighlighter

	references:
		https://john.nachtimwald.com/2009/08/19/better-qplaintextedit-with-line-numbers/
		http://doc.qt.io/qt-5/qtwidgets-widgets-codeeditor-example.html

	'''
	class NumberBar(QWidget):
		'''class that deifnes textEditor numberBar'''

		def __init__(self, editor):
			QWidget.__init__(self, editor)

			self.editor = editor
			self.editor.blockCountChanged.connect(self.updateWidth)
			self.editor.updateRequest.connect(self.updateContents)
			self.font = QFont()
			self.numberBarColor = STYLES["numberbar"]

		def paintEvent(self, event):

			painter = QPainter(self)
			painter.fillRect(event.rect(), self.numberBarColor)

			block = self.editor.firstVisibleBlock()

			# Iterate over all visible text blocks in the document.
			while block.isValid():
				blockNumber = block.blockNumber()
				block_top = self.editor.blockBoundingGeometry(block).translated(self.editor.contentOffset()).top()

				# Check if the position of the block is out side of the visible area.
				if not block.isVisible() or block_top >= event.rect().bottom():
					break

				# We want the line number for the selected line to be bold.
				if blockNumber == self.editor.textCursor().blockNumber():
					self.font.setBold(True)
					painter.setPen(STYLES["blockselected"])
				else:
					self.font.setBold(False)
					painter.setPen(STYLES["blocknormal"])
				painter.setFont(self.font)

				# Draw the line number right justified at the position of the line.
				paint_rect = QRect(0, block_top, self.width(), self.editor.fontMetrics().height())
				painter.drawText(paint_rect, Qt.AlignLeft, str(blockNumber+1))

				block = block.next()

			painter.end()

			QWidget.paintEvent(self, event)

		def getWidth(self):
			count = self.editor.blockCount()
			width = self.fontMetrics().width(str(count)) + 10
			return width

		def updateWidth(self):
			width = self.getWidth()
			if self.width() != width:
				self.setFixedWidth(width)
				self.editor.setViewportMargins(width, 0, 0, 0);

		def updateContents(self, rect, scroll):
			if scroll:
				self.scroll(0, scroll)
			else:
				self.update(0, rect.y(), self.width(), rect.height())

			if rect.contains(self.editor.viewport().rect()):
				fontSize = self.editor.currentCharFormat().font().pointSize()
				self.font.setPointSize(fontSize)
				self.font.setStyle(QFont.StyleNormal)
				self.updateWidth()


	def __init__(self, DISPLAY_LINE_NUMBERS=True, HIGHLIGHT_CURRENT_LINE=True,
				 SyntaxHighlighter=None, *args):
		'''
		Parameters
		----------
		DISPLAY_LINE_NUMBERS : bool
			switch on/off the presence of the lines number bar
		HIGHLIGHT_CURRENT_LINE : bool
			switch on/off the current line highliting
		SyntaxHighlighter : QSyntaxHighlighter
			should be inherited from QSyntaxHighlighter

		'''
		super(QCodeEditor, self).__init__()

		self.setFont(QFont("Ubuntu Mono", 11))
		self.setLineWrapMode(QPlainTextEdit.NoWrap)

		self.DISPLAY_LINE_NUMBERS = DISPLAY_LINE_NUMBERS

		if DISPLAY_LINE_NUMBERS:
			self.number_bar = self.NumberBar(self)

		if HIGHLIGHT_CURRENT_LINE:
			self.currentLineNumber = None
			self.currentLineColor = STYLES['currentLine']
			self.cursorPositionChanged.connect(self.highligtCurrentLine)

		if SyntaxHighlighter is not None: # add highlighter to textdocument
		   self.highlighter = SyntaxHighlighter(self.document())

	def resizeEvent(self, *e):
		'''overload resizeEvent handler'''

		if self.DISPLAY_LINE_NUMBERS:   # resize number_bar widget
			cr = self.contentsRect()
			rec = QRect(cr.left(), cr.top(), self.number_bar.getWidth(), cr.height())
			self.number_bar.setGeometry(rec)

		QPlainTextEdit.resizeEvent(self, *e)

	def highligtCurrentLine(self):
		newCurrentLineNumber = self.textCursor().blockNumber()
		if newCurrentLineNumber != self.currentLineNumber:
			self.currentLineNumber = newCurrentLineNumber
			hi_selection = QTextEdit.ExtraSelection()
			hi_selection.format.setBackground(self.currentLineColor)
			hi_selection.format.setProperty(QTextFormat.FullWidthSelection, True)
			hi_selection.cursor = self.textCursor()
			hi_selection.cursor.clearSelection()
			self.setExtraSelections([hi_selection])

##############################################################################

if __name__ == '__main__':

	# TESTING

	def run_test():

		from PySide2.QtGui import QApplication
		import sys

		app = QApplication([])

		editor = QCodeEditor(DISPLAY_LINE_NUMBERS=True,
							 HIGHLIGHT_CURRENT_LINE=True,
							 SyntaxHighlighter=PythonHighlighter)

# 		text = '''<FINITELATTICE>
#   <LATTICE name="myLattice">
# 	<BASIS>
# 	  <VECTOR>1.0 0.0 0.0</VECTOR>
# 	  <VECTOR>0.0 1.0 0.0</VECTOR>
# 	</BASIS>
#   </LATTICE>
#   <PARAMETER name="L" />
#   <PARAMETER default="L" name="W" />
#   <EXTENT dimension="1" size="L" />
#   <EXTENT dimension="2" size="W" />
#   <BOUNDARY type="periodic" />
# </FINITELATTICE>
# '''
		text = """\
def hello(text):
	print(text)

hello('Hello World')

# Comment"""
		editor.setPlainText(text)
		editor.resize(400,250)
		editor.show()

		sys.exit(app.exec_())


	run_test()
