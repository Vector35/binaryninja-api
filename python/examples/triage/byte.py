# coding: utf8

from PySide2.QtWidgets import QAbstractScrollArea, QAbstractSlider
from PySide2.QtGui import QPainter, QPalette, QFont
from PySide2.QtCore import Qt, QTimer, QRect
import binaryninjaui
from binaryninjaui import View, ViewType, RenderContext, UIContext, ThemeColor, UIAction
from binaryninja.enums import LinearDisassemblyLineType
from binaryninja.binaryview import AddressRange


class ByteViewLine(object):
	def __init__(self, addr, length, text, separator):
		self.address = addr
		self.length = length
		self.text = text
		self.separator = separator


class ByteView(QAbstractScrollArea, View):
	def __init__(self, parent, data):
		QAbstractScrollArea.__init__(self, parent)
		View.__init__(self)
		self.setupView(self)
		self.data = data
		self.byte_mapping = [
			u' ', u'☺', u'☻', u'♥', u'♦', u'♣', u'♠', u'•', u'◘', u'○', u'◙', u'♂', u'♀', u'♪', u'♫', u'☼',
			u'▸', u'◂', u'↕', u'‼', u'¶', u'§', u'▬', u'↨', u'↑', u'↓', u'→', u'←', u'∟', u'↔', u'▴', u'▾',
			u' ', u'!', u'"', u'#', u'$', u'%', u'&', u'\'', u'(', u')', u'*', u'+', u',', u'-', u'.', u'/',
			u'0', u'1', u'2', u'3', u'4', u'5', u'6', u'7', u'8', u'9', u':', u';', u'<', u'=', u'>', u'?',
			u'@', u'A', u'B', u'C', u'D', u'E', u'F', u'G', u'H', u'I', u'J', u'K', u'L', u'M', u'N', u'O',
			u'P', u'Q', u'R', u'S', u'T', u'U', u'V', u'W', u'X', u'Y', u'Z', u'[', u'\\', u']', u'^', u'_',
			u'`', u'a', u'b', u'c', u'd', u'e', u'f', u'g', u'h', u'i', u'j', u'k', u'l', u'm', u'n', u'o',
			u'p', u'q', u'r', u's', u't', u'u', u'v', u'w', u'x', u'y', u'z', u'{', u'|', u'}', u'~', u'⌂',
			u'Ç', u'ü', u'é', u'â', u'ä', u'à', u'å', u'ç', u'ê', u'ë', u'è', u'ï', u'î', u'ì', u'Ä', u'Å',
			u'É', u'æ', u'Æ', u'ô', u'ö', u'ò', u'û', u'ù', u'ÿ', u'Ö', u'Ü', u'¢', u'£', u'¥', u'₧', u'ƒ',
			u'á', u'í', u'ó', u'ú', u'ñ', u'Ñ', u'ª', u'º', u'¿', u'⌐', u'¬', u'½', u'¼', u'¡', u'«', u'»',
			u'░', u'▒', u'▓', u'│', u'┤', u'╡', u'╢', u'╖', u'╕', u'╣', u'║', u'╗', u'╝', u'╜', u'╛', u'┐',
			u'└', u'┴', u'┬', u'├', u'─', u'┼', u'╞', u'╟', u'╚', u'╔', u'╩', u'╦', u'╠', u'═', u'╬', u'╧',
			u'╨', u'╤', u'╥', u'╙', u'╘', u'╒', u'╓', u'╫', u'╪', u'┘', u'┌', u'█', u'▄', u'▌', u'▐', u'▀',
			u'α', u'ß', u'Γ', u'π', u'Σ', u'σ', u'µ', u'τ', u'Φ', u'Θ', u'Ω', u'δ', u'∞', u'φ', u'ε', u'∩',
			u'≡', u'±', u'≥', u'≤', u'⌠', u'⌡', u'÷', u'≈', u'°', u'∙', u'·', u'√', u'ⁿ', u'²', u'■', u' '
		]

		self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
		self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
		self.setFocusPolicy(Qt.StrongFocus)

		self.cursorAddr = self.data.start
		self.prevCursorAddr = self.cursorAddr
		self.selectionStartAddr = self.cursorAddr
		self.topAddr = self.cursorAddr
		self.topLine = 0
		self.selectionVisible = False
		self.caretVisible = False
		self.caretBlink = True
		self.leftButtonDown = False
		self.cols = 128
		self.updatesRequired = False
		self.visibleRows = 1
		self.lines = []

		self.updateRanges()

		areaSize = self.viewport().size()
		self.adjustSize(areaSize.width(), areaSize.height())

		if self.allocatedLength > 0x7fffffff:
			self.scrollBarMultiplier = (self.allocatedLength // 0x7fffffff) + 1
		else:
			self.scrollBarMultiplier = 1
		self.wheelDelta = 0
		self.updatingScrollBar = False
		self.verticalScrollBar().setRange(0, (self.allocatedLength - 1) // self.scrollBarMultiplier)
		self.verticalScrollBar().sliderMoved.connect(self.scrollBarMoved)
		self.verticalScrollBar().actionTriggered.connect(self.scrollBarAction)

		self.cursorTimer = QTimer(self)
		self.cursorTimer.setInterval(500)
		self.cursorTimer.setSingleShot(False)
		self.cursorTimer.timeout.connect(self.cursorTimerEvent)
		self.cursorTimer.start()

		self.updateTimer = QTimer(self)
		self.updateTimer.setInterval(200)
		self.updateTimer.setSingleShot(False)
		#self.updateTimer.timeout.connect(self.updateTimerEvent)

		self.actionHandler().bindAction("Move Cursor Up", UIAction(lambda ctxt: self.up(False)))
		self.actionHandler().bindAction("Move Cursor Down", UIAction(lambda ctxt: self.down(False)))
		self.actionHandler().bindAction("Move Cursor Left", UIAction(lambda ctxt: self.left(1, False)))
		self.actionHandler().bindAction("Move Cursor Right", UIAction(lambda ctxt: self.right(1, False)))
		self.actionHandler().bindAction("Move Cursor Word Left", UIAction(lambda ctxt: self.left(8, False)))
		self.actionHandler().bindAction("Move Cursor Word Right", UIAction(lambda ctxt: self.right(8, False)))
		self.actionHandler().bindAction("Extend Selection Up", UIAction(lambda ctxt: self.up(True)))
		self.actionHandler().bindAction("Extend Selection Down", UIAction(lambda ctxt: self.down(True)))
		self.actionHandler().bindAction("Extend Selection Left", UIAction(lambda ctxt: self.left(1, True)))
		self.actionHandler().bindAction("Extend Selection Right", UIAction(lambda ctxt: self.right(1, True)))
		self.actionHandler().bindAction("Extend Selection Word Left", UIAction(lambda ctxt: self.left(8, True)))
		self.actionHandler().bindAction("Extend Selection Word Right", UIAction(lambda ctxt: self.right(8, True)))
		self.actionHandler().bindAction("Page Up", UIAction(lambda ctxt: self.pageUp(False)))
		self.actionHandler().bindAction("Page Down", UIAction(lambda ctxt: self.pageDown(False)))
		self.actionHandler().bindAction("Extend Selection Page Up", UIAction(lambda ctxt: self.pageUp(True)))
		self.actionHandler().bindAction("Extend Selection Page Down", UIAction(lambda ctxt: self.pageDown(True)))
		self.actionHandler().bindAction("Move Cursor to Start Of Line", UIAction(lambda ctxt: self.moveToStartOfLine(False)))
		self.actionHandler().bindAction("Move Cursor to End Of Line", UIAction(lambda ctxt: self.moveToEndOfLine(False)))
		self.actionHandler().bindAction("Move Cursor to Start Of View", UIAction(lambda ctxt: self.moveToStartOfView(False)))
		self.actionHandler().bindAction("Move Cursor to End Of View", UIAction(lambda ctxt: self.moveToEndOfView(False)))
		self.actionHandler().bindAction("Extend Selection to Start Of Line", UIAction(lambda ctxt: self.moveToStartOfLine(True)))
		self.actionHandler().bindAction("Extend Selection to End Of Line", UIAction(lambda ctxt: self.moveToEndOfLine(True)))
		self.actionHandler().bindAction("Extend Selection to Start Of View", UIAction(lambda ctxt: self.moveToStartOfView(True)))
		self.actionHandler().bindAction("Extend Selection to End Of View", UIAction(lambda ctxt: self.moveToEndOfView(True)))

	def getData(self):
		return self.data

	def getStart(self):
		return self.data.start

	def getEnd(self):
		return self.data.end

	def getLength(self):
		return self.getEnd() - self.getStart()

	def getCurrentOffset(self):
		return self.cursorAddr

	def getSelectionOffsets(self):
		start = self.selectionStartAddr
		end = self.cursorAddr
		if end < start:
			t = start
			start = end
			end = t
		return (start, end)

	def updateRanges(self):
		self.ranges = self.data.allocated_ranges
		# Remove regions not backed by the file
		for i in self.data.segments:
			if i.data_length < len(i):
				self.removeRange(i.start + i.data_length, i.end)
		self.allocatedLength = 0
		for i in self.ranges:
			self.allocatedLength += i.end - i.start

	def removeRange(self, begin, end):
		newRanges = []
		for i in self.ranges:
			if (end <= i.start) or (begin >= i.end):
				newRanges.append(i)
			elif (begin <= i.start) and (end >= i.end):
				continue
			elif (begin <= i.start) and (end < i.end):
				newRanges.append(AddressRange(end, i.end))
			elif (begin > i.start) and (end >= i.end):
				newRanges.append(AddressRange(i.start, begin))
			else:
				newRanges.append(AddressRange(i.start, begin))
				newRanges.append(AddressRange(end, i.end))
		self.ranges = newRanges

	def setTopToAddress(self, addr):
		for i in self.ranges:
			if (addr >= i.start) and (addr <= i.end):
				self.topAddr = addr - ((addr - i.start) % self.cols)
				if self.topAddr < i.start:
					self.topAddr = i.start
				return
			if i.start > addr:
				self.topAddr = i.start
				return
		self.topAddr = self.data.end

	def navigate(self, addr):
		if addr < self.getStart():
			return False
		if addr > self.getEnd():
			return False
		self.cursorAddr = self.getStart()
		for i in self.ranges:
			if i.start > addr:
				break
			if addr > i.end:
				self.cursorAddr = i.end
			elif addr >= i.start:
				self.cursorAddr = addr
			else:
				self.cursorAddr = i.start
		self.setTopToAddress(self.cursorAddr)
		self.refreshLines()
		self.showContextAroundTop()
		self.selectNone()
		self.repositionCaret()
		return True

	def updateFonts(self):
		areaSize = self.viewport().size()
		self.adjustSize(areaSize.width(), areaSize.height())

	def createRenderContext(self):
		render = RenderContext(self)
		userFont = binaryninjaui.getMonospaceFont(self)
		# Some fonts aren't fixed width across all characters, use a known good one
		font = QFont("Menlo", userFont.pointSize())
		font.setKerning(False)
		render.setFont(font)
		return render

	def adjustSize(self, width, height):
		self.addrWidth = max(len("%x" % self.data.end), 8)
		render = self.createRenderContext()
		cols = ((width - 4) // render.getFontWidth()) - (self.addrWidth + 2)
		if cols != self.cols:
			self.cols = cols
			if self.topLine < len(self.lines):
				self.setTopToAddress(self.lines[self.topLine].address)
			else:
				self.setTopToAddress(self.cursorAddr)
			self.refreshLines()
		self.visibleRows = (height - 4) // render.getFontHeight()
		self.verticalScrollBar().setPageStep(self.visibleRows * self.cols // self.scrollBarMultiplier)
		self.refreshAtCurrentLocation()
		self.viewport().update()

	def getContiguousOffsetForAddress(self, addr):
		offset = 0
		for i in self.ranges:
			if (addr >= i.start) and (addr <= i.end):
				offset += addr - i.start
				break
			offset += i.end - i.start
		return offset

	def getAddressForContiguousOffset(self, offset):
		cur = 0
		for i in self.ranges:
			if offset < (cur + (i.end - i.start)):
				return i.start + (offset - cur)
			cur += i.end - i.start
		return self.data.end

	def refreshLines(self):
		addr = self.topAddr
		self.lines = []
		self.topLine = 0
		self.bottomAddr = self.topAddr
		self.updateRanges()
		if self.allocatedLength > 0x7fffffff:
			self.scrollBarMultiplier = (self.allocatedLength // 0x7fffffff) + 1
		else:
			self.scrollBarMultiplier = 1
		self.updatingScrollBar = True
		self.verticalScrollBar().setRange(0, (self.allocatedLength - 1) // self.scrollBarMultiplier)
		self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(addr) // self.scrollBarMultiplier)
		self.updatingScrollBar = False
		self.updateCache()
		self.viewport().update()
		UIContext.updateStatus()

	def refreshAtCurrentLocation(self):
		if self.topLine < len(self.lines):
			self.topAddr = self.lines[self.topLine].address
		self.refreshLines()

	def createLine(self, addr, length, separator):
		if separator:
			return ByteViewLine(addr, length, u'', True)
		else:
			data = self.data.read(addr, length)
			text = u''.join([self.byte_mapping[value] for value in data])
			return ByteViewLine(addr, length, text, False)

	def cachePreviousLines(self):
		prevEnd = None
		for i in self.ranges:
			if (self.topAddr > i.start) and (self.topAddr <= i.end):
				startLine = self.topAddr - ((self.topAddr - i.start) % self.cols)
				if startLine == self.topAddr:
					startLine -= self.cols
				if startLine < i.start:
					startLine = i.start
				line = self.createLine(startLine, self.topAddr - startLine, False)
				self.lines.insert(0, line)
				self.topLine += 1
				self.topAddr = startLine
				return True
			elif i.start >= self.topAddr:
				if prevEnd is None:
					return False
				line = self.createLine(prevEnd, i.start - prevEnd, True)
				self.lines.insert(0, line)
				self.topLine += 1
				self.topAddr = prevEnd
				return True
			prevEnd = i.end
		if prevEnd is None:
			return False
		line = self.createLine(prevEnd, self.topAddr - prevEnd, True)
		self.lines.insert(0, line)
		self.topLine += 1
		self.topAddr = prevEnd

	def cacheNextLines(self):
		lastAddr = self.data.start
		for i in self.ranges:
			if (self.bottomAddr >= i.start) and (self.bottomAddr < i.end):
				endLine = self.bottomAddr + self.cols
				if endLine > i.end:
					endLine = i.end
				line = self.createLine(self.bottomAddr, endLine - self.bottomAddr, False)
				self.lines.append(line)
				self.bottomAddr = endLine
				return True
			elif i.start > self.bottomAddr:
				line = self.createLine(self.bottomAddr, i.start - self.bottomAddr, True)
				self.lines.append(line)
				self.bottomAddr = i.start
				return True
			lastAddr = i.end
		if self.bottomAddr == lastAddr:
			# Ensure there is a place for the cursor at the end of the file
			if (len(self.lines) > 0) and (self.lines[-1].length != self.cols):
				return False
			line = self.createLine(lastAddr, 0, False)
			self.lines.append(line)
			self.bottomAddr += 1
			return True
		return False

	def updateCache(self):
		# Cache enough for the current page and the next page
		while (len(self.lines) - self.topLine) <= (self.visibleRows * 2):
			if not self.cacheNextLines():
				break
		# Cache enough for the previous page
		while self.topLine <= self.visibleRows:
			if not self.cachePreviousLines():
				break
		# Trim cache
		if self.topLine > (self.visibleRows * 4):
			self.lines = self.lines[self.topLine - (self.visibleRows * 4):]
			self.topLine = self.visibleRows * 4
			self.topAddr = self.lines[0].address
		if (len(self.lines) - self.topLine) > (self.visibleRows * 5):
			self.bottomAddr = self.lines[self.topLine + (self.visibleRows * 5)].address
			self.lines = self.lines[0:self.topLine + (self.visibleRows * 5)]

	def scrollLines(self, count):
		newOffset = self.topLine + count
		if newOffset < 0:
			self.topLine = 0
		elif newOffset >= len(self.lines):
			self.topLine = len(self.lines) - 1
		else:
			self.topLine = newOffset
		self.updateCache()
		self.viewport().update()
		if self.topLine < len(self.lines):
			self.updatingScrollBar = True
			addr = self.lines[self.topLine].address
			self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(addr) // self.scrollBarMultiplier)
			self.updatingScrollBar = False

	def showContextAroundTop(self):
		scroll = self.visibleRows // 4
		if scroll > self.topLine:
			self.topLine = 0
		else:
			self.topLine -= scroll
		if self.topLine < len(self.lines):
			self.updatingScrollBar = True
			addr = self.lines[self.topLine].address
			self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(addr) // self.scrollBarMultiplier)
			self.updatingScrollBar = False
		self.updateCache()

	def repositionCaret(self):
		self.updateCache()
		found = False
		for i in range(0, len(self.lines)):
			if (((self.cursorAddr >= self.lines[i].address) and (self.cursorAddr < (self.lines[i].address + self.lines[i].length))) or
				(((i + 1) == len(self.lines)) and (self.cursorAddr == (self.lines[i].address + self.lines[i].length)))):
				if i < self.topLine:
					self.topLine = i
				elif i > (self.topLine + self.visibleRows - 1):
					self.topLine = i - (self.visibleRows - 1)
				self.updatingScrollBar = True
				addr = self.lines[self.topLine].address
				self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(addr) // self.scrollBarMultiplier)
				self.updatingScrollBar = False
				self.updateCache()
				self.viewport().update()
				found = True
				break
		if not found:
			self.setTopToAddress(self.cursorAddr)
			self.refreshLines()
			self.showContextAroundTop()
		# Force caret to be visible and repaint
		self.caretBlink = True
		self.cursorTimer.stop()
		self.cursorTimer.start()
		self.updateCaret()
		UIContext.updateStatus()

	def updateCaret(self):
		# Rerender both the old caret position and the new caret position
		render = self.createRenderContext()
		for i in range(self.topLine, min(len(self.lines), self.topLine + self.visibleRows)):
			if (((self.prevCursorAddr >= self.lines[i].address) and (self.prevCursorAddr <= (self.lines[i].address + self.lines[i].length))) or
				((self.cursorAddr >= self.lines[i].address) and (self.cursorAddr <= (self.lines[i].address + self.lines[i].length)))):
				self.viewport().update(0, (i - self.topLine) * render.getFontHeight(),
					self.viewport().size().width(), render.getFontHeight() + 3)

	def resizeEvent(self, event):
		self.adjustSize(event.size().width(), event.size().height())

	def paintEvent(self, event):
		p = QPainter(self.viewport())
		render = self.createRenderContext()
		render.init(p)
		charWidth = render.getFontWidth()
		charHeight = render.getFontHeight()

		# Compute range that needs to be updated
		topY = event.rect().y()
		botY = topY + event.rect().height()
		topY = (topY - 2) // charHeight
		botY = ((botY - 2) // charHeight) + 1

		# Compute selection range
		selection = False
		selStart, selEnd = self.getSelectionOffsets()
		if selStart != selEnd:
			selection = True

		# Draw selection
		if selection:
			startY = None
			endY = None
			startX = None
			endX = None
			for i in range(0, len(self.lines)):
				if selStart >= self.lines[i].address:
					startY = i - self.topLine
					startX = selStart - self.lines[i].address
					if startX > self.cols:
						startX = self.cols
				if selEnd >= self.lines[i].address:
					endY = i - self.topLine
					endX = selEnd - self.lines[i].address
					if endX > self.cols:
						endX = self.cols

			if startY is not None and endY is not None:
				p.setPen(binaryninjaui.getThemeColor(ThemeColor.SelectionColor))
				p.setBrush(binaryninjaui.getThemeColor(ThemeColor.SelectionColor))
				if startY == endY:
					p.drawRect(2 + (self.addrWidth + 2 + startX) * charWidth, 2 + startY * charHeight,
						(endX - startX) * charWidth, charHeight + 1)
				else:
					p.drawRect(2 + (self.addrWidth + 2 + startX) * charWidth, 2 + startY * charHeight,
						(self.cols - startX) * charWidth, charHeight + 1)
					if endX > 0:
						p.drawRect(2 + (self.addrWidth + 2) * charWidth, 2 + endY * charHeight,
							endX * charWidth, charHeight + 1)
				if (endY - startY) > 1:
					p.drawRect(2 + (self.addrWidth + 2) * charWidth, 2 + (startY + 1) * charHeight,
						self.cols * charWidth, ((endY - startY) - 1) * charHeight + 1)

		# Paint each line
		color = self.palette().color(QPalette.WindowText)
		for y in range(topY, botY):
			if (y + self.topLine) < 0:
				continue
			if (y + self.topLine) >= len(self.lines):
				break
			if self.lines[y + self.topLine].separator:
				render.drawLinearDisassemblyLineBackground(p, LinearDisassemblyLineType.NonContiguousSeparatorLineType,
					QRect(0, 2 + y * charHeight, event.rect().width(), charHeight), 0)
				continue

			lineStartAddr = self.lines[y + self.topLine].address
			addrStr = "%.8x" % lineStartAddr
			length = self.lines[y + self.topLine].length
			text = self.lines[y + self.topLine].text

			cursorCol = None
			if (((self.cursorAddr >= lineStartAddr) and (self.cursorAddr < (lineStartAddr + length))) or
				(((y + self.topLine + 1) >= len(self.lines)) and (self.cursorAddr == (lineStartAddr + length)))):
				cursorCol = self.cursorAddr - lineStartAddr

			render.drawText(p, 2, 2 + y * charHeight, binaryninjaui.getThemeColor(ThemeColor.AddressColor), addrStr)
			render.drawText(p, 2 + (self.addrWidth + 2) * charWidth, 2 + y * charHeight, color, text)

			if self.caretVisible and self.caretBlink and not selection and cursorCol is not None:
				p.setPen(Qt.NoPen)
				p.setBrush(self.palette().color(QPalette.WindowText))
				p.drawRect(2 + (self.addrWidth + 2 + cursorCol) * charWidth, 2 + y * charHeight, charWidth, charHeight + 1)
				caretTextColor = self.palette().color(QPalette.Base)
				byteValue = self.data.read(lineStartAddr + cursorCol, 1)
				if len(byteValue) == 1:
					byteStr = self.byte_mapping[ord(byteValue)]
					render.drawText(p, 2 + (self.addrWidth + 2 + cursorCol) * charWidth, 2 + y * charHeight, caretTextColor, byteStr)

	def wheelEvent(self, event):
		if event.orientation() == Qt.Horizontal:
			return
		self.wheelDelta -= event.delta()
		if (self.wheelDelta <= -40) or (self.wheelDelta >= 40):
			lines = self.wheelDelta // 40
			self.wheelDelta -= lines * 40
			self.scrollLines(lines)

	def scrollBarMoved(self, value):
		if self.updatingScrollBar:
			return
		self.wheelDelta = 0
		addr = self.getAddressForContiguousOffset(value * self.scrollBarMultiplier)
		self.setTopToAddress(addr)
		self.refreshLines()
		for i in range(1, len(self.lines)):
			if (self.lines[i].address + self.lines[i].length) > addr:
				self.topLine = i - 1
				break
		self.updateCache()

	def scrollBarAction(self, action):
		if action == QAbstractSlider.SliderSingleStepAdd:
			self.wheelDelta = 0
			self.scrollLines(1)
		elif action == QAbstractSlider.SliderSingleStepSub:
			self.wheelDelta = 0
			self.scrollLines(-1)
		elif action == QAbstractSlider.SliderPageStepAdd:
			self.wheelDelta = 0
			self.scrollLines(self.visibleRows)
		elif action == QAbstractSlider.SliderPageStepSub:
			self.wheelDelta = 0
			self.scrollLines(-self.visibleRows)
		elif action == QAbstractSlider.SliderToMinimum:
			self.wheelDelta = 0
			self.setTopToAddress(self.getStart())
			self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(self.topAddr) // self.scrollBarMultiplier)
			self.refreshLines()
		elif action == QAbstractSlider.SliderToMaximum:
			self.wheelDelta = 0
			self.setTopToAddress(self.getEnd())
			self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(self.topAddr) // self.scrollBarMultiplier)
			self.refreshLines()

	def cursorTimerEvent(self):
		self.caretBlink = not self.caretBlink
		self.updateCaret()

	def focusInEvent(self, event):
		self.caretVisible = True
		self.updateCaret()

	def focusOutEvent(self, event):
		self.caretVisible = False
		self.leftButtonDown = False
		self.updateCaret()

	def selectNone(self):
		for i in self.lines:
			if (self.cursorAddr >= i.address) and (self.cursorAddr < (i.address + i.length)) and i.separator:
				self.cursorAddr = i.address + i.length
				break
		self.selectionStartAddr = self.cursorAddr
		if self.selectionVisible:
			self.viewport().update()
		self.repositionCaret()
		UIContext.updateStatus()

	def selectAll(self):
		self.selectionStartAddr = self.getStart()
		self.cursorAddr = self.getEnd()
		self.viewport().update()
		UIContext.updateStatus()

	def adjustAddressAfterBackwardMovement(self):
		lastAddr = self.getStart()
		for i in self.ranges:
			if (self.cursorAddr >= i.start) and (self.cursorAddr < i.end):
				break
			if i.start > self.cursorAddr:
				self.cursorAddr = lastAddr
				break
			lastAddr = i.end - 1

	def adjustAddressAfterForwardMovement(self):
		for i in self.ranges:
			if (self.cursorAddr >= i.start) and (self.cursorAddr < i.end):
				break
			if i.start > self.cursorAddr:
				self.cursorAddr = i.start
				break

	def left(self, count, selecting):
		if self.cursorAddr > (self.getStart() + count):
			self.cursorAddr -= count
		else:
			self.cursorAddr = self.getStart()
		self.adjustAddressAfterBackwardMovement()
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		if self.selectionVisible or selecting:
			self.viewport().update()

	def right(self, count, selecting):
		if self.cursorAddr <= (self.getEnd() - count):
			self.cursorAddr += count
		else:
			self.cursorAddr = self.getEnd()
		self.adjustAddressAfterForwardMovement()
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		if self.selectionVisible or selecting:
			self.viewport().update()

	def up(self, selecting):
		self.left(self.cols, selecting)

	def down(self, selecting):
		self.right(self.cols, selecting)

	def pageUp(self, selecting):
		for i in range(0, len(self.lines)):
			if (((self.cursorAddr >= self.lines[i].address) and (self.cursorAddr < (self.lines[i].address + self.lines[i].length))) or
				(((i + 1) == len(self.lines)) and (self.cursorAddr == (self.lines[i].address + self.lines[i].length)))):
				if i < self.visibleRows:
					self.cursorAddr = self.getStart()
				else:
					lineOfs = self.cursorAddr - self.lines[i].address
					self.cursorAddr = self.lines[i - self.visibleRows].address + lineOfs
					if self.cursorAddr < self.lines[i - self.visibleRows].address:
						self.cursorAddr = self.lines[i - self.visibleRows].address
					elif self.cursorAddr >= (self.lines[i - self.visibleRows].address + self.lines[i - self.visibleRows].length):
						self.cursorAddr = self.lines[i - self.visibleRows].address + self.lines[i - self.visibleRows].length - 1
		self.adjustAddressAfterBackwardMovement()
		if self.topLine > self.visibleRows:
			self.topLine -= self.visibleRows
		else:
			self.topLine = 0
		if self.topLine < len(self.lines):
			self.updatingScrollBar = True
			addr = self.lines[self.topLine].address
			self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(addr) // self.scrollBarMultiplier)
			self.updatingScrollBar = False
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		self.viewport().update()

	def pageDown(self, selecting):
		for i in range(0, len(self.lines)):
			if (((self.cursorAddr >= self.lines[i].address) and (self.cursorAddr < (self.lines[i].address + self.lines[i].length))) or
				(((i + 1) == len(self.lines)) and (self.cursorAddr == (self.lines[i].address + self.lines[i].length)))):
				if i >= (len(self.lines) - self.visibleRows):
					self.cursorAddr = self.getEnd()
				else:
					lineOfs = self.cursorAddr - self.lines[i].address
					self.cursorAddr = self.lines[i + self.visibleRows].address + lineOfs
					if self.cursorAddr < self.lines[i + self.visibleRows].address:
						self.cursorAddr = self.lines[i + self.visibleRows].address
					elif self.cursorAddr >= (self.lines[i + self.visibleRows].address + self.lines[i - self.visibleRows].length):
						self.cursorAddr = self.lines[i + self.visibleRows].address + self.lines[i - self.visibleRows].length - 1
		self.adjustAddressAfterForwardMovement()
		if (self.topLine + self.visibleRows) < len(self.lines):
			self.topLine += self.visibleRows
		elif len(self.lines) > 0:
			self.topLine = len(self.lines) - 1
		if self.topLine < len(self.lines):
			self.updatingScrollBar = True
			addr = self.lines[self.topLine].address
			self.verticalScrollBar().setValue(self.getContiguousOffsetForAddress(addr) // self.scrollBarMultiplier)
			self.updatingScrollBar = False
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		self.viewport().update()

	def moveToStartOfLine(self, selecting):
		for i in self.lines:
			if (self.cursorAddr >= i.address) and (self.cursorAddr < (i.address + i.length)):
				self.cursorAddr = i.address
				break
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		if self.selectionVisible or selecting:
			self.viewport().update()

	def moveToEndOfLine(self, selecting):
		for i in self.lines:
			if (self.cursorAddr >= i.address) and (self.cursorAddr < (i.address + i.length)):
				self.cursorAddr = i.address + i.length - 1
				break
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		if self.selectionVisible or selecting:
			self.viewport().update()

	def moveToStartOfView(self, selecting):
		self.cursorAddr = self.getStart()
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		if self.selectionVisible or selecting:
			self.viewport().update()

	def moveToEndOfView(self, selecting):
		self.cursorAddr = self.getEnd()
		if not selecting:
			self.selectNone()
		self.repositionCaret()
		if self.selectionVisible or selecting:
			self.viewport().update()

	def addressFromLocation(self, x, y):
		if y < 0:
			y = 0
		if x < 0:
			x = 0
		if x > self.cols:
			x = self.cols
		if (y + self.topLine) >= len(self.lines):
			return self.getEnd()
		if self.lines[y + self.topLine].separator:
			return self.lines[y + self.topLine].address - 1
		result = self.lines[y + self.topLine].address + x
		if result >= (self.lines[y + self.topLine].address + self.lines[y + self.topLine].length):
			if (y + self.topLine) == (len(self.lines) - 1):
				return self.getEnd()
			else:
				return self.lines[y + self.topLine].address + self.lines[y + self.topLine].length - 1
		return result

	def mousePressEvent(self, event):
		if event.button() != Qt.LeftButton:
			return
		render = self.createRenderContext()
		x = (event.x() - 2) // render.getFontWidth() - (self.addrWidth + 2)
		y = (event.y() - 2) // render.getFontHeight()
		self.lastMouseX = x
		self.lastMouseY = y
		self.cursorAddr = self.addressFromLocation(x, y)
		if (event.modifiers() & Qt.ShiftModifier) == 0:
			self.selectNone()
		self.repositionCaret()
		if (event.modifiers() & Qt.ShiftModifier) != 0:
			self.viewport().update()
		self.leftButtonDown = True

	def mouseMoveEvent(self, event):
		if not self.leftButtonDown:
			return
		render = self.createRenderContext()
		x = (event.x() - 2) // render.getFontWidth() - (self.addrWidth + 2)
		y = (event.y() - 2) // render.getFontHeight()
		if (x == self.lastMouseX) and (y == self.lastMouseY):
			return
		self.lastMouseX = x
		self.lastMouseY = y
		self.cursorAddr = self.addressFromLocation(x, y)
		self.repositionCaret()
		self.viewport().update()

	def mouseReleaseEvent(self, event):
		if event.button() != Qt.LeftButton:
			return
		self.leftButtonDown = False


class ByteViewType(ViewType):
	def __init__(self):
		super(ByteViewType, self).__init__("Bytes", "Byte Overview")

	def getPriority(self, data, filename):
		return 1

	def create(self, data, view_frame):
		return ByteView(view_frame, data)


ViewType.registerViewType(ByteViewType())
