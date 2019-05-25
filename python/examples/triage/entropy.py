import math
import threading
from PySide2.QtWidgets import QWidget
from PySide2.QtGui import QImage, QColor, QPainter
from PySide2.QtCore import Qt, QSize, QTimer
import binaryninjaui
from binaryninjaui import ViewFrame, ThemeColor, UIContext


class EntropyThread(threading.Thread):
	def __init__(self, data, image, block_size):
		super(EntropyThread, self).__init__()
		self.data = data
		self.image = image
		self.block_size = block_size
		self.updated = False

	def run(self):
		width = self.image.width()
		for i in range(0, width):
			v = int(self.data.get_entropy(self.data.start + i * self.block_size, self.block_size)[0] * 255)
			if v >= 240:
				color = binaryninjaui.getThemeColor(ThemeColor.YellowStandardHighlightColor)
				self.image.setPixelColor(i, 0, color)
			else:
				baseColor = binaryninjaui.getThemeColor(ThemeColor.FeatureMapBaseColor)
				entropyColor = binaryninjaui.getThemeColor(ThemeColor.BlueStandardHighlightColor)
				color = binaryninjaui.mixColor(baseColor, entropyColor, v)
				self.image.setPixelColor(i, 0, color)
			self.updated = True


class EntropyWidget(QWidget):
	def __init__(self, parent, view, data):
		super(EntropyWidget, self).__init__(parent)
		self.view = view
		self.data = data
		self.raw_data = data.file.raw

		self.block_size = (len(self.raw_data) / 4096) + 1
		if self.block_size < 1024:
			self.block_size = 1024
		self.width = int(len(self.raw_data) / self.block_size)
		self.image = QImage(self.width, 1, QImage.Format_ARGB32)
		self.image.fill(QColor(0, 0, 0, 0))

		self.thread = EntropyThread(self.raw_data, self.image, self.block_size)
		self.started = False

		self.timer = QTimer()
		self.timer.timeout.connect(self.timerEvent)
		self.timer.setInterval(100)
		self.timer.setSingleShot(False)
		self.timer.start()

		self.setMinimumHeight(UIContext.getScaledWindowSize(32, 32).height())

	def paintEvent(self, event):
		p = QPainter(self)
		p.drawImage(self.rect(), self.image)
		p.drawRect(self.rect())

	def sizeHint(self):
		return QSize(640, 32)

	def timerEvent(self):
		if not self.started:
			self.thread.start()
			self.started = True
		if self.thread.updated:
			self.thread.updated = False
			self.update()

	def mousePressEvent(self, event):
		if event.button() != Qt.LeftButton:
			return
		frac = float(event.x()) / self.rect().width()
		offset = int(frac * self.width * self.block_size)
		self.view.navigateToFileOffset(offset)
