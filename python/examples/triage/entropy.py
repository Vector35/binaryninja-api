import math
import threading
import binaryninjaui
from binaryninjaui import ViewFrame, UIContext
from PySide6.QtCore import Qt, QSize, QTimer, Signal
from PySide6.QtGui import QImage, QColor, QPainter
from PySide6.QtWidgets import QWidget
from binaryninja.enums import ThemeColor

class EntropyThread(threading.Thread):
	def __init__(self, data, image, block_size):
		super(EntropyThread, self).__init__()
		self.data = data
		self.image = image
		self.block_size = block_size
		self.updated = False
		self.average_entropy = 0.0
		self.sample_count = 0
		self.lock = threading.Lock()

	def run(self):
		width = self.image.width()
		for i in range(0, width):
			entropy_result = self.data.get_entropy(self.data.start + i * self.block_size, self.block_size)
			entropy_value = entropy_result[0] if entropy_result else 0.0
			v = int(entropy_value * 255)

			# Update running average
			with self.lock:
				self.sample_count += 1
				self.average_entropy += (entropy_value - self.average_entropy) / self.sample_count

			if v >= 240:
				color = binaryninjaui.getThemeColor(ThemeColor.YellowStandardHighlightColor)
				self.image.setPixelColor(i, 0, color)
			else:
				baseColor = binaryninjaui.getThemeColor(ThemeColor.FeatureMapBaseColor)
				entropyColor = binaryninjaui.getThemeColor(ThemeColor.BlueStandardHighlightColor)
				color = binaryninjaui.mixColor(baseColor, entropyColor, v)
				self.image.setPixelColor(i, 0, color)
			self.updated = True

	def get_average_entropy(self):
		with self.lock:
			return self.average_entropy


class EntropyWidget(QWidget):
	entropyUpdated = Signal(float)

	def __init__(self, parent, view, data):
		super(EntropyWidget, self).__init__(parent)
		self.view = view
		self.data = data
		self.raw_data = data.file.raw

		self.block_size = (self.raw_data.length / 4096) + 1
		if self.block_size < 1024:
			self.block_size = 1024
		self.width = int(self.raw_data.length / self.block_size)
		self.image = QImage(self.width, 1, QImage.Format_ARGB32)
		self.image.fill(QColor(0, 0, 0, 0))

		self.thread = EntropyThread(self.raw_data, self.image, self.block_size)
		self.started = False

		self.timer = QTimer()
		self.timer.timeout.connect(self.timerEvent)
		self.timer.setInterval(100)
		self.timer.setSingleShot(False)
		self.timer.start()

		self.setCursor(Qt.PointingHandCursor)
		self.setMouseTracking(True)
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
			self.entropyUpdated.emit(self.thread.get_average_entropy())

	def mousePressEvent(self, event):
		if event.button() != Qt.LeftButton:
			return
		frac = float(event.x()) / self.rect().width()
		offset = int(frac * self.width * self.block_size)
		self.view.navigateToFileOffset(offset)

	def mouseMoveEvent(self, event):
		frac = float(event.x()) / self.rect().width()
		offset = int(frac * self.width * self.block_size)
		addr = self.data.get_address_for_data_offset(offset)
		if addr is not None:
			self.setToolTip(f"0x{addr:x}")
		else:
			self.setToolTip(f"File offset: 0x{offset:x}")

	def get_average_entropy(self):
		return self.thread.get_average_entropy()
