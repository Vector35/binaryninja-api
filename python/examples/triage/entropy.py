import math
import threading
from PySide2.QtWidgets import QWidget
from PySide2.QtGui import QImage, QColor, QPainter
from PySide2.QtCore import Qt, QSize, QTimer
from binaryninjaui import ViewFrame


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
			block = self.data.read(self.data.start + i * self.block_size, self.block_size)
			if len(block) == 0:
				v = 0
			else:
				dist = [0] * 0x100
				for j in range(0, len(block)):
					value = ord(block[j:j+1])
					dist[value] += 1
				s = 0
				for j in range(0, 256):
					if dist[j] != 0:
						s += (float(dist[j]) / len(block)) * math.log(float(dist[j]) / len(block))
				s = s / math.log(1 / 256.0)
				v = int(s * 255)
			if v >= 240:
				self.image.setPixelColor(i, 0, QColor(v, v, v / 4, 255))
			else:
				self.image.setPixelColor(i, 0, QColor(v / 4, v / 4, v, 255))
			self.updated = True


class EntropyWidget(QWidget):
	def __init__(self, parent, data):
		super(EntropyWidget, self).__init__(parent)
		self.data = data
		self.raw_data = data.file.raw

		self.block_size = 1024
		self.width = int(len(self.raw_data) / self.block_size)
		self.image = QImage(self.width, 1, QImage.Format_ARGB32)
		self.image.fill(QColor(0, 0, 0, 0))

		self.thread = EntropyThread(self.raw_data, self.image, self.block_size)
		self.started = False

		self.timer = QTimer()
		self.timer.timeout.connect(self.timerEvent)
		self.timer.setInterval(250)
		self.timer.setSingleShot(False)
		self.timer.start()

		self.setMinimumHeight(32)

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
		addr = self.data.get_address_for_data_offset(offset)
		view_frame = ViewFrame.viewFrameForWidget(self)
		if view_frame is None:
			return
		if addr is None:
			view_frame.navigate("Hex:Raw", offset)
		else:
			view_frame.navigate("Linear:" + view_frame.getCurrentDataType(), addr)
