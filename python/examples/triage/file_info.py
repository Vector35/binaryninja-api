import os
import hashlib
import threading
import binaryninjaui
from binaryninjaui import UIContext
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QLabel, QGridLayout
from binaryninja.enums import ThemeColor


class CopyableLabel(QLabel):
	def __init__(self, text, color):
		super(CopyableLabel, self).__init__(text)
		from PySide6.QtGui import QPalette
		style = QPalette(self.palette())
		style.setColor(QPalette.WindowText, color)
		self.setPalette(style)
		self.setFont(binaryninjaui.getMonospaceFont(self))
		self.setCursor(Qt.PointingHandCursor)
		self.setMouseTracking(True)
		self.setToolTip("Click to Copy")
		self.copy_text = ""  # Empty - will fall back to current text

	def mousePressEvent(self, event):
		if event.button() == Qt.LeftButton:
			from PySide6.QtWidgets import QApplication
			# Fallback to current text if copy_text not set
			if self.copy_text:
				QApplication.clipboard().setText(self.copy_text)
			else:
				QApplication.clipboard().setText(self.text())

	def setCopyText(self, text):
		self.copy_text = text


class FileInfoWidget(QWidget):
	def __init__(self, parent, data, entropy_widget):
		super(FileInfoWidget, self).__init__(parent)
		self.data = data
		self.entropy_widget = entropy_widget

		layout = QGridLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setVerticalSpacing(1)

		row = 0

		# Get the file path
		file_path = data.file.original_filename
		view = data.parent_view if data.parent_view else data

		# Add path on disk
		self._add_field(layout, row, "Path on disk:", file_path)
		row += 1

		# Add path in project if available
		if data.file.project_file:
			project_path = data.file.project_file.path_in_project
			self._add_field(layout, row, "Path in project:", project_path)
			row += 1

		# Add file size
		file_size = f"0x{view.length:x}"
		self._add_copyable_field(layout, row, "Size:", file_size)
		row += 1

		# Add entropy (will be updated when calculation completes)
		self.entropy_label = CopyableLabel("Calculating...",
			binaryninjaui.getThemeColor(ThemeColor.AlphanumericHighlightColor))
		layout.addWidget(QLabel("Entropy:"), row, 0)
		layout.addWidget(self.entropy_label, row, 1)
		row += 1

		# Add hash fields (calculated in background)
		self.md5_label = CopyableLabel("Calculating...",
			binaryninjaui.getThemeColor(ThemeColor.AlphanumericHighlightColor))
		layout.addWidget(QLabel("MD5:"), row, 0)
		layout.addWidget(self.md5_label, row, 1)
		row += 1

		self.sha1_label = CopyableLabel("Calculating...",
			binaryninjaui.getThemeColor(ThemeColor.AlphanumericHighlightColor))
		layout.addWidget(QLabel("SHA-1:"), row, 0)
		layout.addWidget(self.sha1_label, row, 1)
		row += 1

		self.sha256_label = CopyableLabel("Calculating...",
			binaryninjaui.getThemeColor(ThemeColor.AlphanumericHighlightColor))
		layout.addWidget(QLabel("SHA-256:"), row, 0)
		layout.addWidget(self.sha256_label, row, 1)
		row += 1

		# Set column stretch so value column expands
		layout.setColumnStretch(1, 1)

		self.setLayout(layout)

		# Connect to entropy widget signal
		if entropy_widget:
			entropy_widget.entropyUpdated.connect(self._update_entropy)

		# Start hash calculation in background thread
		self.hash_thread = threading.Thread(target=self._calculate_hashes)
		self.hash_thread.daemon = True
		self.hash_thread.start()

	def _add_field(self, layout, row, name, value):
		value_label = QLabel(value)
		value_label.setFont(binaryninjaui.getMonospaceFont(self))
		layout.addWidget(QLabel(name), row, 0)
		layout.addWidget(value_label, row, 1)

	def _add_copyable_field(self, layout, row, name, value):
		value_label = CopyableLabel(value,
			binaryninjaui.getThemeColor(ThemeColor.AlphanumericHighlightColor))
		layout.addWidget(QLabel(name), row, 0)
		layout.addWidget(value_label, row, 1)

	def _calculate_hashes(self):
		view = self.data.parent_view if self.data.parent_view else self.data
		total_size = view.length

		md5 = hashlib.md5()
		sha1 = hashlib.sha1()
		sha256 = hashlib.sha256()

		offset = 0
		chunk_size = 128 * 1024 * 1024  # 128MB chunks

		while offset < total_size:
			remaining = total_size - offset
			current_chunk = min(chunk_size, remaining)
			data = view.read(offset, current_chunk)

			if data is None or len(data) != current_chunk:
				self.md5_label.setText("Error")
				self.sha1_label.setText("Error")
				self.sha256_label.setText("Error")
				return

			md5.update(data)
			sha1.update(data)
			sha256.update(data)
			offset += current_chunk

		# Update labels on main thread
		from PySide6.QtCore import QMetaObject, Q_ARG
		QMetaObject.invokeMethod(self.md5_label, "setText", Qt.QueuedConnection, Q_ARG(str, md5.hexdigest()))
		QMetaObject.invokeMethod(self.sha1_label, "setText", Qt.QueuedConnection, Q_ARG(str, sha1.hexdigest()))
		QMetaObject.invokeMethod(self.sha256_label, "setText", Qt.QueuedConnection, Q_ARG(str, sha256.hexdigest()))

	def _update_entropy(self, avg_entropy):
		self.entropy_label.setText(f"{avg_entropy:.6f}")
