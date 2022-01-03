# Copyright (c) 2015-2022 Vector 35 Inc
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

# This is an example UI plugin which demonstrates how to add global area widgets to Binary Ninja.
# See .../api/ui/globalarea.h for interface details.

from binaryninjaui import GlobalAreaWidget, GlobalArea, UIActionHandler
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor

instance_id = 0

# Global area widgets must derive from GlobalAreaWidget, not QWidget. GlobalAreaWidget is a QWidget but
# provides callbacks for global area events, and must be created with a title.
class HelloGlobalAreaWidget(GlobalAreaWidget):
	def __init__(self, name):
		global instance_id
		GlobalAreaWidget.__init__(self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)
		offset_layout = QHBoxLayout()
		offset_layout.addWidget(QLabel("Offset: "))
		self.offset = QLabel(hex(0))
		offset_layout.addWidget(self.offset)
		offset_layout.setAlignment(QtCore.Qt.AlignCenter)
		datatype_layout = QHBoxLayout()
		datatype_layout.addWidget(QLabel("Data Type: "))
		self.datatype = QLabel("")
		datatype_layout.addWidget(self.datatype)
		datatype_layout.setAlignment(QtCore.Qt.AlignCenter)
		layout = QVBoxLayout()
		title = QLabel(name, self)
		title.setAlignment(QtCore.Qt.AlignCenter)
		instance = QLabel("Instance: " + str(instance_id), self)
		instance.setAlignment(QtCore.Qt.AlignCenter)
		layout.addStretch()
		layout.addWidget(title)
		layout.addWidget(instance)
		layout.addLayout(datatype_layout)
		layout.addLayout(offset_layout)
		layout.addStretch()
		self.setLayout(layout)
		instance_id += 1
		self.data = None

	def notifyOffsetChanged(self, offset):
		self.offset.setText(hex(offset))

	def notifyViewChanged(self, view_frame):
		if view_frame is None:
			self.datatype.setText("None")
			self.data = None
		else:
			self.datatype.setText(view_frame.getCurrentView())
			view = view_frame.getCurrentViewInterface()
			self.data = view.getData()

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

# Register the global area widget constructor with Binary Ninja. This will create a new
# global area widget for each window. The callback function receives a `UIContext` object
# for identifying the window.
GlobalArea.addWidget(lambda context: HelloGlobalAreaWidget("Hello"))
