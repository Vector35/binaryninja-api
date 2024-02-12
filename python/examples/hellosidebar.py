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

# This is an example UI plugin which demonstrates how to add sidebar widgets to Binary Ninja.
# See .../api/ui/sidebar.h for interface details.

from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, SidebarWidgetLocation, \
	SidebarContextSensitivity
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor

instance_id = 0


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class HelloSidebarWidget(SidebarWidget):
	def __init__(self, name, frame, data):
		global instance_id
		SidebarWidget.__init__(self, name)
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
		self.data = data

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


class HelloSidebarWidgetType(SidebarWidgetType):
	def __init__(self):
		# Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
		# HiDPI display compatibility. They will be automatically made theme
		# aware, so you need only provide a grayscale image, where white is
		# the color of the shape.
		icon = QImage(56, 56, QImage.Format_RGB32)
		icon.fill(0)

		# Render an "H" as the example icon
		p = QPainter()
		p.begin(icon)
		p.setFont(QFont("Open Sans", 56))
		p.setPen(QColor(255, 255, 255, 255))
		p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "H")
		p.end()

		SidebarWidgetType.__init__(self, icon, "Hello")

	def createWidget(self, frame, data):
		# This callback is called when a widget needs to be created for a given context. Different
		# widgets are created for each unique BinaryView. They are created on demand when the sidebar
		# widget is visible and the BinaryView becomes active.
		return HelloSidebarWidget("Hello", frame, data)

	def defaultLocation(self):
		# Default location in the sidebar where this widget will appear
		return SidebarWidgetLocation.RightContent

	def contextSensitivity(self):
		# Context sensitivity controls which contexts have separate instances of the sidebar widget.
		# Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
		# widget implementations to reduce resource usage.

		# This example widget uses a single instance and detects view changes.
		return SidebarContextSensitivity.SelfManagedSidebarContext


# Register the sidebar widget type with Binary Ninja. This will make it appear as an icon in the
# sidebar and the `createWidget` method will be called when a widget is required.
Sidebar.addSidebarWidgetType(HelloSidebarWidgetType())
