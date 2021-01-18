# Copyright (c) 2015-2021 Vector 35 Inc
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

#   This is an example UI plugin which demonstrates how to add dock widgets to Binary Ninja.
# Dock widgets are realized in Binary Ninja with the QDockWidget class provided by Qt.
# QDockWidgets are container objects that can be docked inside a main window or floated as
# a top-level window. A UI widget is placed inside a QDockWidget container. In Binary Ninja,
# QDockWidgets are created and managed internally. Binary Ninja presents two styles of dock widgets.
#   Static: where one UI widget is placed in the container for the lifetime of the application.
#   Dynamic: where a UI widget exists for each binary view type instance, and is dynamically
#      swapped in/out of the container based on the current binary view selection.
# See .../api/ui/dockhandler.h for interface details.
# For Static dock widgets, the UI widget operates on multiple binary view instances (notified by notifyViewChanged)
# For Dynamic dock widgets, the UI widget operates on a single binary view instance

from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget

instance_id = 0
class HelloDockWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		global instance_id
		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
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

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

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

	@staticmethod
	def create_widget(name, parent, data = None):
		return HelloDockWidget(parent, name, data)

def addStaticDockWidget():
	dock_handler = DockHandler.getActiveDockHandler()
	parent = dock_handler.parent()
	dock_widget = HelloDockWidget.create_widget("HelloDockWidget (Static Dock)", parent)
	dock_handler.addDockWidget(dock_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True, False)

def addDynamicDockWidget():
	dock_handler = DockHandler.getActiveDockHandler()
	dock_handler.addDockWidget("HelloDockWidget (Dynamic Dock)", HelloDockWidget.create_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True)

addStaticDockWidget()
addDynamicDockWidget()
