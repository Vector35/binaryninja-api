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

# This is an example UI plugin which demonstrates how to add panes to Binary Ninja.
# See .../api/ui/pane.h for interface details.

from binaryninjaui import Pane, WidgetPane, UIActionHandler, UIActionHandler, UIAction, Menu, UIContext, UIContextNotification
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor

instance_id = 0

# Class to handle UI context notifications. This will be used to listen for view and address
# changes and update the pane accordingly.
class HelloNotifications(UIContextNotification):
	def __init__(self, widget):
		UIContextNotification.__init__(self)
		self.widget = widget

		# __del__ will not be called because the widget owns a reference to this object. Use
		# QWidget.destroyed event to know when to stop listening for notifications.
		self.widget.destroyed.connect(self.destroyed)

		UIContext.registerNotification(self)

	def destroyed(self):
		UIContext.unregisterNotification(self)

	def OnViewChange(self, context, frame, type):
		self.widget.updateState()

	def OnAddressChange(self, context, frame, view, location):
		self.widget.updateState()

# Pane widget itself. This can be any QWidget.
class HelloPaneWidget(QWidget, UIContextNotification):
	def __init__(self, data):
		global instance_id
		QWidget.__init__(self)
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
		title = QLabel("Hello Pane", self)
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

		# Populate initial state
		self.updateState()

		# Set up view and address change notifications
		self.notifications = HelloNotifications(self)

	def updateState(self):
		# Get the currently active view frame for this group of panes. There can be
		# multiple view frames in a single window, or the pane could be popped out
		# into its own window. UIContext.currentViewFrameForWidget will determine
		# the best view frame to use for context.
		frame = UIContext.currentViewFrameForWidget(self)

		# Update UI according to the active frame
		if frame:
			self.datatype.setText(frame.getCurrentView())
			view = frame.getCurrentViewInterface()
			self.data = view.getData()
			self.offset.setText(hex(view.getCurrentOffset()))
		else:
			self.datatype.setText("None")
			self.data = None

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	@staticmethod
	def createPane(context):
		if context.context and context.binaryView:
			widget = HelloPaneWidget(context.binaryView)
			pane = WidgetPane(widget, "Hello")
			context.context.openPane(pane)

	@staticmethod
	def canCreatePane(context):
		return context.context and context.binaryView

UIAction.registerAction("Hello Pane")
UIActionHandler.globalActions().bindAction("Hello Pane", UIAction(HelloPaneWidget.createPane, HelloPaneWidget.canCreatePane))
Menu.mainMenu("Tools").addAction("Hello Pane", "Hello")
