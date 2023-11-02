# Copyright (c) 2015-2023 Vector 35 Inc
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

from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler
from PySide6.QtCore import Qt, QRectF
from PySide6.QtWidgets import QVBoxLayout, QLabel, QComboBox, QTableWidget, QTableWidgetItem, QTextEdit, QApplication, QLineEdit, QHBoxLayout
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from binaryninja import Platform, BinaryView, TypeLibrary, log
from typing import Optional
from re import search

instance_id = 0

class TypelibTypeTableWidget(QTableWidget):
	def __init__(self, parent):
		QTableWidget.__init__(self, parent)
		self.typelib = None

	def setFilterRegExp(self, pattern):
		if pattern == "":
			for i in range(self.rowCount()):
				self.setRowHidden(i, False)
			return

		for i in range(self.rowCount()):
			match = False
			for j in range(self.columnCount()):
				item = self.item(i, j)
				if search(pattern, item.text()):
					match = True
					break
			self.setRowHidden(i, not match)

	def set_type_library(self, typelib, data=None):
		self.typelib = typelib
		self.setColumnCount(3)
		self.setHorizontalHeaderLabels(["Size", "Name", "Type"])
		self.setColumnWidth(0, 32)
		self.setColumnWidth(1, 192)
		self.setColumnWidth(2, 256)
		self.setRowCount(len(typelib.named_types))
		for i, (name, type) in enumerate(typelib.named_types.items()):
			self.setItem(i, 0, QTableWidgetItem(str(len(type))))
			self.setItem(i, 1, QTableWidgetItem(str(name)))
			if data is None:
				self.setItem(i, 2, QTableWidgetItem(str(type)))
			else:
				lines = type.get_lines(data, name)
				self.setItem(i, 2, QTableWidgetItem("".join([str(l) for l in lines])))


class TypelibObjectTableWidget(QTableWidget):
	def __init__(self, parent):
		QTableWidget.__init__(self, parent)
		self.typelib = None
		self.ordinals = None

	def lookup_ordinal(self, name: str) -> str:
		assert self.typelib is not None
		if md := self.typelib.query_metadata("ordinals"):
			if isinstance(md, str):
				md = self.typelib.query_metadata(md)
			assert isinstance(md, dict)
			for key, value in md.items():
				if name == value:
					return key
			return "0"
		return "0"

	def ordinals_exist(self) -> bool:
		assert self.typelib is not None
		return self.typelib.query_metadata("ordinals") is not None

	def set_type_library(self, typelib):
		self.typelib = typelib
		ordinals = self.ordinals_exist()
		columns = ["Ord", "Name", "Type"] if ordinals else ["Name", "Type"]
		self.setColumnCount(len(columns))
		self.setHorizontalHeaderLabels(columns)
		self.setRowCount(len(self.typelib.named_objects))
		column = 0
		if ordinals:
			self.setColumnWidth(column, 32)
			column += 1
		self.setColumnWidth(column, 128)
		column += 1
		self.setColumnWidth(column, 512)
		self.populate_table()

	def setFilterRegExp(self, pattern):
		if pattern == "":
			for i in range(self.rowCount()):
				self.setRowHidden(i, False)
			return

		for i in range(self.rowCount()):
			match = False
			for j in range(self.columnCount()):
				item = self.item(i, j)
				if search(pattern, item.text()):
					match = True
					break
			self.setRowHidden(i, not match)

	def populate_table(self):
		ordinals = self.ordinals_exist()
		for i, (name, type) in enumerate(self.typelib.named_objects.items()):
			name = str(name)
			column = 0
			if ordinals:
				self.setItem(i, column, QTableWidgetItem(self.lookup_ordinal(name)))
				column += 1
			self.setItem(i, column, QTableWidgetItem(name))
			column += 1
			self.setItem(i, column, QTableWidgetItem(str(type)))


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class TypelibExplorerWidget(SidebarWidget):
	def __init__(self, name, frame, data):
		global instance_id
		SidebarWidget.__init__(self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)
		layout = QVBoxLayout()
		self.previous_typelib_index = -1
		self.previous_platform_index = -1
		self.data = None
		self.platform = None
		self.typelib = None

		# platform selector
		self.platform_selector = QComboBox(self)
		self.platform_selector.setEditable(True)
		self.platform_selector.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
		for platform in list(Platform):
			self.platform_selector.addItem(platform.name, platform)
		if data is not None:
			self.platform_selector.setCurrentIndex(self.platform_selector.findText(data.platform.name))
		layout.addWidget(self.platform_selector)

		# typelib selector
		self.typelib_selector = QComboBox(self)
		self.typelib_selector.setEditable(True)
		self.typelib_selector.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
		layout.addWidget(self.typelib_selector)

		# guid
		layout.addWidget(QLabel("GUID", self))
		self.guid = QLineEdit(self)
		self.guid.setReadOnly(True)
		layout.addWidget(self.guid)

		# alternate names
		layout.addWidget(QLabel("Alternate Names", self))
		self.alternate_names = QTextEdit(self)
		self.alternate_names.setReadOnly(True)
		self.alternate_names.setMaximumHeight(64)
		layout.addWidget(self.alternate_names)

		# title and table of objects
		self.object_label = QLabel("Objects", self)
		self.object_filter = QLineEdit(self)
		self.object_filter.setPlaceholderText("Filter (regex)...")
		object_layout = QHBoxLayout()
		object_layout.addWidget(self.object_label)
		object_layout.addWidget(self.object_filter)
		layout.addLayout(object_layout)

		self.object_table = TypelibObjectTableWidget(self)
		self.object_table.verticalHeader().hide()
		self.object_table.setSortingEnabled(True)
		layout.addWidget(self.object_table)

		# title and table of types
		self.table_label = QLabel("Types", self)
		self.types_filter = QLineEdit(self)
		self.types_filter.setPlaceholderText("Filter (regex)...")
		type_layout = QHBoxLayout()
		type_layout.addWidget(self.table_label)
		type_layout.addWidget(self.types_filter)
		layout.addLayout(type_layout)
		self.type_table = TypelibTypeTableWidget(self)
		self.type_table.verticalHeader().hide()
		self.type_table.setSortingEnabled(True)
		layout.addWidget(self.type_table)
		self.setLayout(layout)

		# initialize
		instance_id += 1
		self.typelib_selector.currentIndexChanged.connect(self.on_typelib_selector_changed)
		self.platform_selector.currentIndexChanged.connect(self.on_platform_selector_changed)
		self.object_filter.textChanged.connect(self.object_table.setFilterRegExp)
		self.types_filter.textChanged.connect(self.type_table.setFilterRegExp)
		self.initialize_data(data)

	def setDisabled(self, disabled):
		self.typelib_selector.setDisabled(disabled)
		self.object_table.setDisabled(disabled)
		self.type_table.setDisabled(disabled)

	def initialize_data(self, data: Optional[BinaryView], platform: Optional[Platform]=None, typelib: Optional[TypeLibrary]=None):
		# first ensure we have valid platform and typelib
		data_changed = data != self.data
		platform_changed = platform != self.platform
		if (typelib is None or typelib == self.typelib) and not data_changed and not platform_changed:
			return

		if data is not None and platform is None:
			platform = data.platform

		assert platform is not None, "platform must be specified"

		self.data = data
		self.platform = platform

		if len(self.platform.type_libraries) == 0:
			self.typelib_selector.clear()
			self.type_table.clear()
			self.object_table.clear()
			self.guid.clear()
			self.alternate_names.clear()
			self.object_label.setText("Objects")
			self.table_label.setText("Types")
			log.log_info(f"No typelibs available for the selected platform {self.platform.name}")
			return

		loaded_names = []
		tl_name = lambda tl: tl.name if tl.name is not None else ""
		if typelib is None:
			if self.data is not None and len(self.data.type_libraries) > 0 and self.data.platform == self.platform:
				# if we're on the same platform as the binary show loaded typelibs first
				loaded_typelibs = self.data.type_libraries
				loaded_typelibs = sorted([tl for tl in loaded_typelibs], key=lambda tl: tl_name(tl))
				loaded_names = [tl.name for tl in loaded_typelibs]
				typelib = loaded_typelibs[0]
			else:
				typelib = sorted([tl for tl in self.platform.type_libraries], key=lambda tl: tl_name(tl))[0]

		assert typelib is not None, "typelib must be specified"
		self.typelib = typelib
		# platform and typelib are now guaranteed to be valid

		# clear all the old data
		self.type_table.clear()
		self.object_table.clear()
		self.guid.clear()
		self.alternate_names.clear()
		self.setDisabled(False)

		# populate the typelib selector
		if platform_changed or data_changed:
			self.typelib_selector.currentIndexChanged.disconnect(self.on_typelib_selector_changed)
			self.typelib_selector.clear()
			for name in loaded_names:
				self.typelib_selector.addItem(f"{name} - loaded", name)
			for name in sorted([tl_name(tl) for tl in self.platform.type_libraries]):
				if name not in loaded_names:
					self.typelib_selector.addItem(name, name)
			self.previous_typelib_index = self.typelib_selector.findData(tl_name(typelib))
			self.typelib_selector.setCurrentIndex(self.previous_typelib_index)
			self.typelib_selector.currentIndexChanged.connect(self.on_typelib_selector_changed)

		if platform_changed:
			self.platform_selector.setCurrentIndex(self.platform_selector.findText(self.platform.name))

		# populate the typelib data
		self.guid.setText(str(self.typelib.guid))
		self.alternate_names.setText("\n".join(self.typelib.alternate_names))
		self.object_label.setText(f"Objects ({len(self.typelib.named_objects)})")
		self.object_table.set_type_library(self.typelib)
		self.table_label.setText(f"Types ({len(self.typelib.named_types)})")
		self.type_table.set_type_library(self.typelib, self.data)

	def on_platform_selector_changed(self, index):
		if index == -1 or index == self.previous_platform_index:
			return
		self.previous_platform_index = index

		platform = self.platform_selector.itemData(index)
		self.initialize_data(self.data, platform)

	def on_typelib_selector_changed(self, index):
		if index == -1 or index == self.previous_typelib_index:
			return
		self.previous_typelib_index = index
		assert self.platform is not None
		typelib_name = self.typelib_selector.itemData(index)
		typelibs = self.platform.get_type_libraries_by_name(typelib_name)
		# get the typelib that has the same name as the one we selected
		typelib = next((tl for tl in typelibs if tl.name == typelib_name), None)
		if typelib is None:
			return

		self.initialize_data(self.data, self.platform, typelib)

	def on_binaryview_changed(self, data):
		self.initialize_data(data, data.platform)

	def notifyViewChanged(self, view_frame):
		data = view_frame.getCurrentViewInterface().getData() if view_frame is not None else None
		self.on_binaryview_changed(data)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


class TypelibExplorerWidgetType(SidebarWidgetType):
	def __init__(self):
		# Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
		# HiDPI display compatibility. They will be automatically made theme
		# aware, so you need only provide a grayscale image, where white is
		# the color of the shape.
		icon = QImage(56, 56, QImage.Format_RGB32)
		icon.fill(0)

		p = QPainter()
		p.begin(icon)
		p.setFont(QFont("Open Sans", 56))
		p.setPen(QColor(255, 255, 255, 255))
		p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "T")
		p.end()

		SidebarWidgetType.__init__(self, icon, "Typelib Explorer")

	def createWidget(self, frame, data):
		# This callback is called when a widget needs to be created for a given context. Different
		# widgets are created for each unique BinaryView. They are created on demand when the sidebar
		# widget is visible and the BinaryView becomes active.
		return TypelibExplorerWidget("Typelib Explorer", frame, data)


# Register the sidebar widget type with Binary Ninja. This will make it appear as an icon in the
# sidebar and the `createWidget` method will be called when a widget is required.
Sidebar.addSidebarWidgetType(TypelibExplorerWidgetType())
