from PySide2.QtWidgets import QTreeView
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex
from binaryninja.enums import SymbolType
import binaryninjaui


class GenericImportsModel(QAbstractItemModel):
	def __init__(self, data):
		super(GenericImportsModel, self).__init__()
		self.entries = []
		self.has_modules = False
		self.name_col = 1
		self.module_col = None
		self.total_cols = 2
		for sym in data.get_symbols_of_type(SymbolType.ImportAddressSymbol):
			self.entries.append(sym)
			if str(sym.namespace) != "BNINTERNALNAMESPACE":
				self.has_modules = True
		if self.has_modules:
			self.name_col = 2
			self.module_col = 1
			self.total_cols = 3

	def columnCount(self, parent):
		return self.total_cols

	def rowCount(self, parent):
		return len(self.entries)

	def data(self, index, role):
		if role != Qt.DisplayRole:
			return None
		if index.row() >= len(self.entries):
			return None
		if index.column() == 0:
			return "0x%x" % self.entries[index.row()].address
		if index.column() == self.name_col:
			name = self.entries[index.row()].name
			if name.endswith("@GOT"):
				name = name[:-len("@GOT")]
			elif name.endswith("@PLT"):
				name = name[:-len("@PLT")]
			elif name.endswith("@IAT"):
				name = name[:-len("@IAT")]
			return name
		if index.column() == self.module_col:
			return self.getNamespace(self.entries[index.row()])
		return None

	def headerData(self, section, orientation, role):
		if orientation == Qt.Vertical:
			return None
		if role != Qt.DisplayRole:
			return None
		if section == 0:
			return "Entry"
		if section == self.name_col:
			return "Name"
		if section == self.module_col:
			return "Module"
		return None

	def index(self, row, col, parent):
		if parent.isValid():
			return QModelIndex()
		if row >= len(self.entries):
			return QModelIndex()
		if col >= self.total_cols:
			return QModelIndex()
		return self.createIndex(row, col)

	def parent(self, index):
		return QModelIndex()

	def getSymbol(self, index):
		if index.row() >= len(self.entries):
			return None
		return self.entries[index.row()]

	def getNamespace(self, sym):
		name = str(sym.namespace)
		if name == "BNINTERNALNAMESPACE":
			return ""
		return name

	def sort(self, col, order):
		self.beginResetModel()
		if col == 0:
			self.entries.sort(key = lambda sym: sym.address, reverse = order != Qt.AscendingOrder)
		elif col == self.name_col:
			self.entries.sort(key = lambda sym: sym.name, reverse = order != Qt.AscendingOrder)
		elif col == self.module_col:
			self.entries.sort(key = lambda sym: self.getNamespace(sym), reverse = order != Qt.AscendingOrder)
		self.endResetModel()


class ImportsWidget(QTreeView):
	def __init__(self, parent, view, data):
		super(ImportsWidget, self).__init__(parent)
		self.data = data
		self.view = view

		self.model = GenericImportsModel(self.data)
		self.setModel(self.model)
		self.setRootIsDecorated(False)
		self.setUniformRowHeights(True)
		self.setSortingEnabled(True)
		self.sortByColumn(0, Qt.AscendingOrder)

		self.setFont(binaryninjaui.getMonospaceFont(self))

		self.clicked.connect(self.importSelected)

	def importSelected(self, index):
		sym = self.model.getSymbol(index)
		if sym is not None:
			self.view.setCurrentOffset(sym.address)
