from PySide2.QtWidgets import QTreeView
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from binaryninja.enums import SymbolType, SymbolBinding
import binaryninjaui
from binaryninjaui import ViewFrame


class GenericExportsModel(QAbstractItemModel):
	def __init__(self, data):
		super(GenericExportsModel, self).__init__()
		self.entries = []
		self.addr_col = 0
		self.name_col = 1
		self.ordinal_col = None
		self.total_cols = 2
		for sym in data.get_symbols_of_type(SymbolType.FunctionSymbol):
			if sym.binding == SymbolBinding.GlobalBinding:
				self.entries.append(sym)
		for sym in data.get_symbols_of_type(SymbolType.DataSymbol):
			if sym.binding == SymbolBinding.GlobalBinding:
				self.entries.append(sym)
		if data.view_type == "PE":
			self.ordinal_col = 0
			self.addr_col = 1
			self.name_col = 2
			self.total_cols = 3

	def columnCount(self, parent):
		return self.total_cols

	def rowCount(self, parent):
		if parent.isValid():
			return 0
		return len(self.entries)

	def data(self, index, role):
		if role != Qt.DisplayRole:
			return None
		if index.row() >= len(self.entries):
			return None
		if index.column() == self.addr_col:
			return "0x%x" % self.entries[index.row()].address
		if index.column() == self.name_col:
			return self.entries[index.row()].full_name
		if index.column() == self.ordinal_col:
			return str(self.entries[index.row()].ordinal)
		return None

	def headerData(self, section, orientation, role):
		if orientation == Qt.Vertical:
			return None
		if role != Qt.DisplayRole:
			return None
		if section == self.addr_col:
			return "Address"
		if section == self.name_col:
			return "Name"
		if section == self.ordinal_col:
			return "Ordinal"
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

	def sort(self, col, order):
		self.beginResetModel()
		if col == self.addr_col:
			self.entries.sort(key = lambda sym: sym.address, reverse = order != Qt.AscendingOrder)
		elif col == self.name_col:
			self.entries.sort(key = lambda sym: sym.full_name, reverse = order != Qt.AscendingOrder)
		elif col == self.ordinal_col:
			self.entries.sort(key = lambda sym: sym.ordinal, reverse = order != Qt.AscendingOrder)
		self.endResetModel()


class ExportsWidget(QTreeView):
	def __init__(self, parent, view, data):
		super(ExportsWidget, self).__init__(parent)
		self.data = data
		self.view = view

		self.model = GenericExportsModel(self.data)
		self.setModel(self.model)
		self.setRootIsDecorated(False)
		self.setUniformRowHeights(True)
		self.setSortingEnabled(True)
		self.sortByColumn(0, Qt.AscendingOrder)
		if self.model.ordinal_col is not None:
			self.setColumnWidth(self.model.ordinal_col, 55)
		self.setMinimumSize(QSize(100, 196))

		self.setFont(binaryninjaui.getMonospaceFont(self))

		self.selectionModel().currentChanged.connect(self.exportSelected)
		self.doubleClicked.connect(self.exportDoubleClicked)

	def exportSelected(self, cur, prev):
		sym = self.model.getSymbol(cur)
		if sym is not None:
			self.view.setCurrentOffset(sym.address)

	def exportDoubleClicked(self, cur):
		sym = self.model.getSymbol(cur)
		if sym is not None:
			viewFrame = ViewFrame.viewFrameForWidget(self)
			if len(self.data.get_functions_at(sym.address)) > 0:
				viewFrame.navigate("Graph:" + viewFrame.getCurrentDataType(), sym.address)
			else:
				viewFrame.navigate("Linear:" + viewFrame.getCurrentDataType(), sym.address)
