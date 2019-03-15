from PySide2.QtWidgets import QTreeView, QVBoxLayout, QWidget
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from binaryninja.enums import SymbolType
import binaryninjaui
from binaryninjaui import ViewFrame, FilterTarget, FilteredView


class GenericImportsModel(QAbstractItemModel):
	def __init__(self, data):
		super(GenericImportsModel, self).__init__()
		self.allEntries = []
		self.has_modules = False
		self.name_col = 1
		self.module_col = None
		self.ordinal_col = None
		self.total_cols = 2
		self.sortCol = 0
		self.sortOrder = Qt.AscendingOrder
		for sym in data.get_symbols_of_type(SymbolType.ImportAddressSymbol):
			self.allEntries.append(sym)
			if str(sym.namespace) != "BNINTERNALNAMESPACE":
				self.has_modules = True
		if self.has_modules:
			self.name_col = 3
			self.module_col = 1
			self.ordinal_col = 2
			self.total_cols = 4
		self.entries = list(self.allEntries)

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
		if index.column() == 0:
			return "0x%x" % self.entries[index.row()].address
		if index.column() == self.name_col:
			name = self.entries[index.row()].full_name
			if name.endswith("@GOT"):
				name = name[:-len("@GOT")]
			elif name.endswith("@PLT"):
				name = name[:-len("@PLT")]
			elif name.endswith("@IAT"):
				name = name[:-len("@IAT")]
			return name
		if index.column() == self.module_col:
			return self.getNamespace(self.entries[index.row()])
		if index.column() == self.ordinal_col:
			return str(self.entries[index.row()].ordinal)
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

	def getNamespace(self, sym):
		name = str(sym.namespace)
		if name == "BNINTERNALNAMESPACE":
			return ""
		return name

	def performSort(self, col, order):
		if col == 0:
			self.entries.sort(key = lambda sym: sym.address, reverse = order != Qt.AscendingOrder)
		elif col == self.name_col:
			self.entries.sort(key = lambda sym: sym.full_name, reverse = order != Qt.AscendingOrder)
		elif col == self.module_col:
			self.entries.sort(key = lambda sym: self.getNamespace(sym), reverse = order != Qt.AscendingOrder)
		elif col == self.ordinal_col:
			self.entries.sort(key = lambda sym: sym.ordinal, reverse = order != Qt.AscendingOrder)

	def sort(self, col, order):
		self.beginResetModel()
		self.sortCol = col
		self.sortOrder = order
		self.performSort(col, order)
		self.endResetModel()

	def setFilter(self, filterText):
		self.beginResetModel()
		self.entries = []
		for entry in self.allEntries:
			if FilteredView.match(entry.full_name, filterText):
				self.entries.append(entry)
			elif FilteredView.match(self.getNamespace(entry), filterText):
				self.entries.append(entry)
		self.performSort(self.sortCol, self.sortOrder)
		self.endResetModel()


class ImportsTreeView(QTreeView, FilterTarget):
	def __init__(self, parent, view, data):
		QTreeView.__init__(self, parent)
		FilterTarget.__init__(self)
		self.data = data
		self.parent = parent
		self.view = view

		self.model = GenericImportsModel(self.data)
		self.setModel(self.model)
		self.setRootIsDecorated(False)
		self.setUniformRowHeights(True)
		self.setSortingEnabled(True)
		self.sortByColumn(0, Qt.AscendingOrder)
		if self.model.ordinal_col is not None:
			self.setColumnWidth(self.model.ordinal_col, 55)

		self.setFont(binaryninjaui.getMonospaceFont(self))

		self.selectionModel().currentChanged.connect(self.importSelected)
		self.doubleClicked.connect(self.importDoubleClicked)

	def importSelected(self, cur, prev):
		sym = self.model.getSymbol(cur)
		if sym is not None:
			self.view.setCurrentOffset(sym.address)

	def importDoubleClicked(self, cur):
		sym = self.model.getSymbol(cur)
		if sym is not None:
			viewFrame = ViewFrame.viewFrameForWidget(self)
			viewFrame.navigate("Linear:" + viewFrame.getCurrentDataType(), sym.address)

	def setFilter(self, filterText):
		self.model.setFilter(filterText)

	def scrollToFirstItem(self):
		self.scrollToTop()

	def scrollToCurrentItem(self):
		self.scrollTo(self.currentIndex())

	def selectFirstItem(self):
		self.setCurrentIndex(self.model.index(0, 0, QModelIndex()))

	def activateFirstItem(self):
		self.importDoubleClicked(self.model.index(0, 0, QModelIndex()))

	def closeFilter(self):
		self.setFocus(Qt.OtherFocusReason)

	def keyPressEvent(self, event):
		if (len(event.text()) == 1) and (ord(event.text()[0:1]) > 32) and (ord(event.text()[0:1]) < 127):
			self.parent.filter.showFilter(event.text())
			event.accept()
		elif (event.key() == Qt.Key_Return) or (event.key() == Qt.Key_Enter):
			sel = self.selectionModel().selectedIndexes()
			if len(sel) != 0:
				self.importDoubleClicked(sel[0])
		super(ImportsTreeView, self).keyPressEvent(event)


class ImportsWidget(QWidget):
	def __init__(self, parent, view, data):
		super(ImportsWidget, self).__init__(parent)
		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		self.imports = ImportsTreeView(self, view, data)
		self.filter = FilteredView(self, self.imports, self.imports)
		layout.addWidget(self.filter, 1)
		self.setLayout(layout)
		self.setMinimumSize(QSize(100, 196))
