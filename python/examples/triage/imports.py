from PySide6.QtWidgets import QTreeView, QVBoxLayout, QWidget, QPushButton
from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from binaryninja.mediumlevelil import MediumLevelILOperation
from binaryninja.function import RegisterValueType
from binaryninja.enums import SymbolType, FunctionAnalysisSkipOverride
from binaryninja.types import Symbol, Type
from binaryninja.plugin import PluginCommand
import binaryninjaui
from binaryninjaui import ViewFrame, ViewType, FilterTarget, FilteredView, UIContext, UIActionHandler
import time

platform_info = [
	{
		"prefixes": ["windows"],
		"sym_lookups": ["GetProcAddress", "GetProcAddress@IAT"]
	},
	{
		"prefixes": ["linux", "freebsd", "mac"],
		"sym_lookups": ["_dlsym", "_dlsym@PLT", "dlsym", "dlsym@PLT"],
	}
]


def get_platform_info(bv):
	result = {
		"sym_lookups": [],
	}

	if bv.platform is None:
		return result

	def check_prefix(platform_name, prefixes):
		for prefix in prefixes:
			if platform_name.startswith(prefix):
				return True
		return False

	for p in platform_info:
		if check_prefix(bv.platform.name, p["prefixes"]):
			break
	else:
		return result

	syms = map(bv.get_symbol_by_raw_name, p["sym_lookups"])
	result["sym_lookups"] = [sym.address for sym in filter(lambda x: x is not None, syms)]

	return result

def propagate_var_name(func, mlil_ssa_func, ssa_var, name, ty):
	instructions = list(map(lambda instr: instr.instr_index, mlil_ssa_func.get_ssa_var_uses(ssa_var)))
	seen_instructions = set()

	handled_vars = set([ssa_var])

	var_idx = 1
	while len(instructions):
		idx = instructions.pop()
		instruction = mlil_ssa_func[idx]
		seen_instructions.add(idx)

		if instruction.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
			if instruction.src.operation != MediumLevelILOperation.MLIL_VAR_SSA:
				continue

			if instruction.src.src not in handled_vars:
				continue

			handled_vars.add(instruction.dest)

			for use in list(map(lambda instr: instr.instr_index, mlil_ssa_func.get_ssa_var_uses(instruction.dest))):
				if use not in seen_instructions:
					instructions.append(use)

			func.create_user_var(instruction.dest.var, ty, "%s_%d" % (name, var_idx))

			var_idx += 1
			pass
		elif instruction.operation == MediumLevelILOperation.MLIL_VAR_PHI:
			can_propagate = True
			for source in instruction.src:
				if source not in handled_vars:
					can_propagate = False
					break

			if not can_propagate:
				seen_instructions.remove(idx)
				continue

			handled_vars.add(instruction.dest)
			for use in list(map(lambda instr: instr.instr_index, mlil_ssa_func.get_ssa_var_uses(instruction.dest))):
				if use not in seen_instructions:
					instructions.append(use)

			func.create_user_var(instruction.dest.var, ty, "%s_%d" % (name, var_idx))
			var_idx += 1

		elif instruction.operation == MediumLevelILOperation.MLIL_STORE_SSA:
			if instruction.src.operation != MediumLevelILOperation.MLIL_VAR_SSA:
				continue

			if instruction.src.src not in handled_vars:
				continue

			store_dest = instruction.dest.value
			if store_dest.type not in [RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue]:
				continue

			func.view.define_user_symbol(Symbol(SymbolType.ImportAddressSymbol, store_dest.value, name))
			func.view.define_user_data_var(store_dest.value, ty)

def find_mlil_calls_to_targets(mlil_ssa_func, interesting_targets):
	for bb in mlil_ssa_func:
		for insn in bb:
			if insn.operation != MediumLevelILOperation.MLIL_CALL_SSA:
				continue
			target = insn.dest.value
			if target.type not in [ RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue, RegisterValueType.ImportedAddressValue ]:
				continue
			if target.value not in interesting_targets:
				continue
			yield insn
	return

def find_dynamically_linked_funcs(bv):
	platform_info = get_platform_info(bv)

	funcs_to_check = set()
	for lookup in platform_info["sym_lookups"]:
		for ref in bv.get_code_refs(lookup):
			ref.function.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
			funcs_to_check.add(ref.function)

	bv.update_analysis()
	time.sleep(1)

	for f in funcs_to_check:
		mlil_ssa = f.medium_level_il.ssa_form

		for call in find_mlil_calls_to_targets(mlil_ssa, platform_info["sym_lookups"]):
			if len(call.params) < 2 or len(call.output.vars_written) < 1:
				continue

			symbol_name_addr = call.params[1].value
			if symbol_name_addr.type not in [RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue]:
				continue

			output_var = call.output.vars_written[0]
			symbol_name = bv.get_ascii_string_at(symbol_name_addr.value).value
			#Add confidence to both the args and the return of zero
			symbol_type = Type.pointer(bv.parse_type_string("void foo()")[0], arch=bv.arch)

			if len(symbol_name) == 0:
				continue

			bv.define_user_data_var(symbol_name_addr.value, Type.array(Type.int(1), len(symbol_name)))

			output_name = symbol_name + "@DYN"
			f.create_user_var(output_var.var, symbol_type, output_name)
			propagate_var_name(f, mlil_ssa, output_var, output_name, symbol_type)


class GenericImportsModel(QAbstractItemModel):
	def __init__(self, data):
		super(GenericImportsModel, self).__init__()
		self.filterText = ""
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

	def extendEntries(self, entries):
		self.allEntries.extend(entries)
		self.setFilter(self.filterText)

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
			elif name.endswith("@DYN"):
				name = name[:-len("@DYN")]
			return name
		if index.column() == self.module_col:
			return self.getNamespace(self.entries[index.row()])
		if index.column() == self.ordinal_col:
			if self.entries[index.row()].ordinal == 0:
				return "DYN"
			else:
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
		self.filterText = filterText
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

		# Allow view-specific shortcuts when imports are focused
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)
		self.actionHandler.setActionContext(lambda: self.view.actionContext())

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
		self.data = data
		self.imports = ImportsTreeView(self, view, data)
		self.filter = FilteredView(self, self.imports, self.imports)
		layout.addWidget(self.filter, 1)
		self.setLayout(layout)
		self.setMinimumSize(UIContext.getScaledWindowSize(100, 196))

	def scanDynamic(self):
		find_dynamically_linked_funcs(self.data)
		addedSymbols = list(filter(lambda x: x.name.endswith("@DYN"), self.data.get_symbols_of_type(SymbolType.ImportAddressSymbol)))
		self.imports.model.extendEntries(addedSymbols)
