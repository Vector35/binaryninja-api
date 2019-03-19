# python stuff
import io
import os
import sys
import types
import traceback

# binja stuff
import binaryninjaui
from binaryninja.settings import Settings
from binaryninja import log
from binaryninja import _binaryninjacore as core
from binaryninjaui import View, ViewType, ViewFrame, UIContext, HexEditor
from binaryninja import binaryview
from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QGroupBox, QTreeWidget, QTreeWidgetItem, QLineEdit
from PySide2.QtCore import Qt

if sys.version_info[0] == 2:
	import kshelpers
else:
	from . import kshelpers

class KaitaiView(QScrollArea, View):
	def __init__(self, parent, binaryView):
		QScrollArea.__init__(self, parent)

		View.__init__(self)
		self.setupView(self)

		# BinaryViewType
		self.binaryView = binaryView

		self.rootSelectionStart = 0
		self.rootSelectionEnd = 1

		self.ioRoot = None
		self.ioCurrent = None

		container = QWidget(self)
		layout = QVBoxLayout()

		self.treeGroup = QGroupBox("Data Tree:")
		treeLayout = QVBoxLayout()
		self.treeWidget = QTreeWidget()
		self.treeWidget.setColumnCount(4)
		self.treeWidget.setHeaderLabels(['label','value','start','end'])
		self.treeWidget.itemSelectionChanged.connect(self.onTreeSelect)
		self.structPath = QLineEdit("root")
		self.structPath.setDisabled(True)
		treeLayout.addWidget(self.structPath)
		treeLayout.addWidget(self.treeWidget)
		self.treeGroup.setLayout(treeLayout)

		self.hexGroup = QGroupBox("Hex View:")
		self.hexLayout = QVBoxLayout()
		self.hexWidget = HexEditor(binaryView, ViewFrame.viewFrameForWidget(self), 0)
		self.hexLayout.addWidget(self.hexWidget)
		self.hexGroup.setLayout(self.hexLayout)

		layout.addWidget(self.treeGroup)
		layout.addWidget(self.hexGroup)
		#layout.addStretch(1)
		container.setLayout(layout)
		self.setWidgetResizable(True)
		self.setWidget(container)

		self.kaitaiParse()

	# parse the file using Kaitai, construct the TreeWidget
	def kaitaiParse(self):
		parsed = None

		kaitaiIO = kshelpers.KaitaiBinaryViewIO(self.binaryView)
		if not kaitaiIO:
			print('ERROR: initializing kaitai binary view')
		parsed = kshelpers.parseIo(kaitaiIO)
		if not parsed:
			print('ERROR: parsing the binary view')

		tree = kshelpers.buildQtree(parsed)
		if not tree:
			return

		self.ioRoot = tree.ksobj._io
		self.ioCurrent = tree.ksobj._io

		self.treeWidget.clear()
		self.treeWidget.setSortingEnabled(False)						# temporarily, for efficiency
		# two options with how we create the hierarchy
		if False:
			# treat root as top level "file" container
			tree.setLabel('file')
			tree.setValue(None)
			tree.setStart(0)
			tree.setEnd(0)
			self.treeWidget.insertTopLevelItem(0, tree)
		else:
			# add root's children as top level items
			self.treeWidget.insertTopLevelItems(0, tree.takeChildren())

		#self.treeWidget.expandAll()
		width = self.treeWidget.width()
		self.treeWidget.setColumnWidth(0, .4*width)
		self.treeWidget.setColumnWidth(1, .2*width)
		self.treeWidget.setColumnWidth(2, .1*width)
		self.treeWidget.setColumnWidth(3, .1*width)
		# enable sorting
		self.treeWidget.setSortingEnabled(True)
		self.treeWidget.sortByColumn(2, Qt.AscendingOrder)

		# TODO: select first item, maybe expand a few things
		self.rootSelectionStart = 0
		self.rootSelectionEnd = 1
		self.hexWidget.setSelectionRange(0,1)
		self.treeWidget.setUniformRowHeights(True)

	# callback!
	def getData(self):
		return self.binaryView

	# callback!
	def getCurrentOffset(self):
		middle = self.rootSelectionStart + int((self.rootSelectionEnd - self.rootSelectionStart)/2)
		return middle

	def setCurrentOffset(self, offset):
		print('setCurrentOffset(0x%X)' % offset)
		self.rootSelectionStart = offset
		UIContext.updateStatus(True)

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def navigate(self, addr):
		return False

	def onTreeSelect(self, wtf=None):
		# get KaitaiTreeWidgetItem
		item = self.treeWidget.selectedItems()[0]

		# build path, inform user
		structPath = item.label
		itemTmp = item
		while itemTmp.parent():
			itemTmp = itemTmp.parent()
			structPath = itemTmp.label + '.' + structPath
		self.structPath.setText('root.' + structPath)

		#
		(start, end) = (item.start, item.end)
		if start == None or end == None:
			return

		# determine current IO we're in (the Kaitai input/output abstraction)
		_io = None
		# if the tree item is linked to a KaitaiNode, simply read the IO
		if item.ksobj:
			_io = item.ksobj._parent._io
		else:
			# else we're a leaf
			parent = item.parent()
			if parent:
				# a leaf with a parent -> read parent's IO
				_io = parent.ksobj._io
			else:
				# a leaf without a parent -> we must be at root -> use root IO
				_io = self.ioRoot

		# if the selection is in the root view, store the interval so that upon
		# getCurrentOffset() callback, we return the middle and feature map is
		# updated
		if _io == self.ioRoot:
			self.rootSelectionStart = start
			self.rootSelectionEnd = end

		# current kaitai object is on a different io? then swap HexEditor
		if _io != self.ioCurrent:
			# delete old view
			layoutItem = self.hexLayout.takeAt(0)
			hexEditorWidget = layoutItem.widget()
			hexEditorWidget.setParent(None)
			hexEditorWidget.deleteLater()
			self.hexWidget = None

			# if it's the original file IO, wrap the already-open file binary view
			if _io == self.ioRoot:
				self.hexWidget = HexEditor(self.binaryView, ViewFrame.viewFrameForWidget(self), 0)
			# otherwise delete old view, create a temporary view
			else:
				# create new view
				length = _io.size()
				_io.seek(0)
				data = _io.read_bytes(length)
				bv = binaryview.BinaryView.new(data)
				self.hexWidget = HexEditor(bv, ViewFrame.viewFrameForWidget(self), 0)

			self.hexLayout.addWidget(self.hexWidget)
			self.ioCurrent = _io

		# now position selection in whatever HexEditor is current
		#print('selecting to [0x%X, 0x%X)' % (start, end))
		self.hexWidget.setSelectionRange(start, end)

		# set hex group title to reflect current selection
		self.hexGroup.setTitle('Hex View @ [0x%X, 0x%X)' % (start, end))

class KaitaiViewType(ViewType):
	def __init__(self):
		super(KaitaiViewType, self).__init__("Kaitai", "Kaitai")

	# binaryView:		BinaryView
	def getPriority(self, binaryView, filename):
		# data.file:	FileMetadata
		# data.raw:		BinaryView

		priority = 0
		isExec = binaryView.executable
		weRecognize = kshelpers.idData(binaryView.read(0,16), len(binaryView)) != None
			
		# NOTE: ui/shared/hexeditor.cpp has the hex editor at priority 20 when
		# executable, and 10 otherwise

		if not weRecognize:
			priority = 0
		else:
			if isExec:
				priority = 21
			else:
				priority = 11

#		if isExec and weRecognize:
#			print('priority=25 to slightly beat out the hex editor case=(executable, recognize)')
#			priority = 25
#		if isExec and not weRecognize:
#			print('priority=15 to lose to the hex editor case=(executable, !recognize)')
#			priority = 15
#		if not isExec and weRecognize:
#			print('priority=100 to beat out everything case=(!executable, recognize)')
#			priority = 100
#		if not isExec and not weRecognize:
#			print('priority=5 to lose to hex editor case=(!executable, !recognize)')
#			priority = 5
			
		#print('returning priority=%d for KaitaiViewType' % priority)
		return priority

	def create(self, binaryView, view_frame):
		return KaitaiView(view_frame, binaryView)

ViewType.registerViewType(KaitaiViewType())
