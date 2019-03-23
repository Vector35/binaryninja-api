# -*- coding: utf-8 -*-

# python stuff
import io
import os
import sys
import types
import traceback

# binja stuff
from binaryninja import log
from binaryninja import binaryview
from binaryninja.settings import Settings
from binaryninja import _binaryninjacore as core
from binaryninjaui import View, ViewType, ViewFrame, UIContext, HexEditor, getMonospaceFont

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QGroupBox, QTreeWidget, QTreeWidgetItem, QLineEdit, QHeaderView

from . import menu

if sys.version_info[0] == 2:
	import kshelpers
else:
	from . import kshelpers

class MyQTreeWidget(QTreeWidget):
	def __init__(self):
		QTreeWidget.__init__(self)

		self.oldWidth = 0
		self.oldHeight = 0

		self.queueInitialPresentation = False

	def resizeEvent(self, event):
		QTreeWidget.resizeEvent(self, event)

		if self.queueInitialPresentation:
			self.initialPresentation()

		self.scrollTo(self.currentIndex())

		newWidth = self.width()
		newHeight = self.height()

		#log.log_debug('QTreeWidget resizeEvent(), now I\'m %dx%d' % (newWidth, newHeight))

		if newWidth == self.oldWidth and newHeight == self.oldHeight:
			return

		self.oldWidth = newWidth
		self.oldHeight = newHeight

		self.setColumnWidthsNicely()

	def initialPresentation(self):
		self.expandNicely()

		if self.topLevelItemCount():
			self.topLevelItem(0).setSelected(True)

		self.queueInitialPresentation = False

	def setColumnWidthsNicely(self):
		width = self.width()
		self.setColumnWidth(0, .6*width)
		self.setColumnWidth(1, .2*width)
		self.setColumnWidth(2, .1*width)
		self.setColumnWidth(3, .1*width)

	def expandNicely(self):
		visibleRows = self.topLevelItemCount()
		if not visibleRows:
			return

		height = self.height()
		rowHeight = self.visualItemRect(self.topLevelItem(0)).height()
		rowCapacity = height / rowHeight

		queue = []
		for i in range(visibleRows):
			queue.append(self.topLevelItem(i))

		while visibleRows < rowCapacity:
			#log.log_debug('visibleRows=%d, rowCapacity=%d len(queue)=%d' % (visibleRows, rowCapacity, len(queue)))
			if not queue:
				break

			item = queue[0]
			queue = queue[1:]

			if not item.isExpanded():
				item.setExpanded(True)
				for i in range(item.childCount()):
					queue.append(item.child(i))
					visibleRows += 1

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
		self.layout = QVBoxLayout()

		self.treeWidget = MyQTreeWidget()
		self.treeWidget.setColumnCount(4)
		self.treeWidget.setHeaderLabels(['label','value','start','end'])
		self.treeWidget.itemSelectionChanged.connect(self.onTreeSelect)

		self.structPath = QLineEdit("root")
		self.structPath.setReadOnly(True)

		self.hexWidget = HexEditor(binaryView, ViewFrame.viewFrameForWidget(self), 0)

		self.layout.addWidget(self.treeWidget)
		self.layout.addWidget(self.structPath)
		self.layout.addWidget(self.hexWidget)
		#self.layout.addStretch(1)
		container.setLayout(self.layout)
		self.setWidgetResizable(True)
		self.setWidget(container)

		self.kaitaiParse()

	# parse the file using Kaitai, construct the TreeWidget
	def kaitaiParse(self, ksModuleName=None):
		#log_debug('kaitaiParse() with len(bv)=%d and bv.file.filename=%s' % (len(self.binaryView), self.binaryView.file.filename))

		if len(self.binaryView) == 0:
			return

		kaitaiIO = kshelpers.KaitaiBinaryViewIO(self.binaryView)
		parsed = kshelpers.parseIo(kaitaiIO, ksModuleName)
		if not parsed:
			return

		# it SEEMS as if parsing is finished at this moment, but some parsing
		# is postponed until attributes are accessed, so we must try/catch here
		tree = None
		if True:
			try:
				tree = kshelpers.buildQtree(parsed)
			except Exception as e:
				log.log_error('kaitai module %s threw exception, check file type' % ksModuleName)
				true = None
		else:
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

		# enable sorting
		self.treeWidget.setSortingEnabled(True)
		self.treeWidget.sortByColumn(2, Qt.AscendingOrder)

		# TODO: select first item, maybe expand a few things
		self.rootSelectionStart = 0
		self.rootSelectionEnd = 1

		self.treeWidget.setUniformRowHeights(True)
		self.treeWidget.queueInitialPresentation = True


	# binja callbacks
	def getData(self):
		return self.binaryView

	def getStart(self):
		result = self.binaryView.start
		#log.log_debug('getStart() returning '+str(result))
		return result

	def getEnd(self):
		result = self.binaryView.end
		#log.log_debug('getEnd() returning '+str(result))
		return result

	def getLength(self):
		result = len(self.binaryView)
		#log.log_debug('getLength() returning '+str(result))
		return result

	def getCurrentOffset(self):
		result = self.rootSelectionStart + int((self.rootSelectionEnd - self.rootSelectionStart)/2)
		#result = self.rootSelectionStart
		#log.log_debug('getCurrentOffset() returning '+str(result))
		return result

	def getSelectionOffsets(self):
		result = None
		if self.hexWidget:
			result = self.hexWidget.getSelectionOffsets()
		else:
			result = (self.rootSelectionStart, self.rootSelectionStart)
		#log.log_debug('getSelectionOffsets() returning '+str(result))
		return result

	def setCurrentOffset(self, offset):
		#log.log_debug('setCurrentOffset(0x%X)' % offset)
		self.rootSelectionStart = offset
		UIContext.updateStatus(True)

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def navigate(self, addr):
		#log.log_debug('navigate()')
		return False

	def navigateToFileOffset(self, offset):
		#log.log_debug('navigateToFileOffset()')
		return False

	def onTreeSelect(self, wtf=None):
		# get KaitaiTreeWidgetItem
		items = self.treeWidget.selectedItems()
		if not items or len(items)<1:
			return
		item = items[0]

		# build path, inform user
		structPath = item.label
		itemTmp = item
		while itemTmp.parent():
			itemTmp = itemTmp.parent()
			label = itemTmp.label
			if label.startswith('_m_'):
				label = label[3:]
			structPath = label + '.' + structPath
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
			layoutItem = self.layout.takeAt(2)
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

			self.layout.addWidget(self.hexWidget)
			self.ioCurrent = _io

		# now position selection in whatever HexEditor is current
		#log.log_debug('selecting to [0x%X, 0x%X)' % (start, end))
		self.hexWidget.setSelectionRange(start, end)

		# set hex group title to reflect current selection
		#self.hexGroup.setTitle('Hex View @ [0x%X, 0x%X)' % (start, end))

	def getStatusBarWidget(self):
		return menu.KaitaiStatusBarWidget(self)

class KaitaiViewType(ViewType):
	def __init__(self):
		super(KaitaiViewType, self).__init__("Kaitai", "Kaitai")

	# binaryView:		BinaryView
	def getPriority(self, binaryView, filename):
		#return 100
		#log.log_debug('len(bv)=0x%X executable=%d bytes=%s' % (len(binaryView), binaryView.executable, repr(binaryView.read(0,4))))

		# executable means the view is mapped like an OS loader would load an executable (eg: view=ELF)
		# !executable means executable image is not mapped (eg: view=Raw) (or something like .png is loaded)
		if binaryView.executable:
			return 0

		if binaryView.start != 0:
			return 1

		dataSample = binaryView.read(0, 16)
		if len(dataSample) != 16:
			return 1

		# if we don't recognize it, return 0
		ksModuleName = kshelpers.idData(dataSample, len(binaryView))
		if not ksModuleName:
			return 1

		# for executables, yield to triage (25)
		if ksModuleName in ['elf', 'microsoft_pe', 'mach_o']:
			return 24

		#
		return 100

	def create(self, binaryView, view_frame):
		return KaitaiView(view_frame, binaryView)

ViewType.registerViewType(KaitaiViewType())
