import os
from PySide2.QtWidgets import QWidget, QTreeView, QFileSystemModel, QVBoxLayout, QMessageBox, QAbstractItemView
from PySide2.QtGui import QKeySequence
from PySide2.QtCore import QSettings, QDir
from binaryninjaui import UIActionHandler, UIAction, Menu, FileContext, ContextMenuManager, UIContext
from binaryninja.settings import Settings


class TriageFilePicker(QWidget):
	def __init__(self, context):
		super(TriageFilePicker, self).__init__()
		self.context = context
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)
		self.contextMenu = Menu()
		self.contextMenuManager = ContextMenuManager(self)

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)

		self.model = QFileSystemModel()
		self.model.setRootPath("")
		self.model.setFilter(QDir.AllEntries | QDir.Hidden | QDir.System)
		self.tree = QTreeView(self)
		self.tree.setModel(self.model)
		self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
		self.tree.setColumnWidth(0, 500)
		layout.addWidget(self.tree, 1)

		self.setLayout(layout)

		self.tree.doubleClicked.connect(self.onDoubleClick)

		recentFile = QSettings().value("triage/recentFile", os.path.expanduser("~"))
		while len(recentFile) > 0:
			f = self.model.index(recentFile)
			if f.isValid():
				self.tree.scrollTo(f)
				self.tree.setExpanded(f, True)
				break
			parentDir = os.path.dirname(recentFile)
			if parentDir == recentFile:
				break
			recentFile = parentDir

		self.actionHandler.bindAction("Open Selected Files", UIAction(
			lambda context: self.openSelectedFiles(),
			lambda context: self.areFilesSelected()))
		self.contextMenu.addAction("Open Selected Files", "Open")

	def contextMenuEvent(self, event):
		self.contextMenuManager.show(self.contextMenu, self.actionHandler)

	def onDoubleClick(self, index):
		self.openSelectedFiles()

	def openSelectedFiles(self):
		failedToOpen = []
		files = set()

		for index in self.tree.selectionModel().selectedIndexes():
			if self.model.fileInfo(index).isFile():
				files.add(self.model.fileInfo(index).absoluteFilePath())

		for filename in files:
				QSettings().setValue("triage/recentFile", filename)

				f = FileContext.openFilename(filename)
				if not f:
					failedToOpen.append(filename)
					continue

				for data in f.getAllDataViews():
					Settings().set_string("analysis.mode", Settings().get_string("triage.analysisMode"), data)
					Settings().set_bool("triage.preferSummaryView", True, data)
					if data.view_type != "Raw":
						linearSweepMode = Settings().get_string("triage.linearSweep")
						if linearSweepMode == "none":
							Settings().set_bool("analysis.linearSweep.autorun", False, data)
						elif linearSweepMode == "partial":
							Settings().set_bool("analysis.linearSweep.autorun", True, data)
							Settings().set_bool("analysis.linearSweep.controlFlowGraph", False, data)
						elif linearSweepMode == "full":
							Settings().set_bool("analysis.linearSweep.autorun", True, data)
							Settings().set_bool("analysis.linearSweep.controlFlowGraph", True, data)

				self.context.openFileContext(f)

		if len(failedToOpen) > 0:
			QMessageBox.critical(self, "Error", "Unable to open:\n" + "\n".join(failedToOpen))

	def areFilesSelected(self):
		return self.tree.selectionModel().hasSelection()


def openForTriage(context):
	currentContext = context.context
	if currentContext is None:
		return

	# Do not try to set the parent window when creating tabs, as this will create a parent relationship in
	# the bindings and will cause the widget to be destructed early. The correct parent will be assigned
	# when createTabForWidget is called.
	fp = TriageFilePicker(currentContext)
	currentContext.createTabForWidget("Open for Triage", fp)


Settings().register_setting("triage.analysisMode", """
	{
		"title" : "Triage Analysis Mode",
		"type" : "string",
		"default" : "basic",
		"description" : "Controls the amount of analysis performed on functions when opening for triage.",
		"enum" : ["controlFlow", "basic", "full"],
		"enumDescriptions" : [
			"Only perform control flow analysis on the binary. Cross references are valid only for direct function calls.",
			"Perform fast initial analysis of the binary. This mode does not analyze types or data flow through stack variables.",
			"Perform full analysis of the binary." ]
	}
	""")

Settings().register_setting("triage.linearSweep", """
	{
		"title" : "Triage Linear Sweep Mode",
		"type" : "string",
		"default" : "partial",
		"description" : "Controls the level of linear sweep performed when opening for triage.",
		"enum" : ["none", "partial", "full"],
		"enumDescriptions" : [
			"Do not perform linear sweep of the binary.",
			"Perform linear sweep on the binary, but skip the control flow graph analysis phase.",
			"Perform full linear sweep on the binary." ]
	}
	""")

UIAction.registerAction("Open for Triage...", QKeySequence("Ctrl+Alt+O"))
UIAction.registerAction("Open Selected Files")

UIActionHandler.globalActions().bindAction("Open for Triage...", UIAction(openForTriage))
Menu.mainMenu("File").addAction("Open for Triage...", "Open")

UIContext.registerFileOpenMode("Triage...", "Open file(s) for quick analysis in the Triage Summary view.", "Open for Triage...")
