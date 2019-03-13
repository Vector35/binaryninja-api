import traceback
import binaryninjaui
from binaryninja.settings import Settings
from binaryninja import log
from binaryninjaui import View, ViewType, UIContext
from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QGroupBox
from . import headers
from . import entropy
from . import imports


class TriageView(QScrollArea, View):
	def __init__(self, parent, data):
		QScrollArea.__init__(self, parent)
		View.__init__(self)
		self.setupView(self)
		self.data = data
		self.currentOffset = 0

		container = QWidget(self)
		layout = QVBoxLayout()

		entropyGroup = QGroupBox("Entropy")
		entropyLayout = QVBoxLayout()
		entropyLayout.addWidget(entropy.EntropyWidget(entropyGroup, self.data))
		entropyGroup.setLayout(entropyLayout)
		layout.addWidget(entropyGroup)

		hdr = None
		try:
			if self.data.view_type == "PE":
				hdr = headers.PEHeaders(self.data)
		except:
			log.log_error(traceback.format_exc())

		if hdr is not None:
			headerGroup = QGroupBox("Headers")
			headerLayout = QVBoxLayout()
			headerWidget = headers.HeaderWidget(headerGroup, hdr)
			headerLayout.addWidget(headerWidget)
			headerGroup.setLayout(headerLayout)
			layout.addWidget(headerGroup)

		importGroup = QGroupBox("Imports")
		importLayout = QVBoxLayout()
		importLayout.addWidget(imports.ImportsWidget(importGroup, self, self.data))
		importGroup.setLayout(importLayout)
		layout.addWidget(importGroup)

		button_layout = QHBoxLayout()
		button_layout.addStretch(1)
		self.full_analysis_button = QPushButton("Start Full Analysis")
		self.full_analysis_button.clicked.connect(self.startFullAnalysis)
		button_layout.addWidget(self.full_analysis_button)
		layout.addLayout(button_layout)

		layout.addStretch(1)
		container.setLayout(layout)
		self.setWidgetResizable(True)
		self.setWidget(container)

		if Settings().get_string("analysis.mode", data) == "full":
			self.full_analysis_button.hide()

	def getData(self):
		return self.data

	def getCurrentOffset(self):
		return self.currentOffset

	def setCurrentOffset(self, offset):
		self.currentOffset = offset
		UIContext.updateStatus(True)

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def navigate(self, addr):
		return False

	def startFullAnalysis(self):
		Settings().set_string("analysis.mode", "full", self.data)
		for f in self.data.functions:
			if f.analysis_skipped:
				f.reanalyze()
		self.data.update_analysis()
		self.full_analysis_button.hide()


class TriageViewType(ViewType):
	def __init__(self):
		super(TriageViewType, self).__init__("Triage", "Triage Summary")

	def getPriority(self, data, filename):
		is_full = Settings().get_string("analysis.mode", data) == "full"
		always_prefer = Settings().get_bool("ui.always_prefer_triage", data)
		if data.executable and (always_prefer or not is_full):
			return 100
		return 25

	def create(self, data, view_frame):
		return TriageView(view_frame, data)


Settings().register_setting("ui.always_prefer_triage", """
	{
		"title" : "Always Prefer Triage Summary View",
		"type" : "boolean",
		"default" : false,
		"description" : "Always prefer opening binaries in Triage Summary view, even when performing full analysis."
	}
	""")

ViewType.registerViewType(TriageViewType())
