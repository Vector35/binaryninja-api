# coding: utf8

from PySide2.QtWidgets import QWidget, QLabel, QGridLayout, QHBoxLayout
from binaryninja.enums import SectionSemantics
import binaryninjaui
from binaryninjaui import ThemeColor, ViewFrame, UIContext
from . import headers


class SegmentsWidget(QWidget):
	def __init__(self, parent, data):
		super(SegmentsWidget, self).__init__(parent)

		layout = QGridLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setVerticalSpacing(1)
		layout.setHorizontalSpacing(UIContext.getScaledWindowSize(16, 16).width())

		self.segments = []
		for segment in data.segments:
			if segment.readable or segment.writable or segment.executable:
				self.segments.append(segment)
		self.segments.sort(key = lambda segment: segment.start)

		row = 0
		for segment in self.segments:
			begin = "0x%x" % segment.start
			end = "0x%x" % segment.end

			permissions = ""
			if segment.readable:
				permissions += "r"
			else:
				permissions += "-"
			if segment.writable:
				permissions += "w"
			else:
				permissions += "-"
			if segment.executable:
				permissions += "x"
			else:
				permissions += "-"

			rangeLayout = QHBoxLayout()
			rangeLayout.setContentsMargins(0, 0, 0, 0)
			beginLabel = headers.ClickableAddressLabel(begin)
			dashLabel = QLabel("-")
			dashLabel.setFont(binaryninjaui.getMonospaceFont(self))
			endLabel = headers.ClickableAddressLabel(end)
			rangeLayout.addWidget(beginLabel)
			rangeLayout.addWidget(dashLabel)
			rangeLayout.addWidget(endLabel)
			layout.addLayout(rangeLayout, row, 0)

			permissionsLabel = QLabel(permissions)
			permissionsLabel.setFont(binaryninjaui.getMonospaceFont(self))
			layout.addWidget(permissionsLabel, row, 1)

			row += 1

		layout.setColumnStretch(2, 1)
		self.setLayout(layout)


class SectionsWidget(QWidget):
	def __init__(self, parent, data):
		super(SectionsWidget, self).__init__(parent)

		layout = QGridLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setVerticalSpacing(1)
		layout.setHorizontalSpacing(UIContext.getScaledWindowSize(16, 16).width())

		maxNameLen = 0
		for section in data.sections.values():
			if len(section.name) > maxNameLen:
				maxNameLen = len(section.name)
		if maxNameLen > 32:
			maxNameLen = 32

		self.sections = []
		for section in data.sections.values():
			if section.semantics != SectionSemantics.ExternalSectionSemantics:
				self.sections.append(section)
		self.sections.sort(key = lambda section: section.start)

		row = 0
		for section in self.sections:
			name = section.name
			if len(name) > maxNameLen:
				name = name[:maxNameLen - 1] + "…"

			begin = "0x%x" % section.start
			end = "0x%x" % section.end
			typeName = section.type

			permissions = ""
			if data.is_offset_readable(section.start):
				permissions += "r"
			else:
				permissions += "-"
			if data.is_offset_writable(section.start):
				permissions += "w"
			else:
				permissions += "-"
			if data.is_offset_executable(section.start):
				permissions += "x"
			else:
				permissions += "-"

			semantics = ""
			if section.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics:
				semantics = "Code"
			elif section.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
				semantics = "Read-only Data"
			elif section.semantics == SectionSemantics.ReadWriteDataSectionSemantics:
				semantics = "Writable Data"

			nameLabel = QLabel(name)
			nameLabel.setFont(binaryninjaui.getMonospaceFont(self))
			layout.addWidget(nameLabel, row, 0)

			rangeLayout = QHBoxLayout()
			rangeLayout.setContentsMargins(0, 0, 0, 0)
			beginLabel = headers.ClickableAddressLabel(begin)
			dashLabel = QLabel("-")
			dashLabel.setFont(binaryninjaui.getMonospaceFont(self))
			endLabel = headers.ClickableAddressLabel(end)
			rangeLayout.addWidget(beginLabel)
			rangeLayout.addWidget(dashLabel)
			rangeLayout.addWidget(endLabel)
			layout.addLayout(rangeLayout, row, 1)

			permissionsLabel = QLabel(permissions)
			permissionsLabel.setFont(binaryninjaui.getMonospaceFont(self))
			layout.addWidget(permissionsLabel, row, 2)
			typeLabel = QLabel(typeName)
			typeLabel.setFont(binaryninjaui.getMonospaceFont(self))
			layout.addWidget(typeLabel, row, 3)
			semanticsLabel = QLabel(semantics)
			semanticsLabel.setFont(binaryninjaui.getMonospaceFont(self))
			layout.addWidget(semanticsLabel, row, 4)

			row += 1

		layout.setColumnStretch(5, 1)
		self.setLayout(layout)
