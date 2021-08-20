import time
from binaryninja.binaryview import StructuredDataView
import binaryninjaui
from binaryninjaui import ViewFrame, UIContext
from binaryninja.enums import ThemeColor
from PySide6.QtWidgets import QWidget, QLabel, QGridLayout
from PySide6.QtGui import QPalette


class ClickableLabel(QLabel):
	def __init__(self, text, color, func):
		super(ClickableLabel, self).__init__(text)
		style = QPalette(self.palette())
		style.setColor(QPalette.WindowText, color)
		self.setPalette(style)
		self.setFont(binaryninjaui.getMonospaceFont(self))
		self.func = func

	def mousePressEvent(self, event):
		self.func()


class ClickableAddressLabel(ClickableLabel):
	def __init__(self, text):
		super(ClickableAddressLabel, self).__init__(text, binaryninjaui.getThemeColor(ThemeColor.AddressColor), self.clickEvent)
		self.address = int(text, 0)

	def clickEvent(self):
		viewFrame = ViewFrame.viewFrameForWidget(self)
		viewFrame.navigate("Linear:" + viewFrame.getCurrentDataType(), self.address)


class ClickableCodeLabel(ClickableLabel):
	def __init__(self, text):
		super(ClickableCodeLabel, self).__init__(text, binaryninjaui.getThemeColor(ThemeColor.CodeSymbolColor), self.clickEvent)
		self.address = int(text, 0)

	def clickEvent(self):
		viewFrame = ViewFrame.viewFrameForWidget(self)
		viewFrame.navigate("Graph:" + viewFrame.getCurrentDataType(), self.address)


class GenericHeaders(object):
	def __init__(self, data):
		self.fields = []
		self.fields.append(("Type", data.view_type))
		if data.platform is not None:
			self.fields.append(("Platform", data.platform.name))
		if data.is_valid_offset(data.entry_point):
			self.fields.append(("Entry Point", "0x%x" % data.entry_point, "code"))
		self.columns = 1


class PEHeaders(object):
	def __init__(self, data):
		dos = StructuredDataView(data, "DOS_Header", data.start)
		pe_offset = data.start + int(dos.e_lfanew)
		coff = StructuredDataView(data, "COFF_Header", pe_offset)
		pe_magic = data.read(pe_offset + len(coff), 2)
		self.fields = []
		if pe_magic == b"\x0b\x01":
			peopt = StructuredDataView(data, "PE32_Optional_Header", pe_offset + len(coff))
			self.fields.append(("Type", "PE 32-bit"))
			is64bit = False
		elif pe_magic == b"\x0b\x02":
			peopt = StructuredDataView(data, "PE64_Optional_Header", pe_offset + len(coff))
			self.fields.append(("Type", "PE 64-bit"))
			is64bit = True

		machine_value = int(coff.machine)
		machine_enum = data.get_type_by_name("coff_machine")
		machine_name = str(machine_value)
		for member in machine_enum.enumeration.members:
			if member.value == machine_value:
				machine_name = member.name
		if machine_name.startswith("IMAGE_FILE_MACHINE_"):
			machine_name = machine_name[len("IMAGE_FILE_MACHINE_"):]
		self.fields.append(("Machine", machine_name))

		subsys_value = int(peopt.subsystem)
		subsys_enum = data.get_type_by_name("pe_subsystem")
		subsys_name = str(subsys_value)
		for member in subsys_enum.enumeration.members:
			if member.value == subsys_value:
				subsys_name = member.name
		if subsys_name.startswith("IMAGE_SUBSYSTEM_"):
			subsys_name = subsys_name[len("IMAGE_SUBSYSTEM_"):]
		self.fields.append(("Subsystem", subsys_name))

		self.fields.append(("Timestamp", time.strftime("%c", time.localtime(int(coff.timeDateStamp)))))

		base = int(peopt.imageBase)
		self.fields.append(("Image Base", "0x%x" % base, "ptr"))

		entry_point = base + int(peopt.addressOfEntryPoint)
		self.fields.append(("Entry Point", "0x%x" % entry_point, "code"))

		section_align = int(peopt.sectionAlignment)
		self.fields.append(("Section Alignment", "0x%x" % section_align))

		file_align = int(peopt.fileAlignment)
		self.fields.append(("File Alignment", "0x%x" % file_align))

		checksum = int(peopt.checkSum)
		self.fields.append(("Checksum", "0x%.8x" % checksum))

		code_base = base + int(peopt.baseOfCode)
		self.fields.append(("Base of Code", "0x%x" % code_base, "ptr"))

		if not is64bit:
			data_base = base + int(peopt.baseOfData)
			self.fields.append(("Base of Data", "0x%x" % data_base, "ptr"))

		code_size = int(peopt.sizeOfCode)
		self.fields.append(("Size of Code", "0x%x" % code_size))

		init_data_size = int(peopt.sizeOfInitializedData)
		self.fields.append(("Size of Init Data", "0x%x" % init_data_size))

		uninit_data_size = int(peopt.sizeOfUninitializedData)
		self.fields.append(("Size of Uninit Data", "0x%x" % uninit_data_size))

		header_size = int(peopt.sizeOfHeaders)
		self.fields.append(("Size of Headers", "0x%x" % header_size))

		image_size = int(peopt.sizeOfImage)
		self.fields.append(("Size of Image", "0x%x" % image_size))

		stack_commit = int(peopt.sizeOfStackCommit)
		stack_reserve = int(peopt.sizeOfStackReserve)
		self.fields.append(("Stack Size", "0x%x / 0x%x" % (stack_commit, stack_reserve)))

		heap_commit = int(peopt.sizeOfHeapCommit)
		heap_reserve = int(peopt.sizeOfHeapReserve)
		self.fields.append(("Heap Size", "0x%x / 0x%x" % (heap_commit, heap_reserve)))

		linker_major = int(peopt.majorLinkerVersion)
		linker_minor = int(peopt.minorLinkerVersion)
		self.fields.append(("Linker Version", "%d.%.2d" % (linker_major, linker_minor)))

		image_major = int(peopt.majorImageVersion)
		image_minor = int(peopt.minorImageVersion)
		self.fields.append(("Image Version", "%d.%.2d" % (image_major, image_minor)))

		os_major = int(peopt.majorOperatingSystemVersion)
		os_minor = int(peopt.minorOperatingSystemVersion)
		self.fields.append(("OS Version", "%d.%.2d" % (os_major, os_minor)))

		sub_major = int(peopt.majorSubsystemVersion)
		sub_minor = int(peopt.minorSubsystemVersion)
		self.fields.append(("Subsystem Version", "%d.%.2d" % (sub_major, sub_minor)))

		coff_char_value = int(coff.characteristics)
		coff_char_enum = data.get_type_by_name("coff_characteristics")
		coff_char_values = []
		for member in coff_char_enum.enumeration.members:
			if (coff_char_value & member.value) != 0:
				if member.name.startswith("IMAGE_FILE_"):
					coff_char_values.append(member.name[len("IMAGE_FILE_"):])
				else:
					coff_char_values.append(member.name)
		if len(coff_char_values) > 0:
			self.fields.append(("COFF Characteristics", coff_char_values))

		dll_char_value = int(peopt.dllCharacteristics)
		dll_char_enum = data.get_type_by_name("pe_dll_characteristics")
		dll_char_values = []
		for member in dll_char_enum.enumeration.members:
			if (dll_char_value & member.value) != 0:
				if member.name.startswith("IMAGE_DLLCHARACTERISTICS_"):
					dll_char_values.append(member.name[len("IMAGE_DLLCHARACTERISTICS_"):])
				else:
					dll_char_values.append(member.name)
		if len(dll_char_values) > 0:
			self.fields.append(("DLL Characteristics", dll_char_values))

		self.columns = 3
		self.rows_per_column = 9


class HeaderWidget(QWidget):
	def __init__(self, parent, header):
		super(HeaderWidget, self).__init__(parent)
		layout = QGridLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setVerticalSpacing(1)
		row = 0
		col = 0
		for field in header.fields:
			name = field[0]
			value = field[1]
			fieldType = ""
			if len(field) > 2:
				fieldType = field[2]
			layout.addWidget(QLabel(name + ": "), row, col * 3)
			if isinstance(value, list):
				for i in range(0, len(value)):
					if fieldType == "ptr":
						label = ClickableAddressLabel(value[i])
					elif fieldType == "code":
						label = ClickableCodeLabel(value[i])
					else:
						label = QLabel(value[i])
						label.setFont(binaryninjaui.getMonospaceFont(self))
					layout.addWidget(label, row, col * 3 + 1)
					row += 1
			else:
				if fieldType == "ptr":
					label = ClickableAddressLabel(value)
				elif fieldType == "code":
					label = ClickableCodeLabel(value)
				else:
					label = QLabel(value)
					label.setFont(binaryninjaui.getMonospaceFont(self))
				layout.addWidget(label, row, col * 3 + 1)
				row += 1
			if (header.columns > 1) and (row >= header.rows_per_column) and ((col + 1) < header.columns):
				row = 0
				col += 1
		for col in range(1, header.columns):
			layout.setColumnMinimumWidth(col * 3 - 1, UIContext.getScaledWindowSize(20, 20).width())
		layout.setColumnStretch(header.columns * 3 - 1, 1)
		self.setLayout(layout)
