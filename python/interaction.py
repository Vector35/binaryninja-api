# Copyright (c) 2015-2020 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import ctypes
import traceback

# Binary Ninja components
from binaryninja import _binaryninjacore as core
from binaryninja.enums import FormInputFieldType, MessageBoxIcon, MessageBoxButtonSet, MessageBoxButtonResult, ReportType
from binaryninja import binaryview
from binaryninja import log
from binaryninja import flowgraph

# 2-3 compatibility
from binaryninja import range


class LabelField(object):
	"""
	``LabelField`` adds a text label to the display.
	"""
	def __init__(self, text):
		self._text = text

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.LabelFormField
		value.prompt = self._text

	def _fill_core_result(self, value):
		pass

	def _get_result(self, value):
		pass

	@property
	def text(self):
		""" """
		return self._text

	@text.setter
	def text(self, value):
		self._text = value


class SeparatorField(object):
	"""
	``SeparatorField`` adds vertical separation to the display.
	"""
	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.SeparatorFormField

	def _fill_core_result(self, value):
		pass

	def _get_result(self, value):
		pass


class TextLineField(object):
	"""
	``TextLineField`` Adds prompt for text string input. Result is stored in self.result as a string on completion.
	"""
	def __init__(self, prompt):
		self._prompt = prompt
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.TextLineFormField
		value.prompt = self._prompt

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self._result))

	def _get_result(self, value):
		self._result = value.stringResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class MultilineTextField(object):
	"""
	``MultilineTextField`` add multi-line text string input field. Result is stored in self.result
	as a string. This option is not supported on the command-line.
	"""
	def __init__(self, prompt):
		self._prompt = prompt
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.MultilineTextFormField
		value.prompt = self._prompt

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self._result))

	def _get_result(self, value):
		self._result = value.stringResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class IntegerField(object):
	"""
	``IntegerField`` add prompt for integer. Result is stored in self.result as an int.
	"""
	def __init__(self, prompt):
		self._prompt = prompt
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.IntegerFormField
		value.prompt = self._prompt

	def _fill_core_result(self, value):
		value.intResult = self._result

	def _get_result(self, value):
		self._result = value.intResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class AddressField(object):
	"""
	``AddressField`` prompts the user for an address. By passing the optional view and current_address parameters
	offsets can be used instead of just an address. The result is stored as in int in self.result.

	Note: This API currently functions differently on the command-line, as the view and current_address are
	disregarded. Additionally where as in the UI the result defaults to hexadecimal on the command-line 0x must be 
	specified.
	"""
	def __init__(self, prompt, view=None, current_address=0):
		self._prompt = prompt
		self._view = view
		self._current_address = current_address
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.AddressFormField
		value.prompt = self._prompt
		value.view = None
		if self._view is not None:
			value.view = self._view.handle
		value.currentAddress = self._current_address

	def _fill_core_result(self, value):
		value.addressResult = self._result

	def _get_result(self, value):
		self._result = value.addressResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def current_address(self):
		""" """
		return self._current_address

	@current_address.setter
	def current_address(self, value):
		self._current_address = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class ChoiceField(object):
	"""
	``ChoiceField`` prompts the user to choose from the list of strings provided in ``choices``. Result is stored
	in self.result as an index in to the choices array.

	:attr str prompt: prompt to be presented to the user
	:attr list(str) choices: list of choices to choose from

	"""
	def __init__(self, prompt, choices):
		self._prompt = prompt
		self._choices = choices
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.ChoiceFormField
		value.prompt = self._prompt
		choice_buf = (ctypes.c_char_p * len(self._choices))()
		for i in range(0, len(self._choices)):
			choice_buf[i] = self._choices[i].encode('charmap')
		value.choices = choice_buf
		value.count = len(self._choices)

	def _fill_core_result(self, value):
		value.indexResult = self._result

	def _get_result(self, value):
		self._result = value.indexResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def choices(self):
		""" """
		return self._choices

	@choices.setter
	def choices(self, value):
		self._choices = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class OpenFileNameField(object):
	"""
	``OpenFileNameField`` prompts the user to specify a file name to open. Result is stored in self.result as a string.
	"""
	def __init__(self, prompt, ext=""):
		self._prompt = prompt
		self._ext = ext
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.OpenFileNameFormField
		value.prompt = self._prompt
		value.ext = self._ext

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self.result))

	def _get_result(self, value):
		self._result = value.stringResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def ext(self):
		""" """
		return self._ext

	@ext.setter
	def ext(self, value):
		self._ext = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class SaveFileNameField(object):
	"""
	``SaveFileNameField`` prompts the user to specify a file name to save. Result is stored in self.result as a string.
	"""
	def __init__(self, prompt, ext="", default_name=""):
		self._prompt = prompt
		self._ext = ext
		self._default_name = default_name
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.SaveFileNameFormField
		value.prompt = self._prompt
		value.ext = self._ext
		value.defaultName = self._default_name

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self._result))

	def _get_result(self, value):
		self._result = value.stringResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def ext(self):
		""" """
		return self._ext

	@ext.setter
	def ext(self, value):
		self._ext = value

	@property
	def default_name(self):
		""" """
		return self._default_name

	@default_name.setter
	def default_name(self, value):
		self._default_name = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class DirectoryNameField(object):
	"""
	``DirectoryNameField`` prompts the user to specify a directory name to open. Result is stored in self.result as
	a string.
	"""
	def __init__(self, prompt, default_name=""):
		self._prompt = prompt
		self._default_name = default_name
		self._result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.DirectoryNameFormField
		value.prompt = self._prompt
		value.defaultName = self._default_name

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self._result))

	def _get_result(self, value):
		self._result = value.stringResult

	@property
	def prompt(self):
		""" """
		return self._prompt

	@prompt.setter
	def prompt(self, value):
		self._prompt = value

	@property
	def default_name(self):
		""" """
		return self._default_name

	@default_name.setter
	def default_name(self, value):
		self._default_name = value

	@property
	def result(self):
		""" """
		return self._result

	@result.setter
	def result(self, value):
		self._result = value


class InteractionHandler(object):
	_interaction_handler = None

	def __init__(self):
		self._cb = core.BNInteractionHandlerCallbacks()
		self._cb.context = 0
		self._cb.showPlainTextReport = self._cb.showPlainTextReport.__class__(self._show_plain_text_report)
		self._cb.showMarkdownReport = self._cb.showMarkdownReport.__class__(self._show_markdown_report)
		self._cb.showHTMLReport = self._cb.showHTMLReport.__class__(self._show_html_report)
		self._cb.showGraphReport = self._cb.showGraphReport.__class__(self._show_graph_report)
		self._cb.showReportCollection = self._cb.showReportCollection.__class__(self._show_report_collection)
		self._cb.getTextLineInput = self._cb.getTextLineInput.__class__(self._get_text_line_input)
		self._cb.getIntegerInput = self._cb.getIntegerInput.__class__(self._get_int_input)
		self._cb.getAddressInput = self._cb.getAddressInput.__class__(self._get_address_input)
		self._cb.getChoiceInput = self._cb.getChoiceInput.__class__(self._get_choice_input)
		self._cb.getOpenFileNameInput = self._cb.getOpenFileNameInput.__class__(self._get_open_filename_input)
		self._cb.getSaveFileNameInput = self._cb.getSaveFileNameInput.__class__(self._get_save_filename_input)
		self._cb.getDirectoryNameInput = self._cb.getDirectoryNameInput.__class__(self._get_directory_name_input)
		self._cb.getFormInput = self._cb.getFormInput.__class__(self._get_form_input)
		self._cb.showMessageBox = self._cb.showMessageBox.__class__(self._show_message_box)

	def register(self):
		self.__class__._interaction_handler = self
		core.BNRegisterInteractionHandler(self._cb)

	def _show_plain_text_report(self, ctxt, view, title, contents):
		try:
			if view:
				view = binaryview.BinaryView(handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_plain_text_report(view, title, contents)
		except:
			log.log_error(traceback.format_exc())

	def _show_markdown_report(self, ctxt, view, title, contents, plaintext):
		try:
			if view:
				view = binaryview.BinaryView(handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_markdown_report(view, title, contents, plaintext)
		except:
			log.log_error(traceback.format_exc())

	def _show_html_report(self, ctxt, view, title, contents, plaintext):
		try:
			if view:
				view = binaryview.BinaryView(handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_html_report(view, title, contents, plaintext)
		except:
			log.log_error(traceback.format_exc())

	def _show_graph_report(self, ctxt, view, title, graph):
		try:
			if view:
				view = binaryview.BinaryView(handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_graph_report(view, title, flowgraph.CoreFlowGraph(core.BNNewFlowGraphReference(graph)))
		except:
			log.log_error(traceback.format_exc())

	def _show_report_collection(self, ctxt, title, reports):
		try:
			self.show_report_collection(title, ReportCollection(core.BNNewReportCollectionReference(reports)))
		except:
			log.log_error(traceback.format_exc())

	def _get_text_line_input(self, ctxt, result, prompt, title):
		try:
			value = self.get_text_line_input(prompt, title)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_int_input(self, ctxt, result, prompt, title):
		try:
			value = self.get_int_input(prompt, title)
			if value is None:
				return False
			result[0] = value
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_address_input(self, ctxt, result, prompt, title, view, current_address):
		try:
			if view:
				view = binaryview.BinaryView(handle = core.BNNewViewReference(view))
			else:
				view = None
			value = self.get_address_input(prompt, title, view, current_address)
			if value is None:
				return False
			result[0] = value
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_choice_input(self, ctxt, result, prompt, title, choice_buf, count):
		try:
			choices = []
			for i in range(0, count):
				choices.append(choice_buf[i])
			value = self.get_choice_input(prompt, title, choices)
			if value is None:
				return False
			result[0] = value
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_open_filename_input(self, ctxt, result, prompt, ext):
		try:
			value = self.get_open_filename_input(prompt, ext)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_save_filename_input(self, ctxt, result, prompt, ext, default_name):
		try:
			value = self.get_save_filename_input(prompt, ext, default_name)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_directory_name_input(self, ctxt, result, prompt, default_name):
		try:
			value = self.get_directory_name_input(prompt, default_name)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log.log_error(traceback.format_exc())

	def _get_form_input(self, ctxt, fields, count, title):
		try:
			field_objs = []
			for i in range(0, count):
				if fields[i].type == FormInputFieldType.LabelFormField:
					field_objs.append(LabelField(fields[i].prompt))
				elif fields[i].type == FormInputFieldType.SeparatorFormField:
					field_objs.append(SeparatorField())
				elif fields[i].type == FormInputFieldType.TextLineFormField:
					field_objs.append(TextLineField(fields[i].prompt))
				elif fields[i].type == FormInputFieldType.MultilineTextFormField:
					field_objs.append(MultilineTextField(fields[i].prompt))
				elif fields[i].type == FormInputFieldType.IntegerFormField:
					field_objs.append(IntegerField(fields[i].prompt))
				elif fields[i].type == FormInputFieldType.AddressFormField:
					view = None
					if fields[i].view:
						view = binaryview.BinaryView(handle = core.BNNewViewReference(fields[i].view))
					field_objs.append(AddressField(fields[i].prompt, view, fields[i].currentAddress))
				elif fields[i].type == FormInputFieldType.ChoiceFormField:
					choices = []
					for j in range(0, fields[i].count):
						choices.append(fields[i].choices[j])
					field_objs.append(ChoiceField(fields[i].prompt, choices))
				elif fields[i].type == FormInputFieldType.OpenFileNameFormField:
					field_objs.append(OpenFileNameField(fields[i].prompt, fields[i].ext))
				elif fields[i].type == FormInputFieldType.SaveFileNameFormField:
					field_objs.append(SaveFileNameField(fields[i].prompt, fields[i].ext, fields[i].defaultName))
				elif fields[i].type == FormInputFieldType.DirectoryNameFormField:
					field_objs.append(DirectoryNameField(fields[i].prompt, fields[i].defaultName))
				else:
					field_objs.append(LabelField(fields[i].prompt))
			if not self.get_form_input(field_objs, title):
				return False
			for i in range(0, count):
				field_objs[i]._fill_core_result(fields[i])
			return True
		except:
			log.log_error(traceback.format_exc())

	def _show_message_box(self, ctxt, title, text, buttons, icon):
		try:
			return self.show_message_box(title, text, buttons, icon)
		except:
			log.log_error(traceback.format_exc())

	def show_plain_text_report(self, view, title, contents):
		pass

	def show_markdown_report(self, view, title, contents, plaintext):
		self.show_html_report(view, title, markdown_to_html(contents), plaintext)

	def show_html_report(self, view, title, contents, plaintext):
		if len(plaintext) != 0:
			self.show_plain_text_report(view, title, plaintext)

	def show_graph_report(self, view, title, graph):
		pass

	def show_report_collection(self, title, reports):
		pass

	def get_text_line_input(self, prompt, title):
		return NotImplemented

	def get_int_input(self, prompt, title):
		while True:
			text = self.get_text_line_input(prompt, title)
			if len(text) == 0:
				return False
			try:
				return int(text)
			except:
				continue

	def get_address_input(self, prompt, title, view, current_address):
		return get_int_input(prompt, title)

	def get_choice_input(self, prompt, title, choices):
		return NotImplemented

	def get_open_filename_input(self, prompt, ext):
		return get_text_line_input(prompt, "Open File")

	def get_save_filename_input(self, prompt, ext, default_name):
		return get_text_line_input(prompt, "Save File")

	def get_directory_name_input(self, prompt, default_name):
		return get_text_line_input(prompt, "Select Directory")

	def get_form_input(self, fields, title):
		return False

	def show_message_box(self, title, text, buttons, icon):
		return MessageBoxButtonResult.CancelButton


class PlainTextReport(object):
	def __init__(self, title, contents, view = None):
		self._view = view
		self._title = title
		self._contents = contents

	def __repr__(self):
		return "<plaintext report: %s>" % self._title

	def __str__(self):
		return self._contents

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def title(self):
		""" """
		return self._title

	@title.setter
	def title(self, value):
		self._title = value

	@property
	def contents(self):
		""" """
		return self._contents

	@contents.setter
	def contents(self, value):
		self._contents = value


class MarkdownReport(object):
	def __init__(self, title, contents, plaintext = "", view = None):
		self._view = view
		self._title = title
		self._contents = contents
		self._plaintext = plaintext

	def __repr__(self):
		return "<markdown report: %s>" % self._title

	def __str__(self):
		return self._contents

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def title(self):
		""" """
		return self._title

	@title.setter
	def title(self, value):
		self._title = value

	@property
	def contents(self):
		""" """
		return self._contents

	@contents.setter
	def contents(self, value):
		self._contents = value

	@property
	def plaintext(self):
		""" """
		return self._plaintext

	@plaintext.setter
	def plaintext(self, value):
		self._plaintext = value


class HTMLReport(object):
	def __init__(self, title, contents, plaintext = "", view = None):
		self._view = view
		self._title = title
		self._contents = contents
		self._plaintext = plaintext

	def __repr__(self):
		return "<html report: %s>" % self._title

	def __str__(self):
		return self._contents

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def title(self):
		""" """
		return self._title

	@title.setter
	def title(self, value):
		self._title = value

	@property
	def contents(self):
		""" """
		return self._contents

	@contents.setter
	def contents(self, value):
		self._contents = value

	@property
	def plaintext(self):
		""" """
		return self._plaintext

	@plaintext.setter
	def plaintext(self, value):
		self._plaintext = value


class FlowGraphReport(object):
	def __init__(self, title, graph, view = None):
		self._view = view
		self._title = title
		self._graph = graph

	def __repr__(self):
		return "<graph report: %s>" % self._title

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def title(self):
		""" """
		return self._title

	@title.setter
	def title(self, value):
		self._title = value

	@property
	def graph(self):
		""" """
		return self._graph

	@graph.setter
	def graph(self, value):
		self._graph = value


class ReportCollection(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateReportCollection()
		else:
			self.handle = handle

	def __len__(self):
		return core.BNGetReportCollectionCount(self.handle)

	def _report_from_index(self, i):
		report_type = core.BNGetReportType(self.handle, i)
		title = core.BNGetReportTitle(self.handle, i)
		view = core.BNGetReportView(self.handle, i)
		if view:
			view = binaryview.BinaryView(handle = view)
		else:
			view = None
		if report_type == ReportType.PlainTextReportType:
			contents = core.BNGetReportContents(self.handle, i)
			return PlainTextReport(title, contents, view)
		elif report_type == ReportType.MarkdownReportType:
			contents = core.BNGetReportContents(self.handle, i)
			plaintext = core.BNGetReportPlainText(self.handle, i)
			return MarkdownReport(title, contents, plaintext, view)
		elif report_type == ReportType.HTMLReportType:
			contents = core.BNGetReportContents(self.handle, i)
			plaintext = core.BNGetReportPlainText(self.handle, i)
			return HTMLReport(title, contents, plaintext, view)
		elif report_type == ReportType.FlowGraphReportType:
			graph = flowgraph.CoreFlowGraph(core.BNGetReportFlowGraph(self.handle, i))
			return FlowGraphReport(title, graph, view)
		raise TypeError("invalid report type %s" % repr(report_type))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer report index")
		if (i < 0) or (i >= len(self)):
			raise IndexError("index out of range")
		return self._report_from_index(i)

	def __iter__(self):
		count = len(self)
		for i in range(0, count):
			yield self._report_from_index(i)

	def __repr__(self):
		return "<reports: %s>" % repr(list(self))

	def append(self, report):
		if report.view is None:
			view = None
		else:
			view = report.view.handle
		if isinstance(report, PlainTextReport):
			core.BNAddPlainTextReportToCollection(self.handle, view, report.title, report.contents)
		elif isinstance(report, MarkdownReport):
			core.BNAddMarkdownReportToCollection(self.handle, view, report.title, report.contents, report.plaintext)
		elif isinstance(report, HTMLReport):
			core.BNAddHTMLReportToCollection(self.handle, view, report.title, report.contents, report.plaintext)
		elif isinstance(report, FlowGraphReport):
			core.BNAddGraphReportToCollection(self.handle, view, report.title, report.graph.handle)
		else:
			raise TypeError("expected report object")


def markdown_to_html(contents):
	"""
	``markdown_to_html`` converts the provided markdown to HTML

	:param str contents: Markdown contents to convert to HTML
	:rtype: str
	:Example:
		>>> markdown_to_html("##Yay")
		'<h2>Yay</h2>'
	"""
	return core.BNMarkdownToHTML(contents)


def show_plain_text_report(title, contents):
	"""
	``show_plain_text_report`` displays contents to the user in the UI or on the command-line

	Note: This API functions differently on the command-line vs the UI. In the UI, a pop-up is used. On the command-line,
	a simple text prompt is used.

	:param str title: title to display in the UI pop-up
	:param str contents: plaintext contents to display
	:rtype: None
	:Example:
		>>> show_plain_text_report("title", "contents")
		contents
	"""
	core.BNShowPlainTextReport(None, title, contents)


def show_markdown_report(title, contents, plaintext=""):
	"""
	``show_markdown_report`` displays the markdown contents in UI applications and plaintext in command-line
	applications. This API doesn't support hyperlinking into the BinaryView, use the BinaryView.show_markdown_report
	if hyperlinking is needed.

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used.

	:param str contents: markdown contents to display
	:param str plaintext: Plain text version to display (used on the command-line)
	:rtype: None
	:Example:
		>>> show_markdown_report("title", "##Contents", "Plain text contents")
		Plain text contents
	"""
	core.BNShowMarkdownReport(None, title, contents, plaintext)


def show_html_report(title, contents, plaintext=""):
	"""
	``show_html_report`` displays the HTML contents in UI applications and plaintext in command-line
	applications. This API doesn't support hyperlinking into the BinaryView, use the BinaryView.show_html_report
	if hyperlinking is needed.

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used.

	:param str contents: HTML contents to display
	:param str plaintext: Plain text version to display (used on the command-line)
	:rtype: None
	:Example:
		>>> show_html_report("title", "<h1>Contents</h1>", "Plain text contents")
		Plain text contents
	"""
	core.BNShowHTMLReport(None, title, contents, plaintext)


def show_graph_report(title, graph):
	"""
	``show_graph_report`` displays a flow graph in UI applications

	Note: This API function will have no effect outside the UI.

	:param FlowGraph graph: Flow graph to display
	:rtype: None
	"""
	func = graph.function
	if func is None:
		core.BNShowGraphReport(None, title, graph.handle)
	else:
		core.BNShowGraphReport(func.view.handle, title, graph.handle)


def show_report_collection(title, reports):
	"""
	``show_report_collection`` displays multiple reports in UI applications

	Note: This API function will have no effect outside the UI.

	:param ReportCollection reports: Reports to display
	:rtype: None
	"""
	core.BNShowReportCollection(title, reports.handle)


def get_text_line_input(prompt, title):
	"""
	``get_text_line_input`` prompts the user to input a string with the given prompt and title

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:rtype: str containing the input without trailing newline character.
	:Example:
		>>> get_text_line_input("PROMPT>", "getinfo")
		PROMPT> Input!
		'Input!'
	"""
	value = ctypes.c_char_p()
	if not core.BNGetTextLineInput(value, prompt, title):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_int_input(prompt, title):
	"""
	``get_int_input`` prompts the user to input a integer with the given prompt and title

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:rtype: integer value input by the user.
	:Example:
		>>> get_int_input("PROMPT>", "getinfo")
		PROMPT> 10
		10
	"""
	value = ctypes.c_longlong()
	if not core.BNGetIntegerInput(value, prompt, title):
		return None
	return value.value


def get_address_input(prompt, title):
	"""
	``get_address_input`` prompts the user for an address with the given prompt and title

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:rtype: integer value input by the user.
	:Example:
		>>> get_address_input("PROMPT>", "getinfo")
		PROMPT> 10
		10L
	"""
	value = ctypes.c_ulonglong()
	if not core.BNGetAddressInput(value, prompt, title, None, 0):
		return None
	return value.value


def get_choice_input(prompt, title, choices):
	"""
	``get_choice_input`` prompts the user to select the one of the provided choices

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used. The UI uses a combo box.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:param choices: A list of strings for the user to choose from.
	:type choices: list(str)
	:rtype: integer array index of the selected option
	:Example:
		>>> get_choice_input("PROMPT>", "choices", ["Yes", "No", "Maybe"])
		choices
		1) Yes
		2) No
		3) Maybe
		PROMPT> 1
		0L
	"""
	choice_buf = (ctypes.c_char_p * len(choices))()
	for i in range(0, len(choices)):
		choice_buf[i] = str(choices[i]).encode('charmap')
	value = ctypes.c_ulonglong()
	if not core.BNGetChoiceInput(value, prompt, title, choice_buf, len(choices)):
		return None
	return value.value


def get_open_filename_input(prompt, ext=""):
	"""
	``get_open_filename_input`` prompts the user for a file name to open

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used. The UI uses the native window pop-up for file selection.

	Multiple file selection groups can be included if separated by two semicolons. Multiple file wildcards may be specified by using a space within the parenthesis.

	Also, a simple selector of "*.extension" by itself may also be used instead of specifying the description.

	:param str prompt: Prompt to display.
	:param str ext: Optional, file extension
	:Example:
		>>> get_open_filename_input("filename:", "Executables (*.exe *.com);;Python Files (*.py);;All Files (*)")
		b'foo.exe'
		>>> get_open_filename_input("filename:", "*.py")
		b'test.py'
	"""
	value = ctypes.c_char_p()
	if not core.BNGetOpenFileNameInput(value, prompt, ext):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_save_filename_input(prompt, ext="", default_name=""):
	"""
	``get_save_filename_input`` prompts the user for a file name to save as, optionally providing a file extension and
	default_name

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line
	a simple text prompt is used. The UI uses the native window pop-up for file selection.

	:param str prompt: Prompt to display.
	:param str ext: Optional, file extension
	:param str default_name: Optional, default file name.
	:Example:
		>>> get_save_filename_input("filename:", "exe", "foo.exe")
		filename: foo.exe
		'foo.exe'
	"""
	value = ctypes.c_char_p()
	if not core.BNGetSaveFileNameInput(value, prompt, ext, default_name):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_directory_name_input(prompt, default_name=""):
	"""
	``get_directory_name_input`` prompts the user for a directory name to save as, optionally providing a default_name

	Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line a simple text prompt is used. The UI uses the native window pop-up for file selection.

	:param str prompt: Prompt to display.
	:param str default_name: Optional, default directory name.
	:rtype: str
	:Example:
		>>> get_directory_name_input("prompt")
		prompt dirname
		'dirname'
	"""
	value = ctypes.c_char_p()
	if not core.BNGetDirectoryNameInput(value, prompt, default_name):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_form_input(fields, title):
	"""
	``get_from_input`` Prompts the user for a set of inputs specified in ``fields`` with given title.
	The fields parameter is a list which can contain the following types:
		- str  - an alias for LabelField
		- None - an alias for SeparatorField
		- LabelField         - Text output
		- SeparatorField     - Vertical spacing
		- TextLineField      - Prompt for a string value
		- MultilineTextField - Prompt for multi-line string value
		- IntegerField       - Prompt for an integer
		- AddressField       - Prompt for an address
		- ChoiceField        - Prompt for a choice from provided options
		- OpenFileNameField  - Prompt for file to open
		- SaveFileNameField  - Prompt for file to save to
		- DirectoryNameField - Prompt for directory name
	This API is flexible and works both in the UI via a pop-up dialog and on the command-line. Note that more complicated APIs should consider usin the included pyside2 functionality in the `binaryninjaui` module. Returns true or false depending on whether the user submitted responses or cancelled the dialog.

	:param fields: A list containing these classes, strings or None
	:type fields: list(str) or list(None) or list(LabelField) or list(SeparatorField) or list(TextLineField) or list(MultilineTextField) or list(IntegerField) or list(AddressField) or list(ChoiceField) or list(OpenFileNameField) or list(SaveFileNameField) or list(DirectoryNameField)
	:param str title: The title of the pop-up dialog
	:rtype: bool
	:Example:

		>>> int_f = IntegerField("Specify Integer")
		>>> tex_f = TextLineField("Specify name")
		>>> choice_f = ChoiceField("Options", ["Yes", "No", "Maybe"])
		>>> get_form_input(["Get Data", None, int_f, tex_f, choice_f], "The options")
		Get Data
		<empty>
		Specify Integer 1337
		Specify name Peter
		The options
		1) Yes
		2) No
		3) Maybe
		Options 1
		>>> True
		>>> print(tex_f.result, int_f.result, choice_f.result)
		Peter 1337 0
	"""
	value = (core.BNFormInputField * len(fields))()
	for i in range(0, len(fields)):
		if isinstance(fields[i], str):
			LabelField(fields[i])._fill_core_struct(value[i])
		elif fields[i] is None:
			SeparatorField()._fill_core_struct(value[i])
		else:
			fields[i]._fill_core_struct(value[i])
	if not core.BNGetFormInput(value, len(fields), title):
		return False
	for i in range(0, len(fields)):
		if not (isinstance(fields[i], str) or (fields[i] is None)):
			fields[i]._get_result(value[i])
	core.BNFreeFormInputResults(value, len(fields))
	return True


def show_message_box(title, text, buttons=MessageBoxButtonSet.OKButtonSet, icon=MessageBoxIcon.InformationIcon):
	"""
	``show_message_box`` Displays a configurable message box in the UI, or prompts on the console as appropriate
	retrieves a list of all Symbol objects of the provided symbol type in the optionally
	provided range.

	:param str title: Text title for the message box.
	:param str text: Text for the main body of the message box.
	:param MessageBoxButtonSet buttons: One of :py:class:`MessageBoxButtonSet`
	:param MessageBoxIcon icon: One of :py:class:`MessageBoxIcon`
	:return: Which button was selected
	:rtype: MessageBoxButtonResult
	"""
	return core.BNShowMessageBox(title, text, buttons, icon)
