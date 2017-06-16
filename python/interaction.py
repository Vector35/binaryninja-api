# Copyright (c) 2015-2017 Vector 35 LLC
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
import _binaryninjacore as core
from enums import FormInputFieldType, MessageBoxIcon, MessageBoxButtonSet, MessageBoxButtonResult
import binaryview
import log


class LabelField(object):
	def __init__(self, text):
		self.text = text

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.LabelFormField
		value.prompt = self.text

	def _fill_core_result(self, value):
		pass

	def _get_result(self, value):
		pass


class SeparatorField(object):
	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.SeparatorFormField

	def _fill_core_result(self, value):
		pass

	def _get_result(self, value):
		pass


class TextLineField(object):
	def __init__(self, prompt):
		self.prompt = prompt
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.TextLineFormField
		value.prompt = self.prompt

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self.result))

	def _get_result(self, value):
		self.result = value.stringResult


class MultilineTextField(object):
	def __init__(self, prompt):
		self.prompt = prompt
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.MultilineTextFormField
		value.prompt = self.prompt

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self.result))

	def _get_result(self, value):
		self.result = value.stringResult


class IntegerField(object):
	def __init__(self, prompt):
		self.prompt = prompt
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.IntegerFormField
		value.prompt = self.prompt

	def _fill_core_result(self, value):
		value.intResult = self.result

	def _get_result(self, value):
		self.result = value.intResult


class AddressField(object):
	def __init__(self, prompt, view = None, current_address = 0):
		self.prompt = prompt
		self.view = view
		self.current_address = current_address
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.AddressFormField
		value.prompt = self.prompt
		value.view = None
		if self.view is not None:
			value.view = self.view.handle
		value.currentAddress = self.current_address

	def _fill_core_result(self, value):
		value.addressResult = self.result

	def _get_result(self, value):
		self.result = value.addressResult


class ChoiceField(object):
	def __init__(self, prompt, choices):
		self.prompt = prompt
		self.choices = choices
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.ChoiceFormField
		value.prompt = self.prompt
		choice_buf = (ctypes.c_char_p * len(self.choices))()
		for i in xrange(0, len(self.choices)):
			choice_buf[i] = str(self.choices[i])
		value.choices = choice_buf
		value.count = len(self.choices)

	def _fill_core_result(self, value):
		value.indexResult = self.result

	def _get_result(self, value):
		self.result = value.indexResult


class OpenFileNameField(object):
	def __init__(self, prompt, ext = ""):
		self.prompt = prompt
		self.ext = ext
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.OpenFileNameFormField
		value.prompt = self.prompt
		value.ext = self.ext

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self.result))

	def _get_result(self, value):
		self.result = value.stringResult


class SaveFileNameField(object):
	def __init__(self, prompt, ext = "", default_name = ""):
		self.prompt = prompt
		self.ext = ext
		self.default_name = default_name
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.SaveFileNameFormField
		value.prompt = self.prompt
		value.ext = self.ext
		value.defaultName = self.default_name

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self.result))

	def _get_result(self, value):
		self.result = value.stringResult


class DirectoryNameField(object):
	def __init__(self, prompt, default_name = ""):
		self.prompt = prompt
		self.default_name = default_name
		self.result = None

	def _fill_core_struct(self, value):
		value.type = FormInputFieldType.DirectoryNameFormField
		value.prompt = self.prompt
		value.defaultName = self.default_name

	def _fill_core_result(self, value):
		value.stringResult = core.BNAllocString(str(self.result))

	def _get_result(self, value):
		self.result = value.stringResult


class InteractionHandler(object):
	_interaction_handler = None

	def __init__(self):
		self._cb = core.BNInteractionHandlerCallbacks()
		self._cb.context = 0
		self._cb.showPlainTextReport = self._cb.showPlainTextReport.__class__(self._show_plain_text_report)
		self._cb.showMarkdownReport = self._cb.showMarkdownReport.__class__(self._show_markdown_report)
		self._cb.showHTMLReport = self._cb.showHTMLReport.__class__(self._show_html_report)
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
			for i in xrange(0, count):
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
			for i in xrange(0, count):
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
					for i in xrange(0, fields[i].count):
						choices.append(fields[i].choices[i])
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
			for i in xrange(0, count):
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

	def get_text_line_input(self, prompt, title):
		return None

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
		return None

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


def markdown_to_html(contents):
	return core.BNMarkdownToHTML(contents)


def show_plain_text_report(title, contents):
	core.BNShowPlainTextReport(None, title, contents)


def show_markdown_report(title, contents, plaintext = ""):
	core.BNShowMarkdownReport(None, title, contents, plaintext)


def show_html_report(title, contents, plaintext = ""):
	core.BNShowHTMLReport(None, title, contents, plaintext)


def get_text_line_input(prompt, title):
	value = ctypes.c_char_p()
	if not core.BNGetTextLineInput(value, prompt, title):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_int_input(prompt, title):
	value = ctypes.c_longlong()
	if not core.BNGetIntegerInput(value, prompt, title):
		return None
	return value.value


def get_address_input(prompt, title):
	value = ctypes.c_ulonglong()
	if not core.BNGetAddressInput(value, prompt, title, None, 0):
		return None
	return value.value


def get_choice_input(prompt, title, choices):
	choice_buf = (ctypes.c_char_p * len(choices))()
	for i in xrange(0, len(choices)):
		choice_buf[i] = str(choices[i])
	value = ctypes.c_ulonglong()
	if not core.BNGetChoiceInput(value, prompt, title, choice_buf, len(choices)):
		return None
	return value.value


def get_open_filename_input(prompt, ext = ""):
	value = ctypes.c_char_p()
	if not core.BNGetOpenFileNameInput(value, prompt, ext):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_save_filename_input(prompt, ext = "", default_name = ""):
	value = ctypes.c_char_p()
	if not core.BNGetSaveFileNameInput(value, prompt, ext, default_name):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_directory_name_input(prompt, default_name = ""):
	value = ctypes.c_char_p()
	if not core.BNGetDirectoryNameInput(value, prompt, default_name):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result


def get_form_input(fields, title):
	value = (core.BNFormInputField * len(fields))()
	for i in xrange(0, len(fields)):
		if isinstance(fields[i], str):
			LabelField(fields[i])._fill_core_struct(value[i])
		elif fields[i] is None:
			SeparatorField()._fill_core_struct(value[i])
		else:
			fields[i]._fill_core_struct(value[i])
	if not core.BNGetFormInput(value, len(fields), title):
		return False
	for i in xrange(0, len(fields)):
		if not (isinstance(fields[i], str) or (fields[i] is None)):
			fields[i]._get_result(value[i])
	core.BNFreeFormInputResults(value, len(fields))
	return True


def show_message_box(title, text, buttons = MessageBoxButtonSet.OKButtonSet, icon = MessageBoxIcon.InformationIcon):
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
