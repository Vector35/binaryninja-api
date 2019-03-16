#!/usr/bin/env python

import io
import sys
import types

import binaryninja

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QTreeWidgetItem

from kaitaistruct import KaitaiStruct

#------------------------------------------------------------------------------
# id and parse
#------------------------------------------------------------------------------

def id_data(data):
	if len(data) < 4:
		return None

	if data[0:4] == "\x7fELF":
		return 'elf'
	elif data[0:4] in ['\xfe\xed\xfa\xce', '\xce\xfa\xed\xfe', '\xfe\xed\xfa\xcf', '\xcf\xfa\xed\xfe']:
		return 'macho'
	elif data[0:2] == 'MZ':
		return 'pe'

	return None

def id_file(fpath):
	data = None
	with open(fpath, 'rb') as fp:
		data = fp.read(16)
	return id_data(data)

def getKaitaiModuleFromFileType(ftype):
	if ftype == 'elf':
		from elf import Elf
		return Elf
	elif ftype == 'macho':
		from mach_o import MachO
		return MachO
	elif ftype == 'pe':
		from microsoft_pe import MicrosoftPe
		return MicrosoftPe

	return None

def parse_fpath(fpath):
	kaitaiModule = getKaitaiModuleFromFileType(id_file(fpath))
	if not kaitaiModule: return None
	parsed = kaitaiModule.from_file(fpath)
	parsed._read()
	return parsed

def parse_data(data):
	kaitaiModule = getKaitaiModuleFromFileType(id_data(data))
	if not kaitaiModule: return None
	parsed = kaitaiModule.from_bytes(data)
	parsed._read()
	return parsed

def parse_io(ioObj):
	ioObj.seek(0, io.SEEK_SET)
	kaitaiModule = getKaitaiModuleFromFileType(id_data(ioObj.read(16)))
	ioObj.seek(0, io.SEEK_SET)
	if not kaitaiModule:
		print 'ERROR: finding suitable kaitai module'
		return None
	parsed = kaitaiModule.from_io(ioObj)
	parsed._read()
	return parsed

#------------------------------------------------------------------------------
# Kaitai IO Wrapper
#------------------------------------------------------------------------------

# wraps a BinaryView into an "IO" that KaitaiStream can use
#
# now Kaitai can parse directly from the BinaryView and we can avoid making a
# potentially giant copy of the file contents just for kaitai parsing
#
class KaitaiBinaryViewIO:
	def __init__(self, binaryView):
		self.binaryView = binaryView
		self.position = 0

	def seek(self, offs, whence=io.SEEK_SET):
		#print 'seek(0x%X, %d)' % (offs, whence)
		if whence == io.SEEK_SET:
			self.position = offs
		elif whence == io.SEEK_CUR:
			self.position += offs
		elif whence == io.SEEK_END:
			self.position = len(self.binaryView)
		else:
			raise Exception('unknown whence in seek(): %d' % whence)

	def tell(self):
		#print 'tell() returning 0x%X' % (self.position)
		return self.position

	def read(self, length):
		#print 'read(%d) (starting at position: 0x%X)' % (length, self.position)
		data = self.binaryView.read(self.position, length)
		self.position += length
		return data

	def close(self):
		pass

#------------------------------------------------------------------------------
# text dump/debug testing stuff
#------------------------------------------------------------------------------

def dump(obj, depth=0):
	dump_exceptions = ['_root', '_parent', '_io']

	indent = '    '*depth

	if isinstance(obj, KaitaiStruct):
		for fieldName in dir(obj):
			if hasattr(obj, fieldName):
				getattr(obj, fieldName)

		for fieldName in dir(obj):
			#print 'considering field: %s (hasattr returns: %d)' % (fieldName, hasattr(obj, fieldName))
			if (fieldName != '_debug' and fieldName.startswith('_')) or fieldName in dump_exceptions or not hasattr(obj, fieldName):
				continue

			#print 'A: %s' % fieldName

			subObj = getattr(obj, fieldName)

			if type(subObj) == types.MethodType:
				pass
			elif type(subObj) == types.TypeType:
				pass
			elif type(subObj) == types.ListType:
				if len(subObj)>0 and isinstance(subObj[0], KaitaiStruct):
					for i in range(len(subObj)):
						print '%s.%s[%d]:' % (indent, fieldName, i)
						dump(subObj[i], depth+1)
				else:
					print '%s.%s: %s' % (indent, fieldName, str(subObj))
			elif type(subObj) == types.DictionaryType:
				print '%s.%s: %s' % (indent, fieldName, subObj)

			elif type(subObj) == types.StringType:
				print '%s.%s: %s' % (indent, fieldName, repr(subObj))

			elif type(subObj) == int:
				print '%s.%s: 0x%X (%d)' % (indent, fieldName, subObj, subObj)

			elif str(type(subObj)).startswith('<enum '):
				print '%s.%s: %s' % (indent, fieldName, repr(subObj))

			elif isinstance(subObj, KaitaiStruct):
				print '%s.%s:' % (indent, fieldName)
				dump(subObj, depth+1)

			elif fieldName == '_debug':
				print '%s._debug: %s' % (indent, repr(subObj))
			else:
				print '%s.%s: %s' % (indent, fieldName, type(subObj))
	else:
		print indent + repr(obj)
		#else:
		#	print '%s%s: %s' % (indent, fieldName, repr(subObj))

#------------------------------------------------------------------------------
# Qt/Kaitai OOP
#------------------------------------------------------------------------------

# why subclass?
# - override "<" to get sorting to work right
# - setLabel(), setValue(), etc. conveniences
# - centralized location to modify field names and labels (eg: remove '_m_')

class KaitaiTreeWidgetItem(QTreeWidgetItem):
	def __init__(self, parent=None, data=[None,None,None,None]):
		QTreeWidgetItem.__init__(self, parent, data)

		self.label = None	# string
		self.value = None	# string
		self.start = None	# int
		self.end = None		# int
		self.ksobj = None	# KaitaiStruct

	def __lt__(self, otherItem):
		column = self.treeWidget().sortColumn()

		lhsText = self.text(column)
		rhsText = otherItem.text(column)

		if not lhsText:
			return False
		if not rhsText:
			return True

		try:
			return int(lhsText,16) < int(rhsText, 16)
		except:
			return lhsText.__lt__(rhsText)

	def setLabel(self, label):
		self.label = label
		if label.startswith('_m_'):
			label = label[3:]
		self.setData(0, Qt.DisplayRole, label)

	def setValue(self, value):
		self.value = value
		if type(value) == types.IntType:
			value = '%X'%value
		self.setData(1, Qt.DisplayRole, value)

	def setStart(self, start):
		if start == None:
			self.start = None
		elif type(start) in [types.IntType, types.LongType]:
			self.start = start
			start = '%X'%start
		else:
			self.start = int(start,16)

		self.setData(2, Qt.DisplayRole, start)

	def setEnd(self, end):
		if end == None:
			self.end = None
		elif type(end) in [types.IntType, types.LongType]:
			self.end = end
			end = '%X'%end
		else:
			self.end = int(end,16)
		self.setData(3, Qt.DisplayRole, end)

	def setKaitaiObject(self, ksobj):
		self.ksobj = ksobj
		self.setData(0, Qt.UserRole, ksobj)

	def __str__(self):
		result = 'label=%s: value=%s range=[%s,%s)' % \
			(self.label, self.value, self.start, self.end)

		result += ' ksobj=%s' % self.ksobj

		if self.ksobj:
			result += ' io=%s' % self.ksobj._io

		#if self.parent:
		#	result += ' parent=%s' % self.ksobj.parent

		return result

	def __str_short__(self):
		return '[%s,%s) %s' % (repr(self.start), repr(self.end), repr(self.label))

#------------------------------------------------------------------------------
# build QTree and helpers
#------------------------------------------------------------------------------

# ARGS:
# obj:		KaitaiStruct
# RETURNS:
# KaitaiTreeWidgetItem (QTreeWidgetItem)
#
def build_qtree(ksobj):
	if not isinstance(ksobj, KaitaiStruct):
		return None

	exceptions = ['_root', '_parent', '_io', 'SEQ_FIELDS', '_debug']

	qwi = KaitaiTreeWidgetItem()
	qwi.setKaitaiObject(ksobj)

	for fieldName in dir(ksobj):
		if hasattr(ksobj, fieldName):
			getattr(ksobj, fieldName)

	fields = dir(ksobj)
	for fieldName in fields:
		if fieldName.startswith('_') and (not fieldName.startswith('_m_')):
			continue
		if fieldName in exceptions:
			continue
		if not hasattr(ksobj, fieldName):
			continue
		if ('_m_'+fieldName) in fields:
			# favor the '_m_' version which seems to get the debug info
			continue

		subObj = getattr(ksobj, fieldName)
		subObjType = type(subObj)

		child = None
		if isinstance(subObj, KaitaiStruct):
			fieldLabel = fieldName
			child = build_qtree(subObj)
			if child:
				populate_child(ksobj, fieldName, fieldName, None, child)
			qwi.addChild(child)

		elif subObjType == types.ListType and len(subObj)>0:
			# CASE: is list of KaitaiObjects -> recurse!
			if isinstance(subObj[0], KaitaiStruct):
				child = KaitaiTreeWidgetItem()
				populate_child(ksobj, fieldName, fieldName, None, child)

				# does _debug have an array version of start/end?
				startsEnds = None
				if hasattr(ksobj, '_debug'):
					if fieldName in ksobj._debug:
						if 'arr' in ksobj._debug[fieldName]:
							startsEnds = ksobj._debug[fieldName]['arr']

				for i in range(len(subObj)):
					grandchild = build_qtree(subObj[i])
					fieldLabel = '%s[%d]' % (fieldName, i)
					grandchild.setLabel(fieldLabel)

					if startsEnds:
						grandchild.setStart(startsEnds[i]['start'])
						grandchild.setEnd(startsEnds[i]['end'])

					child.addChild(grandchild)

				qwi.addChild(child)

			# CASE: is list of primitive objects -> create leaves
			else:
				child = KaitaiTreeWidgetItem()
				populate_child(ksobj, fieldName, fieldName, None, child)

				# TODO: explain this hack
				kstmp = KaitaiStruct(ksobj._io)
				kstmp._parent = ksobj
				child.setKaitaiObject(kstmp)

				# does _debug have an array version of start/end?
				startsEnds = None
				if hasattr(ksobj, '_debug'):
					if fieldName in ksobj._debug:
						if 'arr' in ksobj._debug[fieldName]:
							startsEnds = ksobj._debug[fieldName]['arr']

				for i in range(len(subObj)):
					grandchild = createLeaf('%s[%d]'%(fieldName,i), subObj[i])
					if not grandchild:
						continue

					if startsEnds:
						grandchild.setStart(startsEnds[i]['start'])
						grandchild.setEnd(startsEnds[i]['end'])

					child.addChild(grandchild)

				qwi.addChild(child)
		else:
			child = createLeaf(fieldName, subObj)
			if child:
				# don't override createLeaf()'s work on label, value
				populate_child(ksobj, fieldName, None, None, child)
				qwi.addChild(child)

	return qwi

def createLeaf(fieldName, obj):
	objtype = type(obj)

	if objtype == types.MethodType:
		return None
	elif objtype == types.TypeType:
		return None

	fieldValue = None

	if objtype in [types.StringType, types.UnicodeType]:
		#if filter(lambda c: c<32 or c>127, obj):
		fieldValue = repr(obj)
	elif objtype == types.IntType:
		fieldValue = '0x%X (%d)' % (obj, obj)
	elif objtype == types.BooleanType:
		fieldValue = '%s' % (obj)
	elif str(objtype).startswith('<enum '):
		fieldValue = '%s' % (obj)
	else:
		#print 'field %s has type: -%s-' % (fieldName,str(objtype))
		pass

	if fieldValue:
		widget = KaitaiTreeWidgetItem()
		widget.setLabel(fieldName)
		widget.setValue(fieldValue)
		return widget
	else:
		return None

# ARG				TYPE					NOTES
# ksobj:			KaitaiStruct			the current one we're on
# fieldName:		string					actual field name inside the kaitai struct
# fieldLabel:		string					label used in the tree view
# fieldValue:		string					value used in the tree view
# widget:			KaitaiTreeWidgetItem	the item to which we want to imprint start/end
def populate_child(ksobj, fieldName, fieldLabel, fieldValue, widget):
	if fieldLabel:
		widget.setLabel(fieldLabel)
		#print 'setting Label: %s' % fieldLabel
	if fieldValue:
		widget.setValue(fieldValue)

	if (not ksobj) or (not hasattr(ksobj, '_debug')):
		return

	start = None
	if 'start' in ksobj._debug[fieldName]:
		start = ksobj._debug[fieldName]['start']

	end = None
	if 'end' in ksobj._debug[fieldName]:
		end = ksobj._debug[fieldName]['end']

	if start != None:
		widget.setStart(start)
	if end != None:
		widget.setEnd(end)

#------------------------------------------------------------------------------
# main() - for dev testing
#------------------------------------------------------------------------------

if __name__ == '__main__':
	if not sys.argv[2:]:
		sys.exit(-1)

	cmd = sys.argv[1]
	fpath = sys.argv[2]

	if cmd == 'dump':
		parsed = parse_fpath(sys.argv[2])
		print parsed.header.program_headers

	elif cmd == 'dumpbinja':
		binaryView = binaryninja.BinaryViewType['Raw'].open(fpath)
		kaitaiIo = KaitaiBinaryViewIO(binaryView)
		parsed = parse_io(kaitaiIo)
		print parsed.header.program_headers

