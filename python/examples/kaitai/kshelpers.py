#!/usr/bin/env python

from __future__ import absolute_import

import io
import sys
import types

import binaryninja

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QTreeWidgetItem

from .kaitaistruct import KaitaiStruct

#sys.path.append('kaitai_struct_formats/archive')
#sys.path.append('kaitai_struct_formats/cad')
#sys.path.append('kaitai_struct_formats/common')
#sys.path.append('kaitai_struct_formats/database')
#sys.path.append('./kaitai_struct_formats/executable')
#sys.path.append('kaitai_struct_formats/filesystem')
#sys.path.append('kaitai_struct_formats/firmware')
#sys.path.append('kaitai_struct_formats/font')
#sys.path.append('kaitai_struct_formats/game')
#sys.path.append('kaitai_struct_formats/geospatial')
#sys.path.append('kaitai_struct_formats/hardware')
#sys.path.append('kaitai_struct_formats/image')
#sys.path.append('kaitai_struct_formats/log')
#sys.path.append('kaitai_struct_formats/machine_code')
#sys.path.append('kaitai_struct_formats/media')
#sys.path.append('kaitai_struct_formats/network')
#sys.path.append('kaitai_struct_formats/scientific')
#sys.path.append('kaitai_struct_formats/security')
#sys.path.append('kaitai_struct_formats/serialization')
#sys.path.append('kaitai_struct_formats/windows')

#------------------------------------------------------------------------------
# id and parse
#------------------------------------------------------------------------------

def id_data(data):
	if len(data) < 16:
		return None

	if data[0:4] == "\x7fELF":
		return 'elf'
	if data[0:4] in ['\xfe\xed\xfa\xce', '\xce\xfa\xed\xfe', '\xfe\xed\xfa\xcf', '\xcf\xfa\xed\xfe']:
		return 'macho'
	if data[0:2] == 'MZ':
		return 'pe'
	if data[0:8] == '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
		return 'png'
	if data[2:11] == '0xFF\xe0\x00\x10JFIF\x00':
		return 'jpeg'
	if data[0:6] == 'GIF89a':
		return 'gif'

	return None

def id_file(fpath):
	data = None
	with open(fpath, 'rb') as fp:
		data = fp.read(16)
	return id_data(data)

def getKaitaiModuleFromFileType(ftype):
	if ftype == 'elf':
		from .kaitai_struct_formats.executable.elf import Elf
		return Elf
	elif ftype == 'macho':
		from .kaitai_struct_formats.executable.mach_o import MachO
		return MachO
	elif ftype == 'pe':
		from .kaitai_struct_formats.executable.microsoft_pe import MicrosoftPe
		return MicrosoftPe
	elif ftype == 'png':
		from .kaitai_struct_formats.image.png import Png
		return Png
	elif ftype == 'jpeg':
		from .kaitai_struct_formats.image.jpeg import Jpeg
		return Jpeg
	elif ftype == 'gif':
		from .kaitai_struct_formats.image.gif import Gif
		return Gif

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

def import_all_formats():
	from .kaitai_struct_formats.archive.cpio_old_le import CpioOldLe
	from .kaitai_struct_formats.archive.gzip import Gzip
	from .kaitai_struct_formats.archive.lzh import Lzh
	from .kaitai_struct_formats.archive.rar import Rar
	from .kaitai_struct_formats.archive.zip import Zip
	from .kaitai_struct_formats.cad.monomakh_sapr_chg import MonomakhSaprChg
	from .kaitai_struct_formats.common.bcd import Bcd
	from .kaitai_struct_formats.common.vlq_base128_be import VlqBase128Be
	from .kaitai_struct_formats.common.vlq_base128_le import VlqBase128Le
	from .kaitai_struct_formats.database.dbf import Dbf
	from .kaitai_struct_formats.database.gettext_mo import GettextMo
	from .kaitai_struct_formats.database.sqlite3 import Sqlite3
	from .kaitai_struct_formats.database.tsm import Tsm
	from .kaitai_struct_formats.executable.dex import Dex
	from .kaitai_struct_formats.executable.dos_mz import DosMz
	from .kaitai_struct_formats.executable.elf import Elf
	from .kaitai_struct_formats.executable.java_class import JavaClass
	from .kaitai_struct_formats.executable.mach_o import MachO
	from .kaitai_struct_formats.executable.microsoft_pe import MicrosoftPe
	from .kaitai_struct_formats.executable.python_pyc_27 import PythonPyc27
	from .kaitai_struct_formats.executable.swf import Swf
	from .kaitai_struct_formats.filesystem.apm_partition_table import ApmPartitionTable
	from .kaitai_struct_formats.filesystem.apple_single_double import AppleSingleDouble
	from .kaitai_struct_formats.filesystem.cramfs import Cramfs
	from .kaitai_struct_formats.filesystem.ext2 import Ext2
	from .kaitai_struct_formats.filesystem.gpt_partition_table import GptPartitionTable
	from .kaitai_struct_formats.filesystem.iso9660 import Iso9660
	from .kaitai_struct_formats.filesystem.luks import Luks
	from .kaitai_struct_formats.filesystem.lvm2 import Lvm2
	from .kaitai_struct_formats.filesystem.mbr_partition_table import MbrPartitionTable
	from .kaitai_struct_formats.filesystem.tr_dos_image import TrDosImage
	from .kaitai_struct_formats.filesystem.vdi import Vdi
	from .kaitai_struct_formats.filesystem.vfat import Vfat
	from .kaitai_struct_formats.filesystem.vmware_vmdk import VmwareVmdk
	from .kaitai_struct_formats.firmware.andes_firmware import AndesFirmware
	from .kaitai_struct_formats.firmware.ines import Ines
	from .kaitai_struct_formats.firmware.uimage import Uimage
	from .kaitai_struct_formats.font.ttf import Ttf
	from .kaitai_struct_formats.game.allegro_dat import AllegroDat
	from .kaitai_struct_formats.game.doom_wad import DoomWad
	from .kaitai_struct_formats.game.dune_2_pak import Dune2Pak
	from .kaitai_struct_formats.game.fallout2_dat import Fallout2Dat
	from .kaitai_struct_formats.game.fallout_dat import FalloutDat
	from .kaitai_struct_formats.game.ftl_dat import FtlDat
	from .kaitai_struct_formats.game.gran_turismo_vol import GranTurismoVol
	from .kaitai_struct_formats.game.heaps_pak import HeapsPak
	from .kaitai_struct_formats.game.heroes_of_might_and_magic_agg import HeroesOfMightAndMagicAgg
	from .kaitai_struct_formats.game.heroes_of_might_and_magic_bmp import HeroesOfMightAndMagicBmp
	from .kaitai_struct_formats.game.quake_mdl import QuakeMdl
	from .kaitai_struct_formats.game.quake_pak import QuakePak
	from .kaitai_struct_formats.game.renderware_binary_stream import RenderwareBinaryStream
	from .kaitai_struct_formats.game.saints_row_2_vpp_pc import SaintsRow2VppPc
	from .kaitai_struct_formats.game.warcraft_2_pud import Warcraft2Pud
	from .kaitai_struct_formats.geospatial.shapefile_index import ShapefileIndex
	from .kaitai_struct_formats.geospatial.shapefile_main import ShapefileMain
	from .kaitai_struct_formats.hardware.edid import Edid
	from .kaitai_struct_formats.hardware.mifare.mifare_classic import MifareClassic
	from .kaitai_struct_formats.image.bmp import Bmp
	from .kaitai_struct_formats.image.dicom import Dicom
	from .kaitai_struct_formats.image.exif import Exif
	from .kaitai_struct_formats.image.exif_be import ExifBe
	from .kaitai_struct_formats.image.exif_le import ExifLe
	from .kaitai_struct_formats.image.gif import Gif
	from .kaitai_struct_formats.image.icc_4 import Icc4
	from .kaitai_struct_formats.image.ico import Ico
	from .kaitai_struct_formats.image.jpeg import Jpeg
	from .kaitai_struct_formats.image.pcx import Pcx
	from .kaitai_struct_formats.image.pcx_dcx import PcxDcx
	from .kaitai_struct_formats.image.png import Png
	from .kaitai_struct_formats.image.psx_tim import PsxTim
	from .kaitai_struct_formats.image.tga import Tga
	from .kaitai_struct_formats.image.wmf import Wmf
	from .kaitai_struct_formats.image.xwd import Xwd
	from .kaitai_struct_formats.log.aix_utmp import AixUtmp
	from .kaitai_struct_formats.log.glibc_utmp import GlibcUtmp
	from .kaitai_struct_formats.log.systemd_journal import SystemdJournal
	from .kaitai_struct_formats.log.windows_evt_log import WindowsEvtLog
	from .kaitai_struct_formats.machine_code.code_6502 import Code6502
	from .kaitai_struct_formats.media.avi import Avi
	from .kaitai_struct_formats.media.blender_blend import BlenderBlend
	from .kaitai_struct_formats.media.creative_voice_file import CreativeVoiceFile
	from .kaitai_struct_formats.media.genmidi_op2 import GenmidiOp2
	from .kaitai_struct_formats.media.id3v1_1 import Id3v11
	from .kaitai_struct_formats.media.id3v2_3 import Id3v23
	from .kaitai_struct_formats.media.id3v2_4 import Id3v24
	from .kaitai_struct_formats.media.magicavoxel_vox import MagicavoxelVox
	from .kaitai_struct_formats.media.ogg import Ogg
	from .kaitai_struct_formats.media.quicktime_mov import QuicktimeMov
	from .kaitai_struct_formats.media.standard_midi_file import StandardMidiFile
	from .kaitai_struct_formats.media.stl import Stl
	from .kaitai_struct_formats.media.tracker_modules.fasttracker_xm_module import FasttrackerXmModule
	from .kaitai_struct_formats.media.tracker_modules.s3m import S3m
	from .kaitai_struct_formats.media.vp8_ivf import Vp8Ivf
	from .kaitai_struct_formats.media.wav import Wav
	from .kaitai_struct_formats.network.bitcoin_transaction import BitcoinTransaction
	from .kaitai_struct_formats.network.dns_packet import DnsPacket
	from .kaitai_struct_formats.network.ethernet_frame import EthernetFrame
	from .kaitai_struct_formats.network.hccap import Hccap
	from .kaitai_struct_formats.network.hccapx import Hccapx
	from .kaitai_struct_formats.network.icmp_packet import IcmpPacket
	from .kaitai_struct_formats.network.ipv4_packet import Ipv4Packet
	from .kaitai_struct_formats.network.ipv6_packet import Ipv6Packet
	from .kaitai_struct_formats.network.microsoft_network_monitor_v2 import MicrosoftNetworkMonitorV2
	from .kaitai_struct_formats.network.packet_ppi import PacketPpi
	from .kaitai_struct_formats.network.pcap import Pcap
	from .kaitai_struct_formats.network.protocol_body import ProtocolBody
	from .kaitai_struct_formats.network.rtcp_payload import RtcpPayload
	from .kaitai_struct_formats.network.rtp_packet import RtpPacket
	from .kaitai_struct_formats.network.tcp_segment import TcpSegment
	from .kaitai_struct_formats.network.tls_client_hello import TlsClientHello
	from .kaitai_struct_formats.network.udp_datagram import UdpDatagram
	from .kaitai_struct_formats.scientific.nt_mdt.nt_mdt import NtMdt
	from .kaitai_struct_formats.scientific.nt_mdt.nt_mdt_pal import NtMdtPal
	from .kaitai_struct_formats.scientific.spectroscopy.avantes_roh60 import AvantesRoh60
	from .kaitai_struct_formats.scientific.spectroscopy.specpr import Specpr
	from .kaitai_struct_formats.security.openpgp_message import OpenpgpMessage
	from .kaitai_struct_formats.security.ssh_public_key import SshPublicKey
	from .kaitai_struct_formats.serialization.asn1.asn1_der import Asn1Der
	from .kaitai_struct_formats.serialization.bson import Bson
	from .kaitai_struct_formats.serialization.google_protobuf import GoogleProtobuf
	from .kaitai_struct_formats.serialization.microsoft_cfb import MicrosoftCfb
	from .kaitai_struct_formats.serialization.msgpack import Msgpack
	from .kaitai_struct_formats.serialization.ruby_marshal import RubyMarshal
	from .kaitai_struct_formats.windows.regf import Regf
	from .kaitai_struct_formats.windows.windows_lnk_file import WindowsLnkFile
	from .kaitai_struct_formats.windows.windows_minidump import WindowsMinidump
	from .kaitai_struct_formats.windows.windows_resource_file import WindowsResourceFile
	from .kaitai_struct_formats.windows.windows_shell_items import WindowsShellItems
	from .kaitai_struct_formats.windows.windows_systemtime import WindowsSystemtime

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
# main()/ - for dev testing
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

