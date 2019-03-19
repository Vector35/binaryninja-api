#!/usr/bin/env python

# test script

from __future__ import print_function

import io
import sys
import types
import importlib

import binaryninja

if sys.version_info[0] == 2:
	import kaitaistruct
	import kshelpers
else:
	from . import kaitaistruct
	from . import kshelpers

NORMAL = '\033[0m'
BLACK = '\033[0;30m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
GRAY = '\033[0;37m'

LBLACK = '\033[1;30m'
LRED = '\033[1;31m'
LGREEN = '\033[1;32m'
LYELLOW = '\033[1;33m'
LBLUE = '\033[1;34m'
LPURPLE = '\033[1;35m'
LCYAN = '\033[1;36m'
LGRAY = '\033[1;37m'

def dump(obj, depth=0):
	dump_exceptions = ['_root', '_parent', '_io', 'SEQ_FIELDS']

	indent = '    '*depth

	if isinstance(obj, kaitaistruct.KaitaiStruct):
		for fieldName in dir(obj):
			if hasattr(obj, fieldName):
				getattr(obj, fieldName)

		for fieldName in dir(obj):
			#print('considering field: %s (hasattr returns: %d)' % (fieldName, hasattr(obj, fieldName)))
			if fieldName != '_debug' and fieldName.startswith('_'):
				continue
			if fieldName in dump_exceptions:
				continue
			if not hasattr(obj, fieldName):
				continue

			subObj = getattr(obj, fieldName)

			if type(subObj) == types.MethodType:
				pass
			#elif type(subObj) == types.TypeType:
			elif isinstance(subObj, type):
				pass
			elif fieldName == '_debug':
				print(('%s._debug:'+RED+' %s'+NORMAL) % (indent, repr(subObj)))
			#elif type(subObj) == types.ListType:
			elif isinstance(subObj, list):
				if len(subObj)>0 and isinstance(subObj[0], kaitaistruct.KaitaiStruct):
					for i in range(len(subObj)):
						print('%s.%s[%d]:' % (indent, fieldName, i))
						dump(subObj[i], depth+1)
				else:
					print('%s.%s: %s' % (indent, fieldName, str(subObj)))
			#elif type(subObj) == types.DictionaryType:
			elif isinstance(subObj, dict):
				print('%s.%s: %s' % (indent, fieldName, subObj))

			#elif type(subObj) == types.StringType:
			elif isinstance(subObj, str):
				if len(subObj) <= 16:
					print(('%s.%s: '+CYAN+'%s'+NORMAL) % (indent, fieldName, repr(subObj)))
				else:
					print(('%s.%s: '+CYAN+'%s...'+NORMAL+' 0x%X (%d) bytes total') % \
						(indent, fieldName, repr(subObj[0:16]), len(subObj), len(subObj))
					)

			elif type(subObj) == int:
				print(('%s.%s: '+YELLOW+'0x%X '+NORMAL+'('+YELLOW+'%d'+NORMAL+')') % (indent, fieldName, subObj, subObj))

			elif str(type(subObj)).startswith('<enum '):
				print(('%s.%s: '+'%s') % (indent, fieldName, repr(subObj)))

			elif isinstance(subObj, kaitaistruct.KaitaiStruct):
				print('%s.%s:' % (indent, fieldName))
				dump(subObj, depth+1)

			else:
				print('%s.%s: %s' % (indent, fieldName, type(subObj)))
	else:
		print((PURPLE+'%s%s'+NORMAL) % (indent, repr(obj)))
		#else:
		#	print('%s%s: %s' % (indent, fieldName, repr(subObj)))

if __name__ == '__main__':
	if not sys.argv[1:]:
		raise Exception('expected arguments')

	cmd = sys.argv[1]

	if cmd == 'dump':
		fpath = sys.argv[2]
		parsed = kshelpers.parseFpath(fpath)
		dump(parsed)

	if cmd == 'import':
		print('importing every format...')

		module_names = [
			'cpio_old_le', 'gzip', 'lzh', 'rar', 'zip', 'monomakh_sapr_chg', 'bcd',
			'vlq_base128_be', 'vlq_base128_le', 'dbf', 'gettext_mo', 'sqlite3', 'tsm',
			'dex', 'dos_mz', 'elf', 'java_class', 'mach_o', 'microsoft_pe',
			'python_pyc_27', 'swf', 'apm_partition_table', 'apple_single_double', 'cramfs',
			'ext2', 'gpt_partition_table', 'iso9660', 'luks', 'lvm2',
			'mbr_partition_table', 'tr_dos_image', 'vdi', 'vfat', 'vmware_vmdk',
			'andes_firmware', 'ines', 'uimage', 'ttf', 'allegro_dat', 'doom_wad',
			'dune_2_pak', 'fallout2_dat', 'fallout_dat', 'ftl_dat', 'gran_turismo_vol',
			'heaps_pak', 'heroes_of_might_and_magic_agg', 'heroes_of_might_and_magic_bmp',
			'quake_mdl', 'quake_pak', 'renderware_binary_stream', 'saints_row_2_vpp_pc',
			'warcraft_2_pud', 'shapefile_index', 'shapefile_main', 'edid',
			'mifare_classic', 'bmp', 'dicom', 'exif', 'exif_be', 'exif_le', 'gif', 'icc_4',
			'ico', 'jpeg', 'pcx', 'pcx_dcx', 'png', 'psx_tim', 'tga', 'wmf', 'xwd',
			'aix_utmp', 'glibc_utmp', 'systemd_journal', 'windows_evt_log', 'code_6502',
			'avi', 'blender_blend', 'creative_voice_file', 'genmidi_op2', 'id3v1_1',
			'id3v2_3', 'id3v2_4', 'magicavoxel_vox', 'ogg', 'quicktime_mov',
			'standard_midi_file', 'stl', 'fasttracker_xm_module', 's3m', 'vp8_ivf', 'wav',
			'bitcoin_transaction', 'dns_packet', 'ethernet_frame', 'hccap', 'hccapx',
			'icmp_packet', 'ipv4_packet', 'ipv6_packet', 'microsoft_network_monitor_v2',
			'packet_ppi', 'pcap', 'protocol_body', 'rtcp_payload', 'rtp_packet',
			'tcp_segment', 'tls_client_hello', 'udp_datagram', 'nt_mdt', 'nt_mdt_pal',
			'avantes_roh60', 'specpr', 'openpgp_message', 'ssh_public_key', 'asn1_der',
			'bson', 'google_protobuf', 'microsoft_cfb', 'msgpack', 'ruby_marshal', 'regf',
			'windows_lnk_file', 'windows_minidump', 'windows_resource_file',
			'windows_shell_items', 'windows_systemtime'
		]

		(npass, nfail) = (0,0)

		for module_name in module_names:
			class_name = ''.join(map(lambda x: x.capitalize(), module_name.split('_')))

			print('from %s import %s...' % (module_name, class_name), end='')
			try:
				module = importlib.import_module('.'+module_name, 'kaitai')
				method = getattr(module, class_name)
				print('['+GREEN+'PASS'+NORMAL+']')
				npass += 1
			except Exception as e:
				print('['+RED+str(e)+NORMAL+']')
				nfail += 1

		ntests = 1.0*npass + nfail
		assert(ntests == len(module_names))
		print('passes %d of %d (rate: %f%%)' % (npass, ntests, npass/ntests))
		print('failures %d of %d (rate: %f%%)' % (nfail, ntests, nfail/ntests))

	if cmd == 'dumpbinja':
		fpath = sys.argv[2]
		binaryView = binaryninja.BinaryViewType['Raw'].open(fpath)
		kaitaiIo = KaitaiBinaryViewIO(binaryView)
		parsed = parse_io(kaitaiIo)
		print(parsed.header.program_headers)

