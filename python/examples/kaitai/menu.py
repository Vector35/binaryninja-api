# -*- coding: utf-8 -*-

# binja stuff
from binaryninjaui import StatusBarWidget, ContextMenuManager, Menu, UIActionHandler, UIAction

# pyside stuff
from PySide2.QtCore import Qt
from PySide2.QtGui import QPalette
from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QGroupBox, QTreeWidget, QTreeWidgetItem, QLineEdit, QHeaderView, QLabel, QMenu, QHBoxLayout

class KaitaiOptionsWidget(QLabel):
	def __init__(self, parent):
		QLabel.__init__(self, parent)

		self.statusBarWidget = parent

		self.setBackgroundRole(QPalette.Highlight)
		self.setForegroundRole(QPalette.WindowText)
		self.setText(" Formats ▾ ")

		# see api/ui/menus.h
		self.contextMenuManager = ContextMenuManager(self)

		self.menu = Menu()
		self.actionHandler = UIActionHandler()
		self.registerActions()
		self.addActions()
		self.bindActions()

	def registerActions(self):
		# add all action handlers
		UIAction.registerAction("archive\\cpio_old_le")
		UIAction.registerAction("archive\\gzip")
		UIAction.registerAction("archive\\lzh")
		UIAction.registerAction("archive\\rar")
		UIAction.registerAction("archive\\zip")
		UIAction.registerAction("cad\\monomakh_sapr_chg")
		UIAction.registerAction("common\\bcd")
		UIAction.registerAction("database\\dbf")
		UIAction.registerAction("database\\gettext_mo")
		UIAction.registerAction("database\\sqlite3")
		UIAction.registerAction("database\\tsm")
		UIAction.registerAction("executable\\dex")
		UIAction.registerAction("executable\\dos_mz")
		UIAction.registerAction("executable\\elf")
		UIAction.registerAction("executable\\java_class")
		UIAction.registerAction("executable\\mach_o")
		UIAction.registerAction("executable\\microsoft_pe")
		UIAction.registerAction("executable\\python_pyc_27")
		UIAction.registerAction("executable\\swf")
		UIAction.registerAction("filesystem\\apm_partition_table")
		UIAction.registerAction("filesystem\\apple_single_double")
		UIAction.registerAction("filesystem\\cramfs")
		UIAction.registerAction("filesystem\\ext2")
		UIAction.registerAction("filesystem\\gpt_partition_table")
		UIAction.registerAction("filesystem\\iso9660")
		UIAction.registerAction("filesystem\\luks")
		UIAction.registerAction("filesystem\\lvm2")
		UIAction.registerAction("filesystem\\mbr_partition_table")
		UIAction.registerAction("filesystem\\tr_dos_image")
		UIAction.registerAction("filesystem\\vdi")
		UIAction.registerAction("filesystem\\vfat")
		UIAction.registerAction("filesystem\\vmware_vmdk")
		UIAction.registerAction("firmware\\andes_firmware")
		UIAction.registerAction("firmware\\ines")
		UIAction.registerAction("firmware\\uimage")
		UIAction.registerAction("font\\ttf")
		UIAction.registerAction("game\\allegro_dat")
		UIAction.registerAction("game\\doom_wad")
		UIAction.registerAction("game\\dune_2_pak")
		UIAction.registerAction("game\\fallout2_dat")
		UIAction.registerAction("game\\fallout_dat")
		UIAction.registerAction("game\\ftl_dat")
		UIAction.registerAction("game\\gran_turismo_vol")
		UIAction.registerAction("game\\heaps_pak")
		UIAction.registerAction("game\\heroes_of_might_and_magic_agg")
		UIAction.registerAction("game\\heroes_of_might_and_magic_bmp")
		UIAction.registerAction("game\\quake_mdl")
		UIAction.registerAction("game\\quake_pak")
		UIAction.registerAction("game\\renderware_binary_stream")
		UIAction.registerAction("game\\saints_row_2_vpp_pc")
		UIAction.registerAction("game\\warcraft_2_pud")
		UIAction.registerAction("geospatial\\shapefile_index")
		UIAction.registerAction("geospatial\\shapefile_main")
		UIAction.registerAction("hardware\\edid")
		UIAction.registerAction("hardware\\mifare\\mifare_classic")
		UIAction.registerAction("image\\bmp")
		UIAction.registerAction("image\\dicom")
		UIAction.registerAction("image\\exif")
		UIAction.registerAction("image\\exif_be")
		UIAction.registerAction("image\\exif_le")
		UIAction.registerAction("image\\gif")
		UIAction.registerAction("image\\icc_4")
		UIAction.registerAction("image\\ico")
		UIAction.registerAction("image\\jpeg")
		UIAction.registerAction("image\\pcx")
		UIAction.registerAction("image\\pcx_dcx")
		UIAction.registerAction("image\\png")
		UIAction.registerAction("image\\psx_tim")
		UIAction.registerAction("image\\tga")
		UIAction.registerAction("image\\wmf")
		UIAction.registerAction("image\\xwd")
		UIAction.registerAction("log\\aix_utmp")
		UIAction.registerAction("log\\glibc_utmp")
		UIAction.registerAction("log\\systemd_journal")
		UIAction.registerAction("log\\windows_evt_log")
		UIAction.registerAction("machine_code\\code_6502")
		UIAction.registerAction("media\\avi")
		UIAction.registerAction("media\\blender_blend")
		UIAction.registerAction("media\\creative_voice_file")
		UIAction.registerAction("media\\genmidi_op2")
		UIAction.registerAction("media\\id3v1_1")
		UIAction.registerAction("media\\id3v2_3")
		UIAction.registerAction("media\\id3v2_4")
		UIAction.registerAction("media\\magicavoxel_vox")
		UIAction.registerAction("media\\ogg")
		UIAction.registerAction("media\\quicktime_mov")
		UIAction.registerAction("media\\standard_midi_file")
		UIAction.registerAction("media\\stl")
		UIAction.registerAction("media\\tracker_modules\\fasttracker_xm_module")
		UIAction.registerAction("media\\tracker_modules\\s3m")
		UIAction.registerAction("media\\vp8_ivf")
		UIAction.registerAction("media\\wav")
		UIAction.registerAction("network\\bitcoin_transaction")
		UIAction.registerAction("network\\dns_packet")
		UIAction.registerAction("network\\ethernet_frame")
		UIAction.registerAction("network\\hccap")
		UIAction.registerAction("network\\hccapx")
		UIAction.registerAction("network\\icmp_packet")
		UIAction.registerAction("network\\ipv4_packet")
		UIAction.registerAction("network\\ipv6_packet")
		UIAction.registerAction("network\\microsoft_network_monitor_v2")
		UIAction.registerAction("network\\packet_ppi")
		UIAction.registerAction("network\\pcap")
		UIAction.registerAction("network\\protocol_body")
		UIAction.registerAction("network\\rtcp_payload")
		UIAction.registerAction("network\\rtp_packet")
		UIAction.registerAction("network\\tcp_segment")
		UIAction.registerAction("network\\tls_client_hello")
		UIAction.registerAction("network\\udp_datagram")
		UIAction.registerAction("network\\windows_systemtime")
		UIAction.registerAction("scientific\\nt_mdt\\nt_mdt")
		UIAction.registerAction("scientific\\nt_mdt\\nt_mdt_pal")
		UIAction.registerAction("scientific\\spectroscopy\\avantes_roh60")
		UIAction.registerAction("scientific\\spectroscopy\\specpr")
		UIAction.registerAction("security\\openpgp_message")
		UIAction.registerAction("security\\ssh_public_key")
		UIAction.registerAction("serialization\\asn1\\asn1_der")
		UIAction.registerAction("serialization\\bson")
		UIAction.registerAction("serialization\\google_protobuf")
		UIAction.registerAction("serialization\\microsoft_cfb")
		UIAction.registerAction("serialization\\msgpack")
		UIAction.registerAction("serialization\\ruby_marshal")
		UIAction.registerAction("windows\\regf")
		UIAction.registerAction("windows\\windows_lnk_file")
		UIAction.registerAction("windows\\windows_minidump")
		UIAction.registerAction("windows\\windows_resource_file")
		UIAction.registerAction("windows\\windows_shell_items")
		UIAction.registerAction("windows\\windows_systemtime")

	def addActions(self):
		self.menu.addAction("archive\\cpio_old_le", "formats")
		self.menu.addAction("archive\\gzip", "formats")
		self.menu.addAction("archive\\lzh", "formats")
		self.menu.addAction("archive\\rar", "formats")
		self.menu.addAction("archive\\zip", "formats")
		self.menu.addAction("cad\\monomakh_sapr_chg", "formats")
		self.menu.addAction("common\\bcd", "formats")
		self.menu.addAction("database\\dbf", "formats")
		self.menu.addAction("database\\gettext_mo", "formats")
		self.menu.addAction("database\\sqlite3", "formats")
		self.menu.addAction("database\\tsm", "formats")
		self.menu.addAction("executable\\dex", "formats")
		self.menu.addAction("executable\\dos_mz", "formats")
		self.menu.addAction("executable\\elf", "formats")
		self.menu.addAction("executable\\java_class", "formats")
		self.menu.addAction("executable\\mach_o", "formats")
		self.menu.addAction("executable\\microsoft_pe", "formats")
		self.menu.addAction("executable\\python_pyc_27", "formats")
		self.menu.addAction("executable\\swf", "formats")
		self.menu.addAction("filesystem\\apm_partition_table", "formats")
		self.menu.addAction("filesystem\\apple_single_double", "formats")
		self.menu.addAction("filesystem\\cramfs", "formats")
		self.menu.addAction("filesystem\\ext2", "formats")
		self.menu.addAction("filesystem\\gpt_partition_table", "formats")
		self.menu.addAction("filesystem\\iso9660", "formats")
		self.menu.addAction("filesystem\\luks", "formats")
		self.menu.addAction("filesystem\\lvm2", "formats")
		self.menu.addAction("filesystem\\mbr_partition_table", "formats")
		self.menu.addAction("filesystem\\tr_dos_image", "formats")
		self.menu.addAction("filesystem\\vdi", "formats")
		self.menu.addAction("filesystem\\vfat", "formats")
		self.menu.addAction("filesystem\\vmware_vmdk", "formats")
		self.menu.addAction("firmware\\andes_firmware", "formats")
		self.menu.addAction("firmware\\ines", "formats")
		self.menu.addAction("firmware\\uimage", "formats")
		self.menu.addAction("font\\ttf", "formats")
		self.menu.addAction("game\\allegro_dat", "formats")
		self.menu.addAction("game\\doom_wad", "formats")
		self.menu.addAction("game\\dune_2_pak", "formats")
		self.menu.addAction("game\\fallout2_dat", "formats")
		self.menu.addAction("game\\fallout_dat", "formats")
		self.menu.addAction("game\\ftl_dat", "formats")
		self.menu.addAction("game\\gran_turismo_vol", "formats")
		self.menu.addAction("game\\heaps_pak", "formats")
		self.menu.addAction("game\\heroes_of_might_and_magic_agg", "formats")
		self.menu.addAction("game\\heroes_of_might_and_magic_bmp", "formats")
		self.menu.addAction("game\\quake_mdl", "formats")
		self.menu.addAction("game\\quake_pak", "formats")
		self.menu.addAction("game\\renderware_binary_stream", "formats")
		self.menu.addAction("game\\saints_row_2_vpp_pc", "formats")
		self.menu.addAction("game\\warcraft_2_pud", "formats")
		self.menu.addAction("geospatial\\shapefile_index", "formats")
		self.menu.addAction("geospatial\\shapefile_main", "formats")
		self.menu.addAction("hardware\\edid", "formats")
		self.menu.addAction("hardware\\mifare\\mifare_classic", "formats")
		self.menu.addAction("image\\bmp", "formats")
		self.menu.addAction("image\\dicom", "formats")
		self.menu.addAction("image\\exif", "formats")
		self.menu.addAction("image\\exif_be", "formats")
		self.menu.addAction("image\\exif_le", "formats")
		self.menu.addAction("image\\gif", "formats")
		self.menu.addAction("image\\icc_4", "formats")
		self.menu.addAction("image\\ico", "formats")
		self.menu.addAction("image\\jpeg", "formats")
		self.menu.addAction("image\\pcx", "formats")
		self.menu.addAction("image\\pcx_dcx", "formats")
		self.menu.addAction("image\\png", "formats")
		self.menu.addAction("image\\psx_tim", "formats")
		self.menu.addAction("image\\tga", "formats")
		self.menu.addAction("image\\wmf", "formats")
		self.menu.addAction("image\\xwd", "formats")
		self.menu.addAction("log\\aix_utmp", "formats")
		self.menu.addAction("log\\glibc_utmp", "formats")
		self.menu.addAction("log\\systemd_journal", "formats")
		self.menu.addAction("log\\windows_evt_log", "formats")
		self.menu.addAction("machine_code\\code_6502", "formats")
		self.menu.addAction("media\\avi", "formats")
		self.menu.addAction("media\\blender_blend", "formats")
		self.menu.addAction("media\\creative_voice_file", "formats")
		self.menu.addAction("media\\genmidi_op2", "formats")
		self.menu.addAction("media\\id3v1_1", "formats")
		self.menu.addAction("media\\id3v2_3", "formats")
		self.menu.addAction("media\\id3v2_4", "formats")
		self.menu.addAction("media\\magicavoxel_vox", "formats")
		self.menu.addAction("media\\ogg", "formats")
		self.menu.addAction("media\\quicktime_mov", "formats")
		self.menu.addAction("media\\standard_midi_file", "formats")
		self.menu.addAction("media\\stl", "formats")
		self.menu.addAction("media\\tracker_modules\\fasttracker_xm_module", "formats")
		self.menu.addAction("media\\tracker_modules\\s3m", "formats")
		self.menu.addAction("media\\vp8_ivf", "formats")
		self.menu.addAction("media\\wav", "formats")
		self.menu.addAction("network\\bitcoin_transaction", "formats")
		self.menu.addAction("network\\dns_packet", "formats")
		self.menu.addAction("network\\ethernet_frame", "formats")
		self.menu.addAction("network\\hccap", "formats")
		self.menu.addAction("network\\hccapx", "formats")
		self.menu.addAction("network\\icmp_packet", "formats")
		self.menu.addAction("network\\ipv4_packet", "formats")
		self.menu.addAction("network\\ipv6_packet", "formats")
		self.menu.addAction("network\\microsoft_network_monitor_v2", "formats")
		self.menu.addAction("network\\packet_ppi", "formats")
		self.menu.addAction("network\\pcap", "formats")
		self.menu.addAction("network\\protocol_body", "formats")
		self.menu.addAction("network\\rtcp_payload", "formats")
		self.menu.addAction("network\\rtp_packet", "formats")
		self.menu.addAction("network\\tcp_segment", "formats")
		self.menu.addAction("network\\tls_client_hello", "formats")
		self.menu.addAction("network\\udp_datagram", "formats")
		self.menu.addAction("network\\windows_systemtime", "formats")
		self.menu.addAction("scientific\\nt_mdt\\nt_mdt", "formats")
		self.menu.addAction("scientific\\nt_mdt\\nt_mdt_pal", "formats")
		self.menu.addAction("scientific\\spectroscopy\\avantes_roh60", "formats")
		self.menu.addAction("scientific\\spectroscopy\\specpr", "formats")
		self.menu.addAction("security\\openpgp_message", "formats")
		self.menu.addAction("security\\ssh_public_key", "formats")
		self.menu.addAction("serialization\\asn1\\asn1_der", "formats")
		self.menu.addAction("serialization\\bson", "formats")
		self.menu.addAction("serialization\\google_protobuf", "formats")
		self.menu.addAction("serialization\\microsoft_cfb", "formats")
		self.menu.addAction("serialization\\msgpack", "formats")
		self.menu.addAction("serialization\\ruby_marshal", "formats")
		self.menu.addAction("windows\\regf", "formats")
		self.menu.addAction("windows\\windows_lnk_file", "formats")
		self.menu.addAction("windows\\windows_minidump", "formats")
		self.menu.addAction("windows\\windows_resource_file", "formats")
		self.menu.addAction("windows\\windows_shell_items", "formats")
		self.menu.addAction("windows\\windows_systemtime", "formats")

	def bindActions(self):
		self.actionHandler.bindAction("archive\\cpio_old_le", UIAction(self.on_cpio_old_le))
		self.actionHandler.bindAction("archive\\gzip", UIAction(self.on_gzip))
		self.actionHandler.bindAction("archive\\lzh", UIAction(self.on_lzh))
		self.actionHandler.bindAction("archive\\rar", UIAction(self.on_rar))
		self.actionHandler.bindAction("archive\\zip", UIAction(self.on_zip))
		self.actionHandler.bindAction("cad\\monomakh_sapr_chg", UIAction(self.on_monomakh_sapr_chg))
		self.actionHandler.bindAction("common\\bcd", UIAction(self.on_bcd))
		self.actionHandler.bindAction("database\\dbf", UIAction(self.on_dbf))
		self.actionHandler.bindAction("database\\gettext_mo", UIAction(self.on_gettext_mo))
		self.actionHandler.bindAction("database\\sqlite3", UIAction(self.on_sqlite3))
		self.actionHandler.bindAction("database\\tsm", UIAction(self.on_tsm))
		self.actionHandler.bindAction("executable\\dex", UIAction(self.on_dex))
		self.actionHandler.bindAction("executable\\dos_mz", UIAction(self.on_dos_mz))
		self.actionHandler.bindAction("executable\\elf", UIAction(self.on_elf))
		self.actionHandler.bindAction("executable\\java_class", UIAction(self.on_java_class))
		self.actionHandler.bindAction("executable\\mach_o", UIAction(self.on_mach_o))
		self.actionHandler.bindAction("executable\\microsoft_pe", UIAction(self.on_microsoft_pe))
		self.actionHandler.bindAction("executable\\python_pyc_27", UIAction(self.on_python_pyc_27))
		self.actionHandler.bindAction("executable\\swf", UIAction(self.on_swf))
		self.actionHandler.bindAction("filesystem\\apm_partition_table", UIAction(self.on_apm_partition_table))
		self.actionHandler.bindAction("filesystem\\apple_single_double", UIAction(self.on_apple_single_double))
		self.actionHandler.bindAction("filesystem\\cramfs", UIAction(self.on_cramfs))
		self.actionHandler.bindAction("filesystem\\ext2", UIAction(self.on_ext2))
		self.actionHandler.bindAction("filesystem\\gpt_partition_table", UIAction(self.on_gpt_partition_table))
		self.actionHandler.bindAction("filesystem\\iso9660", UIAction(self.on_iso9660))
		self.actionHandler.bindAction("filesystem\\luks", UIAction(self.on_luks))
		self.actionHandler.bindAction("filesystem\\lvm2", UIAction(self.on_lvm2))
		self.actionHandler.bindAction("filesystem\\mbr_partition_table", UIAction(self.on_mbr_partition_table))
		self.actionHandler.bindAction("filesystem\\tr_dos_image", UIAction(self.on_tr_dos_image))
		self.actionHandler.bindAction("filesystem\\vdi", UIAction(self.on_vdi))
		self.actionHandler.bindAction("filesystem\\vfat", UIAction(self.on_vfat))
		self.actionHandler.bindAction("filesystem\\vmware_vmdk", UIAction(self.on_vmware_vmdk))
		self.actionHandler.bindAction("firmware\\andes_firmware", UIAction(self.on_andes_firmware))
		self.actionHandler.bindAction("firmware\\ines", UIAction(self.on_ines))
		self.actionHandler.bindAction("firmware\\uimage", UIAction(self.on_uimage))
		self.actionHandler.bindAction("font\\ttf", UIAction(self.on_ttf))
		self.actionHandler.bindAction("game\\allegro_dat", UIAction(self.on_allegro_dat))
		self.actionHandler.bindAction("game\\doom_wad", UIAction(self.on_doom_wad))
		self.actionHandler.bindAction("game\\dune_2_pak", UIAction(self.on_dune_2_pak))
		self.actionHandler.bindAction("game\\fallout2_dat", UIAction(self.on_fallout2_dat))
		self.actionHandler.bindAction("game\\fallout_dat", UIAction(self.on_fallout_dat))
		self.actionHandler.bindAction("game\\ftl_dat", UIAction(self.on_ftl_dat))
		self.actionHandler.bindAction("game\\gran_turismo_vol", UIAction(self.on_gran_turismo_vol))
		self.actionHandler.bindAction("game\\heaps_pak", UIAction(self.on_heaps_pak))
		self.actionHandler.bindAction("game\\heroes_of_might_and_magic_agg", UIAction(self.on_heroes_of_might_and_magic_agg))
		self.actionHandler.bindAction("game\\heroes_of_might_and_magic_bmp", UIAction(self.on_heroes_of_might_and_magic_bmp))
		self.actionHandler.bindAction("game\\quake_mdl", UIAction(self.on_quake_mdl))
		self.actionHandler.bindAction("game\\quake_pak", UIAction(self.on_quake_pak))
		self.actionHandler.bindAction("game\\renderware_binary_stream", UIAction(self.on_renderware_binary_stream))
		self.actionHandler.bindAction("game\\saints_row_2_vpp_pc", UIAction(self.on_saints_row_2_vpp_pc))
		self.actionHandler.bindAction("game\\warcraft_2_pud", UIAction(self.on_warcraft_2_pud))
		self.actionHandler.bindAction("geospatial\\shapefile_index", UIAction(self.on_shapefile_index))
		self.actionHandler.bindAction("geospatial\\shapefile_main", UIAction(self.on_shapefile_main))
		self.actionHandler.bindAction("hardware\\edid", UIAction(self.on_edid))
		self.actionHandler.bindAction("hardware\\mifare\\mifare_classic", UIAction(self.on_mifare_classic))
		self.actionHandler.bindAction("image\\bmp", UIAction(self.on_bmp))
		self.actionHandler.bindAction("image\\dicom", UIAction(self.on_dicom))
		self.actionHandler.bindAction("image\\exif", UIAction(self.on_exif))
		self.actionHandler.bindAction("image\\exif_be", UIAction(self.on_exif_be))
		self.actionHandler.bindAction("image\\exif_le", UIAction(self.on_exif_le))
		self.actionHandler.bindAction("image\\gif", UIAction(self.on_gif))
		self.actionHandler.bindAction("image\\icc_4", UIAction(self.on_icc_4))
		self.actionHandler.bindAction("image\\ico", UIAction(self.on_ico))
		self.actionHandler.bindAction("image\\jpeg", UIAction(self.on_jpeg))
		self.actionHandler.bindAction("image\\pcx", UIAction(self.on_pcx))
		self.actionHandler.bindAction("image\\pcx_dcx", UIAction(self.on_pcx_dcx))
		self.actionHandler.bindAction("image\\png", UIAction(self.on_png))
		self.actionHandler.bindAction("image\\psx_tim", UIAction(self.on_psx_tim))
		self.actionHandler.bindAction("image\\tga", UIAction(self.on_tga))
		self.actionHandler.bindAction("image\\wmf", UIAction(self.on_wmf))
		self.actionHandler.bindAction("image\\xwd", UIAction(self.on_xwd))
		self.actionHandler.bindAction("log\\aix_utmp", UIAction(self.on_aix_utmp))
		self.actionHandler.bindAction("log\\glibc_utmp", UIAction(self.on_glibc_utmp))
		self.actionHandler.bindAction("log\\systemd_journal", UIAction(self.on_systemd_journal))
		self.actionHandler.bindAction("log\\windows_evt_log", UIAction(self.on_windows_evt_log))
		self.actionHandler.bindAction("machine_code\\code_6502", UIAction(self.on_code_6502))
		self.actionHandler.bindAction("media\\avi", UIAction(self.on_avi))
		self.actionHandler.bindAction("media\\blender_blend", UIAction(self.on_blender_blend))
		self.actionHandler.bindAction("media\\creative_voice_file", UIAction(self.on_creative_voice_file))
		self.actionHandler.bindAction("media\\genmidi_op2", UIAction(self.on_genmidi_op2))
		self.actionHandler.bindAction("media\\id3v1_1", UIAction(self.on_id3v1_1))
		self.actionHandler.bindAction("media\\id3v2_3", UIAction(self.on_id3v2_3))
		self.actionHandler.bindAction("media\\id3v2_4", UIAction(self.on_id3v2_4))
		self.actionHandler.bindAction("media\\magicavoxel_vox", UIAction(self.on_magicavoxel_vox))
		self.actionHandler.bindAction("media\\ogg", UIAction(self.on_ogg))
		self.actionHandler.bindAction("media\\quicktime_mov", UIAction(self.on_quicktime_mov))
		self.actionHandler.bindAction("media\\standard_midi_file", UIAction(self.on_standard_midi_file))
		self.actionHandler.bindAction("media\\stl", UIAction(self.on_stl))
		self.actionHandler.bindAction("media\\tracker_modules\\fasttracker_xm_module", UIAction(self.on_fasttracker_xm_module))
		self.actionHandler.bindAction("media\\tracker_modules\\s3m", UIAction(self.on_s3m))
		self.actionHandler.bindAction("media\\vp8_ivf", UIAction(self.on_vp8_ivf))
		self.actionHandler.bindAction("media\\wav", UIAction(self.on_wav))
		self.actionHandler.bindAction("network\\bitcoin_transaction", UIAction(self.on_bitcoin_transaction))
		self.actionHandler.bindAction("network\\dns_packet", UIAction(self.on_dns_packet))
		self.actionHandler.bindAction("network\\ethernet_frame", UIAction(self.on_ethernet_frame))
		self.actionHandler.bindAction("network\\hccap", UIAction(self.on_hccap))
		self.actionHandler.bindAction("network\\hccapx", UIAction(self.on_hccapx))
		self.actionHandler.bindAction("network\\icmp_packet", UIAction(self.on_icmp_packet))
		self.actionHandler.bindAction("network\\ipv4_packet", UIAction(self.on_ipv4_packet))
		self.actionHandler.bindAction("network\\ipv6_packet", UIAction(self.on_ipv6_packet))
		self.actionHandler.bindAction("network\\microsoft_network_monitor_v2", UIAction(self.on_microsoft_network_monitor_v2))
		self.actionHandler.bindAction("network\\packet_ppi", UIAction(self.on_packet_ppi))
		self.actionHandler.bindAction("network\\pcap", UIAction(self.on_pcap))
		self.actionHandler.bindAction("network\\protocol_body", UIAction(self.on_protocol_body))
		self.actionHandler.bindAction("network\\rtcp_payload", UIAction(self.on_rtcp_payload))
		self.actionHandler.bindAction("network\\rtp_packet", UIAction(self.on_rtp_packet))
		self.actionHandler.bindAction("network\\tcp_segment", UIAction(self.on_tcp_segment))
		self.actionHandler.bindAction("network\\tls_client_hello", UIAction(self.on_tls_client_hello))
		self.actionHandler.bindAction("network\\udp_datagram", UIAction(self.on_udp_datagram))
		self.actionHandler.bindAction("network\\windows_systemtime", UIAction(self.on_windows_systemtime))
		self.actionHandler.bindAction("scientific\\nt_mdt\\nt_mdt", UIAction(self.on_nt_mdt))
		self.actionHandler.bindAction("scientific\\nt_mdt\\nt_mdt_pal", UIAction(self.on_nt_mdt_pal))
		self.actionHandler.bindAction("scientific\\spectroscopy\\avantes_roh60", UIAction(self.on_avantes_roh60))
		self.actionHandler.bindAction("scientific\\spectroscopy\\specpr", UIAction(self.on_specpr))
		self.actionHandler.bindAction("security\\openpgp_message", UIAction(self.on_openpgp_message))
		self.actionHandler.bindAction("security\\ssh_public_key", UIAction(self.on_ssh_public_key))
		self.actionHandler.bindAction("serialization\\asn1\\asn1_der", UIAction(self.on_asn1_der))
		self.actionHandler.bindAction("serialization\\bson", UIAction(self.on_bson))
		self.actionHandler.bindAction("serialization\\google_protobuf", UIAction(self.on_google_protobuf))
		self.actionHandler.bindAction("serialization\\microsoft_cfb", UIAction(self.on_microsoft_cfb))
		self.actionHandler.bindAction("serialization\\msgpack", UIAction(self.on_msgpack))
		self.actionHandler.bindAction("serialization\\ruby_marshal", UIAction(self.on_ruby_marshal))
		self.actionHandler.bindAction("windows\\regf", UIAction(self.on_regf))
		self.actionHandler.bindAction("windows\\windows_lnk_file", UIAction(self.on_windows_lnk_file))
		self.actionHandler.bindAction("windows\\windows_minidump", UIAction(self.on_windows_minidump))
		self.actionHandler.bindAction("windows\\windows_resource_file", UIAction(self.on_windows_resource_file))
		self.actionHandler.bindAction("windows\\windows_shell_items", UIAction(self.on_windows_shell_items))
		self.actionHandler.bindAction("windows\\windows_systemtime", UIAction(self.on_windows_systemtime))

	def mousePressEvent(self, event):
		# when someone clicks our label, pop up the context menu
		self.contextMenuManager.show(self.menu, self.actionHandler)

	def enterEvent(self, event):
		self.setAutoFillBackground(True)
		self.setForegroundRole(QPalette.HighlightedText)
		QLabel.enterEvent(self, event)

	def leaveEvent(self, event):
		self.setAutoFillBackground(False)
		self.setForegroundRole(QPalette.WindowText)
		QLabel.leaveEvent(self, event)

	def on_cpio_old_le(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('cpio_old_le')

	def on_gzip(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('gzip')

	def on_lzh(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('lzh')

	def on_rar(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('rar')

	def on_zip(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('zip')

	def on_monomakh_sapr_chg(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('monomakh_sapr_chg')

	def on_bcd(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('bcd')

	def on_dbf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('dbf')

	def on_gettext_mo(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('gettext_mo')

	def on_sqlite3(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('sqlite3')

	def on_tsm(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('tsm')

	def on_dex(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('dex')

	def on_dos_mz(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('dos_mz')

	def on_elf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('elf')

	def on_java_class(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('java_class')

	def on_mach_o(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('mach_o')

	def on_microsoft_pe(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('microsoft_pe')

	def on_python_pyc_27(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('python_pyc_27')

	def on_swf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('swf')

	def on_apm_partition_table(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('apm_partition_table')

	def on_apple_single_double(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('apple_single_double')

	def on_cramfs(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('cramfs')

	def on_ext2(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ext2')

	def on_gpt_partition_table(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('gpt_partition_table')

	def on_iso9660(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('iso9660')

	def on_luks(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('luks')

	def on_lvm2(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('lvm2')

	def on_mbr_partition_table(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('mbr_partition_table')

	def on_tr_dos_image(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('tr_dos_image')

	def on_vdi(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('vdi')

	def on_vfat(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('vfat')

	def on_vmware_vmdk(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('vmware_vmdk')

	def on_andes_firmware(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('andes_firmware')

	def on_ines(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ines')

	def on_uimage(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('uimage')

	def on_ttf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ttf')

	def on_allegro_dat(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('allegro_dat')

	def on_doom_wad(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('doom_wad')

	def on_dune_2_pak(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('dune_2_pak')

	def on_fallout2_dat(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('fallout2_dat')

	def on_fallout_dat(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('fallout_dat')

	def on_ftl_dat(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ftl_dat')

	def on_gran_turismo_vol(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('gran_turismo_vol')

	def on_heaps_pak(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('heaps_pak')

	def on_heroes_of_might_and_magic_agg(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('heroes_of_might_and_magic_agg')

	def on_heroes_of_might_and_magic_bmp(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('heroes_of_might_and_magic_bmp')

	def on_quake_mdl(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('quake_mdl')

	def on_quake_pak(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('quake_pak')

	def on_renderware_binary_stream(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('renderware_binary_stream')

	def on_saints_row_2_vpp_pc(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('saints_row_2_vpp_pc')

	def on_warcraft_2_pud(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('warcraft_2_pud')

	def on_shapefile_index(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('shapefile_index')

	def on_shapefile_main(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('shapefile_main')

	def on_edid(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('edid')

	def on_mifare_classic(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('mifare_classic')

	def on_bmp(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('bmp')

	def on_dicom(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('dicom')

	def on_exif(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('exif')

	def on_exif_be(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('exif_be')

	def on_exif_le(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('exif_le')

	def on_gif(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('gif')

	def on_icc_4(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('icc_4')

	def on_ico(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ico')

	def on_jpeg(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('jpeg')

	def on_pcx(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('pcx')

	def on_pcx_dcx(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('pcx_dcx')

	def on_png(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('png')

	def on_psx_tim(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('psx_tim')

	def on_tga(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('tga')

	def on_wmf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('wmf')

	def on_xwd(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('xwd')

	def on_aix_utmp(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('aix_utmp')

	def on_glibc_utmp(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('glibc_utmp')

	def on_systemd_journal(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('systemd_journal')

	def on_windows_evt_log(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_evt_log')

	def on_code_6502(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('code_6502')

	def on_avi(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('avi')

	def on_blender_blend(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('blender_blend')

	def on_creative_voice_file(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('creative_voice_file')

	def on_genmidi_op2(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('genmidi_op2')

	def on_id3v1_1(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('id3v1_1')

	def on_id3v2_3(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('id3v2_3')

	def on_id3v2_4(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('id3v2_4')

	def on_magicavoxel_vox(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('magicavoxel_vox')

	def on_ogg(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ogg')

	def on_quicktime_mov(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('quicktime_mov')

	def on_standard_midi_file(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('standard_midi_file')

	def on_stl(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('stl')

	def on_fasttracker_xm_module(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('fasttracker_xm_module')

	def on_s3m(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('s3m')

	def on_vp8_ivf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('vp8_ivf')

	def on_wav(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('wav')

	def on_bitcoin_transaction(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('bitcoin_transaction')

	def on_dns_packet(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('dns_packet')

	def on_ethernet_frame(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ethernet_frame')

	def on_hccap(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('hccap')

	def on_hccapx(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('hccapx')

	def on_icmp_packet(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('icmp_packet')

	def on_ipv4_packet(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ipv4_packet')

	def on_ipv6_packet(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ipv6_packet')

	def on_microsoft_network_monitor_v2(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('microsoft_network_monitor_v2')

	def on_packet_ppi(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('packet_ppi')

	def on_pcap(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('pcap')

	def on_protocol_body(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('protocol_body')

	def on_rtcp_payload(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('rtcp_payload')

	def on_rtp_packet(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('rtp_packet')

	def on_tcp_segment(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('tcp_segment')

	def on_tls_client_hello(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('tls_client_hello')

	def on_udp_datagram(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('udp_datagram')

	def on_windows_systemtime(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_systemtime')

	def on_nt_mdt(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('nt_mdt')

	def on_nt_mdt_pal(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('nt_mdt_pal')

	def on_avantes_roh60(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('avantes_roh60')

	def on_specpr(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('specpr')

	def on_openpgp_message(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('openpgp_message')

	def on_ssh_public_key(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ssh_public_key')

	def on_asn1_der(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('asn1_der')

	def on_bson(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('bson')

	def on_google_protobuf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('google_protobuf')

	def on_microsoft_cfb(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('microsoft_cfb')

	def on_msgpack(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('msgpack')

	def on_ruby_marshal(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('ruby_marshal')

	def on_regf(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('regf')

	def on_windows_lnk_file(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_lnk_file')

	def on_windows_minidump(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_minidump')

	def on_windows_resource_file(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_resource_file')

	def on_windows_shell_items(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_shell_items')

	def on_windows_systemtime(self, uiActionContext):
		self.statusBarWidget.kaitaiView.kaitaiParse('windows_systemtime')


# KaitaiStatusBarWidget <- StatusBarWidget <- QFrame
class KaitaiStatusBarWidget(StatusBarWidget):
	def __init__(self, parent):
		StatusBarWidget.__init__(self, parent)

		self.kaitaiView = parent

		self.layout = QHBoxLayout(self)
		self.layout.setContentsMargins(0,0,0,0)
		
		self.options = KaitaiOptionsWidget(self)
		self.layout.addWidget(self.options)

	def updateStatus(self):
		#print 'updateStatus()'
		pass
