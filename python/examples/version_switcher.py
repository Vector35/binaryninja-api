#!/usr/bin/env python
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

import sys

from binaryninja.update import UpdateChannel, are_auto_updates_enabled, set_auto_updates_enabled, is_update_installation_pending, install_pending_update
from binaryninja import core_version
import datetime

chandefault = UpdateChannel.list[0].name
channel = None
versions = []


def load_channel(newchannel):
	global channel
	global versions
	if (channel is not None and newchannel == channel.name):
		print("Same channel, not updating.")
	else:
		try:
			print("Loading channel %s" % newchannel)
			channel = UpdateChannel[newchannel]
			print("Loading versions...")
			versions = channel.versions
		except Exception:
			print("%s is not a valid channel name. Defaulting to " % chandefault)
			channel = UpdateChannel[chandefault]


def select(version):
	done = False
	date = datetime.datetime.fromtimestamp(version.time).strftime('%c')
	while not done:
		print("Version:\t%s" % version.version)
		print("Updated:\t%s" % date)
		print("Notes:\n\n-----\n%s" % version.notes)
		print("-----")
		print("\t1)\tSwitch to version")
		print("\t2)\tMain Menu")
		selection = raw_input('Choice: ')
		if selection.isdigit():
			selection = int(selection)
		else:
			selection = 0
		if (selection == 2):
			done = True
		elif (selection == 1):
			if (version.version == channel.latest_version.version):
				print("Requesting update to latest version.")
			else:
				print("Requesting update to prior version.")
				if are_auto_updates_enabled():
					print("Disabling automatic updates.")
					set_auto_updates_enabled(False)
			if (version.version == core_version):
				print("Already running %s" % version.version)
			else:
				print("version.version %s" % version.version)
				print("core_version %s" % core_version)
				print("Downloading...")
				print(version.update())
				print("Installing...")
				if is_update_installation_pending:
					#note that the GUI will be launched after update but should still do the upgrade headless
					install_pending_update()
				# forward updating won't work without reloading
				sys.exit()
		else:
			print("Invalid selection")


def list_channels():
	done = False
	print("\tSelect channel:\n")
	while not done:
		channel_list = UpdateChannel.list
		for index, item in enumerate(channel_list):
			print("\t%d)\t%s" % (index + 1, item.name))
		print("\t%d)\t%s" % (len(channel_list) + 1, "Main Menu"))
		selection = raw_input('Choice: ')
		if selection.isdigit():
			selection = int(selection)
		else:
			selection = 0
		if (selection <= 0 or selection > len(channel_list) + 1):
			print("%s is an invalid choice." % selection)
		else:
			done = True
			if (selection != len(channel_list) + 1):
				load_channel(channel_list[selection - 1].name)


def toggle_updates():
	set_auto_updates_enabled(not are_auto_updates_enabled())


def main():
	global channel
	done = False
	load_channel(chandefault)
	while not done:
		print("\n\tBinary Ninja Version Switcher")
		print("\t\tCurrent Channel:\t%s" % channel.name)
		print("\t\tCurrent Version:\t%s" % core_version)
		print("\t\tAuto-Updates On:\t%s\n" % are_auto_updates_enabled())
		for index, version in enumerate(versions):
			date = datetime.datetime.fromtimestamp(version.time).strftime('%c')
			print("\t%d)\t%s (%s)" % (index + 1, version.version, date))
		print("\t%d)\t%s" % (len(versions) + 1, "Switch Channel"))
		print("\t%d)\t%s" % (len(versions) + 2, "Toggle Auto Updates"))
		print("\t%d)\t%s" % (len(versions) + 3, "Exit"))
		selection = raw_input('Choice: ')
		if selection.isdigit():
			selection = int(selection)
		else:
			selection = 0
		if (selection <= 0 or selection > len(versions) + 3):
			print("%d is an invalid choice.\n\n" % selection)
		else:
			if (selection == len(versions) + 3):
				done = True
			elif (selection == len(versions) + 2):
				toggle_updates()
			elif (selection == len(versions) + 1):
				list_channels()
			else:
				select(versions[selection - 1])


if __name__ == "__main__":
	main()
