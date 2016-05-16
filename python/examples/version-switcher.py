#!/usr/bin/env python
import sys
import binaryninja
import datetime

chandefault="private-beta"
channel=0
up=0
versions=0

def load_channel(newchannel):
	global up
	global channel
	global versions
	if (newchannel == channel):
		print "Same channel, not updating."
	else:
		try:
			print "Loading channel %s" % newchannel
			up = binaryninja.UpdateChannel(newchannel, "", "")
			channel = newchannel
			print "Loading versions..."
			versions = up.versions
		except Exception:
			print "%s is not a valid channel name. Defaulting to " % chandefault
			channel = chandefault
			up = binaryninja.UpdateChannel(channel, "", "")

def select(version):
	done = False
	date = datetime.datetime.fromtimestamp(version.time).strftime('%c')
	while not done:
		print "Version:\t%s" % version.version
		print "Updated:\t%s" % date
		print "Notes:\t%s" % version.notes
		print "-----"
		print "\t1)\tSwitch to version"	
		print "\t2)\tMain Menu"
		selection = int(input('Choice: '))
		if (selection == 2):
			done = True
		elif (selection == 1):
			print "Updating..."
			print version.update()
			#forward updating won't work without reloading
			sys.exit()
		else:
			print "Invalid selection"

def list_channels():
	done = False
	while not done:
		channel_list = binaryninja.UpdateChannel.list
		for index, item in enumerate(channel_list):
			print "\t%d)\t%s" % (index+1, item.name)
		print "\t%d)\t%s" % (len(channel_list)+1, "Main Menu")
		selection = input('Choice: ')
		if (int(selection) <= 0 or int(selection) > len(channel_list)+1):
			print "%s is an invalid choice.\n\n" % selection
		else:
			selection = int(selection)
			done = True
			if (selection != len(channel_list) + 1):
				load_channel(channel_list[selection-1].name)

def main():
	done = False
	load_channel(chandefault)
	while not done:
		print "Binary Ninja Version Switcher"
		print "Current Channel: %s " % channel
		for index, version in enumerate(versions):
			date = datetime.datetime.fromtimestamp(version.time).strftime('%c')
			print "\t%d)\t%s (%s)" % (index+1, version.version, date)
		print "\t%d)\t%s" % (len(versions)+1, "Switch Channel")
		print "\t%d)\t%s" % (len(versions)+2, "Exit")
		selection = input('Choice: ')
		if (int(selection) <= 0 or int(selection) > len(versions)+2):
			print "%s is an invalid choice.\n\n" % selection
		else:
			selection = int(selection)
			if (selection == len(versions) + 2):
				done = True
			elif (selection == len(versions) + 1):
				list_channels()
			else:
				select(versions[selection-1])


if __name__ == "__main__":
	main()
