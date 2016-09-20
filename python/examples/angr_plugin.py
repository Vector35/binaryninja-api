# This plugin assumes angr is already installed and available on the system. See the angr documentation
# for information about installing angr. It should be installed using the virtualenv method.
#
# This plugin is currently only known to work on Linux using virtualenv. Switch to the virtual environment
# (using a command such as "workon angr"), then run the Binary Ninja UI from the command line.
#
# This method is known to fail on Mac OS X as the virtualenv used by angr does not appear to provide a
# way to automatically link to the correct version of Python, even when running the UI from within the
# virtual environment. A later update may allow for a manual override to link to the required version
# of Python.

__name__ = "__console__" # angr looks for this, it won't load from within a UI without it
import angr
from binaryninja import *
import tempfile
import threading
import logging
import os

# Disable warning logs as they show up as errors in the UI
logging.disable(logging.WARNING)

# Create sets in the BinaryView's data field to store the desired path for each view
BinaryView.set_default_data("angr_find", set())
BinaryView.set_default_data("angr_avoid", set())

def escaped_output(str):
	return '\n'.join([s.encode("string_escape") for s in str.split('\n')])

# Define a background thread object for solving in the background
class Solver(BackgroundTaskThread):
	def __init__(self, find, avoid, view):
		BackgroundTaskThread.__init__(self, "Solving with angr...", True)
		self.find = tuple(find)
		self.avoid = tuple(avoid)
		self.view = view

		# Write the binary to disk so that the angr API can read it
		self.binary = tempfile.NamedTemporaryFile()
		self.binary.write(view.file.raw.read(0, len(view.file.raw)))
		self.binary.flush()

	def run(self):
		# Create an angr project and an explorer with the user's settings
		p = angr.Project(self.binary.name)
		e = p.surveyors.Explorer(find = self.find, avoid = self.avoid)

		# Solve loop
		while not e.done:
			if self.cancelled:
				# Solve cancelled, show results if there were any
				if len(e.found) > 0:
					break
				return

			# Perform the next step in the solve
			e.step()

			# Update status
			active_count = len(e.active)
			found_count = len(e.found)

			progress = "Solving with angr (%d active path%s" % (active_count, "s" if active_count != 1 else "")
			if found_count > 0:
				progress += ", %d path%s found" % (found_count, "s" if found_count != 1 else "")
			self.progress = progress + ")..."

		# Solve complete, show report
		text_report = "Found %d path%s.\n\n" % (len(e.found), "s" if len(e.found) != 1 else "")
		i = 1
		for f in e.found:
			text_report += "Path %d\n" % i + "=" * 10 + "\n"
			text_report += "stdin:\n" + escaped_output(f.state.posix.dumps(0)) + "\n\n"
			text_report += "stdout:\n" + escaped_output(f.state.posix.dumps(1)) + "\n\n"
			text_report += "stderr:\n" + escaped_output(f.state.posix.dumps(2)) + "\n\n"
			i += 1

		name = self.view.file.filename
		if len(name) > 0:
			show_plain_text_report("Results from angr - " + os.path.basename(self.view.file.filename), text_report)
		else:
			show_plain_text_report("Results from angr", text_report)

def find_instr(bv, addr):
	# Highlight the instruction in green
	blocks = bv.get_basic_blocks_at(addr)
	for block in blocks:
		block.set_auto_highlight(HighlightColor(GreenHighlightColor, alpha = 128))
		block.function.set_auto_instr_highlight(block.arch, addr, GreenHighlightColor)

	# Add the instruction to the list associated with the current view
	bv.data.angr_find.add(addr)

def avoid_instr(bv, addr):
	# Highlight the instruction in red
	blocks = bv.get_basic_blocks_at(addr)
	for block in blocks:
		block.set_auto_highlight(HighlightColor(RedHighlightColor, alpha = 128))
		block.function.set_auto_instr_highlight(block.arch, addr, RedHighlightColor)

	# Add the instruction to the list associated with the current view
	bv.data.angr_avoid.add(addr)

def solve(bv):
	if len(bv.data.angr_find) == 0:
		show_message_box("Angr Solve", "You have not specified a goal instruction.\n\n" +
			"Please right click on the goal instruction and select \"Find Path to This Instruction\" to " +
			"continue.", OKButtonSet, ErrorIcon)
		return

	# Start a solver thread for the path associated with the view
	s = Solver(bv.data.angr_find, bv.data.angr_avoid, bv)
	s.start()

# Register commands for the user to interact with the plugin
PluginCommand.register_for_address("Find Path to This Instruction",
	"When solving, find a path that gets to this instruction", find_instr)
PluginCommand.register_for_address("Avoid This Instruction",
	"When solving, avoid paths that reach this instruction", avoid_instr)
PluginCommand.register("Solve With Angr", "Attempt to solve for a path that satisfies the constraints given", solve)
