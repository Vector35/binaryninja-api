# List Keybindings
#
# Enumerate every keybindable action registered in Binary Ninja along with its
# current and default key sequence. This is the authoritative way to discover
# valid action names (the strings used as keys in a `keybindings.json` file) --
# it reflects exactly what is registered at runtime, including actions added by
# plugins, so it never goes stale the way a hard-coded list would.
#
# Use it to:
#   * Find the exact action name to bind in your keybindings.json
#   * Validate that an existing keybindings.json only references real actions
#   * Generate a keybindings.json skeleton pre-filled with current bindings
#
# This must be run from the integrated Python console in the UI (it relies on
# binaryninjaui, which is only available when the GUI is running). Run it with:
#
#     >>> exec(open("/path/to/list_keybindings.py").read())
#
# or load it as a plugin and invoke "List Keybindings" from the command palette.

import json

from binaryninjaui import UIAction, UIActionHandler, Menu
from PySide6.QtGui import QKeySequence


def _seq_to_str(seq_list):
	"""Serialize alternative key sequences using Qt's portable list format."""
	return QKeySequence.listToString([seq for seq in seq_list if not seq.isEmpty()])


def _canon(seq_str):
	"""Canonicalize a key-sequence string so equivalent spellings compare equal
	(e.g. "Ctrl+Shift+Z" vs a default returned by Qt)."""
	return QKeySequence.listToString(QKeySequence.listFromString(seq_str))


def get_all_actions():
	"""Return {action_name: {"current": str, "default": str}} for every action,
	sorted by action name."""
	result = {}
	for name in sorted(UIAction.getAllRegisteredActions()):
		result[name] = {
			"current": _seq_to_str(UIAction.getKeyBinding(name)),
			"default": _seq_to_str(UIAction.getDefaultKeyBinding(name)),
		}
	return result


def print_keybindings(only_bound=False):
	"""Print a table of every action and its current/default key sequence.

	If only_bound is True, only actions that currently have a binding are shown.
	"""
	actions = get_all_actions()
	name_width = max((len(n) for n in actions), default=0)
	print(f"{'Action'.ljust(name_width)}  {'Current':<22} Default")
	print(f"{'-' * name_width}  {'-' * 22} {'-' * 22}")
	count = 0
	for name, binding in actions.items():
		if only_bound and not binding["current"]:
			continue
		print(f"{name.ljust(name_width)}  {binding['current']:<22} {binding['default']}")
		count += 1
	print(f"\n{count} actions ({len(actions)} total registered)")


def export_keybindings_json(path, only_bound=False):
	"""Write a keybindings.json-style file mapping action name -> current key
	sequence. Useful as a starting point for an IDA/Ghidra migration preset --
	edit the values, delete the lines you don't want, and drop it in your user
	folder as keybindings.json."""
	actions = get_all_actions()
	mapping = {
		name: binding["current"]
		for name, binding in actions.items()
		if binding["current"] or not only_bound
	}
	with open(path, "w") as f:
		json.dump(mapping, f, indent=2, sort_keys=True)
	print(f"Wrote {len(mapping)} actions to {path}")


def audit_keybindings(path):
	"""Audit a keybindings.json against the live defaults, classifying each entry:

	  redundant - the entry just restates the current default (safe to remove;
	              the default applies automatically when the action is omitted)
	  override  - changes an action that has a different default (keep)
	  new       - binds an action that has no default (keep)
	  unbind    - clears a default with "" (keep)
	  missing   - action name is not registered (likely a typo / stale name)

	Defaults are read live via UIAction.getDefaultKeyBinding(), so
	platform-dependent (Save/Find/...) and dynamically registered actions
	resolve correctly. Run this in the UI Python console."""
	with open(path) as f:
		data = json.load(f)

	buckets = {"redundant": [], "override": [], "new": [], "unbind": [], "missing": []}
	for action, key in data.items():
		if not UIAction.isActionRegistered(action):
			buckets["missing"].append((action, key))
			continue
		default = _seq_to_str(UIAction.getDefaultKeyBinding(action))
		if key == "":
			buckets["unbind"].append((action, default)) if default else buckets["redundant"].append((action, "(no default)"))
		elif _canon(key) == _canon(default):
			buckets["redundant"].append((action, key))
		elif default == "":
			buckets["new"].append((action, key))
		else:
			buckets["override"].append((action, key, default))

	print(f"\nAudit of {path}")
	print(f"  REDUNDANT (== default, candidate for removal): {len(buckets['redundant'])}")
	for a, k in buckets["redundant"]:
		print(f"      {a!r}: {k!r}")
	print(f"  overrides: {len(buckets['override'])}")
	for a, k, d in buckets["override"]:
		print(f"      {a!r}: {k!r}  (default {d!r})")
	print(f"  new bindings (no default): {len(buckets['new'])}")
	for a, k in buckets["new"]:
		print(f"      {a!r}: {k!r}")
	print(f"  explicit unbinds: {len(buckets['unbind'])}  {[a for a, _ in buckets['unbind']]}")
	if buckets["missing"]:
		print(f"  MISSING/unregistered action names: {len(buckets['missing'])}")
		for a, k in buckets["missing"]:
			print(f"      {a!r}: {k!r}")
	return buckets


def _list_keybindings_action(_ctx):
	print_keybindings()


# Register a command-palette action when loaded as a plugin in the UI.
if not UIAction.isActionRegistered("List Keybindings"):
	UIAction.registerAction("List Keybindings")
	UIActionHandler.globalActions().bindAction("List Keybindings", UIAction(_list_keybindings_action))
	Menu.mainMenu("Plugins").addAction("List Keybindings", "Keybindings")

# When run directly from the console (exec), print a short usage hint rather
# than dumping every action, so audit/export calls aren't buried in output.
if __name__ == "__main__":
	print("list_keybindings loaded. Available functions:")
	print("  print_keybindings(only_bound=False)        # table of every action's current/default key")
	print("  export_keybindings_json(path)              # write a keybindings.json skeleton")
	print("  audit_keybindings(path)                    # classify a keybindings.json vs live defaults")
