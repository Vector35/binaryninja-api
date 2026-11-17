# Copyright (c) 2015-2026 Vector 35 Inc
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

"""
Code Complexity Report
=======================

An example plugin that surfaces ``Function.get_complexity()`` in the UI (and headlessly).

Installed as a plugin, it registers two commands:

* Right-click a function -> ``Plugins\\Code Complexity\\Show Report for This Function``
  Shows every complexity metric for the clicked function side by side, with a simple bar
  visualization so the relative weight of each factor (length, branching, instruction
  diversity, nesting) is easy to see at a glance.

* ``Plugins\\Code Complexity\\Show Report for All Functions``
  Ranks every function in the binary by composite complexity and shows the top functions
  with a full metric breakdown for each - a quick way to find the functions most worth
  digging into or refactoring.

It can also be run directly, headlessly, against a file on disk:

    python3 complexity_report.py /bin/ls
"""

import sys
from typing import List

import binaryninja
from binaryninja import complexity
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import show_markdown_report

METRICS = Function.complexity_metrics()

# Rough "this is a lot" reference point for each metric, used only to scale the bar charts in
# the report - it has no effect on the scores themselves. Chosen from the distribution of
# values across the functions in a handful of real-world binaries.
_BAR_SCALE = {
	'cyclomatic': 30.0,
	'instruction_count': 400.0,
	'token_count': 1200.0,
	'branch_density': 0.5,
	'halstead': 8000.0,
	'nesting_depth': 8.0,
	'cognitive': 100.0,
	'composite': 300.0,
	'fan_out': 20.0,
	'code_references': 100.0,
	'transitive': 500.0,
}

_METRIC_DESCRIPTIONS = {
	'cyclomatic': 'independent paths through the CFG.',
	'instruction_count': 'raw MLIL length.',
	'token_count': 'raw disassembly text token count.',
	'branch_density': 'fraction of statements that branch.',
	'halstead': 'volume from operator/operand diversity.',
	'nesting_depth': 'deepest if/while/for/switch nesting.',
	'cognitive': 'nesting-weighted control-flow cost.',
	'composite': 'weighted blend of the metrics above.',
	'fan_out': 'how much (and how riskily) this function calls out to other code.',
	'code_references': 'how many places in the code call/reference this function.',
	'transitive': "this function's composite complexity plus everything it calls, recursively.",
}

_BAR_WIDTH = 20


def _bar(metric: str, value: float) -> str:
	scale = _BAR_SCALE.get(metric, 1.0) or 1.0
	filled = int(min(1.0, value / scale) * _BAR_WIDTH)
	return '`' + ('#' * filled) + ('.' * (_BAR_WIDTH - filled)) + '`'


def _function_report_markdown(func: Function) -> str:
	lines = [
		f'# Code Complexity: `{func.name}`',
		'',
		f'*{func.start:#x} in {func.view.file.filename}*',
		'',
		'| Metric | Value | Relative |',
		'|---|---|---|',
	]
	for metric in METRICS:
		value = func.get_complexity(metric)
		lines.append(f'| {metric} | {value:.2f} | {_bar(metric, value)} |')
	lines.append('')
	for metric in METRICS:
		lines.append(f'- `{metric}`: {_METRIC_DESCRIPTIONS[metric]}')
	return '\n'.join(lines)


def _binary_report_markdown(bv: BinaryView, top_n: int = 25) -> str:
	# One shared cache for the whole scan: a helper reachable from many callers (logging, malloc
	# wrappers, ...) gets its own complexity computed once here rather than once per caller that
	# reaches it - see complexity.ComplexityCache. Without this, `transitive` in particular would
	# redo the same common callees' analysis over and over on a binary with much shared code.
	cache = complexity.ComplexityCache()
	scored = []
	for func in bv.functions:
		try:
			scored.append((func, {m: complexity.get_code_complexity(func, m, cache=cache) for m in METRICS}))
		except Exception as e:
			binaryninja.log_warn(f'complexity_report: skipping {func.name}: {e}')
	scored.sort(key=lambda entry: entry[1]['composite'], reverse=True)

	lines = [
		f'# Code Complexity Report: {bv.file.filename}',
		'',
		f'{len(scored)} functions analyzed. Showing the top {min(top_n, len(scored))} by composite score.',
		'',
		'| Function | ' + ' | '.join(METRICS) + ' |',
		'|---|' + '---|' * len(METRICS),
	]
	for func, values in scored[:top_n]:
		row = ' | '.join(f'{values[m]:.2f}' for m in METRICS)
		lines.append(f'| [{func.name}]({func.start:#x}) | {row} |')
	return '\n'.join(lines)


def show_function_complexity(bv: BinaryView, func: Function) -> None:
	show_markdown_report(
		f'Code Complexity: {func.name}', _function_report_markdown(func), _function_report_markdown(func)
	)


def show_binary_complexity(bv: BinaryView) -> None:
	show_markdown_report(
		f'Code Complexity: {bv.file.filename}', _binary_report_markdown(bv), _binary_report_markdown(bv)
	)


PluginCommand.register_for_function(
	'Code Complexity\\Show Report for This Function',
	'Show every code complexity metric for the current function',
	show_function_complexity,
)

PluginCommand.register(
	'Code Complexity\\Show Report for All Functions',
	'Rank every function in the binary by code complexity',
	show_binary_complexity,
)


if __name__ == '__main__':
	if len(sys.argv) != 2:
		print(f'usage: {sys.argv[0]} <path-to-binary>')
		sys.exit(1)

	bv = binaryninja.load(sys.argv[1])
	if bv is None:
		print(f'could not load {sys.argv[1]}')
		sys.exit(1)
	bv.update_analysis_and_wait()

	print(_binary_report_markdown(bv))
