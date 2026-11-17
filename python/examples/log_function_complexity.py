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
log_function_complexity.py
===========================

Headless script that loads a binary, computes every code complexity metric
(`Function.get_complexity()`) for every function, logs the results, and optionally writes them
to a CSV file for further analysis (e.g. in a spreadsheet, or to diff two versions of a binary).

Usage:

    python3 log_function_complexity.py <binary> [--metric NAME] [--top N] [--csv out.csv] [--quiet]

Examples:

    # Log every metric for every function, sorted by composite complexity
    python3 log_function_complexity.py /bin/ls

    # Only the 10 most cyclomatically complex functions
    python3 log_function_complexity.py /bin/ls --metric cyclomatic --top 10

    # Everything, plus a CSV for spreadsheet analysis
    python3 log_function_complexity.py /bin/ls --csv ls_complexity.csv
"""

import argparse
import csv
import sys

import binaryninja
from binaryninja import complexity
from binaryninja.function import Function

METRICS = Function.complexity_metrics()


def parse_args(argv):
	parser = argparse.ArgumentParser(description='Log code complexity metrics for every function in a binary.')
	parser.add_argument('binary', help='Path to the binary to analyze')
	parser.add_argument(
	    '--metric', choices=METRICS + ['all'], default='all',
	    help='Which metric to sort/log by (default: all metrics, sorted by composite)'
	)
	parser.add_argument('--top', type=int, default=None, help='Only log the top N functions (default: all)')
	parser.add_argument('--csv', default=None, help='Optional path to write a CSV of all metrics for all functions')
	parser.add_argument('--quiet', action='store_true', help="Don't print a summary table to stdout")
	return parser.parse_args(argv)


def compute_all(bv) -> list:
	"""
	Returns a list of (Function, {metric_name: value}) for every function that could be analyzed.

	Uses `complexity.compute_all_complexity`, which shares one `ComplexityCache` across the whole
	binary: a helper reachable from many callers (logging, malloc wrappers, ...) has its own
	complexity computed once for the scan, not once per caller that reaches it. Without that, the
	`transitive` metric in particular would redo the same common callees' analysis over and over on
	a binary with much shared code.
	"""
	return complexity.compute_all_complexity(bv.functions, METRICS)


def main(argv=None) -> int:
	args = parse_args(sys.argv[1:] if argv is None else argv)

	bv = binaryninja.load(args.binary)
	if bv is None:
		binaryninja.log_error(f'log_function_complexity: could not load {args.binary}')
		return 1
	bv.update_analysis_and_wait()

	sort_key = 'composite' if args.metric == 'all' else args.metric
	results = compute_all(bv)
	results.sort(key=lambda entry: entry[1][sort_key], reverse=True)
	if args.top is not None:
		results = results[:args.top]

	binaryninja.log_info(
	    f'log_function_complexity: analyzed {len(results)} function(s) in {args.binary}, sorted by {sort_key}'
	)
	for func, values in results:
		if args.metric == 'all':
			detail = ', '.join(f'{m}={values[m]:.2f}' for m in METRICS)
		else:
			detail = f'{args.metric}={values[args.metric]:.2f}'
		binaryninja.log_info(f'{func.name} @ {func.start:#x}: {detail}')

	if not args.quiet:
		header = ['function', 'address'] + METRICS
		widths = [max(len(header[i]), 10) for i in range(len(header))]
		print(' '.join(h.ljust(w) for h, w in zip(header, widths)))
		for func, values in results:
			row = [func.name, f'{func.start:#x}'] + [f'{values[m]:.2f}' for m in METRICS]
			print(' '.join(c.ljust(w) for c, w in zip(row, widths)))

	if args.csv:
		with open(args.csv, 'w', newline='') as f:
			writer = csv.writer(f)
			writer.writerow(['function', 'address'] + METRICS)
			for func, values in results:
				writer.writerow([func.name, hex(func.start)] + [values[m] for m in METRICS])
		binaryninja.log_info(f'log_function_complexity: wrote {len(results)} row(s) to {args.csv}')

	return 0


if __name__ == '__main__':
	sys.exit(main())
