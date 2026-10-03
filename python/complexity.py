# coding=utf-8
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
Code complexity metrics for :py:class:`~binaryninja.function.Function`.

Each metric isolates a different factor that contributes to how hard a function is to read,
test, or reason about:

============================  =====================================================================
Metric                        Factor measured
============================  =====================================================================
``cyclomatic``                Number of linearly independent paths through the control flow graph
                               (classic McCabe metric: edges - nodes + 2).
``instruction_count``         Raw code length, counted in MLIL instructions (including sub-expressions).
``token_count``               Raw lexical size: total disassembly text tokens (mnemonics,
                               operands, punctuation) - the literal size of the listing you'd
                               read, as opposed to `instruction_count`'s semantic MLIL node count.
``branch_density``            Fraction of top-level MLIL statements that alter control flow.
``halstead``                  Diversity of instruction "vocabulary" (distinct operators/operands),
                               using Halstead's volume ``V = N * log2(n)``.
``nesting_depth``             Maximum nesting depth of structured control flow (if/while/for/switch)
                               in the HLIL AST.
``cognitive``                 SonarSource-style cognitive complexity: control flow breaks cost more
                               the more deeply they are nested.
``composite``                 Weighted blend of all of the above into a single score.
``fan_out``                   Number/riskiness of the calls this function makes (one hop only).
``code_references``           Number of places in the binary's code that reference this function -
                               the complement of `fan_out`: blast radius, not internal complexity.
``transitive``                Composite complexity of this function plus everything it calls,
                               recursively - "how much do I actually have to read".
============================  =====================================================================

Every metric from `fan_out` on is interprocedural: it looks beyond the function's own body. That
misses a common real-world shape - a `main()` that is just a flat sequence of calls to a dozen
helpers looks trivial by every intraprocedural metric (low cyclomatic complexity, no nesting) even
though understanding it fully means reading everything it calls. `fan_out`, `code_references`, and
`transitive` capture that (`code_references` in the opposite direction: callers, not callees).

All metrics are exposed through a single entry point, :py:func:`get_code_complexity`, which is
also available as :py:meth:`Function.get_complexity() <binaryninja.function.Function.get_complexity>`.
"""

import math
from collections import Counter
from typing import Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Set, Tuple, TYPE_CHECKING, Union

from . import mediumlevelil
from . import highlevelil
from .enums import MediumLevelILOperation, HighLevelILOperation, SymbolType
from .log import log_warn

if TYPE_CHECKING:
	from . import function


FunctionKey = Tuple[str, str, int]


def function_key(func: 'function.Function') -> FunctionKey:
	"""Return a stable identity for a function, including the architecture/platform at its address."""
	platform = getattr(func, 'platform', None)
	arch = getattr(func, 'arch', None)
	return (
		getattr(platform, 'name', '') if platform is not None else '',
		getattr(arch, 'name', '') if arch is not None else '',
		int(func.start),
	)


# Top-level MLIL statement operations that alter control flow. Calls are intentionally excluded:
# they do not change the shape of the *local* control flow graph, and their cost is already
# captured by `instruction_count` and `halstead`.
_MLIL_BRANCH_OPERATIONS = {
	MediumLevelILOperation.MLIL_IF,
	MediumLevelILOperation.MLIL_GOTO,
	MediumLevelILOperation.MLIL_JUMP,
	MediumLevelILOperation.MLIL_JUMP_TO,
	MediumLevelILOperation.MLIL_TAILCALL,
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
	MediumLevelILOperation.MLIL_TAILCALL_SSA,
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA,
}

# HLIL operations that introduce a new level of structural nesting.
_HLIL_NESTING_OPERATIONS = {
	HighLevelILOperation.HLIL_IF,
	HighLevelILOperation.HLIL_WHILE,
	HighLevelILOperation.HLIL_WHILE_SSA,
	HighLevelILOperation.HLIL_DO_WHILE,
	HighLevelILOperation.HLIL_DO_WHILE_SSA,
	HighLevelILOperation.HLIL_FOR,
	HighLevelILOperation.HLIL_FOR_SSA,
	HighLevelILOperation.HLIL_SWITCH,
}

_MLIL_CALL_OPERATIONS = {
	MediumLevelILOperation.MLIL_CALL,
	MediumLevelILOperation.MLIL_CALL_UNTYPED,
	MediumLevelILOperation.MLIL_CALL_SSA,
	MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
	MediumLevelILOperation.MLIL_TAILCALL,
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
	MediumLevelILOperation.MLIL_TAILCALL_SSA,
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA,
}

_MLIL_SYSCALL_OPERATIONS = {
	MediumLevelILOperation.MLIL_SYSCALL,
	MediumLevelILOperation.MLIL_SYSCALL_SSA,
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED,
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA,
}

# Symbol types whose implementation isn't in this binary (imports/thunks/library stubs) - we can
# see that a call goes there, but not what happens once it does.
_EXTERNAL_SYMBOL_TYPES = {
	SymbolType.ImportAddressSymbol,
	SymbolType.ImportedFunctionSymbol,
	SymbolType.ExternalSymbol,
	SymbolType.LibraryFunctionSymbol,
}

# Default weights used to blend the individual metrics into `composite`. These are tuned so that
# a "typical" small function scores roughly in the single digits and a deeply nested, branchy
# function scores in the tens to hundreds. Callers who want different behavior should call the
# individual metrics directly and combine them with their own weights.
DEFAULT_COMPOSITE_WEIGHTS: Dict[str, float] = {
	'cyclomatic': 0.25,
	'instruction_count': 0.05,
	'branch_density': 10.0,
	'halstead': 0.05,
	'nesting_depth': 2.0,
	'cognitive': 0.5,
}


def _walk_mlil(instr: 'mediumlevelil.MediumLevelILInstruction') -> Iterator['mediumlevelil.MediumLevelILInstruction']:
	"""Yield `instr` and every MLIL sub-expression it contains, depth-first."""
	yield instr
	for _, operand, _ in instr.detailed_operands:
		items = operand if isinstance(operand, list) else [operand]
		for item in items:
			if isinstance(item, mediumlevelil.MediumLevelILInstruction):
				yield from _walk_mlil(item)


def _walk_hlil(instr: 'highlevelil.HighLevelILInstruction') -> Iterator['highlevelil.HighLevelILInstruction']:
	"""Yield `instr` and every HLIL sub-expression it contains, depth-first."""
	yield instr
	for _, operand, _ in instr.detailed_operands:
		items = operand if isinstance(operand, list) else [operand]
		for item in items:
			if isinstance(item, highlevelil.HighLevelILInstruction):
				yield from _walk_hlil(item)


def cyclomatic_complexity(func: 'function.Function') -> float:
	"""
	McCabe cyclomatic complexity: ``M = E - N + 2`` over the function's basic block graph.

	Measures the number of branches in the control flow graph, independent of function size or
	the kinds of instructions used.
	"""
	blocks = list(func.basic_blocks)
	n = len(blocks)
	if n == 0:
		return 0.0
	e = sum(len(bb.outgoing_edges) for bb in blocks)
	return float(e - n + 2)


def instruction_count_complexity(func: 'function.Function') -> float:
	"""
	Raw code length: total number of MLIL instructions, including sub-expressions.

	Falls back to a count of disassembly lines if MLIL is not available for this function.
	"""
	mlil = func.mlil
	if mlil is None:
		return float(sum(1 for _ in func.instructions))
	count = 0
	for stmt in mlil.instructions:
		count += sum(1 for _ in _walk_mlil(stmt))
	return float(count)


def token_count_complexity(func: 'function.Function') -> float:
	"""
	Raw lexical size: total number of disassembly text tokens (mnemonics, operands, punctuation,
	etc.) across the function.

	Unlike `instruction_count`, which counts semantic MLIL nodes, this counts the literal tokens
	of the disassembly listing you'd actually read - two functions with the same MLIL shape can
	still differ here if one uses instructions with more operands/addressing-mode tokens per line
	than the other. Always available, even for functions without MLIL/HLIL.
	"""
	return float(sum(len(tokens) for tokens, _length in func.instructions))


def branch_density_complexity(func: 'function.Function') -> float:
	"""
	Fraction (0.0-1.0) of top-level MLIL statements that alter control flow (if/goto/jump/tailcall).

	Two functions can have the same instruction count but very different "branchiness"; this
	metric isolates that factor independent of raw length.
	"""
	mlil = func.mlil
	if mlil is None:
		return 0.0
	statements = list(mlil.instructions)
	if not statements:
		return 0.0
	branches = sum(1 for stmt in statements if stmt.operation in _MLIL_BRANCH_OPERATIONS)
	return branches / len(statements)


def halstead_volume_complexity(func: 'function.Function') -> float:
	"""
	Halstead volume ``V = N * log2(n)`` over MLIL, where:

	* ``n`` (vocabulary) is the number of distinct operators (MLIL operation kinds) plus the
	  number of distinct operands (constants/variables referenced).
	* ``N`` (length) is the total number of operator and operand occurrences.

	This captures how diverse the instruction "types" used by a function are, as distinct from
	how many instructions there are in total.
	"""
	mlil = func.mlil
	if mlil is None:
		return 0.0

	operators: Counter = Counter()
	operands: Counter = Counter()
	for stmt in mlil.instructions:
		for instr in _walk_mlil(stmt):
			operators[instr.operation] += 1
			for _, operand, _ in instr.detailed_operands:
				values = operand if isinstance(operand, list) else [operand]
				for value in values:
					if value is None or isinstance(value, mediumlevelil.MediumLevelILInstruction):
						# Sub-expressions are counted as their own operator nodes above, not as operands.
						continue
					operands[repr(value)] += 1

	distinct_operators = len(operators)
	distinct_operands = len(operands)
	total_operators = sum(operators.values())
	total_operands = sum(operands.values())

	vocabulary = distinct_operators + distinct_operands
	length = total_operators + total_operands
	if vocabulary <= 1:
		return 0.0
	return length * math.log2(vocabulary)


def _max_nesting_depth(instr: 'highlevelil.HighLevelILInstruction', current_depth: int) -> int:
	next_depth = current_depth + 1 if instr.operation in _HLIL_NESTING_OPERATIONS else current_depth
	deepest = next_depth
	for _, operand, _ in instr.detailed_operands:
		items = operand if isinstance(operand, list) else [operand]
		for item in items:
			if isinstance(item, highlevelil.HighLevelILInstruction):
				deepest = max(deepest, _max_nesting_depth(item, next_depth))
	return deepest


def nesting_depth_complexity(func: 'function.Function') -> float:
	"""
	Maximum nesting depth of structured control flow (if/while/for/do-while/switch) in the HLIL AST.

	Two functions with identical cyclomatic complexity can differ a lot in how deeply their
	branches are nested; deeply nested code is harder to hold in your head even with the same
	number of paths.
	"""
	hlil = func.hlil
	if hlil is None or hlil.root is None:
		return 0.0
	return float(_max_nesting_depth(hlil.root, 0))


def cognitive_complexity(func: 'function.Function') -> float:
	"""
	Simplified SonarSource-style cognitive complexity over the HLIL AST.

	Every control-flow-breaking construct (if/while/for/do-while/switch) costs 1 point, plus 1
	additional point for every level of nesting it sits inside. Unlike cyclomatic complexity,
	this penalizes deeply nested logic more than the same number of branches laid out flat.
	"""
	hlil = func.hlil
	if hlil is None or hlil.root is None:
		return 0.0

	score = 0.0

	def visit(instr: 'highlevelil.HighLevelILInstruction', nesting: int) -> None:
		nonlocal score
		next_nesting = nesting
		if instr.operation in _HLIL_NESTING_OPERATIONS:
			score += 1 + nesting
			next_nesting = nesting + 1
		for _, operand, _ in instr.detailed_operands:
			items = operand if isinstance(operand, list) else [operand]
			for item in items:
				if isinstance(item, highlevelil.HighLevelILInstruction):
					visit(item, next_nesting)

	visit(hlil.root, 0)
	return score


class ComplexityCache:
	"""
	Memoizes the per-function work that :py:func:`composite_complexity`, :py:func:`fan_out_complexity`,
	and :py:func:`transitive_complexity` do, keyed by platform, architecture, and start address.

	A single function is very often reachable from many different callers (a shared helper, a
	logging routine, an allocator wrapper). Without this, scoring every function in a binary via
	:py:func:`transitive_complexity` would redo that shared helper's full analysis - CFG walk,
	MLIL/HLIL traversal, its own call classification - once per caller that reaches it, instead of
	once total. Pass the same cache instance across every function in a scan (see
	:py:func:`compute_all_complexity`) to get that reuse; the default of not passing one at all
	keeps a single one-off call to any of these functions correct (just not sped up by anything
	computed elsewhere).
	"""

	def __init__(self, functions: Optional[Iterable['function.Function']] = None):
		self.composite: Dict[FunctionKey, float] = {}
		self.call_sites: Dict[FunctionKey, '_CallSites'] = {}
		self.functions: Dict[FunctionKey, 'function.Function'] = {}
		self.functions_by_address: Dict[int, List['function.Function']] = {}
		if functions is not None:
			for func in functions:
				self.remember_function(func)

	def remember_function(self, func: 'function.Function') -> None:
		key = function_key(func)
		self.functions[key] = func
		bucket = self.functions_by_address.setdefault(func.start, [])
		if all(function_key(existing) != key for existing in bucket):
			bucket.append(func)

	def forget_function(self, key: FunctionKey) -> None:
		func = self.functions.pop(key, None)
		self.composite.pop(key, None)
		self.call_sites.pop(key, None)
		if func is None:
			return
		bucket = self.functions_by_address.get(func.start)
		if bucket is None:
			return
		self.functions_by_address[func.start] = [candidate for candidate in bucket if function_key(candidate) != key]
		if not self.functions_by_address[func.start]:
			del self.functions_by_address[func.start]

	def resolve_function(self, caller: 'function.Function', addr: int) -> Optional['function.Function']:
		"""Resolve an address without collapsing same-address functions from different platforms."""
		candidates = self.functions_by_address.get(addr)
		if candidates is None:
			candidates = list(caller.view.get_functions_at(addr))
			for candidate in candidates:
				self.remember_function(candidate)
		if not candidates:
			return None
		caller_platform = getattr(caller, 'platform', None)
		caller_arch = getattr(caller, 'arch', None)
		for candidate in candidates:
			if getattr(candidate, 'platform', None) == caller_platform:
				return candidate
		for candidate in candidates:
			if getattr(candidate, 'arch', None) == caller_arch:
				return candidate
		return candidates[0]


def composite_from_metrics(values: Dict[str, float], weights: Dict[str, float] = None) -> float:
	"""Combine already-computed component metrics without walking the function's IL again."""
	effective_weights = dict(DEFAULT_COMPOSITE_WEIGHTS)
	if weights:
		effective_weights.update(weights)
	return sum(effective_weights[name] * values[name] for name in DEFAULT_COMPOSITE_WEIGHTS)


def composite_complexity(
	func: 'function.Function', weights: Dict[str, float] = None, cache: ComplexityCache = None
) -> float:
	"""
	Weighted blend of every other metric into a single score.

	:param weights: Optional override for :py:data:`DEFAULT_COMPOSITE_WEIGHTS`. Any metric name
	                left out keeps its default weight.
	:param cache: See :py:class:`ComplexityCache`. Only used when `weights` is left at its default,
	              since a cached value can't reflect caller-supplied weights.
	"""
	key = function_key(func)
	if weights is None and cache is not None and key in cache.composite:
		return cache.composite[key]

	result = composite_from_metrics({
		'cyclomatic': cyclomatic_complexity(func),
		'instruction_count': instruction_count_complexity(func),
		'branch_density': branch_density_complexity(func),
		'halstead': halstead_volume_complexity(func),
		'nesting_depth': nesting_depth_complexity(func),
		'cognitive': cognitive_complexity(func),
	}, weights)

	if weights is None and cache is not None:
		cache.composite[key] = result
	return result


class _CallSites(NamedTuple):
	# Stable key of each call target that resolves to a function defined in this binary (duplicates
	# included, e.g. the same helper called twice appears twice). Deliberately plain tuples rather
	# than Function objects: this is what gets cached in ComplexityCache, and a
	# Function wrapper keeps its underlying core analysis data alive for as long as anything holds
	# a reference to it. A scan over every function in a large binary would otherwise end up
	# pinning most of the binary's functions in memory for the scan's whole duration, just because
	# each one was somebody's callee at some point. Including platform/architecture in the key also
	# prevents same-address functions in multi-platform views from being silently conflated.
	internal_callee_keys: List[FunctionKey]
	external_count: int
	indirect_count: int


def _classify_call_sites(func: 'function.Function', cache: ComplexityCache = None) -> _CallSites:
	"""
	Walks every call-like MLIL statement in `func` and sorts it into one of three buckets:

	* resolves to a function defined in this binary -> that function's stable key is appended to
	  `internal_callee_keys`
	* resolves to an address, but that address is an import/thunk/library stub, or analysis
	  couldn't identify a function there -> `external_count`
	* the target isn't a static constant at all (computed/register call, e.g. through a function
	  pointer or vtable) -> `indirect_count`, since we can't know what runs there without deeper
	  (and possibly incomplete) analysis
	"""
	key = function_key(func)
	if cache is not None and key in cache.call_sites:
		return cache.call_sites[key]

	mlil = func.mlil
	if mlil is None:
		result = _CallSites([], 0, 0)
		if cache is not None:
			cache.call_sites[key] = result
		return result

	internal_callee_keys: List[FunctionKey] = []
	external_count = 0
	indirect_count = 0

	for stmt in mlil.instructions:
		if stmt.operation in _MLIL_SYSCALL_OPERATIONS:
			external_count += 1
			continue
		if stmt.operation not in _MLIL_CALL_OPERATIONS:
			continue

		dest = stmt.dest
		if not isinstance(dest, mediumlevelil.MediumLevelILConstBase):
			indirect_count += 1
			continue

		target = (
			cache.resolve_function(func, dest.constant)
			if cache is not None else func.view.get_function_at(dest.constant)
		)
		if target is None:
			external_count += 1
			continue

		symbol = func.view.get_symbol_at(dest.constant)
		if symbol is not None and symbol.type in _EXTERNAL_SYMBOL_TYPES:
			external_count += 1
		else:
			internal_callee_keys.append(function_key(target))

	result = _CallSites(internal_callee_keys, external_count, indirect_count)
	if cache is not None:
		cache.call_sites[key] = result
	return result


def compute_metric_bundle(
	func: 'function.Function', cache: ComplexityCache = None
) -> Dict[str, float]:
	"""Compute every non-transitive metric with one MLIL pass and one HLIL pass.

	This is the fast path for table sweeps. The individual metric functions remain the public,
	one-metric-at-a-time API, while callers that need a complete row avoid traversing the same IL
	three or four times and avoid recomputing every composite component.
	"""
	if cache is None:
		cache = ComplexityCache([func])
	else:
		cache.remember_function(func)
	key = function_key(func)

	blocks = list(func.basic_blocks)
	cyclomatic = 0.0 if not blocks else float(sum(len(bb.outgoing_edges) for bb in blocks) - len(blocks) + 2)
	token_count = float(sum(len(tokens) for tokens, _length in func.instructions))

	mlil = func.mlil
	instruction_count = 0.0
	branch_density = 0.0
	halstead = 0.0
	internal_callee_keys: List[FunctionKey] = []
	external_count = 0
	indirect_count = 0
	if mlil is None:
		instruction_count = float(sum(1 for _ in func.instructions))
	else:
		statements = list(mlil.instructions)
		branches = 0
		operators: Counter = Counter()
		operands: Counter = Counter()
		for stmt in statements:
			if stmt.operation in _MLIL_BRANCH_OPERATIONS:
				branches += 1
			if stmt.operation in _MLIL_SYSCALL_OPERATIONS:
				external_count += 1
			elif stmt.operation in _MLIL_CALL_OPERATIONS:
				dest = stmt.dest
				if not isinstance(dest, mediumlevelil.MediumLevelILConstBase):
					indirect_count += 1
				else:
					target = cache.resolve_function(func, dest.constant)
					if target is None:
						external_count += 1
					else:
						symbol = func.view.get_symbol_at(dest.constant)
						if symbol is not None and symbol.type in _EXTERNAL_SYMBOL_TYPES:
							external_count += 1
						else:
							internal_callee_keys.append(function_key(target))
			for instr in _walk_mlil(stmt):
				instruction_count += 1.0
				operators[instr.operation] += 1
				for _, operand, _ in instr.detailed_operands:
					for value in operand if isinstance(operand, list) else [operand]:
						if value is None or isinstance(value, mediumlevelil.MediumLevelILInstruction):
							continue
						operands[repr(value)] += 1
		branch_density = branches / len(statements) if statements else 0.0
		vocabulary = len(operators) + len(operands)
		length = sum(operators.values()) + sum(operands.values())
		halstead = 0.0 if vocabulary <= 1 else length * math.log2(vocabulary)

	hlil = func.hlil
	nesting_depth = 0.0
	cognitive = 0.0
	if hlil is not None and hlil.root is not None:
		def visit(instr: 'highlevelil.HighLevelILInstruction', nesting: int) -> None:
			nonlocal nesting_depth, cognitive
			next_nesting = nesting
			if instr.operation in _HLIL_NESTING_OPERATIONS:
				next_nesting = nesting + 1
				nesting_depth = max(nesting_depth, float(next_nesting))
				cognitive += 1 + nesting
			for _, operand, _ in instr.detailed_operands:
				for item in operand if isinstance(operand, list) else [operand]:
					if isinstance(item, highlevelil.HighLevelILInstruction):
						visit(item, next_nesting)

		visit(hlil.root, 0)

	calls = _CallSites(internal_callee_keys, external_count, indirect_count)
	cache.call_sites[key] = calls
	distinct_targets = len(set(internal_callee_keys))
	values = {
		'cyclomatic': cyclomatic,
		'instruction_count': instruction_count,
		'token_count': token_count,
		'branch_density': branch_density,
		'halstead': halstead,
		'nesting_depth': nesting_depth,
		'cognitive': cognitive,
		'fan_out': float(
			distinct_targets + 0.25 * (len(internal_callee_keys) - distinct_targets) +
			1.5 * external_count + 2.5 * indirect_count
		),
		'code_references': code_reference_count_complexity(func),
	}
	values['composite'] = composite_from_metrics(values)
	cache.composite[key] = values['composite']
	return values


def fan_out_complexity(func: 'function.Function', cache: ComplexityCache = None) -> float:
	"""
	How much, and how riskily, `func` fans out into other code - captures the "`main()` is just a
	dispatcher" shape that every intraprocedural metric misses.

	Distinct callees count in full; repeated calls to a callee already counted (e.g. in a loop)
	count for less, since re-calling something you've already accounted for isn't new complexity.
	Calls to external/library code count more, since you can't inspect what they do. Indirect
	calls (through a computed target - function pointers, vtables, callbacks) count the most,
	since you can't even statically know what runs.

	:param cache: See :py:class:`ComplexityCache`.
	"""
	calls = _classify_call_sites(func, cache)
	distinct_targets = set(calls.internal_callee_keys)
	repeat_calls = len(calls.internal_callee_keys) - len(distinct_targets)
	return (
		len(distinct_targets) +
		0.25 * repeat_calls +
		1.5 * calls.external_count +
		2.5 * calls.indirect_count
	)


def code_reference_count_complexity(func: 'function.Function') -> int:
	"""
	How many places in this binary's code reference `func` - calls, tail calls, or any other code
	cross-reference to its start address (see :py:func:`~binaryninja.binaryview.BinaryView.get_code_refs`).
	The complement of `fan_out`: `fan_out` measures how much `func` reaches into other code, this
	measures how much other code reaches into `func`.

	Not "complexity" in the same sense as the other metrics here - a heavily-referenced function
	isn't necessarily hard to read on its own - but it is a direct measure of blast radius: a change
	to a function referenced from hundreds of call sites has far more to potentially break than one
	referenced from a single caller, which is exactly the kind of risk this report is for surfacing.

	This is a plain reverse-reference lookup against Binary Ninja's own cross-reference index, not a
	walk that touches any other function's analysis - unlike `transitive`, computing this can't itself
	trigger more analysis elsewhere, so it's always safe to include in an incremental recompute.
	"""
	return sum(1 for _ in func.view.get_code_refs(func.start))


def transitive_complexity(
	func: 'function.Function',
	max_depth: int = 2,
	decay: float = 0.5,
	cache: ComplexityCache = None,
	is_cancelled: Optional[Callable[[], bool]] = None,
) -> float:
	"""
	`func`'s own :py:func:`composite_complexity` plus the (decayed) composite complexity of
	everything it calls, recursively, up to `max_depth` hops.

	This is the metric that actually answers "this function looks simple, but how much do I have
	to read to understand what it does": a `main()` with a low `composite` score but a high
	`transitive` score is exactly a thin dispatcher over a lot of real work.

	Each function is only ever counted once per call (tracked by stable function key), which both
	breaks recursion/cycles safely and avoids over-counting a shared helper reached through
	multiple paths - once you've read it, you don't need to read it again for a sibling call. Note
	that this `visited` guard is intentionally local to a single top-level call (it exists to stop
	double-counting *within* func's own subtree, e.g. two of its callees sharing a common
	descendant) - it must not be shared across different top-level functions in a scan, or a
	function reached by an earlier scanned function would wrongly read as contributing 0 to a
	later, unrelated one. Sharing work *safely* across top-level calls in a scan is what `cache`
	is for: see :py:class:`ComplexityCache`.

	:param max_depth: How many call hops to follow. Kept shallow by default since this walks the
	                   call graph and cost grows with fan-out at each level.
	:param decay: Weight applied per hop, so distant callees contribute less than the function's
	              own body.
	:param cache: See :py:class:`ComplexityCache`. Pass the same instance across every function in
	              a whole-binary scan so a shared callee's own complexity is computed once, not
	              once per caller that reaches it.
	:param is_cancelled: Optional callable polled throughout the recursive walk (not just once per
	                      top-level call) so a caller running this on a background task can bail out
	                      of a single expensive call promptly instead of waiting for the whole
	                      walk - which, for a function embedded in a large, tightly-interconnected
	                      cluster (e.g. a parser's mutually-calling helpers), can otherwise take a
	                      very long time to unwind on its own.
	"""
	visited: Set[FunctionKey] = set()
	view = func.view

	def walk(f: 'function.Function', depth: int) -> float:
		if is_cancelled is not None and is_cancelled():
			return 0.0
		key = function_key(f)
		if key in visited:
			return 0.0
		visited.add(key)

		total = composite_complexity(f, cache=cache)
		if depth <= 0:
			return total

		callee_keys = set(_classify_call_sites(f, cache).internal_callee_keys)
		for callee_key in callee_keys:
			if is_cancelled is not None and is_cancelled():
				break
			if callee_key in visited:
				continue
			callee = cache.functions.get(callee_key) if cache is not None else None
			if callee is None:
				candidates = list(view.get_functions_at(callee_key[2]))
				callee = next((candidate for candidate in candidates if function_key(candidate) == callee_key), None)
			if callee is not None:
				total += decay * walk(callee, depth - 1)
		return total

	return walk(func, max_depth)


# Single dispatch table backing the one public API function, `get_code_complexity`.
_METRICS: Dict[str, Callable[['function.Function'], float]] = {
	'cyclomatic': cyclomatic_complexity,
	'instruction_count': instruction_count_complexity,
	'token_count': token_count_complexity,
	'branch_density': branch_density_complexity,
	'halstead': halstead_volume_complexity,
	'nesting_depth': nesting_depth_complexity,
	'cognitive': cognitive_complexity,
	'composite': composite_complexity,
	'fan_out': fan_out_complexity,
	'code_references': code_reference_count_complexity,
	'transitive': transitive_complexity,
}


def list_complexity_metrics() -> List[str]:
	"""Names accepted by :py:func:`get_code_complexity`."""
	return list(_METRICS.keys())


# Metrics whose computation can reuse a ComplexityCache across multiple functions.
_CACHEABLE_METRICS = {'composite', 'fan_out', 'transitive'}


def get_code_complexity(
	func: 'function.Function',
	metric: str = 'composite',
	cache: ComplexityCache = None,
	is_cancelled: Optional[Callable[[], bool]] = None,
) -> Union[int, float]:
	"""
	Compute a code complexity score for `func` using the named metric.

	:param func: Function to analyze.
	:param metric: One of :py:func:`list_complexity_metrics` (default ``"composite"``).
	:param cache: See :py:class:`ComplexityCache`. Only used by the interprocedural metrics
	              (``composite``, ``fan_out``, ``transitive``); ignored otherwise. Scanning many
	              functions should generally use :py:func:`compute_all_complexity` instead, which
	              sets this up for you.
	:param is_cancelled: Optional callable polled during ``transitive``'s recursive call-graph walk
	                      (the one metric whose single computation can itself take a long time on a
	                      large, tightly-interconnected function); ignored by every other metric.
	:raises ValueError: If `metric` is not a recognized metric name.
	"""
	try:
		metric_fn = _METRICS[metric]
	except KeyError:
		raise ValueError(f"Unknown complexity metric {metric!r}; valid options are {list_complexity_metrics()}")
	if metric == 'code_references':
		return int(metric_fn(func))
	if metric == 'transitive':
		return float(metric_fn(func, cache=cache, is_cancelled=is_cancelled))
	if metric in _CACHEABLE_METRICS:
		return float(metric_fn(func, cache=cache))
	return float(metric_fn(func))


def compute_all_complexity(
	functions: 'Iterator[function.Function]', metrics: List[str] = None
) -> List[Tuple['function.Function', Dict[str, float]]]:
	"""
	Compute every metric in `metrics` for every function in `functions`, sharing one
	:py:class:`ComplexityCache` across the whole batch.

	This is the efficient way to score every function in a binary: a shared helper reachable from
	many different functions (a logging routine, an allocator wrapper, ...) has its own complexity
	computed once here, no matter how many of the scanned functions call it - calling
	:py:func:`get_code_complexity` separately per function in a loop would instead redo that
	shared helper's analysis once per caller that reaches it within ``transitive``'s hop limit,
	which is the dominant cost on a large binary with any commonly-used utility functions.

	:param functions: Functions to score, e.g. ``bv.functions``.
	:param metrics: Which metrics to compute for each function (default: all of them).
	:return: A list of ``(function, {metric_name: value})``, in the same order as `functions`.
	"""
	if metrics is None:
		metrics = list_complexity_metrics()
	functions = list(functions)
	cache = ComplexityCache(functions)
	results = []
	first_pass_metrics = [metric for metric in metrics if metric != 'transitive']
	for func in functions:
		try:
			if (set(_METRICS) - {'transitive'}).issubset(first_pass_metrics):
				bundle = compute_metric_bundle(func, cache=cache)
				values = {metric: bundle[metric] for metric in first_pass_metrics}
			else:
				values = {}
				for metric in first_pass_metrics:
					metric_fn = _METRICS[metric]
					if metric == 'composite' and all(name in values for name in DEFAULT_COMPOSITE_WEIGHTS):
						values[metric] = float(composite_from_metrics(values))
						cache.composite[function_key(func)] = values[metric]
					elif metric == 'code_references':
						values[metric] = int(metric_fn(func))
					else:
						values[metric] = (
							float(metric_fn(func, cache=cache)) if metric in _CACHEABLE_METRICS else float(metric_fn(func))
						)
		except Exception as e:
			log_warn(f'compute_all_complexity: skipping {func.name} at {func.start:#x}: {e}')
			continue
		results.append((func, values))
	if 'transitive' in metrics:
		for func, values in results:
			try:
				values['transitive'] = float(transitive_complexity(func, cache=cache))
			except Exception as e:
				log_warn(f'compute_all_complexity: skipping transitive for {func.name} at {func.start:#x}: {e}')
				values['transitive'] = 0.0
	return results
