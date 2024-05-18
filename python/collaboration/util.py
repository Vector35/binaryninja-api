import ctypes
from typing import Callable, Dict, List, Optional, Union

from .. import _binaryninjacore as core
from . import changeset, merge

ProgressFuncType = Callable[[int, int], bool]
NameChangesetFuncType = Callable[['changeset.Changeset'], bool]
ConflictHandlerFuncType = Callable[[Dict[str, 'merge.MergeConflict']], bool]
ConflictHandlerType = Union['merge.ConflictHandler', ConflictHandlerFuncType]


def _last_error() -> str:
	"""
	Get last error from the api

	:return: Last error string
	"""
	return "Operation failed"
	# TODO: keep track of last error in thread
	#return core.BNCollaborationGetLastError()


def nop(*args, **kwargs):
	"""
	Function that just returns True, used as default for callbacks

	:return: True
	"""
	return True


def wrap_progress(progress_func: ProgressFuncType):
	"""
	Wraps a progress function in a ctypes function for passing to the FFI

	:param progress_func: Python progress function
	:return: Wrapped ctypes function
	"""
	return ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
		lambda ctxt, cur, total: progress_func(cur, total))


def wrap_name_changeset(name_changeset_func: NameChangesetFuncType):
	"""
	Wraps a changeset naming function in a ctypes function for passing to the FFI

	:param name_changeset_func: Python changeset naming function
	:return: Wrapped ctypes function
	"""
	return ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, core.BNCollaborationChangesetHandle)(
		lambda ctxt, cs: name_changeset_func(changeset.Changeset(handle=cs)))


def wrap_conflict_handler(handler: Union[ConflictHandlerFuncType, merge.ConflictHandler]):
	"""
	Wraps a conflict handler function in a ConflictHandler object so you can be lazy and just use a lambda

	:param handler: Python conflict handler function
	:return: Wrapped ConflictHandler object
	"""

	if isinstance(handler, merge.ConflictHandler):
		handler_class = handler
	else:
		class LambdaConflictHandler(merge.ConflictHandler):
			def handle(self, conflicts: Dict[str, 'merge.MergeConflict']) -> bool:
				return handler(conflicts)

		handler_class = LambdaConflictHandler()

	return core.BNCollaborationAnalysisConflictHandler(handler_class._handle)


def split_progress(progress_func: Optional[ProgressFuncType], subpart: int,
				   subpart_weights: List[float]) -> ProgressFuncType:
	"""
	Split a single progress function into equally sized subparts.
	This function takes the original progress function and returns a new function whose signature
	is the same but whose output is shortened to correspond to the specified subparts.

	The length of a subpart is proportional to the sum of all the weights.
	E.g. If subpart = 1 and subpartWeights = { 0.25, 0.5, 0.25 }, this will return a function that calls
	progress_func and maps its progress to the range [0.25, 0.75]

	Internally this works by calling progress_func with total = 1000000 and doing math on the current value

	:param progress_func: Original progress function (usually updates a UI)
	:param subpart: Index of subpart whose function to return, from 0 to (subpartWeights.size() - 1)
	:param subpart_weights: Weights of subparts, described above
	:return: A function that will call progress_func() within a modified progress region
	"""
	if not progress_func:
		return lambda cur, total: True
	subpart_sum = sum(subpart_weights)
	if subpart_sum < 0.00001:
		return lambda cur, total: True

	# Normalize weights and keep a running count of weights for the start
	subpart_starts = []
	start = 0
	for i in range(len(subpart_weights)):
		subpart_starts.append(start)
		subpart_weights[i] /= subpart_sum
		start += subpart_weights[i]

	def inner(cur: int, total: int) -> bool:
		steps = 1000000
		subpart_size = steps * subpart_weights[subpart]
		subpart_progress = float(cur) / float(total) * subpart_size
		return progress_func(int(subpart_starts[subpart] * steps + subpart_progress), steps)

	return inner


class LazyT:
	"""
	Lazily loaded objects (but FFI)
	Pretend this class is templated, because the C++ version is
	"""
	def __init__(self, ctor: Optional[Callable[[], object]] = None, handle=None):
		"""
		Create a new LazyT that will be initialized with the result of the given function, when it is first needed.

		:param ctor: Function to construct object
		:param handle: FFI handle for internal use
		"""
		if handle is not None:
			self._handle = handle
		else:
			self.ctor = ctor
			self.value = None
			self._handle = core.BNCollaborationLazyTCreate(ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(
				lambda ctxt: self._perform_deref()), None)

	def _perform_deref(self) -> ctypes.c_void_p:
		if self.value is None:
			self.value = self.ctor()
		result = ctypes.cast(ctypes.py_object(self.value), ctypes.c_void_p)
		return result

	def get(self, expected_type=object):
		"""
		Access the lazily loaded object. Will construct it if this is the first usage.

		:param expected_type: Expected type of result, ctypes will try to cast to it
		:return: Result object
		"""
		result = core.BNCollaborationLazyTDereference(self._handle)
		if result is None:
			return None
		if type == object:
			result = ctypes.cast(result, ctypes.py_object)
			return result
		else:
			result = ctypes.cast(result, expected_type)
			return result
