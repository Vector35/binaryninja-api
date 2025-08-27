import ctypes
import dataclasses
import uuid
from typing import List, Optional, Union

import binaryninja
from binaryninja import BinaryView, Function, BasicBlock, Architecture, Platform, Type, Symbol, LowLevelILInstruction, LowLevelILFunction
from binaryninja._binaryninjacore import BNFreeString, BNAllocString, BNType

from . import _warpcore as warpcore
from .warp_enums import WARPContainerSearchItemKind


class WarpUUID:
    def __init__(self, _uuid: Union[warpcore.BNWARPUUID, str, uuid.UUID]):
        if isinstance(_uuid, str):
            _uuid = uuid.UUID(_uuid)
        if isinstance(_uuid, uuid.UUID):
            uuid_bytes = _uuid.bytes
            _uuid = warpcore.BNWARPUUID()
            _uuid.uuid = (ctypes.c_ubyte * 16).from_buffer_copy(uuid_bytes)
        elif isinstance(_uuid, warpcore.BNWARPUUID):
            # We must create a copy!
            new_uuid = warpcore.BNWARPUUID()
            new_uuid.uuid = (ctypes.c_ubyte * 16).from_buffer_copy(_uuid.uuid)
            _uuid = new_uuid
        self._uuid = _uuid

    def to_string(self) -> str:
        return warpcore.BNWARPUUIDGetString(self._uuid)

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return f"<WarpUUID '{str(self)}'>"

    def __hash__(self):
        # Hash based on the UUID bytes
        return hash(bytes(self._uuid.uuid))

    def __eq__(self, other):
        if not isinstance(other, WarpUUID):
            return False
        return warpcore.BNWARPUUIDEqual(self._uuid, other._uuid)

    @property
    def uuid(self):
        return self._uuid


class Source(WarpUUID):
    def __repr__(self):
        return f"<Source '{str(self)}'>"


class BasicBlockGUID(WarpUUID):
    def __repr__(self):
        return f"<BasicBlockGUID '{str(self)}'>"


class FunctionGUID(WarpUUID):
    def __repr__(self):
        return f"<FunctionGUID '{str(self)}'>"


class ConstraintGUID(WarpUUID):
    def __repr__(self):
        return f"<ConstraintGUID '{str(self)}'>"


class TypeGUID(WarpUUID):
    def __repr__(self):
        return f"<TypeGUID '{str(self)}'>"


@dataclasses.dataclass
class WarpFunctionComment:
    text: str
    offset: int

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<WarpFunctionComment '{self.text}': {self.offset:#x}>"

    @staticmethod
    def from_api(comment: warpcore.BNWARPFunctionComment) -> 'WarpFunctionComment':
        return WarpFunctionComment(
            text=comment.text,
            offset=comment.offset
        )

@dataclasses.dataclass
class WarpConstraint:
    guid: ConstraintGUID
    offset: Optional[int]

    def __str__(self):
        return repr(self)

    def __repr__(self):
        if self.offset is None:
            return f"<WarpConstraint '{self.guid}'>"
        return f"<WarpConstraint '{self.guid}': {self.offset:#x}>"

    @staticmethod
    def from_api(constraint: warpcore.BNWARPConstraint) -> 'WarpConstraint':
        if constraint.offset == -1:
            return WarpConstraint(guid=ConstraintGUID(constraint.guid), offset=None)
        return WarpConstraint(guid=ConstraintGUID(constraint.guid), offset=constraint.offset)

class WarpTarget:
    def __init__(self, handle: Union[warpcore.BNWARPTarget, Platform]):
        if isinstance(handle, Platform):
            self.handle = warpcore.BNWARPGetTarget(handle.handle)
        else:
            self.handle = handle

    def __del__(self):
        if self.handle is not None:
            warpcore.BNWARPFreeTargetReference(self.handle)

    @staticmethod
    def from_platform(platform: Platform) -> Optional['WarpTarget']:
        handle = warpcore.BNWARPGetTarget(platform.handle)
        if not handle:
            return None
        return WarpTarget(handle)


class WarpFunction:
    def __init__(self, handle: Union[warpcore.BNWARPFunction, Function]):
        if isinstance(handle, Function):
            self.handle = warpcore.BNWARPGetFunction(handle.handle)
        else:
            self.handle = handle
    def __del__(self):
        if self.handle is not None:
            warpcore.BNWARPFreeFunctionReference(self.handle)

    def __repr__(self):
        return f"<WarpFunction '{self.name}': '{self.guid}'>"

    @property
    def guid(self) -> FunctionGUID:
        return FunctionGUID(warpcore.BNWARPFunctionGetGUID(self.handle))

    @property
    def name(self) -> str:
        return warpcore.BNWARPFunctionGetSymbolName(self.handle)

    def get_symbol(self, function: Function) -> Symbol:
        symbol_handle = warpcore.BNWARPFunctionGetSymbol(self.handle, function.handle)
        return Symbol(symbol_handle)

    def get_type(self, function: Function) -> Optional[Type]:
        type_handle = warpcore.BNWARPFunctionGetType(self.handle, function.handle)
        if not type_handle:
            return None
        return Type(type_handle)

    @property
    def constraints(self) -> List[WarpConstraint]:
        count = ctypes.c_size_t()
        constraints = warpcore.BNWARPFunctionGetConstraints(self.handle, count)
        if not constraints:
            return []
        result = []
        for i in range(count.value):
            result.append(WarpConstraint.from_api(constraints[i]))
        warpcore.BNWARPFreeConstraintList(constraints, count.value)
        return result

    @property
    def comments(self) -> List[WarpFunctionComment]:
        count = ctypes.c_size_t()
        comments = warpcore.BNWARPFunctionGetComments(self.handle, count)
        if not comments:
            return []
        result = []
        for i in range(count.value):
            result.append(WarpFunctionComment.from_api(comments[i]))
        warpcore.BNWARPFreeFunctionCommentList(comments, count.value)
        return result

    @staticmethod
    def get_matched(function: Function) -> Optional['WarpFunction']:
        handle = warpcore.BNWARPGetMatchedFunction(function.handle)
        if not handle:
            return None
        return WarpFunction(handle)

    def apply(self, function: Function):
        warpcore.BNWARPFunctionApply(self.handle, function.handle)


class WarpContainerSearchQuery:
    def __init__(self, query: str, offset: Optional[int] = None, limit: Optional[int] = None, source: Optional[Source] = None, source_tags: Optional[List[str]] = None):
        self.query = query
        self.source = source
        self.offset = offset
        self.limit = limit
        offset_ptr = None
        if offset is not None:
            self._c_offset = ctypes.c_size_t(offset)
            offset_ptr = ctypes.byref(self._c_offset)
        limit_ptr = None
        if limit is not None:
            self._c_limit = ctypes.c_size_t(limit)
            limit_ptr = ctypes.byref(self._c_limit)
        source_ptr = None
        if source is not None:
            self._c_source = source.uuid
            source_ptr = ctypes.byref(self._c_source)
        source_tags_len = 0
        source_tags_array_ptr = None
        if source_tags is not None:
            source_tags_ptr = (ctypes.c_char_p * len(source_tags))()
            source_tags_len = len(source_tags)
            for i in range(len(source_tags)):
                source_tags_ptr[i] = source_tags[i].encode('utf-8')
            source_tags_array_ptr = ctypes.cast(source_tags_ptr, ctypes.POINTER(ctypes.c_char_p))
        self.handle = warpcore.BNWARPNewContainerSearchQuery(query, offset_ptr, limit_ptr, source_ptr, source_tags_array_ptr, source_tags_len)

    def __del__(self):
        if self.handle is not None:
            warpcore.BNWARPFreeContainerSearchQueryReference(self.handle)

    def __repr__(self):
        # TODO: Display offset and limit in a pythonic way.
        if self.source is None:
            return f"<WarpContainerSearchQuery '{self.query}'>"
        return f"<WarpContainerSearchQuery '{self.query}': '{self.source}'>"


class WarpContainerSearchItem:
    def __init__(self, handle: warpcore.BNWARPContainerSearchItem):
        self.handle = handle

    def __del__(self):
        if self.handle is not None:
            warpcore.BNWARPFreeContainerSearchItemReference(self.handle)

    @property
    def kind(self) -> WARPContainerSearchItemKind:
        return WARPContainerSearchItemKind(warpcore.BNWARPContainerSearchItemGetKind(self.handle))

    @property
    def source(self) -> Source:
        return Source(warpcore.BNWARPContainerSearchItemGetSource(self.handle))

    @property
    def name(self) -> str:
        return warpcore.BNWARPContainerSearchItemGetName(self.handle)

    def get_type(self, arch: Architecture) -> Optional[Type]:
        ty = warpcore.BNWARPContainerSearchItemGetType(arch.handle, self.handle)
        if not ty:
            return None
        return Type(ty)

    @property
    def function(self) -> Optional[WarpFunction]:
        func = warpcore.BNWARPContainerSearchItemGetFunction(self.handle)
        if not func:
            return None
        return WarpFunction(func)

    def __repr__(self):
        return f"<WarpContainerSearchItem '{self.name}': '{self.source}'>"


class WarpContainerResponse:
    def __init__(self, items: List[WarpContainerSearchItem], offset: int, total: int):
        self.items = items
        self.offset = offset
        self.total = total

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def __repr__(self):
        return f"<WarpContainerResponse items={len(self.items)} offset={self.offset} total={self.total}>"

    @staticmethod
    def from_api(response: warpcore.BNWARPContainerSearchResponse) -> 'WarpContainerResponse':
        try:
            items = []
            for i in range(response.count):
                items.append(WarpContainerSearchItem(warpcore.BNWARPNewContainerSearchItemReference(response.items[i])))
            return WarpContainerResponse(items=items, offset=response.offset, total=response.total)
        finally:
            warpcore.BNWARPFreeContainerSearchResponse(response)


class _WarpContainerMetaclass(type):
    def __iter__(self):
        binaryninja._init_plugins()
        count = ctypes.c_ulonglong()
        containers = warpcore.BNWARPGetContainers(count)
        try:
            for i in range(0, count.value):
                yield WarpContainer(warpcore.BNWARPNewContainerReference(containers[i]))
        finally:
            warpcore.BNWARPFreeContainerList(containers, count.value)

    def __getitem__(self, value):
        binaryninja._init_plugins()
        count = ctypes.c_ulonglong()
        containers = warpcore.BNWARPGetContainers(count)
        try:
            for i in range(0, count.value):
                container = WarpContainer(warpcore.BNWARPNewContainerReference(containers[i]))
                if container.name == str(value):
                    return container
            raise KeyError(f"'{value}' is not a valid container name")
        finally:
            warpcore.BNWARPFreeContainerList(containers, count.value)


class WarpContainer(metaclass=_WarpContainerMetaclass):
    def __init__(self, handle: warpcore.BNWARPContainer):
        self.handle = handle

    def __del__(self):
        if self.handle is not None:
            warpcore.BNWARPFreeContainerReference(self.handle)

    def __repr__(self):
        return f"<WarpContainer '{self.name}'>"

    @staticmethod
    def all() -> List['WarpContainer']:
        count = ctypes.c_size_t()
        containers = warpcore.BNWARPGetContainers(count)
        if not containers:
            return []
        result = []
        for i in range(count.value):
            result.append(WarpContainer(warpcore.BNWARPNewContainerReference(containers[i])))
        warpcore.BNWARPFreeContainerList(containers, count.value)
        return result

    @property
    def name(self) -> str:
        return warpcore.BNWARPContainerGetName(self.handle)

    @property
    def sources(self) -> List[Source]:
        count = ctypes.c_size_t()
        sources = warpcore.BNWARPContainerGetSources(self.handle, count)
        if not sources:
            return []
        result = []
        for i in range(count.value):
            result.append(Source(sources[i]))
        warpcore.BNWARPFreeUUIDList(sources, count.value)
        return result

    def add_source(self, source_path: str) -> Optional[Source]:
        source = warpcore.BNWARPUUID()
        if not warpcore.BNWARPContainerAddSource(self.handle, source_path, source):
            return None
        return Source(source)

    def commit_source(self, source: Source) -> bool:
        return warpcore.BNWARPContainerCommitSource(self.handle, source.uuid)

    def is_source_uncommitted(self, source: Source) -> bool:
        return warpcore.BNWARPContainerIsSourceWritable(self.handle, source.uuid)

    def is_source_writable(self, source: Source) -> bool:
        return warpcore.BNWARPContainerIsSourceWritable(self.handle, source.uuid)

    def get_source_path(self, source: Source) -> Optional[str]:
        return warpcore.BNWARPContainerGetSourcePath(self.handle, source.uuid)

    def add_functions(self, target: WarpTarget, source: Source, functions: List[Function]) -> bool:
        count = len(functions)
        core_funcs = (ctypes.POINTER(warpcore.BNWARPFunction) * count)()
        for i in range(count):
            core_funcs[i] = functions[i].handle
        return warpcore.BNWARPContainerAddFunctions(self.handle, target.handle, source.uuid, core_funcs, count)

    def add_types(self, view: BinaryView, source: Source, types: List[Type]) -> bool:
        count = len(types)
        core_types = (ctypes.POINTER(BNType) * count)()
        for i in range(count):
            core_types[i] = types[i].handle
        return warpcore.BNWARPContainerAddTypes(view.handle, self.handle, source.uuid, core_types, count)

    def remove_functions(self, target: WarpTarget, source: Source, functions: List[Function]) -> bool:
        count = len(functions)
        core_funcs = (ctypes.POINTER(warpcore.BNWARPFunction) * count)()
        for i in range(count):
            core_funcs[i] = functions[i].handle
        return warpcore.BNWARPContainerRemoveFunctions(self.handle, target.handle, source.uuid, core_funcs, count)

    def remove_types(self, source: Source, guids: List[TypeGUID]) -> bool:
        count = len(guids)
        core_guids = (ctypes.POINTER(warpcore.BNWARPTypeGUID) * count)()
        for i in range(count):
            core_guids[i] = guids[i].uuid
        return warpcore.BNWARPContainerRemoveTypes(self.handle, source.uuid, core_guids, count)

    def fetch_functions(self, target: WarpTarget, guids: List[FunctionGUID], source_tags: Optional[List[str]] = None):
        count = len(guids)
        core_guids = (warpcore.BNWARPFunctionGUID * count)()
        for i in range(count):
            core_guids[i] = guids[i].uuid
        if source_tags is None:
            source_tags = []
        source_tags_ptr = (ctypes.c_char_p * len(source_tags))()
        source_tags_len = len(source_tags)
        for i in range(len(source_tags)):
            source_tags_ptr[i] = source_tags[i].encode('utf-8')
        source_tags_array_ptr = ctypes.cast(source_tags_ptr, ctypes.POINTER(ctypes.c_char_p))
        warpcore.BNWARPContainerFetchFunctions(self.handle, target.handle, source_tags_array_ptr, source_tags_len, core_guids, count)

    def get_sources_with_function_guid(self, target: WarpTarget, guid: FunctionGUID) -> List[Source]:
        count = ctypes.c_size_t()
        sources = warpcore.BNWARPContainerGetSourcesWithFunctionGUID(self.handle, target.handle, guid.uuid, count)
        if not sources:
            return []
        result = []
        for i in range(count.value):
            result.append(Source(sources[i]))
        warpcore.BNWARPFreeUUIDList(sources, count.value)
        return result

    def get_sources_with_type_guid(self, guid: TypeGUID) -> List[Source]:
        count = ctypes.c_size_t()
        sources = warpcore.BNWARPContainerGetSourcesWithTypeGUID(self.handle, guid.uuid, count)
        if not sources:
            return []
        result = []
        for i in range(count.value):
            result.append(Source(sources[i]))
        warpcore.BNWARPFreeUUIDList(sources, count.value)
        return result

    def get_functions_with_guid(self, target: WarpTarget, source: Source, guid: FunctionGUID) -> List[Function]:
        count = ctypes.c_size_t()
        funcs = warpcore.BNWARPContainerGetFunctionsWithGUID(self.handle, target.handle, source.uuid, guid.uuid, count)
        if not funcs:
            return []
        result = []
        for i in range(count.value):
            result.append(WarpFunction(warpcore.BNWARPNewFunctionReference(funcs[i])))
        warpcore.BNWARPFreeFunctionList(funcs, count.value)
        return result

    def get_type_with_guid(self, arch: Architecture, source: Source, guid: TypeGUID) -> Optional[Type]:
        ty = warpcore.BNWARPContainerGetTypeWithGUID(arch.handle, self.handle, source.uuid, guid.uuid)
        if not ty:
            return None
        return Type(ty)

    def get_type_guids_with_name(self, source: Source, name: str) -> List[TypeGUID]:
        count = ctypes.c_size_t()
        guids = warpcore.BNWARPContainerGetTypeGUIDsWithName(self.handle, source.uuid, name, count)
        if not guids:
            return []
        result = []
        for i in range(count.value):
            result.append(TypeGUID(guids[i]))
        warpcore.BNWARPFreeUUIDList(guids, count.value)
        return result

    def search(self, query: WarpContainerSearchQuery) -> Optional[WarpContainerResponse]:
        response = warpcore.BNWARPContainerSearch(self.handle, query.handle)
        if not response:
            return None
        return WarpContainerResponse.from_api(response.contents)


def run_matcher(view: BinaryView):
    warpcore.BNWARPRunMatcher(view.handle)

def is_instruction_variant(function: LowLevelILFunction, variant: LowLevelILInstruction) -> bool:
    return warpcore.BNWARPIsLiftedInstructionVariant(function.handle, variant.instr_index)

def is_instruction_blacklisted(function: LowLevelILFunction, variant: LowLevelILInstruction) -> bool:
    return warpcore.BNWARPIsLiftedInstructionBlacklisted(function.handle, variant.instr_index)

def is_instruction_computed_variant(function: LowLevelILFunction, variant: LowLevelILInstruction) -> bool:
    """
    Checks to see if the instruction is variant due to some computed value. **Must use LLIL.**
    """
    return warpcore.BNWARPIsLowLevelInstructionComputedVariant(function.handle, variant.instr_index)

def get_function_guid(function: Function) -> Optional[FunctionGUID]:
    guid = warpcore.BNWARPUUID()
    if not warpcore.BNWARPGetAnalysisFunctionGUID(function.handle, guid):
        return None
    return FunctionGUID(guid)


def get_basic_block_guid(basic_block: BasicBlock) -> Optional[BasicBlockGUID]:
    # TODO: I believe this won't work for HLIL: https://github.com/Vector35/binaryninja-api/issues/6998
    if basic_block.is_il:
        basic_block = basic_block.source_block
    guid = warpcore.BNWARPUUID()
    if not warpcore.BNWARPGetBasicBlockGUID(basic_block.handle, guid):
        return None
    return BasicBlockGUID(guid)

# TODO: Magic matched_function, possible_functions