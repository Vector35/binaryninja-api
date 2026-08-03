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

"""Binary similarity providers, session graphs, result resolution, and rendering."""

import ctypes
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any, List, Optional

import binaryninja

from . import _binaryninjacore as core
from . import binaryview, enums, filemetadata, flowgraph, function, lineardisassembly, settings
from .log import log_error_for_exception

SimilarityEntityId = int
#: Identifies a provider instance within a session.
SimilarityProviderId = int
#: Identifies a result within a similarity-session node.
SimilarityResultId = int
SimilarityEntityType = enums.SimilarityEntityType
SimilarityApplyStatus = enums.SimilarityApplyStatus
SimilarityViewType = enums.SimilarityViewType
SimilarityAnnotationType = enums.SimilarityAnnotationType


@dataclass(frozen=True)
class SimilaritySessionCompletionQuery:
    """Chooses which session completion data to read or update.

    A query cannot select both a provider and a resolver. Omitting all IDs selects the whole session.
    """

    node_id: Optional[int] = None
    provider_id: Optional[int] = None
    resolver_id: Optional[int] = None

    def __post_init__(self) -> None:
        if self.provider_id is not None and self.resolver_id is not None:
            raise ValueError("provider_id and resolver_id are mutually exclusive")

    @classmethod
    def for_session(cls) -> 'SimilaritySessionCompletionQuery':
        """Select the whole session."""
        return cls()

    @classmethod
    def for_node(cls, node_id: int) -> 'SimilaritySessionCompletionQuery':
        """Select a node."""
        return cls(node_id=node_id)

    @classmethod
    def for_provider(cls, provider_id: int) -> 'SimilaritySessionCompletionQuery':
        """Select a provider across the session."""
        return cls(provider_id=provider_id)

    @classmethod
    def for_resolver(cls, resolver_id: int) -> 'SimilaritySessionCompletionQuery':
        """Select a resolver across the session."""
        return cls(resolver_id=resolver_id)

    def with_provider(self, provider_id: int) -> 'SimilaritySessionCompletionQuery':
        """Select a provider within the current selection."""
        return replace(self, provider_id=provider_id, resolver_id=None)

    def with_resolver(self, resolver_id: int) -> 'SimilaritySessionCompletionQuery':
        """Select a resolver within the current selection."""
        return replace(self, provider_id=None, resolver_id=resolver_id)

    def _to_core_struct(self) -> core.BNSimilaritySessionCompletionQuery:
        raw_query = core.BNSimilaritySessionCompletionQuery()
        raw_query.hasNodeId = self.node_id is not None
        raw_query.nodeId = _to_core_session_node_id(self.node_id or 0)
        raw_query.hasProviderId = self.provider_id is not None
        raw_query.providerId = _to_core_provider_id(self.provider_id or 0)
        raw_query.hasResolverId = self.resolver_id is not None
        raw_query.resolverId = _to_core_resolver_id(self.resolver_id or 0)
        return raw_query


@dataclass(frozen=True)
class SimilarityEntityInfo:
    """The type, address, and display name of a session entity."""

    type: SimilarityEntityType
    address: int
    name: str = ""

    def __repr__(self):
        return f"<SimilarityEntityInfo type={self.type.name}, address={self.address:#x}, name={self.name!r}>"


@dataclass(frozen=True)
class SimilarityEntityRef:
    """Identifies an entity within a session node."""

    node_id: int
    entity_id: SimilarityEntityId

    def __repr__(self):
        return f"<SimilarityEntityRef node_id={self.node_id}, entity_id={self.entity_id}>"


@dataclass(frozen=True)
class SimilarityView:
    """A graph or linear view produced for a similarity result."""

    group: str
    type: SimilarityViewType
    graph: Optional['flowgraph.FlowGraph'] = None
    data: Optional['binaryview.BinaryView'] = None
    linear_view: Optional['lineardisassembly.LinearViewObject'] = None
    entity: Optional[SimilarityEntityRef] = None


@dataclass(frozen=True)
class SimilarityRangeAnnotation:
    """An added, removed, or changed address range ``[start, end)``."""

    start: int
    end: int
    type: SimilarityAnnotationType


class SimilarityRenderContext:
    """Holds views used to display a similarity result."""

    def __init__(self, handle=None):
        if handle is None:
            handle = core.BNCreateSimilarityRenderContext()
        self.handle = core.handle_of_type(handle, core.BNSimilarityRenderContext)

    def __del__(self):
        if core is not None and hasattr(self, 'handle'):
            core.BNFreeSimilarityRenderContext(self.handle)

    @property
    def preferred_view_type(self) -> 'function.FunctionViewType':
        """Function representation preferred by renderers writing to this context."""
        view_type = core.BNSimilarityRenderContextGetPreferredViewType(self.handle)
        if view_type == enums.FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
            return function.FunctionViewType(core.BNSimilarityRenderContextGetPreferredViewTypeName(self.handle))
        return function.FunctionViewType(view_type)

    @preferred_view_type.setter
    def preferred_view_type(self, view_type: 'function.FunctionViewTypeOrName') -> None:
        view_type = function.FunctionViewType(view_type)
        core.BNSimilarityRenderContextSetPreferredViewType(self.handle, view_type._to_core_struct())

    def add_flow_graph(
        self,
        group: str,
        graph: 'flowgraph.FlowGraph',
        entity: Optional[SimilarityEntityRef] = None,
    ) -> None:
        """Add a flow graph to ``group``."""
        if entity is None:
            core.BNSimilarityRenderContextAddFlowGraph(self.handle, group, graph.handle)
            return
        raw_entity = _to_core_entity_ref(entity)
        core.BNSimilarityRenderContextAddFlowGraphForEntity(self.handle, group, graph.handle, ctypes.byref(raw_entity))

    def add_linear_view(
        self,
        group: str,
        data: 'binaryview.BinaryView',
        linear_view: 'lineardisassembly.LinearViewObject',
        entity: Optional[SimilarityEntityRef] = None,
    ) -> None:
        """Add a linear view backed by ``data`` to ``group``."""
        if entity is None:
            core.BNSimilarityRenderContextAddLinearView(self.handle, group, data.handle, linear_view.handle)
            return
        raw_entity = _to_core_entity_ref(entity)
        core.BNSimilarityRenderContextAddLinearViewForEntity(
            self.handle, group, data.handle, linear_view.handle, ctypes.byref(raw_entity)
        )

    @property
    def views(self) -> List[SimilarityView]:
        """Views in the order they were added."""
        count = ctypes.c_ulonglong()
        views = core.BNGetSimilarityRenderContextViews(self.handle, count)
        result = []
        try:
            for i in range(count.value):
                view = views[i]
                view_type = SimilarityViewType(core.BNSimilarityViewGetType(view))
                graph_handle = core.BNSimilarityViewGetFlowGraph(view)
                data_handle = core.BNSimilarityViewGetLinearViewData(view)
                linear_handle = core.BNSimilarityViewGetLinearView(view)
                raw_entity = core.BNSimilarityEntityRef()
                entity = (
                    SimilarityEntityRef(raw_entity.nodeId.value, raw_entity.entityId.value)
                    if core.BNSimilarityViewGetEntity(view, ctypes.byref(raw_entity))
                    else None
                )
                result.append(
                    SimilarityView(
                        group=core.BNSimilarityViewGetGroup(view),
                        type=view_type,
                        graph=flowgraph.FlowGraph(graph_handle) if graph_handle else None,
                        data=binaryview.BinaryView(handle=data_handle) if data_handle else None,
                        linear_view=lineardisassembly.LinearViewObject(linear_handle) if linear_handle else None,
                        entity=entity,
                    )
                )
        finally:
            core.BNFreeSimilarityViewList(views, count.value)
        return result


class DiffRenderer:
    """Renders functions with similarity range annotations."""

    def __init__(self, handle=None):
        if handle is None:
            handle = core.BNCreateDiffRenderer()
        self.handle = core.handle_of_type(handle, core.BNDiffRenderer)

    def __del__(self):
        if core is not None and hasattr(self, 'handle'):
            core.BNFreeDiffRenderer(self.handle)

    def add_range_annotation(self, annotation: SimilarityRangeAnnotation) -> None:
        """Add an annotation to subsequent renders.

        .. note:: Empty ranges are ignored.
        """
        core.BNDiffRendererAddRangeAnnotation(
            self.handle,
            annotation.start,
            annotation.end,
            annotation.type,
        )

    def render(
        self,
        context: SimilarityRenderContext,
        source: 'function.Function',
        entity: Optional[SimilarityEntityRef] = None,
    ) -> None:
        """Render graph and linear views for ``source``."""
        if entity is None:
            core.BNDiffRendererRenderFunction(self.handle, context.handle, source.handle)
            return
        raw_entity = _to_core_entity_ref(entity)
        core.BNDiffRendererRenderFunctionForEntity(self.handle, context.handle, source.handle, ctypes.byref(raw_entity))

    def render_flow_graph(
        self,
        context: SimilarityRenderContext,
        group: str,
        graph: 'flowgraph.FlowGraph',
        entity: Optional[SimilarityEntityRef] = None,
    ) -> None:
        """Render an annotated flow graph into ``context``."""
        if entity is None:
            core.BNDiffRendererRenderFlowGraph(self.handle, context.handle, group, graph.handle)
            return
        raw_entity = _to_core_entity_ref(entity)
        core.BNDiffRendererRenderFlowGraphForEntity(
            self.handle, context.handle, group, graph.handle, ctypes.byref(raw_entity)
        )

    def render_linear_view(
        self,
        context: SimilarityRenderContext,
        group: str,
        data: 'binaryview.BinaryView',
        linear_view: 'lineardisassembly.LinearViewObject',
        entity: Optional[SimilarityEntityRef] = None,
    ) -> None:
        """Render an annotated linear view into ``context``."""
        if entity is None:
            core.BNDiffRendererRenderLinearView(self.handle, context.handle, group, data.handle, linear_view.handle)
            return
        raw_entity = _to_core_entity_ref(entity)
        core.BNDiffRendererRenderLinearViewForEntity(
            self.handle,
            context.handle,
            group,
            data.handle,
            linear_view.handle,
            ctypes.byref(raw_entity),
        )


def _to_core_entity_id(entity: SimilarityEntityId) -> core.BNSimilarityEntityId:
    return core.BNSimilarityEntityId(value=entity)


def _to_core_result_id(result: SimilarityResultId) -> core.BNSimilarityResultId:
    return core.BNSimilarityResultId(value=result)


def _to_core_session_node_id(node: int) -> core.BNSimilaritySessionNodeId:
    return core.BNSimilaritySessionNodeId(value=node)


def _to_core_entity_ref(entity: SimilarityEntityRef) -> core.BNSimilarityEntityRef:
    result = core.BNSimilarityEntityRef()
    result.nodeId = _to_core_session_node_id(entity.node_id)
    result.entityId = _to_core_entity_id(entity.entity_id)
    return result


def _to_core_provider_id(provider: int) -> core.BNSimilarityProviderId:
    return core.BNSimilarityProviderId(value=provider)


def _to_core_resolver_id(resolver: int) -> core.BNSimilaritySessionResolverId:
    return core.BNSimilaritySessionResolverId(value=resolver)


def _validate_score(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= 255:
        raise ValueError(f"{name} must be between 0 and 255")


@dataclass(frozen=True)
class SimilarityResult:
    """A match produced by a provider.

    Similarity and confidence range from 0 to 255, where 255 is strongest. Automatic metadata transfer requires
    ``target`` to identify an active function.
    """

    #: The provider which produced the match.
    provider_id: SimilarityProviderId
    #: The similarity of the two entities.
    similarity: int
    #: The provider's confidence in the match.
    confidence: int
    #: The matched entity, which may be used as the source for metadata transfer.
    target: SimilarityEntityRef

    def __post_init__(self) -> None:
        _validate_score("similarity", self.similarity)
        _validate_score("confidence", self.confidence)

    def __repr__(self):
        return (
            f"<SimilarityResult provider_id={self.provider_id}, similarity={self.similarity}, "
            f"confidence={self.confidence}, target={self.target!r}>"
        )

    @staticmethod
    def _from_core_struct(result: core.BNSimilarityResult) -> 'SimilarityResult':
        target = SimilarityEntityRef(result.target.nodeId.value, result.target.entityId.value)
        return SimilarityResult(result.providerId.value, result.similarity, result.confidence, target)

    @staticmethod
    def _to_core_struct(result: 'SimilarityResult') -> core.BNSimilarityResult:
        out = core.BNSimilarityResult()
        out.providerId = _to_core_provider_id(result.provider_id)
        out.similarity = result.similarity
        out.confidence = result.confidence
        out.target.nodeId = _to_core_session_node_id(result.target.node_id)
        out.target.entityId = _to_core_entity_id(result.target.entity_id)
        return out


class SimilarityProviderResults:
    """Writes results for one provider visit.

    Only use an instance during the provider callback that received it. A successful visit replaces earlier results
    for the same provider and node or edge. Results for unscheduled entities remain unchanged.
    """

    def __init__(self, handle):
        self._handle = core.handle_of_type(handle, core.BNSimilarityProviderResults)

    @property
    def handle(self):
        if self._handle is None:
            raise RuntimeError("similarity provider results are no longer valid")
        return self._handle

    def _invalidate(self) -> None:
        self._handle = None

    def add_result(
        self,
        source: SimilarityEntityRef,
        target: SimilarityEntityRef,
        similarity: int,
        confidence: int,
    ) -> SimilarityResultId:
        """Add a result for a scheduled entity and return its ID, or zero on failure.

        The ID is unique within the node. A later visit replaces the result and gives it a new ID.
        """
        _validate_score("similarity", similarity)
        _validate_score("confidence", confidence)
        raw_source = _to_core_entity_ref(source)
        raw_target = _to_core_entity_ref(target)
        return core.BNSimilarityProviderResultsAddResult(
            self.handle,
            ctypes.byref(raw_source),
            ctypes.byref(raw_target),
            similarity,
            confidence,
        ).value


class _SimilarityProviderTypeMetaClass(type):
    def __iter__(self):
        binaryninja._init_plugins()
        count = ctypes.c_ulonglong()
        types = core.BNGetSimilarityProviderTypeList(count)
        try:
            for i in range(0, count.value):
                yield CoreSimilarityProviderType(handle=types[i])
        finally:
            core.BNFreeSimilarityProviderTypeList(types)

    def __getitem__(cls, value):
        binaryninja._init_plugins()
        provider_type = core.BNGetSimilarityProviderTypeByName(str(value))
        if provider_type is None:
            raise KeyError(f"'{value}' is not a valid similarity provider type")
        return CoreSimilarityProviderType(handle=provider_type)

    def __contains__(cls: '_SimilarityProviderTypeMetaClass', name: object) -> bool:
        if not isinstance(name, str):
            return False
        try:
            cls[name]
            return True
        except KeyError:
            return False

    def get(
        cls: '_SimilarityProviderTypeMetaClass', name: str, default: Any = None
    ) -> Optional['SimilarityProviderType']:
        try:
            return cls[name]
        except KeyError:
            return default


class SimilarityProviderType(metaclass=_SimilarityProviderTypeMetaClass):
    """Creates similarity providers with the given settings."""

    _registered_types = []
    name = None
    description = None

    def __init__(self, handle=None):
        if handle is not None:
            self.handle = core.handle_of_type(handle, core.BNSimilarityProviderType)
            self.__dict__["name"] = core.BNSimilarityProviderTypeGetName(handle)
            self.__dict__["description"] = core.BNSimilarityProviderTypeGetDescription(handle)

    def register(self) -> None:
        """Register this provider type for the process lifetime."""
        if self.__class__.name is None:
            raise ValueError("Provider type name is missing")
        if self.__class__.description is None:
            raise ValueError("Provider type description is missing")
        self._cb = core.BNCustomSimilarityProviderType()
        self._cb.context = 0
        self._cb.create = self._cb.create.__class__(self._create)
        self._cb.getDefaultSettings = self._cb.getDefaultSettings.__class__(self._get_default_settings)
        self.handle = core.BNRegisterSimilarityProviderType(self.__class__.name, self.__class__.description, self._cb)
        self.__class__._registered_types.append(self)

    def _create(self, ctxt, settings_obj):
        try:
            settings_ref = settings.Settings(handle=core.BNNewSettingsReference(settings_obj))
            provider = self.create(settings_ref)
            if provider is None:
                raise ValueError(f"create returned None for similarity provider type '{self.name}'")
            handle = core.BNNewSimilarityProviderReference(provider.handle)
            handle_ptr = ctypes.cast(handle, ctypes.c_void_p)
            return handle_ptr.value
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProviderType._create")
            return None

    def _get_default_settings(self, ctxt):
        try:
            default_settings = self.get_default_settings()
            if default_settings is None:
                return None
            return ctypes.cast(core.BNNewSettingsReference(default_settings.handle), ctypes.c_void_p).value
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProviderType._get_default_settings")
            return None

    def create(self, settings_obj: 'settings.Settings') -> Optional['SimilarityProvider']:
        """Create a provider using ``settings_obj``, or return ``None``. Custom types must override this method."""
        raise NotImplementedError

    def get_default_settings(self) -> Optional['settings.Settings']:
        """Return settings used to configure new providers."""
        return None

    def __repr__(self):
        return f"<SimilarityProviderType name={self.name!r}>"


class CoreSimilarityProviderType(SimilarityProviderType):
    """A similarity provider type implemented by the core or a native plugin."""

    def create(self, settings_obj: 'settings.Settings') -> Optional['SimilarityProvider']:
        """Create a provider using ``settings_obj``, or return ``None``. Returns ``None`` outside Ultimate."""
        handle = core.BNSimilarityProviderTypeCreateProvider(self.handle, settings_obj.handle)
        if handle is None:
            return None
        return _wrap_owned_similarity_provider(handle)

    def get_default_settings(self) -> Optional['settings.Settings']:
        """Return settings used to configure new providers."""
        handle = core.BNSimilarityProviderTypeGetDefaultSettings(self.handle)
        if handle is None:
            return None
        return settings.Settings(handle=handle)


class SimilarityProvider:
    """Visits session nodes and produces similarity results.

    Implementations must be thread-safe. Callbacks may overlap across nodes and sessions.
    Visits made by a session keep the visited node and both edge endpoints active. Direct calls must provide active
    views.
    """

    _registered_instances = {}

    def __init__(self, provider_type: Optional['SimilarityProviderType'] = None, handle=None):
        self._freed = False
        is_custom = handle is None
        if is_custom:
            if provider_type is None:
                raise ValueError("custom similarity provider must have an associated provider type")
            self._cb = core.BNCustomSimilarityProvider()
            self._cb.context = 0
            self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
            self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
            self._cb.updateSettings = self._cb.updateSettings.__class__(self._update_settings)
            self._cb.visitNode = self._cb.visitNode.__class__(self._visit_node)
            self._cb.visitNodeEdge = self._cb.visitNodeEdge.__class__(self._visit_node_edge)
            self._cb.getName = self._cb.getName.__class__(self._get_name)
            self._cb.apply = self._cb.apply.__class__(self._apply)
            self._cb.render = self._cb.render.__class__(self._render)
            self._cb.free = self._cb.free.__class__(self._free)
            handle = core.BNCreateCustomSimilarityProvider(provider_type.handle, self._cb)
        self.handle = core.handle_of_type(handle, core.BNSimilarityProvider)

    def __del__(self):
        if core is not None and hasattr(self, 'handle') and not self._freed:
            core.BNFreeSimilarityProvider(self.handle)
            self._freed = True

    def _visit_node(self, ctxt, node, results, completion):
        results_obj = None
        try:
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            results_obj = SimilarityProviderResults(handle=results)
            completion_obj = SimilaritySessionCompletion(
                handle=core.BNNewSimilaritySessionCompletionReference(completion)
            )
            outcome = self.perform_visit_node(node_obj, results_obj, completion_obj)
            return True if outcome is None else bool(outcome)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._visit_node")
            return False
        finally:
            if results_obj is not None:
                results_obj._invalidate()

    def _update_settings(self, ctxt, settings_obj):
        try:
            settings_ref = settings.Settings(handle=core.BNNewSettingsReference(settings_obj))
            return bool(self.perform_update_settings(settings_ref))
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._update_settings")
            return False

    def _visit_node_edge(self, ctxt, from_node, to_node, results, completion):
        results_obj = None
        try:
            from_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(from_node))
            to_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(to_node))
            results_obj = SimilarityProviderResults(handle=results)
            completion_obj = SimilaritySessionCompletion(
                handle=core.BNNewSimilaritySessionCompletionReference(completion)
            )
            outcome = self.perform_visit_node_edge(from_obj, to_obj, results_obj, completion_obj)
            return True if outcome is None else bool(outcome)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._visit_node_edge")
            return False
        finally:
            if results_obj is not None:
                results_obj._invalidate()

    def _get_name(self, ctxt, node, entity, result):
        try:
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            name = self.perform_get_name(node_obj, entity.value, result.value)
            if name is None:
                return None
            return core.BNAllocString(str(name))
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._get_name")
            return None

    def _apply(self, ctxt, node, entity, result):
        try:
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            return self.perform_apply(node_obj, entity.value, result.value).value
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._apply")
            return SimilarityApplyStatus.SimilarityApplyFailed.value

    def _render(self, ctxt, node, entity, context, result):
        try:
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            context_obj = SimilarityRenderContext(handle=core.BNNewSimilarityRenderContextReference(context))
            self.perform_render(node_obj, entity.value, context_obj, result.value)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._render")

    def _free(self, ctxt):
        try:
            self._freed = True
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilarityProvider._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._free")

    def _external_ref_taken(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilarityProvider._registered_instances[handle_value] = self
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._external_ref_taken")

    def _external_ref_released(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilarityProvider._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilarityProvider._external_ref_released")

    def perform_visit_node(
        self,
        node: 'SimilaritySessionNode',
        results: SimilarityProviderResults,
        completion: 'SimilaritySessionCompletion',
    ) -> Optional[bool]:
        """Visit a node and write results for it, returning ``False`` to discard the visit.

        Process ``node.scheduled_entities``. Omitted results are removed for those entities only.
        """
        return True

    def perform_update_settings(self, settings_obj: 'settings.Settings') -> bool:
        """Replace this provider's settings only if they are valid.

        Return ``False`` without changing the current settings when the new settings are invalid or updates are not
        supported. Use
        :meth:`SimilaritySession.update_provider_settings` so affected entities are scheduled again.
        """
        return False

    def perform_visit_node_edge(
        self,
        from_node: 'SimilaritySessionNode',
        to_node: 'SimilaritySessionNode',
        results: SimilarityProviderResults,
        completion: 'SimilaritySessionCompletion',
    ) -> Optional[bool]:
        """Visit an edge and write results for it, returning ``False`` to discard the visit."""
        return True

    def perform_get_name(
        self, node: 'SimilaritySessionNode', entity: SimilarityEntityId, result: SimilarityResultId
    ) -> Optional[str]:
        """Return a display name for ``result``."""
        raise NotImplementedError

    def perform_apply(
        self,
        node: 'SimilaritySessionNode',
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> SimilarityApplyStatus:
        """Transfer typical metadata from the result target. Overrides can call this before adding provider metadata."""
        match = node.get_result(result)
        if match is None:
            return SimilarityApplyStatus.SimilarityApplyFailed
        raw_target = core.BNSimilarityEntityRef()
        raw_target.nodeId = _to_core_session_node_id(match.target.node_id)
        raw_target.entityId = _to_core_entity_id(match.target.entity_id)
        return SimilarityApplyStatus(
            core.BNSimilaritySessionNodeApplyTarget(node.handle, _to_core_entity_id(entity), raw_target)
        )

    def perform_render(
        self,
        node: 'SimilaritySessionNode',
        entity: SimilarityEntityId,
        context: SimilarityRenderContext,
        result: SimilarityResultId,
    ) -> None:
        """Add views for ``result`` to ``context``."""
        pass

    @property
    def type(self) -> SimilarityProviderType:
        """The type that created this provider."""
        return CoreSimilarityProviderType(handle=core.BNSimilarityProviderGetType(self.handle))

    @property
    def id(self) -> int:
        """This provider's ID."""
        return core.BNSimilarityProviderGetId(self.handle).value

    def visit_node(self, node: 'SimilaritySessionNode', completion: 'SimilaritySessionCompletion') -> None:
        """Perform a complete visit of ``node``. The core manages the result updates."""
        core.BNSimilarityProviderVisitNode(self.handle, node.handle, completion.handle)

    def visit_node_edge(
        self,
        from_node: 'SimilaritySessionNode',
        to_node: 'SimilaritySessionNode',
        completion: 'SimilaritySessionCompletion',
    ) -> None:
        """Perform a complete visit of the edge from ``from_node`` to ``to_node``."""
        core.BNSimilarityProviderVisitNodeEdge(self.handle, from_node.handle, to_node.handle, completion.handle)

    def get_name(
        self, node: 'SimilaritySessionNode', entity: SimilarityEntityId, result: SimilarityResultId
    ) -> Optional[str]:
        """Return the display name of ``result``."""
        return core.BNSimilarityProviderGetName(
            self.handle, node.handle, _to_core_entity_id(entity), _to_core_result_id(result)
        )

    def apply(
        self,
        node: 'SimilaritySessionNode',
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> SimilarityApplyStatus:
        """Call the provider's apply hook for ``result``."""
        return SimilarityApplyStatus(
            core.BNSimilarityProviderApply(
                self.handle,
                node.handle,
                _to_core_entity_id(entity),
                _to_core_result_id(result),
            )
        )

    def render(
        self,
        node: 'SimilaritySessionNode',
        entity: SimilarityEntityId,
        context: SimilarityRenderContext,
        result: SimilarityResultId,
    ) -> None:
        """Add views for ``result`` to ``context``."""
        core.BNSimilarityProviderRender(
            self.handle, node.handle, _to_core_entity_id(entity), context.handle, _to_core_result_id(result)
        )

    def __repr__(self):
        return f"<SimilarityProvider id={self.id}, type={self.type.name!r}>"


class CoreSimilarityProvider(SimilarityProvider):
    """A similarity provider implemented by the core or a native plugin."""

    pass


def _wrap_owned_similarity_provider(handle) -> SimilarityProvider:
    """Wrap an owned provider reference while preserving custom Python object identity."""
    handle_value = ctypes.cast(handle, ctypes.c_void_p).value
    provider = SimilarityProvider._registered_instances.get(handle_value)
    if provider is not None:
        core.BNFreeSimilarityProvider(handle)
        return provider
    return CoreSimilarityProvider(handle=handle)


class _SimilaritySessionResolverTypeMetaClass(type):
    def __iter__(self):
        binaryninja._init_plugins()
        count = ctypes.c_ulonglong()
        types = core.BNGetSimilaritySessionResolverTypeList(count)
        try:
            for i in range(0, count.value):
                yield CoreSimilaritySessionResolverType(handle=types[i])
        finally:
            core.BNFreeSimilaritySessionResolverTypeList(types)

    def __getitem__(cls, value):
        binaryninja._init_plugins()
        resolver_type = core.BNGetSimilaritySessionResolverTypeByName(str(value))
        if resolver_type is None:
            raise KeyError(f"'{value}' is not a valid similarity session resolver type")
        return CoreSimilaritySessionResolverType(handle=resolver_type)

    def __contains__(cls: '_SimilaritySessionResolverTypeMetaClass', name: object) -> bool:
        if not isinstance(name, str):
            return False
        try:
            cls[name]
            return True
        except KeyError:
            return False

    def get(
        cls: '_SimilaritySessionResolverTypeMetaClass', name: str, default: Any = None
    ) -> Optional['SimilaritySessionResolverType']:
        try:
            return cls[name]
        except KeyError:
            return default


class SimilaritySessionResolverType(metaclass=_SimilaritySessionResolverTypeMetaClass):
    """Creates resolvers with the given settings."""

    _registered_types = []
    name = None
    description = None

    def __init__(self, handle=None):
        if handle is not None:
            self.handle = core.handle_of_type(handle, core.BNSimilaritySessionResolverType)
            self.__dict__["name"] = core.BNSimilaritySessionResolverTypeGetName(handle)
            self.__dict__["description"] = core.BNSimilaritySessionResolverTypeGetDescription(handle)

    def register(self) -> None:
        """Register this resolver type for the process lifetime."""
        if self.__class__.name is None or self.__class__.description is None:
            raise ValueError("Resolver type name or description is missing")
        self._cb = core.BNCustomSimilaritySessionResolverType()
        self._cb.context = 0
        self._cb.create = self._cb.create.__class__(self._create)
        self._cb.getDefaultSettings = self._cb.getDefaultSettings.__class__(self._get_default_settings)
        self.handle = core.BNRegisterSimilaritySessionResolverType(
            self.__class__.name, self.__class__.description, self._cb
        )
        self.__class__._registered_types.append(self)

    def _create(self, ctxt, session, settings_obj):
        try:
            session_obj = SimilaritySession(handle=core.BNNewSimilaritySessionReference(session))
            settings_ref = settings.Settings(handle=core.BNNewSettingsReference(settings_obj))
            resolver = self.create(session_obj, settings_ref)
            if resolver is None:
                return None
            handle = core.BNNewSimilaritySessionResolverReference(resolver.handle)
            handle_ptr = ctypes.cast(handle, ctypes.c_void_p)
            return handle_ptr.value
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolverType._create")
            return None

    def _get_default_settings(self, ctxt):
        try:
            default_settings = self.get_default_settings()
            if default_settings is None:
                return None
            return ctypes.cast(core.BNNewSettingsReference(default_settings.handle), ctypes.c_void_p).value
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolverType._get_default_settings")
            return None

    def create(
        self, session: 'SimilaritySession', settings_obj: 'settings.Settings'
    ) -> Optional['SimilaritySessionResolver']:
        """Create a resolver for ``session``, or return ``None``. Custom types must override this method."""
        raise NotImplementedError

    def get_default_settings(self) -> Optional['settings.Settings']:
        """Return settings used to configure new resolvers."""
        return None

    def __repr__(self):
        return f"<SimilaritySessionResolverType name={self.name!r}>"


class CoreSimilaritySessionResolverType(SimilaritySessionResolverType):
    """A resolver type implemented by the core or a native plugin."""

    def create(
        self, session: 'SimilaritySession', settings_obj: 'settings.Settings'
    ) -> Optional['SimilaritySessionResolver']:
        """Create a resolver for ``session`` using ``settings_obj``, or return ``None``."""
        handle = core.BNSimilaritySessionResolverTypeCreateResolver(self.handle, session.handle, settings_obj.handle)
        if handle is None:
            return None
        return _wrap_owned_similarity_resolver(handle)

    def get_default_settings(self) -> Optional['settings.Settings']:
        """Return settings used to configure new resolvers."""
        handle = core.BNSimilaritySessionResolverTypeGetDefaultSettings(self.handle)
        if handle is None:
            return None
        return settings.Settings(handle=handle)


class SimilaritySessionResolver:
    """Selects provider results to apply to session entities.

    Calls for nodes in the same processing group may run at the same time. Do not keep the session after a callback
    returns.
    """

    _registered_instances = {}

    def __init__(
        self,
        resolver_type: Optional['SimilaritySessionResolverType'] = None,
        session: Optional['SimilaritySession'] = None,
        handle=None,
    ):
        is_custom = handle is None
        if is_custom:
            if resolver_type is None or session is None:
                raise ValueError("custom similarity session resolver must have an associated type and session")
            self._cb = core.BNCustomSimilaritySessionResolver()
            self._cb.context = 0
            self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
            self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
            self._cb.updateSettings = self._cb.updateSettings.__class__(self._update_settings)
            self._cb.prepareForNode = self._cb.prepareForNode.__class__(self._prepare_for_node)
            self._cb.resolveForNode = self._cb.resolveForNode.__class__(self._resolve_for_node)
            self._cb.free = self._cb.free.__class__(self._free)
            handle = core.BNCreateCustomSimilaritySessionResolver(resolver_type.handle, session.handle, self._cb)

        self.handle = core.handle_of_type(handle, core.BNSimilaritySessionResolver)

    def __del__(self):
        if core is not None:
            core.BNFreeSimilaritySessionResolver(self.handle)

    def _resolve_for_node(self, ctxt, session, node, entities, entity_count, completion, resolver_id):
        try:
            session_obj = SimilaritySession(handle=core.BNNewSimilaritySessionReference(session))
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            completion_obj = SimilaritySessionCompletion(
                handle=core.BNNewSimilaritySessionCompletionReference(completion)
            )
            entity_list = [entities[i].value for i in range(entity_count)]
            self.perform_resolve_for_node(session_obj, node_obj, entity_list, completion_obj)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolver._resolve_for_node")

    def _update_settings(self, ctxt, settings_obj):
        try:
            settings_ref = settings.Settings(handle=core.BNNewSettingsReference(settings_obj))
            return bool(self.perform_update_settings(settings_ref))
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolver._update_settings")
            return False

    def _prepare_for_node(self, ctxt, session, node, completion, resolver_id):
        try:
            session_obj = SimilaritySession(handle=core.BNNewSimilaritySessionReference(session))
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            completion_obj = SimilaritySessionCompletion(
                handle=core.BNNewSimilaritySessionCompletionReference(completion)
            )
            self.perform_prepare_for_node(session_obj, node_obj, completion_obj)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolver._prepare_for_node")

    def _free(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionResolver._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolver._free")

    def _external_ref_taken(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionResolver._registered_instances[handle_value] = self
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolver._external_ref_taken")

    def _external_ref_released(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionResolver._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionResolver._external_ref_released")

    def perform_resolve_for_node(
        self,
        session: 'SimilaritySession',
        node: 'SimilaritySessionNode',
        entities: List[SimilarityEntityId],
        completion: 'SimilaritySessionCompletion',
    ) -> None:
        """Select results for ``node`` after its providers have run.

        Call :meth:`SimilaritySessionNode.set_resolved_result` to select a result. Custom resolvers must override this
        method. Call :meth:`SimilaritySessionNode.add_scheduled_entity` to request another round.
        """
        raise NotImplementedError

    def perform_update_settings(self, settings_obj: 'settings.Settings') -> bool:
        """Replace this resolver's settings only if they are valid.

        Return ``False`` without changing the current settings when the new settings are invalid or updates are not
        supported. Use
        :meth:`SimilaritySession.update_resolver_settings` so affected entities are resolved again.
        """
        return False

    def perform_prepare_for_node(
        self,
        session: 'SimilaritySession',
        node: 'SimilaritySessionNode',
        completion: 'SimilaritySessionCompletion',
    ) -> None:
        """Prepare ``node`` before its providers are visited.

        This is useful for large graphs where views may be unavailable, but the resolver needs to change the scheduled
        entities or add entities itself.
        """
        pass

    @property
    def id(self) -> int:
        """This resolver's ID."""
        return core.BNSimilaritySessionResolverGetId(self.handle).value

    @property
    def type(self) -> SimilaritySessionResolverType:
        """The type that created this resolver."""
        resolver_type = core.BNSimilaritySessionResolverGetType(self.handle)
        return CoreSimilaritySessionResolverType(handle=resolver_type)

    def resolve_for_node(
        self,
        session: 'SimilaritySession',
        node: 'SimilaritySessionNode',
        entities: List[SimilarityEntityId],
        completion: 'SimilaritySessionCompletion',
    ) -> None:
        """Select results for ``node`` in ``session``."""
        raw_entities = (core.BNSimilarityEntityId * len(entities))(*(_to_core_entity_id(entity) for entity in entities))
        core.BNSimilaritySessionResolverResolveForNode(
            self.handle, session.handle, node.handle, raw_entities, len(entities), completion.handle
        )

    def prepare_for_node(
        self,
        session: 'SimilaritySession',
        node: 'SimilaritySessionNode',
        completion: 'SimilaritySessionCompletion',
    ) -> None:
        """Prepare ``node`` in ``session`` before its providers are visited."""
        core.BNSimilaritySessionResolverPrepareForNode(self.handle, session.handle, node.handle, completion.handle)

    def __repr__(self):
        return f"<SimilaritySessionResolver type={self.type.name!r}>"


class CoreSimilaritySessionResolver(SimilaritySessionResolver):
    """A resolver implemented by the core or a native plugin."""

    pass


def _wrap_owned_similarity_resolver(handle) -> SimilaritySessionResolver:
    """Wrap an owned resolver reference while preserving custom Python object identity."""
    handle_value = ctypes.cast(handle, ctypes.c_void_p).value
    resolver = SimilaritySessionResolver._registered_instances.get(handle_value)
    if resolver is not None:
        core.BNFreeSimilaritySessionResolver(handle)
        return resolver
    return CoreSimilaritySessionResolver(handle=handle)


class SimilaritySessionReceiver:
    """Receives session-start and entity-update notifications.

    ``perform_on_start`` is called before :meth:`SimilaritySession.run` returns. Update callbacks run on workers and
    may overlap across nodes and sessions.
    """

    _registered_instances = {}

    def __init__(self, handle=None):
        is_custom = handle is None
        if is_custom:
            self._cb = core.BNCustomSimilaritySessionReceiver()
            self._cb.context = 0
            self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
            self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
            self._cb.onStarted = self._cb.onStarted.__class__(self._on_started)
            self._cb.onUpdated = self._cb.onUpdated.__class__(self._on_updated)
            self._cb.free = self._cb.free.__class__(self._free)
            handle = core.BNCreateCustomSimilaritySessionReceiver(self._cb)

        self.handle = core.handle_of_type(handle, core.BNSimilaritySessionReceiver)

    def __del__(self):
        if core is not None:
            core.BNFreeSimilaritySessionReceiver(self.handle)

    def _on_started(self, ctxt, completion):
        try:
            completion_obj = SimilaritySessionCompletion(
                handle=core.BNNewSimilaritySessionCompletionReference(completion)
            )
            self.perform_on_start(completion_obj)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionReceiver._on_started")

    def _on_updated(self, ctxt, node, provider, entities, count):
        try:
            node_obj = SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(node))
            provider_obj = CoreSimilarityProvider(handle=core.BNNewSimilarityProviderReference(provider))
            entity_list = [entities[i].value for i in range(count)]
            self.perform_on_update(node_obj, provider_obj, entity_list)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionReceiver._notify_batch")

    def _free(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionReceiver._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionReceiver._free")

    def _external_ref_taken(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionReceiver._registered_instances[handle_value] = self
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionReceiver._external_ref_taken")

    def _external_ref_released(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionReceiver._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionReceiver._external_ref_released")

    def perform_on_update(
        self, node: 'SimilaritySessionNode', provider: SimilarityProvider, entities: List[SimilarityEntityId]
    ) -> None:
        """Handle entities whose provider results, resolution state, or applied metadata changed.

        Custom receivers must override this method.
        """
        raise NotImplementedError

    def perform_on_start(self, completion: 'SimilaritySessionCompletion') -> None:
        """Handle the start of a session run.

        This is mainly used to get the completion state for the run.
        """
        pass

    def __repr__(self):
        return "<SimilaritySessionReceiver>"


class CoreSimilaritySessionReceiver(SimilaritySessionReceiver):
    """A session receiver implemented by the core or a native plugin."""

    pass


class SimilaritySessionNode:
    """The main unit of similarity processing."""

    def __init__(
        self,
        view: Optional['binaryview.BinaryView'] = None,
        file: Optional['filemetadata.FileMetadata'] = None,
        handle=None,
    ):
        if handle is None:
            if view is not None and file is not None:
                raise ValueError("SimilaritySessionNode accepts either view or file, not both")
            if view is not None:
                handle = core.BNCreateSimilaritySessionNode(view.handle)
            elif file is not None:
                handle = core.BNCreateSimilaritySessionNodeFromFile(file.handle)
            else:
                raise ValueError("SimilaritySessionNode requires a view or file")
        self.handle = core.handle_of_type(handle, core.BNSimilaritySessionNode)

    def __del__(self):
        if core is not None and hasattr(self, "handle"):
            core.BNFreeSimilaritySessionNode(self.handle)

    @property
    def view(self) -> Optional['binaryview.BinaryView']:
        """The open view, if one is available.

        A file-backed node's view may be unavailable outside a session run. The session closes it when the run no
        longer needs it.
        """
        view = core.BNSimilaritySessionNodeGetView(self.handle)
        if view is None:
            return None
        return binaryview.BinaryView(handle=view)

    @view.setter
    def view(self, view: Optional['binaryview.BinaryView']) -> None:
        """Replace the node's view.

        A view backed by a different :class:`FileMetadata` is ignored. Do not mix files.
        """
        core.BNSimilaritySessionNodeSetView(self.handle, view.handle if view is not None else None)

    @property
    def file(self) -> 'filemetadata.FileMetadata':
        """The file backing this node."""
        return filemetadata.FileMetadata(handle=core.BNSimilaritySessionNodeGetFile(self.handle))

    @property
    def load_options(self) -> 'settings.Settings':
        """Options used when opening this node's view. Modify them before running the session."""
        return settings.Settings(handle=core.BNSimilaritySessionNodeGetLoadOptions(self.handle))

    @property
    def id(self) -> int:
        """This node's ID."""
        return core.BNSimilaritySessionNodeGetId(self.handle).value

    def create_entity(self, info: SimilarityEntityInfo) -> SimilarityEntityId:
        """Add an entity without scheduling it.

        An existing entity with the same type and address is reused. A non-empty name refreshes its display name.
        """
        raw_info = core.BNSimilarityEntityInfo()
        raw_info.type = info.type.value
        raw_info.address = info.address
        raw_info.name = info.name
        return core.BNSimilaritySessionNodeCreateEntity(self.handle, raw_info).value

    def remove_entity(self, id: SimilarityEntityId) -> bool:
        """Remove an entity, its schedule, its provider results, and its selected result.

        To only unschedule it, use :meth:`remove_scheduled_entity`.
        """
        return core.BNSimilaritySessionNodeRemoveEntity(self.handle, _to_core_entity_id(id))

    def get_entity(self, id: SimilarityEntityId) -> Optional[SimilarityEntityInfo]:
        """Return information about an entity."""
        info = core.BNSimilarityEntityInfo()
        if core.BNSimilaritySessionNodeGetEntity(self.handle, _to_core_entity_id(id), info):
            try:
                return SimilarityEntityInfo(SimilarityEntityType(info.type), info.address, info.name)
            finally:
                core.BNFreeSimilarityEntityInfo(info)
        return None

    @property
    def entities(self) -> List[SimilarityEntityId]:
        """All entities, including entities used only as match targets."""
        count = ctypes.c_ulonglong()
        entities = core.BNSimilaritySessionNodeGetEntities(self.handle, count)
        result = [entities[i].value for i in range(count.value)]
        core.BNFreeSimilarityEntityList(entities)
        return result

    def add_scheduled_entity(self, id: SimilarityEntityId) -> bool:
        """Schedule an entity for the next provider round.

        Nodes initially schedule all available entities. The session consumes each scheduled batch before resolution;
        resolvers can call this method to request another round.
        """
        return core.BNSimilaritySessionNodeAddScheduledEntity(self.handle, _to_core_entity_id(id))

    def remove_scheduled_entity(self, id: SimilarityEntityId) -> bool:
        """Unschedule an entity without removing it.

        To remove it, use :meth:`remove_entity`.
        """
        return core.BNSimilaritySessionNodeRemoveScheduledEntity(self.handle, _to_core_entity_id(id))

    @property
    def scheduled_entities(self) -> List[SimilarityEntityId]:
        """Entities waiting for provider processing."""
        count = ctypes.c_ulonglong()
        entities = core.BNSimilaritySessionNodeGetScheduledEntities(self.handle, count)
        result = [entities[i].value for i in range(count.value)]
        core.BNFreeSimilarityEntityList(entities)
        return result

    def get_entity_function(self, id: SimilarityEntityId) -> Optional['function.Function']:
        """Return the function represented by an entity, if available."""
        func = core.BNSimilaritySessionNodeGetEntityFunction(self.handle, _to_core_entity_id(id))
        if func is None:
            return None
        return function.Function(handle=func)

    def get_results(self, entity: SimilarityEntityId) -> List[SimilarityResultId]:
        """Return the result IDs for ``entity``."""
        count = ctypes.c_ulonglong()
        results = core.BNSimilaritySessionNodeGetResults(self.handle, _to_core_entity_id(entity), count)
        output = [results[i].value for i in range(count.value)]
        core.BNFreeSimilarityResultIdList(results)
        return output

    def get_result(self, result: SimilarityResultId) -> Optional[SimilarityResult]:
        """Return a stored result by its ID, which is unique within the node."""
        output = core.BNSimilarityResult()
        if not core.BNSimilaritySessionNodeGetResult(self.handle, _to_core_result_id(result), output):
            return None
        return SimilarityResult._from_core_struct(output)

    def set_resolved_result(self, entity: SimilarityEntityId, result: SimilarityResultId) -> bool:
        """Select one of ``entity``'s results."""
        return core.BNSimilaritySessionNodeSetResolvedResult(
            self.handle, _to_core_entity_id(entity), _to_core_result_id(result)
        )

    def get_resolved_result(self, entity: SimilarityEntityId) -> Optional[SimilarityResultId]:
        """Return the selected result for ``entity``."""
        result = core.BNSimilarityResultId()
        if not core.BNSimilaritySessionNodeGetResolvedResult(self.handle, _to_core_entity_id(entity), result):
            return None
        return result.value

    def clear_resolved_result(self, entity: SimilarityEntityId) -> bool:
        """Clear the selected result for ``entity``."""
        return core.BNSimilaritySessionNodeClearResolvedResult(self.handle, _to_core_entity_id(entity))

    @property
    def incoming_edges(self) -> List[int]:
        """IDs of nodes that must run before this node, in ascending order."""
        count = ctypes.c_ulonglong()
        edges = core.BNSimilaritySessionNodeGetIncomingEdges(self.handle, count)
        result = [edges[i].value for i in range(count.value)]
        core.BNFreeSimilaritySessionNodeEdgeList(edges)
        return result

    @property
    def outgoing_edges(self) -> List[int]:
        """IDs of nodes that depend on this node, in ascending order."""
        count = ctypes.c_ulonglong()
        edges = core.BNSimilaritySessionNodeGetOutgoingEdges(self.handle, count)
        result = [edges[i].value for i in range(count.value)]
        core.BNFreeSimilaritySessionNodeEdgeList(edges)
        return result

    @property
    def incoming_nodes(self) -> List['SimilaritySessionNode']:
        """Nodes that must run before this node, ordered by ID."""
        count = ctypes.c_ulonglong()
        nodes = core.BNSimilaritySessionNodeGetIncomingNodes(self.handle, count)
        result = [
            SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(nodes[i])) for i in range(count.value)
        ]
        core.BNFreeSimilaritySessionNodeList(nodes, count.value)
        return result

    @property
    def outgoing_nodes(self) -> List['SimilaritySessionNode']:
        """Nodes that depend on this node, ordered by ID."""
        count = ctypes.c_ulonglong()
        nodes = core.BNSimilaritySessionNodeGetOutgoingNodes(self.handle, count)
        result = [
            SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(nodes[i])) for i in range(count.value)
        ]
        core.BNFreeSimilaritySessionNodeList(nodes, count.value)
        return result

    def __repr__(self):
        file = self.file
        filename = file.filename
        location = f", file={filename!r}" if filename else ""
        return f"<SimilaritySessionNode id={self.id}{location}, entities={len(self.entities)}>"


class SimilaritySessionGraphReceiver:
    """Receives notifications after nodes or edges are added to or removed from a session graph."""

    _registered_instances = {}

    def __init__(self, handle=None):
        if handle is None:
            self._cb = core.BNCustomSimilaritySessionGraphReceiver()
            self._cb.context = 0
            self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
            self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
            self._cb.onGraphChanged = self._cb.onGraphChanged.__class__(self._on_graph_changed)
            self._cb.free = self._cb.free.__class__(self._free)
            handle = core.BNCreateCustomSimilaritySessionGraphReceiver(self._cb)

        self.handle = core.handle_of_type(handle, core.BNSimilaritySessionGraphReceiver)

    def __del__(self):
        if core is not None:
            core.BNFreeSimilaritySessionGraphReceiver(self.handle)

    def _on_graph_changed(self, ctxt):
        try:
            self.perform_on_graph_changed()
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionGraphReceiver._on_graph_changed")

    def _free(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionGraphReceiver._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionGraphReceiver._free")

    def _external_ref_taken(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionGraphReceiver._registered_instances[handle_value] = self
        except Exception:
            log_error_for_exception("Unhandled Python exception in SimilaritySessionGraphReceiver._external_ref_taken")

    def _external_ref_released(self, ctxt):
        try:
            handle_value = ctypes.cast(self.handle, ctypes.c_void_p).value
            SimilaritySessionGraphReceiver._registered_instances.pop(handle_value, None)
        except Exception:
            log_error_for_exception(
                "Unhandled Python exception in SimilaritySessionGraphReceiver._external_ref_released"
            )

    def perform_on_graph_changed(self) -> None:
        """Handle a node or edge being added to or removed from the graph."""
        raise NotImplementedError

    def __repr__(self):
        return "<SimilaritySessionGraphReceiver>"


class CoreSimilaritySessionGraphReceiver(SimilaritySessionGraphReceiver):
    """A session graph receiver implemented by the core or a native plugin."""

    pass


class SimilaritySessionGraph:
    """A graph that controls node processing order and cannot contain cycles.

    Nodes and edges cannot be changed during a run. Methods with no return value ignore changes, while methods that
    return ``bool`` return ``False``.
    """

    def __init__(self, handle):
        self.handle = core.handle_of_type(handle, core.BNSimilaritySessionGraph)

    def __del__(self):
        if core is not None:
            core.BNFreeSimilaritySessionGraph(self.handle)

    def add_node(self, node: SimilaritySessionNode) -> None:
        """Add ``node``, moving it unless either graph is currently running."""
        core.BNSimilaritySessionGraphAddNode(self.handle, node.handle)

    def remove_node(self, node: SimilaritySessionNode) -> None:
        """Remove ``node`` and its edges from this graph."""
        core.BNSimilaritySessionGraphRemoveNode(self.handle, node.handle)

    def is_valid_edge(self, from_node: SimilaritySessionNode, to_node: SimilaritySessionNode) -> bool:
        """Return whether an edge can be added without duplicating an edge or creating a cycle."""
        return core.BNSimilaritySessionGraphIsValidEdge(self.handle, from_node.handle, to_node.handle)

    def add_edge(self, from_node: SimilaritySessionNode, to_node: SimilaritySessionNode) -> bool:
        """Make ``to_node`` run after ``from_node``."""
        return core.BNSimilaritySessionGraphAddEdge(self.handle, from_node.handle, to_node.handle)

    def remove_edge(self, from_node: SimilaritySessionNode, to_node: SimilaritySessionNode) -> bool:
        """Remove the edge from ``from_node`` to ``to_node``."""
        return core.BNSimilaritySessionGraphRemoveEdge(self.handle, from_node.handle, to_node.handle)

    def add_receiver(self, receiver: SimilaritySessionGraphReceiver) -> None:
        """Add a graph-change receiver."""
        core.BNSimilaritySessionGraphAddReceiver(self.handle, receiver.handle)

    def remove_receiver(self, receiver: SimilaritySessionGraphReceiver) -> None:
        """Remove a graph-change receiver."""
        core.BNSimilaritySessionGraphRemoveReceiver(self.handle, receiver.handle)

    @property
    def receivers(self) -> List[SimilaritySessionGraphReceiver]:
        """Graph-change receivers currently registered with this graph."""
        count = ctypes.c_ulonglong()
        handles = core.BNSimilaritySessionGraphGetReceivers(self.handle, count)
        try:
            return [
                CoreSimilaritySessionGraphReceiver(handle=core.BNNewSimilaritySessionGraphReceiverReference(handles[i]))
                for i in range(count.value)
            ]
        finally:
            core.BNFreeSimilaritySessionGraphReceiverList(handles, count.value)

    def get_node(self, id: int) -> Optional[SimilaritySessionNode]:
        """Return the node with ``id``."""
        handle = core.BNSimilaritySessionGraphGetNode(self.handle, _to_core_session_node_id(id))
        if handle is None:
            return None
        return SimilaritySessionNode(handle=handle)

    @property
    def nodes(self) -> List[SimilaritySessionNode]:
        """Nodes in this graph."""
        count = ctypes.c_ulonglong()
        handles = core.BNSimilaritySessionGraphGetNodes(self.handle, count)
        try:
            return [
                SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(handles[i]))
                for i in range(count.value)
            ]
        finally:
            core.BNFreeSimilaritySessionNodeList(handles, count.value)

    def __len__(self):
        return len(self.nodes)

    def __repr__(self):
        return f"<SimilaritySessionGraph nodes={len(self.nodes)}>"

    def get_schedule(self) -> List[List[SimilaritySessionNode]]:
        """Return groups of nodes in processing order. Nodes in the same group may run in parallel."""
        level_count = ctypes.c_ulonglong()
        node_counts = ctypes.POINTER(ctypes.c_ulonglong)()
        schedule_ptr = core.BNSimilaritySessionGraphGetSchedule(
            self.handle, ctypes.byref(node_counts), ctypes.byref(level_count)
        )
        try:
            schedule = []
            for i in range(level_count.value):
                level = []
                for j in range(node_counts[i]):
                    level.append(
                        SimilaritySessionNode(handle=core.BNNewSimilaritySessionNodeReference(schedule_ptr[i][j]))
                    )
                schedule.append(level)
            return schedule
        finally:
            core.BNFreeSimilaritySessionNodeSchedule(schedule_ptr, node_counts, level_count.value)


class SimilaritySessionCompletion:
    """Tracks stop requests, progress, and timing for a session run."""

    def __init__(self, handle=None):
        """Create an independent completion state, or wrap ``handle`` when provided.

        Independent states are normally only needed when calling providers or resolvers directly.
        """
        if handle is None:
            handle = core.BNCreateSimilaritySessionCompletion()
        self.handle = core.handle_of_type(handle, core.BNSimilaritySessionCompletion)

    def __del__(self):
        if core is not None:
            core.BNFreeSimilaritySessionCompletion(self.handle)

    @property
    def is_finished(self) -> bool:
        """Whether the run has finished."""
        return core.BNSimilaritySessionCompletionIsFinished(self.handle)

    @property
    def is_stop_requested(self) -> bool:
        """Whether the run has been asked to stop."""
        return core.BNSimilaritySessionCompletionIsStopRequested(self.handle)

    def request_stop(self) -> None:
        """Ask the active run to stop."""
        core.BNSimilaritySessionCompletionRequestStop(self.handle)

    @property
    def progress(self) -> float:
        """Overall progress from 0.0 to 1.0."""
        return self.get_progress(SimilaritySessionCompletionQuery())

    def get_progress(self, query: SimilaritySessionCompletionQuery) -> float:
        """Return progress matching ``query`` from 0.0 to 1.0."""
        return core.BNSimilaritySessionCompletionGetProgress(self.handle, query._to_core_struct())

    def set_progress(self, query: SimilaritySessionCompletionQuery, progress: float) -> None:
        """Increase provider or resolver progress for a node. Progress cannot decrease.

        .. note:: Call this only from the provider or resolver selected by ``query``.
        """
        core.BNSimilaritySessionCompletionSetProgress(self.handle, query._to_core_struct(), progress)

    def get_timing(self, query: SimilaritySessionCompletionQuery) -> timedelta:
        """Return elapsed time matching ``query``."""
        return timedelta(milliseconds=core.BNSimilaritySessionCompletionGetTiming(self.handle, query._to_core_struct()))

    def __repr__(self):
        return f"<SimilaritySessionCompletion progress={self.progress:.1%}, finished={self.is_finished}>"


class SimilaritySession:
    """Runs similarity providers and resolvers over a graph of binaries."""

    def __init__(self, handle=None):
        if handle is None:
            handle = core.BNCreateSimilaritySession()
        self.handle = core.handle_of_type(handle, core.BNSimilaritySession)

    def __del__(self):
        if core is not None:
            core.BNFreeSimilaritySession(self.handle)

    @property
    def id(self) -> int:
        """This session's ID."""
        return core.BNSimilaritySessionGetId(self.handle).value

    def add_provider(self, provider: SimilarityProvider) -> None:
        """Add a provider and schedule entities processed by earlier runs for the next run.

        .. note:: Ignored while a run is active.
        """
        core.BNSimilaritySessionAddProvider(self.handle, provider.handle)

    def remove_provider(self, provider: SimilarityProvider) -> None:
        """Remove a provider, clear its results, and mark affected entities for resolution.

        .. note:: Ignored while a run is active.
        """
        core.BNSimilaritySessionRemoveProvider(self.handle, provider.handle)

    def update_provider_settings(self, provider: SimilarityProvider, settings_obj: 'settings.Settings') -> bool:
        """Update a provider already in the session and schedule previously processed entities again.

        Returns ``False`` during a run, when the provider is absent, or when it rejects the settings.
        """
        return core.BNSimilaritySessionUpdateProviderSettings(self.handle, provider.handle, settings_obj.handle)

    def get_provider(self, id: int) -> Optional[SimilarityProvider]:
        """Return the provider with ``id``."""
        handle = core.BNSimilaritySessionGetProvider(self.handle, _to_core_provider_id(id))
        if handle is None:
            return None
        return _wrap_owned_similarity_provider(handle)

    @property
    def providers(self) -> List[SimilarityProvider]:
        """Providers in this session."""
        count = ctypes.c_ulonglong()
        providers = core.BNSimilaritySessionGetProviders(self.handle, count)
        try:
            return [
                _wrap_owned_similarity_provider(core.BNNewSimilarityProviderReference(providers[i]))
                for i in range(count.value)
            ]
        finally:
            core.BNFreeSimilarityProviderList(providers, count.value)

    def add_resolver(self, resolver: SimilaritySessionResolver) -> bool:
        """Add a resolver and mark entities processed by earlier runs for resolution.

        .. note:: Returns ``False`` during a run, for a duplicate, or for a resolver from another session.
        """
        return core.BNSimilaritySessionAddResolver(self.handle, resolver.handle)

    def remove_resolver(self, resolver: SimilaritySessionResolver) -> bool:
        """Remove a resolver.

        .. note:: Returns ``False`` during a run, or if it is absent or belongs to another session.
        """
        return core.BNSimilaritySessionRemoveResolver(self.handle, resolver.handle)

    def update_resolver_settings(self, resolver: SimilaritySessionResolver, settings_obj: 'settings.Settings') -> bool:
        """Update a resolver already in the session and mark previously processed entities for resolution.

        Returns ``False`` during a run, when the resolver is absent or belongs to another session, or when it rejects
        the settings.
        """
        return core.BNSimilaritySessionUpdateResolverSettings(self.handle, resolver.handle, settings_obj.handle)

    def get_resolver(self, id: int) -> Optional[SimilaritySessionResolver]:
        """Return the resolver with ``id``, if present."""
        handle = core.BNSimilaritySessionGetResolver(self.handle, _to_core_resolver_id(id))
        if handle is None:
            return None
        return _wrap_owned_similarity_resolver(handle)

    def add_receiver(self, receiver: SimilaritySessionReceiver) -> None:
        """Add a receiver. A running session keeps using the receiver list it started with."""
        core.BNSimilaritySessionAddReceiver(self.handle, receiver.handle)

    def remove_receiver(self, receiver: SimilaritySessionReceiver) -> None:
        """Remove a receiver. A running session keeps using the receiver list it started with."""
        core.BNSimilaritySessionRemoveReceiver(self.handle, receiver.handle)

    @property
    def resolvers(self) -> List[SimilaritySessionResolver]:
        """Resolvers in this session."""
        count = ctypes.c_ulonglong()
        resolvers = core.BNSimilaritySessionGetResolvers(self.handle, count)
        try:
            return [
                _wrap_owned_similarity_resolver(core.BNNewSimilaritySessionResolverReference(resolvers[i]))
                for i in range(count.value)
            ]
        finally:
            core.BNFreeSimilaritySessionResolverList(resolvers, count.value)

    @property
    def receivers(self) -> List[SimilaritySessionReceiver]:
        """Receivers in this session."""
        count = ctypes.c_ulonglong()
        receivers = core.BNSimilaritySessionGetReceivers(self.handle, count)
        try:
            return [
                CoreSimilaritySessionReceiver(handle=core.BNNewSimilaritySessionReceiverReference(receivers[i]))
                for i in range(count.value)
            ]
        finally:
            core.BNFreeSimilaritySessionReceiverList(receivers, count.value)

    @property
    def graph(self) -> SimilaritySessionGraph:
        """The session's dependency graph."""
        return SimilaritySessionGraph(handle=core.BNSimilaritySessionGetGraph(self.handle))

    def run(self) -> SimilaritySessionCompletion:
        """Start a background run with the current graph, providers, and resolvers.

        Changes to them are ignored until the run finishes.

        .. note:: Returns the active run's completion state when already running.
        """
        return SimilaritySessionCompletion(handle=core.BNSimilaritySessionRun(self.handle))

    def __repr__(self):
        return (
            f"<SimilaritySession nodes={len(self.graph)}, providers={len(self.providers)}, "
            f"resolvers={len(self.resolvers)}, receivers={len(self.receivers)}>"
        )
