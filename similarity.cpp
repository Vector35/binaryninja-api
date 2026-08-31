#include <utility>

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

namespace {
	template <typename Result, typename Callback>
	Result RunSimilarityCallback(const char* message, Result failure, Callback&& callback) noexcept
	{
		try
		{
			return callback();
		}
		catch (const std::exception& exception)
		{
			LogErrorForException(exception, "%s", message);
		}
		catch (...)
		{
			LogError("%s", message);
		}
		return failure;
	}

	template <typename Callback>
	void RunSimilarityCallback(const char* message, Callback&& callback) noexcept
	{
		try
		{
			callback();
		}
		catch (const std::exception& exception)
		{
			LogErrorForException(exception, "%s", message);
		}
		catch (...)
		{
			LogError("%s", message);
		}
	}
}  // namespace

SimilarityView::SimilarityView(BNSimilarityView* view)
{
	m_object = view;
}

string SimilarityView::GetGroup() const
{
	char* group = BNSimilarityViewGetGroup(m_object);
	string result = group ? group : "";
	BNFreeString(group);
	return result;
}

BNSimilarityViewType SimilarityView::GetType() const
{
	return BNSimilarityViewGetType(m_object);
}

Ref<FlowGraph> SimilarityView::GetFlowGraph() const
{
	BNFlowGraph* graph = BNSimilarityViewGetFlowGraph(m_object);
	return graph ? Ref<FlowGraph>(new FlowGraph(graph)) : nullptr;
}

Ref<BinaryView> SimilarityView::GetLinearViewData() const
{
	BNBinaryView* data = BNSimilarityViewGetLinearViewData(m_object);
	return data ? Ref<BinaryView>(new BinaryView(data)) : nullptr;
}

Ref<LinearViewObject> SimilarityView::GetLinearView() const
{
	BNLinearViewObject* linearView = BNSimilarityViewGetLinearView(m_object);
	return linearView ? Ref<LinearViewObject>(new LinearViewObject(linearView)) : nullptr;
}

optional<SimilarityEntityRef> SimilarityView::GetEntity() const
{
	BNSimilarityEntityRef entity;
	if (!BNSimilarityViewGetEntity(m_object, &entity))
		return nullopt;
	return SimilarityEntityRef(entity);
}

SimilarityRenderContext::SimilarityRenderContext()
{
	m_object = BNCreateSimilarityRenderContext();
}

SimilarityRenderContext::SimilarityRenderContext(BNSimilarityRenderContext* context)
{
	m_object = context;
}

void SimilarityRenderContext::SetPreferredViewType(const FunctionViewType& type)
{
	BNSimilarityRenderContextSetPreferredViewType(m_object, type.ToAPIStruct());
}

FunctionViewType SimilarityRenderContext::GetPreferredViewType() const
{
	const BNFunctionGraphType type = BNSimilarityRenderContextGetPreferredViewType(m_object);
	if (type != HighLevelLanguageRepresentationFunctionGraph)
		return FunctionViewType(type);
	char* name = BNSimilarityRenderContextGetPreferredViewTypeName(m_object);
	FunctionViewType result {string(name)};
	BNFreeString(name);
	return result;
}

void SimilarityRenderContext::AddFlowGraph(const string& group, FlowGraph& graph)
{
	BNSimilarityRenderContextAddFlowGraph(m_object, group.c_str(), graph.GetObject());
}

void SimilarityRenderContext::AddFlowGraph(const string& group, FlowGraph& graph, const SimilarityEntityRef& entity)
{
	const BNSimilarityEntityRef rawEntity = entity.ToRaw();
	BNSimilarityRenderContextAddFlowGraphForEntity(m_object, group.c_str(), graph.GetObject(), &rawEntity);
}

void SimilarityRenderContext::AddLinearView(const string& group, BinaryView& data, LinearViewObject& linearView)
{
	BNSimilarityRenderContextAddLinearView(m_object, group.c_str(), data.GetObject(), linearView.GetObject());
}

void SimilarityRenderContext::AddLinearView(
	const string& group, BinaryView& data, LinearViewObject& linearView, const SimilarityEntityRef& entity)
{
	const BNSimilarityEntityRef rawEntity = entity.ToRaw();
	BNSimilarityRenderContextAddLinearViewForEntity(
		m_object, group.c_str(), data.GetObject(), linearView.GetObject(), &rawEntity);
}

vector<Ref<SimilarityView>> SimilarityRenderContext::GetViews() const
{
	size_t count = 0;
	BNSimilarityView** views = BNGetSimilarityRenderContextViews(m_object, &count);
	vector<Ref<SimilarityView>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new SimilarityView(BNNewSimilarityViewReference(views[i])));
	BNFreeSimilarityViewList(views, count);
	return result;
}

DiffRenderer::DiffRenderer()
{
	m_object = BNCreateDiffRenderer();
}

DiffRenderer::DiffRenderer(BNDiffRenderer* renderer)
{
	m_object = renderer;
}

void DiffRenderer::AddRangeAnnotation(const SimilarityRangeAnnotation& annotation)
{
	AddRangeAnnotation(annotation.start, annotation.end, annotation.type);
}

void DiffRenderer::AddRangeAnnotation(uint64_t start, uint64_t end, BNSimilarityAnnotationType type)
{
	BNDiffRendererAddRangeAnnotation(m_object, start, end, type);
}

void DiffRenderer::Render(SimilarityRenderContext& context, Function& function)
{
	BNDiffRendererRenderFunction(m_object, context.GetObject(), function.GetObject());
}

void DiffRenderer::Render(SimilarityRenderContext& context, Function& function, const SimilarityEntityRef& entity)
{
	const BNSimilarityEntityRef rawEntity = entity.ToRaw();
	BNDiffRendererRenderFunctionForEntity(m_object, context.GetObject(), function.GetObject(), &rawEntity);
}

void DiffRenderer::Render(SimilarityRenderContext& context, const string& group, FlowGraph& graph)
{
	BNDiffRendererRenderFlowGraph(m_object, context.GetObject(), group.c_str(), graph.GetObject());
}

void DiffRenderer::Render(
	SimilarityRenderContext& context, const string& group, FlowGraph& graph, const SimilarityEntityRef& entity)
{
	const BNSimilarityEntityRef rawEntity = entity.ToRaw();
	BNDiffRendererRenderFlowGraphForEntity(m_object, context.GetObject(), group.c_str(), graph.GetObject(), &rawEntity);
}

void DiffRenderer::Render(
	SimilarityRenderContext& context, const string& group, BinaryView& data, LinearViewObject& linearView)
{
	BNDiffRendererRenderLinearView(
		m_object, context.GetObject(), group.c_str(), data.GetObject(), linearView.GetObject());
}

void DiffRenderer::Render(SimilarityRenderContext& context, const string& group, BinaryView& data,
	LinearViewObject& linearView, const SimilarityEntityRef& entity)
{
	const BNSimilarityEntityRef rawEntity = entity.ToRaw();
	BNDiffRendererRenderLinearViewForEntity(
		m_object, context.GetObject(), group.c_str(), data.GetObject(), linearView.GetObject(), &rawEntity);
}

SimilarityResultId SimilarityProviderResults::AddResult(
	const SimilarityEntityRef& source, const SimilarityEntityRef& target, uint8_t similarity, uint8_t confidence)
{
	const BNSimilarityEntityRef rawSource = source.ToRaw();
	const BNSimilarityEntityRef rawTarget = target.ToRaw();
	return BNSimilarityProviderResultsAddResult(m_object, &rawSource, &rawTarget, similarity, confidence);
}


SimilarityProviderType::SimilarityProviderType(string name, string description) :
	m_nameForRegister(std::move(name)), m_descForRegister(std::move(description))
{}


SimilarityProviderType::SimilarityProviderType(BNSimilarityProviderType* type)
{
	m_object = type;
}


void SimilarityProviderType::Register(SimilarityProviderType* type)
{
	BNCustomSimilarityProviderType cb {};
	cb.context = type;
	cb.create = CreateCallback;
	cb.getDefaultSettings = GetDefaultSettingsCallback;

	type->AddRefForRegistration();
	type->m_object =
		BNRegisterSimilarityProviderType(type->m_nameForRegister.c_str(), type->m_descForRegister.c_str(), &cb);
}


vector<Ref<SimilarityProviderType>> SimilarityProviderType::GetList()
{
	size_t count;
	BNSimilarityProviderType** list = BNGetSimilarityProviderTypeList(&count);
	vector<Ref<SimilarityProviderType>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreSimilarityProviderType(list[i]));
	BNFreeSimilarityProviderTypeList(list);
	return result;
}


Ref<SimilarityProviderType> SimilarityProviderType::GetByName(const string& name)
{
	BNSimilarityProviderType* result = BNGetSimilarityProviderTypeByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreSimilarityProviderType(result);
}


std::string SimilarityProviderType::GetName() const
{
	char* name = BNSimilarityProviderTypeGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string SimilarityProviderType::GetDescription() const
{
	char* description = BNSimilarityProviderTypeGetDescription(m_object);
	std::string result = description;
	BNFreeString(description);
	return result;
}


CoreSimilarityProviderType::CoreSimilarityProviderType(BNSimilarityProviderType* type) : SimilarityProviderType(type) {}


Ref<SimilarityProvider> CoreSimilarityProviderType::Create(Settings& settings)
{
	BNSimilarityProvider* provider = BNSimilarityProviderTypeCreateProvider(m_object, settings.m_object);
	if (!provider)
		return nullptr;
	return new CoreSimilarityProvider(provider);
}

Ref<Settings> CoreSimilarityProviderType::GetDefaultSettings()
{
	BNSettings* settings = BNSimilarityProviderTypeGetDefaultSettings(m_object);
	if (!settings)
		return nullptr;
	return new Settings(settings);
}


SimilarityProvider::SimilarityProvider(BNSimilarityProvider* provider)
{
	m_object = provider;
}


Ref<SimilarityProviderType> SimilarityProvider::GetType() const
{
	return new CoreSimilarityProviderType(BNSimilarityProviderGetType(m_object));
}

SimilarityProviderId SimilarityProvider::GetId() const
{
	return BNSimilarityProviderGetId(m_object);
}


SimilarityProvider::SimilarityProvider(SimilarityProviderType* type)
{
	BNCustomSimilarityProvider cb {};
	cb.context = this;
	cb.updateSettings = UpdateSettingsCallback;
	cb.visitNode = VisitNodeCallback;
	cb.visitNodeEdge = VisitNodeEdgeCallback;
	cb.getName = GetNameCallback;
	cb.apply = ApplyCallback;
	cb.render = RenderCallback;
	cb.free = FreeContextCallback;

	AddRefForRegistration();
	m_object = BNCreateCustomSimilarityProvider(type->m_object, &cb);
}


CoreSimilarityProvider::CoreSimilarityProvider(BNSimilarityProvider* provider) : SimilarityProvider(provider) {}

bool SimilarityProvider::UpdateSettingsCallback(void* ctxt, BNSettings* settings)
{
	return RunSimilarityCallback<bool>("Unhandled exception updating similarity provider settings", false, [&]() {
		CallbackRef<SimilarityProvider> provider(ctxt);
		Ref<Settings> settingsObj = new Settings(BNNewSettingsReference(settings));
		return provider->UpdateSettings(*settingsObj);
	});
}

BNSimilarityApplyStatus SimilarityProvider::Apply(
	SimilaritySessionNode& node, SimilarityEntityId entity, SimilarityResultId resultId)
{
	const auto result = node.GetResult(resultId);
	if (!result)
		return SimilarityApplyFailed;
	const auto rawTarget = result->target.ToRaw();
	return BNSimilaritySessionNodeApplyTarget(node.GetObject(), entity, &rawTarget);
}


void SimilarityProvider::VisitNode(SimilaritySessionNode& node, SimilaritySessionCompletion& completion)
{
	BNSimilarityProviderVisitNode(m_object, node.GetObject(), completion.GetObject());
}

void SimilarityProvider::VisitNodeEdge(
	SimilaritySessionNode& from, SimilaritySessionNode& to, SimilaritySessionCompletion& completion)
{
	BNSimilarityProviderVisitNodeEdge(m_object, from.GetObject(), to.GetObject(), completion.GetObject());
}

bool CoreSimilarityProvider::VisitNode(
	SimilaritySessionNode& node, SimilarityProviderResults& results, SimilaritySessionCompletion& completion)
{
	return BNSimilarityProviderPerformVisitNode(
		m_object, node.GetObject(), results.GetObject(), completion.GetObject());
}

bool CoreSimilarityProvider::VisitNodeEdge(SimilaritySessionNode& from, SimilaritySessionNode& to,
	SimilarityProviderResults& results, SimilaritySessionCompletion& completion)
{
	return BNSimilarityProviderPerformVisitNodeEdge(
		m_object, from.GetObject(), to.GetObject(), results.GetObject(), completion.GetObject());
}


std::optional<std::string> CoreSimilarityProvider::GetName(
	SimilaritySessionNode& node, SimilarityEntityId entity, SimilarityResultId resultId)
{
	char* name = BNSimilarityProviderGetName(m_object, node.GetObject(), entity, resultId);
	if (!name)
		return std::nullopt;
	std::string result = name;
	BNFreeString(name);
	return result;
}


BNSimilarityApplyStatus CoreSimilarityProvider::Apply(SimilaritySessionNode& node, SimilarityEntityId entity,
	SimilarityResultId result)
{
	return BNSimilarityProviderApply(m_object, node.GetObject(), entity, result);
}


void CoreSimilarityProvider::Render(SimilaritySessionNode& node, SimilarityEntityId entity,
	SimilarityRenderContext& context, SimilarityResultId result)
{
	BNSimilarityProviderRender(m_object, node.GetObject(), entity, context.GetObject(), result);
}


SimilaritySessionResolverType::SimilaritySessionResolverType(std::string name, std::string description) :
	m_nameForRegister(std::move(name)), m_descForRegister(std::move(description))
{}


SimilaritySessionResolverType::SimilaritySessionResolverType(BNSimilaritySessionResolverType* type)
{
	m_object = type;
}


void SimilaritySessionResolverType::Register(SimilaritySessionResolverType* type)
{
	BNCustomSimilaritySessionResolverType cb {};
	cb.context = type;
	cb.create = CreateCallback;
	cb.getDefaultSettings = GetDefaultSettingsCallback;

	type->AddRefForRegistration();
	type->m_object =
		BNRegisterSimilaritySessionResolverType(type->m_nameForRegister.c_str(), type->m_descForRegister.c_str(), &cb);
}


std::vector<Ref<SimilaritySessionResolverType>> SimilaritySessionResolverType::GetList()
{
	size_t count;
	BNSimilaritySessionResolverType** list = BNGetSimilaritySessionResolverTypeList(&count);
	std::vector<Ref<SimilaritySessionResolverType>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreSimilaritySessionResolverType(list[i]));
	BNFreeSimilaritySessionResolverTypeList(list);
	return result;
}


Ref<SimilaritySessionResolverType> SimilaritySessionResolverType::GetByName(const std::string& name)
{
	BNSimilaritySessionResolverType* result = BNGetSimilaritySessionResolverTypeByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreSimilaritySessionResolverType(result);
}


std::string SimilaritySessionResolverType::GetName() const
{
	char* name = BNSimilaritySessionResolverTypeGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string SimilaritySessionResolverType::GetDescription() const
{
	char* description = BNSimilaritySessionResolverTypeGetDescription(m_object);
	std::string result = description;
	BNFreeString(description);
	return result;
}


BNSimilaritySessionResolver* SimilaritySessionResolverType::CreateCallback(
	void* ctxt, BNSimilaritySession* session, BNSettings* settings)
{
	return RunSimilarityCallback<
		BNSimilaritySessionResolver*>("Unhandled exception creating similarity session resolver", nullptr, [&]() {
		SimilaritySessionResolverType* type = (SimilaritySessionResolverType*)ctxt;
		Ref<SimilaritySession> sessionObj = new SimilaritySession(BNNewSimilaritySessionReference(session));
		Ref<Settings> settingsObj = new Settings(BNNewSettingsReference(settings));
		Ref<SimilaritySessionResolver> result = type->Create(sessionObj, *settingsObj);
		if (!result)
			return static_cast<BNSimilaritySessionResolver*>(nullptr);
		return BNNewSimilaritySessionResolverReference(result->GetObject());
	});
}


BNSettings* SimilaritySessionResolverType::GetDefaultSettingsCallback(void* ctxt)
{
	return RunSimilarityCallback<
		BNSettings*>("Unhandled exception getting similarity session resolver settings", nullptr, [&]() {
		SimilaritySessionResolverType* type = (SimilaritySessionResolverType*)ctxt;
		Ref<Settings> result = type->GetDefaultSettings();
		if (!result)
			return static_cast<BNSettings*>(nullptr);
		return BNNewSettingsReference(result->GetObject());
	});
}


CoreSimilaritySessionResolverType::CoreSimilaritySessionResolverType(BNSimilaritySessionResolverType* type) :
	SimilaritySessionResolverType(type)
{}


Ref<SimilaritySessionResolver> CoreSimilaritySessionResolverType::Create(
	Ref<SimilaritySession> session, Settings& settings)
{
	BNSimilaritySessionResolver* resolver =
		BNSimilaritySessionResolverTypeCreateResolver(m_object, session->GetObject(), settings.GetObject());
	if (!resolver)
		return nullptr;
	return new CoreSimilaritySessionResolver(resolver);
}


Ref<Settings> CoreSimilaritySessionResolverType::GetDefaultSettings()
{
	BNSettings* settings = BNSimilaritySessionResolverTypeGetDefaultSettings(m_object);
	if (!settings)
		return nullptr;
	return new Settings(settings);
}


SimilaritySessionResolver::SimilaritySessionResolver(BNSimilaritySessionResolver* resolver)
{
	m_object = resolver;
}


SimilaritySessionResolver::SimilaritySessionResolver(
	SimilaritySessionResolverType* type, Ref<SimilaritySession> session)
{
	BNCustomSimilaritySessionResolver cb {};
	cb.context = this;
	cb.updateSettings = UpdateSettingsCallback;
	cb.prepareForNode = PrepareForNodeCallback;
	cb.resolveForNode = ResolveForNodeCallback;
	cb.free = FreeContextCallback;

	AddRefForRegistration();
	m_object = BNCreateCustomSimilaritySessionResolver(type->GetObject(), session->GetObject(), &cb);
}

bool SimilaritySessionResolver::UpdateSettingsCallback(void* ctxt, BNSettings* settings)
{
	return RunSimilarityCallback<bool>("Unhandled exception updating similarity resolver settings", false, [&]() {
		CallbackRef<SimilaritySessionResolver> resolver(ctxt);
		Ref<Settings> settingsObj = new Settings(BNNewSettingsReference(settings));
		return resolver->UpdateSettings(*settingsObj);
	});
}


SimilaritySessionResolverId SimilaritySessionResolver::GetId() const
{
	return BNSimilaritySessionResolverGetId(m_object);
}


Ref<SimilaritySessionResolverType> SimilaritySessionResolver::GetType() const
{
	return new CoreSimilaritySessionResolverType(BNSimilaritySessionResolverGetType(m_object));
}


CoreSimilaritySessionResolver::CoreSimilaritySessionResolver(BNSimilaritySessionResolver* resolver) :
	SimilaritySessionResolver(resolver)
{}


void CoreSimilaritySessionResolver::PrepareForNode(
	SimilaritySession& session, SimilaritySessionNode& node, SimilaritySessionCompletion& completion)
{
	BNSimilaritySessionResolverPrepareForNode(m_object, session.GetObject(), node.GetObject(), completion.GetObject());
}


void CoreSimilaritySessionResolver::ResolveForNode(SimilaritySession& session, SimilaritySessionNode& node,
	const std::vector<SimilarityEntityId>& entities, SimilaritySessionCompletion& completion)
{
	std::vector<BNSimilarityEntityId> coreEntities;
	coreEntities.reserve(entities.size());
	for (const auto entity : entities)
		coreEntities.push_back(entity);
	BNSimilaritySessionResolverResolveForNode(m_object, session.GetObject(), node.GetObject(), coreEntities.data(),
		coreEntities.size(), completion.GetObject());
}


SimilaritySessionNode::SimilaritySessionNode(BNSimilaritySessionNode* node)
{
	m_object = node;
}


SimilaritySessionNode::SimilaritySessionNode(Ref<BinaryView> view)
{
	m_object = BNCreateSimilaritySessionNode(view->GetObject());
}


SimilaritySessionNode::SimilaritySessionNode(Ref<FileMetadata> file)
{
	m_object = BNCreateSimilaritySessionNodeFromFile(file->GetObject());
}


Ref<BinaryView> SimilaritySessionNode::GetView() const
{
	BNBinaryView* view = BNSimilaritySessionNodeGetView(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


void SimilaritySessionNode::SetView(Ref<BinaryView> view)
{
	BNSimilaritySessionNodeSetView(m_object, view ? view->GetObject() : nullptr);
}


Ref<FileMetadata> SimilaritySessionNode::GetFile() const
{
	return new FileMetadata(BNSimilaritySessionNodeGetFile(m_object));
}

Ref<Settings> SimilaritySessionNode::GetLoadOptions() const
{
	return new Settings(BNSimilaritySessionNodeGetLoadOptions(m_object));
}


SimilaritySessionNodeId SimilaritySessionNode::GetId() const
{
	return BNSimilaritySessionNodeGetId(m_object);
}


SimilarityEntityId SimilaritySessionNode::CreateEntity(const SimilarityEntityInfo& info)
{
	auto rawInfo = info.ToRaw();
	return BNSimilaritySessionNodeCreateEntity(m_object, &rawInfo);
}


bool SimilaritySessionNode::RemoveEntity(SimilarityEntityId id)
{
	return BNSimilaritySessionNodeRemoveEntity(m_object, id);
}


std::optional<SimilarityEntityInfo> SimilaritySessionNode::GetEntity(const SimilarityEntityId id)
{
	BNSimilarityEntityInfo result;
	if (!BNSimilaritySessionNodeGetEntity(m_object, id, &result))
		return std::nullopt;
	SimilarityEntityInfo info(result);
	BNFreeSimilarityEntityInfo(&result);
	return info;
}


std::vector<SimilarityEntityId> SimilaritySessionNode::GetEntities()
{
	size_t count = 0;
	BNSimilarityEntityId* entities = BNSimilaritySessionNodeGetEntities(m_object, &count);
	std::vector<SimilarityEntityId> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(entities[i]);
	BNFreeSimilarityEntityList(entities);
	return result;
}

bool SimilaritySessionNode::AddScheduledEntity(SimilarityEntityId id)
{
	return BNSimilaritySessionNodeAddScheduledEntity(m_object, id);
}

bool SimilaritySessionNode::RemoveScheduledEntity(SimilarityEntityId id)
{
	return BNSimilaritySessionNodeRemoveScheduledEntity(m_object, id);
}

std::vector<SimilarityEntityId> SimilaritySessionNode::GetScheduledEntities()
{
	size_t count = 0;
	BNSimilarityEntityId* entities = BNSimilaritySessionNodeGetScheduledEntities(m_object, &count);
	std::vector<SimilarityEntityId> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(entities[i]);
	BNFreeSimilarityEntityList(entities);
	return result;
}


Ref<Function> SimilaritySessionNode::GetEntityFunction(const SimilarityEntityId id)
{
	BNFunction* function = BNSimilaritySessionNodeGetEntityFunction(m_object, id);
	if (!function)
		return nullptr;
	return new Function(function);
}

std::vector<SimilarityResultId> SimilaritySessionNode::GetResults(SimilarityEntityId entity)
{
	size_t count = 0;
	BNSimilarityResultId* results = BNSimilaritySessionNodeGetResults(m_object, entity, &count);
	std::vector<SimilarityResultId> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
		out.push_back(results[i]);
	BNFreeSimilarityResultIdList(results);
	return out;
}

std::optional<SimilarityResult> SimilaritySessionNode::GetResult(SimilarityResultId resultId)
{
	BNSimilarityResult result;
	if (!BNSimilaritySessionNodeGetResult(m_object, resultId, &result))
		return std::nullopt;
	return SimilarityResult(result);
}

bool SimilaritySessionNode::SetResolvedResult(SimilarityEntityId entity, SimilarityResultId result)
{
	return BNSimilaritySessionNodeSetResolvedResult(m_object, entity, result);
}

std::optional<SimilarityResultId> SimilaritySessionNode::GetResolvedResult(SimilarityEntityId entity)
{
	BNSimilarityResultId result;
	if (!BNSimilaritySessionNodeGetResolvedResult(m_object, entity, &result))
		return std::nullopt;
	return result;
}

bool SimilaritySessionNode::ClearResolvedResult(SimilarityEntityId entity)
{
	return BNSimilaritySessionNodeClearResolvedResult(m_object, entity);
}


std::vector<SimilaritySessionNodeId> SimilaritySessionNode::GetIncomingEdges()
{
	size_t count;
	BNSimilaritySessionNodeId* edges = BNSimilaritySessionNodeGetIncomingEdges(m_object, &count);
	std::vector<SimilaritySessionNodeId> result;
	result.reserve(count);
	for (size_t i = 0; i < count; ++i)
		result.push_back(edges[i]);
	BNFreeSimilaritySessionNodeEdgeList(edges);
	return result;
}


std::vector<SimilaritySessionNodeId> SimilaritySessionNode::GetOutgoingEdges()
{
	size_t count;
	BNSimilaritySessionNodeId* edges = BNSimilaritySessionNodeGetOutgoingEdges(m_object, &count);
	std::vector<SimilaritySessionNodeId> result;
	result.reserve(count);
	for (size_t i = 0; i < count; ++i)
		result.push_back(edges[i]);
	BNFreeSimilaritySessionNodeEdgeList(edges);
	return result;
}


std::vector<Ref<SimilaritySessionNode>> SimilaritySessionNode::GetIncomingNodes()
{
	size_t count = 0;
	BNSimilaritySessionNode** nodes = BNSimilaritySessionNodeGetIncomingNodes(m_object, &count);
	std::vector<Ref<SimilaritySessionNode>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(nodes[i])));
	BNFreeSimilaritySessionNodeList(nodes, count);
	return result;
}


std::vector<Ref<SimilaritySessionNode>> SimilaritySessionNode::GetOutgoingNodes()
{
	size_t count = 0;
	BNSimilaritySessionNode** nodes = BNSimilaritySessionNodeGetOutgoingNodes(m_object, &count);
	std::vector<Ref<SimilaritySessionNode>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(nodes[i])));
	BNFreeSimilaritySessionNodeList(nodes, count);
	return result;
}


SimilaritySessionGraph::SimilaritySessionGraph(BNSimilaritySessionGraph* graph)
{
	m_object = graph;
}


void SimilaritySessionGraph::AddNode(Ref<SimilaritySessionNode> node)
{
	BNSimilaritySessionGraphAddNode(m_object, node->GetObject());
}


void SimilaritySessionGraph::RemoveNode(SimilaritySessionNode& node)
{
	BNSimilaritySessionGraphRemoveNode(m_object, node.GetObject());
}


Ref<SimilaritySessionNode> SimilaritySessionGraph::GetNode(const SimilaritySessionNodeId id)
{
	BNSimilaritySessionNode* node = BNSimilaritySessionGraphGetNode(m_object, id);
	if (!node)
		return nullptr;
	return new SimilaritySessionNode(node);
}


std::vector<Ref<SimilaritySessionNode>> SimilaritySessionGraph::GetNodes()
{
	size_t count;
	BNSimilaritySessionNode** nodes = BNSimilaritySessionGraphGetNodes(m_object, &count);
	std::vector<Ref<SimilaritySessionNode>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(nodes[i])));
	BNFreeSimilaritySessionNodeList(nodes, count);
	return result;
}


bool SimilaritySessionGraph::IsValidEdge(SimilaritySessionNode& from, SimilaritySessionNode& to)
{
	return BNSimilaritySessionGraphIsValidEdge(m_object, from.GetObject(), to.GetObject());
}


bool SimilaritySessionGraph::AddEdge(SimilaritySessionNode& from, SimilaritySessionNode& to)
{
	return BNSimilaritySessionGraphAddEdge(m_object, from.GetObject(), to.GetObject());
}


bool SimilaritySessionGraph::RemoveEdge(SimilaritySessionNode& from, SimilaritySessionNode& to)
{
	return BNSimilaritySessionGraphRemoveEdge(m_object, from.GetObject(), to.GetObject());
}


void SimilaritySessionGraph::AddReceiver(Ref<SimilaritySessionGraphReceiver> receiver)
{
	BNSimilaritySessionGraphAddReceiver(m_object, receiver->GetObject());
}


void SimilaritySessionGraph::RemoveReceiver(SimilaritySessionGraphReceiver& receiver)
{
	BNSimilaritySessionGraphRemoveReceiver(m_object, receiver.GetObject());
}


std::vector<Ref<SimilaritySessionGraphReceiver>> SimilaritySessionGraph::GetReceivers()
{
	size_t count = 0;
	BNSimilaritySessionGraphReceiver** receivers = BNSimilaritySessionGraphGetReceivers(m_object, &count);
	std::vector<Ref<SimilaritySessionGraphReceiver>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(
			new CoreSimilaritySessionGraphReceiver(BNNewSimilaritySessionGraphReceiverReference(receivers[i])));
	}
	BNFreeSimilaritySessionGraphReceiverList(receivers, count);
	return result;
}


std::vector<std::vector<Ref<SimilaritySessionNode>>> SimilaritySessionGraph::GetSchedule()
{
	size_t* nodeCounts;
	size_t levelCount;
	BNSimilaritySessionNode*** schedule = BNSimilaritySessionGraphGetSchedule(m_object, &nodeCounts, &levelCount);

	std::vector<std::vector<Ref<SimilaritySessionNode>>> result(levelCount);
	for (size_t i = 0; i < levelCount; i++)
	{
		result[i].reserve(nodeCounts[i]);
		for (size_t j = 0; j < nodeCounts[i]; j++)
			result[i].push_back(new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(schedule[i][j])));
	}
	BNFreeSimilaritySessionNodeSchedule(schedule, nodeCounts, levelCount);
	return result;
}


SimilaritySessionGraphReceiver::SimilaritySessionGraphReceiver(BNSimilaritySessionGraphReceiver* receiver)
{
	m_object = receiver;
}


SimilaritySessionGraphReceiver::SimilaritySessionGraphReceiver()
{
	BNCustomSimilaritySessionGraphReceiver cb {};
	cb.context = this;
	cb.onGraphChanged = OnGraphChangedCallback;
	cb.free = FreeContextCallback;

	AddRefForRegistration();
	m_object = BNCreateCustomSimilaritySessionGraphReceiver(&cb);
}


CoreSimilaritySessionGraphReceiver::CoreSimilaritySessionGraphReceiver(BNSimilaritySessionGraphReceiver* receiver) :
	SimilaritySessionGraphReceiver(receiver)
{}


void CoreSimilaritySessionGraphReceiver::NotifyGraphChanged()
{
	BNSimilaritySessionGraphReceiverNotifyGraphChanged(m_object);
}


SimilaritySession::SimilaritySession(BNSimilaritySession* session)
{
	m_object = session;
}


SimilaritySession::SimilaritySession()
{
	m_object = BNCreateSimilaritySession();
}

SimilaritySessionId SimilaritySession::GetId() const
{
	return BNSimilaritySessionGetId(m_object);
}


void SimilaritySession::AddProvider(Ref<SimilarityProvider> provider)
{
	BNSimilaritySessionAddProvider(m_object, provider->GetObject());
}


void SimilaritySession::RemoveProvider(SimilarityProvider& provider)
{
	BNSimilaritySessionRemoveProvider(m_object, provider.GetObject());
}

bool SimilaritySession::UpdateProviderSettings(SimilarityProvider& provider, Settings& settings)
{
	return BNSimilaritySessionUpdateProviderSettings(m_object, provider.GetObject(), settings.GetObject());
}


Ref<SimilarityProvider> SimilaritySession::GetProvider(SimilarityProviderId id)
{
	BNSimilarityProvider* provider = BNSimilaritySessionGetProvider(m_object, id);
	if (!provider)
		return nullptr;
	return new CoreSimilarityProvider(provider);
}


std::vector<Ref<SimilarityProvider>> SimilaritySession::GetProviders()
{
	size_t count;
	BNSimilarityProvider** providers = BNSimilaritySessionGetProviders(m_object, &count);
	std::vector<Ref<SimilarityProvider>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreSimilarityProvider(BNNewSimilarityProviderReference(providers[i])));
	BNFreeSimilarityProviderList(providers, count);
	return result;
}


bool SimilaritySession::AddResolver(Ref<SimilaritySessionResolver> resolver)
{
	return BNSimilaritySessionAddResolver(m_object, resolver->GetObject());
}


bool SimilaritySession::RemoveResolver(SimilaritySessionResolver& resolver)
{
	return BNSimilaritySessionRemoveResolver(m_object, resolver.GetObject());
}

bool SimilaritySession::UpdateResolverSettings(SimilaritySessionResolver& resolver, Settings& settings)
{
	return BNSimilaritySessionUpdateResolverSettings(m_object, resolver.GetObject(), settings.GetObject());
}


Ref<SimilaritySessionResolver> SimilaritySession::GetResolver(SimilaritySessionResolverId id)
{
	BNSimilaritySessionResolver* resolver = BNSimilaritySessionGetResolver(m_object, id);
	if (!resolver)
		return nullptr;
	return new CoreSimilaritySessionResolver(resolver);
}


std::vector<Ref<SimilaritySessionResolver>> SimilaritySession::GetResolvers()
{
	size_t count;
	BNSimilaritySessionResolver** resolvers = BNSimilaritySessionGetResolvers(m_object, &count);
	std::vector<Ref<SimilaritySessionResolver>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreSimilaritySessionResolver(BNNewSimilaritySessionResolverReference(resolvers[i])));
	BNFreeSimilaritySessionResolverList(resolvers, count);
	return result;
}


Ref<SimilaritySessionGraph> SimilaritySession::GetGraph()
{
	return new SimilaritySessionGraph(BNSimilaritySessionGetGraph(m_object));
}


void SimilaritySession::AddReceiver(Ref<SimilaritySessionReceiver> receiver)
{
	BNSimilaritySessionAddReceiver(m_object, receiver->GetObject());
}


void SimilaritySession::RemoveReceiver(SimilaritySessionReceiver& receiver)
{
	BNSimilaritySessionRemoveReceiver(m_object, receiver.GetObject());
}


std::vector<Ref<SimilaritySessionReceiver>> SimilaritySession::GetReceivers()
{
	size_t count;
	BNSimilaritySessionReceiver** receivers = BNSimilaritySessionGetReceivers(m_object, &count);
	std::vector<Ref<SimilaritySessionReceiver>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreSimilaritySessionReceiver(BNNewSimilaritySessionReceiverReference(receivers[i])));
	BNFreeSimilaritySessionReceiverList(receivers, count);
	return result;
}


Ref<SimilaritySessionCompletion> SimilaritySession::Run()
{
	return new SimilaritySessionCompletion(BNSimilaritySessionRun(m_object));
}


SimilaritySessionReceiver::SimilaritySessionReceiver(BNSimilaritySessionReceiver* receiver)
{
	m_object = receiver;
}


SimilaritySessionReceiver::SimilaritySessionReceiver()
{
	BNCustomSimilaritySessionReceiver cb {};
	cb.context = this;
	cb.onStarted = OnStartedCallback;
	cb.onUpdated = OnUpdatedCallback;
	cb.free = FreeContextCallback;

	AddRefForRegistration();
	m_object = BNCreateCustomSimilaritySessionReceiver(&cb);
}


CoreSimilaritySessionReceiver::CoreSimilaritySessionReceiver(BNSimilaritySessionReceiver* receiver) :
	SimilaritySessionReceiver(receiver)
{}


void CoreSimilaritySessionReceiver::NotifyStart(SimilaritySessionCompletion& completion)
{
	BNSimilaritySessionReceiverNotifyStart(m_object, completion.GetObject());
}


void CoreSimilaritySessionReceiver::NotifyBatch(
	SimilaritySessionNode& node, SimilarityProvider& provider, const std::vector<SimilarityEntityId>& entities)
{
	std::vector<BNSimilarityEntityId> coreEntities;
	coreEntities.reserve(entities.size());
	for (const auto& entity : entities)
		coreEntities.push_back(entity);
	BNSimilaritySessionReceiverNotifyBatch(
		m_object, node.GetObject(), provider.GetObject(), coreEntities.data(), coreEntities.size());
}


SimilaritySessionCompletion::SimilaritySessionCompletion(BNSimilaritySessionCompletion* completion)
{
	m_object = completion;
}


SimilaritySessionCompletion::SimilaritySessionCompletion()
{
	m_object = BNCreateSimilaritySessionCompletion();
}

bool SimilaritySessionCompletion::IsFinished() const
{
	return BNSimilaritySessionCompletionIsFinished(m_object);
}

void SimilaritySessionCompletion::RequestStop()
{
	BNSimilaritySessionCompletionRequestStop(m_object);
}

bool SimilaritySessionCompletion::IsStopRequested() const
{
	return BNSimilaritySessionCompletionIsStopRequested(m_object);
}

double SimilaritySessionCompletion::GetProgress(const SimilaritySessionCompletionQuery& query) const
{
	const BNSimilaritySessionCompletionQuery rawQuery = query.ToRaw();
	return BNSimilaritySessionCompletionGetProgress(m_object, &rawQuery);
}

void SimilaritySessionCompletion::SetProgress(const SimilaritySessionCompletionQuery& query, double progress)
{
	const BNSimilaritySessionCompletionQuery rawQuery = query.ToRaw();
	BNSimilaritySessionCompletionSetProgress(m_object, &rawQuery, progress);
}

std::chrono::milliseconds SimilaritySessionCompletion::GetTiming(const SimilaritySessionCompletionQuery& query) const
{
	const BNSimilaritySessionCompletionQuery rawQuery = query.ToRaw();
	return std::chrono::milliseconds(BNSimilaritySessionCompletionGetTiming(m_object, &rawQuery));
}


BNSimilarityProvider* SimilarityProviderType::CreateCallback(void* ctxt, BNSettings* settings)
{
	return RunSimilarityCallback<
		BNSimilarityProvider*>("Unhandled exception creating similarity provider", nullptr, [&]() {
		SimilarityProviderType* type = (SimilarityProviderType*)ctxt;
		Ref<Settings> settingsObj = new Settings(BNNewSettingsReference(settings));
		Ref<SimilarityProvider> result = type->Create(*settingsObj);
		if (!result)
			return static_cast<BNSimilarityProvider*>(nullptr);
		return BNNewSimilarityProviderReference(result->GetObject());
	});
}


BNSettings* SimilarityProviderType::GetDefaultSettingsCallback(void* ctxt)
{
	return RunSimilarityCallback<
		BNSettings*>("Unhandled exception getting similarity provider settings", nullptr, [&]() {
		SimilarityProviderType* type = (SimilarityProviderType*)ctxt;
		Ref<Settings> result = type->GetDefaultSettings();
		if (!result)
			return static_cast<BNSettings*>(nullptr);
		return BNNewSettingsReference(result->m_object);
	});
}


bool SimilarityProvider::VisitNodeCallback(void* ctxt, BNSimilaritySessionNode* node,
	BNSimilarityProviderResults* results, BNSimilaritySessionCompletion* completion)
{
	try
	{
		CallbackRef<SimilarityProvider> provider(ctxt);
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		SimilarityProviderResults resultsObj(results);
		Ref<SimilaritySessionCompletion> completionObj =
			new SimilaritySessionCompletion(BNNewSimilaritySessionCompletionReference(completion));
		return provider->VisitNode(*nodeObj, resultsObj, *completionObj);
	}
	catch (const std::exception& exception)
	{
		LogErrorForException(exception, "Unhandled exception in similarity provider node visit");
		return false;
	}
	catch (...)
	{
		LogError("Unhandled exception in similarity provider node visit");
		return false;
	}
}


bool SimilarityProvider::VisitNodeEdgeCallback(void* ctxt, BNSimilaritySessionNode* from, BNSimilaritySessionNode* to,
	BNSimilarityProviderResults* results, BNSimilaritySessionCompletion* completion)
{
	try
	{
		CallbackRef<SimilarityProvider> provider(ctxt);
		Ref<SimilaritySessionNode> fromObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(from));
		Ref<SimilaritySessionNode> toObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(to));
		SimilarityProviderResults resultsObj(results);
		Ref<SimilaritySessionCompletion> completionObj =
			new SimilaritySessionCompletion(BNNewSimilaritySessionCompletionReference(completion));
		return provider->VisitNodeEdge(*fromObj, *toObj, resultsObj, *completionObj);
	}
	catch (const std::exception& exception)
	{
		LogErrorForException(exception, "Unhandled exception in similarity provider edge visit");
		return false;
	}
	catch (...)
	{
		LogError("Unhandled exception in similarity provider edge visit");
		return false;
	}
}


char* SimilarityProvider::GetNameCallback(
	void* ctxt, BNSimilaritySessionNode* node, BNSimilarityEntityId entity, BNSimilarityResultId resultId)
{
	return RunSimilarityCallback<char*>("Unhandled exception getting similarity result name", nullptr, [&]() {
		CallbackRef<SimilarityProvider> provider(ctxt);
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		std::optional<std::string> name = provider->GetName(*nodeObj, entity, resultId);
		if (!name)
			return static_cast<char*>(nullptr);
		return BNAllocString(name->c_str());
	});
}


BNSimilarityApplyStatus SimilarityProvider::ApplyCallback(void* ctxt, BNSimilaritySessionNode* node,
	BNSimilarityEntityId entity, BNSimilarityResultId resultId)
{
	return RunSimilarityCallback("Unhandled exception applying similarity result", SimilarityApplyFailed, [&]() {
		CallbackRef<SimilarityProvider> provider(ctxt);
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		return provider->Apply(*nodeObj, entity, resultId);
	});
}


void SimilarityProvider::RenderCallback(void* ctxt, BNSimilaritySessionNode* node,
	BNSimilarityEntityId entity, BNSimilarityRenderContext* context, BNSimilarityResultId resultId)
{
	RunSimilarityCallback("Unhandled exception rendering similarity result", [&]() {
		CallbackRef<SimilarityProvider> provider(ctxt);
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		Ref<SimilarityRenderContext> contextObj =
			new SimilarityRenderContext(BNNewSimilarityRenderContextReference(context));
		provider->Render(*nodeObj, entity, *contextObj, resultId);
	});
}


void SimilarityProvider::FreeContextCallback(void* ctxt)
{
	SimilarityProvider* provider = (SimilarityProvider*)ctxt;
	provider->ReleaseForRegistration();
}


void SimilaritySessionResolver::ResolveForNodeCallback(void* ctxt, BNSimilaritySession* session,
	BNSimilaritySessionNode* node, const BNSimilarityEntityId* entities, size_t entityCount,
	BNSimilaritySessionCompletion* completion, BNSimilaritySessionResolverId resolverId)
{
	RunSimilarityCallback("Unhandled exception resolving similarity results", [&]() {
		(void)resolverId;
		CallbackRef<SimilaritySessionResolver> resolver(ctxt);
		Ref<SimilaritySession> sessionObj = new SimilaritySession(BNNewSimilaritySessionReference(session));
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		Ref<SimilaritySessionCompletion> completionObj =
			new SimilaritySessionCompletion(BNNewSimilaritySessionCompletionReference(completion));
		std::vector<SimilarityEntityId> entityList;
		entityList.reserve(entityCount);
		for (size_t i = 0; i < entityCount; i++)
			entityList.push_back(entities[i]);
		resolver->ResolveForNode(*sessionObj, *nodeObj, entityList, *completionObj);
	});
}


void SimilaritySessionResolver::PrepareForNodeCallback(void* ctxt, BNSimilaritySession* session,
	BNSimilaritySessionNode* node, BNSimilaritySessionCompletion* completion, BNSimilaritySessionResolverId resolverId)
{
	RunSimilarityCallback("Unhandled exception preparing similarity resolver", [&]() {
		(void)resolverId;
		CallbackRef<SimilaritySessionResolver> resolver(ctxt);
		Ref<SimilaritySession> sessionObj = new SimilaritySession(BNNewSimilaritySessionReference(session));
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		Ref<SimilaritySessionCompletion> completionObj =
			new SimilaritySessionCompletion(BNNewSimilaritySessionCompletionReference(completion));
		resolver->PrepareForNode(*sessionObj, *nodeObj, *completionObj);
	});
}


void SimilaritySessionResolver::FreeContextCallback(void* ctxt)
{
	SimilaritySessionResolver* resolver = (SimilaritySessionResolver*)ctxt;
	resolver->ReleaseForRegistration();
}


void SimilaritySessionReceiver::OnStartedCallback(void* ctxt, BNSimilaritySessionCompletion* completion)
{
	RunSimilarityCallback("Unhandled exception starting similarity session receiver", [&]() {
		CallbackRef<SimilaritySessionReceiver> receiver(ctxt);
		Ref<SimilaritySessionCompletion> completionObj =
			new SimilaritySessionCompletion(BNNewSimilaritySessionCompletionReference(completion));
		receiver->NotifyStart(*completionObj);
	});
}


void SimilaritySessionReceiver::OnUpdatedCallback(void* ctxt, BNSimilaritySessionNode* node,
	BNSimilarityProvider* provider, const BNSimilarityEntityId* entities, size_t count)
{
	RunSimilarityCallback("Unhandled exception updating similarity session receiver", [&]() {
		CallbackRef<SimilaritySessionReceiver> receiver(ctxt);
		Ref<SimilaritySessionNode> nodeObj = new SimilaritySessionNode(BNNewSimilaritySessionNodeReference(node));
		Ref<SimilarityProvider> providerObj = new CoreSimilarityProvider(BNNewSimilarityProviderReference(provider));

		std::vector<SimilarityEntityId> entityList;
		entityList.reserve(count);
		for (size_t i = 0; i < count; i++)
			entityList.push_back(entities[i]);

		receiver->NotifyBatch(*nodeObj, *providerObj, entityList);
	});
}


void SimilaritySessionReceiver::FreeContextCallback(void* ctxt)
{
	SimilaritySessionReceiver* receiver = (SimilaritySessionReceiver*)ctxt;
	receiver->ReleaseForRegistration();
}


void SimilaritySessionGraphReceiver::OnGraphChangedCallback(void* ctxt)
{
	RunSimilarityCallback("Unhandled exception updating similarity session graph receiver", [&]() {
		CallbackRef<SimilaritySessionGraphReceiver> receiver(ctxt);
		receiver->NotifyGraphChanged();
	});
}


void SimilaritySessionGraphReceiver::FreeContextCallback(void* ctxt)
{
	SimilaritySessionGraphReceiver* receiver = (SimilaritySessionGraphReceiver*)ctxt;
	receiver->ReleaseForRegistration();
}
