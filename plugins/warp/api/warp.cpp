#include "warpcore.h"
#include "warp.h"

#include <utility>

using namespace Warp;

std::optional<WarpUUID> WarpUUID::FromString(const std::string &str)
{
    BNWARPUUID uuid = {};
    if (!BNWARPUUIDFromString(str.c_str(), &uuid))
        return std::nullopt;
    return WarpUUID(uuid);
}

std::string WarpUUID::ToString() const
{
    char *str = BNWARPUUIDGetString(&uuid);
    std::string result = str;
    BNFreeString(str);
    return result;
}

Target::Target(BNWARPTarget *target)
{
    m_object = target;
}

Ref<Target> Target::FromPlatform(const BinaryNinja::Platform &platform)
{
    BNWARPTarget *result = BNWARPGetTarget(platform.m_object);
    if (!result)
        return nullptr;
    return new Target(result);
}

Constraint::Constraint(ConstraintGUID guid, std::optional<int64_t> offset)
{
    this->guid = guid;
    this->offset = offset;
}

Constraint Constraint::FromAPIObject(BNWARPConstraint *constraint)
{
    auto offset = constraint->offset == INT64_MAX ? std::nullopt : std::optional(constraint->offset);
    return {constraint->guid, offset};
}

FunctionComment::FunctionComment(std::string text, int64_t offset)
{
    this->text = std::move(text);
    this->offset = offset;
}

FunctionComment FunctionComment::FromAPIObject(BNWARPFunctionComment *comment)
{
    return {comment->text, comment->offset};
}

Function::Function(BNWARPFunction *function)
{
    m_object = function;
}

FunctionGUID Function::GetGUID() const
{
    return BNWARPFunctionGetGUID(m_object);
}

std::string Function::GetSymbolName() const
{
    char *name = BNWARPFunctionGetSymbolName(m_object);
    std::string result = name;
    BNFreeString(name);
    return result;
}

BinaryNinja::Ref<BinaryNinja::Symbol> Function::GetSymbol(const BinaryNinja::Function &function) const
{
    BNSymbol *symbol = BNWARPFunctionGetSymbol(m_object, function.m_object);
    if (!symbol)
        return nullptr;
    return new BinaryNinja::Symbol(symbol);
}

BinaryNinja::Ref<BinaryNinja::Type> Function::GetType(const BinaryNinja::Function &function) const
{
    BNType *type = BNWARPFunctionGetType(m_object, function.m_object);
    if (!type)
        return nullptr;
    return new BinaryNinja::Type(type);
}

std::vector<Constraint> Function::GetConstraints() const
{
    size_t count;
    BNWARPConstraint *constraints = BNWARPFunctionGetConstraints(m_object, &count);
    std::vector<Constraint> result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.push_back(Constraint::FromAPIObject(&constraints[i]));
    BNWARPFreeConstraintList(constraints, count);
    return result;
}

std::vector<FunctionComment> Function::GetComments() const
{
    size_t count;
    BNWARPFunctionComment *comments = BNWARPFunctionGetComments(m_object, &count);
    std::vector<FunctionComment> result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.push_back(FunctionComment::FromAPIObject(&comments[i]));
    BNWARPFreeFunctionCommentList(comments, count);
    return result;
}

Ref<Function> Function::Get(const BinaryNinja::Function &function)
{
    BNWARPFunction *result = BNWARPGetFunction(function.m_object);
    if (!result)
        return nullptr;
    return new Function(result);
}

Ref<Function> Function::GetMatched(const BinaryNinja::Function &function)
{
    BNWARPFunction *result = BNWARPGetMatchedFunction(function.m_object);
    if (!result)
        return nullptr;
    return new Function(result);
}

void Function::Apply(const BinaryNinja::Function &function) const
{
    BNWARPFunctionApply(m_object, function.m_object);
}

void Function::RemoveMatch(const BinaryNinja::Function &function)
{
    BNWARPFunctionApply(nullptr, function.m_object);
}

ContainerSearchQuery::ContainerSearchQuery(BNWARPContainerSearchQuery *query)
{
    m_object = query;
}

ContainerSearchQuery::ContainerSearchQuery(const std::string &query)
{
    m_object = BNWARPNewContainerSearchQuery(query.c_str(), nullptr, nullptr, nullptr, nullptr, 0);
}

ContainerSearchQuery::ContainerSearchQuery(const std::string &query, const Source &source)
{
    m_object = BNWARPNewContainerSearchQuery(query.c_str(), nullptr, nullptr, source.Raw(), nullptr, 0);
}

ContainerSearchQuery::ContainerSearchQuery(const std::string &query, size_t offset, size_t limit, const std::optional<Source> &source, const std::vector<SourceTag> &tags)
{
    size_t tagCount = tags.size();
    const char** rawTags = new const char*[tagCount];
    for (size_t i = 0; i < tagCount; i++)
        rawTags[i] = tags[i].c_str();
    if (source)
        m_object = BNWARPNewContainerSearchQuery(query.c_str(), &offset, &limit, source.value().Raw(), rawTags, tagCount);
    else
        m_object = BNWARPNewContainerSearchQuery(query.c_str(), &offset, &limit, nullptr, rawTags, tagCount);
    delete[] rawTags;
}

ContainerSearchItem::ContainerSearchItem(BNWARPContainerSearchItem *item)
{
    m_object = item;
}

BNWARPContainerSearchItemKind ContainerSearchItem::GetKind() const
{
    return BNWARPContainerSearchItemGetKind(m_object);
}

Source ContainerSearchItem::GetSource() const
{
    return BNWARPContainerSearchItemGetSource(m_object);
}

BinaryNinja::Ref<BinaryNinja::Type> ContainerSearchItem::GetType(const BinaryNinja::Ref<BinaryNinja::Architecture> &arch) const
{
    BNType *type = BNWARPContainerSearchItemGetType(arch ? arch->m_object : nullptr, m_object);
    if (!type)
        return nullptr;
    return new BinaryNinja::Type(type);
}

std::string ContainerSearchItem::GetName() const
{
    // NOTE: In the future we may want the name to be optional, see rust core side for more info.
    char *rawName = BNWARPContainerSearchItemGetName(m_object);
    std::string name = rawName;
    BNFreeString(rawName);
    return name;
}

Ref<Function> ContainerSearchItem::GetFunction() const
{
    BNWARPFunction *function = BNWARPContainerSearchItemGetFunction(m_object);
    if (!function)
        return nullptr;
    return new Function(function);
}


ContainerSearchResponse::ContainerSearchResponse(std::vector<Ref<ContainerSearchItem>>&& items, size_t offset,
    size_t total)
{
    this->items = std::move(items);
    this->offset = offset;
    this->total = total;
}

ContainerSearchResponse ContainerSearchResponse::FromAPIObject(BNWARPContainerSearchResponse *response)
{
    std::vector<Ref<ContainerSearchItem>> items;
    items.reserve(response->count);
    for (int i = 0; i < response->count; i++)
        items.push_back(new ContainerSearchItem(BNWARPNewContainerSearchItemReference(response->items[i])));
    ContainerSearchResponse resp = {std::move(items), response->offset, response->total};
    BNWARPFreeContainerSearchResponse(response);
    return resp;
}

Container::Container(BNWARPContainer *container)
{
    m_object = container;
}

std::vector<Ref<Container> > Container::All()
{
    size_t count;
    BNWARPContainer **containers = BNWARPGetContainers(&count);
    std::vector<Ref<Container> > result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.push_back(new Container(BNWARPNewContainerReference(containers[i])));
    BNWARPFreeContainerList(containers, count);
    return result;
}

std::string Container::GetName() const
{
    char *rawName = BNWARPContainerGetName(m_object);
    std::string name = rawName;
    BNFreeString(rawName);
    return name;
}

std::vector<Source> Container::GetSources() const
{
    size_t count;
    BNWARPSource *sources = BNWARPContainerGetSources(m_object, &count);
    std::vector<Source> result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.emplace_back(sources[i]);
    BNWARPFreeUUIDList(sources, count);
    return result;
}

std::optional<Source> Container::AddSource(const std::string &sourcePath) const
{
    Source source;
    if (!BNWARPContainerAddSource(m_object, sourcePath.c_str(), source.RawMut()))
        return std::nullopt;
    return source;
}

bool Container::CommitSource(const Source &source) const
{
    return BNWARPContainerCommitSource(m_object, source.Raw());
}

bool Container::IsSourceUncommitted(const Source &source) const
{
    return BNWARPContainerIsSourceUncommitted(m_object, source.Raw());
}

bool Container::IsSourceWritable(const Source &source) const
{
    return BNWARPContainerIsSourceWritable(m_object, source.Raw());
}

std::optional<std::string> Container::SourcePath(const Source &source) const
{
    char *rawPath = BNWARPContainerGetSourcePath(m_object, source.Raw());
    if (!rawPath)
        return std::nullopt;
    std::string path = rawPath;
    BNFreeString(rawPath);
    return path;
}

bool Container::AddFunctions(const Target &target, const Source &source, const std::vector<Ref<Function> > &functions) const
{
    size_t count = functions.size();
    BNWARPFunction **apiFunctions = new BNWARPFunction *[count];
    for (size_t i = 0; i < count; i++)
        apiFunctions[i] = functions[i]->m_object;
    const bool result = BNWARPContainerAddFunctions(m_object, target.m_object, source.Raw(), apiFunctions, count);
    delete[] apiFunctions;
    return result;
}

bool Container::AddTypes(const BinaryNinja::BinaryView &view, const Source &source,
                         const std::vector<BinaryNinja::Ref<BinaryNinja::Type> > &types) const
{
    size_t count = types.size();
    BNType **apiTypes = new BNType *[count];
    for (size_t i = 0; i < count; i++)
        apiTypes[i] = types[i]->m_object;
    const bool result = BNWARPContainerAddTypes(view.m_object, m_object, source.Raw(), apiTypes, count);
    delete[] apiTypes;
    return result;
}

bool Container::RemoveFunctions(const Target &target, const Source &source,
    const std::vector<Ref<Function>> &functions) const
{
    size_t count = functions.size();
    BNWARPFunction **apiFunctions = new BNWARPFunction *[count];
    for (size_t i = 0; i < count; i++)
        apiFunctions[i] = functions[i]->m_object;
    const bool result = BNWARPContainerRemoveFunctions(m_object, target.m_object, source.Raw(), apiFunctions, count);
    delete[] apiFunctions;
    return result;
}

bool Container::RemoveTypes(const Source &source, const std::vector<TypeGUID> &guids) const
{
    size_t count = guids.size();
    BNWARPTypeGUID* apiGuids = new BNWARPTypeGUID[count];
    for (size_t i = 0; i < count; i++)
        apiGuids[i] = *guids[i].Raw();
    const bool result = BNWARPContainerRemoveTypes(m_object, source.Raw(), apiGuids, count);
    delete[] apiGuids;
    return result;
}

void Container::FetchFunctions(const Target &target, const std::vector<FunctionGUID> &guids, const std::vector<SourceTag> &tags) const
{
    size_t count = guids.size();
    BNWARPFunctionGUID *apiGuids = new BNWARPFunctionGUID[count];
    for (size_t i = 0; i < count; i++)
        apiGuids[i] = *guids[i].Raw();
    size_t tagCount = tags.size();
    const char** rawTags = new const char*[tagCount];
    for (size_t i = 0; i < tagCount; i++)
        rawTags[i] = tags[i].c_str();
    BNWARPContainerFetchFunctions(m_object, target.m_object, rawTags, tagCount, apiGuids, count);
    delete[] apiGuids;
    delete[] rawTags;
}

std::vector<Source> Container::GetSourcesWithFunctionGUID(const Target& target, const FunctionGUID &guid) const
{
    size_t count;
    BNWARPSource *sources = BNWARPContainerGetSourcesWithFunctionGUID(m_object, target.m_object, guid.Raw(), &count);
    std::vector<Source> result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.emplace_back(sources[i]);
    BNWARPFreeUUIDList(sources, count);
    return result;
}

std::vector<Source> Container::GetSourcesWithTypeGUID(const TypeGUID &guid) const
{
    size_t count;
    BNWARPSource *sources = BNWARPContainerGetSourcesWithTypeGUID(m_object, guid.Raw(), &count);
    std::vector<Source> result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.emplace_back(sources[i]);
    BNWARPFreeUUIDList(sources, count);
    return result;
}

std::vector<Ref<Function> > Container::GetFunctionsWithGUID(const Target& target, const Source &source, const FunctionGUID &guid) const
{
    size_t count;
    BNWARPFunction **functions = BNWARPContainerGetFunctionsWithGUID(m_object, target.m_object, source.Raw(), guid.Raw(), &count);
    std::vector<Ref<Function> > result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.push_back(new Function(BNWARPNewFunctionReference(functions[i])));
    BNWARPFreeFunctionList(functions, count);
    return result;
}

BinaryNinja::Ref<BinaryNinja::Type> Container::GetTypeWithGUID(const BinaryNinja::Architecture &arch,
                                                               const Source &source, const TypeGUID &guid) const
{
    BNType *type = BNWARPContainerGetTypeWithGUID(arch.m_object, m_object, source.Raw(), guid.Raw());
    return new BinaryNinja::Type(type);
}

std::vector<TypeGUID> Container::GetTypeGUIDsWithName(const Source &source, const std::string &name) const
{
    size_t count;
    BNWARPTypeGUID *guids = BNWARPContainerGetTypeGUIDsWithName(m_object, source.Raw(), name.c_str(), &count);
    std::vector<TypeGUID> result;
    result.reserve(count);
    for (int i = 0; i < count; i++)
        result.emplace_back(guids[i]);
    BNWARPFreeUUIDList(guids, count);
    return result;
}

std::optional<ContainerSearchResponse> Container::Search(const ContainerSearchQuery &query) const
{
    BNWARPContainerSearchResponse *response = BNWARPContainerSearch(m_object, query.m_object);
    if (!response)
        return std::nullopt;
    return ContainerSearchResponse::FromAPIObject(response);
}

void Warp::RunMatcher(const BinaryNinja::BinaryView &view)
{
    BNWARPRunMatcher(view.m_object);
}

bool IsInstructionVariant(const BinaryNinja::LowLevelILFunction &function, BinaryNinja::ExprId idx)
{
    return BNWARPIsLiftedInstructionVariant(function.m_object, idx);
}

bool IsInstructionBlacklisted(const BinaryNinja::LowLevelILFunction &function, BinaryNinja::ExprId idx)
{
    return BNWARPIsLiftedInstructionBlacklisted(function.m_object, idx);
}

bool IsInstructionComputedVariant(const BinaryNinja::LowLevelILFunction &function, BinaryNinja::ExprId idx)
{
    return BNWARPIsLowLevelInstructionComputedVariant(function.m_object, idx);
}

std::optional<FunctionGUID> Warp::GetAnalysisFunctionGUID(const BinaryNinja::Function &function)
{
    FunctionGUID guid;
    if (!BNWARPGetAnalysisFunctionGUID(function.m_object, guid.RawMut()))
        return std::nullopt;
    return guid;
}

std::optional<BasicBlockGUID> Warp::GetBasicBlockGUID(const BinaryNinja::BasicBlock &basicBlock)
{
    BasicBlockGUID guid;
    if (!BNWARPGetBasicBlockGUID(basicBlock.m_object, guid.RawMut()))
        return std::nullopt;
    return guid;
}
