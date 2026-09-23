#pragma once

#include "binaryninjaapi.h"
#include <algorithm>
#include <tuple>

using namespace BinaryNinja;

static inline auto GetFunctionSemanticKey(Ref<Function> func)
{
	return std::make_tuple(func ? func->GetStart() : 0,
		func && func->GetPlatform() ? func->GetPlatform()->GetName() : std::string());
}

static inline void SortCodeReferences(std::vector<ReferenceSource>& refs)
{
	// Core reference ordering includes object pointers. Resolve in semantic order before allocating names or
	// applying annotations, including when references from multiple service types have been merged.
	auto key = [](const ReferenceSource& ref) {
		return std::tuple_cat(GetFunctionSemanticKey(ref.func),
			std::make_tuple(ref.arch ? ref.arch->GetName() : std::string(), ref.addr));
	};
	std::sort(refs.begin(), refs.end(), [&](const auto& left, const auto& right) { return key(left) < key(right); });
}

static inline void SortAnalysisFunctions(std::vector<Ref<Function>>& funcs)
{
	std::sort(funcs.begin(), funcs.end(), [](const auto& left, const auto& right) {
		return GetFunctionSemanticKey(left) < GetFunctionSemanticKey(right);
	});
}

static inline std::string GetOriginalTypeName(Ref<Type> type)
{
	std::string result;
	if (!type)
		return result;

	if (type->IsPointer())
	{
		auto childType = type->GetChildType().GetValue();
		if (childType && childType->IsNamedTypeRefer())
		{
			return childType->GetNamedTypeReference()->GetName().GetString();
		}
		return type->GetTypeName().GetString();
	}
	if (type->IsNamedTypeRefer())
		return type->GetNamedTypeReference()->GetName().GetString();

	return type->GetTypeName().GetString();
}

static inline std::string GetVarNameForTypeStr(const std::string typeStr)
{
	std::istringstream iss(typeStr);
	std::string word;
	std::string result;

	while (std::getline(iss, word, '_'))
	{
		if (!word.empty())
		{
			word[0] = std::toupper(word[0]);
			std::transform(word.begin() + 1, word.end(), word.begin() + 1, ::tolower);
			result += word;
		}
	}
	return result;
}
