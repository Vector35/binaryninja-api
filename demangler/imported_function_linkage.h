// Copyright 2026 Vector 35 Inc.
// Licensed under the Apache License, Version 2.0.

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <type_traits>
#include <utility>

namespace BN::ImportedFunctionLinkage
{
	// Both ordinary import lookup and signature contributors must use the same
	// loader identity. A raw name can occur in several DLLs or at symbol-only
	// addresses. A concrete external relocation takes precedence over names.
	// nullopt indicates conflicting external identities; more than one returned
	// function indicates ambiguous stubs. Neither case permits selecting a stub.
	template <typename View, typename ImportSymbol, typename FunctionLookup>
	auto FindCandidates(const View& view, const ImportSymbol& importSymbol, bool externalTarget,
		uint64_t targetAddress, FunctionLookup getFunction)
	{
		using FunctionRef = decltype(getFunction(uint64_t{}));
		using NameSpace = std::decay_t<decltype(importSymbol->GetNameSpace())>;
		using Candidates = std::map<uint64_t, FunctionRef>;
		std::set<uint64_t> externalTargets;
		if (externalTarget)
			externalTargets.insert(targetAddress);
		else
		{
			for (const auto& relocation : view->GetRelocationsAt(targetAddress))
				if (auto symbol = relocation->GetSymbol(); symbol && symbol->GetType() == ExternalSymbol)
					externalTargets.insert(symbol->GetAddress());
		}
		if (externalTargets.size() > 1)
			return std::optional<Candidates>();

		const auto relatedSymbols = view->GetSymbolsByRawName(importSymbol->GetRawName());
		std::set<NameSpace> importNamespaces;
		if (!externalTarget)
			importNamespaces.insert(importSymbol->GetNameSpace());
		else
		{
			// Externs occupy a different namespace from their import entries.
			// Their entry relocations recover the loader namespace for stubs
			// whose instructions do not retain an external relocation.
			for (const auto& symbol : relatedSymbols)
			{
				if (symbol->GetType() != ImportAddressSymbol)
					continue;
				for (const auto& relocation : view->GetRelocationsAt(symbol->GetAddress()))
					if (auto external = relocation->GetSymbol(); external && external->GetType() == ExternalSymbol
						&& externalTargets.count(external->GetAddress()))
						importNamespaces.insert(symbol->GetNameSpace());
			}
		}

		Candidates relocatedStubs, namedStubs;
		for (const auto& symbol : relatedSymbols)
		{
			if (symbol->GetType() != ImportedFunctionSymbol)
				continue;
			bool sameImport = false;
			bool hasExternalRelocation = false;
			for (const auto& relocation : view->GetRelocationsAt(symbol->GetAddress()))
			{
				if (auto external = relocation->GetSymbol(); external && external->GetType() == ExternalSymbol)
				{
					hasExternalRelocation = true;
					sameImport |= externalTargets.count(external->GetAddress()) != 0;
				}
			}
			// ImportedFunctionFromImportAddressSymbol preserves namespace.
			// Use it only if no concrete relocation contradicts the identity.
			const bool sameNameSpace = !hasExternalRelocation && importNamespaces.count(symbol->GetNameSpace());
			if (!sameImport && !sameNameSpace)
				continue;
			auto candidate = getFunction(symbol->GetAddress());
			if (candidate)
				(sameImport ? relocatedStubs : namedStubs).emplace(symbol->GetAddress(), candidate);
		}
		return std::optional<Candidates>(relocatedStubs.empty() ? std::move(namedStubs) : std::move(relocatedStubs));
	}
}
