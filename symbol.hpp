#pragma once
#include "refcount.hpp"
#include "symbol.h"

namespace BinaryNinja {

	class Symbol : public CoreRefCountObject<BNSymbol, BNNewSymbolReference, BNFreeSymbol>
	{
	  public:
		Symbol(BNSymbolType type, const std::string& shortName, const std::string& fullName, const std::string& rawName,
		    uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbol* sym);

		BNSymbolType GetType() const;
		BNSymbolBinding GetBinding() const;
		std::string GetShortName() const;
		std::string GetFullName() const;
		std::string GetRawName() const;
		uint64_t GetAddress() const;
		uint64_t GetOrdinal() const;
		bool IsAutoDefined() const;
		NameSpace GetNameSpace() const;

		static Ref<Symbol> ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr);
	};
}