#pragma once

extern "C" {
	enum BNSymbolType
	{
		FunctionSymbol = 0,
		ImportAddressSymbol = 1,
		ImportedFunctionSymbol = 2,
		DataSymbol = 3,
		ImportedDataSymbol = 4,
		ExternalSymbol = 5,
		LibraryFunctionSymbol = 6
	};

	enum BNSymbolBinding
	{
		NoBinding,
		LocalBinding,
		GlobalBinding,
		WeakBinding
	};

	// Symbols
	BINARYNINJACOREAPI BNSymbol* BNCreateSymbol(BNSymbolType type, const char* shortName, const char* fullName,
	    const char* rawName, uint64_t addr, BNSymbolBinding binding, const BNNameSpace* nameSpace, uint64_t ordinal);
	BINARYNINJACOREAPI BNSymbol* BNNewSymbolReference(BNSymbol* sym);
	BINARYNINJACOREAPI void BNFreeSymbol(BNSymbol* sym);
	BINARYNINJACOREAPI BNSymbolType BNGetSymbolType(BNSymbol* sym);
	BINARYNINJACOREAPI BNSymbolBinding BNGetSymbolBinding(BNSymbol* sym);
	BINARYNINJACOREAPI BNNameSpace BNGetSymbolNameSpace(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolShortName(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolFullName(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolRawName(BNSymbol* sym);
	BINARYNINJACOREAPI void* BNGetSymbolRawBytes(BNSymbol* sym, size_t* count);
	BINARYNINJACOREAPI void BNFreeSymbolRawBytes(void* bytes);

	BINARYNINJACOREAPI uint64_t BNGetSymbolAddress(BNSymbol* sym);
	BINARYNINJACOREAPI uint64_t BNGetSymbolOrdinal(BNSymbol* sym);
	BINARYNINJACOREAPI bool BNIsSymbolAutoDefined(BNSymbol* sym);
}