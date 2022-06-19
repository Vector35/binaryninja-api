#pragma once
#include "core/binaryninja_defs.h"

#define MAX_RELOCATION_SIZE 8

extern "C" {
	struct BNRelocationHandler;
	struct BNRelocation;
	struct BNLowLevelILFunction;
	struct BNBinaryView;
	struct BNArchitecture;
	struct BNSymbol;

	enum BNRelocationType
	{
		ELFGlobalRelocationType,
		ELFCopyRelocationType,
		ELFJumpSlotRelocationType,
		StandardRelocationType,
		IgnoredRelocation,
		UnhandledRelocation
	};

	struct BNRelocationInfo
	{
		BNRelocationType type;  // BinaryNinja Relocation Type
		bool pcRelative;        // PC Relative or Absolute (subtract address from relocation)
		bool baseRelative;      // Relative to start of module (Add module base to relocation)
		uint64_t base;          // Base address for this binary view
		size_t size;            // Size of the data to be written
		size_t truncateSize;    // After addition/subtraction truncate to
		uint64_t nativeType;    // Base type from relocation entry
		size_t addend;          // Addend value from relocation entry
		bool hasSign;           // Addend should be subtracted
		bool implicitAddend;    // Addend should be read from the BinaryView
		bool external;          // Relocation entry points to external symbol
		size_t symbolIndex;     // Index into symbol table
		size_t sectionIndex;    // Index into the section table
		uint64_t address;       // Absolute address or segment offset
		uint64_t target;        // Target (set automatically)
		bool dataRelocation;    // This relocation is effecting data not code
		uint8_t relocationDataCache[MAX_RELOCATION_SIZE];
		struct BNRelocationInfo* prev;  // Link to relocation another related relocation
		struct BNRelocationInfo* next;  // Link to relocation another related relocation
	};


	struct BNCustomRelocationHandler
	{
		void* context;
		void (*freeObject)(void* ctxt);

		bool (*getRelocationInfo)(
			void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* result, size_t resultCount);
		bool (*applyRelocation)(
			void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
		size_t (*getOperandForExternalRelocation)(void* ctxt, const uint8_t* data, uint64_t addr, size_t length,
			BNLowLevelILFunction* il, BNRelocation* relocation);
	};

	BINARYNINJACOREAPI void BNArchitectureRegisterRelocationHandler(
		BNArchitecture* arch, const char* viewName, BNRelocationHandler* handler);
	BINARYNINJACOREAPI BNRelocationHandler* BNCreateRelocationHandler(BNCustomRelocationHandler* handler);
	BINARYNINJACOREAPI BNRelocationHandler* BNArchitectureGetRelocationHandler(
		BNArchitecture* arch, const char* viewName);
	BINARYNINJACOREAPI BNRelocationHandler* BNNewRelocationHandlerReference(BNRelocationHandler* handler);
	BINARYNINJACOREAPI void BNFreeRelocationHandler(BNRelocationHandler* handler);
	BINARYNINJACOREAPI bool BNRelocationHandlerGetRelocationInfo(BNRelocationHandler* handler, BNBinaryView* data,
		BNArchitecture* arch, BNRelocationInfo* info, size_t infoCount);
	BINARYNINJACOREAPI bool BNRelocationHandlerApplyRelocation(BNRelocationHandler* handler, BNBinaryView* view,
		BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
	BINARYNINJACOREAPI bool BNRelocationHandlerDefaultApplyRelocation(BNRelocationHandler* handler, BNBinaryView* view,
		BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
	BINARYNINJACOREAPI size_t BNRelocationHandlerGetOperandForExternalRelocation(BNRelocationHandler* handler,
		const uint8_t* data, uint64_t addr, size_t length, const BNLowLevelILFunction* il, BNRelocation* relocation);

	// Relocation object methods
	BINARYNINJACOREAPI BNRelocation* BNNewRelocationReference(BNRelocation* reloc);
	BINARYNINJACOREAPI void BNFreeRelocation(BNRelocation* reloc);
	BINARYNINJACOREAPI BNRelocationInfo BNRelocationGetInfo(BNRelocation* reloc);
	BINARYNINJACOREAPI BNArchitecture* BNRelocationGetArchitecture(BNRelocation* reloc);
	BINARYNINJACOREAPI uint64_t BNRelocationGetTarget(BNRelocation* reloc);
	BINARYNINJACOREAPI uint64_t BNRelocationGetReloc(BNRelocation* reloc);
	BINARYNINJACOREAPI BNSymbol* BNRelocationGetSymbol(BNRelocation* reloc);
}