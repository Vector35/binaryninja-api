#pragma once
#include "binaryninja_defs.h"
#include "relocationhandler.h"
#include "qualifiedname.h"
#include "registervalue.h"
#include "callingconvention.h"
#include "analysis.h"
#include "registervalue.h"
#include "symbol.h"
#include "datavariable.h"

extern "C" {

	struct BNDataBuffer;
	struct BNDisassemblySettings;
	struct BNFileAccessor;
	struct BNFileMetadata;
	struct BNLinearDisassemblyLine;
	struct BNSection;
	struct BNSegment;
	struct BNDataVariable;
	struct BNTagType;
	struct BNTagReference;
	struct BNDebugInfo;
	struct BNPlatform;
	struct BNQualifiedNameTypeAndId;
	struct BNWorkflow;
	struct BNQualifiedNameAndType;

	enum BNSectionSemantics
	{
		DefaultSectionSemantics,
		ReadOnlyCodeSectionSemantics,
		ReadOnlyDataSectionSemantics,
		ReadWriteDataSectionSemantics,
		ExternalSectionSemantics
	};

	enum BNFindFlag
	{
		FindCaseSensitive = 0,
		FindCaseInsensitive = 1
	};

	enum BNModificationStatus
	{
		Original = 0,
		Changed = 1,
		Inserted = 2
	};

	// This describes how a type is referenced
	enum BNTypeReferenceType
	{
		// Type A contains type B
		DirectTypeReferenceType,
		// All other cases, e.g., type A contains a pointer to type B
		IndirectTypeReferenceType,
		// The nature of the reference is unknown
		UnknownTypeReferenceType
	};

	struct BNTypeReferenceSource
	{
		BNQualifiedName name;
		uint64_t offset;
		BNTypeReferenceType type;
	};

	enum BNStringType
	{
		AsciiString = 0,
		Utf16String = 1,
		Utf32String = 2,
		Utf8String = 3
	};

	struct BNRange
	{
		uint64_t start;
		uint64_t end;
	};

	struct BNCustomBinaryView
	{
		void* context;
		bool (*init)(void* ctxt);
		void (*freeObject)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
		size_t (*read)(void* ctxt, void* dest, uint64_t offset, size_t len);
		size_t (*write)(void* ctxt, uint64_t offset, const void* src, size_t len);
		size_t (*insert)(void* ctxt, uint64_t offset, const void* src, size_t len);
		size_t (*remove)(void* ctxt, uint64_t offset, uint64_t len);
		BNModificationStatus (*getModification)(void* ctxt, uint64_t offset);
		bool (*isValidOffset)(void* ctxt, uint64_t offset);
		bool (*isOffsetReadable)(void* ctxt, uint64_t offset);
		bool (*isOffsetWritable)(void* ctxt, uint64_t offset);
		bool (*isOffsetExecutable)(void* ctxt, uint64_t offset);
		bool (*isOffsetBackedByFile)(void* ctxt, uint64_t offset);
		uint64_t (*getNextValidOffset)(void* ctxt, uint64_t offset);
		uint64_t (*getStart)(void* ctxt);
		uint64_t (*getLength)(void* ctxt);
		uint64_t (*getEntryPoint)(void* ctxt);
		bool (*isExecutable)(void* ctxt);
		BNEndianness (*getDefaultEndianness)(void* ctxt);
		bool (*isRelocatable)(void* ctxt);
		size_t (*getAddressSize)(void* ctxt);
		bool (*save)(void* ctxt, BNFileAccessor* accessor);
	};

	struct BNStringReference
	{
		BNStringType type;
		uint64_t start;
		size_t length;
	};

	struct BNReferenceSource
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
	};

	struct BNTypeFieldReference
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
		size_t size;
		BNTypeWithConfidence incomingType;
	};

	struct BNTypeFieldReferenceSizeInfo
	{
		uint64_t offset;
		size_t* sizes;
		size_t count;
	};

	struct BNTypeFieldReferenceTypeInfo
	{
		uint64_t offset;
		BNTypeWithConfidence* types;
		size_t count;
	};

	struct BNBinaryDataNotification
	{
		void* context;
		void (*dataWritten)(void* ctxt, BNBinaryView* view, uint64_t offset, size_t len);
		void (*dataInserted)(void* ctxt, BNBinaryView* view, uint64_t offset, size_t len);
		void (*dataRemoved)(void* ctxt, BNBinaryView* view, uint64_t offset, uint64_t len);
		void (*functionAdded)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*functionRemoved)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*functionUpdated)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*functionUpdateRequested)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*dataVariableAdded)(void* ctxt, BNBinaryView* view, BNDataVariable* var);
		void (*dataVariableRemoved)(void* ctxt, BNBinaryView* view, BNDataVariable* var);
		void (*dataVariableUpdated)(void* ctxt, BNBinaryView* view, BNDataVariable* var);
		void (*dataMetadataUpdated)(void* ctxt, BNBinaryView* view, uint64_t offset);
		void (*tagTypeUpdated)(void* ctxt, BNBinaryView* view, BNTagType* tagType);
		void (*tagAdded)(void* ctxt, BNBinaryView* view, BNTagReference* tagRef);
		void (*tagUpdated)(void* ctxt, BNBinaryView* view, BNTagReference* tagRef);
		void (*tagRemoved)(void* ctxt, BNBinaryView* view, BNTagReference* tagRef);
		void (*symbolAdded)(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		void (*symbolUpdated)(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		void (*symbolRemoved)(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		void (*stringFound)(void* ctxt, BNBinaryView* view, BNStringType type, uint64_t offset, size_t len);
		void (*stringRemoved)(void* ctxt, BNBinaryView* view, BNStringType type, uint64_t offset, size_t len);
		void (*typeDefined)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeUndefined)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeReferenceChanged)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeFieldReferenceChanged)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, uint64_t offset);
	};

	// Segment object methods
	BINARYNINJACOREAPI BNSegment* BNCreateSegment(
	    uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags, bool autoDefined);
	BINARYNINJACOREAPI BNSegment* BNNewSegmentReference(BNSegment* seg);
	BINARYNINJACOREAPI void BNFreeSegment(BNSegment* seg);

	BINARYNINJACOREAPI BNRange* BNSegmentGetRelocationRanges(BNSegment* segment, size_t* count);
	BINARYNINJACOREAPI uint64_t BNSegmentGetRelocationsCount(BNSegment* segment);
	BINARYNINJACOREAPI BNRange* BNSegmentGetRelocationRangesAtAddress(BNSegment* segment, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI bool BNSegmentRangeContainsRelocation(BNSegment* segment, uint64_t addr, size_t size);
	BINARYNINJACOREAPI void BNFreeRelocationRanges(BNRange* ranges);
	BINARYNINJACOREAPI uint64_t BNSegmentGetStart(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetLength(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetEnd(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetDataEnd(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetDataOffset(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetDataLength(BNSegment* segment);
	BINARYNINJACOREAPI uint32_t BNSegmentGetFlags(BNSegment* segment);
	BINARYNINJACOREAPI bool BNSegmentIsAutoDefined(BNSegment* segment);
	BINARYNINJACOREAPI void BNSegmentSetLength(BNSegment* segment, uint64_t length);
	BINARYNINJACOREAPI void BNSegmentSetDataOffset(BNSegment* segment, uint64_t dataOffset);
	BINARYNINJACOREAPI void BNSegmentSetDataLength(BNSegment* segment, uint64_t dataLength);
	BINARYNINJACOREAPI void BNSegmentSetFlags(BNSegment* segment, uint32_t flags);

	// Section object methods
	BINARYNINJACOREAPI BNSection* BNNewSectionReference(BNSection* section);
	BINARYNINJACOREAPI void BNFreeSection(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetName(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetType(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetStart(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetLength(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetEnd(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetLinkedSection(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetInfoSection(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetInfoData(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetAlign(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetEntrySize(BNSection* section);
	BINARYNINJACOREAPI BNSectionSemantics BNSectionGetSemantics(BNSection* section);
	BINARYNINJACOREAPI bool BNSectionIsAutoDefined(BNSection* section);

	// Binary view access
	BINARYNINJACOREAPI BNBinaryView* BNNewViewReference(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeBinaryView(BNBinaryView* view);
	BINARYNINJACOREAPI BNFileMetadata* BNGetFileForView(BNBinaryView* view);
	BINARYNINJACOREAPI char* BNGetViewType(BNBinaryView* view);

	BINARYNINJACOREAPI BNBinaryView* BNGetParentView(BNBinaryView* view);

	BINARYNINJACOREAPI size_t BNReadViewData(BNBinaryView* view, void* dest, uint64_t offset, size_t len);
	BINARYNINJACOREAPI BNDataBuffer* BNReadViewBuffer(BNBinaryView* view, uint64_t offset, size_t len);

	BINARYNINJACOREAPI size_t BNWriteViewData(BNBinaryView* view, uint64_t offset, const void* data, size_t len);
	BINARYNINJACOREAPI size_t BNWriteViewBuffer(BNBinaryView* view, uint64_t offset, BNDataBuffer* data);
	BINARYNINJACOREAPI size_t BNInsertViewData(BNBinaryView* view, uint64_t offset, const void* data, size_t len);
	BINARYNINJACOREAPI size_t BNInsertViewBuffer(BNBinaryView* view, uint64_t offset, BNDataBuffer* data);
	BINARYNINJACOREAPI size_t BNRemoveViewData(BNBinaryView* view, uint64_t offset, uint64_t len);

	BINARYNINJACOREAPI void BNNotifyDataWritten(BNBinaryView* view, uint64_t offset, size_t len);
	BINARYNINJACOREAPI void BNNotifyDataInserted(BNBinaryView* view, uint64_t offset, size_t len);
	BINARYNINJACOREAPI void BNNotifyDataRemoved(BNBinaryView* view, uint64_t offset, uint64_t len);

	BINARYNINJACOREAPI size_t BNGetEntropy(
	    BNBinaryView* view, uint64_t offset, size_t len, size_t blockSize, float* result);

	BINARYNINJACOREAPI BNModificationStatus BNGetModification(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI size_t BNGetModificationArray(
	    BNBinaryView* view, uint64_t offset, BNModificationStatus* result, size_t len);

	BINARYNINJACOREAPI bool BNIsValidOffset(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetReadable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetWritable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetExecutable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetBackedByFile(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetCodeSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetExternSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetWritableSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI uint64_t BNGetNextValidOffset(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI uint64_t BNGetStartOffset(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetEndOffset(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetViewLength(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetEntryPoint(BNBinaryView* view);

	BINARYNINJACOREAPI BNArchitecture* BNGetDefaultArchitecture(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetDefaultArchitecture(BNBinaryView* view, BNArchitecture* arch);
	BINARYNINJACOREAPI BNPlatform* BNGetDefaultPlatform(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetDefaultPlatform(BNBinaryView* view, BNPlatform* platform);
	BINARYNINJACOREAPI BNEndianness BNGetDefaultEndianness(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNIsRelocatable(BNBinaryView* view);
	BINARYNINJACOREAPI size_t BNGetViewAddressSize(BNBinaryView* view);

	BINARYNINJACOREAPI bool BNIsViewModified(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNIsExecutableView(BNBinaryView* view);

	BINARYNINJACOREAPI bool BNSaveToFile(BNBinaryView* view, BNFileAccessor* file);
	BINARYNINJACOREAPI bool BNSaveToFilename(BNBinaryView* view, const char* filename);
	BINARYNINJACOREAPI void BNDefineRelocation(
	    BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* info, uint64_t target, uint64_t reloc);
	BINARYNINJACOREAPI void BNDefineSymbolRelocation(
	    BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* info, BNSymbol* target, uint64_t reloc);
	BINARYNINJACOREAPI BNRange* BNGetRelocationRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNRange* BNGetRelocationRangesAtAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI bool BNRangeContainsRelocation(BNBinaryView* view, uint64_t addr, size_t size);

	BINARYNINJACOREAPI void BNRegisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notify);
	BINARYNINJACOREAPI void BNUnregisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notify);

	BINARYNINJACOREAPI bool BNCanAssemble(BNBinaryView* view, BNArchitecture* arch);

	BINARYNINJACOREAPI bool BNIsNeverBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsAlwaysBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsInvertBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsSkipAndReturnZeroPatchAvailable(
	    BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsSkipAndReturnValuePatchAvailable(
	    BNBinaryView* view, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNConvertToNop(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNAlwaysBranch(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNInvertBranch(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNSkipAndReturnValue(
	    BNBinaryView* view, BNArchitecture* arch, uint64_t addr, uint64_t value);

	BINARYNINJACOREAPI size_t BNGetInstructionLength(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNFindNextData(
	    BNBinaryView* view, uint64_t start, BNDataBuffer* data, uint64_t* result, BNFindFlag flags);
	BINARYNINJACOREAPI bool BNFindNextText(BNBinaryView* view, uint64_t start, const char* data, uint64_t* result,
	    BNDisassemblySettings* settings, BNFindFlag flags, BNFunctionGraphType graph);
	BINARYNINJACOREAPI bool BNFindNextConstant(BNBinaryView* view, uint64_t start, uint64_t constant, uint64_t* result,
	    BNDisassemblySettings* settings, BNFunctionGraphType graph);

	BINARYNINJACOREAPI bool BNFindNextDataWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    BNDataBuffer* data, uint64_t* result, BNFindFlag flags, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total));
	BINARYNINJACOREAPI bool BNFindNextTextWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    const char* data, uint64_t* result, BNDisassemblySettings* settings, BNFindFlag flags,
	    BNFunctionGraphType graph, void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total));
	BINARYNINJACOREAPI bool BNFindNextConstantWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    uint64_t constant, uint64_t* result, BNDisassemblySettings* settings, BNFunctionGraphType graph, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total));

	BINARYNINJACOREAPI bool BNFindAllDataWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    BNDataBuffer* data, BNFindFlag flags, void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total),
	    void* matchCtxt, bool (*matchCallback)(void* matchCtxt, uint64_t addr, BNDataBuffer* match));
	BINARYNINJACOREAPI bool BNFindAllTextWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    const char* data, BNDisassemblySettings* settings, BNFindFlag flags, BNFunctionGraphType graph, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total), void* matchCtxt,
	    bool (*matchCallback)(void* matchCtxt, uint64_t addr, const char* match, BNLinearDisassemblyLine* line));
	BINARYNINJACOREAPI bool BNFindAllConstantWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    uint64_t constant, BNDisassemblySettings* settings, BNFunctionGraphType graph, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total), void* matchCtxt,
	    bool (*matchCallback)(void* matchCtxt, uint64_t addr, BNLinearDisassemblyLine* line));

	BINARYNINJACOREAPI void BNAddAutoSegment(
	    BNBinaryView* view, uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
	BINARYNINJACOREAPI void BNRemoveAutoSegment(BNBinaryView* view, uint64_t start, uint64_t length);
	BINARYNINJACOREAPI void BNAddUserSegment(
	    BNBinaryView* view, uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
	BINARYNINJACOREAPI void BNRemoveUserSegment(BNBinaryView* view, uint64_t start, uint64_t length);
	BINARYNINJACOREAPI BNSegment** BNGetSegments(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeSegmentList(BNSegment** segments, size_t count);
	BINARYNINJACOREAPI BNSegment* BNGetSegmentAt(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI bool BNGetAddressForDataOffset(BNBinaryView* view, uint64_t offset, uint64_t* addr);

	BINARYNINJACOREAPI void BNAddAutoSection(BNBinaryView* view, const char* name, uint64_t start, uint64_t length,
	    BNSectionSemantics semantics, const char* type, uint64_t align, uint64_t entrySize, const char* linkedSection,
	    const char* infoSection, uint64_t infoData);
	BINARYNINJACOREAPI void BNRemoveAutoSection(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI void BNAddUserSection(BNBinaryView* view, const char* name, uint64_t start, uint64_t length,
	    BNSectionSemantics semantics, const char* type, uint64_t align, uint64_t entrySize, const char* linkedSection,
	    const char* infoSection, uint64_t infoData);
	BINARYNINJACOREAPI void BNRemoveUserSection(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNSection** BNGetSections(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNSection** BNGetSectionsAt(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeSectionList(BNSection** sections, size_t count);
	BINARYNINJACOREAPI BNSection* BNGetSectionByName(BNBinaryView* view, const char* name);

	BINARYNINJACOREAPI char** BNGetUniqueSectionNames(BNBinaryView* view, const char** names, size_t count);

	BINARYNINJACOREAPI BNNameSpace* BNGetNameSpaces(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeNameSpaceList(BNNameSpace* nameSpace, size_t count);
	BINARYNINJACOREAPI BNNameSpace BNGetExternalNameSpace();
	BINARYNINJACOREAPI BNNameSpace BNGetInternalNameSpace();
	BINARYNINJACOREAPI void BNFreeNameSpace(BNNameSpace* name);

	BINARYNINJACOREAPI BNAddressRange* BNGetAllocatedRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeAddressRanges(BNAddressRange* ranges);

	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetGlobalPointerValue(BNBinaryView* view);

	// Creation of new types of binary views
	BINARYNINJACOREAPI BNBinaryView* BNCreateCustomBinaryView(
	    const char* name, BNFileMetadata* file, BNBinaryView* parent, BNCustomBinaryView* view);

	BINARYNINJACOREAPI BNSymbol* BNGetSymbolByAddress(BNBinaryView* view, uint64_t addr, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol* BNGetSymbolByRawName(
	    BNBinaryView* view, const char* name, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsByName(
	    BNBinaryView* view, const char* name, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsByRawName(
	    BNBinaryView* view, const char* name, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbols(BNBinaryView* view, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t len, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsOfType(
	    BNBinaryView* view, BNSymbolType type, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsOfTypeInRange(BNBinaryView* view, BNSymbolType type, uint64_t start,
	    uint64_t len, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI void BNFreeSymbolList(BNSymbol** syms, size_t count);
	BINARYNINJACOREAPI BNSymbol** BNGetVisibleSymbols(BNBinaryView* view, size_t* count, const BNNameSpace* nameSpace);

	BINARYNINJACOREAPI void BNDefineAutoSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNUndefineAutoSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNDefineUserSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNUndefineUserSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNDefineImportedFunction(
	    BNBinaryView* view, BNSymbol* importAddressSym, BNFunction* func, BNType* type);
	BINARYNINJACOREAPI BNSymbol* BNDefineAutoSymbolAndVariableOrFunction(
	    BNBinaryView* view, BNPlatform* platform, BNSymbol* sym, BNType* type);
	BINARYNINJACOREAPI void BNBeginBulkModifySymbols(BNBinaryView* view);
	BINARYNINJACOREAPI void BNEndBulkModifySymbols(BNBinaryView* view);

	BINARYNINJACOREAPI bool BNGetStringAtAddress(BNBinaryView* view, uint64_t addr, BNStringReference* strRef);
	BINARYNINJACOREAPI BNStringReference* BNGetStrings(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNStringReference* BNGetStringsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNFreeStringReferenceList(BNStringReference* strings);

	BINARYNINJACOREAPI char* BNGetDisplayStringForInteger(
	    BNBinaryView* binaryView, BNIntegerDisplayType type, uint64_t value, size_t inputWidth, bool isSigned);
	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferences(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferencesInRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);

	BINARYNINJACOREAPI uint64_t* BNGetDataReferences(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesInRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesFrom(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesFromInRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNAddUserDataReference(BNBinaryView* view, uint64_t fromAddr, uint64_t toAddr);
	BINARYNINJACOREAPI void BNRemoveUserDataReference(BNBinaryView* view, uint64_t fromAddr, uint64_t toAddr);
	BINARYNINJACOREAPI void BNFreeDataReferences(uint64_t* refs);

	BINARYNINJACOREAPI BNFunction* BNGetAnalysisFunction(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI BNFunction* BNGetRecentAnalysisFunctionForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionsForAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionsContainingAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNFunction* BNGetAnalysisEntryPoint(BNBinaryView* view);

	BINARYNINJACOREAPI char* BNGetGlobalCommentForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t* BNGetGlobalCommentedAddresses(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNSetGlobalCommentForAddress(BNBinaryView* view, uint64_t addr, const char* comment);
	BINARYNINJACOREAPI BNBasicBlock* BNGetRecentBasicBlockForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlocksForAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlocksStartingAtAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);

	struct BNTypeFieldReferenceTypeInfo;
	BINARYNINJACOREAPI uint64_t* BNGetAllFieldsReferenced(BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNTypeFieldReferenceSizeInfo* BNGetAllSizesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNTypeFieldReferenceTypeInfo* BNGetAllTypesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetSizesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI BNTypeWithConfidence* BNGetTypesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);

	// Analysis
	BINARYNINJACOREAPI bool BNHasFunctions(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNHasSymbols(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNHasDataVariables(BNBinaryView* view);
	BINARYNINJACOREAPI void BNAddAnalysisOption(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI void BNAddFunctionForAnalysis(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNAddEntryPointForAnalysis(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNRemoveAnalysisFunction(BNBinaryView* view, BNFunction* func);
	BINARYNINJACOREAPI BNFunction* BNCreateUserFunction(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNRemoveUserFunction(BNBinaryView* view, BNFunction* func);
	BINARYNINJACOREAPI bool BNHasInitialAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetAnalysisHold(BNBinaryView* view, bool enable);
	BINARYNINJACOREAPI void BNUpdateAnalysisAndWait(BNBinaryView* view);
	BINARYNINJACOREAPI void BNUpdateAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNAbortAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionList(BNBinaryView* view, size_t* count);

	// TypeReferenceSource
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFrom(
	    BNBinaryView* view, BNReferenceSource* addr, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFromInRange(
	    BNBinaryView* view, BNReferenceSource* addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFieldsFrom(
	    BNBinaryView* view, BNReferenceSource* addr, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFieldsFromInRange(
	    BNBinaryView* view, BNReferenceSource* addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetCallees(BNBinaryView* view, BNReferenceSource* callSite, size_t* count);
	BINARYNINJACOREAPI BNReferenceSource* BNGetCallers(BNBinaryView* view, uint64_t callee, size_t* count);

	// ReferenceSource
	BINARYNINJACOREAPI void BNFreeTypeFieldReferences(BNTypeFieldReference* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeCodeReferences(BNReferenceSource* refs, size_t count);
	BINARYNINJACOREAPI uint64_t* BNGetCodeReferencesFrom(BNBinaryView* view, BNReferenceSource* src, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetCodeReferencesFromInRange(
	    BNBinaryView* view, BNReferenceSource* src, uint64_t len, size_t* count);

	// TypeReferenceSource
	struct BNTypeFieldReferenceTypeInfo;
	BINARYNINJACOREAPI void BNFreeTypeReferences(BNTypeReferenceSource* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceSizeInfo(BNTypeFieldReferenceSizeInfo* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceTypeInfo(BNTypeFieldReferenceTypeInfo* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceSizes(size_t* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceTypes(BNTypeWithConfidence* refs, size_t count);

	// DataVariables
	BINARYNINJACOREAPI BNDataVariable* BNGetDataVariables(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeDataVariables(BNDataVariable* vars, size_t count);
	BINARYNINJACOREAPI bool BNGetDataVariableAtAddress(BNBinaryView* view, uint64_t addr, BNDataVariable* var);
	BINARYNINJACOREAPI void BNDefineDataVariable(BNBinaryView* view, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNDefineUserDataVariable(BNBinaryView* view, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNUndefineDataVariable(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI void BNUndefineUserDataVariable(BNBinaryView* view, uint64_t addr);

	BINARYNINJACOREAPI BNSymbol* BNImportedFunctionFromImportAddressSymbol(BNSymbol* sym, uint64_t addr);

	// Analysis Completion Events
	struct BNAnalysisCompletionEvent;
	BINARYNINJACOREAPI BNAnalysisCompletionEvent* BNAddAnalysisCompletionEvent(
	    BNBinaryView* view, void* ctxt, void (*callback)(void* ctxt));
	BINARYNINJACOREAPI BNAnalysisCompletionEvent* BNNewAnalysisCompletionEventReference(
	    BNAnalysisCompletionEvent* event);
	BINARYNINJACOREAPI void BNFreeAnalysisCompletionEvent(BNAnalysisCompletionEvent* event);
	BINARYNINJACOREAPI void BNCancelAnalysisCompletionEvent(BNAnalysisCompletionEvent* event);

	// References to type
	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferencesForType(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesForType(BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetTypeReferencesForType(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);

	// References to type field
	BINARYNINJACOREAPI BNTypeFieldReference* BNGetCodeReferencesForTypeField(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesForTypeField(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetTypeReferencesForTypeField(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);

	// GetNext/GetPrevious
	BINARYNINJACOREAPI uint64_t BNGetNextFunctionStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextBasicBlockStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextDataAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextDataVariableStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousFunctionStartBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousBasicBlockStartBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousBasicBlockEndBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousDataBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousDataVariableStartBeforeAddress(BNBinaryView* view, uint64_t addr);

	// PossibleValueSet
	BINARYNINJACOREAPI bool BNParsePossibleValueSet(BNBinaryView* view, const char* valueText,
	    BNRegisterValueType state, BNPossibleValueSet* result, uint64_t here, char** errors);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetAnalysisTypeList(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeList(BNQualifiedNameAndType* types, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeIdList(BNQualifiedNameTypeAndId* types, size_t count);
	BINARYNINJACOREAPI BNQualifiedName* BNGetAnalysisTypeNames(BNBinaryView* view, size_t* count, const char* matching);
	BINARYNINJACOREAPI void BNFreeTypeNameList(BNQualifiedName* names, size_t count);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeByName(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI char* BNGetAnalysisTypeId(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNGetAnalysisTypeNameById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI bool BNIsAnalysisTypeAutoDefined(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNDefineAnalysisType(
	    BNBinaryView* view, const char* id, BNQualifiedName* defaultName, BNType* type);
	BINARYNINJACOREAPI void BNDefineUserAnalysisType(BNBinaryView* view, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNDefineAnalysisTypes(BNBinaryView* view, BNQualifiedNameTypeAndId* types, size_t count, bool (*progress)(void*, size_t, size_t), void* progressContext);
	BINARYNINJACOREAPI void BNDefineUserAnalysisTypes(BNBinaryView* view, BNQualifiedNameAndType* types, size_t count, bool (*progress)(void*, size_t, size_t), void* progressContext);
	BINARYNINJACOREAPI void BNUndefineAnalysisType(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI void BNUndefineUserAnalysisType(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNRenameAnalysisType(
	    BNBinaryView* view, BNQualifiedName* oldName, BNQualifiedName* newName);
	BINARYNINJACOREAPI char* BNGenerateAutoPlatformTypeId(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoPlatformTypeIdSource(BNPlatform* platform);
	
	BINARYNINJACOREAPI void BNRegisterPlatformTypes(BNBinaryView* view, BNPlatform* platform);
	BINARYNINJACOREAPI void BNReanalyzeAllFunctions(BNBinaryView* view);
	BINARYNINJACOREAPI BNWorkflow* BNGetWorkflowForBinaryView(BNBinaryView* view);

	// Store/Query structured data to/from a BinaryView
	struct BNMetadata;
	BINARYNINJACOREAPI void BNBinaryViewStoreMetadata(
	    BNBinaryView* view, const char* key, BNMetadata* value, bool isAuto);
	BINARYNINJACOREAPI BNMetadata* BNBinaryViewQueryMetadata(BNBinaryView* view, const char* key);
	BINARYNINJACOREAPI void BNBinaryViewRemoveMetadata(BNBinaryView* view, const char* key);

	// Load Settings
	struct BNSettings;
	BINARYNINJACOREAPI char** BNBinaryViewGetLoadSettingsTypeNames(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNSettings* BNBinaryViewGetLoadSettings(BNBinaryView* view, const char* typeName);
	BINARYNINJACOREAPI void BNBinaryViewSetLoadSettings(BNBinaryView* view, const char* typeName, BNSettings* settings);

	// AnalysisParameters
	BINARYNINJACOREAPI BNAnalysisParameters BNGetParametersForAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetParametersForAnalysis(BNBinaryView* view, BNAnalysisParameters params);
	BINARYNINJACOREAPI uint64_t BNGetMaxFunctionSizeForAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetMaxFunctionSizeForAnalysis(BNBinaryView* view, uint64_t size);
	BINARYNINJACOREAPI bool BNGetNewAutoFunctionAnalysisSuppressed(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetNewAutoFunctionAnalysisSuppressed(BNBinaryView* view, bool suppress);

	// ParseExpression
	BINARYNINJACOREAPI bool BNParseExpression(
	    BNBinaryView* view, const char* expression, uint64_t* offset, uint64_t here, char** errorString);
	BINARYNINJACOREAPI void BNFreeParseError(char* errorString);

}