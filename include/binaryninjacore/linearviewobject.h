#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNLinearViewObject;
	struct BNDisassemblySettings;
	struct BNBinaryView;
	struct BNLinearViewCursor;

	enum BNLinearViewObjectIdentifierType
	{
		SingleLinearViewObject,
		AddressLinearViewObject,
		AddressRangeLinearViewObject
	};

	struct BNLinearViewObjectIdentifier
	{
		char* name;
		BNLinearViewObjectIdentifierType type;
		uint64_t start, end;
	};

	struct BNLinearDisassemblyLine;
	BINARYNINJACOREAPI void BNFreeLinearDisassemblyLines(BNLinearDisassemblyLine* lines, size_t count);

	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewDisassembly(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLiftedIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLowLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLowLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMediumLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMediumLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMappedMediumLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMappedMediumLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewHighLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewHighLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLanguageRepresentation(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewDataOnly(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionDisassembly(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLiftedIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLowLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLowLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMediumLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMappedMediumLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMappedMediumLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionHighLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionHighLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLanguageRepresentation(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNNewLinearViewObjectReference(BNLinearViewObject* obj);
	BINARYNINJACOREAPI void BNFreeLinearViewObject(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetFirstLinearViewObjectChild(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLastLinearViewObjectChild(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetPreviousLinearViewObjectChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetNextLinearViewObjectChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForAddress(
	    BNLinearViewObject* parent, uint64_t addr);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForIdentifier(
	    BNLinearViewObject* parent, BNLinearViewObjectIdentifier* id);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetLinearViewObjectLines(
	    BNLinearViewObject* obj, BNLinearViewObject* prev, BNLinearViewObject* next, size_t* count);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectStart(BNLinearViewObject* obj);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectEnd(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObjectIdentifier BNGetLinearViewObjectIdentifier(BNLinearViewObject* obj);
	BINARYNINJACOREAPI void BNFreeLinearViewObjectIdentifier(BNLinearViewObjectIdentifier* id);
	BINARYNINJACOREAPI int BNCompareLinearViewObjectChildren(
	    BNLinearViewObject* obj, BNLinearViewObject* a, BNLinearViewObject* b);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectOrderingIndexTotal(BNLinearViewObject* obj);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectOrderingIndexForChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForOrderingIndex(
	    BNLinearViewObject* parent, uint64_t idx);

	BINARYNINJACOREAPI BNLinearViewCursor* BNCreateLinearViewCursor(BNLinearViewObject* root);
	BINARYNINJACOREAPI BNLinearViewCursor* BNDuplicateLinearViewCursor(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewCursor* BNNewLinearViewCursorReference(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNFreeLinearViewCursor(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNIsLinearViewCursorBeforeBegin(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNIsLinearViewCursorAfterEnd(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewCursorCurrentObject(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewObjectIdentifier* BNGetLinearViewCursorPath(
	    BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearViewCursorPath(BNLinearViewObjectIdentifier* objs, size_t count);
	BINARYNINJACOREAPI BNLinearViewObject** BNGetLinearViewCursorPathObjects(BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearViewCursorPathObjects(BNLinearViewObject** objs, size_t count);
	BINARYNINJACOREAPI BNAddressRange BNGetLinearViewCursorOrderingIndex(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewCursorOrderingIndexTotal(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToBegin(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToEnd(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToAddress(BNLinearViewCursor* cursor, uint64_t addr);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToPath(
	    BNLinearViewCursor* cursor, BNLinearViewObjectIdentifier* ids, size_t count);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToPathAndAddress(
	    BNLinearViewCursor* cursor, BNLinearViewObjectIdentifier* ids, size_t count, uint64_t addr);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToCursorPath(BNLinearViewCursor* cursor, BNLinearViewCursor* path);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToCursorPathAndAddress(
	    BNLinearViewCursor* cursor, BNLinearViewCursor* path, uint64_t addr);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToOrderingIndex(BNLinearViewCursor* cursor, uint64_t idx);
	BINARYNINJACOREAPI bool BNLinearViewCursorNext(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNLinearViewCursorPrevious(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetLinearViewCursorLines(BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI int BNCompareLinearViewCursors(BNLinearViewCursor* a, BNLinearViewCursor* b);
}