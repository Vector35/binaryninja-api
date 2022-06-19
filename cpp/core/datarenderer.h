#pragma once

#include "core/binaryninja_defs.h"

extern "C" {
	struct BNDataRenderer;
	struct BNCustomDataRenderer;
	struct BNBinaryView;
	struct BNTypeContext;
	struct BNDataRendererContainer;
	struct BNType;

	struct BNTypeContext
	{
		BNType* type;
		size_t offset;
	};

	struct BNCustomDataRenderer
	{
		void* context;
		void (*freeObject)(void* ctxt);
		bool (*isValidForData)(
		    void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
		BNDisassemblyTextLine* (*getLinesForData)(void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type,
		    const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
		    BNTypeContext* typeCtx, size_t ctxCount);
	};

	// Custom Data Render methods
	BINARYNINJACOREAPI BNDataRenderer* BNCreateDataRenderer(BNCustomDataRenderer* renderer);
	BINARYNINJACOREAPI BNDataRenderer* BNNewDataRendererReference(BNDataRenderer* renderer);
	BINARYNINJACOREAPI bool BNIsValidForData(
		void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetLinesForData(void* ctxt, BNBinaryView* view, uint64_t addr,
		BNType* type, const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
		BNTypeContext* typeCtx, size_t ctxCount);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNRenderLinesForData(BNBinaryView* data, uint64_t addr, BNType* type,
		const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count, BNTypeContext* typeCtx,
		size_t ctxCount);
	BINARYNINJACOREAPI void BNFreeDataRenderer(BNDataRenderer* renderer);
	BINARYNINJACOREAPI BNDataRendererContainer* BNGetDataRendererContainer();
	BINARYNINJACOREAPI void BNRegisterGenericDataRenderer(BNDataRendererContainer* container, BNDataRenderer* renderer);
	BINARYNINJACOREAPI void BNRegisterTypeSpecificDataRenderer(
		BNDataRendererContainer* container, BNDataRenderer* renderer);
}