#pragma once
#include <vector>
#include <string>
#include "refcount.hpp"
#include "binaryninjacore/datarenderer.h"
#include "binaryninjaapi_new.hpp"

namespace BinaryNinja {
	class BinaryView;
	class Type;
	class QualifiedName;
	struct DisassemblyTextLine;

	class DataRenderer : public CoreRefCountObject<BNDataRenderer, BNNewDataRendererReference, BNFreeDataRenderer>
	{
		static bool IsValidForDataCallback(
			void* ctxt, BNBinaryView* data, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
		static BNDisassemblyTextLine* GetLinesForDataCallback(void* ctxt, BNBinaryView* data, uint64_t addr,
			BNType* type, const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
			BNTypeContext* typeCxt, size_t ctxCount);
		static void FreeCallback(void* ctxt);

	  public:
		DataRenderer();
		DataRenderer(BNDataRenderer* renderer);
		virtual bool IsValidForData(
			BinaryView* data, uint64_t addr, Type* type, std::vector<std::pair<Type*, size_t>>& context);
		virtual std::vector<DisassemblyTextLine> GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
			const std::vector<InstructionTextToken>& prefix, size_t width,
			std::vector<std::pair<Type*, size_t>>& context);
		std::vector<DisassemblyTextLine> RenderLinesForData(BinaryView* data, uint64_t addr, Type* type,
			const std::vector<InstructionTextToken>& prefix, size_t width,
			std::vector<std::pair<Type*, size_t>>& context);

		static bool IsStructOfTypeName(
			Type* type, const QualifiedName& name, std::vector<std::pair<Type*, size_t>>& context);
		static bool IsStructOfTypeName(
			Type* type, const std::string& name, std::vector<std::pair<Type*, size_t>>& context);
	};

	class DataRendererContainer
	{
	  public:
		static void RegisterGenericDataRenderer(DataRenderer* renderer);
		static void RegisterTypeSpecificDataRenderer(DataRenderer* renderer);
	};
}