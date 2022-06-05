#pragma once
#include "binaryninja_defs.h"
#include "refcount.hpp"
#include "confidence.hpp"

namespace BinaryNinja
{
	class Architecture;
	class BinaryView;
	class Type;
	class Function;

	struct Variable : public BNVariable
	{
		Variable();
		Variable(BNVariableSourceType type, uint32_t index, uint64_t storage);
		Variable(BNVariableSourceType type, uint64_t storage);
		Variable(const BNVariable& var);
		Variable(const Variable& var);

		Variable& operator=(const Variable& var);

		bool operator==(const Variable& var) const;
		bool operator!=(const Variable& var) const;
		bool operator<(const Variable& var) const;

		uint64_t ToIdentifier() const;
		static Variable FromIdentifier(uint64_t id);
	};

	struct VariableNameAndType
	{
		Variable var;
		Confidence<Ref<Type>> type;
		std::string name;
		bool autoDefined;

		bool operator==(const VariableNameAndType& a);
		bool operator!=(const VariableNameAndType& a);
	};

	struct ILReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
		BNFunctionGraphType type;
		size_t exprId;
	};

	struct VariableReferenceSource
	{
		Variable var;
		ILReferenceSource source;
	};
}