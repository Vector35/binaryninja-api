#pragma once
#include <string>
#include "confidence.hpp"
#include "refcount.hpp"

namespace BinaryNinja {
    class Type;

	struct DataVariable
	{
		DataVariable() {}
		DataVariable(uint64_t a, Type* t, bool d) : address(a), type(t), autoDiscovered(d) {}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
	};

	struct DataVariableAndName
	{
		DataVariableAndName() {}
		DataVariableAndName(uint64_t a, Type* t, bool d, const std::string& n) :
		    address(a), type(t), autoDiscovered(d), name(n)
		{}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
		std::string name;
	};
}