#pragma once
#include <string>
#include "refcount.hpp"
namespace BinaryNinja {
	class Type;
	struct NameAndType
	{
		std::string name;
		Confidence<Ref<Type>> type;

		NameAndType() = default;
		NameAndType(const Confidence<Ref<Type>>& t);
		NameAndType(const std::string& n, const Confidence<Ref<Type>>& t);
	};
}