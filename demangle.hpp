#pragma once

#include <string>
#include "refcount.hpp"

namespace BinaryNinja {
	class Architecture;
	class QualifiedName;
	class BinaryView;
	class Type;

	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
		const bool simplify = false);
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
		const Ref<BinaryView>& view);
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
		const bool simplify = false);
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
		const Ref<BinaryView>& view);

	class SimplifyName
	{
	  public:
		// Use these functions to interface with the simplifier
		static std::string to_string(const std::string& input);
		static std::string to_string(const QualifiedName& input);
		static QualifiedName to_qualified_name(const std::string& input, bool simplify);
		static QualifiedName to_qualified_name(const QualifiedName& input);

		// Below is everything for the above APIs to work
		enum SimplifierDest
		{
			str,
			fqn
		};

		SimplifyName(const std::string&, const SimplifierDest, const bool);
		~SimplifyName();

		operator std::string() const;
		operator QualifiedName();

	  private:
		const char* m_rust_string;
		const char** m_rust_array;
		uint64_t m_length;
	};
}