#pragma once

#include "refcount.h"
#include <string>

namespace BinaryNinja
{
	class Architecture;
	class BinaryView;
	class QualifiedName;
	class Type;

	/*! Demangles using LLVM's demangler

		\param[in] mangledName a mangled (msvc/itanium/rust/dlang) name
		\param[out] outVarName QualifiedName reference to write the output name to.
		\param[in] simplify Whether to simplify demangled names.

		\ingroup demangle
	*/
	bool DemangleLLVM(const std::string& mangledName, QualifiedName& outVarName, const bool simplify = false);

	/*! Demangles using LLVM's demangler

		\param[in] mangledName a mangled (msvc/itanium/rust/dlang) name
		\param[out] outVarName QualifiedName reference to write the output name to.
		\param[in] view View to check the analysis.types.templateSimplifier for

		\ingroup demangle
	*/
	bool DemangleLLVM(const std::string& mangledName, QualifiedName& outVarName, BinaryView* view);

	/*! Demangles a Microsoft Visual Studio C++ name

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled Microsoft Visual Studio C++ name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] simplify Whether to simplify demangled names.

	    \ingroup demangle
	*/
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
		const bool simplify = false);

	/*! Demangles a Microsoft Visual Studio C++ name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	        to determine whether to simplify the mangled name.

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled Microsoft Visual Studio C++ name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] view View to check the analysis.types.templateSimplifier for

	    \ingroup demangle
	*/
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
		BinaryView* view);

	/*! Demangles a GNU3 name

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled GNU3 name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] simplify Whether to simplify demangled names.

	    \ingroup demangle
	*/
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType,
		QualifiedName& outVarName, const bool simplify = false);

	/*! Demangles a GNU3 name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	        to determine whether to simplify the mangled name.

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled GNU3 name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] view View to check the analysis.types.templateSimplifier for

	    \ingroup demangle
	*/
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType,
		QualifiedName& outVarName, BinaryView* view);

	/*! Determines if a symbol name is a mangled GNU3 name

	    \param[in] mangledName a potentially mangled name

	    \ingroup demangle
	*/
	bool IsGNU3MangledString(const std::string& mangledName);

}
