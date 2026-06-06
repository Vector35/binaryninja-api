// Copyright 2016-2026 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Includes snippets from LLVM, which is under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.

#include "demangle_msvc.h"
#include "unicode.h"
#include <limits>
#include <memory>
#include <ranges>
#include <utility>


#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#else
using namespace BinaryNinja;
using namespace std;
#endif


// The largest observed depth in a real-world corpus of roughly 200k MSVC symbols was 54.
static constexpr size_t MAX_DEMANGLE_NESTING_DEPTH = 256;
static constexpr size_t MAX_ENCODED_NUMBER_HEX_DIGITS = 16;
static constexpr size_t MAX_BACKREFS = 10;

static int64_t EncodedNumberToInt64(uint64_t magnitude, bool negative)
{
	constexpr auto int64Max = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
	constexpr auto int64MinMagnitude = int64Max + 1;

	if (!negative)
	{
		if (magnitude > int64Max)
			throw DemangleException("Invalid encoded number");
		return static_cast<int64_t>(magnitude);
	}

	if (magnitude > int64MinMagnitude)
		throw DemangleException("Invalid encoded number");
	if (magnitude == int64MinMagnitude)
		return std::numeric_limits<int64_t>::min();
	return -static_cast<int64_t>(magnitude);
}

static _STD_STRING FormatEncodedNumberLiteral(uint64_t magnitude, bool negative)
{
	if (negative)
		return "-" + to_string(magnitude);
	return to_string(magnitude);
}

// Define MSVC_DEMANGLE_DEBUG to enable trace logging
#ifdef MSVC_DEMANGLE_DEBUG
#define MSVC_TRACE(...) LogTraceF(__VA_ARGS__)
#else
#define MSVC_TRACE(...) do {} while(0)
#endif

_STD_STRING Demangle::Reader::ReadString(size_t count)
{
	if (count > Length())
		throw DemangleException();
	_STD_STRING out(m_ptr, count);
	m_ptr += count;
	return out;
}


_STD_STRING Demangle::Reader::ReadUntil(char sentinel)
{
	const char* found = static_cast<const char*>(memchr(m_ptr, sentinel, m_end - m_ptr));
	if (!found)
		throw DemangleException();
	size_t count = found - m_ptr;
	_STD_STRING out = ReadString(count);
	Consume(); // sentinel
	return out;
}


DemangledTypeNode::NodeRef Demangle::BackrefList::GetTypeBackrefRef(size_t reference)
{
	if (reference < typeList.size() && typeList[reference])
		return typeList[reference];
	throw DemangleException(_STD_STRING("Backref too large " + std::to_string(reference)));
}


DemangledNamePart::Ref Demangle::BackrefList::GetNameBackrefRef(size_t reference)
{
	if (reference < nameList.size() && nameList[reference])
		return nameList[reference];
	MSVC_TRACE("type: {} - Backref too large: {}/{}", fmt::ptr(this), nameList.size(), reference);
	throw DemangleException(_STD_STRING("Backref too large " + std::to_string(reference)));
}


const DemangledTypeNode& Demangle::BackrefList::GetTypeBackref(size_t reference)
{
	return *GetTypeBackrefRef(reference);
}


const DemangledNamePart& Demangle::BackrefList::GetNameBackref(size_t reference)
{
	return *GetNameBackrefRef(reference);
}


DemangledTypeNode::NodeRef Demangle::BackrefList::PushTypeBackref(DemangledTypeNode::NodeRef t)
{
	if (!t)
		return nullptr;
	if (typeList.size() >= MAX_BACKREFS)
		return nullptr;
	typeList.push_back(t);
	return t;
}


DemangledTypeNode::NodeRef Demangle::BackrefList::PushTypeBackref(const DemangledTypeNode& t)
{
	if (typeList.size() < MAX_BACKREFS)
		return PushTypeBackref(DemangledTypeNode::CreateSharedCopy(t));
	return nullptr;
}


DemangledTypeNode::NodeRef Demangle::BackrefList::PushTypeBackref(DemangledTypeNode&& t)
{
	if (typeList.size() < MAX_BACKREFS)
		return PushTypeBackref(DemangledTypeNode::CreateShared(std::move(t)));
	return nullptr;
}


DemangledNamePart::Ref Demangle::BackrefList::PushNameBackref(DemangledNamePart::Ref t)
{
	if (!t)
		return nullptr;
	MSVC_TRACE("this: {} - Backref: {}", fmt::ptr(this), nameList.size());
	for (const auto& name : nameList)
		if (name && ((name == t) || name->IsStructurallyEqual(*t)))
			return name;
	if (nameList.size() < MAX_BACKREFS)
	{
		nameList.push_back(t);
		return t;
	}
	return nullptr;
}


DemangledNamePart::Ref Demangle::BackrefList::PushNameBackref(const DemangledNamePart& t)
{
	MSVC_TRACE("this: {} - Backref: {}", fmt::ptr(this), nameList.size());
	for (const auto& name : nameList)
		if (name && name->IsStructurallyEqual(t))
			return name;
	if (nameList.size() < MAX_BACKREFS)
	{
		auto ref = DemangledNamePart::CreateSharedCopy(t);
		nameList.push_back(ref);
		return ref;
	}
	return nullptr;
}


DemangledNamePart::Ref Demangle::BackrefList::PushNameBackref(DemangledNamePart&& t)
{
	MSVC_TRACE("this: {} - Backref: {}", fmt::ptr(this), nameList.size());
	for (const auto& name : nameList)
		if (name && name->IsStructurallyEqual(t))
			return name;
	if (nameList.size() < MAX_BACKREFS)
	{
		auto ref = DemangledNamePart::CreateShared(std::move(t));
		nameList.push_back(ref);
		return ref;
	}
	return nullptr;
}


DemangledNamePart::Ref Demangle::BackrefList::PushTemplateSpecialization(DemangledNamePart::Ref t)
{
	if (!t)
		return nullptr;
	templateList.push_back(t);
	return t;
}


DemangledNamePart::Ref Demangle::BackrefList::PushTemplateSpecialization(const DemangledNamePart& t)
{
	return PushTemplateSpecialization(DemangledNamePart::CreateSharedCopy(t));
}


DemangledNamePart::Ref Demangle::BackrefList::PushTemplateSpecialization(DemangledNamePart&& t)
{
	return PushTemplateSpecialization(DemangledNamePart::CreateShared(std::move(t)));
}


Demangle::BackrefContextSwitch::BackrefContextSwitch(BackrefList& active): active(active)
{
	Swap(active, saved);
}


Demangle::BackrefContextSwitch::~BackrefContextSwitch()
{
	Swap(active, saved);
}


void Demangle::BackrefContextSwitch::Swap(BackrefList& left, BackrefList& right)
{
	std::swap(left.typeList, right.typeList);
	std::swap(left.nameList, right.nameList);
	std::swap(left.templateList, right.templateList);
}



Demangle::Demangle(Architecture* arch, _STD_STRING  mangledName) :
	m_mangledName(std::move(mangledName)),
	m_reader(m_mangledName),
	m_arch(arch),
	m_platform(nullptr),
	m_view(nullptr)
{
}


Demangle::Demangle(Ref<Platform> platform, _STD_STRING  mangledName) :
	m_mangledName(std::move(mangledName)),
	m_reader(m_mangledName),
	m_arch(nullptr),
	m_platform(std::move(platform)),
	m_view(nullptr)
{
}


Demangle::Demangle(Ref<BinaryView> view, _STD_STRING  mangledName) :
	m_mangledName(std::move(mangledName)),
	m_reader(m_mangledName),
	m_arch(nullptr),
	m_platform(nullptr),
	m_view(std::move(view))
{
}


Demangle::NestingGuard::NestingGuard(Demangle& demangler) : m_demangler(demangler)
{
	m_demangler.m_nestingDepth++;
	if (m_demangler.m_nestingDepth > MAX_DEMANGLE_NESTING_DEPTH)
	{
		m_demangler.m_nestingDepth--;
		throw DemangleException("Detected adversarial mangled string");
	}
}


Demangle::NestingGuard::~NestingGuard()
{
	m_demangler.m_nestingDepth--;
}


void Demangle::Reset(Architecture* arch, const _STD_STRING& mangledName)
{
	m_mangledName = mangledName;
	m_reader.Reset(m_mangledName);
	m_backrefList.Clear();
	m_arch = arch;
	m_platform = nullptr;
	m_view = nullptr;
	m_templateParamDepth = 0;
	m_nestingDepth = 0;
}


void Demangle::RewriteTemplateBackrefName(NameList& typeName, const BackrefList& nameBackrefList)
{
	if (typeName.empty())
		return;

	DemangledNamePart& baseName = typeName.back();
	if (baseName.HasTemplateArguments())
		return;
	_STD_STRING base = baseName.GetBase();

	for (const auto & it : std::views::reverse(nameBackrefList.templateList))
	{
		if (!it)
			continue;
		const DemangledNamePart& candidate = *it;
		if (!candidate.HasTemplateArguments())
			continue;
		if (candidate.GetBase() != base)
			continue;
		baseName = candidate;
		return;
	}
}

_STD_STRING Demangle::FormatTypeAndName(const DemangledTypeNode& type, const NameList& name) const
{
	StringList nameSegments = FinalizeNameList(name);
	if (type.GetNameType() == OperatorReturnTypeNameType)
	{
		Ref<Type> finalizedType = type.Finalize(m_platform.GetPtr());
		if (finalizedType)
			return finalizedType->GetTypeAndName(QualifiedName(nameSegments));
	}
	return type.GetTypeAndName(nameSegments);
}

DemangledTypeNode Demangle::DemangleReferencedSymbolValue(BackrefList& varList)
{
	// Match LLVM's TemplateParameterReferenceNode parsing: referenced-symbol
	// non-type template arguments are parsed in the active backref context, so
	// later template arguments may refer to names/types introduced inside the
	// referenced symbol.
	BackrefList symbolBackrefs = varList;

	auto context = DemangleSymbol(symbolBackrefs);
	varList = symbolBackrefs;
	_STD_STRING value = "&" + FormatTypeAndName(context.type, context.name);
	return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{value});
}


DemangledTypeNode Demangle::DemangleAutoNonTypeTemplateParam(BackrefList& varList)
{
	if (m_reader.ConsumeIf('0'))
	{
		return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{DecodeEncodedNumberLiteral()});
	}
	if (m_reader.ConsumeIf('1'))
	{
		return DemangleReferencedSymbolValue(varList);
	}
	throw DemangleException();
}


DemangledTypeNode Demangle::DemangleVarType(BackrefList& varList, bool isReturn,
	bool includeImplicitThis, DemangledTypeNode::NodeRef* outTypeBackref, TypeBackrefMode typeBackrefMode)
{
	NestingGuard nestingGuard(*this);
	MSVC_TRACE("{}: '{}' - {}", __FUNCTION__, m_reader.GetRaw(), varList.nameList.size());
	if (outTypeBackref)
		*outTypeBackref = nullptr;
	auto recordTypeBackref = [&](const DemangledTypeNode& type) -> DemangledTypeNode::NodeRef {
		if (isReturn || typeBackrefMode == TypeBackrefMode::SuppressTopLevel)
			return nullptr;
		auto ref = varList.PushTypeBackref(type);
		if (outTypeBackref)
			*outTypeBackref = ref;
		return ref;
	};
	DemangledTypeNode newType;
	bool _const = false, _volatile = false;
	BNReferenceType refType = PointerReferenceType;
	BNTypeClass typeClass = IntegerTypeClass;
	BNStructureVariant structType = StructStructureType;
	NameList typeName;
	BNNameType classFunctionType;
	size_t width = 0;
	bool _enumSigned = false;
	auto demangleArrayExtents = [this]() -> _STD_VECTOR<uint64_t> {
		uint64_t dimensionCount = DecodeEncodedUnsignedNumber();
		if (dimensionCount > static_cast<uint64_t>(m_reader.Length()))
			throw DemangleException("Array dimension count is too large");

		_STD_VECTOR<uint64_t> elementList;
		for (uint64_t i = 0; i < dimensionCount; i++)
		{
			uint64_t element = DecodeEncodedUnsignedNumber();
			elementList.push_back(element);
		}
		return elementList;
	};
	switch (char elm = m_reader.Read())
	{
	case 'A':
		typeClass = PointerTypeClass;
		refType = ReferenceReferenceType;
		_const = false;
		_volatile = false;
		break;
	case 'B':
		typeClass = PointerTypeClass;
		refType = ReferenceReferenceType;
		_const = false;
		_volatile = true;
		break;
	case 'C': return DemangledTypeNode::IntegerType(1, true, "signed char");
	case 'D': return DemangledTypeNode::IntegerType(1, true);
	case 'E': return DemangledTypeNode::IntegerType(1, false);
	case 'F': return DemangledTypeNode::IntegerType(2, true);
	case 'G': return DemangledTypeNode::IntegerType(2, false);
	case 'H': return DemangledTypeNode::IntegerType(4, true);
	case 'I': return DemangledTypeNode::IntegerType(4, false);
	case 'J': return DemangledTypeNode::IntegerType(4, true, "long");
	case 'K': return DemangledTypeNode::IntegerType(4, false, "unsigned long");
	case 'M': return DemangledTypeNode::FloatType(4);
	case 'N': return DemangledTypeNode::FloatType(8);
	case 'O': return DemangledTypeNode::FloatType(10, "long double");
	case 'P': // *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = false;
		_volatile = false;
		break;
	case 'Q': // const *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = true;
		_volatile = false;
		break;
	case 'R': // volatile *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = false;
		_volatile = true;
		break;
	case 'S': // const volatile *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = true;
		_volatile = true;
		break;
	case 'T': typeClass = StructureTypeClass; structType = UnionStructureType;  break;
	case 'U': typeClass = StructureTypeClass; structType = StructStructureType; break;
	case 'V': typeClass = StructureTypeClass; structType = ClassStructureType;  break;
	case 'W':
		typeClass = EnumerationTypeClass;
		switch (m_reader.Read())
		{
		case '0': width = 1; _enumSigned = true;  break;
		case '1': width = 1; _enumSigned = false; break;
		case '2': width = 2; _enumSigned = true;  break;
		case '3': width = 2; _enumSigned = false; break;
		case '4': width = 4; _enumSigned = true;  break;
		case '5': width = 4; _enumSigned = false; break;
		case '6': width = 4; _enumSigned = true;  break;
		case '7': width = 4; _enumSigned = false; break;
		default: throw DemangleException();
		}
		break;
	case 'X': return DemangledTypeNode::VoidType(); break;
	case 'Y':
	{
		// Multi-dimensional array type: Y<ndims><dim1><dim2>...@<elemtype>
		_STD_VECTOR<uint64_t> elementList = demangleArrayExtents();
		newType = DemangleVarType(varList, false);
		for (uint64_t i : std::views::reverse(elementList))
		{
			newType = DemangledTypeNode::ArrayType(std::move(newType), i);
		}
		recordTypeBackref(newType);
		return newType;
	}
	case 'Z': return DemangledTypeNode::VarArgsType();
	case '?':
	{
		char next = m_reader.PeekOr();
		if (next >= '0' && next <= '9')
		{
			size_t reference = m_reader.Read() - '0';
			if (reference < varList.typeList.size() && varList.typeList[reference])
			{
				auto ref = varList.typeList[reference];
				if (outTypeBackref)
					*outTypeBackref = ref;
				return *ref;
			}
			// Legacy fallback: old generated symbols used `?2` here for
			// a deduced-auto placeholder before clang/MSVC settled on
			// the explicit `?<auto>@` spelling handled below.
			if (reference == 2)
				return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{"auto"});
			throw DemangleException(_STD_STRING("Backref too large " + std::to_string(reference)));
		}
		if (next != '<')
			throw DemangleException();

		_STD_STRING placeholder = m_reader.ReadUntil('@');
		m_reader.ConsumeIf('@');
		if (placeholder == "<auto>")
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{"auto"});
		if (placeholder == "<decltype-auto>")
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{"decltype(auto)"});
		return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{placeholder});
	}
	case '_':
		switch (m_reader.Read())
		{
		case 'D': newType = DemangledTypeNode::IntegerType(1, true); break;
		case 'E': newType = DemangledTypeNode::IntegerType(1, false); break;
		case 'F': newType = DemangledTypeNode::IntegerType(2, true); break;
		case 'G': newType = DemangledTypeNode::IntegerType(2, false); break;
		case 'H': newType = DemangledTypeNode::IntegerType(4, true); break;
		case 'I': newType = DemangledTypeNode::IntegerType(4, false); break;
		case 'J': newType = DemangledTypeNode::IntegerType(8, true); break;
		case 'K': newType = DemangledTypeNode::IntegerType(8, false); break;
		case 'L': newType = DemangledTypeNode::IntegerType(16, true); break;
		case 'M': newType = DemangledTypeNode::IntegerType(16, false); break;
		case 'N': newType = DemangledTypeNode::BoolType(); break;
		case 'O':
		{
			auto childType = DemangleVarType(varList, false);
			newType = DemangledTypeNode::ArrayType(std::move(childType), 0);
			break;
		}
		case 'S': newType = DemangledTypeNode::WideCharType(2, "char16_t"); break;
		case 'U': newType = DemangledTypeNode::WideCharType(4, "char32_t"); break;
		case 'W': newType = DemangledTypeNode::WideCharType(2, "wchar_t"); break;
		// `_P` (auto) and `_T` (decltype(auto)) are placeholder return-type
		// encodings. For normal source code they are deduced at the function
		// definition and mangled as the deduced type — you will not see `_P`
		// or `_T` from something like `auto foo() { return 0; }` (that becomes
		// `?foo@@YAHXZ`). They do appear in compiler-emitted symbols for
		// function templates whose declared return type is literally `auto`
		// or `decltype(auto)` and which are mangled before/without deduction
		// settling on a concrete type — e.g. `??$seq@HX@llvm@@YA?A_PH@Z`
		// (llvm::seq) or `??$_Get_unwrapped@...@std@@YA?A_T...@Z`. Handle
		// them as named-type placeholders so downstream type consumers get
		// something sensible (rather than a `<FAILED>` demangle) even though
		// the underlying type is not expressible as a Binary Ninja Type.
		case 'P': newType = DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{"auto"}); break;
		case 'Q': newType = DemangledTypeNode::IntegerType(1, true, "char8_t"); break; // C++20 char8_t
		case 'T': newType = DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{"decltype(auto)"}); break;
		// NOTE: `_X` and `_Y` were previously mapped to coclass/cointerface
		// here, but those encodings are not emitted by any real toolchain.
		// LLVM's MicrosoftDemangle / MicrosoftMangle and Wine's undname
		// reimplementation none of them recognize `_X` or `_Y` as type
		// codes. Real cointerface is plain `Y<name>@@` (no underscore) at
		// the top-level type switch, grouped with T/U/V; coclass has no
		// dedicated mangling and is emitted as `V<name>@@` (class). Let
		// `_X` / `_Y` fall through to the `default: throw` so malformed
		// input is rejected instead of producing a bogus class type.
		default:
			throw DemangleException();
		}
		break;
	case '$':
		if (m_reader.ConsumeIf("$Q")) // &&
		{
			typeClass = PointerTypeClass;
			refType = RValueReferenceType;
			_const = false;
			_volatile = false;
		}
		else if (m_reader.ConsumeIf("$R")) // && volatile
		{
			typeClass = PointerTypeClass;
			refType = RValueReferenceType;
			_const = false;
			_volatile = true;
		}
		else if (m_reader.ConsumeIf("$A"))
		{
			char num = m_reader.Read();
			if (num >= '6' && num <= '9')
			{
				// For member function types (8/9), skip the class scope marker @@
				if (num == '8' || num == '9')
					m_reader.ConsumeIf("@@");
				return DemangleFunction(NoNameType, num >= '7', varList).type;
			}
			throw DemangleException();
		}
		else if (m_reader.ConsumeIf("$C"))
		{
			bool isMember = false;
			DemangleModifiers(_const, _volatile, isMember);
			newType = DemangleVarType(varList, isReturn, includeImplicitThis, nullptr,
				TypeBackrefMode::SuppressTopLevel);
			newType.SetConst(_const);
			newType.SetVolatile(_volatile);
			recordTypeBackref(newType);
			return newType;
		}
		else if (m_reader.ConsumeIf("$T"))
		{
			auto t = DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{"std::nullptr_t"});
			recordTypeBackref(t);
			return t;
		}
		else if (m_reader.ConsumeIf("$B"))
		{
			// $$B is a type modifier (managed/const) - strip and parse underlying type
			return DemangleVarType(varList, isReturn, includeImplicitThis, outTypeBackref, typeBackrefMode);
		}
		else if (m_reader.ConsumeIf('0'))
		{
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{DecodeEncodedNumberLiteral()});
		}
		else if (m_reader.ConsumeIf('D'))
		{
			// $D<type> - template type alias / anonymous type parameter
			return DemangleVarType(varList, isReturn, includeImplicitThis, outTypeBackref, typeBackrefMode);
		}
		else if (m_reader.ConsumeIf('M'))
		{
			// $M<type><value> - C++17 `auto` non-type template parameter.
			// The encoded type is the deduced type for the following bare
			// non-type payload and is not itself printed as a template arg.
			DemangleVarType(varList, false);
			return DemangleAutoNonTypeTemplateParam(varList);
		}
		else if (char next = m_reader.PeekOr(); next == 'H' || next == 'I' || next == 'J')
		{
			// $H/$I/$J - member function pointer value as a non-type template
			// parameter. Format: $H<mangled-symbol><adjustment-number>@;
			// $I has two adjustment numbers, $J has three.
			char kind = m_reader.Read();
			BackrefList symbolBackrefs = varList;
			auto context = DemangleSymbol(symbolBackrefs);
			varList = symbolBackrefs;
			_STD_STRING value = "{" + FormatTypeAndName(context.type, context.name);

			// Read adjustment number(s) — NOT $-prefixed, just raw numbers.
			int adjustments = (kind == 'H') ? 1 : (kind == 'I') ? 2 : 3;
			for (int i = 0; i < adjustments; i++)
			{
				int64_t adj = DecodeEncodedSignedNumber();
				value += "," + to_string(adj);
			}
			value += "}";
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{value});
		}
		else if (m_reader.ConsumeIf('1'))
		{
			return DemangleReferencedSymbolValue(varList);
		}
		else
			throw DemangleException();
		break;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	{
		MSVC_TRACE("Backref {} {}", elm - '0', varList.typeList.size());
		auto ref = varList.GetTypeBackrefRef(elm - '0');
		if (outTypeBackref)
			*outTypeBackref = ref;
		return *ref;
	}
	default:
		throw DemangleException();
	}

	switch (typeClass)
	{
	case PointerTypeClass:
	{
		if (m_reader.ConsumeIf('6'))
		{
			auto childType = DemangleFunction(NoNameType, false, varList).type;
			newType = DemangledTypeNode::PointerType(std::move(childType),
			                                         _const,
			                                         _volatile,
			                                         refType);
			break;
		}
		if (m_reader.ConsumeIf('8'))
		{
			NameList ownerName;
			DemangleName(ownerName, classFunctionType, varList, true);
			RewriteTemplateBackrefName(ownerName, varList);
			auto childType = DemangleFunction(NoNameType, true, varList).type;
			newType = DemangledTypeNode::MemberPointerType(std::move(childType),
			                                         std::move(ownerName),
			                                         _const,
			                                         _volatile);
			break;
		}
		switch (m_reader.PeekOr())
		{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '7':
		case '9':
			throw DemangleException();
		default:  // Non-numeric
		{
			MSVC_TRACE("Demangle pointer subtype: '{}'", m_reader.GetRaw());
			DemangledTypeNode child;
			bool _const2 = false, _volatile2 = false, localIsMember = false;
			NameList ownerName;
			auto suffix = DemanglePointerSuffix();
			ConsumeExtendedModifierPrefix();
			DemangleModifiers(_const2, _volatile2, localIsMember);
			if (localIsMember)
			{
				DemangleName(ownerName, classFunctionType, varList, true);
				RewriteTemplateBackrefName(ownerName, varList);
			}
			if (m_reader.ConsumeIf('Y')) //Multi-dimensions array
			{
				MSVC_TRACE("Demangle multi-dimensions array");
				_STD_VECTOR<uint64_t> elementList = demangleArrayExtents();
				child = DemangleVarType(varList, false);

				for (uint64_t i : std::views::reverse(elementList))
				{
					child = DemangledTypeNode::ArrayType(std::move(child), i);
				}
			}
			else
			{
				child = DemangleVarType(varList, true, includeImplicitThis && !localIsMember);
			}

			child.SetConst(_const2);
			child.SetVolatile(_volatile2);
			if (localIsMember)
			{
				newType = DemangledTypeNode::MemberPointerType(
					std::move(child), std::move(ownerName), _const, _volatile);
			}
			else
			{
				newType = DemangledTypeNode::PointerType(std::move(child),
				                                         _const,
				                                         _volatile,
				                                         refType);
			}

			newType.SetPointerSuffixBits(suffix);
			MSVC_TRACE("Name: {}", newType.GetString());
			break;
		}
		}
		break;
	}
	case EnumerationTypeClass:
		MSVC_TRACE("Demangle enumeration");
		DemangleName(typeName, classFunctionType, varList, true);
		newType = DemangledTypeNode::NamedType(EnumNamedTypeClass, typeName, width, _enumSigned);
		break;
	case StructureTypeClass:
		MSVC_TRACE("Demangle structure");
		DemangleName(typeName, classFunctionType, varList, true);
		RewriteTemplateBackrefName(typeName, varList);
		switch (structType)
		{
		case ClassStructureType:
			newType = DemangledTypeNode::NamedType(ClassNamedTypeClass, typeName);
			break;
		case StructStructureType:
			newType = DemangledTypeNode::NamedType(StructNamedTypeClass, typeName);
			break;
		case UnionStructureType:
			newType = DemangledTypeNode::NamedType(UnionNamedTypeClass, typeName);
			break;
		default:
			newType = DemangledTypeNode::NamedType(UnknownNamedTypeClass, typeName);
			break;
		}
		break;
	default:
		break;
	}
	recordTypeBackref(newType);
	return newType;
}

Demangle::EncodedNumber Demangle::DecodeEncodedNumber()
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	bool negative = m_reader.ConsumeIf('?');
	if (m_reader.Length() == 0)
		throw DemangleException("Invalid encoded number");

	char next = m_reader.PeekOr();
	if (next >= '0' && next <= '9')
	{
		uint64_t magnitude = static_cast<uint64_t>(m_reader.Read() + 1 - '0');
		return {magnitude, negative};
	}

	uint64_t magnitude = 0;
	size_t digitCount = 0;
	while (!m_reader.ConsumeIf('@'))
	{
		char ch = m_reader.Read();
		if (ch < 'A' || ch > 'P')
			throw DemangleException("Invalid encoded number");
		if (digitCount >= MAX_ENCODED_NUMBER_HEX_DIGITS)
			throw DemangleException("Invalid encoded number");
		magnitude = (magnitude << 4) | static_cast<uint64_t>(ch - 'A');
		digitCount++;
	}

	return {magnitude, negative};
}

int64_t Demangle::DecodeEncodedSignedNumber()
{
	EncodedNumber number = DecodeEncodedNumber();
	return EncodedNumberToInt64(number.magnitude, number.negative);
}

uint64_t Demangle::DecodeEncodedUnsignedNumber()
{
	EncodedNumber number = DecodeEncodedNumber();
	if (number.negative)
		throw DemangleException("Invalid encoded number");
	return number.magnitude;
}

int32_t Demangle::DecodeEncodedSignedInt32()
{
	uint32_t lowBits = static_cast<uint32_t>(DecodeEncodedUnsignedNumber());
	if ((lowBits & 0x80000000U) != 0)
		return static_cast<int32_t>(static_cast<int64_t>(lowBits) - 0x100000000LL);
	return static_cast<int32_t>(lowBits);
}

_STD_STRING Demangle::DecodeEncodedNumberLiteral()
{
	EncodedNumber number = DecodeEncodedNumber();
	return FormatEncodedNumberLiteral(number.magnitude, number.negative);
}


char Demangle::DemangleChar()
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	// Basic char is just the char
	if (!m_reader.ConsumeIf('?'))
		return m_reader.Read();

	// Hex char is ?$XX for 2 hex digits XX
	if (m_reader.ConsumeIf('$'))
	{
		MSVC_TRACE("{}: Hex digit '{}'", __FUNCTION__, m_reader.GetRaw());

		char c1 = m_reader.Read();
		char c2 = m_reader.Read();

		if (c1 < 'A' || c1 > 'P')
			throw DemangleException("Invalid character");
		if (c2 < 'A' || c2 > 'P')
			throw DemangleException("Invalid character");

		uint8_t b1 = c1 - 'A';
		uint8_t b2 = c2 - 'A';

		return static_cast<char>((b1 << 4) | b2);
	}

	MSVC_TRACE("{}: Table lookup '{}'", __FUNCTION__, m_reader.GetRaw());

	// Otherwise it's a lookup based on some big table
	// Thanks, LLVM!
	switch (m_reader.Read())
	{
	case '0': return ',';
	case '1': return '/';
	case '2': return '\\';
	case '3': return ':';
	case '4': return '.';
	case '5': return ' ';
	case '6': return '\n';
	case '7': return '\t';
	case '8': return '\'';
	case '9': return '-';
	case 'a': return '\xE1';
	case 'b': return '\xE2';
	case 'c': return '\xE3';
	case 'd': return '\xE4';
	case 'e': return '\xE5';
	case 'f': return '\xE6';
	case 'g': return '\xE7';
	case 'h': return '\xE8';
	case 'i': return '\xE9';
	case 'j': return '\xEA';
	case 'k': return '\xEB';
	case 'l': return '\xEC';
	case 'm': return '\xED';
	case 'n': return '\xEE';
	case 'o': return '\xEF';
	case 'p': return '\xF0';
	case 'q': return '\xF1';
	case 'r': return '\xF2';
	case 's': return '\xF3';
	case 't': return '\xF4';
	case 'u': return '\xF5';
	case 'v': return '\xF6';
	case 'w': return '\xF7';
	case 'x': return '\xF8';
	case 'y': return '\xF9';
	case 'z': return '\xFA';
	case 'A': return '\xC1';
	case 'B': return '\xC2';
	case 'C': return '\xC3';
	case 'D': return '\xC4';
	case 'E': return '\xC5';
	case 'F': return '\xC6';
	case 'G': return '\xC7';
	case 'H': return '\xC8';
	case 'I': return '\xC9';
	case 'J': return '\xCA';
	case 'K': return '\xCB';
	case 'L': return '\xCC';
	case 'M': return '\xCD';
	case 'N': return '\xCE';
	case 'O': return '\xCF';
	case 'P': return '\xD0';
	case 'Q': return '\xD1';
	case 'R': return '\xD2';
	case 'S': return '\xD3';
	case 'T': return '\xD4';
	case 'U': return '\xD5';
	case 'V': return '\xD6';
	case 'W': return '\xD7';
	case 'X': return '\xD8';
	case 'Y': return '\xD9';
	case 'Z': return '\xDA';
	default:
		throw DemangleException("Unknown character");
	}
}


void Demangle::DemangleVariableList(_STD_VECTOR<DemangledTypeNode::Param>& paramList, BackrefList& varList, bool typeBackrefs)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	uint8_t suffix = 0;
	for (;;)
	{
		bool hasModifiers = false;
			if (m_reader.PeekOr() == 'Z')
		{
			if (m_reader.PeekMatch("ZZ", 2))
			{
				paramList.push_back({"", DemangledTypeNode::CreateShared(DemangledTypeNode::VarArgsType())});
				m_reader.Consume();
				continue;
			}
			break;
		}
		if (m_reader.ConsumeIf('@'))
		{
			break;
		}
		else if (m_reader.ConsumeIf("$$$V"))
		{
			// $$$V = empty expanded type / template-template pack (post-MSVC2015 mangling).
			// See clang/lib/AST/MicrosoftMangle.cpp: for MSVC2015-compat this emits $$V,
			// otherwise $$$V.
			continue;
		}
		else if (m_reader.ConsumeIf("$$V") || m_reader.ConsumeIf("$$Z"))
		{
			// $$V = empty expanded type / template-template pack (MSVC2015-compat mangling).
			// $$Z = separator between two consecutive packs (emitted between non-empty packs,
			//       not as a lone template argument). LLVM's demangler leniently skips it in
			//       any position; we follow suit.
			// NB: $$S is NOT emitted by any known toolchain - only $S (single $) is a real
			//     token, handled below.
			continue;
		}
		else if (m_reader.ConsumeIf("$S"))
		{
			// $S = empty expanded non-type template pack
			// (e.g. `template<int... Ns>` or `template<auto... Vs>` instantiated with zero args).
			continue;
		}
		else if (m_reader.ConsumeIf('?'))
		{
			suffix = DemanglePointerSuffix();
			ConsumeExtendedModifierPrefix();
			DemangleModifiers(_const, _volatile, isMember);
			hasModifiers = true;
		}

		MSVC_TRACE("Argument {}: {}", paramList.size(), m_reader.GetRaw());
		DemangledTypeNode::NodeRef parsedType;
		DemangledTypeNode type = DemangleVarType(varList, false, true, &parsedType,
			typeBackrefs ? TypeBackrefMode::RecordTopLevel : TypeBackrefMode::SuppressTopLevel);
		if (hasModifiers)
		{
			type.SetConst(_const);
			type.SetVolatile(_volatile);
			type.SetPointerSuffixBits(suffix);
		}

		DemangledTypeNode::Param vt;
		if (hasModifiers || !parsedType)
			vt.type = DemangledTypeNode::CreateShared(std::move(type));
		else
			vt.type = parsedType;
		paramList.push_back(std::move(vt));
		MSVC_TRACE("Argument {}: '{}' - '{}'", paramList.size() - 1, paramList.back().type->GetString(), m_reader.GetRaw());
	}
	MSVC_TRACE("{}: done '{}'", __FUNCTION__, m_reader.GetRaw());
}


void Demangle::DemangleNameTypeString(_STD_STRING& out)
{
	out = m_reader.ReadUntil('@');
}


static bool IsWinRTEscapedScopeNameChar(char ch)
{
	return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')
	    || (ch >= 'a' && ch <= 'z') || (ch == '_') || (ch == '$');
}


bool Demangle::TryDemangleWinRTEscapedScopeName(NameList& nameList, BackrefList& nameBackrefList)
{
	// LLVM's Microsoft demangler rejects these WinRT interface-scope spellings:
	//   ?get@?QIXamlType@Markup@Xaml@UI@Windows@@Outer@@...
	// We accept them for compatibility with existing BN test cases. At entry,
	// DemangleName has consumed the leading '?' and `m_reader` points at the first
	// simple scope component. The escaped chain ends at its inner '@@'; the
	// normal outer qualified-name '@' is intentionally left for the DemangleName
	// loop to consume.
	const char* start = m_reader.GetRaw();
	if (m_reader.Length() < 4)
		return false;

	char prefix = start[0];
	if (!((prefix >= 'A' && prefix <= 'Z') || (prefix == '_')))
		return false;
	if (start[1] == '@' || start[1] == '?')
		return false;

	const char* limit = start + m_reader.Length();
	const char* end = nullptr;
	for (const char* cur = start + 1; (cur + 1) < limit; cur++)
	{
		if ((cur[0] == '@') && (cur[1] == '@'))
		{
			end = cur;
			break;
		}
	}
	if (!end)
		return false;

	_STD_VECTOR<_STD_STRING> scopeNames;
	const char* componentStart = start;
	while (componentStart < end)
	{
		const char* componentEnd = componentStart;
		while ((componentEnd < end) && (*componentEnd != '@'))
		{
			if (!IsWinRTEscapedScopeNameChar(*componentEnd))
				return false;
			componentEnd++;
		}
		if (componentEnd == componentStart)
			return false;

		scopeNames.emplace_back(componentStart, componentEnd - componentStart);
		componentStart = componentEnd + 1;
	}

	for (const auto& scopeName: scopeNames)
	{
		DemangledNamePart scope = MakeNameSegment(scopeName);
		nameList.insert(nameList.begin(), scope);
		nameBackrefList.PushNameBackref(std::move(scope));
	}
	m_reader.SetRaw(end + 2);
	return true;
}


void Demangle::DemangleNameTypeRtti(BNNameType& classFunctionType,
                                    BackrefList& nameBackrefList,
                                    _STD_STRING& out)
{
	switch (m_reader.Read())
	{
	case '0':
	{
		bool _const = false, _volatile = false;
		uint8_t suffix = 0;
		if (m_reader.ConsumeIf('?'))
		{
			bool isMember = false;
			suffix = DemanglePointerSuffix();
			ConsumeExtendedModifierPrefix();
			DemangleModifiers(_const, _volatile, isMember);
		}

		DemangledTypeNode rtti = DemangleVarType(nameBackrefList, false);
		rtti.SetConst(_const);
		rtti.SetVolatile(_volatile);
		rtti.SetPointerSuffixBits(suffix);
		out = rtti.GetString() + " `RTTI Type Descriptor'";
		classFunctionType = RttiTypeDescriptor;
		break;
	}
	case '1':
		out = "`RTTI Base Class Descriptor at (";
		for (int i = 0; i < 4; i++)
		{
			int64_t num = DecodeEncodedSignedNumber();
			if (i > 0)
			{
				out += ", ";
			}
			out += to_string(num);
		}
		out += ")'";
		classFunctionType = RttiBaseClassDescriptor;
		break;
	case '2':
		out = "`RTTI Base Class Array'";
		classFunctionType = RttiBaseClassArray;
		break;
	case '3':
		out = "`RTTI Class Hierarchy Descriptor'";
		classFunctionType = RttiClassHierarchyDescriptor;
		break;
	case '4':
		out = "`RTTI Complete Object Locator'";
		classFunctionType = RttiCompleteObjectLocator;
		break;
	default: throw DemangleException();
	}
}


void Demangle::DemangleTypeNameLookup(_STD_STRING& out, BNNameType& functionType)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	switch (m_reader.Read())
	{
	case '?': functionType = NoNameType; break;
	case '0': functionType = ConstructorNameType; break;
	case '1': functionType = ConstructorNameType; out = "~"; break; // destructor
	case 'B': functionType = OperatorReturnTypeNameType; out = "operator"; break; // conversion operator
	case '2': functionType = OperatorNewNameType; break;
	case '3': functionType = OperatorDeleteNameType; break;
	case '4': functionType = OperatorAssignNameType; break;
	case '5': functionType = OperatorRightShiftNameType; break;
	case '6': functionType = OperatorLeftShiftNameType; break;
	case '7': functionType = OperatorNotNameType; break;
	case '8': functionType = OperatorEqualNameType; break;
	case '9': functionType = OperatorNotEqualNameType; break;
	case 'A': functionType = OperatorArrayNameType; break;
	case 'C': functionType = OperatorArrowNameType; break;
	case 'D': functionType = OperatorStarNameType; break;
	case 'E': functionType = OperatorIncrementNameType; break;
	case 'F': functionType = OperatorDecrementNameType; break;
	case 'G': functionType = OperatorMinusNameType; break;
	case 'H': functionType = OperatorPlusNameType; break;
	case 'I': functionType = OperatorBitAndNameType; break;
	case 'J': functionType = OperatorArrowStarNameType; break;
	case 'K': functionType = OperatorDivideNameType; break;
	case 'L': functionType = OperatorModulusNameType; break;
	case 'M': functionType = OperatorLessThanNameType; break;
	case 'N': functionType = OperatorLessThanEqualNameType; break;
	case 'O': functionType = OperatorGreaterThanNameType; break;
	case 'P': functionType = OperatorGreaterThanEqualNameType; break;
	case 'Q': functionType = OperatorCommaNameType; break;
	case 'R': functionType = OperatorParenthesesNameType; break;
	case 'S': functionType = OperatorTildeNameType; break;
	case 'T': functionType = OperatorXorNameType; break;
	case 'U': functionType = OperatorBitOrNameType; break;
	case 'V': functionType = OperatorLogicalAndNameType; break;
	case 'W': functionType = OperatorLogicalOrNameType; break;
	case 'X': functionType = OperatorStarEqualNameType; break;
	case 'Y': functionType = OperatorPlusEqualNameType; break;
	case 'Z': functionType = OperatorMinusEqualNameType; break;
	case '_':
	{
		MSVC_TRACE(" {}: '{}'", __FUNCTION__, m_reader.GetRaw());
		switch (m_reader.Read())
		{
		case '0': functionType = OperatorDivideEqualNameType; break;
		case '1': functionType = OperatorModulusEqualNameType; break;
		case '2': functionType = OperatorRightShiftEqualNameType; break;
		case '3': functionType = OperatorLeftShiftEqualNameType; break;
		case '4': functionType = OperatorAndEqualNameType; break;
		case '5': functionType = OperatorOrEqualNameType; break;
		case '6': functionType = OperatorXorEqualNameType; break;
		case '7': functionType = VFTableNameType; break;
		case '8': functionType = VBTableNameType; break;
		case '9': functionType = VCallNameType; break;
		case 'A': functionType = TypeofNameType; break;
		case 'B': functionType = LocalStaticGuardNameType; break;
		case 'C': functionType = StringNameType; break;
		case 'D': functionType = VBaseDestructorNameType; break;
		case 'E': functionType = VectorDeletingDestructorNameType; break;
		case 'F': functionType = DefaultConstructorClosureNameType; break;
		case 'G': functionType = ScalarDeletingDestructorNameType; break;
		case 'H': functionType = VectorConstructorIteratorNameType; break;
		case 'I': functionType = VectorDestructorIteratorNameType; break;
		case 'J': functionType = VectorVBaseConstructorIteratorNameType; break;
		case 'K': functionType = VirtualDisplacementMapNameType; break;
		case 'L': functionType = EHVectorConstructorIteratorNameType; break;
		case 'M': functionType = EHVectorDestructorIteratorNameType; break;
		case 'N': functionType = EHVectorVBaseConstructorIteratorNameType; break;
		case 'O': functionType = CopyConstructorClosureNameType; break;
		case 'P': functionType = UDTReturningNameType; break;
		case 'S': functionType = LocalVFTableNameType; break;
		case 'T': functionType = LocalVFTableConstructorClosureNameType; break;
		case 'U': functionType = OperatorNewArrayNameType; break;
		case 'V': functionType = OperatorDeleteArrayNameType; break;
		case 'X': functionType = PlacementDeleteClosureNameType; break;
		case 'Y': functionType = PlacementDeleteClosureArrayNameType; break;
		case 'Q': // Fallthrough
		case 'W': // Fallthrough
		case 'Z': functionType = NoNameType; break;
		case '_':
		{
			MSVC_TRACE("  {}: '{}'", __FUNCTION__, m_reader.GetRaw());
			switch (const char extendedNameType = m_reader.Read())
			{
			case 'A': functionType = ManagedVectorConstructorIteratorNameType; break;
			case 'B': functionType = ManagedVectorDestructorIteratorNameType; break;
			case 'C': functionType = EHVectorCopyConstructorIteratorNameType; break;
			// ??__D is the *copy* variant per LLVM (MicrosoftDemangle.cpp:701).
			// Previously routed to EHVectorVBaseConstructorIteratorNameType
			// (the non-copy enum used by ??_O), which dropped the "copy" word.
			case 'D': functionType = EHVectorVBaseCopyConstructorIteratorNameType; break;
			// ??__E and ??__F are not reached here — they're handled at the
			// top level in DemangleSymbol, matching LLVM's special-intrinsic
			// dispatch. See DemangleDynamicInitFini.
			case 'E': // fall through — unreachable in practice
			case 'F': functionType = (extendedNameType == 'E') ? DynamicInitializerNameType : DynamicAtExitDestructorNameType; break;
			case 'G': functionType = VectorCopyConstructorIteratorNameType; break;
			case 'H': functionType = VectorVBaseCopyConstructorIteratorNameType; break;
			case 'I': functionType = ManagedVectorCopyConstructorIteratorNameType; break;
			case 'J': functionType = LocalStaticThreadGuardNameType; break;
			case 'K':
			{
				// User-defined literal operator: ??__K<suffix>@<scope-chain>
				// LLVM's demangleLiteralOperatorIdentifier consumes a simple
				// string terminated by '@' as the literal suffix and renders it
				// as `operator ""<suffix>`. The outer DemangleName loop then
				// picks up any enclosing scope chain as a normal prefix.
				functionType = UserDefinedLiteralOperatorNameType;
				_STD_STRING suffix = m_reader.ReadUntil('@');
				if (suffix.empty())
					throw DemangleException("??__K requires a non-empty literal suffix");
				out = "operator \"\"" + suffix;
				break;
			}
			case 'L': functionType = NoNameType; out = "operator co_await"; break;
			case 'M': functionType = NoNameType; out = "operator<=>"; break; // spaceship operator
			default: throw DemangleException("Demangle Lookup Failed"); // fall through
			}
			break;
		}
		default:
			throw DemangleException("Demangle Lookup Failed");
		}
		break;
	}
	default: throw DemangleException("Demangle Lookup Failed");
	}
	if (out.empty())
		out = Type::GetNameTypeString(functionType);
}


DemangledNamePart Demangle::DemangleTemplateInstantiationName(BackrefList& nameBackrefList)
{
	DemangledNamePart out;
	MSVC_TRACE("DemangleTemplateInstantiationName: '{}'", m_reader.GetRaw());
	if (!m_reader.ConsumeIf("?$"))
		throw DemangleException();
	char next = m_reader.PeekOr();
	if (next >= '0' && next <= '9')
	{
		out = nameBackrefList.GetNameBackref(m_reader.Read() - '0');
	}
	else
	{
		_STD_STRING name;
		DemangleNameTypeString(name);
		out = MakeNameSegment(name);
	}
	nameBackrefList.PushNameBackref(out);
	return out;
}


DemangledNamePart Demangle::DemangleTemplateInstantiationNameInLocalContext(BackrefList& nameBackrefList)
{
	DemangledNamePart out;
	BNNameType dummyFunctionType = NoNameType;
	MSVC_TRACE("DemangleTemplateInstantiationNameInLocalContext: '{}'", m_reader.GetRaw());

	{
		_STD_VECTOR<DemangledTypeNode::Param> params;
		bool backrefEligible = true;
		BackrefContextSwitch localContext(nameBackrefList);
		if (!m_reader.ConsumeIf("?$"))
			throw DemangleException();
		out = DemangleUnqualifiedSymbolName(nameBackrefList, dummyFunctionType, backrefEligible);
		if (backrefEligible && dummyFunctionType == NoNameType)
			nameBackrefList.PushNameBackref(out);
		DemangleTemplateParams(params, nameBackrefList, out);
	}

	// DemangleTemplateParams pushed into the temporary local context above.
	// Record the completed specialization again after BackrefContextSwitch
	// restores the enclosing context.
	nameBackrefList.PushTemplateSpecialization(out);
	nameBackrefList.PushNameBackref(out);
	return out;
}


void Demangle::DemangleTemplateParams(_STD_VECTOR<DemangledTypeNode::Param>& params, BackrefList& nameBackrefList, DemangledNamePart& out)
{
	NestingGuard nestingGuard(*this);
	params.clear();
	const bool nestedTemplateContext = (m_templateParamDepth > 0);
	struct NameBackrefScopeGuard
	{
		BackrefList& backrefs;
		size_t typeCount;
		size_t nameCount;
		~NameBackrefScopeGuard()
		{
			backrefs.typeList.resize(typeCount);
			backrefs.nameList.resize(nameCount);
		}
	};
	struct TemplateDepthGuard
	{
		size_t& depth;
		TemplateDepthGuard(size_t& depth): depth(depth) { depth++; }
		~TemplateDepthGuard() { depth--; }
	};

	{
		TemplateDepthGuard depthGuard(m_templateParamDepth);
		NameBackrefScopeGuard scopeGuard {
			nameBackrefList,
			nameBackrefList.typeList.size(),
			nameBackrefList.nameList.size()
		};

		DemangleVariableList(params, nameBackrefList, false);
	}

	out.SetTemplateArguments(params);
	nameBackrefList.PushTemplateSpecialization(out);
	if (nestedTemplateContext)
		nameBackrefList.PushNameBackref(out);
}


DemangledNamePart Demangle::DemangleUnqualifiedSymbolName(BackrefList& nameBackrefList, BNNameType& classFunctionType,
	bool& backrefEligible)
{
	backrefEligible = true;
	DemangledNamePart out;
	_STD_STRING text;
	if (m_reader.ConsumeIf('?'))
	{
		text.clear();
		DemangleTypeNameLookup(text, classFunctionType);
		out = MakeNameSegment(text);
		// Lookup-based operator names are not normal identifier components and
		// should not satisfy later scope backrefs such as strong_ordering@0@.
		backrefEligible = false;
	}
	else if (char next = m_reader.PeekOr(); next >= '0' && next <= '9')
	{
		out = nameBackrefList.GetNameBackref(m_reader.Read() - '0');
	}
	else
	{
		DemangleNameTypeString(text);
		out = MakeNameSegment(text);
	}
	return out;
}


DemangledTypeNode Demangle::DemangleString(NameList& symbolName)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	// ??_C@_<length><crc32>@<name>
	if (!m_reader.ConsumeIf('_'))
	{
		throw DemangleException("Invalid mangled string name");
	}

	// Wide char flag (1 yes / 0 no)
	bool isWideChar = false;
	switch (m_reader.Read())
	{
	case '1':
	case '2': // UTF-16/UTF-32 encoding variants
	case '3':
		isWideChar = true;
		break;
	case '0':
		break;
	default:
		throw DemangleException("Invalid mangled string name");
	}

	// Length is just a number

	uint64_t length = DecodeEncodedUnsignedNumber();

	MSVC_TRACE("{}: Before CRC32 '{}'", __FUNCTION__, m_reader.GetRaw());

	// CRC32 (ignored)
	while (m_reader.Peek() != '@')
	{
		// Usually 8 bytes but I've seen it be 7 for some ungodly reason
		m_reader.Consume();
	}

	m_reader.Consume();

	bool truncated = false;
	_STD_STRING name;
	_STD_STRING literalPrefix;
	DemangledTypeNode type;

	// String bytes
	if (isWideChar)
	{
		MSVC_TRACE("{}: Wide string '{}'", __FUNCTION__, m_reader.GetRaw());
		_STD_STRING utf8name;
		literalPrefix = "L";
		// Track the last wide char so we can detect missing null terminator.
		bool lastWideCharWasNull = false;
		size_t wcharCount = 0;
		while (m_reader.Peek() != '@')
		{
			char highByte = DemangleChar();
			char lowByte = DemangleChar();
			uint8_t chs[2] = {static_cast<uint8_t>(lowByte), static_cast<uint8_t>(highByte)};
			lastWideCharWasNull = (chs[0] == 0) && (chs[1] == 0);
			wcharCount++;

			// TODO: This is actually UCS2 but we don't have an easy decoder for that
			utf8name += Unicode::UTF16ToUTF8(&chs[0], 2);
		}
		m_reader.Consume();

		// MSVC string literals always mangle their trailing null. A payload
		// that doesn't end in a wide null means the original was too long to
		// fit in the mangling and was truncated. Matches LLVM's demangler.
		if (wcharCount == 0 || !lastWideCharWasNull)
			truncated = true;

		name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, utf8name.data(), utf8name.size());
		type = DemangledTypeNode::ArrayType(DemangledTypeNode::WideCharType(2), length / 2);
	}
	else
	{
		MSVC_TRACE("{}: Non-wide string '{}'", __FUNCTION__, m_reader.GetRaw());
		uint64_t numNulls = 0;
		size_t endNulls = 0;
		_STD_VECTOR<uint8_t> chars;
		while (m_reader.Peek() != '@')
		{
			char ch = DemangleChar();
			if (ch == 0)
			{
				numNulls++;
				endNulls++;
			}
			else
			{
				endNulls = 0;
			}
			chars.push_back(ch);
		}
		m_reader.Consume();

		if (length > static_cast<uint64_t>(chars.size()) + 1)
		{
			truncated = true;
		}
		// MSVC includes the trailing '\0' in the mangled payload. If the last
		// byte isn't a null, the original string was truncated to fit the
		// encoding's size limit — LLVM signals this with a `...` suffix.
		if (!chars.empty() && chars.back() != 0)
			truncated = true;

		// Now time to guess encoding. Only take a wide-character guess if both
		// the decoded byte payload and declared array length are aligned for it.
		const size_t payloadBytes = chars.size() - endNulls;
		if ((payloadBytes % 4 == 0) && (length % 4 == 0) && numNulls > length * 2 / 3)
		{
			MSVC_TRACE("{}: Looks like UTF32 '{}'", __FUNCTION__, m_reader.GetRaw());
			_STD_STRING utf8name;
			for (size_t i = 0; i < payloadBytes; i += 4)
			{
				utf8name += Unicode::UTF32ToUTF8(chars.data() + i);
			}
			name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, utf8name.data(), utf8name.size());
			literalPrefix = "U";
			type = DemangledTypeNode::ArrayType(DemangledTypeNode::WideCharType(4), length / 4);
		}
		else if ((payloadBytes % 2 == 0) && (length % 2 == 0) && numNulls > length / 3)
		{
			MSVC_TRACE("{}: Looks like UTF16 '{}'", __FUNCTION__, m_reader.GetRaw());
			_STD_STRING utf8name;
			for (size_t i = 0; i < payloadBytes; i += 2)
			{
				utf8name += Unicode::UTF16ToUTF8(chars.data() + i, 2);
			}
			name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, utf8name.data(), utf8name.size());
			literalPrefix = "L";
			type = DemangledTypeNode::ArrayType(DemangledTypeNode::WideCharType(2), length / 2);
		}
		else
		{
			MSVC_TRACE("{}: Looks like UTF8 '{}'", __FUNCTION__, m_reader.GetRaw());

			name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, chars.data(), chars.size() - endNulls);
			type = DemangledTypeNode::ArrayType(DemangledTypeNode::IntegerType(1, true), length);
		}
	}
	symbolName.clear();
	symbolName.push_back(MakeNameSegment(fmt::bnformat("{}\"{}\"{}", literalPrefix, name, truncated ? "..." : "")));
	return type;
}


DemangledTypeNode Demangle::DemangleTypeInfoName(NameList& symbolName)
{
	if (m_reader.Read() != '?')
		throw DemangleException("Unknown raw name type");
	bool _const = false;
	bool _volatile = false;
	bool isMember = false;
	DemangleModifiers(_const, _volatile, isMember);

	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());

	DemangledTypeNode type = DemangleVarType(m_backrefList, false);
	type.SetConst(_const);
	type.SetVolatile(_volatile);

	switch (type.GetClass())
	{
	case NamedTypeReferenceClass:
	{
		// Match LLVM's demangler: a raw type-info name (.?A...) renders as
		// `<rendered-type> `RTTI Type Descriptor Name''`. Bake the type
		// keyword + name into the symbol's qualified name, then return a
		// fresh NamedType marked RttiTypeDescriptor so BN's core type
		// formatter skips its own class/struct prefix - this mirrors the
		// treatment of ??_R0 in DemangleNameTypeRtti case '0'.
		_STD_STRING rendered = type.GetString() + " `RTTI Type Descriptor Name'";
		symbolName = { MakeNameSegment(rendered) };
		NameList rttiTypeName = type.GetName();
		if (rttiTypeName.empty())
			for (const auto& segment: type.RenderTypeNameSegments())
				rttiTypeName.push_back(MakeNameSegment(segment));
		DemangledTypeNode newType = DemangledTypeNode::NamedType(StructNamedTypeClass, std::move(rttiTypeName));
		newType.SetNameType(RttiTypeDescriptor);
		return newType;
	}
	default:
		throw DemangleException("Unexpected type of RTTI Type Name");
	}
}


void Demangle::PrependNameComponent(NameList& nameList, DemangledNamePart name)
{
	nameList.insert(nameList.begin(), std::move(name));
}


void Demangle::AppendStringName(NameList& nameList, BackrefList& nameBackrefList)
{
	_STD_STRING text;
	DemangleNameTypeString(text);
	DemangledNamePart name = MakeNameSegment(text);
	PrependNameComponent(nameList, name);
	nameBackrefList.PushNameBackref(std::move(name));
}


void Demangle::FinalizeConstructorTemplateName(NameList& nameList, size_t nameListSizeAtEntry, bool pending)
{
	if (!pending)
		return;

	if (nameList.size() <= nameListSizeAtEntry + 1)
		throw DemangleException("Constructor template missing class scope");

	DemangledNamePart& constructorTemplateName = nameList.back();
	if (!constructorTemplateName.HasTemplateArguments())
		throw DemangleException("Invalid constructor template name");

	// `??$?0...@Class@@` is a templated constructor. LLVM models `?0` as a
	// structor identifier and attaches the parsed enclosing class to it after
	// the qualified name is complete; Wine's undname does the same as a string
	// post-process. Keep the parsed template args and only fill in the
	// constructor's base name here:
	// `?0<Args>` becomes `Class<Args>`.
	constructorTemplateName.SetBase(nameList[nameList.size() - 2].GetString() +
		constructorTemplateName.GetBase());
}


bool Demangle::FunctionTypeHasPointerSuffix(char functionType)
{
	return functionType != 'C' && functionType != 'D' && functionType != 'K' && functionType != 'L'
		&& functionType != 'S' && functionType != 'T' && functionType != 'Y' && functionType != 'Z';
}


_STD_STRING Demangle::FormatFunctionScopeSignature(const DemangledTypeNode& type, const NameList& scopeName)
{
	_STD_STRING out = type.GetTypeAndName(FinalizeNameList(scopeName));
	while (!out.empty() && out.back() == ' ')
		out.pop_back();
	return out;
}


void Demangle::AppendLocalScope(NameList& nameList, BackrefList& nameBackrefList, uint64_t scopeOrdinal,
	bool typeNameContext)
{
	NameList scopeName;
	BNNameType scopeFunctionType = NoNameType;
	DemangleName(scopeName, scopeFunctionType, nameBackrefList, typeNameContext);

	if (m_reader.Length() == 0)
		throw DemangleException("Missing local scope function encoding");

	char ft = m_reader.Read();
	if (ft == '9' && m_reader.PeekOr() == '@')
	{
		PrependNameComponent(nameList, MakeNameSegment("`" + to_string(scopeOrdinal) + "'"));
		nameList.insert(nameList.begin(), scopeName.begin(), scopeName.end());
		return;
	}
	if (ft < 'A' || ft > 'Z')
		throw DemangleException("Invalid local scope function encoding");

	DemangledTypeNode scopeType = DemangleFunction(
		scopeFunctionType, FunctionTypeHasPointerSuffix(ft), nameBackrefList).type;

	PrependNameComponent(nameList, MakeNameSegment("`" + to_string(scopeOrdinal) + "'"));
	PrependNameComponent(nameList, MakeNameSegment("`" + FormatFunctionScopeSignature(scopeType, scopeName) + "'"));
}


bool Demangle::TryAppendLocalScopeAt(NameList& nameList, BackrefList& nameBackrefList,
	const char* encodedNumberStart, bool typeNameContext)
{
	struct LocalScopeParseCheckpoint
	{
		Demangle& demangler;
		BackrefList& backrefs;
		NameList& nameList;
		const char* reader;
		NameList savedNameList;
		size_t typeBackrefs;
		size_t nameBackrefs;
		size_t templateBackrefs;

		LocalScopeParseCheckpoint(Demangle& demangler, NameList& nameList, BackrefList& backrefs) :
			demangler(demangler),
			backrefs(backrefs),
			nameList(nameList),
			reader(demangler.m_reader.GetRaw()),
			savedNameList(nameList),
			typeBackrefs(backrefs.typeList.size()),
			nameBackrefs(backrefs.nameList.size()),
			templateBackrefs(backrefs.templateList.size())
		{
		}

		void Restore()
		{
			demangler.m_reader.SetRaw(reader);
			nameList = savedNameList;
			backrefs.typeList.resize(typeBackrefs);
			backrefs.nameList.resize(nameBackrefs);
			backrefs.templateList.resize(templateBackrefs);
		}
	};

	LocalScopeParseCheckpoint checkpoint(*this, nameList, nameBackrefList);

	m_reader.SetRaw(encodedNumberStart);
	uint64_t scopeOrdinal = 0;
	try
	{
		scopeOrdinal = DecodeEncodedUnsignedNumber();
	}
	catch (DemangleException&)
	{
		checkpoint.Restore();
		return false;
	}

	if (m_reader.PeekMatch("??", 2))
	{
		AppendLocalScope(nameList, nameBackrefList, scopeOrdinal, typeNameContext);
		return true;
	}

	checkpoint.Restore();
	return false;
}


void Demangle::DemangleName(NameList& nameList,
                            BNNameType& classFunctionType,
                            BackrefList& nameBackrefList,
                            bool typeNameContext)
{
	NestingGuard nestingGuard(*this);
	// NameList is stored outermost-first for QualifiedName, but MSVC encodes
	// names leaf-first. Ordinary parsed components are prepended; constructor
	// and destructor branches recurse to parse the class scope, then append the
	// synthesized leaf intentionally.
	size_t nameListSizeAtEntry = nameList.size();
	bool pendingConstructorTemplateName = false;

	DemangledNamePart out;
	_STD_STRING outText;
	BNNameType functionType = NoNameType;
	BNNameType dummyFunctionType = NoNameType;
	_STD_VECTOR<DemangledTypeNode::Param> params;

	size_t strippedNestedNamePrefixes = 0;
	while(true)
	{
		MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
		if (m_reader.ConsumeIf("??@"))
		{
			AppendStringName(nameList, nameBackrefList);
		}
		else if (m_reader.ConsumeIf("??"))
		{
			if (m_nestingDepth + strippedNestedNamePrefixes >= MAX_DEMANGLE_NESTING_DEPTH)
				throw DemangleException("Demangle nesting depth exceeded");
			strippedNestedNamePrefixes++;
			continue;
		}
		else if (m_reader.PeekMatch("?$", 2))
		{
			MSVC_TRACE("Demangle Template: '{}'", m_reader.GetRaw());
			if (typeNameContext || (m_templateParamDepth > 0) || (nameList.size() > nameListSizeAtEntry))
			{
				out = DemangleTemplateInstantiationNameInLocalContext(nameBackrefList);
			}
			else
			{
				if (!m_reader.ConsumeIf("?$"))
					throw DemangleException();
				BNNameType localFunctionType = NoNameType;
				bool backrefEligible = true;
				out = DemangleUnqualifiedSymbolName(nameBackrefList, localFunctionType, backrefEligible);
				if (backrefEligible && localFunctionType == NoNameType)
				{
					MSVC_TRACE("Pushing backref NameTemplate {}", out.GetString());
					nameBackrefList.PushNameBackref(out);
				}
				MSVC_TRACE("Demangling Template variables {}", m_reader.GetRaw());
				DemangleTemplateParams(params, nameBackrefList, out);
				if (localFunctionType == ConstructorNameType)
				{
					classFunctionType = ConstructorNameType;
					pendingConstructorTemplateName = true;
				}
			}
			PrependNameComponent(nameList, out);
		}
		else if (char next = m_reader.PeekOr(); next >= '0' && next <= '9')
		{
			MSVC_TRACE("Demangle Backref");
			out = nameBackrefList.GetNameBackref(m_reader.Read() - '0');
			MSVC_TRACE("Demangle Backref: {}", out.GetString());
			PrependNameComponent(nameList, out);
		}
		else if (m_reader.ConsumeIf('?'))
		{
			if (char next = m_reader.PeekOr(); next >= 'a' && next <= 'z')
			{
				// Lowercase after ? indicates a non-standard extension name
				// (e.g., ??null$initializer$ for thread-safe static init guards).
				AppendStringName(nameList, nameBackrefList);
			}
			else if (m_reader.PeekMatch("A0x", 3))
			{
				m_reader.Consume();
				DemangleNameTypeString(outText); // discard compiler-generated hash
				out = MakeNameSegment("`anonymous namespace'");
				PrependNameComponent(nameList, out);
				nameBackrefList.PushNameBackref(std::move(out));
			}
			else if (m_reader.ConsumeIf("_R"))
			{
				MSVC_TRACE("NameRtti");
				DemangleNameTypeRtti(classFunctionType, nameBackrefList, outText);
				out = MakeNameSegment(outText);
				PrependNameComponent(nameList, out);
			}
			else
			{
				bool parsedScopePrefix = false;
				if (nameList.size() > nameListSizeAtEntry)
				{
					parsedScopePrefix = TryAppendLocalScopeAt(nameList, nameBackrefList, m_reader.GetRaw(), typeNameContext) ||
						TryDemangleWinRTEscapedScopeName(nameList, nameBackrefList);
				}

				if (!parsedScopePrefix)
				{
					if (m_reader.ConsumeIf('0'))
					{
						MSVC_TRACE("NameConstructor");
						classFunctionType = ConstructorNameType;
						DemangleName(nameList, dummyFunctionType, nameBackrefList, typeNameContext);
						if (nameList.empty())
							throw DemangleException();
						nameList.push_back(nameList[nameList.size()-1]);
						return;
					}
					if (m_reader.ConsumeIf('1'))
					{
						MSVC_TRACE("NameDestructor");
						classFunctionType = ConstructorNameType;
						DemangleName(nameList, dummyFunctionType, nameBackrefList, typeNameContext);
						if (nameList.empty())
							throw DemangleException();
						nameList.push_back(MakeNameSegment("~" + nameList[nameList.size()-1].GetString()));
						return;
					}
					if (m_reader.ConsumeIf('B'))
					{
						MSVC_TRACE("NameReturn");
						classFunctionType = OperatorReturnTypeNameType;
						if (m_reader.PeekMatch("?$", 2))
						{
							if (m_templateParamDepth > 0)
							{
								out = DemangleTemplateInstantiationNameInLocalContext(nameBackrefList);
							}
							else
							{
								out = DemangleTemplateInstantiationName(nameBackrefList);
								DemangleTemplateParams(params, nameBackrefList, out);
							}
						}
						else
						{
							DemangleNameTypeString(outText);
							out = MakeNameSegment(outText);
							nameBackrefList.PushNameBackref(out);
						}
						PrependNameComponent(nameList, out);
					}
					else
					{
						MSVC_TRACE("Demangle Lookup");
						outText.clear();
						DemangleTypeNameLookup(outText, functionType);
						out = MakeNameSegment(outText);
						classFunctionType = functionType;
						PrependNameComponent(nameList, out);
						// Check if this is a scope specifier. Scope specifiers are ?<char>
						// followed by either @?? or directly ?? (for digit scopes like ?3??func@...)
						// When nameList has prior components, the operator name is actually a scope index
						// Also handle dynamic init/dtor wrapping ??@ (MD5 hash)
						if (m_reader.ConsumeIf("??@"))
						{
							_STD_STRING hash = m_reader.ReadUntil('@');
							PrependNameComponent(nameList, MakeNameSegment("??@" + hash + "@"));
							// Consume the trailing @ (name terminator) — the ??@hash@ pattern
							// is followed by @@ (end of scoped name) before the function type
							if (m_reader.Length() > 0)
								m_reader.ConsumeIf('@');
						}
					}
				}
			}
		}
		else
		{
			AppendStringName(nameList, nameBackrefList);
		}
		if (m_reader.ConsumeIf('@'))
		{
			FinalizeConstructorTemplateName(nameList, nameListSizeAtEntry, pendingConstructorTemplateName);
			return;
		}
	}
}



BNCallingConventionName Demangle::DemangleCallingConvention()
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	switch (m_reader.Read())
	{
	case 'A': //Exported function
	case 'B': return CdeclCallingConvention;
	case 'C': //Exported function
	case 'D': return PascalCallingConvention;
	case 'E': //Exported function
	case 'F': return ThisCallCallingConvention;
	case 'G': //Exported function
	case 'H': return STDCallCallingConvention;
	case 'I': //Exported function
	case 'J': return FastcallCallingConvention;
	case 'K': //Exported function
	case 'L': return NoCallingConvention;
	case 'M': //Exported function
	case 'N': return CLRCallCallingConvention;
	case 'O': //Exported function
	case 'P': return EabiCallCallingConvention;
	case 'Q': return VectorCallCallingConvention;
	case 'S': return SwiftCallingConvention;
	case 'W': return SwiftAsyncCallingConvention;
	default:throw DemangleException();
	}
}


void Demangle::ConsumeExtendedModifierPrefix()
{
	while (m_reader.ConsumeIf("$A"))
	{
	}
}


uint8_t Demangle::DemanglePointerSuffix()
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	uint8_t suffix = 0;
	if (m_reader.PeekOr() == '@')
		return suffix;

	char elm = m_reader.PeekOr();
	for (int i = 0; i < 5; i++, elm = m_reader.PeekOr())
	{
		if (elm == 'E')
			suffix |= (1u << Ptr64Suffix);
		else if (elm == 'F')
			suffix |= (1u << UnalignedSuffix);
		else if (elm == 'G')
			suffix |= (1u << ReferenceSuffix);
		else if (elm == 'H')
			suffix |= (1u << LvalueSuffix);
		else if (elm == 'I')
			suffix |= (1u << RestrictSuffix);
		else
			break;
		m_reader.Consume();
	}
	return suffix;
}

void Demangle::DemangleModifiers(bool& _const, bool& _volatile, bool &isMember)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	// Always write the out params, even when `@` marks the no-modifiers case.
	_const = false;
	_volatile = false;
	isMember = false;
	if (m_reader.PeekOr() == '@')
		return;

	switch (m_reader.Read())
	{
	case 'A': break;
	case 'B': //fall through
	case 'J': _const = true; break;
	case 'C': //fall through
	case 'G': //fall through
	case 'K': _volatile = true; break;
	case 'D': //fall through
	case 'H': //fall through
	case 'L': _const = true; _volatile = true; break;
	case '6': //fall through
	case '7': //fall through
	case 'M': //fall through
	case 'N': break;
	case 'O': _volatile = true; break;
	case 'P': _volatile = true; _const = true; break;
	case 'Q': isMember = true; break;
	case 'U': //fall through
	case 'Y': break;
	case 'R': _const = true; isMember = true; break;
	case 'V': //fall through
	case 'Z': _const = true; break;
	case 'S': _volatile = true; isMember = true; break;
	case 'W': //fall through
	case '0': _volatile = true; break;
	case 'T': _const = true; _volatile = true; isMember = true; break;
	case 'X': //fall through
	case '1': _const = true; _volatile = true; break;
	case '8': //fall through
	case '9': //fall through
	case '2': break;
	case '3': _const = true; break;
	case '4': _volatile = true; break;
	case '5': _const = true; _volatile = true; break;
	case '_':
		switch (m_reader.Read())
		{
		case 'A':
		case 'B':
		case 'C':
		case 'D':
			// Accepted but not currently modeled.
			break;
		default:
			throw DemangleException();
		}
		break;
	default: throw DemangleException();
	}
}


bool Demangle::FunctionClassNeedsImplicitThis(int funcClass)
{
	return funcClass != NoneFunctionClass
		&& (funcClass & StaticFunctionClass) != StaticFunctionClass
		&& (funcClass & GlobalFunctionClass) != GlobalFunctionClass;
}


void Demangle::AppendThunkAdjustorToName(NameList& nameList, const ThunkAdjustor& adjustor)
{
	switch (adjustor.kind)
	{
	case ThunkAdjustorKind::Static:
		AppendToLastNameSegment(nameList, "`adjustor{" + to_string(adjustor.adjustor) + "}'");
		return;
	case ThunkAdjustorKind::Vtordisp:
		AppendToLastNameSegment(nameList, "`vtordisp{" + to_string(adjustor.vtorDispOffset) + ", " +
			to_string(adjustor.staticOffset) + "}'");
		return;
	case ThunkAdjustorKind::Vtordispex:
		AppendToLastNameSegment(nameList, "`vtordispex{" + to_string(adjustor.vbptrOffset) + ", " +
			to_string(adjustor.vbOffsetOffset) + ", " + to_string(adjustor.vtorDispOffset) + ", " +
			to_string(adjustor.staticOffset) + "}'");
		return;
	}
}


void Demangle::SetImplicitThisParameter(DemangledTypeNode& type, BNNameType classFunctionType, const NameList& enclosingName)
{
	NameList thisName = enclosingName;
	if (classFunctionType != OperatorReturnTypeNameType && !thisName.empty())
		thisName.pop_back();
	auto thisNamedType = DemangledTypeNode::NamedType(TypedefNamedTypeClass, std::move(thisName));
	type.SetImplicitThisParameter(DemangledTypeNode::PointerType(
		std::move(thisNamedType), false, false, PointerReferenceType));
}


void Demangle::ApplySymbolFunctionContext(DemangledFunction& function, NameList& symbolName,
	BNNameType classFunctionType, int funcClass)
{
	if (function.thunkAdjustor)
		AppendThunkAdjustorToName(symbolName, *function.thunkAdjustor);
	if (FunctionClassNeedsImplicitThis(funcClass))
		SetImplicitThisParameter(function.type, classFunctionType, symbolName);
}


Demangle::DemangledFunction Demangle::DemangleFunction(BNNameType classFunctionType, bool pointerSuffix,
	BackrefList& nameBackrefList, int funcClass)
{
	NestingGuard nestingGuard(*this);
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	bool _const = false, _volatile = false;
	uint8_t suffix = 0;
	DemangledTypeNode returnType;
	BNCallingConventionName cc;
	std::optional<ThunkAdjustor> thunkAdjustor;

	// Thunk adjustors are part of the function grammar, but the symbol parser
	// owns the name that displays them.
	if ((funcClass & StaticThunkFunctionClass) == StaticThunkFunctionClass)
	{
		ThunkAdjustor adjustor {};
		adjustor.kind = ThunkAdjustorKind::Static;
		adjustor.adjustor = DecodeEncodedUnsignedNumber();
		thunkAdjustor = adjustor;
	}
	else if ((funcClass & VirtualThunkFunctionClass) == VirtualThunkFunctionClass)
	{
		if ((funcClass & VirtualThunkExFunctionClass) == VirtualThunkExFunctionClass)
		{
			ThunkAdjustor adjustor {};
			adjustor.kind = ThunkAdjustorKind::Vtordispex;
			adjustor.vbptrOffset = DecodeEncodedSignedInt32();
			adjustor.vbOffsetOffset = DecodeEncodedSignedInt32();
			adjustor.vtorDispOffset = DecodeEncodedSignedInt32();
			adjustor.staticOffset = DecodeEncodedUnsignedNumber();
			thunkAdjustor = adjustor;
		}
		else
		{
			ThunkAdjustor adjustor {};
			adjustor.kind = ThunkAdjustorKind::Vtordisp;
			adjustor.vtorDispOffset = DecodeEncodedSignedInt32();
			adjustor.staticOffset = DecodeEncodedUnsignedNumber();
			thunkAdjustor = adjustor;
		}
	}

	if (pointerSuffix)
	{
		bool isMember = false;
		suffix = DemanglePointerSuffix();
		ConsumeExtendedModifierPrefix();
		DemangleModifiers(_const, _volatile, isMember);
	}
	m_reader.ConsumeIf('?');
	cc = DemangleCallingConvention();
	bool shouldHaveReturnType = true;
	if (m_reader.ConsumeIf('@'))
	{
		//No return type
		shouldHaveReturnType = false;
		MSVC_TRACE("Function has no return type {}", m_reader.GetRaw());
	}
	else
	{
		//Demangle function return type
		bool return_const = false, return_volatile = false;
		uint8_t return_suffix = 0;
		bool hasModifiers = false;
		//Check for modifiers before return type
		if (m_reader.ConsumeIf('?'))
		{
			bool localIsMember = false;
			return_suffix = DemanglePointerSuffix();
			DemangleModifiers(return_const, return_volatile, localIsMember);
			hasModifiers = true;
		}

		MSVC_TRACE("Demangle function return type {}", m_reader.GetRaw());
		returnType = DemangleVarType(nameBackrefList, true);
		MSVC_TRACE("Return type: {}", returnType.GetString());
		// '...' (varargs) is only legal as the trailing parameter marker,
		// never as a return type. Reject so we don't build a bogus type.
		if (returnType.GetClass() == VarArgsTypeClass)
			throw DemangleException("Varargs ('Z') is not a valid function return type");
		if (hasModifiers)
		{
			returnType.SetConst(return_const);
			returnType.SetVolatile(return_volatile);
			returnType.SetPointerSuffixBits(return_suffix);
		}
	}
	m_reader.ConsumeIf('@');

	MSVC_TRACE("\tDemangle Function Parameters {}", m_reader.GetRaw());
	_STD_VECTOR<DemangledTypeNode::Param> params;

	DemangleVariableList(params, nameBackrefList);
	m_reader.ConsumeIf('Z');

	if (!params.empty() && params.back().type && params.back().type->GetClass() == VoidTypeClass)
		params.pop_back();

	if (!shouldHaveReturnType)
		returnType = DemangledTypeNode::VoidType();
	DemangledTypeNode newType = DemangledTypeNode::FunctionType(std::move(returnType), nullptr, std::move(params));
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	newType.SetPointerSuffixBits(suffix);
	newType.SetNameType(classFunctionType);
	newType.SetCallingConventionName(cc);

	MSVC_TRACE("Successfully Created Function Type!");
	return {std::move(newType), std::move(thunkAdjustor)};
}


DemangledTypeNode Demangle::DemangleData(BackrefList& varList)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	DemangledTypeNode newType = DemangleVarType(varList, false);
	auto suffix = DemanglePointerSuffix();
	DemangleModifiers(_const, _volatile, isMember);
	if (newType.GetClass() == PointerTypeClass)
	{
		newType.AddPointerSuffixBits(suffix);
		newType.AddQualifiersToPointerChild(_const, _volatile);
	}
	else
	{
		newType.SetConst(_const);
		newType.SetVolatile(_volatile);
		newType.SetPointerSuffixBits(suffix);
	}
	return newType;
}


DemangledTypeNode Demangle::DemangleRTTI(BNNameType nameType, const NameList& symbolName)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	if (m_reader.Length() > 0)
		DemangleModifiers(_const, _volatile, isMember);
	NameList typeName = symbolName;
	MSVC_TRACE("new struct type");
	DemangledTypeNode newType = DemangledTypeNode::NamedType(StructNamedTypeClass, typeName);
	newType.SetNameType(nameType);
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	MSVC_TRACE("log: {}", newType.GetString());
	return newType;
}


DemangledTypeNode Demangle::DemangleVTable(BackrefList& nameBackrefList, NameList& symbolName)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	DemangleModifiers(_const, _volatile, isMember);
	DemangledTypeNode newType = DemangledTypeNode::NamedType(StructNamedTypeClass, symbolName);
	if (m_reader.PeekOr() != '@')
	{
		NameList typeName;
		BNNameType classFunctionType = NoNameType;
		DemangleName(typeName, classFunctionType, nameBackrefList, true);
		if (symbolName.empty())
			throw DemangleException("VTable name missing suffix");
		DemangledNamePart suffix = symbolName.back();
		AppendToLastNameSegment(symbolName, "{for `" + JoinNameList(typeName) + "'}");

		typeName.push_back(suffix);
		newType = DemangledTypeNode::NamedType(StructNamedTypeClass, typeName);
	}
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	newType.SetNameType(VFTableNameType);
	return newType;
}


// ??__E (dynamic initializer) / ??__F (dynamic atexit destructor).
//
// LLVM dispatches these at the top level via demangleSpecialIntrinsic -->
// demangleInitFiniStub. The mangling wraps another symbol (either a variable
// or a function) and emits a new function stub that initializes/destroys it:
//
//   ??__E<fn-symbol>                   function form, e.g. ??__Efoo@@YAXXZ
//   ??__E?<var-symbol>@@<fn-encoding>  variable form, e.g. ??__E?foo@@3HA@@YAXXZ
//
// LLVM's output places the descriptor (`dynamic initializer for '<target>'`)
// at file scope — not as a member of the target's enclosing class — and
// interpolates the target name inside backticks/quotes. For the variable
// form, it additionally renders the variable's type inside the inner
// backtick pair: `dynamic initializer for `int foo''.
Demangle::DemangleContext Demangle::DemangleDynamicInitFini(bool isDtor, BackrefList& backrefList)
{
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());

	// /d2FH4 may replace a long wrapped target with an MD5 name (??@<hash>@).
	// Parse it before the optional '?' marker below; otherwise the first '?'
	// of the hash spelling is mistaken for IsKnownStaticDataMember.
	NameList innerNameList;
	BNNameType innerClassFunctionType = NoNameType;
	bool isMD5Name = false;
	if (m_reader.ConsumeIf("??@"))
	{
		_STD_STRING hash = m_reader.ReadUntil('@');
		innerNameList.push_back(MakeNameSegment("??@" + hash + "@"));
		isMD5Name = true;
	}

	// Optional leading '?' flags the "known static data member" form. LLVM
	// calls this IsKnownStaticDataMember — when present, the mangling is
	// required to carry two trailing '@' before the outer function encoding
	// rather than one.
	bool isKnownStaticDataMember = false;
	if (!isMD5Name && m_reader.ConsumeIf('?'))
	{
		isKnownStaticDataMember = true;
	}

	// Parse the inner symbol's qualified name exactly as any other symbol
	// would. DemangleName handles locally-scoped pieces, anonymous namespaces,
	// templates, etc. so a target like
	//   instance@?1??Get@Globals@@SAAEAU1@XZ@
	// resolves correctly.
	if (!isMD5Name)
		DemangleName(innerNameList, innerClassFunctionType, backrefList);

	const char* prefix = isDtor
		? "`dynamic atexit destructor for "
		: "`dynamic initializer for ";
	BNNameType classFunctionType = isDtor
		? DynamicAtExitDestructorNameType
		: DynamicInitializerNameType;

	_STD_STRING descriptor;

	if (m_reader.Length() == 0)
		throw DemangleException("Truncated ??__E/??__F");

	char next = m_reader.Peek();
	if (next >= '0' && next <= '4')
	{
		// Variable form: <storage-class><type-encoding> <@-terminators>
		// <outer-function-encoding>. We don't attach the storage class to
		// anything — it exists only to disambiguate variable-vs-function
		// inside the wrapper and to match the mangling grammar.
		m_reader.Consume(); // storage class
		DemangledTypeNode varType = DemangleData(backrefList);
		_STD_STRING varTypeStr = varType.GetString();
		_STD_STRING innerJoined = JoinNameList(innerNameList);
		descriptor = _STD_STRING(prefix) + "`" + varTypeStr + " " + innerJoined + "''";

		// Consume the @-terminators between the inner variable encoding and
		// the outer function encoding. LLVM requires two when the optional
		// leading '?' was present, one otherwise.
		int atCount = isKnownStaticDataMember ? 2 : 1;
		for (int i = 0; i < atCount; i++)
		{
			if (m_reader.Length() == 0 || m_reader.Read() != '@')
				throw DemangleException("Expected '@' terminator in ??__E/??__F variable form");
		}
	}
	else
	{
		// Function form: the inner symbol's function encoding follows
		// directly. The outer stub reuses that encoding (there's no separate
		// outer signature).
		if (isKnownStaticDataMember)
			throw DemangleException("??__E/??__F with leading '?' but no variable form");
		if (isMD5Name)
		{
			while (m_reader.ConsumeIf('@'))
			{
			}
		}
		_STD_STRING innerJoined = JoinNameList(innerNameList);
		descriptor = _STD_STRING(prefix) + "'" + innerJoined + "''";
	}

	// Replace the symbol's qualified name with just the descriptor — this is
	// what puts the output at file scope with no enclosing class prefix.
	NameList descriptorName = { MakeNameSegment(descriptor) };

	auto parseOuterFunction = [&](bool pointerSuffix, int funcClass, BNMemberAccess access, BNMemberScope scope) {
		DemangledFunction function = DemangleFunction(classFunctionType, pointerSuffix, backrefList, funcClass);
		ApplySymbolFunctionContext(function, descriptorName, classFunctionType, funcClass);
		return DemangleContext{std::move(descriptorName), std::move(function.type), access, scope};
	};

	// Parse the outer function encoding. MSVC emits a global cdecl stub
	// ('Y'/'Z') in practice but we dispatch through the full table for
	// robustness (private/public/static/etc.).
	if (m_reader.Length() == 0)
		throw DemangleException("Truncated ??__E/??__F outer function encoding");
	switch (char funcType = m_reader.Read())
	{
	case 'A': //fall through
	case 'B': return parseOuterFunction(true,  PrivateFunctionClass,                         PrivateAccess,   NoScope    );
	case 'C': //fall through
	case 'D': return parseOuterFunction(false, PrivateFunctionClass | StaticFunctionClass,   PrivateAccess,   StaticScope);
	case 'I': //fall through
	case 'J': return parseOuterFunction(true,  ProtectedFunctionClass,                       ProtectedAccess, NoScope    );
	case 'K': //fall through
	case 'L': return parseOuterFunction(false, ProtectedFunctionClass | StaticFunctionClass, ProtectedAccess, StaticScope);
	case 'Q': //fall through
	case 'R': return parseOuterFunction(true,  PublicFunctionClass,                          PublicAccess,    NoScope    );
	case 'S': //fall through
	case 'T': return parseOuterFunction(false, PublicFunctionClass | StaticFunctionClass,    PublicAccess,    StaticScope);
	case 'Y': //fall through
	case 'Z': return parseOuterFunction(false, GlobalFunctionClass,                          NoAccess,        NoScope    );
	default:
		throw DemangleException(_STD_STRING("Unexpected outer function type '") + funcType + "' in ??__E/??__F");
	}
}


Demangle::DemangleContext Demangle::DemangleSymbol()
{
	return DemangleSymbol(m_backrefList);
}


Demangle::DemangleContext Demangle::DemangleSymbol(BackrefList& backrefList)
{
	NestingGuard nestingGuard(*this);
	MSVC_TRACE("{}: '{}'", __FUNCTION__, m_reader.GetRaw());
	BNNameType classFunctionType = NoNameType;
	NameList varName;

	if (m_reader.ConsumeIf('.'))
	{
		NameList typeInfoName;
		DemangledTypeNode type = DemangleTypeInfoName(typeInfoName);
		return { std::move(typeInfoName), std::move(type), NoAccess, NoScope };
	}

	if (m_reader.Read() != '?')
	{
		throw DemangleException();
	}

	// MD5-hashed names: ??@<32hex>@
	if (m_reader.ConsumeIf("?@"))
	{
		_STD_STRING hash = m_reader.ReadUntil('@');
		NameList md5Name = { MakeNameSegment("??@" + hash + "@") };
		return { std::move(md5Name), DemangledTypeNode::VoidType(), NoAccess, NoScope };
	}

	// Special intrinsics dispatched at the top level (matches LLVM's
	// demangleSpecialIntrinsic). ??__E/??__F have a non-uniform grammar
	// that the normal DemangleName scope-chain loop can't express — the
	// bytes after the code are a wrapped inner symbol, not scope prefixes.
	if (m_reader.ConsumeIf("?__E"))
		return DemangleDynamicInitFini(false, backrefList);
	if (m_reader.ConsumeIf("?__F"))
		return DemangleDynamicInitFini(true, backrefList);

	DemangleName(varName, classFunctionType, backrefList);
	MSVC_TRACE("Done demangling Name: '{}' - '{}'", JoinNameList(varName), m_reader.GetRaw());

	DemangleContext context;
	auto setContext = [&](DemangledTypeNode type, BNMemberAccess access, BNMemberScope scope) {
		context.type = std::move(type);
		context.access = access;
		context.scope = scope;
	};
	auto finishContext = [&]() {
		context.name = std::move(varName);
		return std::move(context);
	};

	if (classFunctionType == StringNameType)
	{
		setContext(DemangleString(varName), NoAccess, NoScope);
		return finishContext();
	}

	// ??__J (local static thread guard) and local-scope ??_B guards are
	// variables, not functions. The storage marker is '4' (not visible) or '5'
	// (visible). Some local guard names then carry a one-digit local ordinal
	// instead of a type encoding, e.g. `...@51` -> `{2}`.
	char nextSymbolByte = m_reader.PeekOr();
	if ((classFunctionType == LocalStaticThreadGuardNameType)
		|| (classFunctionType == LocalStaticGuardNameType && m_reader.Length() >= 2
			&& (nextSymbolByte == '4' || nextSymbolByte == '5')
			&& m_reader.PeekAt(1) >= '0' && m_reader.PeekAt(1) <= '9'))
	{
		if (m_reader.Length() == 0)
			throw DemangleException("Truncated local static guard");
		char next = m_reader.Read();
		if (next != '4' && next != '5')
			throw DemangleException("local static guard requires variable storage class ('4' or '5'), got '" + _STD_STRING(1, next) + "'");
		if (char next = m_reader.PeekOr(); next >= '0' && next <= '9')
		{
			int64_t guardOrdinal = m_reader.Read() - '0' + 1;
			AppendToLastNameSegment(varName, "{" + to_string(guardOrdinal) + "}");
			setContext(DemangledTypeNode::IntegerType(4, false), NoAccess, NoScope);
			return finishContext();
		}
		setContext(DemangleData(backrefList), NoAccess, NoScope);
		return finishContext();
	}

	auto setDataContext = [&](BNMemberAccess access, BNMemberScope scope) {
		setContext(DemangleData(backrefList), access, scope);
	};
	auto setFunctionContext = [&](bool pointerSuffix, int funcClass, BNMemberAccess access, BNMemberScope scope) {
		DemangledFunction function = DemangleFunction(classFunctionType, pointerSuffix, backrefList, funcClass);
		ApplySymbolFunctionContext(function, varName, classFunctionType, funcClass);
		setContext(std::move(function.type), access, scope);
	};

	switch(char funcType = m_reader.Read())
	{
	case '0': setDataContext(PrivateAccess,   StaticScope); break;
	case '1': setDataContext(ProtectedAccess, StaticScope); break;
	case '2': setDataContext(PublicAccess,    StaticScope); break;
	case '3': //fall through
	case '4': setDataContext(NoAccess,        NoScope    ); break;
	case '5':  //fall through
	case '6':  //fall through
	case '7':
		setContext(DemangleVTable(backrefList, varName), NoAccess, NoScope);
		break;
	case '8':  //fall through
	case '9':
		setContext(DemangleRTTI(classFunctionType, varName), NoAccess, NoScope);
		break;
	case 'A':  //fall through
	case 'B': setFunctionContext(true,  PrivateFunctionClass,                                  PrivateAccess,   NoScope     ); break;
	case 'C': //fall through
	case 'D': setFunctionContext(false, PrivateFunctionClass | StaticFunctionClass,            PrivateAccess,   StaticScope ); break;
	case 'E': //fall through
	case 'F': setFunctionContext(true,  PrivateFunctionClass | VirtualFunctionClass,           PrivateAccess,   VirtualScope); break;
	case 'G': //fall through
	case 'H': setFunctionContext(true,  PrivateFunctionClass | StaticThunkFunctionClass,       PrivateAccess,   ThunkScope  ); break;
	case 'I': //fall through
	case 'J': setFunctionContext(true,  ProtectedFunctionClass,                                ProtectedAccess, NoScope     ); break;
	case 'K': //fall through
	case 'L': setFunctionContext(false, ProtectedFunctionClass | StaticFunctionClass,          ProtectedAccess, StaticScope ); break;
	case 'M': //fall through
	case 'N': setFunctionContext(true,  ProtectedFunctionClass | VirtualFunctionClass,         ProtectedAccess, VirtualScope); break;
	case 'O': //fall through
	case 'P': setFunctionContext(true,  ProtectedFunctionClass | StaticThunkFunctionClass,     ProtectedAccess, ThunkScope  ); break;
	case 'Q': //fall through
	case 'R': setFunctionContext(true,  PublicFunctionClass,                                   PublicAccess,    NoScope     ); break;
	case 'S': //fall through
	case 'T': setFunctionContext(false, PublicFunctionClass | StaticFunctionClass,             PublicAccess,    StaticScope ); break;
	case 'U': //fall through
	case 'V': setFunctionContext(true,  PublicFunctionClass | VirtualFunctionClass,            PublicAccess,    VirtualScope); break;
	case 'W': //fall through
	case 'X': setFunctionContext(true,  PublicFunctionClass | StaticThunkFunctionClass,        PublicAccess,    ThunkScope  ); break;
	case 'Y': //fall through
	case 'Z': setFunctionContext(false, GlobalFunctionClass,                                   NoAccess,        NoScope     ); break;
	case '$':
	{
		if (m_reader.ConsumeIf('B'))
		{
			// Vcall thunk: $B<encoded_offset><calling_convention><this_type>
			uint64_t offset = DecodeEncodedUnsignedNumber();
			if (varName.empty())
				throw DemangleException("Vcall thunk missing name");
			varName.back() = MakeNameSegment("`vcall'{" + to_string(offset) + ", {flat}}'");
			// Consume calling convention char + this-type flag char
			if (m_reader.Length() >= 1)
				m_reader.Consume(); // calling convention (A=cdecl, etc.)
			char next = m_reader.PeekOr();
			if (next != '\0' && next != '@')
				m_reader.Consume(); // this-type flag
			setContext(DemangledTypeNode::VoidType(), NoAccess, NoScope);
			break;
		}
		int funcClass = VirtualThunkFunctionClass;
		if (m_reader.ConsumeIf('R'))
		{
			funcClass |= VirtualThunkExFunctionClass;
		}
		switch (char thunkType = m_reader.Read())
		{
		case '0': //fall through
		case '1': setFunctionContext(true, funcClass | VirtualFunctionClass | PrivateFunctionClass,   PrivateAccess,   ThunkScope); break;
		case '2': //fall through
		case '3': setFunctionContext(true, funcClass | VirtualFunctionClass | ProtectedFunctionClass, ProtectedAccess, ThunkScope); break;
		case '4': //fall through
		case '5': setFunctionContext(true, funcClass | VirtualFunctionClass | PublicFunctionClass,    PublicAccess,    ThunkScope); break;
		default: throw DemangleException("Unknown virtual thunk type " + _STD_STRING(1, thunkType));
		}
		break;
	}
	default:  throw DemangleException("Unknown function type " + _STD_STRING(1, funcType));
	}
	return finishContext();
}

std::pair<Ref<Type>, QualifiedName> Demangle::Finalize(BinaryView* view)
{
	DemangleContext context = DemangleSymbol();
	if (m_reader.Length() != 0)
		LogDebugF("Demangling Succeeded with trailing characters '{}' in '{}'", m_reader.GetRaw(), m_mangledName);

	Ref<Platform> platform = m_platform;
	if (!platform && view)
		platform = view->GetDefaultPlatform();

	Architecture* arch = m_arch;
#ifdef BINARYNINJACORE_LIBRARY
	if (!arch && platform)
		arch = platform->GetArchitecture();
	if (!arch && view)
		arch = view->GetDefaultArchitecture();
#else
	Ref<Architecture> viewArch;
	Ref<Architecture> platformArch;
	if (!arch && platform)
	{
		platformArch = platform->GetArchitecture();
		arch = platformArch.GetPtr();
	}
	if (!arch && view)
	{
		viewArch = view->GetDefaultArchitecture();
		arch = viewArch.GetPtr();
	}
#endif
	if (!arch)
		throw DemangleException();

	if (!platform)
		platform = arch->GetStandalonePlatform();

	return {context.type.Finalize(platform.GetPtr()), QualifiedName(FinalizeNameList(context.name))};
}

std::pair<Ref<Type>, QualifiedName> Demangle::Finalize()
{
	return Finalize(m_view.GetPtr());
}

template <typename DemangleBody>
static bool DemangleMSImpl(const _STD_STRING& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
	DemangleBody&& demangleBody)
{
	outType = nullptr;
	if (mangledName.empty() || (mangledName[0] != '?' && mangledName[0] != '.'))
		return false;

	try
	{
		auto result = demangleBody();
		outType = std::move(result.first);
		outVarName = std::move(result.second);
		return true;
	}
	catch (DemangleException& e)
	{
		LogDebugF("Demangling Failed '{}' '{}'", mangledName, e.what());
		return false;
	}
	catch (std::exception& e)
	{
		LogDebugF("Demangling Failed '{}' '{}'", mangledName, e.what());
		return false;
	}
}

bool Demangle::DemangleMS(Architecture* arch, const _STD_STRING& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, const Ref<BinaryView>& view)
{
	if (view)
	{
		return DemangleMSImpl(mangledName, outType, outVarName, [&]() {
			Demangle demangle(arch, mangledName);
			return demangle.Finalize(view.GetPtr());
		});
	}
	return DemangleMS(arch, mangledName, outType, outVarName);
}

bool Demangle::DemangleMS(Architecture* arch, const _STD_STRING& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, BinaryView* view)
{
	if (view)
		return DemangleMS(arch, mangledName, outType, outVarName, Ref<BinaryView>(view));
	return DemangleMS(arch, mangledName, outType, outVarName);
}

bool Demangle::DemangleMS(Platform* platform, const _STD_STRING& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName)
{
	outType = nullptr;
	if (!platform)
		return false;

	return DemangleMSImpl(mangledName, outType, outVarName, [&]() {
		Demangle demangle(Ref<Platform>(platform), mangledName);
		return demangle.Finalize();
	});
}

bool Demangle::DemangleMS(Architecture* arch, const _STD_STRING& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName)
{
	return DemangleMSImpl(mangledName, outType, outVarName, [&]() {
		thread_local Demangle demangle(arch, mangledName);
		demangle.Reset(arch, mangledName);
		return demangle.Finalize();
	});
}


bool Demangle::DemangleMS(const _STD_STRING& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, const Ref<BinaryView>& view)
{
	return DemangleMSImpl(mangledName, outType, outVarName, [&]() {
		// Can't use thread_local here — BinaryView overload needs platform/view state
		Demangle demangle(view, mangledName);
		return demangle.Finalize();
	});
}

bool Demangle::DemangleMS(const _STD_STRING& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, BinaryView* view)
{
	outType = nullptr;
	if (!view)
		return false;
	return DemangleMS(mangledName, outType, outVarName, Ref<BinaryView>(view));
}


class MSDemangler: public Demangler
{
public:
	MSDemangler(): Demangler("MS")
	{
	}
	~MSDemangler() override = default;

	bool IsMangledString(const _STD_STRING& name) override
	{
		return !name.empty() && (name[0] == '?' || name[0] == '.');
	}

#ifdef BINARYNINJACORE_LIBRARY
	bool Demangle(Architecture* arch, const _STD_STRING& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      BinaryView* view) override
#else
	virtual bool Demangle(Ref<Architecture> arch, const _STD_STRING& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      Ref<BinaryView> view) override
#endif
	{
		if (view)
			return Demangle::DemangleMS(arch, name, outType, outVarName, view);
		return Demangle::DemangleMS(arch, name, outType, outVarName);
	}
};

extern "C"
{
#ifndef BINARYNINJACORE_LIBRARY
	BN_DECLARE_CORE_ABI_VERSION
#endif

#ifdef BINARYNINJACORE_LIBRARY
	bool DemangleMSVCPluginInit()
#elif defined(DEMO_EDITION)
	bool DemangleMSVCPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		static auto demangler = new MSDemangler();
		Demangler::Register(demangler);
		return true;
	}
}
