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

#include "demangled_template_simplifier.h"

#include <algorithm>
#include <initializer_list>
#include <memory>
#include <string_view>

#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#else
using namespace BinaryNinja;
using namespace std;
#endif

namespace
{
	using Param = DemangledTypeNode::Param;
	using ParamList = vector<Param>;

	std::string_view TrimSpaces(std::string_view s)
	{
		size_t start = 0;
		while (start < s.size() && s[start] == ' ')
			start++;
		size_t end = s.size();
		while (end > start && s[end - 1] == ' ')
			end--;
		return s.substr(start, end - start);
	}

	bool StartsWith(std::string_view s, const char* prefix)
	{
		size_t n = strlen(prefix);
		return s.compare(0, n, prefix) == 0;
	}

	std::string_view StripLeadingTypeKeyword(std::string_view s)
	{
		s = TrimSpaces(s);
		if (StartsWith(s, "class "))
			return s.substr(6);
		if (StartsWith(s, "struct "))
			return s.substr(7);
		if (StartsWith(s, "union "))
			return s.substr(6);
		if (StartsWith(s, "enum "))
			return s.substr(5);
		return s;
	}

	string RemoveSpaces(std::string_view s)
	{
		string out;
		out.reserve(s.size());
		for (char c : s)
		{
			if (c != ' ')
				out += c;
		}
		return out;
	}

	bool StringEquals(const string& s, std::string_view value)
	{
		return s.size() == value.size() &&
			(value.empty() || memcmp(s.data(), value.data(), value.size()) == 0);
	}

	bool IsUnqualifiedNonPointerType(const DemangledTypeNode& type)
	{
		return !type.IsConst() && !type.IsVolatile() && type.GetPointerSuffixBits() == 0;
	}

	size_t ResolvedIntegerWidth(size_t width, DemangledTypeNode::WidthKind widthKind)
	{
		switch (widthKind)
		{
		case DemangledTypeNode::AddressWidth:
			return 8;
		case DemangledTypeNode::DefaultIntegerWidth:
			return 4;
		case DemangledTypeNode::FixedWidth:
		default:
			return width;
		}
	}

	bool GetUnqualifiedIntegerTypeInfo(const DemangledTypeNode& type, size_t& width,
		DemangledTypeNode::WidthKind& widthKind, bool& isSigned, std::string_view& altName)
	{
		return IsUnqualifiedNonPointerType(type) && type.GetIntegerTypeInfo(width, widthKind, isSigned, altName);
	}

	bool GetUnqualifiedWideCharTypeInfo(const DemangledTypeNode& type, size_t& width,
		std::string_view& altName)
	{
		return IsUnqualifiedNonPointerType(type) && type.GetWideCharTypeInfo(width, altName);
	}

	string CanonicalTypeNoSpaces(const DemangledTypeNode& type)
	{
		string s = type.GetString();
		return RemoveSpaces(StripLeadingTypeKeyword(std::string_view(s.data(), s.size())));
	}

	string CanonicalTypeNoSpaces(std::string_view type)
	{
		return RemoveSpaces(StripLeadingTypeKeyword(type));
	}

	bool SameType(const DemangledTypeNode& a, const DemangledTypeNode& b)
	{
		if (a.IsStructurallyEqual(b))
			return true;
		return CanonicalTypeNoSpaces(a) == CanonicalTypeNoSpaces(b);
	}

	bool SameType(const DemangledTypeNode& a, std::string_view b)
	{
		if (!a.IsConst() && !a.IsVolatile() && a.GetPointerSuffixBits() == 0 && a.GetClass() == NamedTypeReferenceClass)
		{
			const DemangledQualifiedName& name = a.GetName();
			if (name.size() == 1 && !name[0].HasTemplateArguments())
			{
				const string& base = name[0].GetBase();
				if (StringEquals(base, b))
					return true;
			}
		}
		return CanonicalTypeNoSpaces(a) == CanonicalTypeNoSpaces(b);
	}

	bool IsSimpleNamedType(const DemangledTypeNode& type, std::string_view name, bool cnst = false)
	{
		if (type.IsConst() != cnst || type.IsVolatile() || type.GetPointerSuffixBits() != 0 ||
			type.GetClass() != NamedTypeReferenceClass)
			return false;

		const DemangledQualifiedName& typeName = type.GetName();
		if (typeName.size() != 1 || typeName[0].HasTemplateArguments())
			return false;
		const string& base = typeName[0].GetBase();
		return StringEquals(base, name);
	}

	bool IsQualifiedName(const DemangledTypeNode& type, std::initializer_list<std::string_view> expected)
	{
		if (!IsUnqualifiedNonPointerType(type) || type.GetClass() != NamedTypeReferenceClass)
			return false;

		const DemangledQualifiedName& name = type.GetName();
		if (name.size() != expected.size())
			return false;

		size_t i = 0;
		for (std::string_view expectedSegment : expected)
		{
			if (name[i].HasTemplateArguments() || !StringEquals(name[i].GetBase(), expectedSegment))
				return false;
			i++;
		}
		return true;
	}

	const char* CharFamilyAliasName(const DemangledTypeNode& element, const char* charAlias,
		const char* wcharAlias, const char* char8Alias = nullptr, const char* char16Alias = nullptr,
		const char* char32Alias = nullptr)
	{
		size_t width = 0;
		DemangledTypeNode::WidthKind widthKind = DemangledTypeNode::FixedWidth;
		bool isSigned = false;
		std::string_view altName;
		if (GetUnqualifiedIntegerTypeInfo(element, width, widthKind, isSigned, altName))
		{
			if (char8Alias && altName == "char8_t")
				return char8Alias;
			if (isSigned && (altName.empty() || altName == "char") &&
				ResolvedIntegerWidth(width, widthKind) == 1)
				return charAlias;
		}

		size_t wideWidth = 0;
		std::string_view wideAltName;
		if (GetUnqualifiedWideCharTypeInfo(element, wideWidth, wideAltName))
		{
			if (char16Alias && wideAltName == "char16_t")
				return char16Alias;
			if (char32Alias && wideAltName == "char32_t")
				return char32Alias;
			if (wideAltName.empty() || wideAltName == "wchar_t")
				return wcharAlias;
		}

		if (IsSimpleNamedType(element, "char"))
			return charAlias;
		if (IsSimpleNamedType(element, "wchar_t"))
			return wcharAlias;
		if (char8Alias && IsSimpleNamedType(element, "char8_t"))
			return char8Alias;
		if (char16Alias && IsSimpleNamedType(element, "char16_t"))
			return char16Alias;
		if (char32Alias && IsSimpleNamedType(element, "char32_t"))
			return char32Alias;

		const string type = CanonicalTypeNoSpaces(element);
		if (type == "char")
			return charAlias;
		if (type == "wchar_t")
			return wcharAlias;
		if (char8Alias && type == "char8_t")
			return char8Alias;
		if (char16Alias && type == "char16_t")
			return char16Alias;
		if (char32Alias && type == "char32_t")
			return char32Alias;
		return nullptr;
	}

	bool HasOnlyOmittedPointerSuffixes(const DemangledTypeNode& type)
	{
		return (type.GetPointerSuffixBits() & ~(1u << Ptr64Suffix)) == 0;
	}

	bool IsConstTypeNamed(const DemangledTypeNode& type, std::string_view name)
	{
		if (IsSimpleNamedType(type, name, true))
			return true;
		if (!type.IsConst() || type.IsVolatile())
			return false;

		DemangledTypeNode unqualified = type;
		unqualified.SetConst(false);
		return SameType(unqualified, name);
	}

	bool IsInlineStdNamespace(const DemangledNamePart& component)
	{
		if (component.HasTemplateArguments())
			return false;
		const string& name = component.GetBase();
		return name == "__1" || name == "__cxx11" || name == "__detail";
	}

	bool IsAbslInlineNamespace(const DemangledNamePart& component)
	{
		if (component.HasTemplateArguments())
			return false;
		const string& name = component.GetBase();
		if (!StartsWith(name, "lts_"))
			return false;
		for (size_t i = 4; i < name.size(); i++)
		{
			if (!isdigit(static_cast<unsigned char>(name[i])) && name[i] != '_')
				return false;
		}
		return name.size() > 4;
	}

	bool IsStdScope(const DemangledQualifiedName& name, size_t* templateIndex)
	{
		if (name.empty() || name[0].HasTemplateArguments() || name[0].GetBase() != "std")
			return false;

		size_t i = 1;
		while (i < name.size() && IsInlineStdNamespace(name[i]))
			i++;
		if (i >= name.size())
			return false;
		*templateIndex = i;
		return true;
	}

	bool IsStdScope(const DemangledTypeNode& type, size_t* templateIndex)
	{
		const DemangledQualifiedName& name = type.GetName();
		return IsStdScope(name, templateIndex);
	}

	bool IsAbslScope(const DemangledQualifiedName& name, size_t* templateIndex)
	{
		if (name.empty() || name[0].HasTemplateArguments() || name[0].GetBase() != "absl")
			return false;

		size_t i = 1;
		while (i < name.size() && IsAbslInlineNamespace(name[i]))
			i++;
		if (i >= name.size())
			return false;
		*templateIndex = i;
		return true;
	}

	bool IsAbslScope(const DemangledTypeNode& type, size_t* templateIndex)
	{
		const DemangledQualifiedName& name = type.GetName();
		return IsAbslScope(name, templateIndex);
	}

	bool IsStdTemplate(const DemangledTypeNode& type, std::string_view tmpl, const ParamList** args = nullptr)
	{
		size_t templateIndex = 0;
		if (!IsStdScope(type, &templateIndex))
			return false;

		const DemangledQualifiedName& name = type.GetName();
		if (name.empty() || templateIndex + 1 != name.size())
			return false;
		if (name[templateIndex].GetBase() != tmpl || !name[templateIndex].HasTemplateArguments())
			return false;
		if (args)
			*args = &name[templateIndex].GetTemplateArguments();
		return true;
	}

	bool IsAbslTemplate(const DemangledTypeNode& type, std::string_view tmpl, const ParamList** args = nullptr)
	{
		size_t templateIndex = 0;
		if (!IsAbslScope(type, &templateIndex))
			return false;

		const DemangledQualifiedName& name = type.GetName();
		if (name.empty() || templateIndex + 1 != name.size())
			return false;
		if (name[templateIndex].GetBase() != tmpl || !name[templateIndex].HasTemplateArguments())
			return false;
		if (args)
			*args = &name[templateIndex].GetTemplateArguments();
		return true;
	}

	bool IsAbslNestedTemplate(const DemangledTypeNode& type, std::string_view scope, std::string_view tmpl,
		const ParamList** args = nullptr)
	{
		size_t scopeIndex = 0;
		if (!IsAbslScope(type, &scopeIndex))
			return false;

		const DemangledQualifiedName& name = type.GetName();
		if (scopeIndex + 2 != name.size())
			return false;
		if (name[scopeIndex].HasTemplateArguments() || name[scopeIndex].GetBase() != scope)
			return false;
		if (name[scopeIndex + 1].GetBase() != tmpl || !name[scopeIndex + 1].HasTemplateArguments())
			return false;
		if (args)
			*args = &name[scopeIndex + 1].GetTemplateArguments();
		return true;
	}

	bool IsAbslNestedName(const DemangledTypeNode& type, std::string_view scope, std::string_view base)
	{
		size_t scopeIndex = 0;
		if (!IsAbslScope(type, &scopeIndex))
			return false;

		const DemangledQualifiedName& name = type.GetName();
		return scopeIndex + 2 == name.size() && !name[scopeIndex].HasTemplateArguments() &&
			name[scopeIndex].GetBase() == scope && !name[scopeIndex + 1].HasTemplateArguments() &&
			name[scopeIndex + 1].GetBase() == base;
	}

	bool IsStdPmrTemplate(const DemangledTypeNode& type, std::string_view tmpl, const ParamList** args = nullptr)
	{
		const DemangledQualifiedName& name = type.GetName();
		if (name.size() < 3 || name[0].HasTemplateArguments() || name[0].GetBase() != "std")
			return false;

		size_t i = 1;
		while (i < name.size() && IsInlineStdNamespace(name[i]))
			i++;
		if (i >= name.size() || name[i].HasTemplateArguments() || name[i].GetBase() != "pmr")
			return false;
		i++;
		if (i + 1 != name.size())
			return false;
		if (name[i].GetBase() != tmpl || !name[i].HasTemplateArguments())
			return false;
		if (args)
			*args = &name[i].GetTemplateArguments();
		return true;
	}

	bool IsStdOneArgTemplate(const DemangledTypeNode& type, std::string_view tmpl, const DemangledTypeNode& arg)
	{
		const ParamList* args = nullptr;
		if (!IsStdTemplate(type, tmpl, &args) || args->size() != 1 || !(*args)[0].type)
			return false;
		return SameType(*(*args)[0].type, arg);
	}

	bool IsStdOneArgTemplate(const DemangledTypeNode& type, std::string_view tmpl, std::string_view arg)
	{
		const ParamList* args = nullptr;
		if (!IsStdTemplate(type, tmpl, &args) || args->size() != 1 || !(*args)[0].type)
			return false;
		return SameType(*(*args)[0].type, arg);
	}

	bool IsStdPmrOneArgTemplate(const DemangledTypeNode& type, std::string_view tmpl, const DemangledTypeNode& arg)
	{
		const ParamList* args = nullptr;
		if (!IsStdPmrTemplate(type, tmpl, &args) || args->size() != 1 || !(*args)[0].type)
			return false;
		return SameType(*(*args)[0].type, arg);
	}

	bool IsPmrPolymorphicAllocator(const DemangledTypeNode& type, const DemangledTypeNode& valueType)
	{
		return IsStdPmrOneArgTemplate(type, "polymorphic_allocator", valueType);
	}

	bool IsConstTypeOf(const DemangledTypeNode& type, const DemangledTypeNode& base)
	{
		if (type.IsConst() && !type.IsVolatile())
		{
			DemangledTypeNode unqualified = type;
			unqualified.SetConst(false);
			if (SameType(unqualified, base))
				return true;
		}

		const string baseString = base.GetString();
		string suffixConst = baseString;
		suffixConst += " const";
		string prefixConst = "const ";
		prefixConst += baseString;
		const string actual = CanonicalTypeNoSpaces(type);
		return actual == CanonicalTypeNoSpaces(std::string_view(suffixConst.data(), suffixConst.size())) ||
			actual == CanonicalTypeNoSpaces(std::string_view(prefixConst.data(), prefixConst.size()));
	}

	bool IsStdPairOfConstKeyValue(const DemangledTypeNode& type, const DemangledTypeNode& key,
		const DemangledTypeNode& value)
	{
		const ParamList* pairArgs = nullptr;
		if (!IsStdTemplate(type, "pair", &pairArgs) || pairArgs->size() != 2 || !(*pairArgs)[0].type ||
			!(*pairArgs)[1].type)
			return false;
		return IsConstTypeOf(*(*pairArgs)[0].type, key) && SameType(*(*pairArgs)[1].type, value);
	}

	bool IsStdPairOfKeyValue(const DemangledTypeNode& type, const DemangledTypeNode& key,
		const DemangledTypeNode& value)
	{
		const ParamList* pairArgs = nullptr;
		if (!IsStdTemplate(type, "pair", &pairArgs) || pairArgs->size() != 2 || !(*pairArgs)[0].type ||
			!(*pairArgs)[1].type)
			return false;
		return SameType(*(*pairArgs)[0].type, key) && SameType(*(*pairArgs)[1].type, value);
	}

	bool IsDefaultPairAllocator(const DemangledTypeNode& type, const DemangledTypeNode& key,
		const DemangledTypeNode& value)
	{
		const ParamList* allocArgs = nullptr;
		if (!IsStdTemplate(type, "allocator", &allocArgs) || allocArgs->size() != 1 || !(*allocArgs)[0].type)
			return false;
		return IsStdPairOfConstKeyValue(*(*allocArgs)[0].type, key, value);
	}

	bool IsDefaultPairAllocatorWithMutableKey(const DemangledTypeNode& type, const DemangledTypeNode& key,
		const DemangledTypeNode& value)
	{
		const ParamList* allocArgs = nullptr;
		if (!IsStdTemplate(type, "allocator", &allocArgs) || allocArgs->size() != 1 || !(*allocArgs)[0].type)
			return false;
		return IsStdPairOfConstKeyValue(*(*allocArgs)[0].type, key, value) ||
			IsStdPairOfKeyValue(*(*allocArgs)[0].type, key, value);
	}

	bool IsPmrPairAllocator(const DemangledTypeNode& type, const DemangledTypeNode& key,
		const DemangledTypeNode& value)
	{
		const ParamList* allocArgs = nullptr;
		if (!IsStdPmrTemplate(type, "polymorphic_allocator", &allocArgs) || allocArgs->size() != 1 ||
			!(*allocArgs)[0].type)
			return false;
		return IsStdPairOfConstKeyValue(*(*allocArgs)[0].type, key, value);
	}

	bool IsAbslOneArgTemplate(const DemangledTypeNode& type, std::string_view tmpl, const DemangledTypeNode& arg)
	{
		const ParamList* args = nullptr;
		if (!IsAbslTemplate(type, tmpl, &args) || args->size() != 1 || !(*args)[0].type)
			return false;
		return SameType(*(*args)[0].type, arg);
	}

	std::string_view AbiBaseName(std::string_view name);

	bool IsStdStringLike(const DemangledTypeNode& type)
	{
		const DemangledQualifiedName& name = type.GetName();
		size_t templateIndex = 0;
		if (!IsStdScope(name, &templateIndex))
			return false;
		if (templateIndex + 1 != name.size())
			return false;

		const std::string_view base = AbiBaseName(name[templateIndex].GetBase());
		if (base == "basic_string" || base == "basic_string_view")
			return true;
		return !name[templateIndex].HasTemplateArguments() &&
			(base == "string" || base == "wstring" || base == "u8string" || base == "u16string" ||
				base == "u32string" || base == "string_view" || base == "wstring_view" || base == "u8string_view" ||
				base == "u16string_view" || base == "u32string_view");
	}

	bool IsAbslStringViewLike(const DemangledTypeNode& type)
	{
		size_t templateIndex = 0;
		if (!IsAbslScope(type, &templateIndex))
			return false;
		const DemangledQualifiedName& name = type.GetName();
		return templateIndex + 1 == name.size() && !name[templateIndex].HasTemplateArguments() &&
			name[templateIndex].GetBase() == "string_view";
	}

	bool IsAbslDefaultStringLikeKey(const DemangledTypeNode& key)
	{
		return IsStdStringLike(key) || IsAbslStringViewLike(key);
	}

	bool IsAbslNestedOneArgTemplate(const DemangledTypeNode& type, std::string_view scope, std::string_view tmpl,
		const DemangledTypeNode& arg)
	{
		const ParamList* args = nullptr;
		if (!IsAbslNestedTemplate(type, scope, tmpl, &args) || args->size() != 1 || !(*args)[0].type)
			return false;
		return SameType(*(*args)[0].type, arg);
	}

	bool IsAbslHashDefault(const DemangledTypeNode& type, const DemangledTypeNode& key)
	{
		if (IsAbslNestedOneArgTemplate(type, "container_internal", "hash_default_hash", key) ||
			IsAbslNestedOneArgTemplate(type, "hash_internal", "Hash", key) || IsAbslOneArgTemplate(type, "Hash", key))
			return true;

		if (IsAbslNestedName(type, "container_internal", "StringHash"))
			return IsAbslDefaultStringLikeKey(key);

		const ParamList* args = nullptr;
		if (IsAbslNestedTemplate(type, "container_internal", "BasicStringHash", &args) && args->size() == 1 &&
			(*args)[0].type)
		{
			const DemangledTypeNode& charType = *(*args)[0].type;
			return CharFamilyAliasName(charType, "", "", nullptr, "", "") || IsAbslDefaultStringLikeKey(key);
		}
		return false;
	}

	bool IsAbslEqDefault(const DemangledTypeNode& type, const DemangledTypeNode& key)
	{
		if (IsAbslNestedOneArgTemplate(type, "container_internal", "hash_default_eq", key) ||
			IsStdOneArgTemplate(type, "equal_to", key))
			return true;

		const ParamList* args = nullptr;
		if (IsStdTemplate(type, "equal_to", &args) && args->size() == 1 && (*args)[0].type &&
			SameType(*(*args)[0].type, "void"))
			return true;

		if (IsAbslNestedName(type, "container_internal", "StringEq"))
			return IsAbslDefaultStringLikeKey(key);

		if (IsAbslNestedTemplate(type, "container_internal", "BasicStringEq", &args) && args->size() == 1 &&
			(*args)[0].type)
		{
			const DemangledTypeNode& charType = *(*args)[0].type;
			return CharFamilyAliasName(charType, "", "", nullptr, "", "") || IsAbslDefaultStringLikeKey(key);
		}
		return false;
	}

	bool IsBoostScope(const DemangledQualifiedName& name, size_t* templateIndex)
	{
		if (name.empty() || name[0].HasTemplateArguments() || name[0].GetBase() != "boost")
			return false;
		if (name.size() < 2)
			return false;
		*templateIndex = 1;
		return true;
	}

	bool IsBoostScope(const DemangledTypeNode& type, size_t* templateIndex)
	{
		const DemangledQualifiedName& name = type.GetName();
		return IsBoostScope(name, templateIndex);
	}

	bool IsBoostTemplate(const DemangledTypeNode& type, std::string_view tmpl, const ParamList** args = nullptr)
	{
		size_t templateIndex = 0;
		if (!IsBoostScope(type, &templateIndex))
			return false;

		const DemangledQualifiedName& name = type.GetName();
		if (templateIndex + 1 != name.size())
			return false;
		if (name[templateIndex].GetBase() != tmpl || !name[templateIndex].HasTemplateArguments())
			return false;
		if (args)
			*args = &name[templateIndex].GetTemplateArguments();
		return true;
	}

	bool IsBoostOneArgTemplate(const DemangledTypeNode& type, std::string_view tmpl, const DemangledTypeNode& arg)
	{
		const ParamList* args = nullptr;
		if (!IsBoostTemplate(type, tmpl, &args) || args->size() != 1 || !(*args)[0].type)
			return false;
		return SameType(*(*args)[0].type, arg);
	}

	bool GetSimpleLiteralName(const DemangledTypeNode& arg, std::string_view& literal)
	{
		if (arg.IsConst() || arg.IsVolatile() || arg.GetPointerSuffixBits() != 0 ||
			arg.GetClass() != NamedTypeReferenceClass)
			return false;

		const DemangledQualifiedName& name = arg.GetName();
		if (name.size() != 1 || name[0].HasTemplateArguments())
			return false;
		literal = name[0].GetBase();
		return true;
	}

	bool IsIntegerSuffix(char c)
	{
		return c == 'u' || c == 'U' || c == 'l' || c == 'L';
	}

	bool MatchesNonTypeValue(std::string_view raw, std::string_view value)
	{
		raw = TrimSpaces(raw);
		size_t castClose = raw.rfind(')');
		if (!raw.empty() && raw[0] == '(' && castClose != std::string_view::npos && castClose + 1 < raw.size())
			raw = TrimSpaces(raw.substr(castClose + 1));

		size_t rawIndex = 0;
		for (char expected: value)
		{
			while (rawIndex < raw.size() && raw[rawIndex] == ' ')
				rawIndex++;
			if (rawIndex >= raw.size() || raw[rawIndex] != expected)
				return false;
			rawIndex++;
		}

		while (rawIndex < raw.size() && raw[rawIndex] == ' ')
			rawIndex++;
		while (rawIndex < raw.size() && IsIntegerSuffix(raw[rawIndex]))
			rawIndex++;
		while (rawIndex < raw.size() && raw[rawIndex] == ' ')
			rawIndex++;
		return rawIndex == raw.size();
	}

	bool IsNonTypeValue(const DemangledTypeNode& arg, std::string_view value)
	{
		std::string_view literal;
		return GetSimpleLiteralName(arg, literal) && MatchesNonTypeValue(literal, value);
	}

	bool CanonicalIntegerLiteral(std::string_view raw, string& out)
	{
		raw = TrimSpaces(raw);
		bool hadCast = false;
		size_t castClose = raw.rfind(')');
		if (!raw.empty() && raw[0] == '(' && castClose != std::string_view::npos && castClose + 1 < raw.size())
		{
			raw = TrimSpaces(raw.substr(castClose + 1));
			hadCast = true;
		}

		string s = RemoveSpaces(raw);
		size_t i = 0;
		if (i < s.size() && (s[i] == '-' || s[i] == '+'))
			i++;
		const size_t digitsStart = i;
		while (i < s.size() && isdigit(static_cast<unsigned char>(s[i])))
			i++;
		if (i == digitsStart)
			return false;

		const size_t suffixStart = i;
		while (i < s.size())
		{
			char c = s[i];
			if (c != 'u' && c != 'U' && c != 'l' && c != 'L')
				return false;
			i++;
		}
		if (suffixStart == s.size() && !hadCast)
			return false;

		out = s.substr(0, suffixStart);
		return !out.empty() && out != s;
	}

	bool CanonicalizeNonTypeIntegerLiteral(DemangledTypeNode& type)
	{
		std::string_view literal;
		if (!GetSimpleLiteralName(type, literal))
			return false;

		string canonical;
		if (!CanonicalIntegerLiteral(literal, canonical))
			return false;
		type = DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{canonical});
		return true;
	}

	bool IsVoidType(const DemangledTypeNode& arg)
	{
		return SameType(arg, "void");
	}

	bool IsPtrdiffType(const DemangledTypeNode& arg)
	{
		if (IsSimpleNamedType(arg, "long") || IsSimpleNamedType(arg, "long int") ||
			IsSimpleNamedType(arg, "long long") || IsSimpleNamedType(arg, "long long int") ||
			IsSimpleNamedType(arg, "__int64") || IsSimpleNamedType(arg, "int64_t") ||
			IsQualifiedName(arg, {"std", "ptrdiff_t"}))
			return true;

		size_t width = 0;
		DemangledTypeNode::WidthKind widthKind = DemangledTypeNode::FixedWidth;
		bool isSigned = false;
		std::string_view altName;
		if (GetUnqualifiedIntegerTypeInfo(arg, width, widthKind, isSigned, altName))
		{
			if (altName == "long" || altName == "long int" || altName == "long long" ||
				altName == "long long int" || altName == "__int64" || altName == "int64_t")
				return true;
			return isSigned && altName.empty() && ResolvedIntegerWidth(width, widthKind) == 8;
		}

		string t = CanonicalTypeNoSpaces(arg);
		return t == "long" || t == "longint" || t == "longlong" || t == "longlongint" ||
			t == "__int64" || t == "int64_t" || t == "std::ptrdiff_t";
	}

	bool IsPointerTo(const DemangledTypeNode& type, const DemangledTypeNode& pointee)
	{
		const DemangledTypeNode* child = nullptr;
		BNReferenceType referenceType = PointerReferenceType;
		return !type.IsConst() && !type.IsVolatile() && HasOnlyOmittedPointerSuffixes(type) &&
			type.GetPointerChildType(child, referenceType) && referenceType == PointerReferenceType && child &&
			SameType(*child, pointee);
	}

	bool IsReferenceTo(const DemangledTypeNode& type, const DemangledTypeNode& referenced)
	{
		const DemangledTypeNode* child = nullptr;
		BNReferenceType referenceType = PointerReferenceType;
		return !type.IsConst() && !type.IsVolatile() && HasOnlyOmittedPointerSuffixes(type) &&
			type.GetPointerChildType(child, referenceType) && referenceType == ReferenceReferenceType && child &&
			SameType(*child, referenced);
	}

	bool IsConstPointerTo(const DemangledTypeNode& type, std::string_view pointee)
	{
		const DemangledTypeNode* child = nullptr;
		BNReferenceType referenceType = PointerReferenceType;
		return !type.IsConst() && !type.IsVolatile() && HasOnlyOmittedPointerSuffixes(type) &&
			type.GetPointerChildType(child, referenceType) && referenceType == PointerReferenceType && child &&
			IsConstTypeNamed(*child, pointee);
	}

	bool IsStringConstIterator(const DemangledTypeNode& type, bool wide, bool pmr)
	{
		const ParamList* wrapIterArgs = nullptr;
		if (IsStdTemplate(type, "__wrap_iter", &wrapIterArgs) && wrapIterArgs->size() == 1 &&
			(*wrapIterArgs)[0].type)
		{
			return IsConstPointerTo(*(*wrapIterArgs)[0].type, wide ? "wchar_t" : "char");
		}

		const char* stringName = wide ? "wstring" : "string";
		if (pmr)
		{
			if (IsQualifiedName(type, {"std", "pmr", stringName, "const_iterator"}))
				return true;
		}
		return IsQualifiedName(type, {"std", stringName, "const_iterator"});
	}

	const char* RegexIteratorAliasName(const DemangledTypeNode& iterator, const char* charPointerAlias,
		const char* wcharPointerAlias, const char* stringAlias, const char* wstringAlias, bool pmr = false)
	{
		if (IsConstPointerTo(iterator, "char"))
			return charPointerAlias;
		if (IsConstPointerTo(iterator, "wchar_t"))
			return wcharPointerAlias;
		if (IsStringConstIterator(iterator, false, pmr))
			return stringAlias;
		if (IsStringConstIterator(iterator, true, pmr))
			return wstringAlias;
		return nullptr;
	}

	bool IsSubMatchOfIterator(const DemangledTypeNode& type, const DemangledTypeNode& iterator, bool pmr = false)
	{
		const ParamList* subMatchArgs = nullptr;
		if (IsStdTemplate(type, "sub_match", &subMatchArgs) && subMatchArgs->size() == 1 && (*subMatchArgs)[0].type)
			return SameType(*(*subMatchArgs)[0].type, iterator);

		size_t templateIndex = 0;
		if (!IsStdScope(type, &templateIndex))
			return false;
		const DemangledQualifiedName& name = type.GetName();
		if (name.empty() || templateIndex + 1 != name.size() || name[templateIndex].HasTemplateArguments())
			return false;

		const char* expected = RegexIteratorAliasName(iterator, "csub_match", "wcsub_match", "ssub_match",
			"wssub_match", pmr);
		return expected && name[templateIndex].GetBase() == expected;
	}

	bool IsDefaultSubMatchAllocator(const DemangledTypeNode& type, const DemangledTypeNode& iterator)
	{
		const ParamList* allocArgs = nullptr;
		if (!IsStdTemplate(type, "allocator", &allocArgs) || allocArgs->size() != 1 || !(*allocArgs)[0].type)
			return false;
		return IsSubMatchOfIterator(*(*allocArgs)[0].type, iterator);
	}

	bool IsPmrSubMatchAllocator(const DemangledTypeNode& type, const DemangledTypeNode& iterator)
	{
		const ParamList* allocArgs = nullptr;
		if (!IsStdPmrTemplate(type, "polymorphic_allocator", &allocArgs) || allocArgs->size() != 1 ||
			!(*allocArgs)[0].type)
			return false;
		return IsSubMatchOfIterator(*(*allocArgs)[0].type, iterator, true);
	}

	const char* WideStringName(std::string_view name)
	{
		if (name == "basic_string") return "wstring";
		if (name == "basic_stringbuf") return "wstringbuf";
		if (name == "basic_istringstream") return "wistringstream";
		if (name == "basic_ostringstream") return "wostringstream";
		if (name == "basic_stringstream") return "wstringstream";
		if (name == "basic_ios") return "wios";
		if (name == "basic_streambuf") return "wstreambuf";
		if (name == "basic_istream") return "wistream";
		if (name == "basic_ostream") return "wostream";
		if (name == "basic_iostream") return "wiostream";
		if (name == "basic_filebuf") return "wfilebuf";
		if (name == "basic_ifstream") return "wifstream";
		if (name == "basic_ofstream") return "wofstream";
		if (name == "basic_fstream") return "wfstream";
		return nullptr;
	}

	const char* AtomicAliasForName(std::string_view t)
	{
		if (t == "bool") return "atomic_bool";
		if (t == "char") return "atomic_char";
		if (t == "signed char") return "atomic_schar";
		if (t == "unsigned char") return "atomic_uchar";
		if (t == "short" || t == "short int") return "atomic_short";
		if (t == "unsigned short" || t == "unsigned short int") return "atomic_ushort";
		if (t == "int") return "atomic_int";
		if (t == "unsigned" || t == "unsigned int") return "atomic_uint";
		if (t == "long" || t == "long int") return "atomic_long";
		if (t == "unsigned long" || t == "unsigned long int") return "atomic_ulong";
		if (t == "long long" || t == "long long int") return "atomic_llong";
		if (t == "unsigned long long" || t == "unsigned long long int") return "atomic_ullong";
		if (t == "char8_t") return "atomic_char8_t";
		if (t == "char16_t") return "atomic_char16_t";
		if (t == "char32_t") return "atomic_char32_t";
		if (t == "wchar_t") return "atomic_wchar_t";
		if (t == "int8_t" || t == "__int8") return "atomic_int8_t";
		if (t == "uint8_t" || t == "unsigned __int8") return "atomic_uint8_t";
		if (t == "int16_t" || t == "__int16") return "atomic_int16_t";
		if (t == "uint16_t" || t == "unsigned __int16") return "atomic_uint16_t";
		if (t == "int32_t" || t == "__int32") return "atomic_int32_t";
		if (t == "uint32_t" || t == "unsigned __int32") return "atomic_uint32_t";
		if (t == "int64_t" || t == "__int64") return "atomic_int64_t";
		if (t == "uint64_t" || t == "unsigned __int64") return "atomic_uint64_t";
		if (t == "int_least8_t") return "atomic_int_least8_t";
		if (t == "uint_least8_t") return "atomic_uint_least8_t";
		if (t == "int_least16_t") return "atomic_int_least16_t";
		if (t == "uint_least16_t") return "atomic_uint_least16_t";
		if (t == "int_least32_t") return "atomic_int_least32_t";
		if (t == "uint_least32_t") return "atomic_uint_least32_t";
		if (t == "int_least64_t") return "atomic_int_least64_t";
		if (t == "uint_least64_t") return "atomic_uint_least64_t";
		if (t == "int_fast8_t") return "atomic_int_fast8_t";
		if (t == "uint_fast8_t") return "atomic_uint_fast8_t";
		if (t == "int_fast16_t") return "atomic_int_fast16_t";
		if (t == "uint_fast16_t") return "atomic_uint_fast16_t";
		if (t == "int_fast32_t") return "atomic_int_fast32_t";
		if (t == "uint_fast32_t") return "atomic_uint_fast32_t";
		if (t == "int_fast64_t") return "atomic_int_fast64_t";
		if (t == "uint_fast64_t") return "atomic_uint_fast64_t";
		if (t == "intptr_t") return "atomic_intptr_t";
		if (t == "uintptr_t") return "atomic_uintptr_t";
		if (t == "size_t") return "atomic_size_t";
		if (t == "ptrdiff_t") return "atomic_ptrdiff_t";
		if (t == "intmax_t") return "atomic_intmax_t";
		if (t == "uintmax_t") return "atomic_uintmax_t";
		return nullptr;
	}

	const char* AtomicAliasForPrimitive(const DemangledTypeNode& type)
	{
		if (!IsUnqualifiedNonPointerType(type))
			return nullptr;

		if (type.GetClass() == BoolTypeClass)
			return "atomic_bool";

		size_t width = 0;
		DemangledTypeNode::WidthKind widthKind = DemangledTypeNode::FixedWidth;
		bool isSigned = false;
		std::string_view altName;
		if (GetUnqualifiedIntegerTypeInfo(type, width, widthKind, isSigned, altName))
		{
			if (!altName.empty())
			{
				if (const char* alias = AtomicAliasForName(altName))
					return alias;
			}

			switch (ResolvedIntegerWidth(width, widthKind))
			{
			case 1:
				return isSigned ? "atomic_char" : "atomic_uint8_t";
			case 2:
				return isSigned ? "atomic_int16_t" : "atomic_uint16_t";
			case 4:
				return isSigned ? "atomic_int32_t" : "atomic_uint32_t";
			case 8:
				return isSigned ? "atomic_int64_t" : "atomic_uint64_t";
			default:
				return nullptr;
			}
		}

		size_t wideWidth = 0;
		std::string_view wideAltName;
		if (GetUnqualifiedWideCharTypeInfo(type, wideWidth, wideAltName))
		{
			if (!wideAltName.empty())
			{
				if (const char* alias = AtomicAliasForName(wideAltName))
					return alias;
			}
			return "atomic_wchar_t";
		}

		return nullptr;
	}

	const char* AtomicAliasForNamedType(const DemangledTypeNode& type)
	{
		if (!IsUnqualifiedNonPointerType(type) || type.GetClass() != NamedTypeReferenceClass)
			return nullptr;

		const DemangledQualifiedName& name = type.GetName();
		if (name.size() == 1 && !name[0].HasTemplateArguments())
			return AtomicAliasForName(name[0].GetBase());

		if (name.size() == 2 && !name[0].HasTemplateArguments() && !name[1].HasTemplateArguments() &&
			StringEquals(name[0].GetBase(), "std"))
			return AtomicAliasForName(name[1].GetBase());

		return nullptr;
	}

	const char* AtomicAliasName(const DemangledTypeNode& type)
	{
		if (const char* alias = AtomicAliasForPrimitive(type))
			return alias;
		if (const char* alias = AtomicAliasForNamedType(type))
			return alias;

		const string t = CanonicalTypeNoSpaces(type);
		if (t == "bool") return "atomic_bool";
		if (t == "char") return "atomic_char";
		if (t == "signedchar") return "atomic_schar";
		if (t == "unsignedchar") return "atomic_uchar";
		if (t == "short" || t == "shortint") return "atomic_short";
		if (t == "unsignedshort" || t == "unsignedshortint") return "atomic_ushort";
		if (t == "int") return "atomic_int";
		if (t == "unsigned" || t == "unsignedint") return "atomic_uint";
		if (t == "long" || t == "longint") return "atomic_long";
		if (t == "unsignedlong" || t == "unsignedlongint") return "atomic_ulong";
		if (t == "longlong" || t == "longlongint") return "atomic_llong";
		if (t == "unsignedlonglong" || t == "unsignedlonglongint") return "atomic_ullong";
		if (t == "char8_t") return "atomic_char8_t";
		if (t == "char16_t") return "atomic_char16_t";
		if (t == "char32_t") return "atomic_char32_t";
		if (t == "wchar_t") return "atomic_wchar_t";
		if (t == "int8_t" || t == "std::int8_t" || t == "__int8") return "atomic_int8_t";
		if (t == "uint8_t" || t == "std::uint8_t" || t == "unsigned__int8") return "atomic_uint8_t";
		if (t == "int16_t" || t == "std::int16_t" || t == "__int16") return "atomic_int16_t";
		if (t == "uint16_t" || t == "std::uint16_t" || t == "unsigned__int16") return "atomic_uint16_t";
		if (t == "int32_t" || t == "std::int32_t" || t == "__int32") return "atomic_int32_t";
		if (t == "uint32_t" || t == "std::uint32_t" || t == "unsigned__int32") return "atomic_uint32_t";
		if (t == "int64_t" || t == "std::int64_t" || t == "__int64") return "atomic_int64_t";
		if (t == "uint64_t" || t == "std::uint64_t" || t == "unsigned__int64") return "atomic_uint64_t";
		if (t == "int_least8_t" || t == "std::int_least8_t") return "atomic_int_least8_t";
		if (t == "uint_least8_t" || t == "std::uint_least8_t") return "atomic_uint_least8_t";
		if (t == "int_least16_t" || t == "std::int_least16_t") return "atomic_int_least16_t";
		if (t == "uint_least16_t" || t == "std::uint_least16_t") return "atomic_uint_least16_t";
		if (t == "int_least32_t" || t == "std::int_least32_t") return "atomic_int_least32_t";
		if (t == "uint_least32_t" || t == "std::uint_least32_t") return "atomic_uint_least32_t";
		if (t == "int_least64_t" || t == "std::int_least64_t") return "atomic_int_least64_t";
		if (t == "uint_least64_t" || t == "std::uint_least64_t") return "atomic_uint_least64_t";
		if (t == "int_fast8_t" || t == "std::int_fast8_t") return "atomic_int_fast8_t";
		if (t == "uint_fast8_t" || t == "std::uint_fast8_t") return "atomic_uint_fast8_t";
		if (t == "int_fast16_t" || t == "std::int_fast16_t") return "atomic_int_fast16_t";
		if (t == "uint_fast16_t" || t == "std::uint_fast16_t") return "atomic_uint_fast16_t";
		if (t == "int_fast32_t" || t == "std::int_fast32_t") return "atomic_int_fast32_t";
		if (t == "uint_fast32_t" || t == "std::uint_fast32_t") return "atomic_uint_fast32_t";
		if (t == "int_fast64_t" || t == "std::int_fast64_t") return "atomic_int_fast64_t";
		if (t == "uint_fast64_t" || t == "std::uint_fast64_t") return "atomic_uint_fast64_t";
		if (t == "intptr_t" || t == "std::intptr_t") return "atomic_intptr_t";
		if (t == "uintptr_t" || t == "std::uintptr_t") return "atomic_uintptr_t";
		if (t == "size_t" || t == "std::size_t") return "atomic_size_t";
		if (t == "ptrdiff_t" || t == "std::ptrdiff_t") return "atomic_ptrdiff_t";
		if (t == "intmax_t" || t == "std::intmax_t") return "atomic_intmax_t";
		if (t == "uintmax_t" || t == "std::uintmax_t") return "atomic_uintmax_t";
		return nullptr;
	}

	void ResizeTemplateArgs(DemangledNamePart& c, size_t n)
	{
		c.GetMutableTemplateArguments().resize(n);
	}

	std::string_view AbiBaseName(std::string_view name)
	{
		size_t suffixStart = name.size();
		while (suffixStart > 0 && name[suffixStart - 1] == ']')
		{
			std::string_view prefix = name.substr(0, suffixStart);
			size_t tagStart = prefix.rfind("[abi:");
			if (tagStart == std::string_view::npos)
				break;
			suffixStart = tagStart;
		}
		return name.substr(0, suffixStart);
	}

	std::string_view AbiTagSuffix(std::string_view name)
	{
		size_t suffixStart = name.size();
		while (suffixStart > 0 && name[suffixStart - 1] == ']')
		{
			std::string_view prefix = name.substr(0, suffixStart);
			size_t tagStart = prefix.rfind("[abi:");
			if (tagStart == std::string_view::npos)
				break;
			suffixStart = tagStart;
		}
		return name.substr(suffixStart);
	}

	void ReplaceWithAlias(DemangledNamePart& c, std::string_view alias)
	{
		string replacement(alias.data(), alias.size());
		const std::string_view abiSuffix = AbiTagSuffix(c.GetBase());
		replacement.append(abiSuffix.data(), abiSuffix.size());
		c.SetBase(std::move(replacement));
		c.ClearTemplateArguments();
	}

	bool ApplyStringRule(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.size() != 3 || (name != "basic_string" && name != "basic_stringbuf" &&
				name != "basic_istringstream" && name != "basic_ostringstream" && name != "basic_stringstream"))
			return false;
		if (!args[0].type || !args[1].type || !args[2].type)
			return false;

		const DemangledTypeNode& element = *args[0].type;
		if (!IsStdOneArgTemplate(*args[1].type, "char_traits", element) ||
			!IsStdOneArgTemplate(*args[2].type, "allocator", element))
			return false;

		if (SameType(element, "char"))
		{
			if (name == "basic_string")
				ReplaceWithAlias(c, "string");
			else
				ReplaceWithAlias(c, name.substr(6));
			return true;
		}
		if (SameType(element, "wchar_t"))
		{
			if (const char* wide = WideStringName(name))
				ReplaceWithAlias(c, wide);
			else
				return false;
			return true;
		}
		if (name == "basic_string")
		{
			if (const char* alias = CharFamilyAliasName(element, "string", "wstring", "u8string", "u16string",
					"u32string"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}

		if (const char* alias = CharFamilyAliasName(element, nullptr, nullptr, name == "basic_string" ? "u8string" : nullptr,
				name == "basic_string" ? "u16string" : nullptr, name == "basic_string" ? "u32string" : nullptr))
		{
			ReplaceWithAlias(c, alias);
			return true;
		}

		ResizeTemplateArgs(c, 1);
		return true;
	}

	bool ApplyIostreamRule(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.size() != 2 || !StartsWith(name, "basic_"))
			return false;
		if (name != "basic_ios" && name != "basic_streambuf" && name != "basic_istream" &&
			name != "basic_ostream" && name != "basic_iostream" && name != "basic_filebuf" &&
			name != "basic_ifstream" && name != "basic_ofstream" && name != "basic_fstream")
			return false;
		if (!args[0].type || !args[1].type)
			return false;

		const DemangledTypeNode& element = *args[0].type;
		if (!IsStdOneArgTemplate(*args[1].type, "char_traits", element))
			return false;

		if (SameType(element, "char"))
		{
			ReplaceWithAlias(c, name.substr(6));
			return true;
		}
		if (SameType(element, "wchar_t"))
		{
			if (const char* wide = WideStringName(name))
			{
				ReplaceWithAlias(c, wide);
				return true;
			}
		}

		ResizeTemplateArgs(c, 1);
		return true;
	}

	bool ApplyContainerRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if (name == "vector" && args.size() == 2 && args[0].type && args[1].type &&
			IsStdOneArgTemplate(*args[1].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if (name == "vector" && args.size() == 3 && args[0].type && args[1].type && args[2].type &&
			IsStdOneArgTemplate(*args[1].type, "allocator", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "lessthan", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if ((name == "deque" || name == "forward_list" || name == "list") && args.size() == 2 &&
			args[0].type && args[1].type && IsStdOneArgTemplate(*args[1].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if ((name == "stack" || name == "queue") && args.size() == 2 && args[0].type && args[1].type)
		{
			const ParamList* dequeArgs = nullptr;
			if (IsStdTemplate(*args[1].type, "deque", &dequeArgs) && dequeArgs->size() == 1 &&
				(*dequeArgs)[0].type && SameType(*(*dequeArgs)[0].type, *args[0].type))
			{
				ResizeTemplateArgs(c, 1);
				return true;
			}
		}

		if (name == "priority_queue" && args.size() == 3 && args[0].type && args[1].type && args[2].type)
		{
			const ParamList* vectorArgs = nullptr;
			if (IsStdTemplate(*args[1].type, "vector", &vectorArgs) && vectorArgs->size() == 1 &&
				(*vectorArgs)[0].type && SameType(*(*vectorArgs)[0].type, *args[0].type) &&
				IsStdOneArgTemplate(*args[2].type, "less", *args[0].type))
			{
				ResizeTemplateArgs(c, 1);
				return true;
			}
		}

		if ((name == "set" || name == "multiset") && args.size() == 3 && args[0].type && args[1].type &&
			args[2].type && IsStdOneArgTemplate(*args[1].type, "less", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if ((name == "map" || name == "multimap") && args.size() == 4 && args[0].type && args[1].type &&
			args[2].type && args[3].type && IsStdOneArgTemplate(*args[2].type, "less", *args[0].type) &&
			IsDefaultPairAllocator(*args[3].type, *args[0].type, *args[1].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}

		if ((name == "unordered_set" || name == "unordered_multiset") && args.size() == 4 && args[0].type &&
			args[1].type && args[2].type && args[3].type &&
			IsStdOneArgTemplate(*args[1].type, "hash", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "equal_to", *args[0].type) &&
			IsStdOneArgTemplate(*args[3].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if ((name == "unordered_map" || name == "unordered_multimap") && args.size() == 5 && args[0].type &&
			args[1].type && args[2].type && args[3].type && args[4].type &&
			IsStdOneArgTemplate(*args[2].type, "hash", *args[0].type) &&
			IsStdOneArgTemplate(*args[3].type, "equal_to", *args[0].type) &&
			IsDefaultPairAllocator(*args[4].type, *args[0].type, *args[1].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}

		return false;
	}

	bool ApplyDiscoveredStdRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if (name == "basic_regex" && args.size() == 2 && args[0].type && args[1].type &&
			IsStdOneArgTemplate(*args[1].type, "regex_traits", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "unique_ptr" && args.size() == 2 && args[0].type && args[1].type &&
			IsStdOneArgTemplate(*args[1].type, "default_delete", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "match_results" && args.size() == 2 && args[0].type && args[1].type &&
			IsDefaultSubMatchAllocator(*args[1].type, *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "ratio" && args.size() == 2 && args[1].type && IsNonTypeValue(*args[1].type, "1"))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "extent" && args.size() == 2 && args[1].type && IsNonTypeValue(*args[1].type, "0"))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "enable_if" && args.size() == 2 && args[1].type && IsVoidType(*args[1].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "compare_three_way_result" && args.size() == 2 && args[0].type && args[1].type &&
			SameType(*args[0].type, *args[1].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "formatter" && args.size() == 2 && args[1].type && SameType(*args[1].type, "char"))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if ((name == "moneypunct" || name == "moneypunct_byname") && args.size() == 2 && args[1].type &&
			(IsNonTypeValue(*args[1].type, "false") || IsNonTypeValue(*args[1].type, "0")))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if ((name == "codecvt_utf8" || name == "codecvt_utf16" || name == "codecvt_utf8_utf16") &&
			args.size() == 3 && args[1].type && args[2].type && IsNonTypeValue(*args[1].type, "1114111") &&
			IsNonTypeValue(*args[2].type, "0"))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "istream_iterator" && args.size() == 4 && args[1].type && args[2].type && args[3].type &&
			SameType(*args[1].type, "char") && IsStdOneArgTemplate(*args[2].type, "char_traits", "char") &&
			IsPtrdiffType(*args[3].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "ostream_iterator" && args.size() == 3 && args[1].type && args[2].type &&
			SameType(*args[1].type, "char") && IsStdOneArgTemplate(*args[2].type, "char_traits", "char"))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (name == "iterator" && args.size() == 5 && args[1].type && args[2].type && args[3].type &&
			args[4].type && IsPtrdiffType(*args[2].type) && IsPointerTo(*args[3].type, *args[1].type) &&
			IsReferenceTo(*args[4].type, *args[1].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}
		if ((name == "default_searcher" || name == "boyer_moore_searcher" ||
				name == "boyer_moore_horspool_searcher") && args.size() == 2 && args[1].type)
		{
			const ParamList* equalArgs = nullptr;
			if (IsStdTemplate(*args[1].type, "equal_to", &equalArgs) && equalArgs->size() == 1 &&
				(*equalArgs)[0].type && IsVoidType(*(*equalArgs)[0].type))
			{
				ResizeTemplateArgs(c, 1);
				return true;
			}
		}
		if ((name == "boyer_moore_searcher" || name == "boyer_moore_horspool_searcher") && args.size() == 3 &&
			args[2].type && IsStdOneArgTemplate(*args[2].type, "equal_to", "void"))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}
		return false;
	}

	bool ApplyChronoRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		if (c.GetBase() != "duration" || args.size() != 2 || !args[1].type)
			return false;

		const ParamList* ratioArgs = nullptr;
		if (IsStdTemplate(*args[1].type, "ratio", &ratioArgs) && ratioArgs->size() == 1 &&
			(*ratioArgs)[0].type && IsNonTypeValue(*(*ratioArgs)[0].type, "1"))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		return false;
	}

	bool ApplyGenericStdDefaultRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		if (args.size() == 2 && args[0].type && args[1].type &&
			(IsStdOneArgTemplate(*args[1].type, "char_traits", *args[0].type) ||
				IsStdOneArgTemplate(*args[1].type, "istreambuf_iterator", *args[0].type) ||
				IsStdOneArgTemplate(*args[1].type, "ostreambuf_iterator", *args[0].type)))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if (args.size() == 3 && args[0].type && args[1].type && args[2].type &&
			IsStdOneArgTemplate(*args[1].type, "char_traits", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		return false;
	}

	bool ApplyStdFunctionTemplateRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if ((name == "operator<<" || name == "operator+") && args.size() == 3 && args[0].type && args[1].type && args[2].type &&
			IsStdOneArgTemplate(*args[1].type, "char_traits", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			if (name == "operator<<")
				c.ClearTemplateArguments();
			else
				ResizeTemplateArgs(c, 1);
			return true;
		}

		if (name != "operator==" && name != "operator!=" && name != "operator<" && name != "operator<=" &&
			name != "operator>" && name != "operator>=" && name != "operator<=>")
			return false;

		if (args.size() == 5 && args[0].type && args[1].type && args[2].type && args[3].type && args[4].type &&
			IsStdOneArgTemplate(*args[2].type, "hash", *args[0].type) &&
			IsStdOneArgTemplate(*args[3].type, "equal_to", *args[0].type) &&
			IsDefaultPairAllocator(*args[4].type, *args[0].type, *args[1].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}
		if (args.size() == 4 && args[0].type && args[1].type && args[2].type && args[3].type &&
			IsStdOneArgTemplate(*args[1].type, "hash", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "equal_to", *args[0].type) &&
			IsStdOneArgTemplate(*args[3].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (args.size() == 4 && args[0].type && args[1].type && args[2].type && args[3].type &&
			IsStdOneArgTemplate(*args[2].type, "less", *args[0].type) &&
			IsDefaultPairAllocator(*args[3].type, *args[0].type, *args[1].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}
		if (args.size() == 3 && args[0].type && args[1].type && args[2].type &&
			IsStdOneArgTemplate(*args[1].type, "less", *args[0].type) &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		if (args.size() == 2 && args[0].type && args[1].type &&
			IsStdOneArgTemplate(*args[1].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}
		return false;
	}

	bool ApplyStdTemplateRules(DemangledNamePart& c)
	{
		if (ApplyStringRule(c))
			return true;
		if (ApplyIostreamRule(c))
			return true;
		if (ApplyContainerRules(c))
			return true;
		if (ApplyDiscoveredStdRules(c))
			return true;
		if (ApplyStdFunctionTemplateRules(c))
			return true;
		return ApplyGenericStdDefaultRules(c);
	}

	bool ApplyAbslTemplateRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if ((name == "flat_hash_set" || name == "node_hash_set") && args.size() == 4 && args[0].type &&
			args[1].type && args[2].type && args[3].type &&
			IsStdOneArgTemplate(*args[3].type, "allocator", *args[0].type))
		{
			const bool defaultHash = IsAbslHashDefault(*args[1].type, *args[0].type);
			const bool defaultEq = IsAbslEqDefault(*args[2].type, *args[0].type);
			if (defaultHash && defaultEq)
				ResizeTemplateArgs(c, 1);
			else if (defaultEq)
				ResizeTemplateArgs(c, 2);
			else
				ResizeTemplateArgs(c, 3);
			return true;
		}

		if ((name == "flat_hash_map" || name == "node_hash_map") && args.size() == 5 && args[0].type &&
			args[1].type && args[2].type && args[3].type && args[4].type &&
			IsDefaultPairAllocator(*args[4].type, *args[0].type, *args[1].type))
		{
			const bool defaultHash = IsAbslHashDefault(*args[2].type, *args[0].type);
			const bool defaultEq = IsAbslEqDefault(*args[3].type, *args[0].type);
			if (defaultHash && defaultEq)
				ResizeTemplateArgs(c, 2);
			else if (defaultEq)
				ResizeTemplateArgs(c, 3);
			else
				ResizeTemplateArgs(c, 4);
			return true;
		}

		if ((name == "btree_set" || name == "btree_multiset") && args.size() == 3 && args[0].type &&
			args[1].type && args[2].type && IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			if (IsStdOneArgTemplate(*args[1].type, "less", *args[0].type))
				ResizeTemplateArgs(c, 1);
			else
				ResizeTemplateArgs(c, 2);
			return true;
		}

		if ((name == "btree_map" || name == "btree_multimap") && args.size() == 4 && args[0].type &&
			args[1].type && args[2].type && args[3].type &&
			IsDefaultPairAllocator(*args[3].type, *args[0].type, *args[1].type))
		{
			if (IsStdOneArgTemplate(*args[2].type, "less", *args[0].type))
				ResizeTemplateArgs(c, 2);
			else
				ResizeTemplateArgs(c, 3);
			return true;
		}

		if (name == "InlinedVector" && args.size() == 3 && args[0].type && args[2].type &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}

		if (name == "FixedArray" && args.size() == 3 && args[0].type && args[2].type &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}

		return false;
	}

	bool ApplyBoostContainerStringRule(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (name != "basic_string" || args.size() != 3 || !args[0].type || !args[1].type || !args[2].type)
			return false;

		const DemangledTypeNode& element = *args[0].type;
		if (!IsStdOneArgTemplate(*args[1].type, "char_traits", element) ||
			!IsStdOneArgTemplate(*args[2].type, "allocator", element))
			return false;

		if (const char* alias = CharFamilyAliasName(element, "string", "wstring", "u8string", "u16string",
				"u32string"))
		{
			ReplaceWithAlias(c, alias);
			return true;
		}

		ResizeTemplateArgs(c, 1);
		return true;
	}

	bool ApplyBoostContainerTemplateRules(DemangledNamePart& c)
	{
		if (ApplyBoostContainerStringRule(c))
			return true;

		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if ((name == "vector" || name == "deque" || name == "list" || name == "slist" ||
				name == "stable_vector") && args.size() == 2 && args[0].type && args[1].type &&
			IsStdOneArgTemplate(*args[1].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if (name == "small_vector" && args.size() == 3 && args[0].type && args[2].type &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			ResizeTemplateArgs(c, 2);
			return true;
		}

		if ((name == "set" || name == "multiset" || name == "flat_set" || name == "flat_multiset") &&
			args.size() == 3 && args[0].type && args[1].type && args[2].type &&
			IsStdOneArgTemplate(*args[2].type, "allocator", *args[0].type))
		{
			if (IsStdOneArgTemplate(*args[1].type, "less", *args[0].type))
				ResizeTemplateArgs(c, 1);
			else
				ResizeTemplateArgs(c, 2);
			return true;
		}

		if ((name == "map" || name == "multimap" || name == "flat_map" || name == "flat_multimap") &&
			args.size() == 4 && args[0].type && args[1].type && args[2].type && args[3].type &&
			IsDefaultPairAllocatorWithMutableKey(*args[3].type, *args[0].type, *args[1].type))
		{
			if (IsStdOneArgTemplate(*args[2].type, "less", *args[0].type))
				ResizeTemplateArgs(c, 2);
			else
				ResizeTemplateArgs(c, 3);
			return true;
		}

		return false;
	}

	bool ApplyBoostUnorderedTemplateRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if ((name == "unordered_set" || name == "unordered_multiset") && args.size() == 4 && args[0].type &&
			args[1].type && args[2].type && args[3].type &&
			IsStdOneArgTemplate(*args[3].type, "allocator", *args[0].type))
		{
			const bool defaultHash = IsBoostOneArgTemplate(*args[1].type, "hash", *args[0].type);
			const bool defaultEqual = IsStdOneArgTemplate(*args[2].type, "equal_to", *args[0].type);
			if (defaultHash && defaultEqual)
				ResizeTemplateArgs(c, 1);
			else if (defaultEqual)
				ResizeTemplateArgs(c, 2);
			else
				ResizeTemplateArgs(c, 3);
			return true;
		}

		if ((name == "unordered_map" || name == "unordered_multimap") && args.size() == 5 && args[0].type &&
			args[1].type && args[2].type && args[3].type && args[4].type &&
			IsDefaultPairAllocator(*args[4].type, *args[0].type, *args[1].type))
		{
			const bool defaultHash = IsBoostOneArgTemplate(*args[2].type, "hash", *args[0].type);
			const bool defaultEqual = IsStdOneArgTemplate(*args[3].type, "equal_to", *args[0].type);
			if (defaultHash && defaultEqual)
				ResizeTemplateArgs(c, 2);
			else if (defaultEqual)
				ResizeTemplateArgs(c, 3);
			else
				ResizeTemplateArgs(c, 4);
			return true;
		}

		return false;
	}

	bool ApplyPmrAliasToStdTemplate(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if (name == "basic_string" && args.size() == 3 && args[0].type && args[1].type && args[2].type &&
			IsStdOneArgTemplate(*args[1].type, "char_traits", *args[0].type) &&
			IsPmrPolymorphicAllocator(*args[2].type, *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if ((name == "vector" || name == "deque" || name == "forward_list" || name == "list") &&
			args.size() == 2 && args[0].type && args[1].type &&
			IsPmrPolymorphicAllocator(*args[1].type, *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		if ((name == "set" || name == "multiset") && args.size() == 3 && args[0].type && args[1].type &&
			args[2].type && IsPmrPolymorphicAllocator(*args[2].type, *args[0].type))
		{
			if (IsStdOneArgTemplate(*args[1].type, "less", *args[0].type))
				ResizeTemplateArgs(c, 1);
			else
				ResizeTemplateArgs(c, 2);
			return true;
		}

		if ((name == "map" || name == "multimap") && args.size() == 4 && args[0].type && args[1].type &&
			args[2].type && args[3].type && IsPmrPairAllocator(*args[3].type, *args[0].type, *args[1].type))
		{
			if (IsStdOneArgTemplate(*args[2].type, "less", *args[0].type))
				ResizeTemplateArgs(c, 2);
			else
				ResizeTemplateArgs(c, 3);
			return true;
		}

		if ((name == "unordered_set" || name == "unordered_multiset") && args.size() == 4 && args[0].type &&
			args[1].type && args[2].type && args[3].type &&
			IsPmrPolymorphicAllocator(*args[3].type, *args[0].type))
		{
			const bool defaultHash = IsStdOneArgTemplate(*args[1].type, "hash", *args[0].type);
			const bool defaultEqual = IsStdOneArgTemplate(*args[2].type, "equal_to", *args[0].type);
			if (defaultHash && defaultEqual)
				ResizeTemplateArgs(c, 1);
			else if (defaultEqual)
				ResizeTemplateArgs(c, 2);
			else
				ResizeTemplateArgs(c, 3);
			return true;
		}

		if ((name == "unordered_map" || name == "unordered_multimap") && args.size() == 5 && args[0].type &&
			args[1].type && args[2].type && args[3].type && args[4].type &&
			IsPmrPairAllocator(*args[4].type, *args[0].type, *args[1].type))
		{
			const bool defaultHash = IsStdOneArgTemplate(*args[2].type, "hash", *args[0].type);
			const bool defaultEqual = IsStdOneArgTemplate(*args[3].type, "equal_to", *args[0].type);
			if (defaultHash && defaultEqual)
				ResizeTemplateArgs(c, 2);
			else if (defaultEqual)
				ResizeTemplateArgs(c, 3);
			else
				ResizeTemplateArgs(c, 4);
			return true;
		}

		if (name == "match_results" && args.size() == 2 && args[0].type && args[1].type &&
			IsPmrSubMatchAllocator(*args[1].type, *args[0].type))
		{
			ResizeTemplateArgs(c, 1);
			return true;
		}

		return false;
	}

	bool ApplyConcreteStdAliasRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (args.empty())
			return false;

		if (name == "atomic" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = AtomicAliasName(*args[0].type))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if (name == "basic_string" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = CharFamilyAliasName(*args[0].type, "string", "wstring", "u8string",
					"u16string", "u32string"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if (name == "basic_string_view" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = CharFamilyAliasName(*args[0].type, "string_view", "wstring_view",
					"u8string_view", "u16string_view", "u32string_view"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if (name == "basic_regex" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = CharFamilyAliasName(*args[0].type, "regex", "wregex"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if (name == "sub_match" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = RegexIteratorAliasName(*args[0].type, "csub_match", "wcsub_match",
					"ssub_match", "wssub_match"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if (name == "match_results" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = RegexIteratorAliasName(*args[0].type, "cmatch", "wcmatch", "smatch",
					"wsmatch"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if ((name == "regex_iterator" || name == "regex_token_iterator") && (args.size() == 1 || args.size() == 3) &&
			args[0].type)
		{
			if (args.size() == 3)
			{
				if (!args[1].type || !args[2].type)
					return false;
				const bool charIterator = IsConstPointerTo(*args[0].type, "char") ||
					IsStringConstIterator(*args[0].type, false, false);
				const bool wcharIterator = IsConstPointerTo(*args[0].type, "wchar_t") ||
					IsStringConstIterator(*args[0].type, true, false);
				if (!((charIterator && SameType(*args[1].type, "char") &&
						IsStdOneArgTemplate(*args[2].type, "regex_traits", "char")) ||
						(wcharIterator && SameType(*args[1].type, "wchar_t") &&
							IsStdOneArgTemplate(*args[2].type, "regex_traits", "wchar_t"))))
					return false;
			}

			const bool token = name == "regex_token_iterator";
			const char* alias = RegexIteratorAliasName(*args[0].type,
				token ? "cregex_token_iterator" : "cregex_iterator",
				token ? "wcregex_token_iterator" : "wcregex_iterator",
				token ? "sregex_token_iterator" : "sregex_iterator",
				token ? "wsregex_token_iterator" : "wsregex_iterator");
			if (alias)
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if ((name == "basic_syncbuf" || name == "basic_osyncstream" || name == "basic_spanbuf" ||
				name == "basic_ispanstream" || name == "basic_ospanstream" || name == "basic_spanstream") &&
			args.size() == 1 && args[0].type)
		{
			if (name == "basic_syncbuf")
			{
				if (const char* alias = CharFamilyAliasName(*args[0].type, "syncbuf", "wsyncbuf"))
				{
					ReplaceWithAlias(c, alias);
					return true;
				}
			}
			else if (name == "basic_osyncstream")
			{
				if (const char* alias = CharFamilyAliasName(*args[0].type, "osyncstream", "wosyncstream"))
				{
					ReplaceWithAlias(c, alias);
					return true;
				}
			}
			else if (name == "basic_spanbuf")
			{
				if (const char* alias = CharFamilyAliasName(*args[0].type, "spanbuf", "wspanbuf"))
				{
					ReplaceWithAlias(c, alias);
					return true;
				}
			}
			else if (name == "basic_ispanstream")
			{
				if (const char* alias = CharFamilyAliasName(*args[0].type, "ispanstream", "wispanstream"))
				{
					ReplaceWithAlias(c, alias);
					return true;
				}
			}
			else if (name == "basic_ospanstream")
			{
				if (const char* alias = CharFamilyAliasName(*args[0].type, "ospanstream", "wospanstream"))
				{
					ReplaceWithAlias(c, alias);
					return true;
				}
			}
			else if (name == "basic_spanstream")
			{
				if (const char* alias = CharFamilyAliasName(*args[0].type, "spanstream", "wspanstream"))
				{
					ReplaceWithAlias(c, alias);
					return true;
				}
			}
		}
		return false;
	}

	bool ApplyPmrConcreteAliasRules(DemangledNamePart& c)
	{
		ParamList& args = c.GetMutableTemplateArguments();
		const std::string_view name = AbiBaseName(c.GetBase());
		if (name == "basic_string" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = CharFamilyAliasName(*args[0].type, "string", "wstring", "u8string",
					"u16string", "u32string"))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		if (name == "match_results" && args.size() == 1 && args[0].type)
		{
			if (const char* alias = RegexIteratorAliasName(*args[0].type, "cmatch", "wcmatch", "smatch",
					"wsmatch", true))
			{
				ReplaceWithAlias(c, alias);
				return true;
			}
		}
		return false;
	}

	void SimplifyTemplateArguments(DemangledNamePart& c, bool& changed)
	{
		for (auto& arg: c.GetMutableTemplateArguments())
		{
			if (!arg.type)
				continue;
			DemangledTypeNode mutableType = *arg.type;
			bool argChanged = CanonicalizeNonTypeIntegerLiteral(mutableType);
			auto nested = DemangledTemplateSimplifier::SimplifyTypeNodeInPlace(mutableType);
			if (argChanged || nested.changed)
			{
				arg.type = DemangledTypeNode::CreateShared(std::move(mutableType));
				changed = true;
			}
		}
	}

	bool ApplyNamespaceRules(DemangledQualifiedName& name)
	{
		bool changed = false;
		if (!name.empty() && !name[0].HasTemplateArguments() && name[0].GetBase() == "__gnu_cxx")
		{
			name.erase(name.begin());
			changed = true;
		}

		for (auto i = 1; i < name.size();)
		{
			if (!name[i - 1].HasTemplateArguments() && name[i - 1].GetBase() == "std" &&
				IsInlineStdNamespace(name[i]))
			{
				name.erase(name.begin() + i);
				changed = true;
				continue;
			}
			i++;
		}
		for (auto i = 1; i < name.size();)
		{
			if (!name[i - 1].HasTemplateArguments() && name[i - 1].GetBase() == "absl" &&
				IsAbslInlineNamespace(name[i]))
			{
				name.erase(name.begin() + i);
				changed = true;
				continue;
			}
			i++;
		}
		return changed;
	}

	bool ApplyStdRules(DemangledQualifiedName& name)
	{
		bool changed = false;
		for (auto i = 1; i < name.size(); i++)
		{
			if (name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "std")
				continue;
			if (ApplyStdTemplateRules(name[i]))
				changed = true;
		}

		for (auto i = 1; i < name.size(); i++)
		{
			if (name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "std")
				continue;
			if (ApplyPmrAliasToStdTemplate(name[i]))
			{
				name.insert(name.begin() + i, DemangledNamePart("pmr"));
				changed = true;
				i++;
			}
		}

		for (auto i = 1; i < name.size(); i++)
		{
			if (name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "std")
				continue;
			if (ApplyConcreteStdAliasRules(name[i]))
				changed = true;
		}

		for (auto i = 2; i < name.size(); i++)
		{
			if (name[i - 2].HasTemplateArguments() || name[i - 2].GetBase() != "std" ||
				name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "pmr")
				continue;
			if (ApplyPmrConcreteAliasRules(name[i]))
				changed = true;
		}

		for (auto i = 2; i < name.size(); i++)
		{
			if (name[i - 2].HasTemplateArguments() || name[i - 2].GetBase() != "std" ||
				name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "chrono")
				continue;
			if (ApplyChronoRules(name[i]))
				changed = true;
		}
		return changed;
	}

	bool ApplyAbslRules(DemangledQualifiedName& name)
	{
		bool changed = false;
		for (size_t i = 1; i < name.size(); i++)
		{
			if (name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "absl")
				continue;
			if (ApplyAbslTemplateRules(name[i]))
				changed = true;
		}
		return changed;
	}

	bool ApplyBoostRules(DemangledQualifiedName& name)
	{
		bool changed = false;
		for (size_t i = 1; i < name.size(); i++)
		{
			if (name[i - 1].HasTemplateArguments() || name[i - 1].GetBase() != "boost")
				continue;
			if (ApplyBoostUnorderedTemplateRules(name[i]))
				changed = true;
		}

		for (size_t i = 2; i < name.size(); i++)
		{
			if (name[i - 2].HasTemplateArguments() || name[i - 2].GetBase() != "boost" ||
				name[i - 1].HasTemplateArguments())
				continue;

			if (name[i - 1].GetBase() == "container")
			{
				if (ApplyBoostContainerTemplateRules(name[i]))
					changed = true;
			}
			else if (name[i - 1].GetBase() == "unordered")
			{
				if (ApplyBoostUnorderedTemplateRules(name[i]))
					changed = true;
			}
		}
		return changed;
	}

	struct AbiTaggedName
	{
		string base;
		string tags;
	};

	AbiTaggedName SplitAbiTagSuffix(std::string_view name)
	{
		size_t suffixStart = name.size();
		while (suffixStart > 0 && name[suffixStart - 1] == ']')
		{
			std::string_view prefix = name.substr(0, suffixStart);
			size_t tagStart = prefix.rfind("[abi:");
			if (tagStart == std::string_view::npos)
				break;
			suffixStart = tagStart;
		}
		return {
			string(name.substr(0, suffixStart)),
			string(name.substr(suffixStart))
		};
	}

	string AddAbiTags(const string& base, const string& tags)
	{
		if (tags.empty() || (base.size() >= tags.size() && base.compare(base.size() - tags.size(), tags.size(), tags) == 0))
			return base;
		return base + tags;
	}

	bool ConstructorNameMatches(const string& previousBase, const string& currentBase)
	{
		if (previousBase == currentBase)
			return true;
		if (currentBase.size() > previousBase.size() + 1 &&
			currentBase.compare(0, previousBase.size(), previousBase) == 0 &&
			currentBase[previousBase.size()] == '<')
			return true;
		if (StartsWith(std::string_view(currentBase.data(), currentBase.size()), "basic_") &&
			previousBase == currentBase.substr(6))
			return true;
		if (const char* wideName = WideStringName(currentBase))
			return previousBase == wideName;
		return false;
	}

	bool RewriteSimplifiedConstructorSegments(DemangledQualifiedName& name)
	{
		bool changed = false;
		for (size_t i = 1; i < name.size(); i++)
		{
			std::string_view currentName = name[i].GetBase();
			bool destructor = false;
			if (!currentName.empty() && currentName[0] == '~')
			{
				destructor = true;
				currentName.remove_prefix(1);
			}

			AbiTaggedName current = SplitAbiTagSuffix(currentName);
			AbiTaggedName previous = SplitAbiTagSuffix(name[i - 1].GetBase());
			if (current.base.empty() || previous.base.empty() || !ConstructorNameMatches(previous.base, current.base))
				continue;

			string replacement = AddAbiTags(previous.base, current.tags);
			if (destructor)
				replacement.insert(replacement.begin(), '~');

			bool argsChanged = false;
			DemangledNamePart simplifiedCurrent = name[i];
			if (name[i].HasTemplateArguments() && !destructor)
			{
				simplifiedCurrent.SetBase(current.base);
				if (ApplyStdTemplateRules(simplifiedCurrent) || ApplyConcreteStdAliasRules(simplifiedCurrent) ||
					ApplyAbslTemplateRules(simplifiedCurrent) ||
					ApplyBoostContainerTemplateRules(simplifiedCurrent) ||
					ApplyBoostUnorderedTemplateRules(simplifiedCurrent))
				{
					const std::string_view simplifiedBase = AbiBaseName(simplifiedCurrent.GetBase());
					if (simplifiedBase == previous.base || simplifiedBase == replacement)
					{
						argsChanged = true;
					}
				}
			}

			if (replacement != name[i].GetBase())
			{
				name[i].SetBase(replacement);
				changed = true;
			}
			if (argsChanged)
			{
				name[i].SetTemplateArguments(simplifiedCurrent.GetTemplateArguments(), true);
				if (!simplifiedCurrent.HasTemplateArguments())
					name[i].ClearTemplateArguments();
				changed = true;
			}
		}
		return changed;
	}

	bool IsAliasName(std::string_view alias, const unordered_set<std::string_view>& aliases)
	{
		return aliases.find(alias) != aliases.end();
	}

	bool IsTopLevelSimplifiedAlias(const DemangledQualifiedName& name)
	{
		if (name.empty() || name[0].HasTemplateArguments())
			return false;

		if (name[0].GetBase() == "std")
		{
			static const unordered_set<std::string_view> stdAliases = {
				"string", "wstring", "u8string", "u16string", "u32string",
				"string_view", "wstring_view", "u8string_view", "u16string_view", "u32string_view",
				"stringbuf", "wstringbuf", "istringstream", "wistringstream",
				"ostringstream", "wostringstream", "stringstream", "wstringstream",
				"ios", "wios", "streambuf", "wstreambuf", "istream", "wistream",
				"ostream", "wostream", "iostream", "wiostream", "filebuf", "wfilebuf",
				"ifstream", "wifstream", "ofstream", "wofstream", "fstream", "wfstream",
				"syncbuf", "wsyncbuf", "osyncstream", "wosyncstream", "spanbuf", "wspanbuf",
				"ispanstream", "wispanstream", "ospanstream", "wospanstream", "spanstream", "wspanstream",
				"regex", "wregex", "csub_match", "wcsub_match", "ssub_match", "wssub_match",
				"cmatch", "wcmatch", "smatch", "wsmatch", "cregex_iterator", "wcregex_iterator",
				"sregex_iterator", "wsregex_iterator", "cregex_token_iterator", "wcregex_token_iterator",
				"sregex_token_iterator", "wsregex_token_iterator",
				"atomic_bool", "atomic_char", "atomic_schar", "atomic_uchar",
				"atomic_short", "atomic_ushort", "atomic_int", "atomic_uint",
				"atomic_long", "atomic_ulong", "atomic_llong", "atomic_ullong",
				"atomic_char8_t", "atomic_char16_t", "atomic_char32_t", "atomic_wchar_t",
				"atomic_int8_t", "atomic_uint8_t", "atomic_int16_t", "atomic_uint16_t",
				"atomic_int32_t", "atomic_uint32_t", "atomic_int64_t", "atomic_uint64_t",
				"atomic_int_least8_t", "atomic_uint_least8_t", "atomic_int_least16_t",
				"atomic_uint_least16_t", "atomic_int_least32_t", "atomic_uint_least32_t",
				"atomic_int_least64_t", "atomic_uint_least64_t", "atomic_int_fast8_t",
				"atomic_uint_fast8_t", "atomic_int_fast16_t", "atomic_uint_fast16_t",
				"atomic_int_fast32_t", "atomic_uint_fast32_t", "atomic_int_fast64_t",
				"atomic_uint_fast64_t", "atomic_intptr_t", "atomic_uintptr_t",
				"atomic_size_t", "atomic_ptrdiff_t", "atomic_intmax_t", "atomic_uintmax_t",
				"atomic_signed_lock_free", "atomic_unsigned_lock_free", "streampos"
			};

			if (name.size() == 2 && !name[1].HasTemplateArguments())
				return IsAliasName(name[1].GetBase(), stdAliases);

			if (name.size() != 3 || name[1].HasTemplateArguments() || name[1].GetBase() != "pmr" ||
				name[2].HasTemplateArguments())
				return false;

			static const unordered_set<std::string_view> pmrAliases = {
				"string", "wstring", "u8string", "u16string", "u32string",
				"vector", "deque", "list", "forward_list",
				"map", "multimap", "set", "multiset",
				"unordered_map", "unordered_multimap", "unordered_set", "unordered_multiset",
				"match_results", "cmatch", "wcmatch", "smatch", "wsmatch"
			};
			return IsAliasName(name[2].GetBase(), pmrAliases);
		}

		if (name[0].GetBase() == "boost" && name.size() == 3 && !name[1].HasTemplateArguments() &&
			name[1].GetBase() == "container" && !name[2].HasTemplateArguments())
		{
			static const unordered_set<std::string_view> boostContainerAliases = {
				"string", "wstring", "u8string", "u16string", "u32string"
			};
			return IsAliasName(name[2].GetBase(), boostContainerAliases);
		}

		return false;
	}

	bool HasTemplateArgs(const DemangledQualifiedName& name)
	{
		return std::ranges::any_of(name, [](const auto& component) { return component.HasTemplateArguments(); });
	}

	// Compatibility parser for qualified names that do not come from a demangler AST.
	// Native GNU3/MSVC paths use the structured DemangledTypeNode overloads.
	size_t FindTemplateOpen(std::string_view component)
	{
		component = TrimSpaces(component);
		if (StartsWith(component, "operator"))
		{
			static constexpr std::string_view operators[] = {
				"operator<=>", "operator<<=", "operator>>=", "operator->*", "operator++", "operator--",
				"operator<<", "operator>>", "operator<=", "operator>=", "operator==", "operator!=",
				"operator+=", "operator-=", "operator*=", "operator/=", "operator%=", "operator&=",
				"operator|=", "operator^=", "operator&&", "operator||", "operator()", "operator[]",
				"operator->", "operator<", "operator>", "operator+", "operator-", "operator*",
				"operator/", "operator%", "operator&", "operator|", "operator^", "operator~",
				"operator!", "operator=", "operator,"
			};
			for (std::string_view op: operators)
			{
				if (component.size() > op.size() && component.compare(0, op.size(), op) == 0 &&
					component[op.size()] == '<')
					return op.size();
			}
			return std::string_view::npos;
		}
		int depth = 0;
		for (size_t i = 0; i < component.size(); i++)
		{
			if (component[i] == '<')
			{
				if (depth == 0)
					return i;
				depth++;
			}
			else if (component[i] == '>' && depth > 0)
			{
				depth--;
			}
		}
		return std::string_view::npos;
	}

	vector<std::string_view> SplitTopLevel(std::string_view s, char delimiter)
	{
		vector<std::string_view> out;
		int angleDepth = 0, parenDepth = 0, bracketDepth = 0;
		size_t start = 0;
		for (size_t i = 0; i < s.size(); i++)
		{
			char c = s[i];
			if (delimiter == ':' && i + 1 < s.size() && c == ':' && s[i + 1] == ':' &&
				angleDepth == 0 && parenDepth == 0 && bracketDepth == 0)
			{
				out.push_back(TrimSpaces(s.substr(start, i - start)));
				i++;
				start = i + 1;
				continue;
			}
			if (delimiter != ':' && c == delimiter && angleDepth == 0 && parenDepth == 0 && bracketDepth == 0)
			{
				out.push_back(TrimSpaces(s.substr(start, i - start)));
				start = i + 1;
				continue;
			}
			switch (c)
			{
			case '<': angleDepth++; break;
			case '>': if (angleDepth > 0) angleDepth--; break;
			case '(': parenDepth++; break;
			case ')': if (parenDepth > 0) parenDepth--; break;
			case '[': bracketDepth++; break;
			case ']': if (bracketDepth > 0) bracketDepth--; break;
			default: break;
			}
		}
		out.push_back(TrimSpaces(s.substr(start)));
		return out;
	}

	DemangledTypeNode ParseCompatibilityType(std::string_view s);

	ParamList ParseCompatibilityArgs(std::string_view s)
	{
		ParamList args;
		for (std::string_view arg: SplitTopLevel(s, ','))
		{
			DemangledTypeNode node = ParseCompatibilityType(arg);
			args.push_back({"", DemangledTypeNode::CreateShared(std::move(node))});
		}
		return args;
	}

	DemangledQualifiedName ParseCompatibilityName(std::string_view s)
	{
		DemangledQualifiedName out;
		for (std::string_view part: SplitTopLevel(s, ':'))
		{
			part = TrimSpaces(part);
			size_t open = FindTemplateOpen(part);
			if (open == std::string_view::npos)
			{
				out.emplace_back(part);
				continue;
			}
			size_t close = part.rfind('>');
			if (close == std::string_view::npos || close < open)
			{
				out.emplace_back(part);
				continue;
			}

			std::string_view base = TrimSpaces(part.substr(0, open));
			DemangledNamePart segment{base};
			segment.SetTemplateArguments(ParseCompatibilityArgs(part.substr(open + 1, close - open - 1)), true);
			out.push_back(std::move(segment));
		}
		return out;
	}

	DemangledTypeNode ParseCompatibilityType(std::string_view s)
	{
		s = StripLeadingTypeKeyword(s);
		if (s.empty())
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{""});
		if (s.find("::") == std::string_view::npos && FindTemplateOpen(s) == std::string_view::npos)
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{string(s)});
		return DemangledTypeNode::NamedType(UnknownNamedTypeClass, ParseCompatibilityName(s));
	}

	StringList RenderSegments(const DemangledQualifiedName& name)
	{
		return DemangledTypeNode::NamedType(UnknownNamedTypeClass, name).RenderTypeNameSegments();
	}
}

DemangledTemplateSimplifier::SimplifyNameResult DemangledTemplateSimplifier::SimplifyNameSegmentsInPlace(
	DemangledQualifiedName& name)
{
	SimplifyNameResult result;
	if (name.empty())
		return result;

	bool changed = false;
	for (auto& component: name)
		SimplifyTemplateArguments(component, changed);
	changed |= ApplyNamespaceRules(name);
	changed |= ApplyStdRules(name);
	changed |= ApplyAbslRules(name);
	changed |= ApplyBoostRules(name);
	changed |= RewriteSimplifiedConstructorSegments(name);

	result.changed = changed;
	result.topLevelIsAlias = IsTopLevelSimplifiedAlias(name);
	return result;
}

DemangledTemplateSimplifier::SimplifyNameResult DemangledTemplateSimplifier::SimplifyTypeNodeInPlace(
	DemangledTypeNode& type)
{
	SimplifyNameResult result;
	bool topLevelNameIsAlias = false;
	result.changed = type.MutateQualifiedNames([&](DemangledQualifiedName& name) {
		auto nameResult = SimplifyNameSegmentsInPlace(name);
		if (nameResult.topLevelIsAlias)
		{
			topLevelNameIsAlias = true;
			result.topLevelIsAlias = true;
		}
		return nameResult.changed;
	});
	if (topLevelNameIsAlias && type.GetClass() == NamedTypeReferenceClass && type.GetNTRClass() != UnknownNamedTypeClass)
	{
		type.SetNTRType(UnknownNamedTypeClass);
		result.changed = true;
	}
	if (type.MutateChildTypes([&](DemangledTypeNode& child) {
		auto childResult = SimplifyTypeNodeInPlace(child);
		if (childResult.topLevelIsAlias)
			result.topLevelIsAlias = true;
		return childResult.changed;
	}))
		result.changed = true;
	return result;
}

BN::QualifiedName DemangledTemplateSimplifier::SimplifyQualifiedName(const BN::QualifiedName& name)
{
	auto renderedName = name.GetString();
	auto stripped = StripLeadingTypeKeyword(std::string_view(renderedName.data(), renderedName.size()));
	DemangledQualifiedName parsed = ParseCompatibilityName(stripped);
	SimplifyNameSegmentsInPlace(parsed);
	return BN::QualifiedName(RenderSegments(parsed));
}

bool DemangledTemplateSimplifier::NameSegmentsHaveTemplateArguments(const DemangledQualifiedName& name)
{
	return HasTemplateArgs(name);
}
