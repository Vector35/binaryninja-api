#pragma once
#include <map>
#include "type.h"
#include "variable.hpp"
#include "confidence.hpp"
#include "qualifiedname.hpp"

namespace BinaryNinja {

	class Structure;
	class NamedTypeReference;
	class Enumeration;
	class EnumerationBuilder;
	class StructureBuilder;
	class NamedTypeReferenceBuilder;
	class FunctionParameter;
	class TypeDefinitionLine;
	class Platform;
	class CallingConvention;
	class InstructionTextToken;

	class Type : public CoreRefCountObject<BNType, BNNewTypeReference, BNFreeType>
	{
	  public:
		Type(BNType* type);

		bool operator==(const Type& other);
		bool operator!=(const Type& other);

		BNTypeClass GetClass() const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		QualifiedName GetTypeName() const;
		Confidence<bool> IsSigned() const;
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const;
		bool IsSystemCall() const;

		Confidence<Ref<Type>> GetChildType() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		std::vector<FunctionParameter> GetParameters() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<bool> CanReturn() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const;
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;
		Ref<NamedTypeReference> GetRegisteredName() const;
		uint32_t GetSystemCallNumber() const;
		BNIntegerDisplayType GetIntegerTypeDisplayType() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;

		std::string GetString(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetTypeAndName(const QualifiedName& name, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetStringBeforeName(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetStringAfterName(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;

		std::vector<InstructionTextToken> GetTokens(
			Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(
			Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::vector<InstructionTextToken> GetTokensAfterName(
			Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			BNTokenEscapingType escaping = NoTokenEscapingType) const;

		Ref<Type> Duplicate() const;

		static Ref<Type> VoidType();
		static Ref<Type> BoolType();
		static Ref<Type> IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");
		static Ref<Type> FloatType(size_t width, const std::string& altName = "");
		static Ref<Type> WideCharType(size_t width, const std::string& altName = "");
		static Ref<Type> StructureType(Structure* strct);
		static Ref<Type> NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static Ref<Type> NamedType(const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(BinaryView* view, const QualifiedName& name);
		static Ref<Type> EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0,
			const Confidence<bool>& isSigned = Confidence<bool>(false, 0));
		static Ref<Type> EnumerationType(
			Enumeration* enm, size_t width, const Confidence<bool>& isSigned = Confidence<bool>(false, 0));
		static Ref<Type> PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static Ref<Type> PointerType(size_t width, const Confidence<Ref<Type>>& type,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static Ref<Type> ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
			const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
			const Confidence<bool>& varArg = Confidence<bool>(false, 0),
			const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
			const Confidence<Ref<CallingConvention>>& callingConvention,
			const std::vector<FunctionParameter>& params,
			const Confidence<bool>& hasVariableArguments,
			const Confidence<bool>& canReturn,
			const Confidence<int64_t>& stackAdjust,
			const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
			const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
			BNNameType ft = NoNameType);

		static std::string GenerateAutoTypeId(const std::string& source, const QualifiedName& name);
		static std::string GenerateAutoDemangledTypeId(const QualifiedName& name);
		static std::string GetAutoDemangledTypeIdSource();
		static std::string GenerateAutoDebugTypeId(const QualifiedName& name);
		static std::string GetAutoDebugTypeIdSource();

		Confidence<Ref<Type>> WithConfidence(uint8_t conf);

		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }
		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		bool IsVoid() const { return GetClass() == VoidTypeClass; }
		bool IsBool() const { return GetClass() == BoolTypeClass; }
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }
		bool IsFloat() const { return GetClass() == FloatTypeClass; }
		bool IsStructure() const { return GetClass() == StructureTypeClass; }
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }
		bool IsPointer() const { return GetClass() == PointerTypeClass; }
		bool IsArray() const { return GetClass() == ArrayTypeClass; }
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }
		bool IsValue() const { return GetClass() == ValueTypeClass; }
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }

		Ref<Type> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Type> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Type> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);

		bool AddTypeMemberTokens(BinaryView* data, std::vector<InstructionTextToken>& tokens, int64_t offset,
			std::vector<std::string>& nameList, size_t size = 0, bool indirect = false);
		std::vector<TypeDefinitionLine> GetLines(Ref<BinaryView> data, const std::string& name,
			int lineWidth = 80, bool collapsed = false, BNTokenEscapingType escaping = NoTokenEscapingType);

		static std::string GetSizeSuffix(size_t size);
	};

	struct FunctionParameter
	{
		std::string name;
		Confidence<Ref<Type>> type;
		bool defaultLocation;
		Variable location;

		FunctionParameter() = default;
		FunctionParameter(const std::string& name, Confidence<Ref<Type>> type): name(name), type(type), defaultLocation(true)
		{}

		FunctionParameter(const std::string& name, const Confidence<Ref<Type>>& type, bool defaultLocation,
			const Variable& location):
			name(name), type(type), defaultLocation(defaultLocation), location(location)
		{}
	};

	class TypeBuilder
	{
		BNTypeBuilder* m_object;

	  public:
		TypeBuilder();
		TypeBuilder(BNTypeBuilder* type);
		TypeBuilder(const TypeBuilder& type);
		TypeBuilder(TypeBuilder&& type);
		TypeBuilder(Type* type);
		TypeBuilder& operator=(const TypeBuilder& type);
		TypeBuilder& operator=(TypeBuilder&& type);
		TypeBuilder& operator=(Type* type);

		Ref<Type> Finalize();

		BNTypeClass GetClass() const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		QualifiedName GetTypeName() const;
		Confidence<bool> IsSigned() const;
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const;
		bool IsSystemCall() const;
		void SetIntegerTypeDisplayType(BNIntegerDisplayType displayType);

		Confidence<Ref<Type>> GetChildType() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		std::vector<FunctionParameter> GetParameters() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<bool> CanReturn() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const;
		TypeBuilder& SetScope(const Confidence<BNMemberScope>& scope);
		TypeBuilder& SetConst(const Confidence<bool>& cnst);
		TypeBuilder& SetVolatile(const Confidence<bool>& vltl);
		TypeBuilder& SetChildType(const Confidence<Ref<Type>>& child);
		TypeBuilder& SetSigned(const Confidence<bool>& vltl);
		TypeBuilder& SetTypeName(const QualifiedName& name);
		TypeBuilder& SetAlternateName(const std::string& name);
		TypeBuilder& SetSystemCall(bool sc, uint32_t n = 0);
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;
		uint32_t GetSystemCallNumber() const;

		TypeBuilder& SetFunctionCanReturn(const Confidence<bool>& canReturn);
		TypeBuilder& SetParameters(const std::vector<FunctionParameter>& params);

		std::string GetString(Platform* platform = nullptr) const;
		std::string GetTypeAndName(const QualifiedName& name) const;
		std::string GetStringBeforeName(Platform* platform = nullptr) const;
		std::string GetStringAfterName(Platform* platform = nullptr) const;

		std::vector<InstructionTextToken> GetTokens(
			Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(
			Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensAfterName(
			Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		static TypeBuilder VoidType();
		static TypeBuilder BoolType();
		static TypeBuilder IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");
		static TypeBuilder FloatType(size_t width, const std::string& typeName = "");
		static TypeBuilder WideCharType(size_t width, const std::string& typeName = "");
		static TypeBuilder StructureType(Structure* strct);
		static TypeBuilder StructureType(StructureBuilder* strct);
		static TypeBuilder NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static TypeBuilder NamedType(NamedTypeReferenceBuilder* ref, size_t width = 0, size_t align = 1,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static TypeBuilder NamedType(const QualifiedName& name, Type* type);
		static TypeBuilder NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static TypeBuilder NamedType(BinaryView* view, const QualifiedName& name);
		static TypeBuilder EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0,
			const Confidence<bool>& issigned = Confidence<bool>(false, 0));
		static TypeBuilder EnumerationType(Architecture* arch, EnumerationBuilder* enm, size_t width = 0,
			const Confidence<bool>& issigned = Confidence<bool>(false, 0));
		static TypeBuilder PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static TypeBuilder PointerType(size_t width, const Confidence<Ref<Type>>& type,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static TypeBuilder ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);
		static TypeBuilder FunctionType(const Confidence<Ref<Type>>& returnValue,
			const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
			const Confidence<bool>& varArg = Confidence<bool>(false, 0),
			const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));
		static TypeBuilder FunctionType(const Confidence<Ref<Type>>& returnValue,
			const Confidence<Ref<CallingConvention>>& callingConvention,
			const std::vector<FunctionParameter>& params,
			const Confidence<bool>& hasVariableArguments,
			const Confidence<bool>& canReturn,
			const Confidence<int64_t>& stackAdjust,
			const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
			const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
			BNNameType ft = NoNameType);

		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }
		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		bool IsVoid() const { return GetClass() == VoidTypeClass; }
		bool IsBool() const { return GetClass() == BoolTypeClass; }
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }
		bool IsFloat() const { return GetClass() == FloatTypeClass; }
		bool IsStructure() const { return GetClass() == StructureTypeClass; }
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }
		bool IsPointer() const { return GetClass() == PointerTypeClass; }
		bool IsArray() const { return GetClass() == ArrayTypeClass; }
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }
		bool IsValue() const { return GetClass() == ValueTypeClass; }
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }
	};

	class NamedTypeReference :
		public CoreRefCountObject<BNNamedTypeReference, BNNewNamedTypeReference, BNFreeNamedTypeReference>
	{
	  public:
		NamedTypeReference(BNNamedTypeReference* nt);
		NamedTypeReference(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
			const QualifiedName& name = QualifiedName());
		BNNamedTypeReferenceClass GetTypeReferenceClass() const;
		std::string GetTypeId() const;
		QualifiedName GetName() const;

		static Ref<NamedTypeReference> GenerateAutoTypeReference(
			BNNamedTypeReferenceClass cls, const std::string& source, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDemangledTypeReference(
			BNNamedTypeReferenceClass cls, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDebugTypeReference(
			BNNamedTypeReferenceClass cls, const QualifiedName& name);
	};

	class NamedTypeReferenceBuilder
	{
		BNNamedTypeReferenceBuilder* m_object;

	  public:
		NamedTypeReferenceBuilder(BNNamedTypeReferenceBuilder* nt);
		NamedTypeReferenceBuilder(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
			const QualifiedName& name = QualifiedName());
		~NamedTypeReferenceBuilder();
		BNNamedTypeReferenceBuilder* GetObject() { return m_object; };
		BNNamedTypeReferenceClass GetTypeReferenceClass() const;
		std::string GetTypeId() const;
		QualifiedName GetName() const;

		void SetTypeReferenceClass(BNNamedTypeReferenceClass type);
		void SetTypeId(const std::string& id);
		void SetName(const QualifiedName& name);

		Ref<NamedTypeReference> Finalize();
	};

	struct StructureMember
	{
		Ref<Type> type;
		std::string name;
		uint64_t offset;
		BNMemberAccess access;
		BNMemberScope scope;
	};

	class Structure : public CoreRefCountObject<BNStructure, BNNewStructureReference, BNFreeStructure>
	{
	  public:
		Structure(BNStructure* s);

		std::vector<StructureMember> GetMembers() const;
		bool GetMemberByName(const std::string& name, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		bool IsPacked() const;
		bool IsUnion() const;
		BNStructureVariant GetStructureType() const;

		Ref<Structure> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Structure> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Structure> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);
	};

	class StructureBuilder
	{
		BNStructureBuilder* m_object;

	  public:
		StructureBuilder();
		StructureBuilder(BNStructureBuilder* s);
		StructureBuilder(BNStructureVariant type, bool packed = false);
		StructureBuilder(const StructureBuilder& s);
		StructureBuilder(StructureBuilder&& s);
		StructureBuilder(Structure* s);
		~StructureBuilder();
		StructureBuilder& operator=(const StructureBuilder& s);
		StructureBuilder& operator=(StructureBuilder&& s);
		StructureBuilder& operator=(Structure* s);
		BNStructureBuilder* GetObject() { return m_object; };

		Ref<Structure> Finalize() const;

		std::vector<StructureMember> GetMembers() const;
		bool GetMemberByName(const std::string& name, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;
		uint64_t GetWidth() const;
		StructureBuilder& SetWidth(size_t width);
		size_t GetAlignment() const;
		StructureBuilder& SetAlignment(size_t align);
		bool IsPacked() const;
		StructureBuilder& SetPacked(bool packed);
		bool IsUnion() const;
		StructureBuilder& SetStructureType(BNStructureVariant type);
		BNStructureVariant GetStructureType() const;
		StructureBuilder& AddMember(const Confidence<Ref<Type>>& type, const std::string& name,
			BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);
		StructureBuilder& AddMemberAtOffset(const Confidence<Ref<Type>>& type, const std::string& name, uint64_t offset,
			bool overwriteExisting = true, BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);
		StructureBuilder& RemoveMember(size_t idx);
		StructureBuilder& ReplaceMember(
			size_t idx, const Confidence<Ref<Type>>& type, const std::string& name, bool overwriteExisting = true);
	};

	struct EnumerationMember
	{
		std::string name;
		uint64_t value;
		bool isDefault;
	};

	class Enumeration : public CoreRefCountObject<BNEnumeration, BNNewEnumerationReference, BNFreeEnumeration>
	{
	  public:
		Enumeration(BNEnumeration* e);

		std::vector<EnumerationMember> GetMembers() const;
	};

	class EnumerationBuilder
	{
		BNEnumerationBuilder* m_object;

	  public:
		EnumerationBuilder();
		EnumerationBuilder(BNEnumerationBuilder* e);
		EnumerationBuilder(const EnumerationBuilder& e);
		EnumerationBuilder(EnumerationBuilder&& e);
		EnumerationBuilder(Enumeration* e);
		~EnumerationBuilder();
		BNEnumerationBuilder* GetObject() { return m_object; }
		EnumerationBuilder& operator=(const EnumerationBuilder& e);
		EnumerationBuilder& operator=(EnumerationBuilder&& e);
		EnumerationBuilder& operator=(Enumeration* e);

		Ref<Enumeration> Finalize() const;

		std::vector<EnumerationMember> GetMembers() const;

		EnumerationBuilder& AddMember(const std::string& name);
		EnumerationBuilder& AddMemberWithValue(const std::string& name, uint64_t value);
		EnumerationBuilder& RemoveMember(size_t idx);
		EnumerationBuilder& ReplaceMember(size_t idx, const std::string& name, uint64_t value);
	};

	struct TypeDefinitionLine
	{
		BNTypeDefinitionLineType lineType;
		std::vector<InstructionTextToken> tokens;
		Ref<Type> type, rootType;
		std::string rootTypeName;
		uint64_t offset;
		size_t fieldIndex;

		static TypeDefinitionLine FromAPIObject(BNTypeDefinitionLine* line);
		static BNTypeDefinitionLine* CreateTypeDefinitionLineList(
		    const std::vector<TypeDefinitionLine>& lines);
		static void FreeTypeDefinitionLineList(
		    BNTypeDefinitionLine* lines, size_t count);
	};

	bool PreprocessSource(const std::string& source, const std::string& fileName, std::string& output,
	    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>());

}