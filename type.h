#pragma once

#include "binaryninjacore.h"
#include "confidence.h"
#include "namelist.h"
#include "refcount.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class Architecture;
	class BinaryView;
	class CallingConvention;
	class Enumeration;
	struct FunctionParameter;
	struct InstructionTextToken;
	class NamedTypeReference;
	class Platform;
	class QualifiedName;
	class Structure;
	class TypeContainer;
	struct TypeDefinitionLine;


	/*!
		\ingroup types
	*/
	class Type : public CoreRefCountObject<BNType, BNNewTypeReference, BNFreeType>
	{
	  public:
		Type(BNType* type);

		bool operator==(const Type& other);
		bool operator!=(const Type& other);


		/*! Retrieve the Type Class for this Structure

		 	One of:

		        VoidTypeClass
				BoolTypeClass
				IntegerTypeClass
				FloatTypeClass
				StructureTypeClass
				EnumerationTypeClass
				PointerTypeClass
				ArrayTypeClass
				FunctionTypeClass
				VarArgsTypeClass
				ValueTypeClass
				NamedTypeReferenceClass
				WideCharTypeClass

		    \return The type class
		*/
		BNTypeClass GetClass() const;

		/*! Get the width in bytes of the Type

		    \return The type width
		*/
		uint64_t GetWidth() const;
		size_t GetAlignment() const;

		/*! Get the QualifiedName for the Type

		    \return The QualifiedName for the type
		*/
		QualifiedName GetTypeName() const;

		/*! Whether the type is signed
		*/
		Confidence<bool> IsSigned() const;

		/*! Whether the type is constant

		*/
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const; // Unimplemented!
		bool IsSystemCall() const;


		/*! Get the child type for this Type if one exists

		    \return The child type
		*/
		Confidence<Ref<Type>> GetChildType() const;

		/*! For Function Types, get the calling convention

		    \return The CallingConvention
		*/
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;

		/*! For Function Types, get a list of parameters

		    \return A vector of FunctionParameters
		*/
		std::vector<FunctionParameter> GetParameters() const;

		/*! For Function Types, whether the Function has variadic arguments

		    \return Whether the function has variable arguments
		*/
		Confidence<bool> HasVariableArguments() const;

		/*! For Function Types, whether a function can return (is not marked noreturn)

		    \return Whether the function can return
		*/
		Confidence<bool> CanReturn() const;

		/*! For Function Types, whether a function is pure (has no observable side-effects)

		    \return Whether the function is pure
		*/
		Confidence<bool> IsPure() const;

		/*! For Structure Types, the underlying Structure

		    \return The underlying structure
		*/
		Ref<Structure> GetStructure() const;

		/*! For Enumeration Types, the underlying Enumeration

		    \return The underlying enumeration
		*/
		Ref<Enumeration> GetEnumeration() const;

		/*! For NamedTypeReference Types, the underlying NamedTypeReference

		    \return The underlying NamedTypeReference
		*/
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const; // Unimplemented!
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;
		Ref<NamedTypeReference> GetRegisteredName() const;
		uint32_t GetSystemCallNumber() const;
		BNIntegerDisplayType GetIntegerTypeDisplayType() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;
		BNPointerBaseType GetPointerBaseType() const;
		int64_t GetPointerBaseOffset() const;

		std::set<BNPointerSuffix> GetPointerSuffix() const;
		std::string GetPointerSuffixString() const;
		std::vector<InstructionTextToken> GetPointerSuffixTokens(uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

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


		/*! Create a "void" type

		    \return The created Type object
		*/
		static Ref<Type> VoidType();

		/*! Create a "bool" type

		    \return The created Type object
		*/
		static Ref<Type> BoolType();

		/*! Create a signed or unsigned integer with a set width

		    \param width Width of the Type in bytes
		    \param sign Whether the integer is a signed or unsigned type
		    \param altName Alternative name for the type
		    \return The created Type object
		*/
		static Ref<Type> IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");

		/*! Create a float or double Type with a specified width

		    \param width Width of the Type in bytes
		    \param altName Alternative name for the type
		    \return The created Type object
		*/
		static Ref<Type> FloatType(size_t width, const std::string& altName = "");
		static Ref<Type> WideCharType(size_t width, const std::string& altName = "");

		/*! Create a Type object from a Structure object

		 	Structure objects can be generated using the StructureBuilder class.

		    \param strct Structure object
		    \return The created Type object
		*/
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

		/*! Create a Pointer type, which points to another Type

			\code{.cpp}
		 	// Creating a "char *" type
		 	auto arch = bv->GetDefaultArchitecture();
		    auto charPointerType = Type::PointerType(arch, Type::IntegerType(1, false));
		 	\endcode

			\param arch Architecture, used to calculate the proper pointer width
			\param type Type that this Type points to
			\param cnst Whether this type is const
			\param vltl Whether this type is volatile
			\param refType Reference Type, one of "PointerReferenceType", "ReferenceReferenceType", "RValueReferenceType", "NoReference"
			\return The created type
		*/
		static Ref<Type> PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);

		/*! Create a Pointer type, which points to another Type

			\code{.cpp}
			// Creating a "char *" type in a binary compiled for 64 bit address spaces
			auto charPointerType = Type::PointerType(8, Type::IntegerType(1, false));
			\endcode

			\param width Width of the pointer in bytes
			\param type Type that this type points to
			\param cnst Whether this type is const
			\param vltl Whether this type is volatile
			\param refType Reference Type, one of "PointerReferenceType", "ReferenceReferenceType", "RValueReferenceType", "NoReference"
			\return The created type
		*/
		static Ref<Type> PointerType(size_t width, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);

		/*! Create an Array Type

			\param type Type for Elements contained in this Array
			\param elem Number of elements
			\return The created Type
		*/
		static Ref<Type> ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);

		/*! Create a Function Type

			\code{.cpp}
		    Ref<Type> retType = Type::VoidType();

			std::vector<FunctionParameter> params
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		    params.push_back({"arg0",
				Type::IntegerType(8, false),
				true,
				Variable()});

		    auto functionType = Type::FunctionType(retType, cc, params);
		    \endcode

			\param returnValue Return value Type
			\param callingConvention Calling convention for the function
			\param params list of FunctionParameter s
			\param varArg Whether this function has variadic arguments, default false
			\param stackAdjust Stack adjustment for this function, default 0
			\return The created function types
		*/
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& varArg = Confidence<bool>(false, 0),
		    const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));

		/*! Create a Function Type

			\code{.cpp}
		    Ref<Type> retType = Type::VoidType();

			std::vector<FunctionParameter> params
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		    params.push_back({"arg0",
				Type::IntegerType(8, false),
				true,
				Variable()});

		    auto functionType = Type::FunctionType(retType, cc, params);
		    \endcode

			\param returnValue Return value Type
			\param callingConvention Calling convention for the function
			\param params list of FunctionParameters
			\param varArg Whether this function has variadic arguments, default false
			\param stackAdjust Stack adjustment for this function, default 0
		 	\param regStackAdjust Register stack adjustmemt
		 	\param returnRegs Return registers
			\return The created function types
		*/
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention,
		    const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& hasVariableArguments,
		    const Confidence<bool>& canReturn,
		    const Confidence<int64_t>& stackAdjust,
		    const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
		    const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
		    BNNameType ft = NoNameType,
		    const Confidence<bool>& pure = Confidence<bool>(false, 0));

		static std::string GenerateAutoTypeId(const std::string& source, const QualifiedName& name);
		static std::string GenerateAutoDemangledTypeId(const QualifiedName& name);
		static std::string GetAutoDemangledTypeIdSource();
		static std::string GenerateAutoDebugTypeId(const QualifiedName& name);
		static std::string GetAutoDebugTypeIdSource();

		/*! Get this type wrapped in a Confidence template

			\param conf Confidence value between 0 and 255
			\return Confidence-wrapped Type
		*/
		Confidence<Ref<Type>> WithConfidence(uint8_t conf);

		/*! If this Type is a NamedTypeReference, check whether it is reference to a specific Type

			\param refType BNNamedTypeReference to check it against
			\return Whether it is a reference of this type
		*/
		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);

		/*! If this Type is a NamedTypeReference, check whether it refers to a Struct Type

			\return Whether it refers to a struct type.
		*/
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to an Enum Type

			\return Whether it refers to an Enum type.
		*/
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Union Type

			\return Whether it refers to a union type.
		*/
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Class Type

			\return Whether it refers to a class type.
		*/
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Typedef type

			\return Whether it refers to a typedef type.
		*/

		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Struct or Class Type

			\return Whether it refers to a struct or class type.
		*/
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		/*! Check whether this type is a Void type.

			\return Whether this->GetClass() == VoidTypeClass
		*/
		bool IsVoid() const { return GetClass() == VoidTypeClass; }

		/*! Check whether this type is a Boolean type.

			\return Whether this->GetClass() == BoolTypeClass
		*/
		bool IsBool() const { return GetClass() == BoolTypeClass; }

		/*! Check whether this type is an Integer type.

			\return Whether this->GetClass() == IntegerTypeClass
		*/
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }

		/*! Check whether this type is a Float type.

			\return Whether this->GetClass() == FloatTypeClass
		*/
		bool IsFloat() const { return GetClass() == FloatTypeClass; }

		/*! Check whether this type is a Structure type.

			\return Whether this->GetClass() == StructureTypeClass
		*/
		bool IsStructure() const { return GetClass() == StructureTypeClass; }

		/*! Check whether this type is an Enumeration type.

			\return Whether this->GetClass() == EnumerationTypeClass
		*/
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }

		/*! Check whether this type is a Pointer type.

			\return Whether this->GetClass() == PointerTypeClass
		*/
		bool IsPointer() const { return GetClass() == PointerTypeClass; }

		/*! Check whether this type is an Array type.

			\return Whether this->GetClass() == ArrayTypeClass
		*/
		bool IsArray() const { return GetClass() == ArrayTypeClass; }

		/*! Check whether this type is a Function type.

			\return Whether this->GetClass() == FunctionTypeClass
		*/
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }

		/*! Check whether this type is a Variadic Arguments type.

			\return Whether this->GetClass() == VarArgsTypeClass
		*/
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }

		/*! Check whether this type is a Value type.

			\return Whether this->GetClass() == ValueTypeClass
		*/
		bool IsValue() const { return GetClass() == ValueTypeClass; }

		/*! Check whether this type is a Named Type Reference type.

			\return Whether this->GetClass() == NamedTypeReferenceClass
		*/
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }

		/*! Check whether this type is a Wide Char type.

			\return Whether this->GetClass() == WideCharTypeClass
		*/
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }

		Ref<Type> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Type> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Type> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);

		bool AddTypeMemberTokens(BinaryView* data, std::vector<InstructionTextToken>& tokens, int64_t offset,
		    std::vector<std::string>& nameList, size_t size = 0, bool indirect = false);
		std::vector<TypeDefinitionLine> GetLines(const TypeContainer& types, const std::string& name,
			int paddingCols = 64, bool collapsed = false, BNTokenEscapingType escaping = NoTokenEscapingType);

		static std::string GetSizeSuffix(size_t size);
	};

	class EnumerationBuilder;
	class StructureBuilder;
	class NamedTypeReferenceBuilder;
	/*!
		\ingroup types
	*/
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
		Confidence<bool> IsPure() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const;
		TypeBuilder& SetWidth(size_t width);
		TypeBuilder& SetAlignment(size_t alignment);
		TypeBuilder& SetNamedTypeReference(NamedTypeReference* ntr);
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
		BNPointerBaseType GetPointerBaseType() const;
		int64_t GetPointerBaseOffset() const;

		TypeBuilder& SetOffset(uint64_t offset);
		TypeBuilder& SetFunctionCanReturn(const Confidence<bool>& canReturn);
		TypeBuilder& SetPure(const Confidence<bool>& pure);
		TypeBuilder& SetParameters(const std::vector<FunctionParameter>& params);
		TypeBuilder& SetPointerBase(BNPointerBaseType baseType, int64_t baseOffset);

		std::set<BNPointerSuffix> GetPointerSuffix() const;
		std::string GetPointerSuffixString() const;
		std::vector<InstructionTextToken> GetPointerSuffixTokens(uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		TypeBuilder& AddPointerSuffix(BNPointerSuffix ps);
		TypeBuilder& SetPointerSuffix(const std::set<BNPointerSuffix>& suffix);

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
		    BNNameType ft = NoNameType,
		    const Confidence<bool>& pure = Confidence<bool>(false, 0));

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

	/*!
		\ingroup types
	*/
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

	/*!
		\ingroup types
	*/
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

	/*!
		\ingroup types
	*/
	struct StructureMember
	{
		Confidence<Ref<Type>> type;
		std::string name;
		uint64_t offset;
		BNMemberAccess access;
		BNMemberScope scope;
	};

	/*!
	    \ingroup types
	*/
	struct InheritedStructureMember
	{
		Ref<NamedTypeReference> base;
		uint64_t baseOffset;
		StructureMember member;
		size_t memberIndex;
	};

	/*!
	    \ingroup types
	*/
	struct BaseStructure
	{
		Ref<NamedTypeReference> type;
		uint64_t offset, width;

		BaseStructure(NamedTypeReference* type, uint64_t offset, uint64_t width);
		BaseStructure(Type* type, uint64_t offset);
	};

	/*! Structure is a class that wraps built structures and retrieves info about them.

		\see StructureBuilder is used for building structures
	 	\ingroup types
	*/
	class Structure : public CoreRefCountObject<BNStructure, BNNewStructureReference, BNFreeStructure>
	{
	  public:
		Structure(BNStructure* s);

		/*! Get a list of base structures. Offsets that are not defined by this structure will be filled
		    in by the fields of the base structure(s).

		    \return The list of base structures
		*/
		std::vector<BaseStructure> GetBaseStructures() const;

		/*! Get a list of Structure members, excluding those inherited from base structures

			\return The list of structure members
		*/
		std::vector<StructureMember> GetMembers() const;

		/*! Get a list of Structure members, including those inherited from base structures

		    \return The list of structure members
		*/
		std::vector<InheritedStructureMember> GetMembersIncludingInherited(const TypeContainer& types) const;

		/*! Get a structure member (including inherited members) at a certain offset

		 	\param view The relevant binary view
			\param offset Offset to check
			\param result Reference to a InheritedStructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberIncludingInheritedAtOffset(BinaryView* view, int64_t offset,
			InheritedStructureMember& result) const;

		/*! Get a structure member by name

			\param name Name of the member to retrieve
			\param result Reference to a StructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberByName(const std::string& name, StructureMember& result) const;

		/*! Get a structure member at a certain offset

			\param offset Offset to check
			\param result Reference to a StructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;

		/*! Get a structure member and its index at a certain offset

			\param offset Offset to check
			\param result Reference to a StructureMember to copy the result to
			\param idx Reference to a size_t to copy the index to
			\return Whether a member was found
		*/
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;

		/*! Get the structure width in bytes

			\return The structure width in bytes
		*/
		uint64_t GetWidth() const;

		/*! Get the structure pointer offset in bytes. Pointers to this structure will implicitly
		    have this offset subtracted from the pointer to arrive at the start of the structure.
		    Effectively, the pointer offset becomes the new start of the structure, and fields
		    before it are accessed using negative offsets from the pointer.

		    \return The structure pointer offset in bytes
		*/
		int64_t GetPointerOffset() const;

		/*! Get the structure alignment

			\return The structure alignment
		*/
		size_t GetAlignment() const;

		/*! Whether the structure is packed

			\return Whether the structure is packed
		*/
		bool IsPacked() const;

		/*! Whether the structure is a union

			\return Whether the structure is a union
		*/
		bool IsUnion() const;

		/*! Whether structure field references propagate the references to data variable field values

		    \return Whether the structure propagates data variable references
		*/
		bool PropagateDataVariableReferences() const;

		/*! Get the structure type

			\return The structure type
		*/
		BNStructureVariant GetStructureType() const;

		Ref<Structure> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Structure> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Structure> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);
	};

	/*! StructureBuilder is a convenience class used for building Structure Types.

	 	\b Example:
		\code{.cpp}
		StructureBuilder versionMinBuilder;
		versionMinBuilder.AddMember(Type::NamedType(bv, cmdTypeEnumQualName), "cmd");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "version");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "sdk");
		Ref<Structure> versionMinStruct = versionMinBuilder.Finalize();
		QualifiedName versionMinName = string("version_min");
		string versionMinTypeId = Type::GenerateAutoTypeId("macho", versionMinName);
		Ref<Type> versionMinType = Type::StructureType(versionMinStruct);
		QualifiedName versionMinQualName = bv->GetAnalysis()->DefineType(versionMinTypeId, versionMinName, versionMinType);
	 	\endcode

	 	\ingroup types
	*/
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

		/*! Complete the structure building process and return a Structure object

		    \return a built Structure object
		*/
		Ref<Structure> Finalize() const;

		std::vector<BaseStructure> GetBaseStructures() const;
		StructureBuilder& SetBaseStructures(const std::vector<BaseStructure>& bases);

		/*! GetMembers returns a list of structure members

		    \return vector of StructureMember objects
		*/
		std::vector<StructureMember> GetMembers() const;

		/*! GetMemberByName retrieves a structure member by name

		    \param name Name of the member (field)
		    \param result Reference to a StructureMember object the field will be passed to
		    \return Whether a StructureMember was successfully retrieved
		*/
		bool GetMemberByName(const std::string& name, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;
		uint64_t GetWidth() const;
		StructureBuilder& SetWidth(size_t width);
		int64_t GetPointerOffset() const;
		StructureBuilder& SetPointerOffset(int64_t offset);
		size_t GetAlignment() const;
		StructureBuilder& SetAlignment(size_t align);
		bool IsPacked() const;
		StructureBuilder& SetPacked(bool packed);
		bool IsUnion() const;
		bool PropagateDataVariableReferences() const;
		StructureBuilder& SetPropagateDataVariableReferences(bool value);

		/*! Set the structure type

		    \param type One of: ClassStructureType, StructStructureType, UnionStructureType
		    \return reference to this StructureBuilder
		*/
		StructureBuilder& SetStructureType(BNStructureVariant type);

		/*! Get the Structure Type

		    \return A BNStructureVariant
		    \retval ClassStructureType If this structure represents a class
		    \retval StructStructureType If this structure represents a structure
		    \retval UnionStructureType If this structure represents a union
		*/
		BNStructureVariant GetStructureType() const;

		/*! AddMember adds a member (field) to a structure

		    \param type Type of the Field
		    \param name Name of the field
		    \param access Optional, One of NoAccess, PrivateAccess, ProtectedAccess, PublicAccess
		    \param scope Optional, One of NoScope, StaticScope, VirtualScope, ThunkScope, FriendScope
		    \return reference to the Structure Builder
		*/
		StructureBuilder& AddMember(const Confidence<Ref<Type>>& type, const std::string& name,
		    BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);

		/*! AddMemberAtOffset adds a member at a specific offset within the struct

		    \param type Type of the Field
		    \param name Name of the field
		    \param offset Offset to add the member within the struct
		    \param overwriteExisting Whether to overwrite an existing member at that offset, Optional, default true
		    \param access One of NoAccess, PrivateAccess, ProtectedAccess, PublicAccess
		    \param scope One of NoScope, StaticScope, VirtualScope, ThunkScope, FriendScope
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& AddMemberAtOffset(const Confidence<Ref<Type>>& type, const std::string& name, uint64_t offset,
		    bool overwriteExisting = true, BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);

		/*! RemoveMember removes a member at a specified index

		    \param idx Index to remove
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& RemoveMember(size_t idx);

		/*! ReplaceMember replaces a member at an index

		    \param idx Index of the StructureMember to be replaced
		    \param type Type of the new Member
		    \param name Name of the new Member
		    \param overwriteExisting Whether to overwrite the existing member, default true
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& ReplaceMember(
		    size_t idx, const Confidence<Ref<Type>>& type, const std::string& name, bool overwriteExisting = true);
	};

	/*!
		\ingroup types
	*/
	struct EnumerationMember
	{
		std::string name;
		uint64_t value;
		bool isDefault;
	};

	/*!
		\ingroup types
	*/
	class Enumeration : public CoreRefCountObject<BNEnumeration, BNNewEnumerationReference, BNFreeEnumeration>
	{
	  public:
		Enumeration(BNEnumeration* e);

		std::vector<InstructionTextToken> GetTokensForValue(uint64_t value, size_t width, Ref<Type> type);
		std::vector<EnumerationMember> GetMembers() const;
	};

	/*! EnumerationBuilder is a convenience class used for building Enumeration Types.

	 	\b Example:
	 	\code{.cpp}
		EnumerationBuilder segFlagsTypeBuilder;
		segFlagsTypeBuilder.AddMemberWithValue("SG_HIGHVM", 0x1);
		segFlagsTypeBuilder.AddMemberWithValue("SG_FVMLIB", 0x2);
		segFlagsTypeBuilder.AddMemberWithValue("SG_NORELOC", 0x4);
		segFlagsTypeBuilder.AddMemberWithValue("SG_PROTECTED_VERSION_1", 0x8);
		Ref<Enumeration> segFlagsTypeEnum = segFlagsTypeBuilder.Finalize();
	 	\endcode

	 	\ingroup types
	*/
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

		/*! Finalize the building process and return the built Enumeration

			\return the Enumeration
		*/
		Ref<Enumeration> Finalize() const;

		/*! Get a list of members in this enum

			\return list of EnumerationMember
		*/
		std::vector<EnumerationMember> GetMembers() const;

		/*! Add a member to the enum.

			\note If there is already a member in the Enum, the value of newly added ones will be the value of the previously added one + 1

			\param name Name of the enum member
			\return A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& AddMember(const std::string& name);

		/*! Add a member to the enum with a set value

			\param name Name of the enum member
			\param value Value of th enum member
			\return A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& AddMemberWithValue(const std::string& name, uint64_t value);

		/*! Remove a member from the enum

			\param idx Index to remove
			\return  A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& RemoveMember(size_t idx);

		/*! Replace a member at an index

			\param idx Index to replace
			\param name Name of the new member
			\param value Value of the new member
			\return  A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& ReplaceMember(size_t idx, const std::string& name, uint64_t value);
	};
}
