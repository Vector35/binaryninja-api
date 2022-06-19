#pragma once
#include "core/binaryninja_defs.h"
#include "core/registervalue.h"
#include "core/qualifiedname.h"

extern "C" {
	struct BNArchitecture;
	struct BNArchitectureAndAddress;
	struct BNBinaryView;
	struct BNCallingConvention;
	struct BNEnumeration;
	struct BNEnumerationBuilder;
	struct BNHighLevelILFunction;
	struct BNIndirectBranchInfo;
	struct BNInstructionTextLine;
	struct BNMediumLevelILFunction;
	struct BNLowLevelILFunction;
	struct BNNamedTypeReference;
	struct BNNamedTypeReferenceBuilder;
	struct BNPlatform;
	struct BNStructure;
	struct BNStructureBuilder;
	struct BNType;
	struct BNTypeBuilder;

	enum BNTokenEscapingType
	{
		NoTokenEscapingType = 0,
		BackticksTokenEscapingType = 1,
	};

	enum BNMemberScope
	{
		NoScope,
		StaticScope,
		VirtualScope,
		ThunkScope,
		FriendScope
	};

	enum BNMemberAccess
	{
		NoAccess,
		PrivateAccess,
		ProtectedAccess,
		PublicAccess
	};

	struct BNStructureMember
	{
		BNType* type;
		char* name;
		uint64_t offset;
		uint8_t typeConfidence;
		BNMemberAccess access;
		BNMemberScope scope;
	};

	struct BNEnumerationMember
	{
		char* name;
		uint64_t value;
		bool isDefault;
	};


	enum BNStructureVariant
	{
		ClassStructureType = 0,
		StructStructureType = 1,
		UnionStructureType = 2
	};

	enum BNReferenceType
	{
		PointerReferenceType = 0,
		ReferenceReferenceType = 1,
		RValueReferenceType = 2,
		NoReference = 3
	};

	enum BNPointerSuffix
	{
		Ptr64Suffix,
		UnalignedSuffix,
		RestrictSuffix,
		ReferenceSuffix,
		LvalueSuffix
	};

	// Caution: these enumeration values are used a lookups into the static NameTypeStrings in the core
	// if you modify this you must also modify the string lookups as well
	enum BNNameType
	{
		NoNameType,
		ConstructorNameType,
		DestructorNameType,
		OperatorNewNameType,
		OperatorDeleteNameType,
		OperatorAssignNameType,
		OperatorRightShiftNameType,
		OperatorLeftShiftNameType,
		OperatorNotNameType,
		OperatorEqualNameType,
		OperatorNotEqualNameType,
		OperatorArrayNameType,
		OperatorArrowNameType,
		OperatorStarNameType,
		OperatorIncrementNameType,
		OperatorDecrementNameType,
		OperatorMinusNameType,
		OperatorPlusNameType,
		OperatorBitAndNameType,
		OperatorArrowStarNameType,
		OperatorDivideNameType,
		OperatorModulusNameType,
		OperatorLessThanNameType,
		OperatorLessThanEqualNameType,
		OperatorGreaterThanNameType,
		OperatorGreaterThanEqualNameType,
		OperatorCommaNameType,
		OperatorParenthesesNameType,
		OperatorTildeNameType,
		OperatorXorNameType,
		OperatorBitOrNameType,
		OperatorLogicalAndNameType,
		OperatorLogicalOrNameType,
		OperatorStarEqualNameType,
		OperatorPlusEqualNameType,
		OperatorMinusEqualNameType,
		OperatorDivideEqualNameType,
		OperatorModulusEqualNameType,
		OperatorRightShiftEqualNameType,
		OperatorLeftShiftEqualNameType,
		OperatorAndEqualNameType,
		OperatorOrEqualNameType,
		OperatorXorEqualNameType,
		VFTableNameType,
		VBTableNameType,
		VCallNameType,
		TypeofNameType,
		LocalStaticGuardNameType,
		StringNameType,
		VBaseDestructorNameType,
		VectorDeletingDestructorNameType,
		DefaultConstructorClosureNameType,
		ScalarDeletingDestructorNameType,
		VectorConstructorIteratorNameType,
		VectorDestructorIteratorNameType,
		VectorVBaseConstructorIteratorNameType,
		VirtualDisplacementMapNameType,
		EHVectorConstructorIteratorNameType,
		EHVectorDestructorIteratorNameType,
		EHVectorVBaseConstructorIteratorNameType,
		CopyConstructorClosureNameType,
		UDTReturningNameType,
		LocalVFTableNameType,
		LocalVFTableConstructorClosureNameType,
		OperatorNewArrayNameType,
		OperatorDeleteArrayNameType,
		PlacementDeleteClosureNameType,
		PlacementDeleteClosureArrayNameType,
		OperatorReturnTypeNameType,
		RttiTypeDescriptor,
		RttiBaseClassDescriptor,
		RttiBaseClassArray,
		RttiClassHierarchyDescriptor,
		RttiCompleteObjectLocator,
		OperatorUnaryMinusNameType,
		OperatorUnaryPlusNameType,
		OperatorUnaryBitAndNameType,
		OperatorUnaryStarNameType
	};

	struct BNCallingConventionWithConfidence
	{
		BNCallingConvention* convention;
		uint8_t confidence;
	};

	struct BNFunctionParameter
	{
		char* name;
		BNType* type;
		uint8_t typeConfidence;
		bool defaultLocation;
		BNVariable location;
	};


	enum BNTypeDefinitionLineType
	{
		TypedefLineType,
		StructDefinitionLineType,
		StructFieldLineType,
		StructDefinitionEndLineType,
		EnumDefinitionLineType,
		EnumMemberLineType,
		EnumDefinitionEndLineType,
		PaddingLineType,
		UndefinedXrefLineType
	};

	struct BNTypeDefinitionLine
	{
		BNTypeDefinitionLineType lineType;
		BNInstructionTextToken* tokens;
		size_t count;
		BNType* type;
		BNType* rootType;
		char* rootTypeName;
		uint64_t offset;
		size_t fieldIndex;
	};

	// Types
	BINARYNINJACOREAPI bool BNTypesEqual(BNType* a, BNType* b);
	BINARYNINJACOREAPI bool BNTypesNotEqual(BNType* a, BNType* b);
	BINARYNINJACOREAPI BNType* BNCreateVoidType(void);
	BINARYNINJACOREAPI BNType* BNCreateBoolType(void);
	BINARYNINJACOREAPI BNType* BNCreateIntegerType(size_t width, BNBoolWithConfidence* sign, const char* altName);
	BINARYNINJACOREAPI BNType* BNCreateFloatType(size_t width, const char* altName);
	BINARYNINJACOREAPI BNType* BNCreateWideCharType(size_t width, const char* altName);
	BINARYNINJACOREAPI BNType* BNCreateStructureType(BNStructure* s);
	BINARYNINJACOREAPI BNType* BNCreateEnumerationType(
	    BNArchitecture* arch, BNEnumeration* e, size_t width, BNBoolWithConfidence* isSigned);
	BINARYNINJACOREAPI BNType* BNCreateEnumerationTypeOfWidth(
	    BNEnumeration* e, size_t width, BNBoolWithConfidence* isSigned);
	BINARYNINJACOREAPI BNType* BNCreatePointerType(BNArchitecture* arch, const BNTypeWithConfidence* const type,
	    BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl, BNReferenceType refType);
	BINARYNINJACOREAPI BNType* BNCreatePointerTypeOfWidth(size_t width, const BNTypeWithConfidence* const type,
	    BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl, BNReferenceType refType);
	BINARYNINJACOREAPI BNType* BNCreateArrayType(const BNTypeWithConfidence* const type, uint64_t elem);
	BINARYNINJACOREAPI BNType* BNCreateFunctionType(BNTypeWithConfidence* returnValue, BNCallingConventionWithConfidence* callingConvention,
	    BNFunctionParameter* params, size_t paramCount, BNBoolWithConfidence* varArg,
	    BNBoolWithConfidence* canReturn, BNOffsetWithConfidence* stackAdjust,
	    uint32_t* regStackAdjustRegs, BNOffsetWithConfidence* regStackAdjustValues, size_t regStackAdjustCount,
	    BNRegisterSetWithConfidence* returnRegs, BNNameType ft);
	BINARYNINJACOREAPI BNType* BNNewTypeReference(BNType* type);
	BINARYNINJACOREAPI BNType* BNDuplicateType(BNType* type);
	BINARYNINJACOREAPI char* BNGetTypeAndName(BNType* type, BNQualifiedName* name, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI void BNFreeType(BNType* type);

	BINARYNINJACOREAPI BNTypeBuilder* BNCreateTypeBuilderFromType(BNType* type);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateVoidTypeBuilder(void);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateBoolTypeBuilder(void);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateIntegerTypeBuilder(
	    size_t width, BNBoolWithConfidence* sign, const char* altName);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateFloatTypeBuilder(size_t width, const char* altName);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateWideCharTypeBuilder(size_t width, const char* altName);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateStructureTypeBuilder(BNStructure* s);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateStructureTypeBuilderWithBuilder(BNStructureBuilder* s);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateEnumerationTypeBuilder(
	    BNArchitecture* arch, BNEnumeration* e, size_t width, BNBoolWithConfidence* isSigned);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateEnumerationTypeBuilderWithBuilder(
	    BNArchitecture* arch, BNEnumerationBuilder* e, size_t width, BNBoolWithConfidence* isSigned);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreatePointerTypeBuilder(BNArchitecture* arch,
	    const BNTypeWithConfidence* const type, BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl,
	    BNReferenceType refType);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreatePointerTypeBuilderOfWidth(size_t width,
	    const BNTypeWithConfidence* const type, BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl,
	    BNReferenceType refType);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateArrayTypeBuilder(const BNTypeWithConfidence* const type, uint64_t elem);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateFunctionTypeBuilder(BNTypeWithConfidence* returnValue, BNCallingConventionWithConfidence* callingConvention,
		BNFunctionParameter* params, size_t paramCount, BNBoolWithConfidence* varArg,
		BNBoolWithConfidence* canReturn, BNOffsetWithConfidence* stackAdjust,
		uint32_t* regStackAdjustRegs, BNOffsetWithConfidence* regStackAdjustValues, size_t regStackAdjustCount,
		BNRegisterSetWithConfidence* returnRegs, BNNameType ft);
	BINARYNINJACOREAPI BNType* BNFinalizeTypeBuilder(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNTypeBuilder* BNDuplicateTypeBuilder(BNTypeBuilder* type);
	BINARYNINJACOREAPI char* BNGetTypeBuilderTypeAndName(BNTypeBuilder* type, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNFreeTypeBuilder(BNTypeBuilder* type);

	BINARYNINJACOREAPI BNQualifiedName BNTypeGetTypeName(BNType* nt);
	BINARYNINJACOREAPI BNTypeClass BNGetTypeClass(BNType* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeWidth(BNType* type);
	BINARYNINJACOREAPI size_t BNGetTypeAlignment(BNType* type);
	BINARYNINJACOREAPI BNIntegerDisplayType BNGetIntegerTypeDisplayType(BNType* type);
	BINARYNINJACOREAPI void BNSetIntegerTypeDisplayType(BNTypeBuilder* type, BNIntegerDisplayType displayType);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeSigned(BNType* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeConst(BNType* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeVolatile(BNType* type);
	BINARYNINJACOREAPI bool BNIsTypeFloatingPoint(BNType* type);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetChildType(BNType* type);
	BINARYNINJACOREAPI BNCallingConventionWithConfidence BNGetTypeCallingConvention(BNType* type);
	BINARYNINJACOREAPI BNFunctionParameter* BNGetTypeParameters(BNType* type, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeParameterList(BNFunctionParameter* types, size_t count);
	BINARYNINJACOREAPI BNBoolWithConfidence BNTypeHasVariableArguments(BNType* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNFunctionTypeCanReturn(BNType* type);
	BINARYNINJACOREAPI BNStructure* BNGetTypeStructure(BNType* type);
	BINARYNINJACOREAPI BNEnumeration* BNGetTypeEnumeration(BNType* type);
	BINARYNINJACOREAPI BNNamedTypeReference* BNGetTypeNamedTypeReference(BNType* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeElementCount(BNType* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeOffset(BNType* type);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetTypeStackAdjustment(BNType* type);
	BINARYNINJACOREAPI BNQualifiedName BNTypeGetStructureName(BNType* type);
	BINARYNINJACOREAPI BNNamedTypeReference* BNGetRegisteredTypeName(BNType* type);
	BINARYNINJACOREAPI BNReferenceType BNTypeGetReferenceType(BNType* type);
	BINARYNINJACOREAPI char* BNGetTypeAlternateName(BNType* type);
	BINARYNINJACOREAPI uint32_t BNTypeGetSystemCallNumber(BNType* type);
	BINARYNINJACOREAPI bool BNTypeIsSystemCall(BNType* type);

	BINARYNINJACOREAPI char* BNGetTypeString(BNType* type, BNPlatform* platform, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI char* BNGetTypeStringBeforeName(BNType* type, BNPlatform* platform, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI char* BNGetTypeStringAfterName(BNType* type, BNPlatform* platform, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeTokens(
	    BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNTokenEscapingType escaping, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeTokensBeforeName(
	    BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNTokenEscapingType escaping, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeTokensAfterName(
	    BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNTokenEscapingType escaping, size_t* count);

	BINARYNINJACOREAPI BNType* BNTypeWithReplacedStructure(BNType* type, BNStructure* from, BNStructure* to);
	BINARYNINJACOREAPI BNType* BNTypeWithReplacedEnumeration(BNType* type, BNEnumeration* from, BNEnumeration* to);
	BINARYNINJACOREAPI BNType* BNTypeWithReplacedNamedTypeReference(
	    BNType* type, BNNamedTypeReference* from, BNNamedTypeReference* to);

	BINARYNINJACOREAPI bool BNAddTypeMemberTokens(BNType* type, BNBinaryView* data, BNInstructionTextToken** tokens,
	    size_t* tokenCount, int64_t offset, char*** nameList, size_t* nameCount, size_t size, bool indirect);
	BINARYNINJACOREAPI BNTypeDefinitionLine* BNGetTypeLines(BNType* type, BNBinaryView* data, const char* name, int lineWidth, bool collapsed, BNTokenEscapingType escaping, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeDefinitionLineList(BNTypeDefinitionLine* list, size_t count);

	BINARYNINJACOREAPI BNQualifiedName BNTypeBuilderGetTypeName(BNTypeBuilder* nt);
	BINARYNINJACOREAPI void BNTypeBuilderSetTypeName(BNTypeBuilder* type, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNTypeBuilderSetAlternateName(BNTypeBuilder* type, const char* name);
	BINARYNINJACOREAPI BNTypeClass BNGetTypeBuilderClass(BNTypeBuilder* type);
	BINARYNINJACOREAPI void BNTypeBuilderSetSystemCallNumber(BNTypeBuilder* type, bool v, uint32_t n);
	BINARYNINJACOREAPI uint64_t BNGetTypeBuilderWidth(BNTypeBuilder* type);
	BINARYNINJACOREAPI size_t BNGetTypeBuilderAlignment(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeBuilderSigned(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeBuilderConst(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeBuilderVolatile(BNTypeBuilder* type);
	BINARYNINJACOREAPI bool BNIsTypeBuilderFloatingPoint(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetTypeBuilderChildType(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNCallingConventionWithConfidence BNGetTypeBuilderCallingConvention(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNFunctionParameter* BNGetTypeBuilderParameters(BNTypeBuilder* type, size_t* count);
	BINARYNINJACOREAPI BNBoolWithConfidence BNTypeBuilderHasVariableArguments(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNBoolWithConfidence BNFunctionTypeBuilderCanReturn(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNStructure* BNGetTypeBuilderStructure(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNEnumeration* BNGetTypeBuilderEnumeration(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNNamedTypeReference* BNGetTypeBuilderNamedTypeReference(BNTypeBuilder* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeBuilderElementCount(BNTypeBuilder* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeBuilderOffset(BNTypeBuilder* type);
	BINARYNINJACOREAPI void BNSetFunctionTypeBuilderCanReturn(BNTypeBuilder* type, BNBoolWithConfidence* canReturn);
	BINARYNINJACOREAPI void BNSetFunctionTypeBuilderParameters(
	    BNTypeBuilder* type, BNFunctionParameter* params, size_t paramCount);
	BINARYNINJACOREAPI void BNTypeBuilderSetConst(BNTypeBuilder* type, BNBoolWithConfidence* cnst);
	BINARYNINJACOREAPI void BNTypeBuilderSetVolatile(BNTypeBuilder* type, BNBoolWithConfidence* vltl);
	BINARYNINJACOREAPI void BNTypeBuilderSetSigned(BNTypeBuilder* type, BNBoolWithConfidence* sign);
	BINARYNINJACOREAPI void BNTypeBuilderSetChildType(BNTypeBuilder* type, BNTypeWithConfidence* child);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetTypeBuilderStackAdjustment(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNQualifiedName BNTypeBuilderGetStructureName(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNReferenceType BNTypeBuilderGetReferenceType(BNTypeBuilder* type);
	BINARYNINJACOREAPI char* BNGetTypeBuilderAlternateName(BNTypeBuilder* type);
	BINARYNINJACOREAPI bool BNTypeBuilderIsSystemCall(BNTypeBuilder* type);
	BINARYNINJACOREAPI uint32_t BNTypeBuilderGetSystemCallNumber(BNTypeBuilder* type);
	BINARYNINJACOREAPI void BNTypeBuilderSetStackAdjustment(BNTypeBuilder* type, BNOffsetWithConfidence* adjust);

	BINARYNINJACOREAPI char* BNGetTypeBuilderString(BNTypeBuilder* type, BNPlatform* platform);
	BINARYNINJACOREAPI char* BNGetTypeBuilderStringBeforeName(BNTypeBuilder* type, BNPlatform* platform);
	BINARYNINJACOREAPI char* BNGetTypeBuilderStringAfterName(BNTypeBuilder* type, BNPlatform* platform);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeBuilderTokens(
	    BNTypeBuilder* type, BNPlatform* platform, uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeBuilderTokensBeforeName(
	    BNTypeBuilder* type, BNPlatform* platform, uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeBuilderTokensAfterName(
	    BNTypeBuilder* type, BNPlatform* platform, uint8_t baseConfidence, size_t* count);

	BINARYNINJACOREAPI BNType* BNCreateNamedTypeReference(
	    BNNamedTypeReference* nt, size_t width, size_t align, BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl);
	BINARYNINJACOREAPI BNType* BNCreateNamedTypeReferenceFromTypeAndId(
	    const char* id, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI BNType* BNCreateNamedTypeReferenceFromType(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateNamedTypeReferenceBuilder(
	    BNNamedTypeReference* nt, size_t width, size_t align, BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateNamedTypeReferenceBuilderWithBuilder(BNNamedTypeReferenceBuilder* nt,
	    size_t width, size_t align, BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateNamedTypeReferenceBuilderFromTypeAndId(
	    const char* id, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI BNTypeBuilder* BNCreateNamedTypeReferenceBuilderFromType(
	    BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNNamedTypeReference* BNCreateNamedType(
	    BNNamedTypeReferenceClass cls, const char* id, BNQualifiedName* name);
	BINARYNINJACOREAPI BNNamedTypeReferenceClass BNGetTypeReferenceClass(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI char* BNGetTypeReferenceId(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI BNQualifiedName BNGetTypeReferenceName(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI void BNFreeQualifiedName(BNQualifiedName* name);
	BINARYNINJACOREAPI void BNFreeNamedTypeReference(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI BNNamedTypeReference* BNNewNamedTypeReference(BNNamedTypeReference* nt);

	BINARYNINJACOREAPI BNNamedTypeReferenceBuilder* BNCreateNamedTypeBuilder(
	    BNNamedTypeReferenceClass cls, const char* id, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNFreeNamedTypeReferenceBuilder(BNNamedTypeReferenceBuilder* s);
	BINARYNINJACOREAPI void BNSetNamedTypeReferenceBuilderTypeClass(
	    BNNamedTypeReferenceBuilder* s, BNNamedTypeReferenceClass type);
	BINARYNINJACOREAPI void BNSetNamedTypeReferenceBuilderTypeId(BNNamedTypeReferenceBuilder* s, const char* id);
	BINARYNINJACOREAPI void BNSetNamedTypeReferenceBuilderName(BNNamedTypeReferenceBuilder* s, BNQualifiedName* name);
	BINARYNINJACOREAPI BNNamedTypeReference* BNFinalizeNamedTypeReferenceBuilder(BNNamedTypeReferenceBuilder* s);
	BINARYNINJACOREAPI BNNamedTypeReferenceClass BNGetTypeReferenceBuilderClass(BNNamedTypeReferenceBuilder* nt);
	BINARYNINJACOREAPI char* BNGetTypeReferenceBuilderId(BNNamedTypeReferenceBuilder* nt);
	BINARYNINJACOREAPI BNQualifiedName BNGetTypeReferenceBuilderName(BNNamedTypeReferenceBuilder* nt);

	BINARYNINJACOREAPI BNStructureBuilder* BNCreateStructureBuilder(void);
	BINARYNINJACOREAPI BNStructureBuilder* BNCreateStructureBuilderWithOptions(BNStructureVariant type, bool packed);
	BINARYNINJACOREAPI BNStructureBuilder* BNCreateStructureBuilderFromStructure(BNStructure* s);
	BINARYNINJACOREAPI BNStructureBuilder* BNDuplicateStructureBuilder(BNStructureBuilder* s);
	BINARYNINJACOREAPI BNStructure* BNFinalizeStructureBuilder(BNStructureBuilder* s);
	BINARYNINJACOREAPI BNStructure* BNNewStructureReference(BNStructure* s);
	BINARYNINJACOREAPI void BNFreeStructure(BNStructure* s);
	BINARYNINJACOREAPI void BNFreeStructureBuilder(BNStructureBuilder* s);

	BINARYNINJACOREAPI BNStructureMember* BNGetStructureMemberByName(BNStructure* s, const char* name);
	BINARYNINJACOREAPI BNStructureMember* BNGetStructureMemberAtOffset(BNStructure* s, int64_t offset, size_t* idx);
	BINARYNINJACOREAPI void BNFreeStructureMember(BNStructureMember* s);
	BINARYNINJACOREAPI BNStructureMember* BNGetStructureMembers(BNStructure* s, size_t* count);
	BINARYNINJACOREAPI void BNFreeStructureMemberList(BNStructureMember* members, size_t count);
	BINARYNINJACOREAPI uint64_t BNGetStructureWidth(BNStructure* s);
	BINARYNINJACOREAPI size_t BNGetStructureAlignment(BNStructure* s);
	BINARYNINJACOREAPI bool BNIsStructurePacked(BNStructure* s);
	BINARYNINJACOREAPI bool BNIsStructureUnion(BNStructure* s);
	BINARYNINJACOREAPI BNStructureVariant BNGetStructureType(BNStructure* s);

	BINARYNINJACOREAPI BNStructure* BNStructureWithReplacedStructure(
	    BNStructure* s, BNStructure* from, BNStructure* to);
	BINARYNINJACOREAPI BNStructure* BNStructureWithReplacedEnumeration(
	    BNStructure* s, BNEnumeration* from, BNEnumeration* to);
	BINARYNINJACOREAPI BNStructure* BNStructureWithReplacedNamedTypeReference(
	    BNStructure* s, BNNamedTypeReference* from, BNNamedTypeReference* to);

	BINARYNINJACOREAPI BNStructureMember* BNGetStructureBuilderMemberByName(BNStructureBuilder* s, const char* name);
	BINARYNINJACOREAPI BNStructureMember* BNGetStructureBuilderMemberAtOffset(
	    BNStructureBuilder* s, int64_t offset, size_t* idx);
	BINARYNINJACOREAPI BNStructureMember* BNGetStructureBuilderMembers(BNStructureBuilder* s, size_t* count);
	BINARYNINJACOREAPI uint64_t BNGetStructureBuilderWidth(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderWidth(BNStructureBuilder* s, uint64_t width);
	BINARYNINJACOREAPI size_t BNGetStructureBuilderAlignment(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderAlignment(BNStructureBuilder* s, size_t align);
	BINARYNINJACOREAPI bool BNIsStructureBuilderPacked(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderPacked(BNStructureBuilder* s, bool packed);
	BINARYNINJACOREAPI bool BNIsStructureBuilderUnion(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderType(BNStructureBuilder* s, BNStructureVariant type);
	BINARYNINJACOREAPI BNStructureVariant BNGetStructureBuilderType(BNStructureBuilder* s);

	BINARYNINJACOREAPI void BNAddStructureBuilderMember(BNStructureBuilder* s, const BNTypeWithConfidence* const type,
	    const char* name, BNMemberAccess access, BNMemberScope scope);
	BINARYNINJACOREAPI void BNAddStructureBuilderMemberAtOffset(BNStructureBuilder* s,
	    const BNTypeWithConfidence* const type, const char* name, uint64_t offset, bool overwriteExisting,
	    BNMemberAccess access, BNMemberScope scope);
	BINARYNINJACOREAPI void BNRemoveStructureBuilderMember(BNStructureBuilder* s, size_t idx);
	BINARYNINJACOREAPI void BNReplaceStructureBuilderMember(BNStructureBuilder* s, size_t idx,
	    const BNTypeWithConfidence* const type, const char* name, bool overwriteExisting);

	BINARYNINJACOREAPI BNEnumerationBuilder* BNCreateEnumerationBuilder(void);
	BINARYNINJACOREAPI BNEnumerationBuilder* BNCreateEnumerationBuilderFromEnumeration(BNEnumeration* e);
	BINARYNINJACOREAPI BNEnumerationBuilder* BNDuplicateEnumerationBuilder(BNEnumerationBuilder* e);
	BINARYNINJACOREAPI BNEnumeration* BNFinalizeEnumerationBuilder(BNEnumerationBuilder* e);
	BINARYNINJACOREAPI BNEnumeration* BNNewEnumerationReference(BNEnumeration* e);
	BINARYNINJACOREAPI void BNFreeEnumeration(BNEnumeration* e);
	BINARYNINJACOREAPI void BNFreeEnumerationBuilder(BNEnumerationBuilder* e);

	BINARYNINJACOREAPI BNEnumerationMember* BNGetEnumerationMembers(BNEnumeration* e, size_t* count);
	BINARYNINJACOREAPI void BNFreeEnumerationMemberList(BNEnumerationMember* members, size_t count);

	BINARYNINJACOREAPI BNEnumerationMember* BNGetEnumerationBuilderMembers(BNEnumerationBuilder* e, size_t* count);

	BINARYNINJACOREAPI void BNAddEnumerationBuilderMember(BNEnumerationBuilder* e, const char* name);
	BINARYNINJACOREAPI void BNAddEnumerationBuilderMemberWithValue(
	    BNEnumerationBuilder* e, const char* name, uint64_t value);
	BINARYNINJACOREAPI void BNRemoveEnumerationBuilderMember(BNEnumerationBuilder* e, size_t idx);
	BINARYNINJACOREAPI void BNReplaceEnumerationBuilderMember(
	    BNEnumerationBuilder* e, size_t idx, const char* name, uint64_t value);

	BINARYNINJACOREAPI BNStructure* BNCreateStructureFromOffsetAccess(
	    BNBinaryView* view, BNQualifiedName* name, bool* newMember);
	BINARYNINJACOREAPI BNTypeWithConfidence BNCreateStructureMemberFromAccess(
	    BNBinaryView* view, BNQualifiedName* name, uint64_t offset);

	BINARYNINJACOREAPI char* BNEscapeTypeName(const char* name, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI char* BNUnescapeTypeName(const char* name, BNTokenEscapingType escaping);

	BINARYNINJACOREAPI char* BNGenerateAutoTypeId(const char* source, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGenerateAutoDemangledTypeId(BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoDemangledTypeIdSource(void);
	BINARYNINJACOREAPI char* BNGenerateAutoDebugTypeId(BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoDebugTypeIdSource(void);

}