// Copyright (c) 2015-2017 Vector 35 LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#ifndef __BINARYNINJACORE_H__
#define __BINARYNINJACORE_H__

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __GNUC__
#  ifdef BINARYNINJACORE_LIBRARY
#    define BINARYNINJACOREAPI __attribute__((visibility("default")))
#  else
#    define BINARYNINJACOREAPI
#  endif
#  define BINARYNINJAPLUGIN __attribute__((visibility("default")))
#else
#ifdef _MSC_VER
#  ifdef BINARYNINJACORE_LIBRARY
#    define BINARYNINJACOREAPI __declspec(dllexport)
#  else
#    define BINARYNINJACOREAPI
#  endif
#  define BINARYNINJAPLUGIN __declspec(dllexport)
#else
#define BINARYNINJACOREAPI
#endif
#endif

#ifdef WIN32
#define PATH_SEP "\\"
#else
#define PATH_SEP "/"
#endif

#define BN_MAX_INSTRUCTION_LENGTH   256
#define BN_DEFAULT_NSTRUCTION_LENGTH 16
#define BN_DEFAULT_OPCODE_DISPLAY   8
#define BN_MAX_INSTRUCTION_BRANCHES 3

#define BN_MAX_STORED_DATA_LENGTH   0x3fffffff
#define BN_NULL_ID                  -1

#define LLIL_TEMP(n)                (0x80000000 | (uint32_t)(n))
#define LLIL_REG_IS_TEMP(n)         (((n) & 0x80000000) != 0)
#define LLIL_GET_TEMP_REG_INDEX(n)  ((n) & 0x7fffffff)
#define BN_INVALID_REGISTER         0xffffffff

#define BN_INVALID_OPERAND          0xffffffff

#define BN_INVALID_EXPR             ((size_t)-1)

#define BN_DEFAULT_MIN_STRING_LENGTH 4
#define BN_MAX_STRING_LENGTH         128

#define LLVM_SVCS_CB_NOTE 0
#define LLVM_SVCS_CB_WARNING 1
#define LLVM_SVCS_CB_ERROR 2

#define LLVM_SVCS_DIALECT_UNSPEC 0
#define LLVM_SVCS_DIALECT_ATT 1
#define LLVM_SVCS_DIALECT_INTEL 2

#define LLVM_SVCS_CM_DEFAULT 0
#define LLVM_SVCS_CM_SMALL 1
#define LLVM_SVCS_CM_KERNEL 2
#define LLVM_SVCS_CM_MEDIUM 3
#define LLVM_SVCS_CM_LARGE 4

#define LLVM_SVCS_RM_STATIC 0
#define LLVM_SVCS_RM_PIC 1
#define LLVM_SVCS_RM_DYNAMIC_NO_PIC 2

#define BN_MAX_VARIABLE_OFFSET       0x7fffffffffLL
#define BN_MAX_VARIABLE_INDEX        0xfffff

#define BN_FULL_CONFIDENCE      255
#define BN_MINIMUM_CONFIDENCE   1
#define BN_HEURISTIC_CONFIDENCE 192

#ifdef __cplusplus
extern "C"
{
#endif
	enum BNPluginLoadOrder
	{
		EarlyPluginLoadOrder,
		NormalPluginLoadOrder,
		LatePluginLoadOrder
	};

	typedef bool (*BNCorePluginInitFunction)(void);
	typedef void (*BNCorePluginDependencyFunction)(void);

	struct BNDataBuffer;
	struct BNBinaryView;
	struct BNBinaryViewType;
	struct BNBinaryReader;
	struct BNBinaryWriter;
	struct BNFileMetadata;
	struct BNTransform;
	struct BNArchitecture;
	struct BNFunction;
	struct BNBasicBlock;
	struct BNDownloadProvider;
	struct BNDownloadInstance;
	struct BNFunctionGraph;
	struct BNFunctionGraphBlock;
	struct BNSymbol;
	struct BNTemporaryFile;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;
	struct BNType;
	struct BNStructure;
	struct BNNamedTypeReference;
	struct BNEnumeration;
	struct BNCallingConvention;
	struct BNPlatform;
	struct BNAnalysisCompletionEvent;
	struct BNDisassemblySettings;
	struct BNScriptingProvider;
	struct BNScriptingInstance;
	struct BNMainThreadAction;
	struct BNBackgroundTask;
	struct BNRepository;
	struct BNRepoPlugin;
	struct BNRepositoryManager;
	struct BNMetadata;

	typedef bool (*BNLoadPluginCallback)(const char* repoPath, const char* pluginPath, void* ctx);

	//! Console log levels
	enum BNLogLevel
	{
		DebugLog = 0,   //! Debug logging level, most verbose logging level
		InfoLog = 1,    //! Information logging level, default logging level
		WarningLog = 2, //! Warning logging level, messages show with warning icon in the UI
		ErrorLog = 3,   //! Error logging level, messages show with error icon in the UI
		AlertLog = 4    //! Alert logging level, messages are displayed with popup message box in the UI
	};

	enum BNEndianness
	{
		LittleEndian = 0,
		BigEndian = 1
	};

	enum BNModificationStatus
	{
		Original = 0,
		Changed = 1,
		Inserted = 2
	};

	enum BNTransformType
	{
		BinaryCodecTransform = 0, // Two-way transform of data, binary input/output
		TextCodecTransform = 1, // Two-way transform of data, encoder output is text
		UnicodeCodecTransform = 2, // Two-way transform of data, encoder output is Unicode string (as UTF8)
		DecodeTransform = 3, // One-way decode only
		BinaryEncodeTransform = 4, // One-way encode only, output is binary
		TextEncodeTransform = 5, // One-way encode only, output is text
		EncryptTransform = 6, // Two-way encryption
		InvertingTransform = 7, // Transform that can be undone by performing twice
		HashTransform = 8 // Hash function
	};

	enum BNBranchType
	{
		UnconditionalBranch = 0,
		FalseBranch = 1,
		TrueBranch = 2,
		CallDestination = 3,
		FunctionReturn = 4,
		SystemCall = 5,
		IndirectBranch = 6,
		UnresolvedBranch = 127
	};

	enum BNInstructionTextTokenType
	{
		TextToken = 0,
		InstructionToken = 1,
		OperandSeparatorToken = 2,
		RegisterToken = 3,
		IntegerToken = 4,
		PossibleAddressToken = 5,
		BeginMemoryOperandToken = 6,
		EndMemoryOperandToken = 7,
		FloatingPointToken = 8,
		AnnotationToken = 9,
		CodeRelativeAddressToken = 10,
		ArgumentNameToken = 11,
		HexDumpByteValueToken = 12,
		HexDumpSkippedByteToken = 13,
		HexDumpInvalidByteToken = 14,
		HexDumpTextToken = 15,
		OpcodeToken = 16,
		StringToken = 17,
		CharacterConstantToken = 18,
		KeywordToken = 19,
		TypeNameToken = 20,
		FieldNameToken = 21,

		// The following are output by the analysis system automatically, these should
		// not be used directly by the architecture plugins
		CodeSymbolToken = 64,
		DataSymbolToken = 65,
		LocalVariableToken = 66,
		ImportToken = 67,
		AddressDisplayToken = 68,
		IndirectImportToken = 69
	};

	enum BNInstructionTextTokenContext
	{
		NoTokenContext = 0,
		LocalVariableTokenContext = 1,
		DataVariableTokenContext = 2,
		FunctionReturnTokenContext = 3
	};

	enum BNLinearDisassemblyLineType
	{
		BlankLineType,
		CodeDisassemblyLineType,
		DataVariableLineType,
		HexDumpLineType,
		FunctionHeaderLineType,
		FunctionHeaderStartLineType,
		FunctionHeaderEndLineType,
		FunctionContinuationLineType,
		LocalVariableLineType,
		LocalVariableListEndLineType,
		FunctionEndLineType,
		NoteStartLineType,
		NoteLineType,
		NoteEndLineType,
		SectionStartLineType,
		SectionEndLineType,
		SectionSeparatorLineType,
		NonContiguousSeparatorLineType
	};

	enum BNSymbolType
	{
		FunctionSymbol = 0,
		ImportAddressSymbol = 1,
		ImportedFunctionSymbol = 2,
		DataSymbol = 3,
		ImportedDataSymbol = 4
	};

	enum BNActionType
	{
		TemporaryAction = 0,
		DataModificationAction = 1,
		AnalysisAction = 2,
		DataModificationAndAnalysisAction = 3
	};

	enum BNLowLevelILOperation
	{
		LLIL_NOP,
		LLIL_SET_REG, // Not valid in SSA form (see LLIL_SET_REG_SSA)
		LLIL_SET_REG_SPLIT, // Not valid in SSA form (see LLIL_SET_REG_SPLIT_SSA)
		LLIL_SET_FLAG, // Not valid in SSA form (see LLIL_SET_FLAG_SSA)
		LLIL_SET_REG_STACK_REL, // Not valid in SSA form (see LLIL_SET_REG_STACK_REL_SSA)
		LLIL_REG_STACK_PUSH, // Not valid in SSA form (expanded)
		LLIL_LOAD, // Not valid in SSA form (see LLIL_LOAD_SSA)
		LLIL_STORE, // Not valid in SSA form (see LLIL_STORE_SSA)
		LLIL_PUSH, // Not valid in SSA form (expanded)
		LLIL_POP, // Not valid in SSA form (expanded)
		LLIL_REG, // Not valid in SSA form (see LLIL_REG_SSA)
		LLIL_REG_SPLIT, // Not valid in SSA form (see LLIL_REG_SPLIT_SSA)
		LLIL_REG_STACK_REL, // Not valid in SSA form (see LLIL_REG_STACK_REL_SSA)
		LLIL_REG_STACK_POP, // Not valid in SSA form (expanded)
		LLIL_REG_STACK_FREE_REG, // Not valid in SSA form (see LLIL_REG_STACK_FREE_REL_SSA, LLIL_REG_STACK_FREE_ABS_SSA)
		LLIL_REG_STACK_FREE_REL, // Not valid in SSA from (see LLIL_REG_STACK_FREE_REL_SSA)
		LLIL_CONST,
		LLIL_CONST_PTR,
		LLIL_FLOAT_CONST,
		LLIL_FLAG, // Not valid in SSA form (see LLIL_FLAG_SSA)
		LLIL_FLAG_BIT, // Not valid in SSA form (see LLIL_FLAG_BIT_SSA)
		LLIL_ADD,
		LLIL_ADC,
		LLIL_SUB,
		LLIL_SBB,
		LLIL_AND,
		LLIL_OR,
		LLIL_XOR,
		LLIL_LSL,
		LLIL_LSR,
		LLIL_ASR,
		LLIL_ROL,
		LLIL_RLC,
		LLIL_ROR,
		LLIL_RRC,
		LLIL_MUL,
		LLIL_MULU_DP,
		LLIL_MULS_DP,
		LLIL_DIVU,
		LLIL_DIVU_DP,
		LLIL_DIVS,
		LLIL_DIVS_DP,
		LLIL_MODU,
		LLIL_MODU_DP,
		LLIL_MODS,
		LLIL_MODS_DP,
		LLIL_NEG,
		LLIL_NOT,
		LLIL_SX,
		LLIL_ZX,
		LLIL_LOW_PART,
		LLIL_JUMP,
		LLIL_JUMP_TO,
		LLIL_CALL,
		LLIL_CALL_STACK_ADJUST,
		LLIL_TAILCALL,
		LLIL_RET,
		LLIL_NORET,
		LLIL_IF,
		LLIL_GOTO,
		LLIL_FLAG_COND, // Valid only in Lifted IL
		LLIL_FLAG_GROUP, // Valid only in Lifted IL
		LLIL_CMP_E,
		LLIL_CMP_NE,
		LLIL_CMP_SLT,
		LLIL_CMP_ULT,
		LLIL_CMP_SLE,
		LLIL_CMP_ULE,
		LLIL_CMP_SGE,
		LLIL_CMP_UGE,
		LLIL_CMP_SGT,
		LLIL_CMP_UGT,
		LLIL_TEST_BIT,
		LLIL_BOOL_TO_INT,
		LLIL_ADD_OVERFLOW,
		LLIL_SYSCALL,
		LLIL_BP,
		LLIL_TRAP,
		LLIL_INTRINSIC,
		LLIL_UNDEF,
		LLIL_UNIMPL,
		LLIL_UNIMPL_MEM,

		// Floating point
		LLIL_FADD,
		LLIL_FSUB,
		LLIL_FMUL,
		LLIL_FDIV,
		LLIL_FSQRT,
		LLIL_FNEG,
		LLIL_FABS,
		LLIL_FLOAT_TO_INT,
		LLIL_INT_TO_FLOAT,
		LLIL_FLOAT_CONV,
		LLIL_ROUND_TO_INT,
		LLIL_FLOOR,
		LLIL_CEIL,
		LLIL_FTRUNC,
		LLIL_FCMP_E,
		LLIL_FCMP_NE,
		LLIL_FCMP_LT,
		LLIL_FCMP_LE,
		LLIL_FCMP_GE,
		LLIL_FCMP_GT,
		LLIL_FCMP_O,
		LLIL_FCMP_UO,

		// The following instructions are only used in SSA form
		LLIL_SET_REG_SSA,
		LLIL_SET_REG_SSA_PARTIAL,
		LLIL_SET_REG_SPLIT_SSA,
		LLIL_SET_REG_STACK_REL_SSA,
		LLIL_SET_REG_STACK_ABS_SSA,
		LLIL_REG_SPLIT_DEST_SSA, // Only valid within an LLIL_SET_REG_SPLIT_SSA instruction
		LLIL_REG_STACK_DEST_SSA, // Only valid within LLIL_SET_REG_STACK_REL_SSA or LLIL_SET_REG_STACK_ABS_SSA
		LLIL_REG_SSA,
		LLIL_REG_SSA_PARTIAL,
		LLIL_REG_SPLIT_SSA,
		LLIL_REG_STACK_REL_SSA,
		LLIL_REG_STACK_ABS_SSA,
		LLIL_REG_STACK_FREE_REL_SSA,
		LLIL_REG_STACK_FREE_ABS_SSA,
		LLIL_SET_FLAG_SSA,
		LLIL_FLAG_SSA,
		LLIL_FLAG_BIT_SSA,
		LLIL_CALL_SSA,
		LLIL_SYSCALL_SSA,
		LLIL_TAILCALL_SSA,
		LLIL_CALL_PARAM, // Only valid within the LLIL_CALL_SSA, LLIL_SYSCALL_SSA, LLIL_INTRINSIC, LLIL_INTRINSIC_SSA instructions
		LLIL_CALL_STACK_SSA, // Only valid within the LLIL_CALL_SSA or LLIL_SYSCALL_SSA instructions
		LLIL_CALL_OUTPUT_SSA, // Only valid within the LLIL_CALL_SSA or LLIL_SYSCALL_SSA instructions
		LLIL_LOAD_SSA,
		LLIL_STORE_SSA,
		LLIL_INTRINSIC_SSA,
		LLIL_REG_PHI,
		LLIL_REG_STACK_PHI,
		LLIL_FLAG_PHI,
		LLIL_MEM_PHI
	};

	enum BNLowLevelILFlagCondition
	{
		LLFC_E,
		LLFC_NE,
		LLFC_SLT,
		LLFC_ULT,
		LLFC_SLE,
		LLFC_ULE,
		LLFC_SGE,
		LLFC_UGE,
		LLFC_SGT,
		LLFC_UGT,
		LLFC_NEG,
		LLFC_POS,
		LLFC_O,
		LLFC_NO,
		LLFC_FE,
		LLFC_FNE,
		LLFC_FLT,
		LLFC_FLE,
		LLFC_FGE,
		LLFC_FGT,
		LLFC_FO,
		LLFC_FUO
	};

	enum BNFlagRole
	{
		SpecialFlagRole = 0,
		ZeroFlagRole = 1,
		PositiveSignFlagRole = 2,
		NegativeSignFlagRole = 3,
		CarryFlagRole = 4,
		OverflowFlagRole = 5,
		HalfCarryFlagRole = 6,
		EvenParityFlagRole = 7,
		OddParityFlagRole = 8,
		OrderedFlagRole = 9,
		UnorderedFlagRole = 10
	};

	enum BNFunctionGraphType
	{
		NormalFunctionGraph = 0,
		LowLevelILFunctionGraph = 1,
		LiftedILFunctionGraph = 2,
		LowLevelILSSAFormFunctionGraph = 3,
		MediumLevelILFunctionGraph = 4,
		MediumLevelILSSAFormFunctionGraph = 5,
		MappedMediumLevelILFunctionGraph = 6,
		MappedMediumLevelILSSAFormFunctionGraph = 7
	};

	enum BNDisassemblyOption
	{
		ShowAddress = 0,
		ShowOpcode = 1,
		ExpandLongOpcode = 2,
		ShowVariablesAtTopOfGraph = 3,
		ShowVariableTypesWhenAssigned = 4,
		ShowDefaultRegisterTypes = 5,
		ShowCallParameterNames = 6,

		// Linear disassembly options
		GroupLinearDisassemblyFunctions = 64,

		// Debugging options
		ShowFlagUsage = 128
	};

	enum BNTypeClass
	{
		VoidTypeClass = 0,
		BoolTypeClass = 1,
		IntegerTypeClass = 2,
		FloatTypeClass = 3,
		StructureTypeClass = 4,
		EnumerationTypeClass = 5,
		PointerTypeClass = 6,
		ArrayTypeClass = 7,
		FunctionTypeClass = 8,
		VarArgsTypeClass = 9,
		ValueTypeClass = 10,
		NamedTypeReferenceClass = 11
	};

	enum BNNamedTypeReferenceClass
	{
		UnknownNamedTypeClass = 0,
		TypedefNamedTypeClass = 1,
		ClassNamedTypeClass = 2,
		StructNamedTypeClass = 3,
		UnionNamedTypeClass = 4,
		EnumNamedTypeClass = 5
	};

	enum BNStructureType
	{
		ClassStructureType = 0,
		StructStructureType = 1,
		UnionStructureType = 2
	};

	enum BNMemberScope {
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
		VectorVBaseConstructorIteratoreNameType,
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
		RttiClassHeirarchyDescriptor,
		RttiCompleteObjectLocator,
		OperatorUnaryMinusNameType,
		OperatorUnaryPlusNameType,
		OperatorUnaryBitAndNameType,
		OperatorUnaryStarNameType
	};

	enum BNCallingConventionName
	{
		NoCallingConvention,
		CdeclCallingConvention,
		PascalCallingConvention,
		ThisCallCallingConvention,
		STDCallCallingConvention,
		FastcallCallingConvention,
		CLRCallCallingConvention,
		EabiCallCallingConvention,
		VectorCallCallingConvention
	};

	enum BNStringType
	{
		AsciiString = 0,
		Utf16String = 1,
		Utf32String = 2
	};

	enum BNIntegerDisplayType
	{
		DefaultIntegerDisplayType,
		BinaryDisplayType,
		SignedOctalDisplayType,
		UnsignedOctalDisplayType,
		SignedDecimalDisplayType,
		UnsignedDecimalDisplayType,
		SignedHexadecimalDisplayType,
		UnsignedHexadecimalDisplayType,
		CharacterConstantDisplayType,
		PointerDisplayType
	};

	struct BNLowLevelILInstruction
	{
		BNLowLevelILOperation operation;
		size_t size;
		uint32_t flags;
		uint32_t sourceOperand;
		uint64_t operands[4];
		uint64_t address;
	};

	struct BNLowLevelILLabel
	{
		bool resolved;
		size_t ref;
		size_t operand;
	};

	enum BNImplicitRegisterExtend
	{
		NoExtend,
		ZeroExtendToFullWidth,
		SignExtendToFullWidth
	};

	struct BNRegisterInfo
	{
		uint32_t fullWidthRegister;
		size_t offset;
		size_t size;
		BNImplicitRegisterExtend extend;
	};

	struct BNRegisterStackInfo
	{
		uint32_t firstStorageReg, firstTopRelativeReg;
		uint32_t storageCount, topRelativeCount;
		uint32_t stackTopReg;
	};

	enum BNRegisterValueType
	{
		UndeterminedValue,
		EntryValue,
		ConstantValue,
		ConstantPointerValue,
		StackFrameOffset,
		ReturnAddressValue,
		ImportedAddressValue,

		// The following are only valid in BNPossibleValueSet
		SignedRangeValue,
		UnsignedRangeValue,
		LookupTableValue,
		InSetOfValues,
		NotInSetOfValues
	};

	enum BNPluginOrigin
	{
		OfficialPluginOrigin,
		CommunityPluginOrigin,
		OtherPluginOrigin
	};

	enum BNPluginUpdateStatus
	{
		UpToDatePluginStatus,
		UpdatesAvailablePluginStatus
	};

	enum BNPluginType
	{
		CorePluginType,
		UiPluginType,
		ArchitecturePluginType,
		BinaryViewPluginType
	};

	struct BNLookupTableEntry
	{
		int64_t* fromValues;
		size_t fromCount;
		int64_t toValue;
	};

	struct BNRegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
	};

	struct BNRegisterValueWithConfidence
	{
		BNRegisterValue value;
		uint8_t confidence;
	};

	struct BNValueRange
	{
		uint64_t start, end, step;
	};

	struct BNPossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		BNValueRange* ranges;
		int64_t* valueSet;
		BNLookupTableEntry* table;
		size_t count;
	};

	struct BNRegisterOrConstant
	{
		bool constant;
		uint32_t reg;
		uint64_t value;
	};

	struct BNDataVariable
	{
		uint64_t address;
		BNType* type;
		bool autoDiscovered;
		uint8_t typeConfidence;
	};

	enum BNMediumLevelILOperation
	{
		MLIL_NOP,
		MLIL_SET_VAR, // Not valid in SSA form (see MLIL_SET_VAR_SSA)
		MLIL_SET_VAR_FIELD, // Not valid in SSA form (see MLIL_SET_VAR_FIELD)
		MLIL_SET_VAR_SPLIT, // Not valid in SSA form (see MLIL_SET_VAR_SPLIT_SSA)
		MLIL_LOAD, // Not valid in SSA form (see MLIL_LOAD_SSA)
		MLIL_LOAD_STRUCT, // Not valid in SSA form (see MLIL_LOAD_STRUCT_SSA)
		MLIL_STORE, // Not valid in SSA form (see MLIL_STORE_SSA)
		MLIL_STORE_STRUCT, // Not valid in SSA form (see MLIL_STORE_STRUCT_SSA)
		MLIL_VAR, // Not valid in SSA form (see MLIL_VAR_SSA)
		MLIL_VAR_FIELD, // Not valid in SSA form (see MLIL_VAR_SSA_FIELD)
		MLIL_VAR_SPLIT, // Not valid in SSA form (see MLIL_VAR_SSA)
		MLIL_ADDRESS_OF,
		MLIL_ADDRESS_OF_FIELD,
		MLIL_CONST,
		MLIL_CONST_PTR,
		MLIL_FLOAT_CONST,
		MLIL_IMPORT,
		MLIL_ADD,
		MLIL_ADC,
		MLIL_SUB,
		MLIL_SBB,
		MLIL_AND,
		MLIL_OR,
		MLIL_XOR,
		MLIL_LSL,
		MLIL_LSR,
		MLIL_ASR,
		MLIL_ROL,
		MLIL_RLC,
		MLIL_ROR,
		MLIL_RRC,
		MLIL_MUL,
		MLIL_MULU_DP,
		MLIL_MULS_DP,
		MLIL_DIVU,
		MLIL_DIVU_DP,
		MLIL_DIVS,
		MLIL_DIVS_DP,
		MLIL_MODU,
		MLIL_MODU_DP,
		MLIL_MODS,
		MLIL_MODS_DP,
		MLIL_NEG,
		MLIL_NOT,
		MLIL_SX,
		MLIL_ZX,
		MLIL_LOW_PART,
		MLIL_JUMP,
		MLIL_JUMP_TO,
		MLIL_CALL, // Not valid in SSA form (see MLIL_CALL_SSA)
		MLIL_CALL_UNTYPED, // Not valid in SSA form (see MLIL_CALL_UNTYPED_SSA)
		MLIL_CALL_OUTPUT, // Only valid within MLIL_CALL, MLIL_SYSCALL, MLIL_TAILCALL family instructions
		MLIL_CALL_PARAM, // Only valid within MLIL_CALL, MLIL_SYSCALL, MLIL_TAILCALL family instructions
		MLIL_RET, // Not valid in SSA form (see MLIL_RET_SSA)
		MLIL_NORET,
		MLIL_IF,
		MLIL_GOTO,
		MLIL_CMP_E,
		MLIL_CMP_NE,
		MLIL_CMP_SLT,
		MLIL_CMP_ULT,
		MLIL_CMP_SLE,
		MLIL_CMP_ULE,
		MLIL_CMP_SGE,
		MLIL_CMP_UGE,
		MLIL_CMP_SGT,
		MLIL_CMP_UGT,
		MLIL_TEST_BIT,
		MLIL_BOOL_TO_INT,
		MLIL_ADD_OVERFLOW,
		MLIL_SYSCALL, // Not valid in SSA form (see MLIL_SYSCALL_SSA)
		MLIL_SYSCALL_UNTYPED, // Not valid in SSA form (see MLIL_SYSCALL_UNTYPED_SSA)
		MLIL_TAILCALL, // Not valid in SSA form (see MLIL_TAILCALL_SSA)
		MLIL_TAILCALL_UNTYPED, // Not valid in SSA form (see MLIL_TAILCALL_UNTYPED_SSA)
		MLIL_INTRINSIC, // Not valid in SSA form (see MLIL_INTRINSIC_SSA)
		MLIL_FREE_VAR_SLOT, // Not valid in SSA from (see MLIL_FREE_VAR_SLOT_SSA)
		MLIL_BP,
		MLIL_TRAP,
		MLIL_UNDEF,
		MLIL_UNIMPL,
		MLIL_UNIMPL_MEM,

		// Floating point
		MLIL_FADD,
		MLIL_FSUB,
		MLIL_FMUL,
		MLIL_FDIV,
		MLIL_FSQRT,
		MLIL_FNEG,
		MLIL_FABS,
		MLIL_FLOAT_TO_INT,
		MLIL_INT_TO_FLOAT,
		MLIL_FLOAT_CONV,
		MLIL_ROUND_TO_INT,
		MLIL_FLOOR,
		MLIL_CEIL,
		MLIL_FTRUNC,
		MLIL_FCMP_E,
		MLIL_FCMP_NE,
		MLIL_FCMP_LT,
		MLIL_FCMP_LE,
		MLIL_FCMP_GE,
		MLIL_FCMP_GT,
		MLIL_FCMP_O,
		MLIL_FCMP_UO,

		// The following instructions are only used in SSA form
		MLIL_SET_VAR_SSA,
		MLIL_SET_VAR_SSA_FIELD,
		MLIL_SET_VAR_SPLIT_SSA,
		MLIL_SET_VAR_ALIASED,
		MLIL_SET_VAR_ALIASED_FIELD,
		MLIL_VAR_SSA,
		MLIL_VAR_SSA_FIELD,
		MLIL_VAR_ALIASED,
		MLIL_VAR_ALIASED_FIELD,
		MLIL_VAR_SPLIT_SSA,
		MLIL_CALL_SSA,
		MLIL_CALL_UNTYPED_SSA,
		MLIL_SYSCALL_SSA,
		MLIL_SYSCALL_UNTYPED_SSA,
		MLIL_TAILCALL_SSA,
		MLIL_TAILCALL_UNTYPED_SSA,
		MLIL_CALL_PARAM_SSA, // Only valid within the MLIL_CALL_SSA, MLIL_SYSCALL_SSA, MLIL_TAILCALL_SSA family instructions
		MLIL_CALL_OUTPUT_SSA, // Only valid within the MLIL_CALL_SSA or MLIL_SYSCALL_SSA, MLIL_TAILCALL_SSA family instructions
		MLIL_LOAD_SSA,
		MLIL_LOAD_STRUCT_SSA,
		MLIL_STORE_SSA,
		MLIL_STORE_STRUCT_SSA,
		MLIL_INTRINSIC_SSA,
		MLIL_FREE_VAR_SLOT_SSA,
		MLIL_VAR_PHI,
		MLIL_MEM_PHI
	};

	struct BNMediumLevelILInstruction
	{
		BNMediumLevelILOperation operation;
		uint32_t sourceOperand;
		size_t size;
		uint64_t operands[5];
		uint64_t address;
	};

	struct BNMediumLevelILLabel
	{
		bool resolved;
		size_t ref;
		size_t operand;
	};

	enum BNVariableSourceType
	{
		StackVariableSourceType,
		RegisterVariableSourceType,
		FlagVariableSourceType
	};

	struct BNVariable
	{
		BNVariableSourceType type;
		uint32_t index;
		int64_t storage;
	};

	// Callbacks
	struct BNLogListener
	{
		void* context;
		void (*log)(void* ctxt, BNLogLevel level, const char* msg);
		void (*close)(void* ctxt);
		BNLogLevel (*getLogLevel)(void* ctxt);
	};

	struct BNNavigationHandler
	{
		void* context;
		char* (*getCurrentView)(void* ctxt);
		uint64_t (*getCurrentOffset)(void* ctxt);
		bool (*navigate)(void* ctxt, const char* view, uint64_t offset);
	};

	struct BNQualifiedName
	{
		char** name;
		size_t nameCount;
	};

	struct BNBinaryDataNotification
	{
		void* context;
		void (*dataWritten)(void* ctxt, BNBinaryView* view, uint64_t offset, size_t len);
		void (*dataInserted)(void* ctxt, BNBinaryView* view, uint64_t offset, size_t len);
		void (*dataRemoved)(void* ctxt, BNBinaryView* view, uint64_t offset, uint64_t len);
		void (*functionAdded)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*functionRemoved)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*functionUpdated)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*functionUpdateRequested)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*dataVariableAdded)(void* ctxt, BNBinaryView* view, BNDataVariable* var);
		void (*dataVariableRemoved)(void* ctxt, BNBinaryView* view, BNDataVariable* var);
		void (*dataVariableUpdated)(void* ctxt, BNBinaryView* view, BNDataVariable* var);
		void (*stringFound)(void* ctxt, BNBinaryView* view, BNStringType type, uint64_t offset, size_t len);
		void (*stringRemoved)(void* ctxt, BNBinaryView* view, BNStringType type, uint64_t offset, size_t len);
		void (*typeDefined)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeUndefined)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
	};

	struct BNFileAccessor
	{
		void* context;
		uint64_t (*getLength)(void* ctxt);
		size_t (*read)(void* ctxt, void* dest, uint64_t offset, size_t len);
		size_t (*write)(void* ctxt, uint64_t offset, const void* src, size_t len);
	};

	struct BNCustomBinaryView
	{
		void* context;
		bool (*init)(void* ctxt);
		void (*freeObject)(void* ctxt);
		size_t (*read)(void* ctxt, void* dest, uint64_t offset, size_t len);
		size_t (*write)(void* ctxt, uint64_t offset, const void* src, size_t len);
		size_t (*insert)(void* ctxt, uint64_t offset, const void* src, size_t len);
		size_t (*remove)(void* ctxt, uint64_t offset, uint64_t len);
		BNModificationStatus (*getModification)(void* ctxt, uint64_t offset);
		bool (*isValidOffset)(void* ctxt, uint64_t offset);
		bool (*isOffsetReadable)(void* ctxt, uint64_t offset);
		bool (*isOffsetWritable)(void* ctxt, uint64_t offset);
		bool (*isOffsetExecutable)(void* ctxt, uint64_t offset);
		bool (*isOffsetBackedByFile)(void* ctxt, uint64_t offset);
		uint64_t (*getNextValidOffset)(void* ctxt, uint64_t offset);
		uint64_t (*getStart)(void* ctxt);
		uint64_t (*getLength)(void* ctxt);
		uint64_t (*getEntryPoint)(void* ctxt);
		bool (*isExecutable)(void* ctxt);
		BNEndianness (*getDefaultEndianness)(void* ctxt);
		bool (*isRelocatable)(void* ctxt);
		size_t (*getAddressSize)(void* ctxt);
		bool (*save)(void* ctxt, BNFileAccessor* accessor);
	};

	struct BNCustomBinaryViewType
	{
		void* context;
		BNBinaryView* (*create)(void* ctxt, BNBinaryView* data);
		bool (*isValidForData)(void* ctxt, BNBinaryView* data);
	};

	struct BNTransformParameterInfo
	{
		char* name;
		char* longName;
		size_t fixedLength; // Variable length if zero
	};

	struct BNTransformParameter
	{
		const char* name;
		BNDataBuffer* value;
	};

	struct BNCustomTransform
	{
		void* context;
		BNTransformParameterInfo* (*getParameters)(void* ctxt, size_t* count);
		void (*freeParameters)(BNTransformParameterInfo* params, size_t count);
		bool (*decode)(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		bool (*encode)(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
	};

	struct BNInstructionInfo
	{
		size_t length;
		size_t branchCount;
		bool archTransitionByTargetAddr;
		bool branchDelay;
		BNBranchType branchType[BN_MAX_INSTRUCTION_BRANCHES];
		uint64_t branchTarget[BN_MAX_INSTRUCTION_BRANCHES];
		BNArchitecture* branchArch[BN_MAX_INSTRUCTION_BRANCHES]; // If null, same architecture as instruction
	};

	struct BNInstructionTextToken
	{
		BNInstructionTextTokenType type;
		char* text;
		uint64_t value;
		size_t size, operand;
		BNInstructionTextTokenContext context;
		uint8_t confidence;
		uint64_t address;
	};

	struct BNInstructionTextLine
	{
		BNInstructionTextToken* tokens;
		size_t count;
	};

	struct BNFlagConditionForSemanticClass
	{
		uint32_t semanticClass;
		BNLowLevelILFlagCondition condition;
	};

	struct BNNameAndType
	{
		char* name;
		BNType* type;
		uint8_t typeConfidence;
	};

	struct BNTypeWithConfidence
	{
		BNType* type;
		uint8_t confidence;
	};

	struct BNCustomArchitecture
	{
		void* context;
		void (*init)(void* context, BNArchitecture* obj);
		BNEndianness (*getEndianness)(void* ctxt);
		size_t (*getAddressSize)(void* ctxt);
		size_t (*getDefaultIntegerSize)(void* ctxt);
		size_t (*getInstructionAlignment)(void* ctxt);
		size_t (*getMaxInstructionLength)(void* ctxt);
		size_t (*getOpcodeDisplayLength)(void* ctxt);
		BNArchitecture* (*getAssociatedArchitectureByAddress)(void* ctxt, uint64_t* addr);
		bool (*getInstructionInfo)(void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
		bool (*getInstructionText)(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len,
		                           BNInstructionTextToken** result, size_t* count);
		void (*freeInstructionText)(BNInstructionTextToken* tokens, size_t count);
		bool (*getInstructionLowLevelIL)(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
		char* (*getRegisterName)(void* ctxt, uint32_t reg);
		char* (*getFlagName)(void* ctxt, uint32_t flag);
		char* (*getFlagWriteTypeName)(void* ctxt, uint32_t flags);
		char* (*getSemanticFlagClassName)(void* ctxt, uint32_t semClass);
		char* (*getSemanticFlagGroupName)(void* ctxt, uint32_t semGroup);
		uint32_t* (*getFullWidthRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getAllRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getAllFlags)(void* ctxt, size_t* count);
		uint32_t* (*getAllFlagWriteTypes)(void* ctxt, size_t* count);
		uint32_t* (*getAllSemanticFlagClasses)(void* ctxt, size_t* count);
		uint32_t* (*getAllSemanticFlagGroups)(void* ctxt, size_t* count);
		BNFlagRole (*getFlagRole)(void* ctxt, uint32_t flag, uint32_t semClass);
		uint32_t* (*getFlagsRequiredForFlagCondition)(void* ctxt, BNLowLevelILFlagCondition cond,
			uint32_t semClass, size_t* count);
		uint32_t* (*getFlagsRequiredForSemanticFlagGroup)(void* ctxt, uint32_t semGroup, size_t* count);
		BNFlagConditionForSemanticClass* (*getFlagConditionsForSemanticFlagGroup)(void* ctxt, uint32_t semGroup, size_t* count);
		void (*freeFlagConditionsForSemanticFlagGroup)(void* ctxt, BNFlagConditionForSemanticClass* conditions);
		uint32_t* (*getFlagsWrittenByFlagWriteType)(void* ctxt, uint32_t writeType, size_t* count);
		uint32_t (*getSemanticClassForFlagWriteType)(void* ctxt, uint32_t writeType);
		size_t (*getFlagWriteLowLevelIL)(void* ctxt, BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il);
		size_t (*getFlagConditionLowLevelIL)(void* ctxt, BNLowLevelILFlagCondition cond,
			uint32_t semClass, BNLowLevelILFunction* il);
		size_t (*getSemanticFlagGroupLowLevelIL)(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs);
		void (*getRegisterInfo)(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		uint32_t (*getStackPointerRegister)(void* ctxt);
		uint32_t (*getLinkRegister)(void* ctxt);
		uint32_t* (*getGlobalRegisters)(void* ctxt, size_t* count);

		char* (*getRegisterStackName)(void* ctxt, uint32_t regStack);
		uint32_t* (*getAllRegisterStacks)(void* ctxt, size_t* count);
		void (*getRegisterStackInfo)(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		char* (*getIntrinsicName)(void* ctxt, uint32_t intrinsic);
		uint32_t* (*getAllIntrinsics)(void* ctxt, size_t* count);
		BNNameAndType* (*getIntrinsicInputs)(void* ctxt, uint32_t intrinsic, size_t* count);
		void (*freeNameAndTypeList)(void* ctxt, BNNameAndType* nt, size_t count);
		BNTypeWithConfidence* (*getIntrinsicOutputs)(void* ctxt, uint32_t intrinsic, size_t* count);
		void (*freeTypeList)(void* ctxt, BNTypeWithConfidence* types, size_t count);

		bool (*assemble)(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);

		bool (*isNeverBranchPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isAlwaysBranchPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isInvertBranchPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isSkipAndReturnZeroPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isSkipAndReturnValuePatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);

		bool (*convertToNop)(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		bool (*alwaysBranch)(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		bool (*invertBranch)(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		bool (*skipAndReturnValue)(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value);
	};

	struct BNBasicBlockEdge
	{
		BNBranchType type;
		BNBasicBlock* target;
		bool backEdge;
	};

	struct BNPoint
	{
		float x;
		float y;
	};

	struct BNFunctionGraphEdge
	{
		BNBranchType type;
		BNBasicBlock* target;
		BNPoint* points;
		size_t pointCount;
		bool backEdge;
	};

	struct BNDisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		BNInstructionTextToken* tokens;
		size_t count;
	};

	struct BNLinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		BNFunction* function;
		BNBasicBlock* block;
		size_t lineOffset;
		BNDisassemblyTextLine contents;
	};

	struct BNLinearDisassemblyPosition
	{
		BNFunction* function;
		BNBasicBlock* block;
		uint64_t address;
	};

	struct BNReferenceSource
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
	};

	struct BNUndoAction
	{
		BNActionType type;
		void* context;
		void (*freeObject)(void* ctxt);
		void (*undo)(void* ctxt, BNBinaryView* data);
		void (*redo)(void* ctxt, BNBinaryView* data);
		char* (*serialize)(void* ctxt);
	};

	struct BNCallingConventionWithConfidence
	{
		BNCallingConvention* convention;
		uint8_t confidence;
	};

	struct BNBoolWithConfidence
	{
		bool value;
		uint8_t confidence;
	};

	struct BNSizeWithConfidence
	{
		size_t value;
		uint8_t confidence;
	};

	struct BNMemberScopeWithConfidence
	{
		BNMemberScope value;
		uint8_t confidence;
	};

	struct BNMemberAccessWithConfidence
	{
		BNMemberAccess value;
		uint8_t confidence;
	};

	struct BNParameterVariablesWithConfidence
	{
		BNVariable* vars;
		size_t count;
		uint8_t confidence;
	};

	struct BNRegisterSetWithConfidence
	{
		uint32_t* regs;
		size_t count;
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

	struct BNQualifiedNameAndType
	{
		BNQualifiedName name;
		BNType* type;
	};

	struct BNStructureMember
	{
		BNType* type;
		char* name;
		uint64_t offset;
		uint8_t typeConfidence;
	};

	struct BNEnumerationMember
	{
		char* name;
		uint64_t value;
		bool isDefault;
	};

	struct BNFunctionRecognizer
	{
		void* context;
		bool (*recognizeLowLevelIL)(void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		bool (*recognizeMediumLevelIL)(void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);
	};

	struct BNTypeParserResult
	{
		BNQualifiedNameAndType* types;
		BNQualifiedNameAndType* variables;
		BNQualifiedNameAndType* functions;
		size_t typeCount, variableCount, functionCount;
	};

	enum BNUpdateResult
	{
		UpdateFailed = 0,
		UpdateSuccess = 1,
		AlreadyUpToDate = 2,
		UpdateAvailable = 3
	};

	struct BNUpdateChannel
	{
		char* name;
		char* description;
		char* latestVersion;
	};

	struct BNUpdateVersion
	{
		char* version;
		char* notes;
		uint64_t time;
	};

	struct BNStringReference
	{
		BNStringType type;
		uint64_t start;
		size_t length;
	};

	enum BNPluginCommandType
	{
		DefaultPluginCommand,
		AddressPluginCommand,
		RangePluginCommand,
		FunctionPluginCommand,
		LowLevelILFunctionPluginCommand,
		LowLevelILInstructionPluginCommand,
		MediumLevelILFunctionPluginCommand,
		MediumLevelILInstructionPluginCommand
	};

	struct BNPluginCommand
	{
		char* name;
		char* description;
		BNPluginCommandType type;
		void* context;

		void (*defaultCommand)(void* ctxt, BNBinaryView* view);
		void (*addressCommand)(void* ctxt, BNBinaryView* view, uint64_t addr);
		void (*rangeCommand)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		void (*functionCommand)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*lowLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		void (*lowLevelILInstructionCommand)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		void (*mediumLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		void (*mediumLevelILInstructionCommand)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);

		bool (*defaultIsValid)(void* ctxt, BNBinaryView* view);
		bool (*addressIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr);
		bool (*rangeIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		bool (*functionIsValid)(void* ctxt, BNBinaryView* view, BNFunction* func);
		bool (*lowLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		bool (*lowLevelILInstructionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		bool (*mediumLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		bool (*mediumLevelILInstructionIsValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
	};

	struct BNCustomCallingConvention
	{
		void* context;

		void (*freeObject)(void* ctxt);

		uint32_t* (*getCallerSavedRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getIntegerArgumentRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getFloatArgumentRegisters)(void* ctxt, size_t* count);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs);

		bool (*areArgumentRegistersSharedIndex)(void* ctxt);
		bool (*isStackReservedForArgumentRegisters)(void* ctxt);
		bool (*isStackAdjustedOnReturn)(void* ctxt);

		uint32_t (*getIntegerReturnValueRegister)(void* ctxt);
		uint32_t (*getHighIntegerReturnValueRegister)(void* ctxt);
		uint32_t (*getFloatReturnValueRegister)(void* ctxt);
		uint32_t (*getGlobalPointerRegister)(void* ctxt);

		uint32_t* (*getImplicitlyDefinedRegisters)(void* ctxt, size_t* count);
		void (*getIncomingRegisterValue)(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		void (*getIncomingFlagValue)(void* ctxt, uint32_t flag, BNFunction* func, BNRegisterValue* result);

		void (*getIncomingVariableForParameterVariable)(void* ctxt, const BNVariable* var,
			BNFunction* func, BNVariable* result);
		void (*getParameterVariableForIncomingVariable)(void* ctxt, const BNVariable* var,
			BNFunction* func, BNVariable* result);
	};

	struct BNVariableNameAndType
	{
		BNVariable var;
		BNType* type;
		char* name;
		bool autoDefined;
		uint8_t typeConfidence;
	};

	struct BNStackVariableReference
	{
		uint32_t sourceOperand;
		uint8_t typeConfidence;
		BNType* type;
		char* name;
		uint64_t varIdentifier;
		int64_t referencedOffset;
		size_t size;
	};

	struct BNIndirectBranchInfo
	{
		BNArchitecture* sourceArch;
		uint64_t sourceAddr;
		BNArchitecture* destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

	struct BNArchitectureAndAddress
	{
		BNArchitecture* arch;
		uint64_t address;
	};

	enum BNAnalysisState
	{
		IdleState,
		DisassembleState,
		AnalyzeState
	};

	struct BNAnalysisProgress
	{
		BNAnalysisState state;
		size_t count, total;
	};

	struct BNDownloadInstanceOutputCallbacks
	{
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	};

	struct BNDownloadInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		int (*performRequest)(void* ctxt, const char* url);
	};

	struct BNDownloadProviderCallbacks
	{
		void* context;
		BNDownloadInstance* (*createInstance)(void* ctxt);
	};

	enum BNFindFlag
	{
		NoFindFlags = 0,
		FindCaseInsensitive = 1
	};

	enum BNScriptingProviderInputReadyState
	{
		NotReadyForInput,
		ReadyForScriptExecution,
		ReadyForScriptProgramInput
	};

	enum BNScriptingProviderExecuteResult
	{
		InvalidScriptInput,
		IncompleteScriptInput,
		SuccessfulScriptExecution
	};


	struct BNScriptingInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		BNScriptingProviderExecuteResult (*executeScriptInput)(void* ctxt, const char* input);
		void (*setCurrentBinaryView)(void* ctxt, BNBinaryView* view);
		void (*setCurrentFunction)(void* ctxt, BNFunction* func);
		void (*setCurrentBasicBlock)(void* ctxt, BNBasicBlock* block);
		void (*setCurrentAddress)(void* ctxt, uint64_t addr);
		void (*setCurrentSelection)(void* ctxt, uint64_t begin, uint64_t end);
	};

	struct BNScriptingProviderCallbacks
	{
		void* context;
		BNScriptingInstance* (*createInstance)(void* ctxt);

	};

	struct BNScriptingOutputListener
	{
		void* context;
		void (*output)(void* ctxt, const char* text);
		void (*error)(void* ctxt, const char* text);
		void (*inputReadyStateChanged)(void* ctxt, BNScriptingProviderInputReadyState state);
	};

	struct BNMainThreadCallbacks
	{
		void* context;
		void (*addAction)(void* ctxt, BNMainThreadAction* action);
	};

	struct BNConstantReference
	{
		int64_t value;
		size_t size;
		bool pointer, intermediate;
	};

	struct BNMetadataValueStore
	{
		size_t size;
		char** keys;
		BNMetadata** values;
	};

	enum BNHighlightColorStyle
	{
		StandardHighlightColor = 0,
		MixedHighlightColor = 1,
		CustomHighlightColor = 2
	};

	enum BNHighlightStandardColor
	{
		NoHighlightColor = 0,
		BlueHighlightColor = 1,
		GreenHighlightColor = 2,
		CyanHighlightColor = 3,
		RedHighlightColor = 4,
		MagentaHighlightColor = 5,
		YellowHighlightColor = 6,
		OrangeHighlightColor = 7,
		WhiteHighlightColor = 8,
		BlackHighlightColor = 9
	};

	struct BNHighlightColor
	{
		BNHighlightColorStyle style;
		BNHighlightStandardColor color;
		BNHighlightStandardColor mixColor;
		uint8_t mix, r, g, b, alpha;
	};

	enum BNMessageBoxIcon
	{
		InformationIcon,
		QuestionIcon,
		WarningIcon,
		ErrorIcon
	};

	enum BNMessageBoxButtonSet
	{
		OKButtonSet,
		YesNoButtonSet,
		YesNoCancelButtonSet
	};

	enum BNMessageBoxButtonResult
	{
		NoButton = 0,
		YesButton = 1,
		OKButton = 2,
		CancelButton = 3
	};

	enum BNFormInputFieldType
	{
		LabelFormField,
		SeparatorFormField,
		TextLineFormField,
		MultilineTextFormField,
		IntegerFormField,
		AddressFormField,
		ChoiceFormField,
		OpenFileNameFormField,
		SaveFileNameFormField,
		DirectoryNameFormField
	};

	struct BNFormInputField
	{
		BNFormInputFieldType type;
		const char* prompt;
		BNBinaryView* view; // For AddressFormField
		uint64_t currentAddress; // For AddressFormField
		const char** choices; // For ChoiceFormField
		size_t count; // For ChoiceFormField
		const char* ext; // For OpenFileNameFormField, SaveFileNameFormField
		const char* defaultName; // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		char* stringResult;
		size_t indexResult;
	};

	struct BNInteractionHandlerCallbacks
	{
		void* context;
		void (*showPlainTextReport)(void* ctxt, BNBinaryView* view, const char* title, const char* contents);
		void (*showMarkdownReport)(void* ctxt, BNBinaryView* view, const char* title, const char* contents,
			const char* plaintext);
		void (*showHTMLReport)(void* ctxt, BNBinaryView* view, const char* title, const char* contents,
			const char* plaintext);
		bool (*getTextLineInput)(void* ctxt, char** result, const char* prompt, const char* title);
		bool (*getIntegerInput)(void* ctxt, int64_t* result, const char* prompt, const char* title);
		bool (*getAddressInput)(void* ctxt, uint64_t* result, const char* prompt, const char* title,
			BNBinaryView* view, uint64_t currentAddr);
		bool (*getChoiceInput)(void* ctxt, size_t* result, const char* prompt, const char* title,
			const char** choices, size_t count);
		bool (*getOpenFileNameInput)(void* ctxt, char** result, const char* prompt, const char* ext);
		bool (*getSaveFileNameInput)(void* ctxt, char** result, const char* prompt, const char* ext,
			const char* defaultName);
		bool (*getDirectoryNameInput)(void* ctxt, char** result, const char* prompt, const char* defaultName);
		bool (*getFormInput)(void* ctxt, BNFormInputField* fields, size_t count, const char* title);
		BNMessageBoxButtonResult (*showMessageBox)(void* ctxt, const char* title, const char* text,
			BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon);
	};

	struct BNObjectDestructionCallbacks
	{
		void* context;
		// The provided pointers have a reference count of zero. Do not add additional references, doing so
		// can lead to a double free. These are provided only for freeing additional state related to the
		// objects passed.
		void (*destructBinaryView)(void* ctxt, BNBinaryView* view);
		void (*destructFileMetadata)(void* ctxt, BNFileMetadata* file);
		void (*destructFunction)(void* ctxt, BNFunction* func);
	};

	enum BNSegmentFlag
	{
		SegmentExecutable = 1,
		SegmentWritable = 2,
		SegmentReadable = 4,
		SegmentContainsData = 8,
		SegmentContainsCode = 0x10,
		SegmentDenyWrite = 0x20,
		SegmentDenyExecute = 0x40
	};

	struct BNSegment
	{
		uint64_t start, length;
		uint64_t dataOffset, dataLength;
		uint32_t flags;
		bool autoDefined;
	};

	enum BNSectionSemantics
	{
		DefaultSectionSemantics,
		ReadOnlyCodeSectionSemantics,
		ReadOnlyDataSectionSemantics,
		ReadWriteDataSectionSemantics
	};

	struct BNSection
	{
		char* name;
		char* type;
		uint64_t start, length;
		char* linkedSection;
		char* infoSection;
		uint64_t infoData;
		uint64_t align, entrySize;
		BNSectionSemantics semantics;
		bool autoDefined;
	};

	struct BNAddressRange
	{
		uint64_t start;
		uint64_t end;
	};

	struct BNSystemCallInfo
	{
		uint32_t number;
		BNQualifiedName name;
		BNType* type;
	};

	enum BNILBranchDependence
	{
		NotBranchDependent,
		TrueBranchDependent,
		FalseBranchDependent
	};

	struct BNILBranchInstructionAndDependence
	{
		size_t branch;
		BNILBranchDependence dependence;
	};

	struct BNPerformanceInfo
	{
		char* name;
		double seconds;
	};

	enum BNMetadataType
	{
		InvalidDataType,
		BooleanDataType,
		StringDataType,
		UnsignedIntegerDataType,
		SignedIntegerDataType,
		DoubleDataType,
		RawDataType,
		KeyValueDataType,
		ArrayDataType
	};

	struct BNRegisterStackAdjustment
	{
		uint32_t regStack;
		int32_t adjustment;
		uint8_t confidence;
	};

	enum BNFunctionAnalysisSkipOverride
	{
		DefaultFunctionAnalysisSkip,
		NeverSkipFunctionAnalysis,
		AlwaysSkipFunctionAnalysis
	};

	BINARYNINJACOREAPI char* BNAllocString(const char* contents);
	BINARYNINJACOREAPI void BNFreeString(char* str);
	BINARYNINJACOREAPI char** BNAllocStringList(const char** contents, size_t size);
	BINARYNINJACOREAPI void BNFreeStringList(char** strs, size_t count);

	BINARYNINJACOREAPI void BNShutdown(void);

	BINARYNINJACOREAPI char* BNGetVersionString(void);
	BINARYNINJACOREAPI uint32_t BNGetBuildId(void);

	BINARYNINJACOREAPI char* BNGetSerialNumber(void);
	BINARYNINJACOREAPI uint64_t BNGetLicenseExpirationTime(void);
	BINARYNINJACOREAPI bool BNIsLicenseValidated(void);
	BINARYNINJACOREAPI char* BNGetLicensedUserEmail(void);
	BINARYNINJACOREAPI char* BNGetProduct(void);
	BINARYNINJACOREAPI char* BNGetProductType(void);
	BINARYNINJACOREAPI int BNGetLicenseCount(void);
	BINARYNINJACOREAPI bool BNIsUIEnabled(void);

	BINARYNINJACOREAPI void BNRegisterObjectDestructionCallbacks(BNObjectDestructionCallbacks* callbacks);
	BINARYNINJACOREAPI void BNUnregisterObjectDestructionCallbacks(BNObjectDestructionCallbacks* callbacks);

	BINARYNINJACOREAPI char* BNGetUniqueIdentifierString(void);

	// Plugin initialization
	BINARYNINJACOREAPI void BNInitCorePlugins(void);
	BINARYNINJACOREAPI void BNInitUserPlugins(void);
	BINARYNINJACOREAPI void BNInitRepoPlugins(void);

	BINARYNINJACOREAPI char* BNGetInstallDirectory(void);
	BINARYNINJACOREAPI char* BNGetBundledPluginDirectory(void);
	BINARYNINJACOREAPI void BNSetBundledPluginDirectory(const char* path);
	BINARYNINJACOREAPI char* BNGetUserDirectory(void);
	BINARYNINJACOREAPI char* BNGetUserPluginDirectory(void);
	BINARYNINJACOREAPI char* BNGetRepositoriesDirectory(void);
	BINARYNINJACOREAPI char* BNGetSettingsFileName(void);
	BINARYNINJACOREAPI void BNSaveLastRun(void);

	BINARYNINJACOREAPI char* BNGetPathRelativeToBundledPluginDirectory(const char* path);
	BINARYNINJACOREAPI char* BNGetPathRelativeToUserPluginDirectory(const char* path);

	BINARYNINJACOREAPI bool BNExecuteWorkerProcess(const char* path, const char* args[],
	                                               BNDataBuffer* input, char** output, char** error,
	                                               bool stdoutIsText, bool stderrIsText);

	BINARYNINJACOREAPI void BNSetCurrentPluginLoadOrder(BNPluginLoadOrder order);
	BINARYNINJACOREAPI void BNAddRequiredPluginDependency(const char* name);
	BINARYNINJACOREAPI void BNAddOptionalPluginDependency(const char* name);

	// Logging
	BINARYNINJACOREAPI void BNLog(BNLogLevel level, const char* fmt, ...);
	BINARYNINJACOREAPI void BNLogDebug(const char* fmt, ...);
	BINARYNINJACOREAPI void BNLogInfo(const char* fmt, ...);
	BINARYNINJACOREAPI void BNLogWarn(const char* fmt, ...);
	BINARYNINJACOREAPI void BNLogError(const char* fmt, ...);
	BINARYNINJACOREAPI void BNLogAlert(const char* fmt, ...);

	BINARYNINJACOREAPI void BNRegisterLogListener(BNLogListener* listener);
	BINARYNINJACOREAPI void BNUnregisterLogListener(BNLogListener* listener);
	BINARYNINJACOREAPI void BNUpdateLogListeners(void);

	BINARYNINJACOREAPI void BNLogToStdout(BNLogLevel minimumLevel);
	BINARYNINJACOREAPI void BNLogToStderr(BNLogLevel minimumLevel);
	BINARYNINJACOREAPI bool BNLogToFile(BNLogLevel minimumLevel, const char* path, bool append);
	BINARYNINJACOREAPI void BNCloseLogs(void);

	// Temporary files
	BINARYNINJACOREAPI BNTemporaryFile* BNCreateTemporaryFile(void);
	BINARYNINJACOREAPI BNTemporaryFile* BNCreateTemporaryFileWithContents(BNDataBuffer* data);
	BINARYNINJACOREAPI BNTemporaryFile* BNNewTemporaryFileReference(BNTemporaryFile* file);
	BINARYNINJACOREAPI void BNFreeTemporaryFile(BNTemporaryFile* file);
	BINARYNINJACOREAPI char* BNGetTemporaryFilePath(BNTemporaryFile* file);
	BINARYNINJACOREAPI BNDataBuffer* BNGetTemporaryFileContents(BNTemporaryFile* file);

	// Data buffer management
	BINARYNINJACOREAPI BNDataBuffer* BNCreateDataBuffer(const void* data, size_t len);
	BINARYNINJACOREAPI BNDataBuffer* BNDuplicateDataBuffer(BNDataBuffer* buf);
	BINARYNINJACOREAPI void BNFreeDataBuffer(BNDataBuffer* buf);
	BINARYNINJACOREAPI void* BNGetDataBufferContents(BNDataBuffer* buf);
	BINARYNINJACOREAPI void* BNGetDataBufferContentsAt(BNDataBuffer* buf, size_t offset);
	BINARYNINJACOREAPI size_t BNGetDataBufferLength(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNGetDataBufferSlice(BNDataBuffer* buf, size_t start, size_t len);

	BINARYNINJACOREAPI void BNSetDataBufferLength(BNDataBuffer* buf, size_t len);
	BINARYNINJACOREAPI void BNClearDataBuffer(BNDataBuffer* buf);
	BINARYNINJACOREAPI void BNSetDataBufferContents(BNDataBuffer* buf, void* data, size_t len);
	BINARYNINJACOREAPI void BNAssignDataBuffer(BNDataBuffer* dest, BNDataBuffer* src);
	BINARYNINJACOREAPI void BNAppendDataBuffer(BNDataBuffer* dest, BNDataBuffer* src);
	BINARYNINJACOREAPI void BNAppendDataBufferContents(BNDataBuffer* dest, const void* src, size_t len);

	BINARYNINJACOREAPI uint8_t BNGetDataBufferByte(BNDataBuffer* buf, size_t offset);
	BINARYNINJACOREAPI void BNSetDataBufferByte(BNDataBuffer* buf, size_t offset, uint8_t val);

	BINARYNINJACOREAPI char* BNDataBufferToEscapedString(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNDecodeEscapedString(const char* str);
	BINARYNINJACOREAPI char* BNDataBufferToBase64(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNDecodeBase64(const char* str);

	BINARYNINJACOREAPI BNDataBuffer* BNZlibCompress(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNZlibDecompress(BNDataBuffer* buf);

	// File metadata object
	BINARYNINJACOREAPI BNFileMetadata* BNCreateFileMetadata(void);
	BINARYNINJACOREAPI BNFileMetadata* BNNewFileReference(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNFreeFileMetadata(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNCloseFile(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetFileMetadataNavigationHandler(BNFileMetadata* file, BNNavigationHandler* handler);
	BINARYNINJACOREAPI bool BNIsFileModified(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNIsAnalysisChanged(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNMarkFileModified(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNMarkFileSaved(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNIsBackedByDatabase(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNCreateDatabase(BNBinaryView* data, const char* path);
	BINARYNINJACOREAPI bool BNCreateDatabaseWithProgress(BNBinaryView* data, const char* path,
		void* ctxt, void (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNBinaryView* BNOpenExistingDatabase(BNFileMetadata* file, const char* path);
	BINARYNINJACOREAPI BNBinaryView* BNOpenExistingDatabaseWithProgress(BNFileMetadata* file, const char* path,
		void* ctxt, void (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI bool BNSaveAutoSnapshot(BNBinaryView* data);
	BINARYNINJACOREAPI bool BNSaveAutoSnapshotWithProgress(BNBinaryView* data, void* ctxt,
		void (*progress)(void* ctxt, size_t progress, size_t total));

	BINARYNINJACOREAPI char* BNGetFilename(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetFilename(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI void BNRegisterUndoActionType(const char* name, void* typeContext,
	                                                 bool (*deserialize)(void* ctxt, const char* data, BNUndoAction* result));
	BINARYNINJACOREAPI void BNBeginUndoActions(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNAddUndoAction(BNBinaryView* view, const char* type, BNUndoAction* action);
	BINARYNINJACOREAPI void BNCommitUndoActions(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNUndo(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNRedo(BNFileMetadata* file);

	BINARYNINJACOREAPI char* BNGetCurrentView(BNFileMetadata* file);
	BINARYNINJACOREAPI uint64_t BNGetCurrentOffset(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNNavigate(BNFileMetadata* file, const char* view, uint64_t offset);

	BINARYNINJACOREAPI BNBinaryView* BNGetFileViewOfType(BNFileMetadata* file, const char* name);

	// Binary view access
	BINARYNINJACOREAPI BNBinaryView* BNNewViewReference(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeBinaryView(BNBinaryView* view);
	BINARYNINJACOREAPI BNFileMetadata* BNGetFileForView(BNBinaryView* view);
	BINARYNINJACOREAPI char* BNGetViewType(BNBinaryView* view);

	BINARYNINJACOREAPI BNBinaryView* BNGetParentView(BNBinaryView* view);

	BINARYNINJACOREAPI size_t BNReadViewData(BNBinaryView* view, void* dest, uint64_t offset, size_t len);
	BINARYNINJACOREAPI BNDataBuffer* BNReadViewBuffer(BNBinaryView* view, uint64_t offset, size_t len);

	BINARYNINJACOREAPI size_t BNWriteViewData(BNBinaryView* view, uint64_t offset, const void* data, size_t len);
	BINARYNINJACOREAPI size_t BNWriteViewBuffer(BNBinaryView* view, uint64_t offset, BNDataBuffer* data);
	BINARYNINJACOREAPI size_t BNInsertViewData(BNBinaryView* view, uint64_t offset, const void* data, size_t len);
	BINARYNINJACOREAPI size_t BNInsertViewBuffer(BNBinaryView* view, uint64_t offset, BNDataBuffer* data);
	BINARYNINJACOREAPI size_t BNRemoveViewData(BNBinaryView* view, uint64_t offset, uint64_t len);

	BINARYNINJACOREAPI void BNNotifyDataWritten(BNBinaryView* view, uint64_t offset, size_t len);
	BINARYNINJACOREAPI void BNNotifyDataInserted(BNBinaryView* view, uint64_t offset, size_t len);
	BINARYNINJACOREAPI void BNNotifyDataRemoved(BNBinaryView* view, uint64_t offset, uint64_t len);

	BINARYNINJACOREAPI BNModificationStatus BNGetModification(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI size_t BNGetModificationArray(BNBinaryView* view, uint64_t offset, BNModificationStatus* result, size_t len);

	BINARYNINJACOREAPI bool BNIsValidOffset(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetReadable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetWritable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetExecutable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetBackedByFile(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetCodeSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetWritableSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI uint64_t BNGetNextValidOffset(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI uint64_t BNGetStartOffset(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetEndOffset(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetViewLength(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetEntryPoint(BNBinaryView* view);

	BINARYNINJACOREAPI BNArchitecture* BNGetDefaultArchitecture(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetDefaultArchitecture(BNBinaryView* view, BNArchitecture* arch);
	BINARYNINJACOREAPI BNPlatform* BNGetDefaultPlatform(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetDefaultPlatform(BNBinaryView* view, BNPlatform* platform);
	BINARYNINJACOREAPI BNEndianness BNGetDefaultEndianness(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNIsRelocatable(BNBinaryView* view);
	BINARYNINJACOREAPI size_t BNGetViewAddressSize(BNBinaryView* view);

	BINARYNINJACOREAPI bool BNIsViewModified(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNIsExecutableView(BNBinaryView* view);

	BINARYNINJACOREAPI bool BNSaveToFile(BNBinaryView* view, BNFileAccessor* file);
	BINARYNINJACOREAPI bool BNSaveToFilename(BNBinaryView* view, const char* filename);

	BINARYNINJACOREAPI void BNRegisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notify);
	BINARYNINJACOREAPI void BNUnregisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notify);

	BINARYNINJACOREAPI bool BNIsNeverBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsAlwaysBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsInvertBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsSkipAndReturnZeroPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsSkipAndReturnValuePatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNConvertToNop(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNAlwaysBranch(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNInvertBranch(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNSkipAndReturnValue(BNBinaryView* view, BNArchitecture* arch, uint64_t addr, uint64_t value);

	BINARYNINJACOREAPI size_t BNGetInstructionLength(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNFindNextData(BNBinaryView* view, uint64_t start, BNDataBuffer* data, uint64_t* result,
		BNFindFlag flags);

	BINARYNINJACOREAPI void BNAddAutoSegment(BNBinaryView* view, uint64_t start, uint64_t length,
		uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
	BINARYNINJACOREAPI void BNRemoveAutoSegment(BNBinaryView* view, uint64_t start, uint64_t length);
	BINARYNINJACOREAPI void BNAddUserSegment(BNBinaryView* view, uint64_t start, uint64_t length,
		uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
	BINARYNINJACOREAPI void BNRemoveUserSegment(BNBinaryView* view, uint64_t start, uint64_t length);
	BINARYNINJACOREAPI BNSegment* BNGetSegments(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeSegmentList(BNSegment* segments);
	BINARYNINJACOREAPI bool BNGetSegmentAt(BNBinaryView* view, uint64_t addr, BNSegment* result);
	BINARYNINJACOREAPI bool BNGetAddressForDataOffset(BNBinaryView* view, uint64_t offset, uint64_t* addr);

	BINARYNINJACOREAPI void BNAddAutoSection(BNBinaryView* view, const char* name, uint64_t start, uint64_t length,
		BNSectionSemantics semantics, const char* type, uint64_t align, uint64_t entrySize,
		const char* linkedSection, const char* infoSection, uint64_t infoData);
	BINARYNINJACOREAPI void BNRemoveAutoSection(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI void BNAddUserSection(BNBinaryView* view, const char* name, uint64_t start, uint64_t length,
		BNSectionSemantics semantics, const char* type, uint64_t align, uint64_t entrySize,
		const char* linkedSection, const char* infoSection, uint64_t infoData);
	BINARYNINJACOREAPI void BNRemoveUserSection(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNSection* BNGetSections(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNSection* BNGetSectionsAt(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeSectionList(BNSection* sections, size_t count);
	BINARYNINJACOREAPI bool BNGetSectionByName(BNBinaryView* view, const char* name, BNSection* result);
	BINARYNINJACOREAPI void BNFreeSection(BNSection* section);

	BINARYNINJACOREAPI char** BNGetUniqueSectionNames(BNBinaryView* view, const char** names, size_t count);

	BINARYNINJACOREAPI BNAddressRange* BNGetAllocatedRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeAddressRanges(BNAddressRange* ranges);

	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetGlobalPointerValue(BNBinaryView* view);

	// Raw binary data view
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataView(BNFileMetadata* file);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromBuffer(BNFileMetadata* file, BNDataBuffer* buf);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromData(BNFileMetadata* file, const void* data, size_t len);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromFilename(BNFileMetadata* file, const char* filename);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromFile(BNFileMetadata* file, BNFileAccessor* accessor);

	// Creation of new types of binary views
	BINARYNINJACOREAPI BNBinaryView* BNCreateCustomBinaryView(const char* name, BNFileMetadata* file,
		BNBinaryView* parent, BNCustomBinaryView* view);

	// Binary view type management
	BINARYNINJACOREAPI BNBinaryViewType* BNGetBinaryViewTypeByName(const char* name);
	BINARYNINJACOREAPI BNBinaryViewType** BNGetBinaryViewTypes(size_t* count);
	BINARYNINJACOREAPI BNBinaryViewType** BNGetBinaryViewTypesForData(BNBinaryView* data, size_t* count);
	BINARYNINJACOREAPI void BNFreeBinaryViewTypeList(BNBinaryViewType** types);
	BINARYNINJACOREAPI char* BNGetBinaryViewTypeName(BNBinaryViewType* type);
	BINARYNINJACOREAPI char* BNGetBinaryViewTypeLongName(BNBinaryViewType* type);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryViewOfType(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeValidForData(BNBinaryViewType* type, BNBinaryView* data);

	BINARYNINJACOREAPI BNBinaryViewType* BNRegisterBinaryViewType(const char* name, const char* longName,
	                                                              BNCustomBinaryViewType* type);

	BINARYNINJACOREAPI void BNRegisterArchitectureForViewType(BNBinaryViewType* type, uint32_t id,
		BNEndianness endian, BNArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNGetArchitectureForViewType(BNBinaryViewType* type, uint32_t id,
		BNEndianness endian);

	BINARYNINJACOREAPI void BNRegisterPlatformForViewType(BNBinaryViewType* type, uint32_t id, BNArchitecture* arch,
	                                                      BNPlatform* platform);
	BINARYNINJACOREAPI void BNRegisterDefaultPlatformForViewType(BNBinaryViewType* type, BNArchitecture* arch,
	                                                             BNPlatform* platform);
	BINARYNINJACOREAPI BNPlatform* BNGetPlatformForViewType(BNBinaryViewType* type, uint32_t id, BNArchitecture* arch);

	// Stream reader object
	BINARYNINJACOREAPI BNBinaryReader* BNCreateBinaryReader(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeBinaryReader(BNBinaryReader* stream);
	BINARYNINJACOREAPI BNEndianness BNGetBinaryReaderEndianness(BNBinaryReader* stream);
	BINARYNINJACOREAPI void BNSetBinaryReaderEndianness(BNBinaryReader* stream, BNEndianness endian);

	BINARYNINJACOREAPI bool BNReadData(BNBinaryReader* stream, void* dest, size_t len);
	BINARYNINJACOREAPI bool BNRead8(BNBinaryReader* stream, uint8_t* result);
	BINARYNINJACOREAPI bool BNRead16(BNBinaryReader* stream, uint16_t* result);
	BINARYNINJACOREAPI bool BNRead32(BNBinaryReader* stream, uint32_t* result);
	BINARYNINJACOREAPI bool BNRead64(BNBinaryReader* stream, uint64_t* result);
	BINARYNINJACOREAPI bool BNReadLE16(BNBinaryReader* stream, uint16_t* result);
	BINARYNINJACOREAPI bool BNReadLE32(BNBinaryReader* stream, uint32_t* result);
	BINARYNINJACOREAPI bool BNReadLE64(BNBinaryReader* stream, uint64_t* result);
	BINARYNINJACOREAPI bool BNReadBE16(BNBinaryReader* stream, uint16_t* result);
	BINARYNINJACOREAPI bool BNReadBE32(BNBinaryReader* stream, uint32_t* result);
	BINARYNINJACOREAPI bool BNReadBE64(BNBinaryReader* stream, uint64_t* result);

	BINARYNINJACOREAPI uint64_t BNGetReaderPosition(BNBinaryReader* stream);
	BINARYNINJACOREAPI void BNSeekBinaryReader(BNBinaryReader* stream, uint64_t offset);
	BINARYNINJACOREAPI void BNSeekBinaryReaderRelative(BNBinaryReader* stream, int64_t offset);
	BINARYNINJACOREAPI bool BNIsEndOfFile(BNBinaryReader* stream);

	// Stream writer object
	BINARYNINJACOREAPI BNBinaryWriter* BNCreateBinaryWriter(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeBinaryWriter(BNBinaryWriter* stream);
	BINARYNINJACOREAPI BNEndianness BNGetBinaryWriterEndianness(BNBinaryWriter* stream);
	BINARYNINJACOREAPI void BNSetBinaryWriterEndianness(BNBinaryWriter* stream, BNEndianness endian);

	BINARYNINJACOREAPI bool BNWriteData(BNBinaryWriter* stream, const void* src, size_t len);
	BINARYNINJACOREAPI bool BNWrite8(BNBinaryWriter* stream, uint8_t val);
	BINARYNINJACOREAPI bool BNWrite16(BNBinaryWriter* stream, uint16_t val);
	BINARYNINJACOREAPI bool BNWrite32(BNBinaryWriter* stream, uint32_t val);
	BINARYNINJACOREAPI bool BNWrite64(BNBinaryWriter* stream, uint64_t val);
	BINARYNINJACOREAPI bool BNWriteLE16(BNBinaryWriter* stream, uint16_t val);
	BINARYNINJACOREAPI bool BNWriteLE32(BNBinaryWriter* stream, uint32_t val);
	BINARYNINJACOREAPI bool BNWriteLE64(BNBinaryWriter* stream, uint64_t val);
	BINARYNINJACOREAPI bool BNWriteBE16(BNBinaryWriter* stream, uint16_t val);
	BINARYNINJACOREAPI bool BNWriteBE32(BNBinaryWriter* stream, uint32_t val);
	BINARYNINJACOREAPI bool BNWriteBE64(BNBinaryWriter* stream, uint64_t val);

	BINARYNINJACOREAPI uint64_t BNGetWriterPosition(BNBinaryWriter* stream);
	BINARYNINJACOREAPI void BNSeekBinaryWriter(BNBinaryWriter* stream, uint64_t offset);
	BINARYNINJACOREAPI void BNSeekBinaryWriterRelative(BNBinaryWriter* stream, int64_t offset);

	// Transforms
	BINARYNINJACOREAPI BNTransform* BNGetTransformByName(const char* name);
	BINARYNINJACOREAPI BNTransform** BNGetTransformTypeList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformTypeList(BNTransform** xforms);
	BINARYNINJACOREAPI BNTransform* BNRegisterTransformType(BNTransformType type, const char* name, const char* longName,
	                                                        const char* group, BNCustomTransform* xform);

	BINARYNINJACOREAPI BNTransformType BNGetTransformType(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformLongName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformGroup(BNTransform* xform);
	BINARYNINJACOREAPI BNTransformParameterInfo* BNGetTransformParameterList(BNTransform* xform, size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformParameterList(BNTransformParameterInfo* params, size_t count);
	BINARYNINJACOREAPI bool BNDecode(BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output,
	                                 BNTransformParameter* params, size_t paramCount);
	BINARYNINJACOREAPI bool BNEncode(BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output,
	                                 BNTransformParameter* params, size_t paramCount);

	// Architectures
	BINARYNINJACOREAPI BNArchitecture* BNGetArchitectureByName(const char* name);
	BINARYNINJACOREAPI BNArchitecture** BNGetArchitectureList(size_t* count);
	BINARYNINJACOREAPI void BNFreeArchitectureList(BNArchitecture** archs);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitecture(const char* name, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitectureExtension(const char* name,
		BNArchitecture* base, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI void BNAddArchitectureRedirection(BNArchitecture* arch, BNArchitecture* from, BNArchitecture* to);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitectureHook(BNArchitecture* base, BNCustomArchitecture* arch);

	BINARYNINJACOREAPI char* BNGetArchitectureName(BNArchitecture* arch);
	BINARYNINJACOREAPI BNEndianness BNGetArchitectureEndianness(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureAddressSize(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureDefaultIntegerSize(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureInstructionAlignment(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureMaxInstructionLength(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureOpcodeDisplayLength(BNArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNGetAssociatedArchitectureByAddress(BNArchitecture* arch, uint64_t* addr);
	BINARYNINJACOREAPI bool BNGetInstructionInfo(BNArchitecture* arch, const uint8_t* data, uint64_t addr,
	                                             size_t maxLen, BNInstructionInfo* result);
	BINARYNINJACOREAPI bool BNGetInstructionText(BNArchitecture* arch, const uint8_t* data, uint64_t addr,
	                                             size_t* len, BNInstructionTextToken** result, size_t* count);
	BINARYNINJACOREAPI bool BNGetInstructionLowLevelIL(BNArchitecture* arch, const uint8_t* data, uint64_t addr,
	                                                   size_t* len, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI void BNFreeInstructionText(BNInstructionTextToken* tokens, size_t count);
	BINARYNINJACOREAPI char* BNGetArchitectureRegisterName(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI char* BNGetArchitectureFlagName(BNArchitecture* arch, uint32_t flag);
	BINARYNINJACOREAPI char* BNGetArchitectureFlagWriteTypeName(BNArchitecture* arch, uint32_t flags);
	BINARYNINJACOREAPI char* BNGetArchitectureSemanticFlagClassName(BNArchitecture* arch, uint32_t semClass);
	BINARYNINJACOREAPI char* BNGetArchitectureSemanticFlagGroupName(BNArchitecture* arch, uint32_t semGroup);
	BINARYNINJACOREAPI uint32_t* BNGetFullWidthArchitectureRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureFlags(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureFlagWriteTypes(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureSemanticFlagClasses(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureSemanticFlagGroups(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNFlagRole BNGetArchitectureFlagRole(BNArchitecture* arch, uint32_t flag, uint32_t semClass);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsRequiredForFlagCondition(BNArchitecture* arch, BNLowLevelILFlagCondition cond,
		uint32_t semClass, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsRequiredForSemanticFlagGroup(BNArchitecture* arch,
		uint32_t semGroup, size_t* count);
	BINARYNINJACOREAPI BNFlagConditionForSemanticClass* BNGetArchitectureFlagConditionsForSemanticFlagGroup(BNArchitecture* arch,
		uint32_t semGroup, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlagConditionsForSemanticFlagGroup(BNFlagConditionForSemanticClass* conditions);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsWrittenByFlagWriteType(BNArchitecture* arch, uint32_t writeType,
		size_t* count);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureSemanticClassForFlagWriteType(BNArchitecture* arch, uint32_t writeType);
	BINARYNINJACOREAPI size_t BNGetArchitectureFlagWriteLowLevelIL(BNArchitecture* arch, BNLowLevelILOperation op,
		size_t size, uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
		BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetDefaultArchitectureFlagWriteLowLevelIL(BNArchitecture* arch, BNLowLevelILOperation op,
		size_t size, BNFlagRole role, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetArchitectureFlagConditionLowLevelIL(BNArchitecture* arch, BNLowLevelILFlagCondition cond,
		uint32_t semClass, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetDefaultArchitectureFlagConditionLowLevelIL(BNArchitecture* arch, BNLowLevelILFlagCondition cond,
		uint32_t semClass, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetArchitectureSemanticFlagGroupLowLevelIL(BNArchitecture* arch,
		uint32_t semGroup, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI uint32_t* BNGetModifiedArchitectureRegistersOnWrite(BNArchitecture* arch, uint32_t reg, size_t* count);
	BINARYNINJACOREAPI void BNFreeRegisterList(uint32_t* regs);
	BINARYNINJACOREAPI BNRegisterInfo BNGetArchitectureRegisterInfo(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureStackPointerRegister(BNArchitecture* arch);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureLinkRegister(BNArchitecture* arch);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureGlobalRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI bool BNIsArchitectureGlobalRegister(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureRegisterByName(BNArchitecture* arch, const char* name);

	BINARYNINJACOREAPI char* BNGetArchitectureRegisterStackName(BNArchitecture* arch, uint32_t regStack);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureRegisterStacks(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNRegisterStackInfo BNGetArchitectureRegisterStackInfo(BNArchitecture* arch, uint32_t regStack);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureRegisterStackForRegister(BNArchitecture* arch, uint32_t reg);

	BINARYNINJACOREAPI char* BNGetArchitectureIntrinsicName(BNArchitecture* arch, uint32_t intrinsic);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureIntrinsics(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNNameAndType* BNGetArchitectureIntrinsicInputs(BNArchitecture* arch, uint32_t intrinsic, size_t* count);
	BINARYNINJACOREAPI void BNFreeNameAndTypeList(BNNameAndType* nt, size_t count);
	BINARYNINJACOREAPI BNTypeWithConfidence* BNGetArchitectureIntrinsicOutputs(BNArchitecture* arch, uint32_t intrinsic,
		size_t* count);
	BINARYNINJACOREAPI void BNFreeOutputTypeList(BNTypeWithConfidence* types, size_t count);

	BINARYNINJACOREAPI bool BNAssemble(BNArchitecture* arch, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);

	BINARYNINJACOREAPI bool BNIsArchitectureNeverBranchPatchAvailable(BNArchitecture* arch, const uint8_t* data,
	                                                                  uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureAlwaysBranchPatchAvailable(BNArchitecture* arch, const uint8_t* data,
	                                                                   uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureInvertBranchPatchAvailable(BNArchitecture* arch, const uint8_t* data,
	                                                                   uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureSkipAndReturnZeroPatchAvailable(BNArchitecture* arch, const uint8_t* data,
	                                                                        uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureSkipAndReturnValuePatchAvailable(BNArchitecture* arch, const uint8_t* data,
	                                                                         uint64_t addr, size_t len);

	BINARYNINJACOREAPI bool BNArchitectureConvertToNop(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureAlwaysBranch(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureInvertBranch(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureSkipAndReturnValue(BNArchitecture* arch, uint8_t* data, uint64_t addr,
	                                                         size_t len, uint64_t value);

	BINARYNINJACOREAPI void BNRegisterArchitectureFunctionRecognizer(BNArchitecture* arch, BNFunctionRecognizer* rec);

	BINARYNINJACOREAPI bool BNIsBinaryViewTypeArchitectureConstantDefined(BNArchitecture* arch, const char* type,
	                                                                      const char* name);
	BINARYNINJACOREAPI uint64_t BNGetBinaryViewTypeArchitectureConstant(BNArchitecture* arch, const char* type,
	                                                                    const char* name, uint64_t defaultValue);
	BINARYNINJACOREAPI void BNSetBinaryViewTypeArchitectureConstant(BNArchitecture* arch, const char* type,
	                                                                const char* name, uint64_t value);

	// Analysis
	BINARYNINJACOREAPI void BNAddAnalysisOption(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI void BNAddFunctionForAnalysis(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNAddEntryPointForAnalysis(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNRemoveAnalysisFunction(BNBinaryView* view, BNFunction* func);
	BINARYNINJACOREAPI void BNCreateUserFunction(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNRemoveUserFunction(BNBinaryView* view, BNFunction* func);
	BINARYNINJACOREAPI void BNUpdateAnalysisAndWait(BNBinaryView* view);
	BINARYNINJACOREAPI void BNUpdateAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNAbortAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNIsFunctionUpdateNeeded(BNFunction* func);
	BINARYNINJACOREAPI void BNRequestAdvancedFunctionAnalysisData(BNFunction* func);
	BINARYNINJACOREAPI void BNReleaseAdvancedFunctionAnalysisData(BNFunction* func);
	BINARYNINJACOREAPI void BNReleaseAdvancedFunctionAnalysisDataMultiple(BNFunction* func, size_t count);

	BINARYNINJACOREAPI BNFunction* BNNewFunctionReference(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeFunction(BNFunction* func);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionList(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeFunctionList(BNFunction** funcs, size_t count);
	BINARYNINJACOREAPI bool BNHasFunctions(BNBinaryView* view);
	BINARYNINJACOREAPI BNFunction* BNGetAnalysisFunction(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI BNFunction* BNGetRecentAnalysisFunctionForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionsForAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNFunction* BNGetAnalysisEntryPoint(BNBinaryView* view);

	BINARYNINJACOREAPI BNBinaryView* BNGetFunctionData(BNFunction* func);
	BINARYNINJACOREAPI BNArchitecture* BNGetFunctionArchitecture(BNFunction* func);
	BINARYNINJACOREAPI BNPlatform* BNGetFunctionPlatform(BNFunction* func);
	BINARYNINJACOREAPI uint64_t BNGetFunctionStart(BNFunction* func);
	BINARYNINJACOREAPI BNSymbol* BNGetFunctionSymbol(BNFunction* func);
	BINARYNINJACOREAPI bool BNWasFunctionAutomaticallyDiscovered(BNFunction* func);
	BINARYNINJACOREAPI BNBoolWithConfidence BNCanFunctionReturn(BNFunction* func);
	BINARYNINJACOREAPI void BNSetFunctionAutoType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI void BNSetFunctionUserType(BNFunction* func, BNType* type);

	BINARYNINJACOREAPI char* BNGetFunctionComment(BNFunction* func);
	BINARYNINJACOREAPI char* BNGetCommentForAddress(BNFunction* func, uint64_t addr);
	BINARYNINJACOREAPI uint64_t* BNGetCommentedAddresses(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeAddressList(uint64_t* addrs);
	BINARYNINJACOREAPI void BNSetFunctionComment(BNFunction* func, const char* comment);
	BINARYNINJACOREAPI void BNSetCommentForAddress(BNFunction* func, uint64_t addr, const char* comment);

	BINARYNINJACOREAPI BNBasicBlock* BNNewBasicBlockReference(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNFreeBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetFunctionBasicBlockList(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeBasicBlockList(BNBasicBlock** blocks, size_t count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetFunctionBasicBlockAtAddress(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNBasicBlock* BNGetRecentBasicBlockForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlocksForAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlocksStartingAtAddress(BNBinaryView* view, uint64_t addr, size_t* count);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLowLevelIL(BNFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILExitsForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr,
	                                                              size_t* count);
	BINARYNINJACOREAPI void BNFreeILInstructionList(size_t* list);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMediumLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValue BNGetRegisterValueAtInstruction(BNFunction* func, BNArchitecture* arch,
		uint64_t addr, uint32_t reg);
	BINARYNINJACOREAPI BNRegisterValue BNGetRegisterValueAfterInstruction(BNFunction* func, BNArchitecture* arch,
		uint64_t addr, uint32_t reg);
	BINARYNINJACOREAPI BNRegisterValue BNGetStackContentsAtInstruction(BNFunction* func, BNArchitecture* arch,
		uint64_t addr, int64_t offset, size_t size);
	BINARYNINJACOREAPI BNRegisterValue BNGetStackContentsAfterInstruction(BNFunction* func, BNArchitecture* arch,
		uint64_t addr, int64_t offset, size_t size);
	BINARYNINJACOREAPI BNRegisterValue BNGetParameterValueAtInstruction(BNFunction* func, BNArchitecture* arch,
		uint64_t addr, BNType* functionType, size_t i);
	BINARYNINJACOREAPI BNRegisterValue BNGetParameterValueAtLowLevelILInstruction(BNFunction* func, size_t instr,
		BNType* functionType, size_t i);
	BINARYNINJACOREAPI void BNFreePossibleValueSet(BNPossibleValueSet* value);
	BINARYNINJACOREAPI uint32_t* BNGetRegistersReadByInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr,
	                                                             size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetRegistersWrittenByInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr,
	                                                                size_t* count);
	BINARYNINJACOREAPI BNStackVariableReference* BNGetStackVariablesReferencedByInstruction(BNFunction* func, BNArchitecture* arch,
	                                                                                        uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeStackVariableReferenceList(BNStackVariableReference* refs, size_t count);
	BINARYNINJACOREAPI BNConstantReference* BNGetConstantsReferencedByInstruction(BNFunction* func,
		BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeConstantReferenceList(BNConstantReference* refs);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLiftedIL(BNFunction* func);
	BINARYNINJACOREAPI size_t BNGetLiftedILForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t* BNGetLiftedILFlagUsesForDefinition(BNFunction* func, size_t i, uint32_t flag, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLiftedILFlagDefinitionsForUse(BNFunction* func, size_t i, uint32_t flag, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFlagsReadByLiftedILInstruction(BNFunction* func, size_t i, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFlagsWrittenByLiftedILInstruction(BNFunction* func, size_t i, size_t* count);

	BINARYNINJACOREAPI BNType* BNGetFunctionType(BNFunction* func);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetFunctionReturnType(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterSetWithConfidence BNGetFunctionReturnRegisters(BNFunction* func);
	BINARYNINJACOREAPI BNCallingConventionWithConfidence BNGetFunctionCallingConvention(BNFunction* func);
	BINARYNINJACOREAPI BNParameterVariablesWithConfidence BNGetFunctionParameterVariables(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeParameterVariables(BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI BNBoolWithConfidence BNFunctionHasVariableArguments(BNFunction* func);
	BINARYNINJACOREAPI BNSizeWithConfidence BNGetFunctionStackAdjustment(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterStackAdjustment* BNGetFunctionRegisterStackAdjustments(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeRegisterStackAdjustments(BNRegisterStackAdjustment* adjustments);
	BINARYNINJACOREAPI BNRegisterSetWithConfidence BNGetFunctionClobberedRegisters(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeRegisterSet(BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNSetAutoFunctionReturnType(BNFunction* func, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetAutoFunctionReturnRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);
	BINARYNINJACOREAPI void BNSetAutoFunctionCallingConvention(BNFunction* func, BNCallingConventionWithConfidence* convention);
	BINARYNINJACOREAPI void BNSetAutoFunctionParameterVariables(BNFunction* func, BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI void BNSetAutoFunctionHasVariableArguments(BNFunction* func, BNBoolWithConfidence* varArgs);
	BINARYNINJACOREAPI void BNSetAutoFunctionCanReturn(BNFunction* func, BNBoolWithConfidence* returns);
	BINARYNINJACOREAPI void BNSetAutoFunctionStackAdjustment(BNFunction* func, BNSizeWithConfidence* stackAdjust);
	BINARYNINJACOREAPI void BNSetAutoFunctionRegisterStackAdjustments(BNFunction* func,
		BNRegisterStackAdjustment* adjustments, size_t count);
	BINARYNINJACOREAPI void BNSetAutoFunctionClobberedRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNSetUserFunctionReturnType(BNFunction* func, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetUserFunctionReturnRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);
	BINARYNINJACOREAPI void BNSetUserFunctionCallingConvention(BNFunction* func, BNCallingConventionWithConfidence* convention);
	BINARYNINJACOREAPI void BNSetUserFunctionParameterVariables(BNFunction* func, BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI void BNSetUserFunctionHasVariableArguments(BNFunction* func, BNBoolWithConfidence* varArgs);
	BINARYNINJACOREAPI void BNSetUserFunctionCanReturn(BNFunction* func, BNBoolWithConfidence* returns);
	BINARYNINJACOREAPI void BNSetUserFunctionStackAdjustment(BNFunction* func, BNSizeWithConfidence* stackAdjust);
	BINARYNINJACOREAPI void BNSetUserFunctionRegisterStackAdjustments(BNFunction* func,
		BNRegisterStackAdjustment* adjustments, size_t count);
	BINARYNINJACOREAPI void BNSetUserFunctionClobberedRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNApplyImportedTypes(BNFunction* func, BNSymbol* sym);
	BINARYNINJACOREAPI void BNApplyAutoDiscoveredFunctionType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI bool BNFunctionHasExplicitlyDefinedType(BNFunction* func);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetFunctionTypeTokens(BNFunction* func,
		BNDisassemblySettings* settings, size_t* count);

	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetFunctionGlobalPointerValue(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetFunctionRegisterValueAtExit(BNFunction* func, uint32_t reg);

	BINARYNINJACOREAPI BNFunction* BNGetBasicBlockFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNArchitecture* BNGetBasicBlockArchitecture(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockStart(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockEnd(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockLength(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlockEdge* BNGetBasicBlockOutgoingEdges(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlockEdge* BNGetBasicBlockIncomingEdges(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI void BNFreeBasicBlockEdgeList(BNBasicBlockEdge* edges, size_t count);
	BINARYNINJACOREAPI bool BNBasicBlockHasUndeterminedOutgoingEdges(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNBasicBlockCanExit(BNBasicBlock* block);
	BINARYNINJACOREAPI size_t BNGetBasicBlockIndex(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominators(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockStrictDominators(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockImmediateDominator(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominatorTreeChildren(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominanceFrontier(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockIteratedDominanceFrontier(BNBasicBlock** blocks,
		size_t incomingCount, size_t* outputCount);
	BINARYNINJACOREAPI bool BNIsILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsLowLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsMediumLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetBasicBlockLowLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetBasicBlockMediumLevelILFunction(BNBasicBlock* block);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetBasicBlockDisassemblyText(BNBasicBlock* block,
		BNDisassemblySettings* settings, size_t* count);
	BINARYNINJACOREAPI void BNFreeDisassemblyTextLines(BNDisassemblyTextLine* lines, size_t count);

	BINARYNINJACOREAPI void BNMarkFunctionAsRecentlyUsed(BNFunction* func);
	BINARYNINJACOREAPI void BNMarkBasicBlockAsRecentlyUsed(BNBasicBlock* block);

	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferences(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferencesInRange(BNBinaryView* view, uint64_t addr,
	                                                                 uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNFreeCodeReferences(BNReferenceSource* refs, size_t count);

	BINARYNINJACOREAPI void BNRegisterGlobalFunctionRecognizer(BNFunctionRecognizer* rec);

	BINARYNINJACOREAPI BNStringReference* BNGetStrings(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNStringReference* BNGetStringsInRange(BNBinaryView* view, uint64_t start,
	                                                          uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNFreeStringReferenceList(BNStringReference* strings);

	BINARYNINJACOREAPI BNVariableNameAndType* BNGetStackLayout(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeVariableNameAndTypeList(BNVariableNameAndType* vars, size_t count);
	BINARYNINJACOREAPI void BNCreateAutoStackVariable(BNFunction* func, int64_t offset,
		BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNCreateUserStackVariable(BNFunction* func, int64_t offset,
		BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNDeleteAutoStackVariable(BNFunction* func, int64_t offset);
	BINARYNINJACOREAPI void BNDeleteUserStackVariable(BNFunction* func, int64_t offset);
	BINARYNINJACOREAPI bool BNGetStackVariableAtFrameOffset(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		int64_t offset, BNVariableNameAndType* var);
	BINARYNINJACOREAPI void BNFreeVariableNameAndType(BNVariableNameAndType* var);

	BINARYNINJACOREAPI BNVariableNameAndType* BNGetFunctionVariables(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNCreateAutoVariable(BNFunction* func, const BNVariable* var, BNTypeWithConfidence* type,
		const char* name, bool ignoreDisjointUses);
	BINARYNINJACOREAPI void BNCreateUserVariable(BNFunction* func, const BNVariable* var, BNTypeWithConfidence* type,
		const char* name, bool ignoreDisjointUses);
	BINARYNINJACOREAPI void BNDeleteAutoVariable(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI void BNDeleteUserVariable(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetVariableType(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI char* BNGetVariableName(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI uint64_t BNToVariableIdentifier(const BNVariable* var);
	BINARYNINJACOREAPI BNVariable BNFromVariableIdentifier(uint64_t id);

	BINARYNINJACOREAPI void BNSetAutoIndirectBranches(BNFunction* func, BNArchitecture* sourceArch, uint64_t source,
	                                                  BNArchitectureAndAddress* branches, size_t count);
	BINARYNINJACOREAPI void BNSetUserIndirectBranches(BNFunction* func, BNArchitecture* sourceArch, uint64_t source,
	                                                  BNArchitectureAndAddress* branches, size_t count);

	BINARYNINJACOREAPI BNIndirectBranchInfo* BNGetIndirectBranches(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNIndirectBranchInfo* BNGetIndirectBranchesAt(BNFunction* func, BNArchitecture* arch,
	                                                                 uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeIndirectBranchList(BNIndirectBranchInfo* branches);

	BINARYNINJACOREAPI void BNSetAutoCallStackAdjustment(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		size_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetUserCallStackAdjustment(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		size_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetAutoCallRegisterStackAdjustment(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		BNRegisterStackAdjustment* adjust, size_t count);
	BINARYNINJACOREAPI void BNSetUserCallRegisterStackAdjustment(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		BNRegisterStackAdjustment* adjust, size_t count);
	BINARYNINJACOREAPI void BNSetAutoCallRegisterStackAdjustmentForRegisterStack(BNFunction* func,
		BNArchitecture* arch, uint64_t addr, uint32_t regStack, int32_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetUserCallRegisterStackAdjustmentForRegisterStack(BNFunction* func,
		BNArchitecture* arch, uint64_t addr, uint32_t regStack, int32_t adjust, uint8_t confidence);

	BINARYNINJACOREAPI BNSizeWithConfidence BNGetCallStackAdjustment(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNRegisterStackAdjustment* BNGetCallRegisterStackAdjustment(BNFunction* func,
		BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNRegisterStackAdjustment BNGetCallRegisterStackAdjustmentForRegisterStack(BNFunction* func,
		BNArchitecture* arch, uint64_t addr, uint32_t regStack);

	BINARYNINJACOREAPI BNInstructionTextLine* BNGetFunctionBlockAnnotations(BNFunction* func, BNArchitecture* arch,
		uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeInstructionTextLines(BNInstructionTextLine* lines, size_t count);

	BINARYNINJACOREAPI BNIntegerDisplayType BNGetIntegerConstantDisplayType(BNFunction* func, BNArchitecture* arch,
		uint64_t instrAddr, uint64_t value, size_t operand);
	BINARYNINJACOREAPI void BNSetIntegerConstantDisplayType(BNFunction* func, BNArchitecture* arch,
		uint64_t instrAddr, uint64_t value, size_t operand, BNIntegerDisplayType type);

	BINARYNINJACOREAPI bool BNIsFunctionTooLarge(BNFunction* func);
	BINARYNINJACOREAPI bool BNIsFunctionAnalysisSkipped(BNFunction* func);
	BINARYNINJACOREAPI BNFunctionAnalysisSkipOverride BNGetFunctionAnalysisSkipOverride(BNFunction* func);
	BINARYNINJACOREAPI void BNSetFunctionAnalysisSkipOverride(BNFunction* func, BNFunctionAnalysisSkipOverride skip);

	BINARYNINJACOREAPI uint64_t BNGetMaxFunctionSizeForAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetMaxFunctionSizeForAnalysis(BNBinaryView* view, uint64_t size);

	BINARYNINJACOREAPI BNAnalysisCompletionEvent* BNAddAnalysisCompletionEvent(BNBinaryView* view, void* ctxt,
		void (*callback)(void* ctxt));
	BINARYNINJACOREAPI BNAnalysisCompletionEvent* BNNewAnalysisCompletionEventReference(BNAnalysisCompletionEvent* event);
	BINARYNINJACOREAPI void BNFreeAnalysisCompletionEvent(BNAnalysisCompletionEvent* event);
	BINARYNINJACOREAPI void BNCancelAnalysisCompletionEvent(BNAnalysisCompletionEvent* event);

	BINARYNINJACOREAPI BNAnalysisProgress BNGetAnalysisProgress(BNBinaryView* view);
	BINARYNINJACOREAPI BNBackgroundTask* BNGetBackgroundAnalysisTask(BNBinaryView* view);

	BINARYNINJACOREAPI uint64_t BNGetNextFunctionStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextBasicBlockStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextDataAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextDataVariableAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousFunctionStartBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousBasicBlockStartBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousBasicBlockEndBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousDataBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousDataVariableBeforeAddress(BNBinaryView* view, uint64_t addr);

	BINARYNINJACOREAPI BNLinearDisassemblyPosition BNGetLinearDisassemblyPositionForAddress(BNBinaryView* view,
		uint64_t addr, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNFreeLinearDisassemblyPosition(BNLinearDisassemblyPosition* pos);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetPreviousLinearDisassemblyLines(BNBinaryView* view,
		BNLinearDisassemblyPosition* pos, BNDisassemblySettings* settings, size_t* count);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetNextLinearDisassemblyLines(BNBinaryView* view,
		BNLinearDisassemblyPosition* pos, BNDisassemblySettings* settings, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearDisassemblyLines(BNLinearDisassemblyLine* lines, size_t count);

	BINARYNINJACOREAPI void BNDefineDataVariable(BNBinaryView* view, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNDefineUserDataVariable(BNBinaryView* view, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNUndefineDataVariable(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI void BNUndefineUserDataVariable(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNDataVariable* BNGetDataVariables(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeDataVariables(BNDataVariable* vars, size_t count);
	BINARYNINJACOREAPI bool BNGetDataVariableAtAddress(BNBinaryView* view, uint64_t addr, BNDataVariable* var);

	BINARYNINJACOREAPI bool BNParseTypeString(BNBinaryView* view, const char* text,
		BNQualifiedNameAndType* result, char** errors);
	BINARYNINJACOREAPI void BNFreeQualifiedNameAndType(BNQualifiedNameAndType* obj);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetAnalysisTypeList(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeList(BNQualifiedNameAndType* types, size_t count);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeByName(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI char* BNGetAnalysisTypeId(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNGetAnalysisTypeNameById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI bool BNIsAnalysisTypeAutoDefined(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNDefineAnalysisType(BNBinaryView* view, const char* id,
		BNQualifiedName* defaultName, BNType* type);
	BINARYNINJACOREAPI void BNDefineUserAnalysisType(BNBinaryView* view, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNUndefineAnalysisType(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI void BNUndefineUserAnalysisType(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNRenameAnalysisType(BNBinaryView* view, BNQualifiedName* oldName, BNQualifiedName* newName);
	BINARYNINJACOREAPI char* BNGenerateAutoTypeId(const char* source, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGenerateAutoPlatformTypeId(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGenerateAutoDemangledTypeId(BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoPlatformTypeIdSource(BNPlatform* platform);
	BINARYNINJACOREAPI char* BNGetAutoDemangledTypeIdSource(void);
	BINARYNINJACOREAPI char* BNGenerateAutoDebugTypeId(BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoDebugTypeIdSource(void);

	BINARYNINJACOREAPI void BNRegisterPlatformTypes(BNBinaryView* view, BNPlatform* platform);

	BINARYNINJACOREAPI void BNReanalyzeAllFunctions(BNBinaryView* view);
	BINARYNINJACOREAPI void BNReanalyzeFunction(BNFunction* func);

	BINARYNINJACOREAPI BNHighlightColor BNGetInstructionHighlight(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNSetAutoInstructionHighlight(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		BNHighlightColor color);
	BINARYNINJACOREAPI void BNSetUserInstructionHighlight(BNFunction* func, BNArchitecture* arch, uint64_t addr,
		BNHighlightColor color);
	BINARYNINJACOREAPI BNHighlightColor BNGetBasicBlockHighlight(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetAutoBasicBlockHighlight(BNBasicBlock* block, BNHighlightColor color);
	BINARYNINJACOREAPI void BNSetUserBasicBlockHighlight(BNBasicBlock* block, BNHighlightColor color);

	BINARYNINJACOREAPI BNPerformanceInfo* BNGetFunctionAnalysisPerformanceInfo(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeAnalysisPerformanceInfo(BNPerformanceInfo* info, size_t count);

	// Disassembly settings
	BINARYNINJACOREAPI BNDisassemblySettings* BNCreateDisassemblySettings(void);
	BINARYNINJACOREAPI BNDisassemblySettings* BNNewDisassemblySettingsReference(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNFreeDisassemblySettings(BNDisassemblySettings* settings);

	BINARYNINJACOREAPI bool BNIsDisassemblySettingsOptionSet(BNDisassemblySettings* settings,
		BNDisassemblyOption option);
	BINARYNINJACOREAPI void BNSetDisassemblySettingsOption(BNDisassemblySettings* settings,
		BNDisassemblyOption option, bool state);

	BINARYNINJACOREAPI size_t BNGetDisassemblyWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyWidth(BNDisassemblySettings* settings, size_t width);
	BINARYNINJACOREAPI size_t BNGetDisassemblyMaximumSymbolWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyMaximumSymbolWidth(BNDisassemblySettings* settings, size_t width);

	// Function graph
	BINARYNINJACOREAPI BNFunctionGraph* BNCreateFunctionGraph(BNFunction* func);
	BINARYNINJACOREAPI BNFunctionGraph* BNNewFunctionGraphReference(BNFunctionGraph* graph);
	BINARYNINJACOREAPI void BNFreeFunctionGraph(BNFunctionGraph* graph);
	BINARYNINJACOREAPI BNFunction* BNGetFunctionForFunctionGraph(BNFunctionGraph* graph);

	BINARYNINJACOREAPI int BNGetHorizontalFunctionGraphBlockMargin(BNFunctionGraph* graph);
	BINARYNINJACOREAPI int BNGetVerticalFunctionGraphBlockMargin(BNFunctionGraph* graph);
	BINARYNINJACOREAPI void BNSetFunctionGraphBlockMargins(BNFunctionGraph* graph, int horiz, int vert);

	BINARYNINJACOREAPI BNDisassemblySettings* BNGetFunctionGraphSettings(BNFunctionGraph* graph);

	BINARYNINJACOREAPI void BNStartFunctionGraphLayout(BNFunctionGraph* graph, BNFunctionGraphType type);
	BINARYNINJACOREAPI bool BNIsFunctionGraphLayoutComplete(BNFunctionGraph* graph);
	BINARYNINJACOREAPI void BNSetFunctionGraphCompleteCallback(BNFunctionGraph* graph, void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI void BNAbortFunctionGraph(BNFunctionGraph* graph);
	BINARYNINJACOREAPI BNFunctionGraphType BNGetFunctionGraphType(BNFunctionGraph* graph);
	BINARYNINJACOREAPI bool BNIsILFunctionGraph(BNFunctionGraph* graph);
	BINARYNINJACOREAPI bool BNIsLowLevelILFunctionGraph(BNFunctionGraph* graph);
	BINARYNINJACOREAPI bool BNIsMediumLevelILFunctionGraph(BNFunctionGraph* graph);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionGraphLowLevelILFunction(BNFunctionGraph* graph);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionGraphMediumLevelILFunction(BNFunctionGraph* graph);

	BINARYNINJACOREAPI BNFunctionGraphBlock** BNGetFunctionGraphBlocks(BNFunctionGraph* graph, size_t* count);
	BINARYNINJACOREAPI BNFunctionGraphBlock** BNGetFunctionGraphBlocksInRegion(
		BNFunctionGraph* graph, int left, int top, int right, int bottom, size_t* count);
	BINARYNINJACOREAPI void BNFreeFunctionGraphBlockList(BNFunctionGraphBlock** blocks, size_t count);
	BINARYNINJACOREAPI bool BNFunctionGraphHasBlocks(BNFunctionGraph* graph);

	BINARYNINJACOREAPI int BNGetFunctionGraphWidth(BNFunctionGraph* graph);
	BINARYNINJACOREAPI int BNGetFunctionGraphHeight(BNFunctionGraph* graph);

	BINARYNINJACOREAPI bool BNIsFunctionGraphOptionSet(BNFunctionGraph* graph, BNDisassemblyOption option);
	BINARYNINJACOREAPI void BNSetFunctionGraphOption(BNFunctionGraph* graph, BNDisassemblyOption option, bool state);

	BINARYNINJACOREAPI BNFunctionGraphBlock* BNNewFunctionGraphBlockReference(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI void BNFreeFunctionGraphBlock(BNFunctionGraphBlock* block);

	BINARYNINJACOREAPI BNBasicBlock* BNGetFunctionGraphBasicBlock(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI BNArchitecture* BNGetFunctionGraphBlockArchitecture(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetFunctionGraphBlockStart(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetFunctionGraphBlockEnd(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI int BNGetFunctionGraphBlockX(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI int BNGetFunctionGraphBlockY(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI int BNGetFunctionGraphBlockWidth(BNFunctionGraphBlock* block);
	BINARYNINJACOREAPI int BNGetFunctionGraphBlockHeight(BNFunctionGraphBlock* block);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetFunctionGraphBlockLines(BNFunctionGraphBlock* block, size_t* count);
	BINARYNINJACOREAPI BNFunctionGraphEdge* BNGetFunctionGraphBlockOutgoingEdges(BNFunctionGraphBlock* block, size_t* count);
	BINARYNINJACOREAPI void BNFreeFunctionGraphBlockOutgoingEdgeList(BNFunctionGraphEdge* edges, size_t count);

	// Symbols
	BINARYNINJACOREAPI BNSymbol* BNCreateSymbol(BNSymbolType type, const char* shortName, const char* fullName,
	                                            const char* rawName, uint64_t addr);
	BINARYNINJACOREAPI BNSymbol* BNNewSymbolReference(BNSymbol* sym);
	BINARYNINJACOREAPI void BNFreeSymbol(BNSymbol* sym);
	BINARYNINJACOREAPI BNSymbolType BNGetSymbolType(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolShortName(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolFullName(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolRawName(BNSymbol* sym);
	BINARYNINJACOREAPI uint64_t BNGetSymbolAddress(BNSymbol* sym);
	BINARYNINJACOREAPI bool BNIsSymbolAutoDefined(BNSymbol* sym);
	BINARYNINJACOREAPI void BNSetSymbolAutoDefined(BNSymbol* sym, bool val);

	BINARYNINJACOREAPI BNSymbol* BNGetSymbolByAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNSymbol* BNGetSymbolByRawName(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsByName(BNBinaryView* view, const char* name, size_t* count);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbols(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsInRange(BNBinaryView* view, uint64_t start, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsOfType(BNBinaryView* view, BNSymbolType type, size_t* count);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsOfTypeInRange(BNBinaryView* view, BNSymbolType type,
	                                                        uint64_t start, uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNFreeSymbolList(BNSymbol** syms, size_t count);

	BINARYNINJACOREAPI void BNDefineAutoSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNUndefineAutoSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNDefineUserSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNUndefineUserSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNDefineImportedFunction(BNBinaryView* view, BNSymbol* importAddressSym, BNFunction* func);
	BINARYNINJACOREAPI void BNDefineAutoSymbolAndVariableOrFunction(BNBinaryView* view, BNPlatform* platform,
		BNSymbol* sym, BNType* type);

	BINARYNINJACOREAPI BNSymbol* BNImportedFunctionFromImportAddressSymbol(BNSymbol* sym, uint64_t addr);

	// Low-level IL
	BINARYNINJACOREAPI BNLowLevelILFunction* BNCreateLowLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNNewLowLevelILFunctionReference(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeLowLevelILFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetLowLevelILOwnerFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNLowLevelILGetCurrentAddress(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNLowLevelILSetCurrentAddress(BNLowLevelILFunction* func,
		BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNLowLevelILGetInstructionStart(BNLowLevelILFunction* func,
		BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNLowLevelILClearIndirectBranches(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNLowLevelILSetIndirectBranches(BNLowLevelILFunction* func, BNArchitectureAndAddress* branches,
		size_t count);
	BINARYNINJACOREAPI size_t BNLowLevelILAddExpr(BNLowLevelILFunction* func, BNLowLevelILOperation operation, size_t size,
		uint32_t flags, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
	BINARYNINJACOREAPI size_t BNLowLevelILAddExprWithLocation(BNLowLevelILFunction* func, uint64_t addr, uint32_t sourceOperand,
		BNLowLevelILOperation operation, size_t size, uint32_t flags, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
	BINARYNINJACOREAPI void BNLowLevelILSetExprSourceOperand(BNLowLevelILFunction* func, size_t expr, uint32_t operand);
	BINARYNINJACOREAPI size_t BNLowLevelILAddInstruction(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNLowLevelILGoto(BNLowLevelILFunction* func, BNLowLevelILLabel* label);
	BINARYNINJACOREAPI size_t BNLowLevelILGotoWithLocation(BNLowLevelILFunction* func, BNLowLevelILLabel* label,
		uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI size_t BNLowLevelILIf(BNLowLevelILFunction* func, uint64_t op, BNLowLevelILLabel* t, BNLowLevelILLabel* f);
	BINARYNINJACOREAPI size_t BNLowLevelILIfWithLocation(BNLowLevelILFunction* func, uint64_t op,
		BNLowLevelILLabel* t, BNLowLevelILLabel* f, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI void BNLowLevelILInitLabel(BNLowLevelILLabel* label);
	BINARYNINJACOREAPI void BNLowLevelILMarkLabel(BNLowLevelILFunction* func, BNLowLevelILLabel* label);
	BINARYNINJACOREAPI void BNFinalizeLowLevelILFunction(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI void BNPrepareToCopyLowLevelILFunction(BNLowLevelILFunction* func, BNLowLevelILFunction* src);
	BINARYNINJACOREAPI void BNPrepareToCopyLowLevelILBasicBlock(BNLowLevelILFunction* func, BNBasicBlock* block);
	BINARYNINJACOREAPI BNLowLevelILLabel* BNGetLabelForLowLevelILSourceInstruction(BNLowLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNLowLevelILAddLabelList(BNLowLevelILFunction* func, BNLowLevelILLabel** labels, size_t count);
	BINARYNINJACOREAPI size_t BNLowLevelILAddOperandList(BNLowLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNLowLevelILGetOperandList(BNLowLevelILFunction* func, size_t expr, size_t operand,
	                                                        size_t* count);
	BINARYNINJACOREAPI void BNLowLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNLowLevelILInstruction BNGetLowLevelILByIndex(BNLowLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetLowLevelILIndexForInstruction(BNLowLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionForExpr(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionCount(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILExprCount(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI void BNUpdateLowLevelILOperand(BNLowLevelILFunction* func, size_t instr,
		size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNReplaceLowLevelILExpr(BNLowLevelILFunction* func, size_t expr, size_t newExpr);

	BINARYNINJACOREAPI void BNAddLowLevelILLabelForAddress(BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNLowLevelILLabel* BNGetLowLevelILLabelForAddress(BNLowLevelILFunction* func,
	                                                                     BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNGetLowLevelILExprText(BNLowLevelILFunction* func, BNArchitecture* arch, size_t i,
		BNInstructionTextToken** tokens, size_t* count);
	BINARYNINJACOREAPI bool BNGetLowLevelILInstructionText(BNLowLevelILFunction* il, BNFunction* func,
		BNArchitecture* arch, size_t i, BNInstructionTextToken** tokens, size_t* count);

	BINARYNINJACOREAPI uint32_t BNGetLowLevelILTemporaryRegisterCount(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI uint32_t BNGetLowLevelILTemporaryFlagCount(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI BNBasicBlock** BNGetLowLevelILBasicBlockList(BNLowLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILSSAForm(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILNonSSAForm(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILNonSSAInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAExprIndex(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILNonSSAExprIndex(BNLowLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetLowLevelILSSARegisterDefinition(BNLowLevelILFunction* func,
		uint32_t reg, size_t version);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAFlagDefinition(BNLowLevelILFunction* func,
		uint32_t reg, size_t version);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAMemoryDefinition(BNLowLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSARegisterUses(BNLowLevelILFunction* func,
		uint32_t reg, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSAFlagUses(BNLowLevelILFunction* func, uint32_t reg, size_t version,
		size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSAMemoryUses(BNLowLevelILFunction* func, size_t version, size_t* count);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILSSARegisterValue(BNLowLevelILFunction* func,
		uint32_t reg, size_t version);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILSSAFlagValue(BNLowLevelILFunction* func,
		uint32_t flag, size_t version);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILExprValue(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleExprValues(BNLowLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILRegisterValueAtInstruction(BNLowLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILRegisterValueAfterInstruction(BNLowLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleRegisterValuesAtInstruction(BNLowLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleRegisterValuesAfterInstruction(BNLowLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILFlagValueAtInstruction(BNLowLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILFlagValueAfterInstruction(BNLowLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleFlagValuesAtInstruction(BNLowLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleFlagValuesAfterInstruction(BNLowLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILStackContentsAtInstruction(BNLowLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILStackContentsAfterInstruction(BNLowLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleStackContentsAtInstruction(BNLowLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleStackContentsAfterInstruction(BNLowLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILForLowLevelIL(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMappedMediumLevelIL(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprIndex(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMappedMediumLevelILInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMappedMediumLevelILExprIndex(BNLowLevelILFunction* func, size_t expr);

	// Medium-level IL
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNCreateMediumLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNNewMediumLevelILFunctionReference(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeMediumLevelILFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetMediumLevelILOwnerFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNMediumLevelILGetCurrentAddress(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNMediumLevelILSetCurrentAddress(BNMediumLevelILFunction* func,
		BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNMediumLevelILGetInstructionStart(BNMediumLevelILFunction* func,
		BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddExpr(BNMediumLevelILFunction* func, BNMediumLevelILOperation operation,
		size_t size, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddExprWithLocation(BNMediumLevelILFunction* func,
		BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddInstruction(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNMediumLevelILGoto(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI size_t BNMediumLevelILGotoWithLocation(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label,
		uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI size_t BNMediumLevelILIf(BNMediumLevelILFunction* func, uint64_t op,
		BNMediumLevelILLabel* t, BNMediumLevelILLabel* f);
	BINARYNINJACOREAPI size_t BNMediumLevelILIfWithLocation(BNMediumLevelILFunction* func, uint64_t op,
		BNMediumLevelILLabel* t, BNMediumLevelILLabel* f, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI void BNMediumLevelILInitLabel(BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI void BNMediumLevelILMarkLabel(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI void BNFinalizeMediumLevelILFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateMediumLevelILSSAForm(BNMediumLevelILFunction* func,
		bool analyzeConditionals, bool handleAliases, BNVariable* knownNotAliases, size_t knownNotAliasCount,
		BNVariable* knownAliases, size_t knownAliasCount);

	BINARYNINJACOREAPI void BNPrepareToCopyMediumLevelILFunction(BNMediumLevelILFunction* func,
		BNMediumLevelILFunction* src);
	BINARYNINJACOREAPI void BNPrepareToCopyMediumLevelILBasicBlock(BNMediumLevelILFunction* func, BNBasicBlock* block);
	BINARYNINJACOREAPI BNMediumLevelILLabel* BNGetLabelForMediumLevelILSourceInstruction(BNMediumLevelILFunction* func,
		size_t instr);

	BINARYNINJACOREAPI size_t BNMediumLevelILAddLabelList(BNMediumLevelILFunction* func,
		BNMediumLevelILLabel** labels, size_t count);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddOperandList(BNMediumLevelILFunction* func,
		uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNMediumLevelILGetOperandList(BNMediumLevelILFunction* func, size_t expr,
		size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNMediumLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNMediumLevelILInstruction BNGetMediumLevelILByIndex(BNMediumLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILIndexForInstruction(BNMediumLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionForExpr(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionCount(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprCount(BNMediumLevelILFunction* func);

	BINARYNINJACOREAPI void BNUpdateMediumLevelILOperand(BNMediumLevelILFunction* func, size_t instr,
		size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNMarkMediumLevelILInstructionForRemoval(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI void BNReplaceMediumLevelILInstruction(BNMediumLevelILFunction* func, size_t instr, size_t expr);
	BINARYNINJACOREAPI void BNReplaceMediumLevelILExpr(BNMediumLevelILFunction* func, size_t expr, size_t newExpr);

	BINARYNINJACOREAPI bool BNGetMediumLevelILExprText(BNMediumLevelILFunction* func, BNArchitecture* arch, size_t i,
		BNInstructionTextToken** tokens, size_t* count);
	BINARYNINJACOREAPI bool BNGetMediumLevelILInstructionText(BNMediumLevelILFunction* il, BNFunction* func,
		BNArchitecture* arch, size_t i, BNInstructionTextToken** tokens, size_t* count);

	BINARYNINJACOREAPI BNBasicBlock** BNGetMediumLevelILBasicBlockList(BNMediumLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILSSAForm(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILNonSSAForm(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILNonSSAInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILNonSSAExprIndex(BNMediumLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAVarDefinition(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t version);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAMemoryDefinition(BNMediumLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILSSAVarUses(BNMediumLevelILFunction* func, const BNVariable* var,
		size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILSSAMemoryUses(BNMediumLevelILFunction* func,
		size_t version, size_t* count);
	BINARYNINJACOREAPI bool BNIsMediumLevelILSSAVarLive(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t version);

	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableDefinitions(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableUses(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t* count);

	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILSSAVarValue(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t version);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILExprValue(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleSSAVarValues(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t version, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleExprValues(BNMediumLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAVarVersionAtILInstruction(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAMemoryVersionAtILInstruction(BNMediumLevelILFunction* func,
		size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForRegisterAtInstruction(BNMediumLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForFlagAtInstruction(BNMediumLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForStackLocationAtInstruction(BNMediumLevelILFunction* func,
		int64_t offset, size_t instr);

	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILRegisterValueAtInstruction(BNMediumLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILRegisterValueAfterInstruction(BNMediumLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleRegisterValuesAtInstruction(BNMediumLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(BNMediumLevelILFunction* func,
		uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILFlagValueAtInstruction(BNMediumLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILFlagValueAfterInstruction(BNMediumLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleFlagValuesAtInstruction(BNMediumLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleFlagValuesAfterInstruction(BNMediumLevelILFunction* func,
		uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILStackContentsAtInstruction(BNMediumLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILStackContentsAfterInstruction(BNMediumLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleStackContentsAtInstruction(BNMediumLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleStackContentsAfterInstruction(BNMediumLevelILFunction* func,
		int64_t offset, size_t len, size_t instr);

	BINARYNINJACOREAPI BNILBranchDependence BNGetMediumLevelILBranchDependence(BNMediumLevelILFunction* func,
		size_t curInstr, size_t branchInstr);
	BINARYNINJACOREAPI BNILBranchInstructionAndDependence* BNGetAllMediumLevelILBranchDependence(
		BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreeILBranchDependenceList(BNILBranchInstructionAndDependence* branches);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILForMediumLevelIL(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILExprIndex(BNMediumLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetMediumLevelILExprType(BNMediumLevelILFunction* func, size_t expr);

	// Types
	BINARYNINJACOREAPI BNType* BNCreateVoidType(void);
	BINARYNINJACOREAPI BNType* BNCreateBoolType(void);
	BINARYNINJACOREAPI BNType* BNCreateIntegerType(size_t width, BNBoolWithConfidence* sign, const char* altName);
	BINARYNINJACOREAPI BNType* BNCreateFloatType(size_t width, const char* altName);
	BINARYNINJACOREAPI BNType* BNCreateStructureType(BNStructure* s);
	BINARYNINJACOREAPI BNType* BNCreateEnumerationType(BNArchitecture* arch, BNEnumeration* e, size_t width, bool isSigned);
	BINARYNINJACOREAPI BNType* BNCreatePointerType(BNArchitecture* arch, BNTypeWithConfidence* type,
		BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl, BNReferenceType refType);
	BINARYNINJACOREAPI BNType* BNCreatePointerTypeOfWidth(size_t width, BNTypeWithConfidence* type,
		BNBoolWithConfidence* cnst, BNBoolWithConfidence* vltl, BNReferenceType refType);
	BINARYNINJACOREAPI BNType* BNCreateArrayType(BNTypeWithConfidence* type, uint64_t elem);
	BINARYNINJACOREAPI BNType* BNCreateFunctionType(BNTypeWithConfidence* returnValue,
		BNCallingConventionWithConfidence* callingConvention, BNFunctionParameter* params,
		size_t paramCount, BNBoolWithConfidence* varArg, BNSizeWithConfidence* stackAdjust);
	BINARYNINJACOREAPI BNType* BNNewTypeReference(BNType* type);
	BINARYNINJACOREAPI BNType* BNDuplicateType(BNType* type);
	BINARYNINJACOREAPI char* BNGetTypeAndName(BNType* type, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNFreeType(BNType* type);

	BINARYNINJACOREAPI BNQualifiedName BNTypeGetTypeName(BNType* nt);
	BINARYNINJACOREAPI void BNTypeSetTypeName(BNType* type, BNQualifiedName* name);
	BINARYNINJACOREAPI BNTypeClass BNGetTypeClass(BNType* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeWidth(BNType* type);
	BINARYNINJACOREAPI size_t BNGetTypeAlignment(BNType* type);
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
	BINARYNINJACOREAPI void BNSetFunctionTypeCanReturn(BNType* type, BNBoolWithConfidence* canReturn);
	BINARYNINJACOREAPI BNMemberScopeWithConfidence BNTypeGetMemberScope(BNType* type);
	BINARYNINJACOREAPI void BNTypeSetMemberScope(BNType* type, BNMemberScopeWithConfidence* scope);
	BINARYNINJACOREAPI BNMemberAccessWithConfidence BNTypeGetMemberAccess(BNType* type);
	BINARYNINJACOREAPI void BNTypeSetMemberAccess(BNType* type, BNMemberAccessWithConfidence* access);
	BINARYNINJACOREAPI void BNTypeSetConst(BNType* type, BNBoolWithConfidence* cnst);
	BINARYNINJACOREAPI void BNTypeSetVolatile(BNType* type, BNBoolWithConfidence* vltl);
	BINARYNINJACOREAPI BNSizeWithConfidence BNGetTypeStackAdjustment(BNType* type);

	BINARYNINJACOREAPI char* BNGetTypeString(BNType* type, BNPlatform* platform);
	BINARYNINJACOREAPI char* BNGetTypeStringBeforeName(BNType* type, BNPlatform* platform);
	BINARYNINJACOREAPI char* BNGetTypeStringAfterName(BNType* type, BNPlatform* platform);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeTokens(BNType* type, BNPlatform* platform,
		uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeTokensBeforeName(BNType* type, BNPlatform* platform,
		uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeTokensAfterName(BNType* type, BNPlatform* platform,
		uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI void BNFreeTokenList(BNInstructionTextToken* tokens, size_t count);

	BINARYNINJACOREAPI BNType* BNCreateNamedTypeReference(BNNamedTypeReference* nt, size_t width, size_t align);
	BINARYNINJACOREAPI BNType* BNCreateNamedTypeReferenceFromTypeAndId(const char* id, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI BNType* BNCreateNamedTypeReferenceFromType(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNNamedTypeReference* BNCreateNamedType(void);
	BINARYNINJACOREAPI void BNSetTypeReferenceClass(BNNamedTypeReference* nt, BNNamedTypeReferenceClass cls);
	BINARYNINJACOREAPI BNNamedTypeReferenceClass BNGetTypeReferenceClass(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI void BNSetTypeReferenceId(BNNamedTypeReference* nt, const char* id);
	BINARYNINJACOREAPI char* BNGetTypeReferenceId(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI void BNSetTypeReferenceName(BNNamedTypeReference* nt, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNGetTypeReferenceName(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI void BNFreeQualifiedName(BNQualifiedName* name);
	BINARYNINJACOREAPI void BNFreeNamedTypeReference(BNNamedTypeReference* nt);
	BINARYNINJACOREAPI BNNamedTypeReference* BNNewNamedTypeReference(BNNamedTypeReference* nt);

	BINARYNINJACOREAPI BNStructure* BNCreateStructure(void);
	BINARYNINJACOREAPI BNStructure* BNCreateStructureWithOptions(BNStructureType type, bool packed);
	BINARYNINJACOREAPI BNStructure* BNNewStructureReference(BNStructure* s);
	BINARYNINJACOREAPI void BNFreeStructure(BNStructure* s);

	BINARYNINJACOREAPI BNStructureMember* BNGetStructureMembers(BNStructure* s, size_t* count);
	BINARYNINJACOREAPI void BNFreeStructureMemberList(BNStructureMember* members, size_t count);
	BINARYNINJACOREAPI uint64_t BNGetStructureWidth(BNStructure* s);
	BINARYNINJACOREAPI void BNSetStructureWidth(BNStructure* s, uint64_t width);
	BINARYNINJACOREAPI size_t BNGetStructureAlignment(BNStructure* s);
	BINARYNINJACOREAPI void BNSetStructureAlignment(BNStructure* s, size_t align);
	BINARYNINJACOREAPI bool BNIsStructurePacked(BNStructure* s);
	BINARYNINJACOREAPI void BNSetStructurePacked(BNStructure* s, bool packed);
	BINARYNINJACOREAPI bool BNIsStructureUnion(BNStructure* s);
	BINARYNINJACOREAPI void BNSetStructureType(BNStructure* s, BNStructureType type);
	BINARYNINJACOREAPI BNStructureType BNGetStructureType(BNStructure* s);

	BINARYNINJACOREAPI void BNAddStructureMember(BNStructure* s, BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNAddStructureMemberAtOffset(BNStructure* s, BNTypeWithConfidence* type,
		const char* name, uint64_t offset);
	BINARYNINJACOREAPI void BNRemoveStructureMember(BNStructure* s, size_t idx);
	BINARYNINJACOREAPI void BNReplaceStructureMember(BNStructure* s, size_t idx, BNTypeWithConfidence* type,
		const char* name);

	BINARYNINJACOREAPI BNEnumeration* BNCreateEnumeration(void);
	BINARYNINJACOREAPI BNEnumeration* BNNewEnumerationReference(BNEnumeration* e);
	BINARYNINJACOREAPI void BNFreeEnumeration(BNEnumeration* e);

	BINARYNINJACOREAPI BNEnumerationMember* BNGetEnumerationMembers(BNEnumeration* e, size_t* count);
	BINARYNINJACOREAPI void BNFreeEnumerationMemberList(BNEnumerationMember* members, size_t count);

	BINARYNINJACOREAPI void BNAddEnumerationMember(BNEnumeration* e, const char* name);
	BINARYNINJACOREAPI void BNAddEnumerationMemberWithValue(BNEnumeration* e, const char* name, uint64_t value);
	BINARYNINJACOREAPI void BNRemoveEnumerationMember(BNEnumeration* e, size_t idx);
	BINARYNINJACOREAPI void BNReplaceEnumerationMember(BNEnumeration* e, size_t idx, const char* name, uint64_t value);

	// Source code processing
	BINARYNINJACOREAPI bool BNPreprocessSource(const char* source, const char* fileName, char** output, char** errors,
		const char** includeDirs, size_t includeDirCount);
	BINARYNINJACOREAPI bool BNParseTypesFromSource(BNPlatform* platform, const char* source, const char* fileName,
		BNTypeParserResult* result, char** errors, const char** includeDirs, size_t includeDirCount,
		const char* autoTypeSource);
	BINARYNINJACOREAPI bool BNParseTypesFromSourceFile(BNPlatform* platform, const char* fileName,
		BNTypeParserResult* result, char** errors, const char** includeDirs, size_t includeDirCount,
		const char* autoTypeSource);
	BINARYNINJACOREAPI void BNFreeTypeParserResult(BNTypeParserResult* result);

	// Updates
	BINARYNINJACOREAPI BNUpdateChannel* BNGetUpdateChannels(size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelList(BNUpdateChannel* list, size_t count);
	BINARYNINJACOREAPI BNUpdateVersion* BNGetUpdateChannelVersions(const char* channel, size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelVersionList(BNUpdateVersion* list, size_t count);

	BINARYNINJACOREAPI bool BNAreUpdatesAvailable(const char* channel, uint64_t* expireTime, uint64_t* serverTime, char** errors);

	BINARYNINJACOREAPI BNUpdateResult BNUpdateToVersion(const char* channel, const char* version, char** errors,
	                                                    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total),
	                                                    void* context);
	BINARYNINJACOREAPI BNUpdateResult BNUpdateToLatestVersion(const char* channel, char** errors,
	                                                          bool (*progress)(void* ctxt, uint64_t progress, uint64_t total),
	                                                          void* context);

	BINARYNINJACOREAPI bool BNAreAutoUpdatesEnabled(void);
	BINARYNINJACOREAPI void BNSetAutoUpdatesEnabled(bool enabled);
	BINARYNINJACOREAPI uint64_t BNGetTimeSinceLastUpdateCheck(void);
	BINARYNINJACOREAPI void BNUpdatesChecked(void);

	BINARYNINJACOREAPI char* BNGetActiveUpdateChannel(void);
	BINARYNINJACOREAPI void BNSetActiveUpdateChannel(const char* channel);

	BINARYNINJACOREAPI bool BNIsUpdateInstallationPending(void);
	BINARYNINJACOREAPI void BNInstallPendingUpdate(char** errors);

	// Plugin commands
	BINARYNINJACOREAPI void BNRegisterPluginCommand(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view), bool (*isValid)(void* ctxt, BNBinaryView* view), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForAddress(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, uint64_t addr),
		bool (*isValid)(void* ctxt, BNBinaryView* view, uint64_t addr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForRange(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len),
		bool (*isValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForFunction(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, BNFunction* func),
		bool (*isValid)(void* ctxt, BNBinaryView* view, BNFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForLowLevelILFunction(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func),
		bool (*isValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForLowLevelILInstruction(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr),
		bool (*isValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILFunction(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func),
		bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILInstruction(const char* name, const char* description,
		void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr),
		bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr), void* context);

	BINARYNINJACOREAPI BNPluginCommand* BNGetAllPluginCommands(size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommands(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForAddress(BNBinaryView* view, uint64_t addr,
		size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForRange(BNBinaryView* view, uint64_t addr,
		uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForFunction(BNBinaryView* view, BNFunction* func,
		size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILFunction(BNBinaryView* view,
		BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILInstruction(BNBinaryView* view,
		BNLowLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILFunction(BNBinaryView* view,
		BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILInstruction(BNBinaryView* view,
		BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreePluginCommandList(BNPluginCommand* commands);

	// Calling conventions
	BINARYNINJACOREAPI BNCallingConvention* BNCreateCallingConvention(BNArchitecture* arch, const char* name,
	                                                                  BNCustomCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI BNCallingConvention* BNNewCallingConventionReference(BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNFreeCallingConvention(BNCallingConvention* cc);

	BINARYNINJACOREAPI BNCallingConvention** BNGetArchitectureCallingConventions(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI void BNFreeCallingConventionList(BNCallingConvention** list, size_t count);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureCallingConventionByName(BNArchitecture* arch,
	                                                                                 const char* name);

	BINARYNINJACOREAPI BNArchitecture* BNGetCallingConventionArchitecture(BNCallingConvention* cc);
	BINARYNINJACOREAPI char* BNGetCallingConventionName(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t* BNGetCallerSavedRegisters(BNCallingConvention* cc, size_t* count);

	BINARYNINJACOREAPI uint32_t* BNGetIntegerArgumentRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFloatArgumentRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI bool BNAreArgumentRegistersSharedIndex(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsStackReservedForArgumentRegisters(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsStackAdjustedOnReturn(BNCallingConvention* cc);

	BINARYNINJACOREAPI uint32_t BNGetIntegerReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetHighIntegerReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetFloatReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetGlobalPointerRegister(BNCallingConvention* cc);

	BINARYNINJACOREAPI uint32_t* BNGetImplicitlyDefinedRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI BNRegisterValue BNGetIncomingRegisterValue(BNCallingConvention* cc, uint32_t reg, BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValue BNGetIncomingFlagValue(BNCallingConvention* cc, uint32_t reg, BNFunction* func);

	BINARYNINJACOREAPI BNVariable BNGetIncomingVariableForParameterVariable(BNCallingConvention* cc,
		const BNVariable* var, BNFunction* func);
	BINARYNINJACOREAPI BNVariable BNGetParameterVariableForIncomingVariable(BNCallingConvention* cc,
		const BNVariable* var, BNFunction* func);
	BINARYNINJACOREAPI BNVariable BNGetDefaultIncomingVariableForParameterVariable(BNCallingConvention* cc,
		const BNVariable* var);
	BINARYNINJACOREAPI BNVariable BNGetDefaultParameterVariableForIncomingVariable(BNCallingConvention* cc,
		const BNVariable* var);

	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureDefaultCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureCdeclCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureStdcallCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureFastcallCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI void BNSetArchitectureDefaultCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetArchitectureCdeclCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetArchitectureStdcallCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetArchitectureFastcallCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);

	// Platforms
	BINARYNINJACOREAPI BNPlatform* BNCreatePlatform(BNArchitecture* arch, const char* name);
	BINARYNINJACOREAPI void BNRegisterPlatform(const char* os, BNPlatform* platform);
	BINARYNINJACOREAPI BNPlatform* BNNewPlatformReference(BNPlatform* platform);
	BINARYNINJACOREAPI void BNFreePlatform(BNPlatform* platform);

	BINARYNINJACOREAPI char* BNGetPlatformName(BNPlatform* platform);
	BINARYNINJACOREAPI BNArchitecture* BNGetPlatformArchitecture(BNPlatform* platform);

	BINARYNINJACOREAPI BNPlatform* BNGetPlatformByName(const char* name);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformList(size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByArchitecture(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByOS(const char* os, size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByOSAndArchitecture(const char* os, BNArchitecture* arch,
	                                                                     size_t* count);
	BINARYNINJACOREAPI void BNFreePlatformList(BNPlatform** platform, size_t count);
	BINARYNINJACOREAPI char** BNGetPlatformOSList(size_t* count);
	BINARYNINJACOREAPI void BNFreePlatformOSList(char** list, size_t count);

	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformDefaultCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformCdeclCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformStdcallCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformFastcallCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention** BNGetPlatformCallingConventions(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformSystemCallConvention(BNPlatform* platform);

	BINARYNINJACOREAPI void BNRegisterPlatformCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformDefaultCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformCdeclCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformStdcallCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformFastcallCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetPlatformSystemCallConvention(BNPlatform* platform, BNCallingConvention* cc);

	BINARYNINJACOREAPI BNPlatform* BNGetArchitectureStandalonePlatform(BNArchitecture* arch);

	BINARYNINJACOREAPI BNPlatform* BNGetRelatedPlatform(BNPlatform* platform, BNArchitecture* arch);
	BINARYNINJACOREAPI void BNAddRelatedPlatform(BNPlatform* platform, BNArchitecture* arch, BNPlatform* related);
	BINARYNINJACOREAPI BNPlatform* BNGetAssociatedPlatformByAddress(BNPlatform* platform, uint64_t* addr);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformTypes(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformVariables(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformFunctions(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNSystemCallInfo* BNGetPlatformSystemCalls(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI void BNFreeSystemCallList(BNSystemCallInfo* syscalls, size_t count);
	BINARYNINJACOREAPI BNType* BNGetPlatformTypeByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetPlatformVariableByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetPlatformFunctionByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetPlatformSystemCallName(BNPlatform* platform, uint32_t number);
	BINARYNINJACOREAPI BNType* BNGetPlatformSystemCallType(BNPlatform* platform, uint32_t number);

	//Demangler
	BINARYNINJACOREAPI bool BNDemangleMS(BNArchitecture* arch,
	                                     const char* mangledName,
	                                     BNType** outType,
	                                     char*** outVarName,
	                                     size_t* outVarNameElements);

	// Download providers
	BINARYNINJACOREAPI BNDownloadProvider* BNRegisterDownloadProvider(const char* name, BNDownloadProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadProvider** BNGetDownloadProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeDownloadProviderList(BNDownloadProvider** providers);
	BINARYNINJACOREAPI BNDownloadProvider* BNGetDownloadProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetDownloadProviderName(BNDownloadProvider* provider);
	BINARYNINJACOREAPI BNDownloadInstance* BNCreateDownloadProviderInstance(BNDownloadProvider* provider);

	BINARYNINJACOREAPI BNDownloadInstance* BNInitDownloadInstance(BNDownloadProvider* provider, BNDownloadInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadInstance* BNNewDownloadInstanceReference(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI int BNPerformDownloadRequest(BNDownloadInstance* instance, const char* url, BNDownloadInstanceOutputCallbacks* callbacks);
	BINARYNINJACOREAPI uint64_t BNWriteDataForDownloadInstance(BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNNotifyProgressForDownloadInstance(BNDownloadInstance* instance, uint64_t progress, uint64_t total);
	BINARYNINJACOREAPI char* BNGetErrorForDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNSetErrorForDownloadInstance(BNDownloadInstance* instance, const char* error);

	// Scripting providers
	BINARYNINJACOREAPI BNScriptingProvider* BNRegisterScriptingProvider(const char* name,
		BNScriptingProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingProvider** BNGetScriptingProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeScriptingProviderList(BNScriptingProvider** providers);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetScriptingProviderName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI BNScriptingInstance* BNCreateScriptingProviderInstance(BNScriptingProvider* provider);

	BINARYNINJACOREAPI BNScriptingInstance* BNInitScriptingInstance(BNScriptingProvider* provider,
		BNScriptingInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingInstance* BNNewScriptingInstanceReference(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNFreeScriptingInstance(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNNotifyOutputForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyErrorForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyInputReadyStateForScriptingInstance(BNScriptingInstance* instance,
		BNScriptingProviderInputReadyState state);

	BINARYNINJACOREAPI void BNRegisterScriptingInstanceOutputListener(BNScriptingInstance* instance,
		BNScriptingOutputListener* callbacks);
	BINARYNINJACOREAPI void BNUnregisterScriptingInstanceOutputListener(BNScriptingInstance* instance,
		BNScriptingOutputListener* callbacks);

	BINARYNINJACOREAPI BNScriptingProviderInputReadyState BNGetScriptingInstanceInputReadyState(
		BNScriptingInstance* instance);
	BINARYNINJACOREAPI BNScriptingProviderExecuteResult BNExecuteScriptInput(BNScriptingInstance* instance,
		const char* input);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBinaryView(BNScriptingInstance* instance, BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentFunction(BNScriptingInstance* instance, BNFunction* func);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBasicBlock(BNScriptingInstance* instance, BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentAddress(BNScriptingInstance* instance, uint64_t addr);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentSelection(BNScriptingInstance* instance,
		uint64_t begin, uint64_t end);

	// Main thread actions
	BINARYNINJACOREAPI void BNRegisterMainThread(BNMainThreadCallbacks* callbacks);
	BINARYNINJACOREAPI BNMainThreadAction* BNNewMainThreadActionReference(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNFreeMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNExecuteMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI bool BNIsMainThreadActionDone(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNWaitForMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI BNMainThreadAction* BNExecuteOnMainThread(void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI void BNExecuteOnMainThreadAndWait(void* ctxt, void (*func)(void* ctxt));

	// Worker thread queue management
	BINARYNINJACOREAPI void BNWorkerEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerPriorityEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerInteractiveEnqueue(void* ctxt, void (*action)(void* ctxt));

	BINARYNINJACOREAPI size_t BNGetWorkerThreadCount(void);
	BINARYNINJACOREAPI void BNSetWorkerThreadCount(size_t count);

	// Background task progress reporting
	BINARYNINJACOREAPI BNBackgroundTask* BNBeginBackgroundTask(const char* initialText, bool canCancel);
	BINARYNINJACOREAPI void BNFinishBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNSetBackgroundTaskProgressText(BNBackgroundTask* task, const char* text);
	BINARYNINJACOREAPI bool BNIsBackgroundTaskCancelled(BNBackgroundTask* task);

	BINARYNINJACOREAPI BNBackgroundTask** BNGetRunningBackgroundTasks(size_t* count);
	BINARYNINJACOREAPI BNBackgroundTask* BNNewBackgroundTaskReference(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNFreeBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNFreeBackgroundTaskList(BNBackgroundTask** tasks, size_t count);
	BINARYNINJACOREAPI char* BNGetBackgroundTaskProgressText(BNBackgroundTask* task);
	BINARYNINJACOREAPI bool BNCanCancelBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNCancelBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI bool BNIsBackgroundTaskFinished(BNBackgroundTask* task);

	// Interaction APIs
	BINARYNINJACOREAPI void BNRegisterInteractionHandler(BNInteractionHandlerCallbacks* callbacks);
	BINARYNINJACOREAPI char* BNMarkdownToHTML(const char* contents);
	BINARYNINJACOREAPI void BNShowPlainTextReport(BNBinaryView* view, const char* title, const char* contents);
	BINARYNINJACOREAPI void BNShowMarkdownReport(BNBinaryView* view, const char* title, const char* contents,
		const char* plaintext);
	BINARYNINJACOREAPI void BNShowHTMLReport(BNBinaryView* view, const char* title, const char* contents,
		const char* plaintext);
	BINARYNINJACOREAPI bool BNGetTextLineInput(char** result, const char* prompt, const char* title);
	BINARYNINJACOREAPI bool BNGetIntegerInput(int64_t* result, const char* prompt, const char* title);
	BINARYNINJACOREAPI bool BNGetAddressInput(uint64_t* result, const char* prompt, const char* title,
		BNBinaryView* view, uint64_t currentAddr);
	BINARYNINJACOREAPI bool BNGetChoiceInput(size_t* result, const char* prompt, const char* title,
		const char** choices, size_t count);
	BINARYNINJACOREAPI bool BNGetOpenFileNameInput(char** result, const char* prompt, const char* ext);
	BINARYNINJACOREAPI bool BNGetSaveFileNameInput(char** result, const char* prompt, const char* ext,
		const char* defaultName);
	BINARYNINJACOREAPI bool BNGetDirectoryNameInput(char** result, const char* prompt, const char* defaultName);
	BINARYNINJACOREAPI bool BNGetFormInput(BNFormInputField* fields, size_t count, const char* title);
	BINARYNINJACOREAPI void BNFreeFormInputResults(BNFormInputField* fields, size_t count);
	BINARYNINJACOREAPI BNMessageBoxButtonResult BNShowMessageBox(const char* title, const char* text,
		BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon);

	BINARYNINJACOREAPI bool BNDemangleGNU3(BNArchitecture* arch,
	                                       const char* mangledName,
	                                       BNType** outType,
	                                       char*** outVarName,
	                                       size_t* outVarNameElements);
	BINARYNINJACOREAPI void BNFreeDemangledName(char*** name, size_t nameElements);

	// Plugin repository APIs
	BINARYNINJACOREAPI const char* BNPluginGetApi(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetAuthor(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetDescription(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLicense(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLicenseText(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLongdescription(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetMinimimVersions(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetName(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetVersion(BNRepoPlugin* p);
	BINARYNINJACOREAPI void BNFreePluginTypes(BNPluginType* r);
	BINARYNINJACOREAPI BNRepoPlugin* BNNewPluginReference(BNRepoPlugin* r);
	BINARYNINJACOREAPI void BNFreePlugin(BNRepoPlugin* plugin);
	BINARYNINJACOREAPI const char* BNPluginGetPath(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsInstalled(BNRepoPlugin* p);
	BINARYNINJACOREAPI void BNPluginSetEnabled(BNRepoPlugin* p, bool enabled);
	BINARYNINJACOREAPI bool BNPluginIsEnabled(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNPluginUpdateStatus BNPluginGetPluginUpdateStatus(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNPluginType* BNPluginGetPluginTypes(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI bool BNPluginEnable(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginDisable(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginInstall(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginUninstall(BNRepoPlugin* p);

	BINARYNINJACOREAPI BNRepository* BNNewRepositoryReference(BNRepository* r);
	BINARYNINJACOREAPI void BNFreeRepository(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetUrl(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetRepoPath(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetLocalReference(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetRemoteReference(BNRepository* r);
	BINARYNINJACOREAPI BNRepoPlugin** BNRepositoryGetPlugins(BNRepository* r, size_t* count);
	BINARYNINJACOREAPI void BNFreeRepositoryPluginList(BNRepoPlugin** r);
	BINARYNINJACOREAPI bool BNRepositoryIsInitialized(BNRepository* r);
	BINARYNINJACOREAPI void BNRepositoryFreePluginDirectoryList(char** list, size_t count);
	BINARYNINJACOREAPI BNRepoPlugin* BNRepositoryGetPluginByPath(BNRepository* r, const char* pluginPath);
	BINARYNINJACOREAPI const char* BNRepositoryGetPluginsPath(BNRepository* r);

	BINARYNINJACOREAPI BNRepositoryManager* BNCreateRepositoryManager(const char* enabledPluginsPath);
	BINARYNINJACOREAPI BNRepositoryManager* BNNewRepositoryManagerReference(BNRepositoryManager* r);
	BINARYNINJACOREAPI void BNFreeRepositoryManager(BNRepositoryManager* r);
	BINARYNINJACOREAPI bool BNRepositoryManagerCheckForUpdates(BNRepositoryManager* r);
	BINARYNINJACOREAPI BNRepository** BNRepositoryManagerGetRepositories(BNRepositoryManager* r, size_t* count);
	BINARYNINJACOREAPI void BNFreeRepositoryManagerRepositoriesList(BNRepository** r);
	BINARYNINJACOREAPI bool BNRepositoryManagerAddRepository(BNRepositoryManager* r,
		const char* url,
		const char* repoPath,
		const char* localReference,
		const char* remoteReference);
	BINARYNINJACOREAPI bool BNRepositoryManagerEnablePlugin(BNRepositoryManager* r, const char* repoName, const char* pluginPath);
	BINARYNINJACOREAPI bool BNRepositoryManagerDisablePlugin(BNRepositoryManager* r, const char* repoName, const char* pluginPath);
	BINARYNINJACOREAPI bool BNRepositoryManagerInstallPlugin(BNRepositoryManager* r, const char* repoName, const char* pluginPath);
	BINARYNINJACOREAPI bool BNRepositoryManagerUninstallPlugin(BNRepositoryManager* r, const char* repoName, const char* pluginPath);
	BINARYNINJACOREAPI bool BNRepositoryManagerUpdatePlugin(BNRepositoryManager* r, const char* repoName, const char* pluginPath);
	BINARYNINJACOREAPI BNRepository* BNRepositoryGetRepositoryByPath(BNRepositoryManager* r, const char* repoPath);
	BINARYNINJACOREAPI BNRepositoryManager* BNGetRepositoryManager();

	BINARYNINJACOREAPI BNRepository* BNRepositoryManagerGetDefaultRepository(BNRepositoryManager* r);
	BINARYNINJACOREAPI void BNRegisterForPluginLoading(
		const char* pluginApiName,
		bool (*cb)(const char* repoPath, const char* pluginPath, void* ctx),
		void* ctx);
	BINARYNINJACOREAPI bool BNLoadPluginForApi(const char* pluginApiName, const char* repoPath, const char* pluginPath);

	// LLVM Services APIs
	BINARYNINJACOREAPI void BNLlvmServicesInit(void);

	BINARYNINJACOREAPI int BNLlvmServicesAssemble(const char *src, int dialect, const char *triplet,
		int codeModel, int relocMode, char **outBytes, int *outBytesLen, char **err, int *errLen);

	BINARYNINJACOREAPI void BNLlvmServicesAssembleFree(char *outBytes, char *err);

	// Filesystem functionality
	BINARYNINJACOREAPI int BNDeleteFile(const char* path);
	BINARYNINJACOREAPI int BNDeleteDirectory(const char* path, int contentsOnly);
	BINARYNINJACOREAPI bool BNCreateDirectory(const char* path, bool createSubdirectories);
	BINARYNINJACOREAPI bool BNPathExists(const char* path);
	BINARYNINJACOREAPI bool BNIsPathDirectory(const char* path);
	BINARYNINJACOREAPI bool BNIsPathRegularFile(const char* path);
	BINARYNINJACOREAPI bool BNFileSize(const char* path, uint64_t* size);

	// Settings APIs
	BINARYNINJACOREAPI bool BNSettingGetBool(const char* settingGroup, const char* name, bool defaultValue);
	BINARYNINJACOREAPI int64_t BNSettingGetInteger(const char* settingGroup, const char* name, int64_t defaultValue);
	BINARYNINJACOREAPI char* BNSettingGetString(const char* settingGroup, const char* name, const char* defaultValue);
	// intoutSize is number of elements in defaultValue one entry and number of elements in return type on exit
	BINARYNINJACOREAPI int64_t* BNSettingGetIntegerList(const char* settingGroup, const char* name, int64_t* defaultValue, size_t* inoutSize);
	// intoutSize is number of elements in defaultValue one entry and number of elements in return type on exit
	BINARYNINJACOREAPI const char** BNSettingGetStringList(const char* settingGroup, const char* name, const char** defaultValue, size_t* inoutSize);
	BINARYNINJACOREAPI double BNSettingGetDouble(const char* settingGroup, const char* name, double defaultValue);

	BINARYNINJACOREAPI void BNFreeSettingIntegerList(int64_t* integerList);
	//Check the type of a core setting
	BINARYNINJACOREAPI bool BNSettingIsBool(const char* name, const char* settingGroup);
	BINARYNINJACOREAPI bool BNSettingIsInteger(const char* name, const char* settingGroup);
	BINARYNINJACOREAPI bool BNSettingIsString(const char* name, const char* settingGroup);
	BINARYNINJACOREAPI bool BNSettingIsStringList(const char* name, const char* settingGroup);
	BINARYNINJACOREAPI bool BNSettingIsIntegerList(const char* name, const char* settingGroup);
	BINARYNINJACOREAPI bool BNSettingIsDouble(const char* name, const char* settingGroup);
	// Check if a plugin setting is present
	BINARYNINJACOREAPI bool BNSettingIsPresent(const char* settingGroup, const char* name);

	BINARYNINJACOREAPI bool BNSettingSetBool(const char* settingGroup, const char* name, bool value, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingSetInteger(const char* settingGroup, const char* name, int64_t value, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingSetString(const char* settingGroup, const char* name, const char* value, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingSetDouble(const char* settingGroup, const char* name, double value, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingSetIntegerList(const char* settingGroup, const char* name, const int64_t* value, size_t size, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingSetStringList(const char* settingGroup, const char* name, const char** value, size_t size, bool autoFlush);

	BINARYNINJACOREAPI bool BNSettingRemoveSetting(const char* settingGroup, const char* setting, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingRemoveSettingGroup(const char* settingGroup, bool autoFlush);
	BINARYNINJACOREAPI bool BNSettingFlushSettings();

	//Metadata APIs

	// Create Metadata of various types
	BINARYNINJACOREAPI BNMetadata* BNNewMetadataReference(BNMetadata* data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataBooleanData(bool data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataStringData(const char* data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataUnsignedIntegerData(uint64_t data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataSignedIntegerData(int64_t data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataDoubleData(double data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataOfType(BNMetadataType type);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataRawData(const uint8_t* data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataArray(BNMetadata** data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataValueStore(const char** keys, BNMetadata** values, size_t size);

	BINARYNINJACOREAPI bool BNMetadataIsEqual(BNMetadata* lhs, BNMetadata* rhs);

	BINARYNINJACOREAPI bool BNMetadataSetValueForKey(BNMetadata* data, const char* key, BNMetadata* md);
	BINARYNINJACOREAPI BNMetadata* BNMetadataGetForKey(BNMetadata* data, const char* key);
	BINARYNINJACOREAPI bool BNMetadataArrayAppend(BNMetadata* data, BNMetadata* md);
	BINARYNINJACOREAPI void BNMetadataRemoveKey(BNMetadata* data, const char* key);
	BINARYNINJACOREAPI size_t BNMetadataSize(BNMetadata* data);
	BINARYNINJACOREAPI BNMetadata* BNMetadataGetForIndex(BNMetadata* data, size_t index);
	BINARYNINJACOREAPI void BNMetadataRemoveIndex(BNMetadata* data, size_t index);

	BINARYNINJACOREAPI void BNFreeMetadataArray(BNMetadata** data);
	BINARYNINJACOREAPI void BNFreeMetadataValueStore(BNMetadataValueStore* data);
	BINARYNINJACOREAPI void BNFreeMetadata(BNMetadata* data);
	BINARYNINJACOREAPI void BNFreeMetadataRaw(uint8_t* data);
	// Retrieve Structured Data
	BINARYNINJACOREAPI bool BNMetadataGetBoolean(BNMetadata* data);
	BINARYNINJACOREAPI char* BNMetadataGetString(BNMetadata* data);
	BINARYNINJACOREAPI uint64_t BNMetadataGetUnsignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI int64_t BNMetadataGetSignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI double BNMetadataGetDouble(BNMetadata* data);
	BINARYNINJACOREAPI uint8_t* BNMetadataGetRaw(BNMetadata* data, size_t* size);
	BINARYNINJACOREAPI BNMetadata** BNMetadataGetArray(BNMetadata* data, size_t* size);
	BINARYNINJACOREAPI BNMetadataValueStore* BNMetadataGetValueStore(BNMetadata* data);

	//Query type of Metadata
	BINARYNINJACOREAPI BNMetadataType BNMetadataGetType(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsBoolean(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsString(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsUnsignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsSignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsDouble(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsRaw(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsArray(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsKeyValueStore(BNMetadata* data);

	// Store/Query structured data to/from a BinaryView
	BINARYNINJACOREAPI void BNBinaryViewStoreMetadata(BNBinaryView* view, const char* key, BNMetadata* value);
	BINARYNINJACOREAPI BNMetadata* BNBinaryViewQueryMetadata(BNBinaryView* view, const char* key);
	BINARYNINJACOREAPI void BNBinaryViewRemoveMetadata(BNBinaryView* view, const char* key);

#ifdef __cplusplus
}
#endif

#endif
