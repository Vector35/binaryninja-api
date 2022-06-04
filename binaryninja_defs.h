#pragma once
#ifndef BN_TYPE_PARSER
#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <vector>
#include <string>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif
#endif

#ifdef __GNUC__
	#ifdef BINARYNINJACORE_LIBRARY
		#define BINARYNINJACOREAPI __attribute__((visibility("default")))
	#else
		#define BINARYNINJACOREAPI
	#endif
	#define BINARYNINJAPLUGIN __attribute__((visibility("default")))
#else
	#ifdef _MSC_VER
		#ifndef DEMO_VERSION
			#ifdef BINARYNINJACORE_LIBRARY
				#define BINARYNINJACOREAPI __declspec(dllexport)
			#else
				#define BINARYNINJACOREAPI
			#endif
			#define BINARYNINJAPLUGIN __declspec(dllexport)
		#else
			#define BINARYNINJACOREAPI
			#define BINARYNINJAPLUGIN
		#endif
	#else
		#define BINARYNINJACOREAPI
	#endif
#endif

#define BN_FULL_CONFIDENCE      255
#define BN_MINIMUM_CONFIDENCE   1
#define BN_DEFAULT_CONFIDENCE   96
#define BN_HEURISTIC_CONFIDENCE 192
#define BN_DEBUGINFO_CONFIDENCE 200

#define BN_AUTOCOERCE_EXTERN_PTR 0xfffffffd
#define BN_NOCOERCE_EXTERN_PTR   0xfffffffe
#define BN_INVALID_OPERAND       0xffffffff

#define LLIL_TEMP(n)               (0x80000000 | (uint32_t)(n))
#define LLIL_REG_IS_TEMP(n)        (((n)&0x80000000) != 0)
#define LLIL_GET_TEMP_REG_INDEX(n) ((n)&0x7fffffff)
#define BN_INVALID_REGISTER        0xffffffff

#define DEFAULT_INTERNAL_NAMESPACE "BNINTERNALNAMESPACE"
#define DEFAULT_EXTERNAL_NAMESPACE "BNEXTERNALNAMESPACE"

#define BN_INVALID_EXPR ((size_t)-1)

#ifdef _MSC_VER
	#define NOEXCEPT
#else
	#define NOEXCEPT noexcept
#endif

extern "C" {
	struct BNType;
	struct BNTag;

	enum BNEndianness
	{
		LittleEndian = 0,
		BigEndian = 1
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
		NamedTypeReferenceClass = 11,
		WideCharTypeClass = 12
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

	enum BNLowLevelILOperation
	{
		LLIL_NOP,
		LLIL_SET_REG,             // Not valid in SSA form (see LLIL_SET_REG_SSA)
		LLIL_SET_REG_SPLIT,       // Not valid in SSA form (see LLIL_SET_REG_SPLIT_SSA)
		LLIL_SET_FLAG,            // Not valid in SSA form (see LLIL_SET_FLAG_SSA)
		LLIL_SET_REG_STACK_REL,   // Not valid in SSA form (see LLIL_SET_REG_STACK_REL_SSA)
		LLIL_REG_STACK_PUSH,      // Not valid in SSA form (expanded)
		LLIL_LOAD,                // Not valid in SSA form (see LLIL_LOAD_SSA)
		LLIL_STORE,               // Not valid in SSA form (see LLIL_STORE_SSA)
		LLIL_PUSH,                // Not valid in SSA form (expanded)
		LLIL_POP,                 // Not valid in SSA form (expanded)
		LLIL_REG,                 // Not valid in SSA form (see LLIL_REG_SSA)
		LLIL_REG_SPLIT,           // Not valid in SSA form (see LLIL_REG_SPLIT_SSA)
		LLIL_REG_STACK_REL,       // Not valid in SSA form (see LLIL_REG_STACK_REL_SSA)
		LLIL_REG_STACK_POP,       // Not valid in SSA form (expanded)
		LLIL_REG_STACK_FREE_REG,  // Not valid in SSA form (see LLIL_REG_STACK_FREE_REL_SSA,
		                          // LLIL_REG_STACK_FREE_ABS_SSA)
		LLIL_REG_STACK_FREE_REL,  // Not valid in SSA from (see LLIL_REG_STACK_FREE_REL_SSA)
		LLIL_CONST,
		LLIL_CONST_PTR,
		LLIL_EXTERN_PTR,
		LLIL_FLOAT_CONST,
		LLIL_FLAG,      // Not valid in SSA form (see LLIL_FLAG_SSA)
		LLIL_FLAG_BIT,  // Not valid in SSA form (see LLIL_FLAG_BIT_SSA)
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
		LLIL_FLAG_COND,   // Valid only in Lifted IL
		LLIL_FLAG_GROUP,  // Valid only in Lifted IL
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
		LLIL_REG_SPLIT_DEST_SSA,  // Only valid within an LLIL_SET_REG_SPLIT_SSA instruction
		LLIL_REG_STACK_DEST_SSA,  // Only valid within LLIL_SET_REG_STACK_REL_SSA or LLIL_SET_REG_STACK_ABS_SSA
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
		LLIL_CALL_PARAM,  // Only valid within the LLIL_CALL_SSA, LLIL_SYSCALL_SSA, LLIL_INTRINSIC, LLIL_INTRINSIC_SSA
		                  // instructions
		LLIL_CALL_STACK_SSA,   // Only valid within the LLIL_CALL_SSA or LLIL_SYSCALL_SSA instructions
		LLIL_CALL_OUTPUT_SSA,  // Only valid within the LLIL_CALL_SSA or LLIL_SYSCALL_SSA instructions
		LLIL_LOAD_SSA,
		LLIL_STORE_SSA,
		LLIL_INTRINSIC_SSA,
		LLIL_REG_PHI,
		LLIL_REG_STACK_PHI,
		LLIL_FLAG_PHI,
		LLIL_MEM_PHI
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
		ExceptionBranch = 7,
		UnresolvedBranch = 127,
		UserDefinedBranch = 128
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

	enum BNFunctionGraphType
	{
		InvalidILViewType = -1,
		NormalFunctionGraph = 0,
		LowLevelILFunctionGraph = 1,
		LiftedILFunctionGraph = 2,
		LowLevelILSSAFormFunctionGraph = 3,
		MediumLevelILFunctionGraph = 4,
		MediumLevelILSSAFormFunctionGraph = 5,
		MappedMediumLevelILFunctionGraph = 6,
		MappedMediumLevelILSSAFormFunctionGraph = 7,
		HighLevelILFunctionGraph = 8,
		HighLevelILSSAFormFunctionGraph = 9,
		HighLevelLanguageRepresentationFunctionGraph = 10,
	};

	struct BNBoolWithConfidence
	{
		bool value;
		uint8_t confidence;
	};

	struct BNOffsetWithConfidence
	{
		int64_t value;
		uint8_t confidence;
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
		PointerDisplayType,
		FloatDisplayType,
		DoubleDisplayType
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

	struct BNAddressRange
	{
		uint64_t start;
		uint64_t end;
	};

	enum BNDataFlowQueryOption
	{
		FromAddressesInLookupTableQueryOption  // Use addresses instead of index in the from list within
		                                       // LookupTableValue results
	};

	struct BNTypeWithConfidence
	{
		BNType* type;
		uint8_t confidence;
	};

	enum BNDeadStoreElimination
	{
		DefaultDeadStoreElimination,
		PreventDeadStoreElimination,
		AllowDeadStoreElimination
	};

	struct BNDisassemblyTextLineTypeInfo
	{
		bool hasTypeInfo;
		BNType* parentType;
		size_t fieldIndex;
		uint64_t offset;
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
		NameSpaceToken = 22,
		NameSpaceSeparatorToken = 23,
		TagToken = 24,
		StructOffsetToken = 25,
		StructOffsetByteValueToken = 26,
		StructureHexDumpTextToken = 27,
		GotoLabelToken = 28,
		CommentToken = 29,
		PossibleValueToken = 30,
		PossibleValueTypeToken = 31,
		ArrayIndexToken = 32,
		IndentationToken = 33,
		UnknownMemoryToken = 34,
		// The following are output by the analysis system automatically, these should
		// not be used directly by the architecture plugins
		CodeSymbolToken = 64,
		DataSymbolToken = 65,
		LocalVariableToken = 66,
		ImportToken = 67,
		AddressDisplayToken = 68,
		IndirectImportToken = 69,
		ExternalSymbolToken = 70
	};

	enum BNInstructionTextTokenContext
	{
		NoTokenContext = 0,
		LocalVariableTokenContext = 1,
		DataVariableTokenContext = 2,
		FunctionReturnTokenContext = 3,
		InstructionAddressTokenContext = 4,
		ILInstructionIndexTokenContext = 5
	};

	struct BNInstructionTextToken
	{
		BNInstructionTextTokenType type;
		char* text;
		uint64_t value;
		uint64_t width;
		size_t size, operand;
		BNInstructionTextTokenContext context;
		uint8_t confidence;
		uint64_t address;
		char** typeNames;
		size_t namesCount;
	};

	struct BNDisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		BNInstructionTextToken* tokens;
		size_t count;
		BNHighlightColor highlight;
		BNTag** tags;
		size_t tagCount;
		BNDisassemblyTextLineTypeInfo typeInfo;
	};


	enum BNLinearDisassemblyLineType
	{
		BlankLineType,
		BasicLineType,
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
		NonContiguousSeparatorLineType,
		AnalysisWarningLineType
	};

	enum BNThemeColor
	{
		// Hex dump colors
		AddressColor,
		ModifiedColor,
		InsertedColor,
		NotPresentColor,
		SelectionColor,
		OutlineColor,
		BackgroundHighlightDarkColor,
		BackgroundHighlightLightColor,
		BoldBackgroundHighlightDarkColor,
		BoldBackgroundHighlightLightColor,
		AlphanumericHighlightColor,
		PrintableHighlightColor,

		// Graph colors
		GraphBackgroundDarkColor,
		GraphBackgroundLightColor,
		GraphNodeDarkColor,
		GraphNodeLightColor,
		GraphNodeOutlineColor,
		TrueBranchColor,
		FalseBranchColor,
		UnconditionalBranchColor,
		AltTrueBranchColor,
		AltFalseBranchColor,
		AltUnconditionalBranchColor,

		// Disassembly colors
		RegisterColor,
		NumberColor,
		CodeSymbolColor,
		DataSymbolColor,
		StackVariableColor,
		ImportColor,
		InstructionHighlightColor,
		TokenHighlightColor,
		TokenSelectionColor,
		AnnotationColor,
		OpcodeColor,
		LinearDisassemblyFunctionHeaderColor,
		LinearDisassemblyBlockColor,
		LinearDisassemblyNoteColor,
		LinearDisassemblySeparatorColor,
		StringColor,
		TypeNameColor,
		FieldNameColor,
		KeywordColor,
		UncertainColor,
		NameSpaceColor,
		NameSpaceSeparatorColor,
		GotoLabelColor,
		CommentColor,

		// Script console colors
		ScriptConsoleOutputColor,
		ScriptConsoleWarningColor,
		ScriptConsoleErrorColor,
		ScriptConsoleEchoColor,

		// Highlighting colors
		BlueStandardHighlightColor,
		GreenStandardHighlightColor,
		CyanStandardHighlightColor,
		RedStandardHighlightColor,
		MagentaStandardHighlightColor,
		YellowStandardHighlightColor,
		OrangeStandardHighlightColor,
		WhiteStandardHighlightColor,
		BlackStandardHighlightColor,

		// MiniGraph
		MiniGraphOverlayColor,

		// FeatureMap
		FeatureMapBaseColor,
		FeatureMapNavLineColor,
		FeatureMapNavHighlightColor,
		FeatureMapDataVariableColor,
		FeatureMapAsciiStringColor,
		FeatureMapUnicodeStringColor,
		FeatureMapFunctionColor,
		FeatureMapImportColor,
		FeatureMapExternColor,
		FeatureMapLibraryColor,

		// Sidebar colors
		SidebarBackgroundColor,
		SidebarInactiveIconColor,
		SidebarActiveIconColor,
		SidebarHeaderBackgroundColor,
		SidebarHeaderTextColor,
		SidebarWidgetBackgroundColor,

		// Pane colors
		ActivePaneBackgroundColor,
		InactivePaneBackgroundColor
	};

	struct BNFunction;
	struct BNBasicBlock;
	struct BNLinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		BNFunction* function;
		BNBasicBlock* block;
		BNDisassemblyTextLine contents;
	};

	BINARYNINJACOREAPI char* BNAllocString(const char* contents);
	BINARYNINJACOREAPI void BNFreeString(char* str);
	BINARYNINJACOREAPI char** BNAllocStringList(const char** contents, size_t size);
	BINARYNINJACOREAPI void BNFreeStringList(char** strs, size_t count);

	// Filesystem functionality
	BINARYNINJACOREAPI int BNDeleteFile(const char* path);
	BINARYNINJACOREAPI int BNDeleteDirectory(const char* path, int contentsOnly);
	BINARYNINJACOREAPI bool BNCreateDirectory(const char* path, bool createSubdirectories);
	BINARYNINJACOREAPI bool BNPathExists(const char* path);
	BINARYNINJACOREAPI char* BNGetParentPath(const char* path);
	BINARYNINJACOREAPI bool BNIsPathDirectory(const char* path);
	BINARYNINJACOREAPI bool BNIsPathRegularFile(const char* path);
	BINARYNINJACOREAPI bool BNFileSize(const char* path, uint64_t* size);
	BINARYNINJACOREAPI bool BNRenameFile(const char* source, const char* dest);
	BINARYNINJACOREAPI bool BNCopyFile(const char* source, const char* dest);
	BINARYNINJACOREAPI const char* BNGetFileName(const char* path);
	BINARYNINJACOREAPI const char* BNGetFileExtension(const char* path);
	BINARYNINJACOREAPI char** BNGetFilePathsInDirectory(const char* path, size_t* count);
	BINARYNINJACOREAPI char* BNAppendPath(const char* path, const char* part);
	BINARYNINJACOREAPI void BNFreePath(char* path);
}