// Copyright (c) 2015-2024 Vector 35 Inc
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

#ifndef BN_TYPE_PARSER
#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#else
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif
#endif

// Current ABI version for linking to the core. This is incremented any time
// there are changes to the API that affect linking, including new functions,
// new types, or modifications to existing functions or types.
#define BN_CURRENT_CORE_ABI_VERSION 73

// Minimum ABI version that is supported for loading of plugins. Plugins that
// are linked to an ABI version less than this will not be able to load and
// will require rebuilding. The minimum version is increased when there are
// incompatible changes that break binary compatibility, such as changes to
// existing types or functions.
#define BN_MINIMUM_CORE_ABI_VERSION 73

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

#ifdef WIN32
	#define PATH_SEP "\\"
#else
	#define PATH_SEP "/"
#endif

/*!
    @addtogroup core
    @{
*/
#define BN_MAX_INSTRUCTION_LENGTH     256
#define BN_DEFAULT_INSTRUCTION_LENGTH 16
#define BN_DEFAULT_OPCODE_DISPLAY     8
#define BN_MAX_INSTRUCTION_BRANCHES   3

#define BN_MAX_STORED_DATA_LENGTH 0x3fffffff
#define BN_NULL_ID                -1

#define LLIL_TEMP(n)               (0x80000000 | (uint32_t)(n))
#define LLIL_REG_IS_TEMP(n)        (((n)&0x80000000) != 0)
#define LLIL_GET_TEMP_REG_INDEX(n) ((n)&0x7fffffff)
#define BN_INVALID_REGISTER        0xffffffff

#define BN_AUTOCOERCE_EXTERN_PTR 0xfffffffd
#define BN_NOCOERCE_EXTERN_PTR   0xfffffffe
#define BN_INVALID_OPERAND       0xffffffff

#define BN_INVALID_EXPR ((size_t)-1)

#define BN_MAX_STRING_LENGTH 128

#define LLVM_SVCS_CB_NOTE    0
#define LLVM_SVCS_CB_WARNING 1
#define LLVM_SVCS_CB_ERROR   2

#define LLVM_SVCS_DIALECT_UNSPEC 0
#define LLVM_SVCS_DIALECT_ATT    1
#define LLVM_SVCS_DIALECT_INTEL  2

#define LLVM_SVCS_CM_DEFAULT 0
#define LLVM_SVCS_CM_SMALL   1
#define LLVM_SVCS_CM_KERNEL  2
#define LLVM_SVCS_CM_MEDIUM  3
#define LLVM_SVCS_CM_LARGE   4

#define LLVM_SVCS_RM_STATIC         0
#define LLVM_SVCS_RM_PIC            1
#define LLVM_SVCS_RM_DYNAMIC_NO_PIC 2

#define BN_MAX_VARIABLE_OFFSET 0x7fffffffffLL
#define BN_MAX_VARIABLE_INDEX  0xfffff

#define BN_FULL_CONFIDENCE      255
#define BN_MINIMUM_CONFIDENCE   1
#define BN_DEFAULT_CONFIDENCE   96
#define BN_HEURISTIC_CONFIDENCE 192
#define BN_DEBUGINFO_CONFIDENCE 200

#define DEFAULT_INTERNAL_NAMESPACE "BNINTERNALNAMESPACE"
#define DEFAULT_EXTERNAL_NAMESPACE "BNEXTERNALNAMESPACE"

#define BNDB_SUFFIX "bndb"
#define BNDB_EXT ("." BNDB_SUFFIX)
#define BNTA_SUFFIX "bnta"
#define BNTA_EXT ("." BNTA_SUFFIX)
#define BNPM_SUFFIX "bnpm"
#define BNPM_EXT ("." BNPM_SUFFIX)
#define BNPR_SUFFIX "bnpr"
#define BNPR_EXT ("." BNPR_SUFFIX)

// The BN_DECLARE_CORE_ABI_VERSION must be included in native plugin modules. If
// the ABI version is not declared, the core will not load the plugin.
#ifdef DEMO_VERSION
	#define BN_DECLARE_CORE_ABI_VERSION
#else
	#ifdef __cplusplus
		#define BN_DECLARE_CORE_ABI_VERSION \
			extern "C" \
			{ \
				BINARYNINJAPLUGIN uint32_t CorePluginABIVersion() { return BN_CURRENT_CORE_ABI_VERSION; } \
			}
	#else
		#define BN_DECLARE_CORE_ABI_VERSION \
			BINARYNINJAPLUGIN uint32_t CorePluginABIVersion(void) { return BN_CURRENT_CORE_ABI_VERSION; }
	#endif
#endif


#ifdef __has_attribute
	#define BN_HAVE_ATTRIBUTE(x) __has_attribute(x)
#else
	#define BN_HAVE_ATTRIBUTE(x) 0
#endif

#if BN_HAVE_ATTRIBUTE(format) || (defined(__GNUC__) && !defined(__clang__))
	#define BN_PRINTF_ATTRIBUTE(string_index, first_to_check) \
		__attribute__((format(__printf__, string_index, first_to_check)))
#else
	#define BN_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif


#ifdef __cplusplus
extern "C"
{
#endif
	typedef enum BNPluginLoadOrder
	{
		EarlyPluginLoadOrder,
		NormalPluginLoadOrder,
		LatePluginLoadOrder
	} BNPluginLoadOrder;

	typedef enum PluginLoadStatus
	{
		NotAttemptedStatus,
		LoadSucceededStatus,
		LoadFailedStatus
	} PluginLoadStatus;

	typedef bool (*BNCorePluginInitFunction)(void);
	typedef void (*BNCorePluginDependencyFunction)(void);
	typedef uint32_t (*BNCorePluginABIVersionFunction)(void);

	typedef struct BNDataBuffer BNDataBuffer;
	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNBinaryViewType BNBinaryViewType;
	typedef struct BNBinaryReader BNBinaryReader;
	typedef struct BNBinaryWriter BNBinaryWriter;
	typedef struct BNKeyValueStore BNKeyValueStore;
	typedef struct BNSnapshot BNSnapshot;
	typedef struct BNDatabase BNDatabase;
	typedef struct BNFileMetadata BNFileMetadata;
	typedef struct BNTransform BNTransform;
	typedef struct BNArchitecture BNArchitecture;
	typedef struct BNFunction BNFunction;
	typedef struct BNBasicBlock BNBasicBlock;
	typedef struct BNDownloadProvider BNDownloadProvider;
	typedef struct BNDownloadInstance BNDownloadInstance;
	typedef struct BNWebsocketProvider BNWebsocketProvider;
	typedef struct BNWebsocketClient BNWebsocketClient;
	typedef struct BNTypeParser BNTypeParser;
	typedef struct BNTypePrinter BNTypePrinter;
	typedef struct BNFlowGraph BNFlowGraph;
	typedef struct BNFlowGraphNode BNFlowGraphNode;
	typedef struct BNFlowGraphLayoutRequest BNFlowGraphLayoutRequest;
	typedef struct BNSymbol BNSymbol;
	typedef struct BNTemporaryFile BNTemporaryFile;
	typedef struct BNLowLevelILFunction BNLowLevelILFunction;
	typedef struct BNMediumLevelILFunction BNMediumLevelILFunction;
	typedef struct BNHighLevelILFunction BNHighLevelILFunction;
	typedef struct BNLanguageRepresentationFunction BNLanguageRepresentationFunction;
	typedef struct BNType BNType;
	typedef struct BNTypeBuilder BNTypeBuilder;
	typedef struct BNTypeLibrary BNTypeLibrary;
	typedef struct BNTypeLibraryMapping BNTypeLibraryMapping;
	typedef struct BNStructure BNStructure;
	typedef struct BNStructureBuilder BNStructureBuilder;
	typedef struct BNTagType BNTagType;
	typedef struct BNTag BNTag;
	typedef struct BNTagReference BNTagReference;
	typedef struct BNUser BNUser;
	typedef struct BNNamedTypeReference BNNamedTypeReference;
	typedef struct BNNamedTypeReferenceBuilder BNNamedTypeReferenceBuilder;
	typedef struct BNEnumeration BNEnumeration;
	typedef struct BNEnumerationBuilder BNEnumerationBuilder;
	typedef struct BNCallingConvention BNCallingConvention;
	typedef struct BNPlatform BNPlatform;
	typedef struct BNActivity BNActivity;
	typedef struct BNAnalysisContext BNAnalysisContext;
	typedef struct BNWorkflow BNWorkflow;
	typedef struct BNAnalysisCompletionEvent BNAnalysisCompletionEvent;
	typedef struct BNDisassemblySettings BNDisassemblySettings;
	typedef struct BNSaveSettings BNSaveSettings;
	typedef struct BNScriptingProvider BNScriptingProvider;
	typedef struct BNScriptingInstance BNScriptingInstance;
	typedef struct BNMainThreadAction BNMainThreadAction;
	typedef struct BNBackgroundTask BNBackgroundTask;
	typedef struct BNRepository BNRepository;
	typedef struct BNRepoPlugin BNRepoPlugin;
	typedef struct BNRepositoryManager BNRepositoryManager;
	typedef struct BNComponent BNComponent;
	typedef struct BNSettings BNSettings;
	typedef struct BNMetadata BNMetadata;
	typedef struct BNReportCollection BNReportCollection;
	typedef struct BNRelocation BNRelocation;
	typedef struct BNSegment BNSegment;
	typedef struct BNSection BNSection;
	typedef struct BNRelocationInfo BNRelocationInfo;
	typedef struct BNRelocationHandler BNRelocationHandler;
	typedef struct BNDataBuffer BNDataBuffer;
	typedef struct BNDataRenderer BNDataRenderer;
	typedef struct BNDataRendererContainer BNDataRendererContainer;
	typedef struct BNDisassemblyTextRenderer BNDisassemblyTextRenderer;
	typedef struct BNLinearViewObject BNLinearViewObject;
	typedef struct BNLinearViewCursor BNLinearViewCursor;
	typedef struct BNDebugInfo BNDebugInfo;
	typedef struct BNDebugInfoParser BNDebugInfoParser;
	typedef struct BNSecretsProvider BNSecretsProvider;
	typedef struct BNLogger BNLogger;
	typedef struct BNSymbolQueue BNSymbolQueue;
	typedef struct BNTypeArchive BNTypeArchive;
	typedef struct BNTypeContainer BNTypeContainer;
	typedef struct BNProject BNProject;
	typedef struct BNProjectFile BNProjectFile;
	typedef struct BNExternalLibrary BNExternalLibrary;
	typedef struct BNExternalLocation BNExternalLocation;
	typedef struct BNProjectFolder BNProjectFolder;
	typedef struct BNBaseAddressDetection BNBaseAddressDetection;
	typedef struct BNCollaborationChangeset BNCollaborationChangeset;
	typedef struct BNRemoteFile BNRemoteFile;
	typedef struct BNRemoteFolder BNRemoteFolder;
	typedef struct BNCollaborationGroup BNCollaborationGroup;
	typedef struct BNCollaborationPermission BNCollaborationPermission;
	typedef struct BNRemoteProject BNRemoteProject;
	typedef struct BNRemote BNRemote;
	typedef struct BNCollaborationSnapshot BNCollaborationSnapshot;
	typedef struct BNCollaborationUndoEntry BNCollaborationUndoEntry;
	typedef struct BNCollaborationUser BNCollaborationUser;
	typedef struct BNAnalysisMergeConflict BNAnalysisMergeConflict;
	typedef struct BNAnalysisMergeConflictSplitter BNAnalysisMergeConflictSplitter;
	typedef struct BNTypeArchiveMergeConflict BNTypeArchiveMergeConflict;
	typedef struct BNCollaborationLazyT BNCollaborationLazyT;
	typedef struct BNUndoAction BNUndoAction;
	typedef struct BNUndoEntry BNUndoEntry;

	//! Console log levels
	typedef enum BNLogLevel
	{
		DebugLog = 0,    //! Debug logging level, most verbose logging level
		InfoLog = 1,     //! Information logging level, default logging level
		WarningLog = 2,  //! Warning logging level, messages show with warning icon in the UI
		ErrorLog = 3,    //! Error logging level, messages show with error icon in the UI
		AlertLog = 4     //! Alert logging level, messages are displayed with popup message box in the UI
	} BNLogLevel;

	typedef enum BNEndianness
	{
		LittleEndian = 0,
		BigEndian = 1
	} BNEndianness;

	typedef enum BNModificationStatus
	{
		Original = 0,
		Changed = 1,
		Inserted = 2
	} BNModificationStatus;

	typedef enum BNTransformType
	{
		BinaryCodecTransform = 0,   // Two-way transform of data, binary input/output
		TextCodecTransform = 1,     // Two-way transform of data, encoder output is text
		UnicodeCodecTransform = 2,  // Two-way transform of data, encoder output is Unicode string (as UTF8)
		DecodeTransform = 3,        // One-way decode only
		BinaryEncodeTransform = 4,  // One-way encode only, output is binary
		TextEncodeTransform = 5,    // One-way encode only, output is text
		EncryptTransform = 6,       // Two-way encryption
		InvertingTransform = 7,     // Transform that can be undone by performing twice
		HashTransform = 8           // Hash function
	} BNTransformType;

	typedef enum BNBranchType
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
	} BNBranchType;

	typedef enum BNInstructionTextTokenType
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
		EnumerationMemberToken = 35,
		OperationToken = 36,
		BaseStructureNameToken = 37,
		BaseStructureSeparatorToken = 38,
		BraceToken = 39,
		// The following are output by the analysis system automatically, these should
		// not be used directly by the architecture plugins
		CodeSymbolToken = 64,
		DataSymbolToken = 65,
		LocalVariableToken = 66,
		ImportToken = 67,
		AddressDisplayToken = 68,
		IndirectImportToken = 69,
		ExternalSymbolToken = 70,
		StackVariableToken = 71,
		AddressSeparatorToken = 72
	} BNInstructionTextTokenType;

	typedef enum BNInstructionTextTokenContext
	{
		NoTokenContext = 0,
		LocalVariableTokenContext = 1,
		DataVariableTokenContext = 2,
		FunctionReturnTokenContext = 3,
		InstructionAddressTokenContext = 4,
		ILInstructionIndexTokenContext = 5,
		ConstDataTokenContext = 6, // For Const Data arrays
		ConstStringDataTokenContext = 7, // For ConstData strings
		StringReferenceTokenContext = 8, // For References to strings
		StringDataVariableTokenContext = 9, // For String DataVariables
		StringDisplayTokenContext = 10 // For displaying strings which aren't associated with an address
	} BNInstructionTextTokenContext;

	typedef enum BNLinearDisassemblyLineType
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
	} BNLinearDisassemblyLineType;

	typedef enum BNTokenEscapingType
	{
		NoTokenEscapingType = 0,
		BackticksTokenEscapingType = 1,
		QuotedStringEscapingType = 2,
		ReplaceInvalidCharsEscapingType = 3,
	} BNTokenEscapingType;

	typedef enum BNAnalysisWarningActionType
	{
		NoAnalysisWarningAction = 0,
		ForceAnalysisWarningAction = 1,
		ShowStackGraphWarningAction = 2
	} BNAnalysisWarningActionType;

	typedef enum BNSymbolType
	{
		FunctionSymbol = 0,
		ImportAddressSymbol = 1,
		ImportedFunctionSymbol = 2,
		DataSymbol = 3,
		ImportedDataSymbol = 4,
		ExternalSymbol = 5,
		LibraryFunctionSymbol = 6,
		SymbolicFunctionSymbol = 7,
		LocalLabelSymbol = 8,
	} BNSymbolType;

	typedef enum BNSymbolBinding
	{
		NoBinding,
		LocalBinding,
		GlobalBinding,
		WeakBinding
	} BNSymbolBinding;

	typedef enum BNActionType
	{
		TemporaryAction = 0,
		DataModificationAction = 1,
		AnalysisAction = 2,
		DataModificationAndAnalysisAction = 3
	} BNActionType;

	typedef enum BNLowLevelILOperation
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
		LLIL_CALL_PARAM,  // Only valid within the LLIL_CALL_SSA, LLIL_SYSCALL_SSA, LLIL_INTRINSIC, LLIL_INTRINSIC_SSA,
		                  // LLIL_MEMORY_INTRINSIC_SSA, LLIL_TAILCALL, LLIL_TAILCALL_SSA instructions
		LLIL_CALL_STACK_SSA,           // Only valid within the LLIL_CALL_SSA or LLIL_SYSCALL_SSA instructions
		LLIL_CALL_OUTPUT_SSA,          // Only valid within the LLIL_CALL_SSA or LLIL_SYSCALL_SSA instructions
		LLIL_SEPARATE_PARAM_LIST_SSA,  // Only valid within the LLIL_CALL_PARAM instruction
		LLIL_SHARED_PARAM_SLOT_SSA,    // Only valid within the LLIL_CALL_PARAM or LLIL_SEPARATE_PARAM_LIST_SSA instructions
		LLIL_MEMORY_INTRINSIC_OUTPUT_SSA,  // Only valid within the LLIL_MEMORY_INTRINSIC_SSA instruction
		LLIL_LOAD_SSA,
		LLIL_STORE_SSA,
		LLIL_INTRINSIC_SSA,
		LLIL_MEMORY_INTRINSIC_SSA,
		LLIL_REG_PHI,
		LLIL_REG_STACK_PHI,
		LLIL_FLAG_PHI,
		LLIL_MEM_PHI
	} BNLowLevelILOperation;

	typedef enum BNLowLevelILFlagCondition
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
	} BNLowLevelILFlagCondition;

	typedef enum BNFlagRole
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
		UnorderedFlagRole = 10,
		CarryFlagWithInvertedSubtractRole = 11,
	} BNFlagRole;

	typedef enum BNFunctionGraphType
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
	} BNFunctionGraphType;

	typedef enum BNDisassemblyOption
	{
		ShowAddress = 0,
		ShowOpcode = 1,
		ExpandLongOpcode = 2,
		ShowVariablesAtTopOfGraph = 3,
		ShowVariableTypesWhenAssigned = 4,
		ShowRegisterHighlight = 7,
		ShowFunctionAddress = 8,
		ShowFunctionHeader = 9,
		ShowTypeCasts = 10,

		// Linear disassembly options
		GroupLinearDisassemblyFunctions = 64,
		HighLevelILLinearDisassembly = 65,
		WaitForIL = 66,
		IndentHLILBody = 67,

		// Debugging options
		ShowFlagUsage = 128,
		ShowStackPointer = 129,
		ShowILTypes = 130,
		ShowILOpcodes = 131,
	} BNDisassemblyOption;

	typedef enum BNDisassemblyAddressMode
	{
		AbsoluteDisassemblyAddressMode,
		RelativeToBinaryStartDisassemblyAddressMode,
		RelativeToSegmentStartDisassemblyAddressMode,
		RelativeToSectionStartDisassemblyAddressMode,
		RelativeToFunctionStartDisassemblyAddressMode,
		RelativeToAddressBaseOffsetDisassemblyAddressMode,
		DisassemblyAddressModeMask = 0xFFFF,

		IncludeNameDisassemblyAddressModeFlag = 0x10000,
		DecimalDisassemblyAddressModeFlag = 0x20000,
		DisassemblyAddressModeFlagsMask = 0xFFFF0000,
	} BNDisassemblyAddressMode;

	typedef enum BNDisassemblyCallParameterHints
	{
		NeverShowMatchingParameterHints,
		AlwaysShowParameterHints,
		NeverShowParameterHints,
	} BNDisassemblyCallParameterHints;

	typedef enum BNTypeClass
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
	} BNTypeClass;

	typedef enum BNNamedTypeReferenceClass
	{
		UnknownNamedTypeClass = 0,
		TypedefNamedTypeClass = 1,
		ClassNamedTypeClass = 2,
		StructNamedTypeClass = 3,
		UnionNamedTypeClass = 4,
		EnumNamedTypeClass = 5
	} BNNamedTypeReferenceClass;

	typedef enum BNStructureVariant
	{
		ClassStructureType = 0,
		StructStructureType = 1,
		UnionStructureType = 2
	} BNStructureVariant;

	typedef enum BNMemberScope
	{
		NoScope,
		StaticScope,
		VirtualScope,
		ThunkScope,
		FriendScope
	} BNMemberScope;

	typedef enum BNMemberAccess
	{
		NoAccess,
		PrivateAccess,
		ProtectedAccess,
		PublicAccess
	} BNMemberAccess;

	typedef enum BNReferenceType
	{
		PointerReferenceType = 0,
		ReferenceReferenceType = 1,
		RValueReferenceType = 2,
		NoReference = 3
	} BNReferenceType;

	typedef enum BNPointerSuffix
	{
		Ptr64Suffix,
		UnalignedSuffix,
		RestrictSuffix,
		ReferenceSuffix,
		LvalueSuffix,
	} BNPointerSuffix;

	typedef enum BNPointerBaseType
	{
		AbsolutePointerBaseType,
		RelativeToConstantPointerBaseType,
		RelativeToBinaryStartPointerBaseType,
		RelativeToVariableAddressPointerBaseType,
	} BNPointerBaseType;

	// Caution: these enumeration values are used a lookups into the static NameTypeStrings in the core
	// if you modify this you must also modify the string lookups as well
	typedef enum BNNameType
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
		OperatorUnaryStarNameType,
		OmniCallSigNameType,
		ManagedVectorConstructorIteratorNameType,
		ManagedVectorDestructorIteratorNameType,
		EHVectorCopyConstructorIteratorNameType,
		EHVectorVBaseCopyConstructorIteratorNameType,
		DynamicInitializerNameType,
		DynamicAtExitDestructorNameType,
		VectorCopyConstructorIteratorNameType,
		VectorVBaseCopyConstructorIteratorNameType,
		ManagedVectorCopyConstructorIteratorNameType,
		LocalStaticThreadGuardNameType,
		UserDefinedLiteralOperatorNameType,
	} BNNameType;

	typedef enum BNCallingConventionName
	{
		NoCallingConvention,
		CdeclCallingConvention,
		PascalCallingConvention,
		ThisCallCallingConvention,
		STDCallCallingConvention,
		FastcallCallingConvention,
		CLRCallCallingConvention,
		EabiCallCallingConvention,
		VectorCallCallingConvention,
		SwiftCallingConvention,
		SwiftAsyncCallingConvention
	} BNCallingConventionName;

	typedef enum BNStringType
	{
		AsciiString = 0,
		Utf16String = 1,
		Utf32String = 2,
		Utf8String = 3
	} BNStringType;

	typedef enum BNIntegerDisplayType
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
		DoubleDisplayType,
		EnumerationDisplayType,
	} BNIntegerDisplayType;

	typedef enum BNFlowGraphOption
	{
		FlowGraphUsesBlockHighlights,
		FlowGraphUsesInstructionHighlights,
		FlowGraphIncludesUserComments,
		FlowGraphAllowsPatching,
		FlowGraphAllowsInlineInstructionEditing,
		FlowGraphShowsSecondaryRegisterHighlighting
	} BNFlowGraphOption;

	typedef enum BNILInstructionAttribute
	{
		// If present on a store instruction, allows elimination of variables associated with the store
		ILAllowDeadStoreElimination = 1,

		// If present on a store instruction, prevents elimination of variables associated with the store
		ILPreventDeadStoreElimination = 2,

		// Assumes that a variable assignment might be used in some way during MLIL translation
		MLILAssumePossibleUse = 4,

		// MLIL variable usage has an unknown size and may be used partially (i.e. an automatically discovered register
		// parameter in a call)
		MLILUnknownSize = 8,

		// lifted instruction uses pointer authentication
		SrcInstructionUsesPointerAuth = 0x10,

		// Prevents alias analysis from being performed on the instruction
		ILPreventAliasAnalysis = 0x20,

		// Set on and instruction that has been re-written to clarify ControlFlowGuard constructs
		ILIsCFGProtected = 0x40
	} BNILInstructionAttribute;

	typedef enum BNIntrinsicClass
	{
		GeneralIntrinsicClass,
		MemoryIntrinsicClass
	} BNIntrinsicClass;

	typedef struct BNLowLevelILInstruction
	{
		BNLowLevelILOperation operation;
		uint32_t attributes;
		size_t size;
		uint32_t flags;
		uint32_t sourceOperand;
		uint64_t operands[4];
		uint64_t address;
	} BNLowLevelILInstruction;

	typedef struct BNLowLevelILLabel
	{
		bool resolved;
		size_t ref;
		size_t operand;
	} BNLowLevelILLabel;

	typedef enum BNImplicitRegisterExtend
	{
		NoExtend,
		ZeroExtendToFullWidth,
		SignExtendToFullWidth
	} BNImplicitRegisterExtend;

	typedef struct BNRegisterInfo
	{
		uint32_t fullWidthRegister;
		size_t offset;
		size_t size;
		BNImplicitRegisterExtend extend;
	} BNRegisterInfo;

	typedef struct BNRegisterStackInfo
	{
		uint32_t firstStorageReg, firstTopRelativeReg;
		uint32_t storageCount, topRelativeCount;
		uint32_t stackTopReg;
	} BNRegisterStackInfo;

	typedef enum BNRegisterValueType
	{
		UndeterminedValue,
		EntryValue,
		ConstantValue,
		ConstantPointerValue,
		ExternalPointerValue,
		StackFrameOffset,
		ReturnAddressValue,
		ImportedAddressValue,

		// The following are only valid in BNPossibleValueSet
		SignedRangeValue,
		UnsignedRangeValue,
		LookupTableValue,
		InSetOfValues,
		NotInSetOfValues,

		// The following support constant data and values larger than 8 bytes
		ConstantDataValue = 0x8000,
		ConstantDataZeroExtendValue = ConstantDataValue | 0x1,
		ConstantDataSignExtendValue = ConstantDataValue | 0x2,
		ConstantDataAggregateValue = ConstantDataValue | 0x3
	} BNRegisterValueType;

	typedef enum BNDataFlowQueryOption
	{
		FromAddressesInLookupTableQueryOption  // Use addresses instead of index in the from list within
		                                       // LookupTableValue results
	} BNDataFlowQueryOption;

	typedef enum BNPluginOrigin
	{
		OfficialPluginOrigin,
		CommunityPluginOrigin,
		OtherPluginOrigin
	} BNPluginOrigin;

	typedef enum BNPluginStatus
	{
		NotInstalledPluginStatus = 0x00000000,
		InstalledPluginStatus = 0x00000001,
		EnabledPluginStatus = 0x00000002,
		UpdateAvailablePluginStatus = 0x00000010,
		DeletePendingPluginStatus = 0x00000020,
		UpdatePendingPluginStatus = 0x00000040,
		DisablePendingPluginStatus = 0x00000080,
		PendingRestartPluginStatus = 0x00000200,
		BeingUpdatedPluginStatus = 0x00000400,
		BeingDeletedPluginStatus = 0x00000800,
		DependenciesBeingInstalledStatus = 0x00001000
	} BNPluginStatus;

	typedef enum BNPluginType
	{
		CorePluginType,
		UiPluginType,
		ArchitecturePluginType,
		BinaryViewPluginType,
		HelperPluginType,
		SyncPluginType
	} BNPluginType;

	typedef struct BNLookupTableEntry
	{
		int64_t* fromValues;
		size_t fromCount;
		int64_t toValue;
	} BNLookupTableEntry;

	typedef struct BNRegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		size_t size;
	} BNRegisterValue;

	typedef struct BNRegisterValueWithConfidence
	{
		BNRegisterValue value;
		uint8_t confidence;
	} BNRegisterValueWithConfidence;

	typedef struct BNValueRange
	{
		uint64_t start, end, step;
	} BNValueRange;

	typedef struct BNPossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		size_t size;
		BNValueRange* ranges;
		int64_t* valueSet;
		BNLookupTableEntry* table;
		size_t count;
	} BNPossibleValueSet;


	typedef struct BNRegisterOrConstant
	{
		bool constant;
		uint32_t reg;
		uint64_t value;
	} BNRegisterOrConstant;

	typedef struct BNDataVariable
	{
		uint64_t address;
		BNType* type;
		bool autoDiscovered;
		uint8_t typeConfidence;
	} BNDataVariable;

	typedef struct BNDataVariableAndName
	{
		uint64_t address;
		BNType* type;
		char* name;
		bool autoDiscovered;
		uint8_t typeConfidence;
	} BNDataVariableAndName;

	typedef struct BNDataVariableAndNameAndDebugParser
	{
		uint64_t address;
		BNType* type;
		char* name;
		char* parser;
		bool autoDiscovered;
		uint8_t typeConfidence;
	} BNDataVariableAndNameAndDebugParser;

	typedef enum BNMediumLevelILOperation
	{
		MLIL_NOP,
		MLIL_SET_VAR,        // Not valid in SSA form (see MLIL_SET_VAR_SSA)
		MLIL_SET_VAR_FIELD,  // Not valid in SSA form (see MLIL_SET_VAR_FIELD)
		MLIL_SET_VAR_SPLIT,  // Not valid in SSA form (see MLIL_SET_VAR_SPLIT_SSA)
		MLIL_LOAD,           // Not valid in SSA form (see MLIL_LOAD_SSA)
		MLIL_LOAD_STRUCT,    // Not valid in SSA form (see MLIL_LOAD_STRUCT_SSA)
		MLIL_STORE,          // Not valid in SSA form (see MLIL_STORE_SSA)
		MLIL_STORE_STRUCT,   // Not valid in SSA form (see MLIL_STORE_STRUCT_SSA)
		MLIL_VAR,            // Not valid in SSA form (see MLIL_VAR_SSA)
		MLIL_VAR_FIELD,      // Not valid in SSA form (see MLIL_VAR_SSA_FIELD)
		MLIL_VAR_SPLIT,      // Not valid in SSA form (see MLIL_VAR_SPLIT_SSA)
		MLIL_ADDRESS_OF,
		MLIL_ADDRESS_OF_FIELD,
		MLIL_CONST,
		MLIL_CONST_DATA,
		MLIL_CONST_PTR,
		MLIL_EXTERN_PTR,
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
		MLIL_RET_HINT,             // Intermediate stages, does not appear in final forms
		MLIL_CALL,                 // Not valid in SSA form (see MLIL_CALL_SSA)
		MLIL_CALL_UNTYPED,         // Not valid in SSA form (see MLIL_CALL_UNTYPED_SSA)
		MLIL_CALL_OUTPUT,          // Only valid within MLIL_CALL, MLIL_SYSCALL, MLIL_TAILCALL family instructions
		MLIL_CALL_PARAM,           // Only valid within MLIL_CALL, MLIL_SYSCALL, MLIL_TAILCALL family instructions
		MLIL_SEPARATE_PARAM_LIST,  // Only valid within the MLIL_CALL_PARAM or MLIL_CALL_PARAM_SSA instructions inside
		                           // untyped call variants
		MLIL_SHARED_PARAM_SLOT,    // Only valid within the MLIL_CALL_PARAM, MLIL_CALL_PARAM_SSA, or
		                           // MLIL_SEPARATE_PARAM_LIST instructions inside untyped call variants
		MLIL_RET,
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
		MLIL_SYSCALL,           // Not valid in SSA form (see MLIL_SYSCALL_SSA)
		MLIL_SYSCALL_UNTYPED,   // Not valid in SSA form (see MLIL_SYSCALL_UNTYPED_SSA)
		MLIL_TAILCALL,          // Not valid in SSA form (see MLIL_TAILCALL_SSA)
		MLIL_TAILCALL_UNTYPED,  // Not valid in SSA form (see MLIL_TAILCALL_UNTYPED_SSA)
		MLIL_INTRINSIC,         // Not valid in SSA form (see MLIL_INTRINSIC_SSA)
		MLIL_FREE_VAR_SLOT,     // Not valid in SSA from (see MLIL_FREE_VAR_SLOT_SSA)
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
		MLIL_CALL_PARAM_SSA,   // Only valid within the MLIL_CALL_SSA, MLIL_SYSCALL_SSA, MLIL_TAILCALL_SSA, MLIL_INTRINSIC_SSA family
		                       // instructions
		MLIL_CALL_OUTPUT_SSA,  // Only valid within the MLIL_CALL_SSA or MLIL_SYSCALL_SSA, MLIL_TAILCALL_SSA family
		                       // instructions
		MLIL_MEMORY_INTRINSIC_OUTPUT_SSA,  // Only valid within the MLIL_MEMORY_INTRINSIC_SSA instruction
		MLIL_LOAD_SSA,
		MLIL_LOAD_STRUCT_SSA,
		MLIL_STORE_SSA,
		MLIL_STORE_STRUCT_SSA,
		MLIL_INTRINSIC_SSA,
		MLIL_MEMORY_INTRINSIC_SSA,
		MLIL_FREE_VAR_SLOT_SSA,
		MLIL_VAR_PHI,
		MLIL_MEM_PHI
	} BNMediumLevelILOperation;

	typedef struct BNMediumLevelILInstruction
	{
		BNMediumLevelILOperation operation;
		uint32_t attributes;
		uint32_t sourceOperand;
		size_t size;
		uint64_t operands[5];
		uint64_t address;
	} BNMediumLevelILInstruction;

	typedef struct BNMediumLevelILLabel
	{
		bool resolved;
		size_t ref;
		size_t operand;
	} BNMediumLevelILLabel;

	typedef enum BNVariableSourceType
	{
		StackVariableSourceType,
		RegisterVariableSourceType,
		FlagVariableSourceType
	} BNVariableSourceType;

	typedef struct BNVariable
	{
		BNVariableSourceType type;
		uint32_t index;
		int64_t storage;
	} BNVariable;

	typedef enum BNHighLevelILOperation
	{
		HLIL_NOP,

		HLIL_BLOCK,
		HLIL_IF,
		HLIL_WHILE,
		HLIL_DO_WHILE,
		HLIL_FOR,
		HLIL_SWITCH,
		HLIL_CASE,
		HLIL_BREAK,
		HLIL_CONTINUE,
		HLIL_JUMP,
		HLIL_RET,
		HLIL_NORET,
		HLIL_GOTO,
		HLIL_LABEL,

		HLIL_VAR_DECLARE,
		HLIL_VAR_INIT,
		HLIL_ASSIGN,
		HLIL_ASSIGN_UNPACK,
		HLIL_VAR,
		HLIL_STRUCT_FIELD,
		HLIL_ARRAY_INDEX,
		HLIL_SPLIT,
		HLIL_DEREF,
		HLIL_DEREF_FIELD,
		HLIL_ADDRESS_OF,
		HLIL_CONST,
		HLIL_CONST_DATA,
		HLIL_CONST_PTR,
		HLIL_EXTERN_PTR,
		HLIL_FLOAT_CONST,
		HLIL_IMPORT,
		HLIL_ADD,
		HLIL_ADC,
		HLIL_SUB,
		HLIL_SBB,
		HLIL_AND,
		HLIL_OR,
		HLIL_XOR,
		HLIL_LSL,
		HLIL_LSR,
		HLIL_ASR,
		HLIL_ROL,
		HLIL_RLC,
		HLIL_ROR,
		HLIL_RRC,
		HLIL_MUL,
		HLIL_MULU_DP,
		HLIL_MULS_DP,
		HLIL_DIVU,
		HLIL_DIVU_DP,
		HLIL_DIVS,
		HLIL_DIVS_DP,
		HLIL_MODU,
		HLIL_MODU_DP,
		HLIL_MODS,
		HLIL_MODS_DP,
		HLIL_NEG,
		HLIL_NOT,
		HLIL_SX,
		HLIL_ZX,
		HLIL_LOW_PART,
		HLIL_CALL,
		HLIL_CMP_E,
		HLIL_CMP_NE,
		HLIL_CMP_SLT,
		HLIL_CMP_ULT,
		HLIL_CMP_SLE,
		HLIL_CMP_ULE,
		HLIL_CMP_SGE,
		HLIL_CMP_UGE,
		HLIL_CMP_SGT,
		HLIL_CMP_UGT,
		HLIL_TEST_BIT,
		HLIL_BOOL_TO_INT,
		HLIL_ADD_OVERFLOW,
		HLIL_SYSCALL,
		HLIL_TAILCALL,
		HLIL_INTRINSIC,
		HLIL_BP,
		HLIL_TRAP,
		HLIL_UNDEF,
		HLIL_UNIMPL,
		HLIL_UNIMPL_MEM,

		// Floating point
		HLIL_FADD,
		HLIL_FSUB,
		HLIL_FMUL,
		HLIL_FDIV,
		HLIL_FSQRT,
		HLIL_FNEG,
		HLIL_FABS,
		HLIL_FLOAT_TO_INT,
		HLIL_INT_TO_FLOAT,
		HLIL_FLOAT_CONV,
		HLIL_ROUND_TO_INT,
		HLIL_FLOOR,
		HLIL_CEIL,
		HLIL_FTRUNC,
		HLIL_FCMP_E,
		HLIL_FCMP_NE,
		HLIL_FCMP_LT,
		HLIL_FCMP_LE,
		HLIL_FCMP_GE,
		HLIL_FCMP_GT,
		HLIL_FCMP_O,
		HLIL_FCMP_UO,

		// Unreachable hint, typically used in switch statements that analysis knows
		// has an unreachable default.
		HLIL_UNREACHABLE,

		// The following instructions are only used in SSA form
		HLIL_WHILE_SSA,
		HLIL_DO_WHILE_SSA,
		HLIL_FOR_SSA,
		HLIL_VAR_INIT_SSA,
		HLIL_ASSIGN_MEM_SSA,
		HLIL_ASSIGN_UNPACK_MEM_SSA,
		HLIL_VAR_SSA,
		HLIL_ARRAY_INDEX_SSA,
		HLIL_DEREF_SSA,
		HLIL_DEREF_FIELD_SSA,
		HLIL_CALL_SSA,
		HLIL_SYSCALL_SSA,
		HLIL_INTRINSIC_SSA,
		HLIL_VAR_PHI,
		HLIL_MEM_PHI
	} BNHighLevelILOperation;

	typedef struct BNHighLevelILInstruction
	{
		BNHighLevelILOperation operation;
		uint32_t attributes;
		uint32_t sourceOperand;
		size_t size;
		uint64_t operands[5];
		uint64_t address;
		size_t parent;
	} BNHighLevelILInstruction;

	// Callbacks
	typedef struct BNLogListener
	{
		void* context;
		void (*log)(void* ctxt, size_t sessionId, BNLogLevel level, const char* msg, const char* logger_name, size_t tid);
		void (*close)(void* ctxt);
		BNLogLevel (*getLogLevel)(void* ctxt);
	} BNLogListener;

	typedef struct BNNavigationHandler
	{
		void* context;
		char* (*getCurrentView)(void* ctxt);
		uint64_t (*getCurrentOffset)(void* ctxt);
		bool (*navigate)(void* ctxt, const char* view, uint64_t offset);
	} BNNavigationHandler;

	typedef struct BNNameList
	{
		char** name;
		char* join;
		size_t nameCount;
	} BNNameList;

	typedef struct BNNameSpace
	{
		char** name;
		char* join;
		size_t nameCount;
	} BNNameSpace;

	typedef struct BNQualifiedName
	{
		char** name;
		char* join;
		size_t nameCount;
	} BNQualifiedName;

	typedef struct BNBinaryDataNotification
	{
		void* context;
		uint64_t (*notificationBarrier)(void*ctxt, BNBinaryView* view);
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
		void (*dataMetadataUpdated)(void* ctxt, BNBinaryView* view, uint64_t offset);
		void (*tagTypeUpdated)(void* ctxt, BNBinaryView* view, BNTagType* tagType);
		void (*tagAdded)(void* ctxt, BNBinaryView* view, BNTagReference* tagRef);
		void (*tagRemoved)(void* ctxt, BNBinaryView* view, BNTagReference* tagRef);
		void (*tagUpdated)(void* ctxt, BNBinaryView* view, BNTagReference* tagRef);

		void (*symbolAdded)(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		void (*symbolRemoved)(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		void (*symbolUpdated)(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		void (*stringFound)(void* ctxt, BNBinaryView* view, BNStringType type, uint64_t offset, size_t len);
		void (*stringRemoved)(void* ctxt, BNBinaryView* view, BNStringType type, uint64_t offset, size_t len);
		void (*typeDefined)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeUndefined)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeReferenceChanged)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, BNType* type);
		void (*typeFieldReferenceChanged)(void* ctxt, BNBinaryView* view, BNQualifiedName* name, uint64_t offset);
		void (*segmentAdded)(void* ctxt, BNBinaryView* view, BNSegment* segment);
		void (*segmentRemoved)(void* ctxt, BNBinaryView* view, BNSegment* segment);
		void (*segmentUpdated)(void* ctxt, BNBinaryView* view, BNSegment* segment);
		void (*sectionAdded)(void* ctxt, BNBinaryView* view, BNSection* section);
		void (*sectionRemoved)(void* ctxt, BNBinaryView* view, BNSection* section);
		void (*sectionUpdated)(void* ctxt, BNBinaryView* view, BNSection* section);
		void (*componentNameUpdated)(void* ctxt, BNBinaryView* view, char* previousName, BNComponent* component);
		void (*componentAdded)(void*ctxt, BNBinaryView* view, BNComponent* component);
		void (*componentMoved)(void*ctxt, BNBinaryView* view, BNComponent* formerParent, BNComponent* newParent, BNComponent* component);
		void (*componentRemoved)(void*ctxt, BNBinaryView* view, BNComponent* formerParent, BNComponent* component);
		void (*componentFunctionAdded)(void*ctxt, BNBinaryView* view, BNComponent* component, BNFunction* function);
		void (*componentFunctionRemoved)(void*ctxt, BNBinaryView* view, BNComponent* component, BNFunction* function);
		void (*componentDataVariableAdded)(void*ctxt, BNBinaryView* view, BNComponent* component, BNDataVariable* var);
		void (*componentDataVariableRemoved)(void*ctxt, BNBinaryView* view, BNComponent* component, BNDataVariable* var);
		void (*externalLibraryAdded)(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		void (*externalLibraryUpdated)(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		void (*externalLibraryRemoved)(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		void (*externalLocationAdded)(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		void (*externalLocationUpdated)(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		void (*externalLocationRemoved)(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		void (*typeArchiveAttached)(void* ctxt, BNBinaryView* view, const char* id, const char* path);
		void (*typeArchiveDetached)(void* ctxt, BNBinaryView* view, const char* id, const char* path);
		void (*typeArchiveConnected)(void* ctxt, BNBinaryView* view, BNTypeArchive* archive);
		void (*typeArchiveDisconnected)(void* ctxt, BNBinaryView* view, BNTypeArchive* archive);
		void (*undoEntryAdded)(void* ctxt, BNBinaryView* view, BNUndoEntry* entry);
		void (*undoEntryTaken)(void* ctxt, BNBinaryView* view, BNUndoEntry* entry);
		void (*redoEntryTaken)(void* ctxt, BNBinaryView* view, BNUndoEntry* entry);
		void (*rebased)(void* ctxt, BNBinaryView* oldView, BNBinaryView* newView);
	} BNBinaryDataNotification;

	typedef struct BNProjectNotification
	{
		void* context;
		bool (*beforeOpenProject)(void* ctxt, BNProject* project);
		void (*afterOpenProject)(void* ctxt, BNProject* project);
		bool (*beforeCloseProject)(void* ctxt, BNProject* project);
		void (*afterCloseProject)(void* ctxt, BNProject* project);
		bool (*beforeProjectMetadataWritten)(void* ctxt, BNProject* project, char* key, BNMetadata* value);
		void (*afterProjectMetadataWritten)(void* ctxt, BNProject* project, char* key, BNMetadata* value);
		bool (*beforeProjectFileCreated)(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		void (*afterProjectFileCreated)(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		bool (*beforeProjectFileUpdated)(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		void (*afterProjectFileUpdated)(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		bool (*beforeProjectFileDeleted)(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		void (*afterProjectFileDeleted)(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		bool (*beforeProjectFolderCreated)(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		void (*afterProjectFolderCreated)(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		bool (*beforeProjectFolderUpdated)(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		void (*afterProjectFolderUpdated)(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		bool (*beforeProjectFolderDeleted)(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		void (*afterProjectFolderDeleted)(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
	} BNProjectNotification;

	typedef struct BNFileAccessor
	{
		void* context;
		uint64_t (*getLength)(void* ctxt);
		size_t (*read)(void* ctxt, void* dest, uint64_t offset, size_t len);
		size_t (*write)(void* ctxt, uint64_t offset, const void* src, size_t len);
	} BNFileAccessor;

	typedef struct BNCustomBinaryView
	{
		void* context;
		bool (*init)(void* ctxt);
		void (*freeObject)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
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
	} BNCustomBinaryView;

	typedef struct BNCustomBinaryViewType
	{
		void* context;
		BNBinaryView* (*create)(void* ctxt, BNBinaryView* data);
		BNBinaryView* (*parse)(void* ctxt, BNBinaryView* data);
		bool (*isValidForData)(void* ctxt, BNBinaryView* data);
		bool (*isDeprecated)(void* ctxt);
		bool (*isForceLoadable)(void* ctxt);
		BNSettings* (*getLoadSettingsForData)(void* ctxt, BNBinaryView* data);
	} BNCustomBinaryViewType;

	typedef struct BNTransformParameterInfo
	{
		char* name;
		char* longName;
		size_t fixedLength;  // Variable length if zero
	} BNTransformParameterInfo;

	typedef struct BNTransformParameter
	{
		const char* name;
		BNDataBuffer* value;
	} BNTransformParameter;

	typedef struct BNCustomTransform
	{
		void* context;
		BNTransformParameterInfo* (*getParameters)(void* ctxt, size_t* count);
		void (*freeParameters)(BNTransformParameterInfo* params, size_t count);
		bool (*decode)(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		bool (*encode)(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
	} BNCustomTransform;

	typedef struct BNInstructionInfo
	{
		size_t length;
		size_t branchCount;
		bool archTransitionByTargetAddr;
		uint8_t delaySlots;
		BNBranchType branchType[BN_MAX_INSTRUCTION_BRANCHES];
		uint64_t branchTarget[BN_MAX_INSTRUCTION_BRANCHES];
		BNArchitecture* branchArch[BN_MAX_INSTRUCTION_BRANCHES];  // If null, same architecture as instruction
	} BNInstructionInfo;

	typedef enum BNRelocationType
	{
		ELFGlobalRelocationType,
		ELFCopyRelocationType,
		ELFJumpSlotRelocationType,
		StandardRelocationType,
		IgnoredRelocation,
		UnhandledRelocation
	} BNRelocationType;
#define MAX_RELOCATION_SIZE 8
	typedef struct BNRelocationInfo
	{
		BNRelocationType type;  // BinaryNinja Relocation Type
		bool pcRelative;        // PC Relative or Absolute (subtract address from relocation)
		bool baseRelative;      // Relative to start of module (Add module base to relocation)
		uint64_t base;          // Base address for this binary view
		size_t size;            // Size of the data to be written
		size_t truncateSize;    // After addition/subtraction truncate to
		uint64_t nativeType;    // Base type from relocation entry
		size_t addend;          // Addend value from relocation entry
		bool hasSign;           // Addend should be subtracted
		bool implicitAddend;    // Addend should be read from the BinaryView
		bool external;          // Relocation entry points to external symbol
		size_t symbolIndex;     // Index into symbol table
		size_t sectionIndex;    // Index into the section table
		uint64_t address;       // Absolute address or segment offset
		uint64_t target;        // Target (set automatically)
		bool dataRelocation;    // This relocation is effecting data not code
		uint8_t relocationDataCache[MAX_RELOCATION_SIZE];
		struct BNRelocationInfo* prev;  // Link to relocation another related relocation
		struct BNRelocationInfo* next;  // Link to relocation another related relocation
	} BNRelocationInfo;

	typedef struct BNInstructionTextToken
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
		size_t exprIndex;
	} BNInstructionTextToken;

	typedef struct BNInstructionTextLine
	{
		BNInstructionTextToken* tokens;
		size_t count;
	} BNInstructionTextLine;

	typedef enum BNTypeDefinitionLineType
	{
		TypedefLineType,
		StructDefinitionLineType,
		StructFieldLineType,
		StructDefinitionEndLineType,
		EnumDefinitionLineType,
		EnumMemberLineType,
		EnumDefinitionEndLineType,
		PaddingLineType,
		UndefinedXrefLineType,
		CollapsedPaddingLineType,
		EmptyLineType,
	} BNTypeDefinitionLineType;

	typedef struct BNTypeDefinitionLine
	{
		BNTypeDefinitionLineType lineType;
		BNInstructionTextToken* tokens;
		size_t count;
		BNType* type;
		BNType* parentType;
		BNType* rootType;
		char* rootTypeName;
		BNNamedTypeReference* baseType;
		uint64_t baseOffset;
		uint64_t offset;
		size_t fieldIndex;
	} BNTypeDefinitionLine;


	typedef struct BNFlagConditionForSemanticClass
	{
		uint32_t semanticClass;
		BNLowLevelILFlagCondition condition;
	} BNFlagConditionForSemanticClass;

	typedef struct BNNameAndType
	{
		char* name;
		BNType* type;
		uint8_t typeConfidence;
	} BNNameAndType;

	typedef struct BNTypeWithConfidence
	{
		BNType* type;
		uint8_t confidence;
	} BNTypeWithConfidence;

	typedef struct BNCustomArchitecture
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
		bool (*getInstructionInfo)(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
		bool (*getInstructionText)(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len,
		    BNInstructionTextToken** result, size_t* count);
		void (*freeInstructionText)(BNInstructionTextToken* tokens, size_t count);
		bool (*getInstructionLowLevelIL)(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
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
		uint32_t* (*getFlagsRequiredForFlagCondition)(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
		uint32_t* (*getFlagsRequiredForSemanticFlagGroup)(void* ctxt, uint32_t semGroup, size_t* count);
		BNFlagConditionForSemanticClass* (*getFlagConditionsForSemanticFlagGroup)(
		    void* ctxt, uint32_t semGroup, size_t* count);
		void (*freeFlagConditionsForSemanticFlagGroup)(void* ctxt, BNFlagConditionForSemanticClass* conditions);
		uint32_t* (*getFlagsWrittenByFlagWriteType)(void* ctxt, uint32_t writeType, size_t* count);
		uint32_t (*getSemanticClassForFlagWriteType)(void* ctxt, uint32_t writeType);
		size_t (*getFlagWriteLowLevelIL)(void* ctxt, BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il);
		size_t (*getFlagConditionLowLevelIL)(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
		size_t (*getSemanticFlagGroupLowLevelIL)(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs);
		void (*getRegisterInfo)(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		uint32_t (*getStackPointerRegister)(void* ctxt);
		uint32_t (*getLinkRegister)(void* ctxt);
		uint32_t* (*getGlobalRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getSystemRegisters)(void* ctxt, size_t* count);

		char* (*getRegisterStackName)(void* ctxt, uint32_t regStack);
		uint32_t* (*getAllRegisterStacks)(void* ctxt, size_t* count);
		void (*getRegisterStackInfo)(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		BNIntrinsicClass (*getIntrinsicClass)(void* ctxt, uint32_t intrinsic);
		char* (*getIntrinsicName)(void* ctxt, uint32_t intrinsic);
		uint32_t* (*getAllIntrinsics)(void* ctxt, size_t* count);
		BNNameAndType* (*getIntrinsicInputs)(void* ctxt, uint32_t intrinsic, size_t* count);
		void (*freeNameAndTypeList)(void* ctxt, BNNameAndType* nt, size_t count);
		BNTypeWithConfidence* (*getIntrinsicOutputs)(void* ctxt, uint32_t intrinsic, size_t* count);
		void (*freeTypeList)(void* ctxt, BNTypeWithConfidence* types, size_t count);

		bool (*canAssemble)(void* ctxt);
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
	} BNCustomArchitecture;

	typedef struct BNCustomPlatform
	{
		void* context;
		void (*init)(void* ctxt, BNPlatform* obj);
		void (*viewInit)(void* ctxt, BNBinaryView* view);

		uint32_t* (*getGlobalRegisters)(void* ctxt, size_t* count);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs, size_t len);

		BNType* (*getGlobalRegisterType)(void* ctxt, uint32_t reg);

		void (*adjustTypeParserInput)(
			void* ctxt,
			BNTypeParser* parser,
			const char* const* argumentsIn,
			size_t argumentsLenIn,
			const char* const* sourceFileNamesIn,
			const char* const* sourceFileValuesIn,
			size_t sourceFilesLenIn,
			char*** argumentsOut,
			size_t* argumentsLenOut,
			char*** sourceFileNamesOut,
			char*** sourceFileValuesOut,
			size_t* sourceFilesLenOut
		);
		void (*freeTypeParserInput)(
			void* ctxt,
			char** arguments,
			size_t argumentsLen,
			char** sourceFileNames,
			char** sourceFileValues,
			size_t sourceFilesLen
		);

		bool (*getFallbackEnabled)(void* ctxt);
	} BNCustomPlatform;

	typedef struct BNBasicBlockEdge
	{
		BNBranchType type;
		BNBasicBlock* target;
		bool backEdge;
		bool fallThrough;
	} BNBasicBlockEdge;

	typedef struct BNPoint
	{
		float x;
		float y;
	} BNPoint;

	typedef enum BNThemeColor
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
		GraphNodeShadowColor,
		GraphEntryNodeIndicatorColor,
		GraphExitNodeIndicatorColor,
		GraphExitNoreturnNodeIndicatorColor,
		TrueBranchColor,
		FalseBranchColor,
		UnconditionalBranchColor,
		AltTrueBranchColor,
		AltFalseBranchColor,
		AltUnconditionalBranchColor,

		// Disassembly colors
		InstructionColor,
		RegisterColor,
		NumberColor,
		CodeSymbolColor,
		DataSymbolColor,
		LocalVariableColor,
		StackVariableColor,
		ImportColor,
		ExportColor,
		InstructionHighlightColor,
		RelatedInstructionHighlightColor,
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
		OperationColor,
		BaseStructureNameColor,
		IndentationLineColor,
		IndentationLineHighlightColor,

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
		SidebarHeaderBackgroundColor,  // Deprecated, has no effect (paints as QPalette::Window)
		SidebarHeaderTextColor,
		SidebarWidgetBackgroundColor,

		// Pane colors
		ActivePaneBackgroundColor,
		InactivePaneBackgroundColor,

		// Tab colors
		TabBarTabActiveColor,
		TabBarTabHoverColor,
		TabBarTabInactiveColor,
		TabBarTabBorderColor,
		TabBarTabGlowColor,

		// Status colors
		StatusBarServerConnectedColor,
		StatusBarServerDisconnectedColor,
		StatusBarServerWarningColor,
		StatusBarProjectColor,

		// Brace colors
		BraceOption1Color,
		BraceOption2Color,
		BraceOption3Color,
		BraceOption4Color,
		BraceOption5Color,
		BraceOption6Color,

		// Type class colors
		VoidTypeColor,
		StructureTypeColor,
		EnumerationTypeColor,
		FunctionTypeColor,
		BoolTypeColor,
		IntegerTypeColor,
		FloatTypeColor,
		PointerTypeColor,
		ArrayTypeColor,
		VarArgsTypeColor,
		ValueTypeColor,
		NamedTypeReferenceColor,
		WideCharTypeColor,
	} BNThemeColor;

	// The following edge styles map to Qt's Qt::PenStyle enumeration
	typedef enum BNEdgePenStyle
	{
		NoPen = 0,           // no line at all.
		SolidLine = 1,       // A plain line (default)
		DashLine = 2,        // Dashes separated by a few pixels.
		DotLine = 3,         // Dots separated by a few pixels.
		DashDotLine = 4,     // Alternate dots and dashes.
		DashDotDotLine = 5,  // One dash, two dots, one dash, two dots.
	} BNEdgePenStyle;

	typedef struct BNEdgeStyle
	{
		BNEdgePenStyle style;
		size_t width;
		BNThemeColor color;
	} BNEdgeStyle;

	typedef struct BNFlowGraphEdge
	{
		BNBranchType type;
		BNFlowGraphNode* target;
		BNPoint* points;
		size_t pointCount;
		bool backEdge;
		BNEdgeStyle style;
	} BNFlowGraphEdge;

	typedef enum BNHighlightColorStyle
	{
		StandardHighlightColor = 0,
		MixedHighlightColor = 1,
		CustomHighlightColor = 2
	} BNHighlightColorStyle;

	typedef enum BNHighlightStandardColor
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
	} BNHighlightStandardColor;

	typedef struct BNHighlightColor
	{
		BNHighlightColorStyle style;
		BNHighlightStandardColor color;
		BNHighlightStandardColor mixColor;
		uint8_t mix, r, g, b, alpha;
	} BNHighlightColor;

	typedef struct BNDisassemblyTextLineTypeInfo
	{
		bool hasTypeInfo;
		BNType* parentType;
		size_t fieldIndex;
		uint64_t offset;
	} BNDisassemblyTextLineTypeInfo;

	typedef struct BNDisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		BNInstructionTextToken* tokens;
		size_t count;
		BNHighlightColor highlight;
		BNTag** tags;
		size_t tagCount;
		BNDisassemblyTextLineTypeInfo typeInfo;
	} BNDisassemblyTextLine;

	typedef struct BNLinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		BNFunction* function;
		BNBasicBlock* block;
		BNDisassemblyTextLine contents;
	} BNLinearDisassemblyLine;

	typedef struct BNReferenceSource
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
	} BNReferenceSource;

	typedef struct BNTypeFieldReference
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
		size_t size;
		BNTypeWithConfidence incomingType;
	} BNTypeFieldReference;

	typedef struct BNILReferenceSource
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
		BNFunctionGraphType type;
		size_t exprId;
	} BNILReferenceSource;

	typedef struct BNTypeFieldReferenceSizeInfo
	{
		uint64_t offset;
		size_t* sizes;
		size_t count;
	} BNTypeFieldReferenceSizeInfo;

	typedef struct BNTypeFieldReferenceTypeInfo
	{
		uint64_t offset;
		BNTypeWithConfidence* types;
		size_t count;
	} BNTypeFieldReferenceTypeInfo;

	typedef struct BNVariableReferenceSource
	{
		BNVariable var;
		BNILReferenceSource source;
	} BNVariableReferenceSource;

	typedef struct BNTypeField
	{
		BNQualifiedName name;
		uint64_t offset;
	} BNTypeField;

	// This describes how a type is referenced
	typedef enum BNTypeReferenceType
	{
		// Type A contains type B
		DirectTypeReferenceType,
		// All other cases, e.g., type A contains a pointer to type B
		IndirectTypeReferenceType,
		// The nature of the reference is unknown
		UnknownTypeReferenceType
	} BNTypeReferenceType;

	typedef struct BNTypeReferenceSource
	{
		BNQualifiedName name;
		uint64_t offset;
		BNTypeReferenceType type;
	} BNTypeReferenceSource;

	typedef enum BNTagTypeType
	{
		UserTagType,
		NotificationTagType,
		BookmarksTagType
	} BNTagTypeType;

	typedef enum BNTagReferenceType
	{
		AddressTagReference,
		FunctionTagReference,
		DataTagReference
	} BNTagReferenceType;

	typedef struct BNTagReference
	{
		BNTagReferenceType refType;
		bool autoDefined;
		BNTag* tag;
		BNArchitecture* arch;
		BNFunction* func;
		uint64_t addr;
	} BNTagReference;

	typedef struct BNCallingConventionWithConfidence
	{
		BNCallingConvention* convention;
		uint8_t confidence;
	} BNCallingConventionWithConfidence;

	typedef struct BNBoolWithConfidence
	{
		bool value;
		uint8_t confidence;
	} BNBoolWithConfidence;

	typedef struct BNOffsetWithConfidence
	{
		int64_t value;
		uint8_t confidence;
	} BNOffsetWithConfidence;

	typedef struct BNParameterVariablesWithConfidence
	{
		BNVariable* vars;
		size_t count;
		uint8_t confidence;
	} BNParameterVariablesWithConfidence;

	typedef struct BNRegisterSetWithConfidence
	{
		uint32_t* regs;
		size_t count;
		uint8_t confidence;
	} BNRegisterSetWithConfidence;

	typedef struct BNFunctionParameter
	{
		char* name;
		BNType* type;
		uint8_t typeConfidence;
		bool defaultLocation;
		BNVariable location;
	} BNFunctionParameter;

	typedef struct BNQualifiedNameAndType
	{
		BNQualifiedName name;
		BNType* type;
	} BNQualifiedNameAndType;

	typedef struct BNQualifiedNameTypeAndId
	{
		BNQualifiedName name;
		char* id;
		BNType* type;
	} BNQualifiedNameTypeAndId;

	typedef struct BNStructureMember
	{
		BNType* type;
		char* name;
		uint64_t offset;
		uint8_t typeConfidence;
		BNMemberAccess access;
		BNMemberScope scope;
	} BNStructureMember;

	typedef struct BNInheritedStructureMember
	{
		BNNamedTypeReference* base;
		uint64_t baseOffset;
		BNStructureMember member;
		size_t memberIndex;
	} BNInheritedStructureMember;

	typedef struct BNBaseStructure
	{
		BNNamedTypeReference* type;
		uint64_t offset;
		uint64_t width;
	} BNBaseStructure;

	typedef struct BNEnumerationMember
	{
		char* name;
		uint64_t value;
		bool isDefault;
	} BNEnumerationMember;

	typedef struct BNFunctionRecognizer
	{
		void* context;
		bool (*recognizeLowLevelIL)(void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		bool (*recognizeMediumLevelIL)(void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);
	} BNFunctionRecognizer;

	typedef struct BNCustomRelocationHandler
	{
		void* context;
		void (*freeObject)(void* ctxt);

		bool (*getRelocationInfo)(
		    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* result, size_t resultCount);
		bool (*applyRelocation)(
		    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
		size_t (*getOperandForExternalRelocation)(void* ctxt, const uint8_t* data, uint64_t addr, size_t length,
		    BNLowLevelILFunction* il, BNRelocation* relocation);
	} BNCustomRelocationHandler;

	typedef enum BNTypeParserOption
	{
		IncludeSystemTypes,
		BuiltinMacros,
	} BNTypeParserOption;

	typedef struct BNParsedType
	{
		BNQualifiedName name;
		BNType* type;
		bool isUser;
	} BNParsedType;

	typedef struct BNTypeParserResult
	{
		BNParsedType* types;
		BNParsedType* variables;
		BNParsedType* functions;
		size_t typeCount, variableCount, functionCount;
	} BNTypeParserResult;

	typedef enum BNTypeParserErrorSeverity
	{
		IgnoredSeverity = 0,
		NoteSeverity = 1,
		RemarkSeverity = 2,
		WarningSeverity = 3,
		ErrorSeverity = 4,
		FatalSeverity = 5,
	} BNTypeParserErrorSeverity;

	typedef struct BNTypeParserError
	{
		BNTypeParserErrorSeverity severity;
		char* message;
		char* fileName;
		uint64_t line;
		uint64_t column;
	} BNTypeParserError;

	typedef struct BNQualifiedNameList
	{
		BNQualifiedName* names;
		size_t count;
	} BNQualifiedNameList;

	typedef enum BNUpdateResult
	{
		UpdateFailed = 0,
		UpdateSuccess = 1,
		AlreadyUpToDate = 2,
		UpdateAvailable = 3
	} BNUpdateResult;

	typedef struct BNUpdateChannel
	{
		char* name;
		char* description;
		char* latestVersion;
	} BNUpdateChannel;

	typedef struct BNVersionInfo {
		uint32_t major;
		uint32_t minor;
		uint32_t build;
		char* channel;
	} BNVersionInfo;

	typedef struct BNChangelogEntry {
		BNVersionInfo version;
		char* notes;
		uint64_t time;
	} BNChangelogEntry;

	typedef struct BNUpdateVersionNew {
		BNVersionInfo version;
		char* name;
		uint64_t time;
	} BNUpdateVersionNew;

	typedef struct BNUpdateChannelFullInfo {
		BNUpdateVersionNew* versions;
		uint64_t versionCount;
		BNChangelogEntry* changelogEntries;
		uint64_t changelogEntryCount;
		char* name;
		char* desc;
		char* latestVersion;
	} BNUpdateChannelFullInfo;

	typedef struct BNUpdateVersion
	{
		char* version;
		char* notes;
		uint64_t time;
	} BNUpdateVersion;

	typedef struct BNStringReference
	{
		BNStringType type;
		uint64_t start;
		size_t length;
	} BNStringReference;

	typedef enum BNPluginCommandType
	{
		DefaultPluginCommand,
		AddressPluginCommand,
		RangePluginCommand,
		FunctionPluginCommand,
		LowLevelILFunctionPluginCommand,
		LowLevelILInstructionPluginCommand,
		MediumLevelILFunctionPluginCommand,
		MediumLevelILInstructionPluginCommand,
		HighLevelILFunctionPluginCommand,
		HighLevelILInstructionPluginCommand
	} BNPluginCommandType;

	typedef struct BNPluginCommand
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
		void (*mediumLevelILInstructionCommand)(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		void (*highLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		void (*highLevelILInstructionCommand)(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		bool (*defaultIsValid)(void* ctxt, BNBinaryView* view);
		bool (*addressIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr);
		bool (*rangeIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		bool (*functionIsValid)(void* ctxt, BNBinaryView* view, BNFunction* func);
		bool (*lowLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		bool (*lowLevelILInstructionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		bool (*mediumLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		bool (*mediumLevelILInstructionIsValid)(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		bool (*highLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		bool (*highLevelILInstructionIsValid)(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);
	} BNPluginCommand;

	typedef struct BNCustomCallingConvention
	{
		void* context;

		void (*freeObject)(void* ctxt);

		uint32_t* (*getCallerSavedRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getCalleeSavedRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getIntegerArgumentRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getFloatArgumentRegisters)(void* ctxt, size_t* count);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs);

		bool (*areArgumentRegistersSharedIndex)(void* ctxt);
		bool (*isStackReservedForArgumentRegisters)(void* ctxt);
		bool (*isStackAdjustedOnReturn)(void* ctxt);
		bool (*isEligibleForHeuristics)(void* ctxt);

		uint32_t (*getIntegerReturnValueRegister)(void* ctxt);
		uint32_t (*getHighIntegerReturnValueRegister)(void* ctxt);
		uint32_t (*getFloatReturnValueRegister)(void* ctxt);
		uint32_t (*getGlobalPointerRegister)(void* ctxt);

		uint32_t* (*getImplicitlyDefinedRegisters)(void* ctxt, size_t* count);
		void (*getIncomingRegisterValue)(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		void (*getIncomingFlagValue)(void* ctxt, uint32_t flag, BNFunction* func, BNRegisterValue* result);

		void (*getIncomingVariableForParameterVariable)(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);
		void (*getParameterVariableForIncomingVariable)(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);

		bool (*areArgumentRegistersUsedForVarArgs)(void* ctxt);
	} BNCustomCallingConvention;

	typedef struct BNVariableNameAndType
	{
		BNVariable var;
		BNType* type;
		char* name;
		bool autoDefined;
		uint8_t typeConfidence;
	} BNVariableNameAndType;

	typedef struct BNStackVariableReference
	{
		uint32_t sourceOperand;
		uint8_t typeConfidence;
		BNType* type;
		char* name;
		uint64_t varIdentifier;
		int64_t referencedOffset;
		size_t size;
	} BNStackVariableReference;

	typedef struct BNIndirectBranchInfo
	{
		BNArchitecture* sourceArch;
		uint64_t sourceAddr;
		BNArchitecture* destArch;
		uint64_t destAddr;
		bool autoDefined;
	} BNIndirectBranchInfo;

	typedef struct BNArchitectureAndAddress
	{
		BNArchitecture* arch;
		uint64_t address;
	} BNArchitectureAndAddress;

	typedef struct BNUserVariableValue
	{
		BNVariable var;
		BNArchitectureAndAddress defSite;
		BNPossibleValueSet value;
	} BNUserVariableValue;

	typedef enum BNFunctionUpdateType
	{
		UserFunctionUpdate,
		FullAutoFunctionUpdate,
		IncrementalAutoFunctionUpdate
	} BNFunctionUpdateType;

	typedef enum BNAnalysisState
	{
		InitialState,
		HoldState,
		IdleState,
		DisassembleState,
		AnalyzeState,
		ExtendedAnalyzeState
	} BNAnalysisState;

	typedef struct BNActiveAnalysisInfo
	{
		BNFunction* func;
		uint64_t analysisTime;
		size_t updateCount;
		size_t submitCount;
	} BNActiveAnalysisInfo;

	typedef struct BNAnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		BNActiveAnalysisInfo* activeInfo;
		size_t count;
	} BNAnalysisInfo;

	typedef struct BNAnalysisProgress
	{
		BNAnalysisState state;
		size_t count, total;
	} BNAnalysisProgress;

	typedef enum BNAnalysisMode
	{
		FullAnalysisMode,
		IntermediateAnalysisMode,
		BasicAnalysisMode,
		ControlFlowAnalysisMode
	} BNAnalysisMode;

	typedef struct BNAnalysisParameters
	{
		uint64_t maxAnalysisTime;
		uint64_t maxFunctionSize;
		uint64_t maxFunctionAnalysisTime;
		size_t maxFunctionUpdateCount;
		size_t maxFunctionSubmitCount;
		bool suppressNewAutoFunctionAnalysis;
		BNAnalysisMode mode;
		bool alwaysAnalyzeIndirectBranches;
		size_t advancedAnalysisCacheSize;
	} BNAnalysisParameters;

	typedef struct BNDownloadInstanceResponse
	{
		uint16_t statusCode;
		uint64_t headerCount;
		char** headerKeys;
		char** headerValues;
	} BNDownloadInstanceResponse;

	typedef struct BNDownloadInstanceInputOutputCallbacks
	{
		int64_t (*readCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* readContext;
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	} BNDownloadInstanceInputOutputCallbacks;

	typedef struct BNDownloadInstanceOutputCallbacks
	{
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	} BNDownloadInstanceOutputCallbacks;

	typedef struct BNDownloadInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		int (*performRequest)(void* ctxt, const char* url);
		int (*performCustomRequest)(void* ctxt, const char* method, const char* url, uint64_t headerCount,
		    const char* const* headerKeys, const char* const* headerValues, BNDownloadInstanceResponse** response);
		void (*freeResponse)(void* ctxt, BNDownloadInstanceResponse* response);
	} BNDownloadInstanceCallbacks;

	typedef struct BNDownloadProviderCallbacks
	{
		void* context;
		BNDownloadInstance* (*createInstance)(void* ctxt);
	} BNDownloadProviderCallbacks;

	typedef struct BNWebsocketClientOutputCallbacks
	{
		void* context;
		bool (*connectedCallback)(void* ctxt);
		void (*disconnectedCallback)(void* ctxt);
		void (*errorCallback)(const char* msg, void* ctxt);
		bool (*readCallback)(uint8_t* data, uint64_t len, void* ctxt);
	} BNWebsocketClientOutputCallbacks;

	typedef struct BNWebsocketClientCallbacks
	{
		void* context;
		void (*destroyClient)(void* ctxt);
		bool (*connect)(void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys,
		    const char* const* headerValues);
		bool (*write)(const uint8_t* data, uint64_t len, void* ctxt);
		bool (*disconnect)(void* ctxt);
	} BNWebsocketClientCallbacks;

	typedef struct BNWebsocketProviderCallbacks
	{
		void* context;
		BNWebsocketClient* (*createClient)(void* ctxt);
	} BNWebsocketProviderCallbacks;

	typedef enum BNFindFlag
	{
		FindCaseSensitive = 0,
		FindCaseInsensitive = 1
	} BNFindFlag;

	typedef enum BNFindRangeType
	{
		AllRangeType,
		CustomRangeType,
		CurrentFunctionRangeType
	} BNFindRangeType;

	typedef enum BNFindType
	{
		FindTypeRawString,
		FindTypeEscapedString,
		FindTypeText,
		FindTypeConstant,
		FindTypeBytes
	} BNFindType;

	typedef enum BNScriptingProviderInputReadyState
	{
		NotReadyForInput,
		ReadyForScriptExecution,
		ReadyForScriptProgramInput
	} BNScriptingProviderInputReadyState;

	typedef enum BNScriptingProviderExecuteResult
	{
		InvalidScriptInput,
		IncompleteScriptInput,
		SuccessfulScriptExecution,
		ScriptExecutionCancelled
	} BNScriptingProviderExecuteResult;


	typedef struct BNScriptingInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
		BNScriptingProviderExecuteResult (*executeScriptInput)(void* ctxt, const char* input);
		BNScriptingProviderExecuteResult (*executeScriptInputFromFilename)(void *ctxt, const char* input);
		void (*cancelScriptInput)(void* ctxt);
		void (*releaseBinaryView)(void* ctxt, BNBinaryView* view);
		void (*setCurrentBinaryView)(void* ctxt, BNBinaryView* view);
		void (*setCurrentFunction)(void* ctxt, BNFunction* func);
		void (*setCurrentBasicBlock)(void* ctxt, BNBasicBlock* block);
		void (*setCurrentAddress)(void* ctxt, uint64_t addr);
		void (*setCurrentSelection)(void* ctxt, uint64_t begin, uint64_t end);
		char* (*completeInput)(void* ctxt, const char* text, uint64_t state);
		void (*stop)(void* ctxt);
	} BNScriptingInstanceCallbacks;

	typedef struct BNScriptingProviderCallbacks
	{
		void* context;
		BNScriptingInstance* (*createInstance)(void* ctxt);
		bool (*loadModule)(void* ctxt, const char* repoPath, const char* pluginPath, bool force);
		bool (*installModules)(void* ctxt, const char* modules);
	} BNScriptingProviderCallbacks;

	typedef struct BNScriptingOutputListener
	{
		void* context;
		void (*output)(void* ctxt, const char* text);
		void (*warning)(void* ctxt, const char* text);
		void (*error)(void* ctxt, const char* text);
		void (*inputReadyStateChanged)(void* ctxt, BNScriptingProviderInputReadyState state);
	} BNScriptingOutputListener;

	typedef struct BNMainThreadCallbacks
	{
		void* context;
		void (*addAction)(void* ctxt, BNMainThreadAction* action);
	} BNMainThreadCallbacks;

	typedef struct BNTypeParserCallbacks
	{
		void* context;
		bool (*getOptionText)(void* ctxt, BNTypeParserOption option, const char* value, char** result);
		bool (*preprocessSource)(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			char** output, BNTypeParserError** errors, size_t* errorCount
		);
		bool (*parseTypesFromSource)(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			const char* autoTypeSource, BNTypeParserResult* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		bool (*parseTypeString)(void* ctxt,
			const char* source, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			BNQualifiedNameAndType* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		void (*freeString)(void* ctxt, char* string);
		void (*freeResult)(void* ctxt, BNTypeParserResult* result);
		void (*freeErrorList)(void* ctxt, BNTypeParserError* errors, size_t errorCount);
	} BNTypeParserCallbacks;

	typedef struct BNTypePrinterCallbacks
	{
		void* context;
		bool (*getTypeTokens)(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, uint8_t baseConfidence, BNTokenEscapingType escaping,
			BNInstructionTextToken** result, size_t* resultCount);
		bool (*getTypeTokensBeforeName)(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		bool (*getTypeTokensAfterName)(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		bool (*getTypeString)(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, BNTokenEscapingType escaping, char** result);
		bool (*getTypeStringBeforeName)(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		bool (*getTypeStringAfterName)(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		bool (*getTypeLines)(void* ctxt, BNType* type, BNTypeContainer* types, BNQualifiedName* name,
			int paddingCols, bool collapsed,
			BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount);
		bool (*printAllTypes)(void* ctxt, BNQualifiedName* names, BNType** types, size_t typeCount,
			BNBinaryView* data, int paddingCols, BNTokenEscapingType escaping, char** result);
		void (*freeTokens)(void* ctxt, BNInstructionTextToken* tokens, size_t count);
		void (*freeString)(void* ctxt, char* string);
		void (*freeLines)(void* ctxt, BNTypeDefinitionLine* lines, size_t count);
	} BNTypePrinterCallbacks;

	typedef struct BNConstantReference
	{
		int64_t value;
		size_t size;
		bool pointer, intermediate;
	} BNConstantReference;

	typedef struct BNMetadataValueStore
	{
		size_t size;
		char** keys;
		BNMetadata** values;
	} BNMetadataValueStore;

	typedef enum BNSaveOption
	{
		RemoveUndoData,
		TrimSnapshots,
		PurgeOriginalFilenamePath
	} BNSaveOption;

	typedef enum BNMessageBoxIcon
	{
		InformationIcon,
		QuestionIcon,
		WarningIcon,
		ErrorIcon
	} BNMessageBoxIcon;

	typedef enum BNMessageBoxButtonSet
	{
		OKButtonSet,
		YesNoButtonSet,
		YesNoCancelButtonSet
	} BNMessageBoxButtonSet;

	typedef enum BNMessageBoxButtonResult
	{
		NoButton = 0,
		YesButton = 1,
		OKButton = 2,
		CancelButton = 3
	} BNMessageBoxButtonResult;

	typedef enum BNFormInputFieldType
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
	} BNFormInputFieldType;

	typedef struct BNFormInputField
	{
		BNFormInputFieldType type;
		const char* prompt;
		BNBinaryView* view;       // For AddressFormField
		uint64_t currentAddress;  // For AddressFormField
		const char** choices;     // For ChoiceFormField
		size_t count;             // For ChoiceFormField
		const char* ext;          // For OpenFileNameFormField, SaveFileNameFormField
		const char* defaultName;  // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		char* stringResult;
		size_t indexResult;
		bool hasDefault;
		int64_t intDefault;
		uint64_t addressDefault;
		const char* stringDefault;
		size_t indexDefault;
	} BNFormInputField;

	typedef struct BNInteractionHandlerCallbacks
	{
		void* context;
		void (*showPlainTextReport)(void* ctxt, BNBinaryView* view, const char* title, const char* contents);
		void (*showMarkdownReport)(
		    void* ctxt, BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
		void (*showHTMLReport)(
		    void* ctxt, BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
		void (*showGraphReport)(void* ctxt, BNBinaryView* view, const char* title, BNFlowGraph* graph);
		void (*showReportCollection)(void* ctxt, const char* title, BNReportCollection* reports);
		bool (*getTextLineInput)(void* ctxt, char** result, const char* prompt, const char* title);
		bool (*getIntegerInput)(void* ctxt, int64_t* result, const char* prompt, const char* title);
		bool (*getAddressInput)(void* ctxt, uint64_t* result, const char* prompt, const char* title, BNBinaryView* view,
		    uint64_t currentAddr);
		bool (*getChoiceInput)(
			void* ctxt, size_t* result, const char* prompt, const char* title, const char** choices, size_t count);
		bool (*getLargeChoiceInput)(
			void* ctxt, size_t* result, const char* prompt, const char* title, const char** choices, size_t count);
		bool (*getOpenFileNameInput)(void* ctxt, char** result, const char* prompt, const char* ext);
		bool (*getSaveFileNameInput)(
		    void* ctxt, char** result, const char* prompt, const char* ext, const char* defaultName);
		bool (*getDirectoryNameInput)(void* ctxt, char** result, const char* prompt, const char* defaultName);
		bool (*getFormInput)(void* ctxt, BNFormInputField* fields, size_t count, const char* title);
		BNMessageBoxButtonResult (*showMessageBox)(
		    void* ctxt, const char* title, const char* text, BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon);
		bool (*openUrl)(void* ctxt, const char* url);
		bool (*runProgressDialog)(void* ctxt, const char* title, bool canCancel,
			void (*task)(void* taskCtxt, bool(*progress)(void* progressCtxt, size_t cur, size_t max), void* progressCtxt), void* taskCtxt);
	} BNInteractionHandlerCallbacks;

	typedef struct BNObjectDestructionCallbacks
	{
		void* context;
		// The provided pointers have a reference count of zero. Do not add additional references, doing so
		// can lead to a double free. These are provided only for freeing additional state related to the
		// objects passed.
		void (*destructBinaryView)(void* ctxt, BNBinaryView* view);
		void (*destructFileMetadata)(void* ctxt, BNFileMetadata* file);
		void (*destructFunction)(void* ctxt, BNFunction* func);
	} BNObjectDestructionCallbacks;

	typedef struct BNTypeContext
	{
		BNType* type;
		size_t offset;
	} BNTypeContext;

	typedef struct BNCustomDataRenderer
	{
		void* context;
		void (*freeObject)(void* ctxt);
		bool (*isValidForData)(
		    void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
		BNDisassemblyTextLine* (*getLinesForData)(void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type,
		    const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
		    BNTypeContext* typeCtx, size_t ctxCount);
		void (*freeLines)(void* ctx, BNDisassemblyTextLine* lines, size_t count);
	} BNCustomDataRenderer;

	typedef enum BNSegmentFlag
	{
		SegmentExecutable = 1,
		SegmentWritable = 2,
		SegmentReadable = 4,
		SegmentContainsData = 8,
		SegmentContainsCode = 0x10,
		SegmentDenyWrite = 0x20,
		SegmentDenyExecute = 0x40
	} BNSegmentFlag;

	typedef enum BNSectionSemantics
	{
		DefaultSectionSemantics,
		ReadOnlyCodeSectionSemantics,
		ReadOnlyDataSectionSemantics,
		ReadWriteDataSectionSemantics,
		ExternalSectionSemantics
	} BNSectionSemantics;

	typedef struct BNAddressRange
	{
		uint64_t start;
		uint64_t end;
	} BNAddressRange;

	typedef struct BNILIndexRange
	{
		size_t start;
		size_t end;
	} BNILIndexRange;

	typedef struct BNSystemCallInfo
	{
		uint32_t number;
		BNQualifiedName name;
		BNType* type;
	} BNSystemCallInfo;

	typedef enum BNILBranchDependence
	{
		NotBranchDependent,
		TrueBranchDependent,
		FalseBranchDependent
	} BNILBranchDependence;

	typedef struct BNILBranchInstructionAndDependence
	{
		size_t branch;
		BNILBranchDependence dependence;
	} BNILBranchInstructionAndDependence;

	typedef struct BNPerformanceInfo
	{
		char* name;
		double seconds;
	} BNPerformanceInfo;

	typedef struct BNMemoryUsageInfo
	{
		char* name;
		uint64_t value;
	} BNMemoryUsageInfo;

	typedef enum BNMetadataType
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
	} BNMetadataType;

	typedef struct BNRegisterStackAdjustment
	{
		uint32_t regStack;
		int32_t adjustment;
		uint8_t confidence;
	} BNRegisterStackAdjustment;

	typedef enum BNFunctionAnalysisSkipOverride
	{
		DefaultFunctionAnalysisSkip,
		NeverSkipFunctionAnalysis,
		AlwaysSkipFunctionAnalysis
	} BNFunctionAnalysisSkipOverride;

	typedef enum BNReportType
	{
		PlainTextReportType,
		MarkdownReportType,
		HTMLReportType,
		FlowGraphReportType
	} BNReportType;

	typedef struct BNCustomFlowGraph
	{
		void* context;
		void (*prepareForLayout)(void* ctxt);
		void (*populateNodes)(void* ctxt);
		void (*completeLayout)(void* ctxt);
		BNFlowGraph* (*update)(void* ctxt);
		void (*freeObject)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
	} BNCustomFlowGraph;

	typedef struct BNRange
	{
		uint64_t start;
		uint64_t end;
	} BNRange;

	typedef enum BNAnalysisSkipReason
	{
		NoSkipReason,
		AlwaysSkipReason,
		ExceedFunctionSizeSkipReason,
		ExceedFunctionAnalysisTimeSkipReason,
		ExceedFunctionUpdateCountSkipReason,
		NewAutoFunctionAnalysisSuppressedReason,
		BasicAnalysisSkipReason,
		IntermediateAnalysisSkipReason
	} BNAnalysisSkipReason;

	typedef enum BNSettingsScope
	{
		SettingsInvalidScope = 0,
		SettingsAutoScope = 1,
		SettingsDefaultScope = 2,
		SettingsUserScope = 4,
		SettingsProjectScope = 8,
		SettingsResourceScope = 0x10
	} BNSettingsScope;

	typedef enum BNLinearViewObjectIdentifierType
	{
		SingleLinearViewObject,
		AddressLinearViewObject,
		AddressRangeLinearViewObject
	} BNLinearViewObjectIdentifierType;

	typedef struct BNLinearViewObjectIdentifier
	{
		char* name;
		BNLinearViewObjectIdentifierType type;
		uint64_t start, end;
	} BNLinearViewObjectIdentifier;

	typedef enum BNBinaryViewEventType
	{
		BinaryViewFinalizationEvent,
		BinaryViewInitialAnalysisCompletionEvent
	} BNBinaryViewEventType;

	typedef struct BNBinaryViewEvent
	{
		BNBinaryViewEventType type;
		void (*callback)(void* ctx, BNBinaryView* view);
		void* ctx;
	} BNBinaryViewEvent;

	typedef enum BNDeadStoreElimination
	{
		DefaultDeadStoreElimination,
		PreventDeadStoreElimination,
		AllowDeadStoreElimination
	} BNDeadStoreElimination;

	typedef struct BNDebugFunctionInfo
	{
		char* shortName;
		char* fullName;
		char* rawName;
		uint64_t address;
		BNType* type;
		BNPlatform* platform;
		char** components;
		size_t componentN;
		BNVariableNameAndType* localVariables;
		size_t localVariableN;
	} BNDebugFunctionInfo;

	typedef struct BNSecretsProviderCallbacks
	{
		void* context;
		bool (*hasData)(void* ctxt, const char* key);
		char* (*getData)(void* ctxt, const char* key);
		bool (*storeData)(void* ctxt, const char* key, const char* data);
		bool (*deleteData)(void* ctxt, const char* key);
	} BNSecretsProviderCallbacks;

	typedef struct BNMergedVariable
	{
		BNVariable target;
		BNVariable* sources;
		size_t sourceCount;
	} BNMergedVariable;

	typedef struct BNEnterpriseServerCallbacks
	{
		void* context;
		void (*licenseStatusChanged)(void* ctxt, bool stillValid);
	} BNEnterpriseServerCallbacks;

	typedef struct BNTypeArchiveNotification
	{
		void* context;
		void (*typeAdded)(void* ctxt, BNTypeArchive* archive, const char* id, BNType* definition);
		void (*typeUpdated)(void* ctxt, BNTypeArchive* archive, const char* id, BNType* oldDefinition, BNType* newDefinition);
		void (*typeRenamed)(void* ctxt, BNTypeArchive* archive, const char* id, const BNQualifiedName* oldName, const BNQualifiedName* newName);
		void (*typeDeleted)(void* ctxt, BNTypeArchive* archive, const char* id, BNType* definition);
	} BNTypeArchiveNotification;

	typedef enum BNTypeContainerType
	{
		AnalysisTypeContainerType,
		AnalysisAutoTypeContainerType,
		AnalysisUserTypeContainerType,
		TypeLibraryTypeContainerType,
		TypeArchiveTypeContainerType,
		DebugInfoTypeContainerType,
		PlatformTypeContainerType,
		OtherTypeContainerType
	} BNTypeContainerType;

	typedef enum BNSyncStatus
	{
		NotSyncedSyncStatus,
		NoChangesSyncStatus,
		UnknownSyncStatus,
		CanPushSyncStatus,
		CanPullSyncStatus,
		CanPushAndPullSyncStatus,
		ConflictSyncStatus
	} BNSyncStatus;

	typedef enum BNBaseAddressDetectionPOISetting
	{
		POIAnalysisStringsOnly,
		POIAnalysisFunctionsOnly,
		POIAnalysisAll,
	} BNBaseAddressDetectionPOISetting;

	typedef enum BNBaseAddressDetectionPOIType
	{
		POIString,
		POIFunction,
		POIDataVariable,
		POIFileStart,
		POIFileEnd,
	} BNBaseAddressDetectionPOIType;

	typedef enum BNBaseAddressDetectionConfidence
	{
		NoConfidence,
		LowConfidence,
		HighConfidence,
	} BNBaseAddressDetectionConfidence;

	typedef struct BNBaseAddressDetectionSettings
	{
		const char* Architecture;
		const char* Analysis;
		uint32_t MinStrlen;
		uint32_t Alignment;
		uint64_t LowerBoundary;
		uint64_t UpperBoundary;
		BNBaseAddressDetectionPOISetting POIAnalysis;
		uint32_t MaxPointersPerCluster;
	} BNBaseAddressDetectionSettings;

	typedef struct BNBaseAddressDetectionReason
	{
		uint64_t Pointer;
		uint64_t POIOffset;
		BNBaseAddressDetectionPOIType POIType;
	} BNBaseAddressDetectionReason;

	typedef struct BNBaseAddressDetectionScore
	{
		size_t Score;
		uint64_t BaseAddress;
	} BNBaseAddressDetectionScore;

	typedef enum BNCollaborationPermissionLevel
	{
		AdminPermission = 1,
		EditPermission = 2,
		ViewPermission = 3
	} BNCollaborationPermissionLevel;

	typedef enum BNRemoteFileType
	{
		RawDataFileType, // "RW"
		BinaryViewAnalysisFileType, // "BV"
		TypeArchiveFileType, // "TA"
		UnknownFileType, // Others
	} BNRemoteFileType;

	typedef enum BNMergeConflictDataType
	{
		TextConflictDataType,
		JsonConflictDataType,
		BinaryConflictDataType
	} BNMergeConflictDataType;

	typedef struct BNAnalysisMergeConflictSplitterCallbacks
	{
		void* context;
		char* (*getName)(void* context);
		void (*reset)(void* context);
		void (*finished)(void* context);
		bool (*canSplit)(void* context, const char* key, const BNAnalysisMergeConflict* conflict);
		bool (*split)(void* context, const char* originalKey, const BNAnalysisMergeConflict* originalConflict, BNKeyValueStore* result, char*** newKeys, BNAnalysisMergeConflict*** newConflicts, size_t* newCount);
		void (*freeName)(void* context, char* name);
		void (*freeKeyList)(void* context, char** keyList, size_t count);
		void (*freeConflictList)(void* context, BNAnalysisMergeConflict** conflictList, size_t count);
	} BNAnalysisMergeConflictSplitterCallbacks;

	typedef bool(*BNProgressFunction)(void*, size_t, size_t);
	typedef bool(*BNCollaborationAnalysisConflictHandler)(void*, const char** keys, BNAnalysisMergeConflict** conflicts, size_t conflictCount);
	typedef bool(*BNCollaborationNameChangesetFunction)(void*, BNCollaborationChangeset*);

	BINARYNINJACOREAPI char* BNAllocString(const char* contents);
	BINARYNINJACOREAPI void BNFreeString(char* str);
	BINARYNINJACOREAPI char** BNAllocStringList(const char** contents, size_t size);
	BINARYNINJACOREAPI void BNFreeStringList(char** strs, size_t count);

	BINARYNINJACOREAPI void BNShutdown(void);
	BINARYNINJACOREAPI bool BNIsShutdownRequested(void);

	BINARYNINJACOREAPI BNVersionInfo BNGetVersionInfo(void);
	BINARYNINJACOREAPI char* BNGetVersionString(void);
	BINARYNINJACOREAPI uint32_t BNGetBuildId(void);
	BINARYNINJACOREAPI uint32_t BNGetCurrentCoreABIVersion(void);
	BINARYNINJACOREAPI uint32_t BNGetMinimumCoreABIVersion(void);

	BINARYNINJACOREAPI char* BNGetSerialNumber(void);
	BINARYNINJACOREAPI uint64_t BNGetLicenseExpirationTime(void);
	BINARYNINJACOREAPI bool BNIsLicenseValidated(void);
	BINARYNINJACOREAPI char* BNGetLicensedUserEmail(void);
	BINARYNINJACOREAPI char* BNGetProduct(void);
	BINARYNINJACOREAPI char* BNGetProductType(void);
	BINARYNINJACOREAPI int BNGetLicenseCount(void);
	BINARYNINJACOREAPI bool BNIsUIEnabled(void);
	BINARYNINJACOREAPI void BNSetLicense(const char* licenseData);

	BINARYNINJACOREAPI bool BNIsDatabase(const char* filename);

	BINARYNINJACOREAPI bool BNAuthenticateEnterpriseServerWithCredentials(
	    const char* username, const char* password, bool remember);
	BINARYNINJACOREAPI bool BNAuthenticateEnterpriseServerWithMethod(const char* method, bool remember);
	BINARYNINJACOREAPI size_t BNGetEnterpriseServerAuthenticationMethods(char*** methods, char*** names);
	BINARYNINJACOREAPI bool BNDeauthenticateEnterpriseServer(void);
	BINARYNINJACOREAPI void BNCancelEnterpriseServerAuthentication(void);
	BINARYNINJACOREAPI bool BNConnectEnterpriseServer(void);
	BINARYNINJACOREAPI bool BNUpdateEnterpriseServerLicense(uint64_t timeout);
	BINARYNINJACOREAPI bool BNReleaseEnterpriseServerLicense(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerConnected(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerAuthenticated(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerUsername(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerToken(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerUrl(void);
	BINARYNINJACOREAPI bool BNSetEnterpriseServerUrl(const char* url);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerName(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerId(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerVersion(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerBuildId(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerLicenseExpirationTime(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerLicenseDuration(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerFloatingLicense(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerReservationTimeLimit(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerLicenseStillActivated(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerLastError(void);
	BINARYNINJACOREAPI void BNRegisterEnterpriseServerNotification(BNEnterpriseServerCallbacks* notify);
	BINARYNINJACOREAPI void BNUnregisterEnterpriseServerNotification(BNEnterpriseServerCallbacks* notify);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerInitialized(void);
	BINARYNINJACOREAPI bool BNInitializeEnterpriseServer(void);

	BINARYNINJACOREAPI void BNRegisterObjectDestructionCallbacks(BNObjectDestructionCallbacks* callbacks);
	BINARYNINJACOREAPI void BNUnregisterObjectDestructionCallbacks(BNObjectDestructionCallbacks* callbacks);

	BINARYNINJACOREAPI char* BNGetUniqueIdentifierString(void);

	// Plugin initialization
	BINARYNINJACOREAPI bool BNInitPlugins(bool allowUserPlugins);
	BINARYNINJACOREAPI bool BNInitCorePlugins(void);  // Deprecated, use BNInitPlugins
	BINARYNINJACOREAPI void BNDisablePlugins(void);
	BINARYNINJACOREAPI bool BNIsPluginsEnabled(void);
	BINARYNINJACOREAPI void BNInitUserPlugins(void);  // Deprecated, use BNInitPlugins
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
	BINARYNINJACOREAPI char* BNGetPathRelativeToUserDirectory(const char* path);

	BINARYNINJACOREAPI bool BNExecuteWorkerProcess(const char* path, const char** args, BNDataBuffer* input,
	    char** output, char** error, bool stdoutIsText, bool stderrIsText);

	BINARYNINJACOREAPI void BNSetCurrentPluginLoadOrder(BNPluginLoadOrder order);
	BINARYNINJACOREAPI void BNAddRequiredPluginDependency(const char* name);
	BINARYNINJACOREAPI void BNAddOptionalPluginDependency(const char* name);

	// Logging
	BN_PRINTF_ATTRIBUTE(5, 6)
	BINARYNINJACOREAPI void BNLog(
		size_t session, BNLogLevel level, const char* logger_name, size_t tid, const char* fmt, ...);

	BN_PRINTF_ATTRIBUTE(1, 2)
	BINARYNINJACOREAPI void BNLogDebug(const char* fmt, ...);

	BN_PRINTF_ATTRIBUTE(1, 2)
	BINARYNINJACOREAPI void BNLogInfo(const char* fmt, ...);

	BN_PRINTF_ATTRIBUTE(1, 2)
	BINARYNINJACOREAPI void BNLogWarn(const char* fmt, ...);

	BN_PRINTF_ATTRIBUTE(1, 2)
	BINARYNINJACOREAPI void BNLogError(const char* fmt, ...);

	BN_PRINTF_ATTRIBUTE(1, 2)
	BINARYNINJACOREAPI void BNLogAlert(const char* fmt, ...);

	BINARYNINJACOREAPI void BNLogString(
		size_t session, BNLogLevel level, const char* logger_name, size_t tid, const char* str);


	BINARYNINJACOREAPI BNLogger* BNNewLoggerReference(BNLogger* logger);
	BINARYNINJACOREAPI void BNFreeLogger(BNLogger* logger);

	BN_PRINTF_ATTRIBUTE(3, 4)
	BINARYNINJACOREAPI void BNLoggerLog(BNLogger* logger, BNLogLevel level, const char* fmt, ...);
	BINARYNINJACOREAPI void BNLoggerLogString(BNLogger* logger, BNLogLevel level, const char* msg);

	BINARYNINJACOREAPI char* BNLoggerGetName(BNLogger* logger);
	BINARYNINJACOREAPI size_t BNLoggerGetSessionId(BNLogger* logger);
	BINARYNINJACOREAPI BNLogger* BNLogCreateLogger(const char* loggerName, size_t sessionId);
	BINARYNINJACOREAPI BNLogger* BNLogGetLogger(const char* loggerName, size_t sessionId);
	BINARYNINJACOREAPI char** BNLogGetLoggerNames(size_t* count);

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

	BINARYNINJACOREAPI char* BNDataBufferToEscapedString(BNDataBuffer* buf, bool nullTerminates);
	BINARYNINJACOREAPI BNDataBuffer* BNDecodeEscapedString(const char* str);
	BINARYNINJACOREAPI char* BNDataBufferToBase64(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNDecodeBase64(const char* str);

	BINARYNINJACOREAPI BNDataBuffer* BNZlibCompress(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNZlibDecompress(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNLzmaDecompress(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNLzma2Decompress(BNDataBuffer* buf);
	BINARYNINJACOREAPI BNDataBuffer* BNXzDecompress(BNDataBuffer* buf);

	// Save settings
	BINARYNINJACOREAPI BNSaveSettings* BNCreateSaveSettings(void);
	BINARYNINJACOREAPI BNSaveSettings* BNNewSaveSettingsReference(BNSaveSettings* settings);
	BINARYNINJACOREAPI void BNFreeSaveSettings(BNSaveSettings* settings);

	BINARYNINJACOREAPI bool BNIsSaveSettingsOptionSet(BNSaveSettings* settings, BNSaveOption option);
	BINARYNINJACOREAPI void BNSetSaveSettingsOption(BNSaveSettings* settings, BNSaveOption option, bool state);
	BINARYNINJACOREAPI char* BNGetSaveSettingsName(BNSaveSettings* settings);
	BINARYNINJACOREAPI void BNSetSaveSettingsName(BNSaveSettings* settings, const char* name);

	// File metadata object
	BINARYNINJACOREAPI BNFileMetadata* BNCreateFileMetadata();
	BINARYNINJACOREAPI BNFileMetadata* BNNewFileReference(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNFreeFileMetadata(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNCloseFile(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetFileMetadataNavigationHandler(BNFileMetadata* file, BNNavigationHandler* handler);
	BINARYNINJACOREAPI bool BNIsFileModified(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNIsAnalysisChanged(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNMarkFileModified(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNMarkFileSaved(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNIsBackedByDatabase(BNFileMetadata* file, const char* binaryViewType);

	BINARYNINJACOREAPI bool BNCreateDatabase(BNBinaryView* data, const char* path, BNSaveSettings* settings);
	BINARYNINJACOREAPI bool BNCreateDatabaseWithProgress(BNBinaryView* data, const char* path, void* ctxt,
	    bool (*progress)(void* ctxt, size_t progress, size_t total), BNSaveSettings* settings);
	BINARYNINJACOREAPI BNBinaryView* BNOpenExistingDatabase(BNFileMetadata* file, const char* path);
	BINARYNINJACOREAPI BNBinaryView* BNOpenExistingDatabaseWithProgress(BNFileMetadata* file, const char* path,
	    void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNBinaryView* BNOpenDatabaseForConfiguration(BNFileMetadata* file, const char* path);
	BINARYNINJACOREAPI bool BNSaveAutoSnapshot(BNBinaryView* data, BNSaveSettings* settings);
	BINARYNINJACOREAPI bool BNSaveAutoSnapshotWithProgress(BNBinaryView* data, void* ctxt,
	    bool (*progress)(void* ctxt, size_t progress, size_t total), BNSaveSettings* settings);
	BINARYNINJACOREAPI void BNGetSnapshotData(BNFileMetadata* file, BNKeyValueStore* data, BNKeyValueStore* cache,
	    void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total));
	BINARYNINJACOREAPI void BNApplySnapshotData(BNFileMetadata* file, BNBinaryView* view, BNKeyValueStore* data,
	    BNKeyValueStore* cache, void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total),
	    bool openForConfiguration, bool restoreRawView);
	BINARYNINJACOREAPI BNDatabase* BNGetFileMetadataDatabase(BNFileMetadata* file);

	// Key value store
	BINARYNINJACOREAPI BNKeyValueStore* BNCreateKeyValueStore(void);
	BINARYNINJACOREAPI BNKeyValueStore* BNCreateKeyValueStoreFromDataBuffer(BNDataBuffer* buffer);
	BINARYNINJACOREAPI BNKeyValueStore* BNNewKeyValueStoreReference(BNKeyValueStore* store);
	BINARYNINJACOREAPI void BNFreeKeyValueStore(BNKeyValueStore* store);

	BINARYNINJACOREAPI char** BNGetKeyValueStoreKeys(BNKeyValueStore* store, size_t* count);
	BINARYNINJACOREAPI bool BNKeyValueStoreHasValue(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI char* BNGetKeyValueStoreValue(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI BNDataBuffer* BNGetKeyValueStoreValueHash(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI BNDataBuffer* BNGetKeyValueStoreBuffer(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI bool BNSetKeyValueStoreValue(BNKeyValueStore* store, const char* name, const char* value);
	BINARYNINJACOREAPI bool BNSetKeyValueStoreBuffer(
	    BNKeyValueStore* store, const char* name, const BNDataBuffer* value);
	BINARYNINJACOREAPI BNDataBuffer* BNGetKeyValueStoreSerializedData(BNKeyValueStore* store);
	BINARYNINJACOREAPI void BNBeginKeyValueStoreNamespace(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI void BNEndKeyValueStoreNamespace(BNKeyValueStore* store);
	BINARYNINJACOREAPI bool BNIsKeyValueStoreEmpty(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreValueSize(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreDataSize(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreValueStorageSize(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreNamespaceSize(BNKeyValueStore* store);

	// Project object
	BINARYNINJACOREAPI BNProject* BNNewProjectReference(BNProject* project);
	BINARYNINJACOREAPI void BNFreeProject(BNProject* project);
	BINARYNINJACOREAPI void BNFreeProjectList(BNProject** projects, size_t count);
	BINARYNINJACOREAPI BNProject** BNGetOpenProjects(size_t* count);
	BINARYNINJACOREAPI BNProject* BNCreateProject(const char* path, const char* name);
	BINARYNINJACOREAPI BNProject* BNOpenProject(const char* path);
	BINARYNINJACOREAPI bool BNProjectOpen(BNProject* project);
	BINARYNINJACOREAPI bool BNProjectClose(BNProject* project);
	BINARYNINJACOREAPI char* BNProjectGetId(BNProject* project);
	BINARYNINJACOREAPI bool BNProjectIsOpen(BNProject* project);
	BINARYNINJACOREAPI char* BNProjectGetPath(BNProject* project);
	BINARYNINJACOREAPI char* BNProjectGetName(BNProject* project);
	BINARYNINJACOREAPI void BNProjectSetName(BNProject* project, const char* name);
	BINARYNINJACOREAPI char* BNProjectGetDescription(BNProject* project);
	BINARYNINJACOREAPI void BNProjectSetDescription(BNProject* project, const char* description);

	BINARYNINJACOREAPI BNMetadata* BNProjectQueryMetadata(BNProject* project, const char* key);
	BINARYNINJACOREAPI bool BNProjectStoreMetadata(BNProject* project, const char* key, BNMetadata* value);
	BINARYNINJACOREAPI void BNProjectRemoveMetadata(BNProject* project, const char* key);

	BINARYNINJACOREAPI BNProjectFile* BNProjectCreateFileFromPath(BNProject* project, const char* path, BNProjectFolder* folder, const char* name, const char* description, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNProjectFile* BNProjectCreateFileFromPathUnsafe(BNProject* project, const char* path, BNProjectFolder* folder, const char* name, const char* description, const char* id, int64_t creationTimestamp, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNProjectFile* BNProjectCreateFile(BNProject* project, const uint8_t* contents, size_t contentsSize, BNProjectFolder* folder, const char* name, const char* description, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNProjectFile* BNProjectCreateFileUnsafe(BNProject* project, const uint8_t* contents, size_t contentsSize, BNProjectFolder* folder, const char* name, const char* description, const char* id, int64_t creationTimestamp, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNProjectFile** BNProjectGetFiles(BNProject* project, size_t* count);
	BINARYNINJACOREAPI BNProjectFile* BNProjectGetFileById(BNProject* project, const char* id);
	BINARYNINJACOREAPI BNProjectFile* BNProjectGetFileByPathOnDisk(BNProject* project, const char* path);

	BINARYNINJACOREAPI void BNProjectPushFile(BNProject* project, BNProjectFile* file);
	BINARYNINJACOREAPI bool BNProjectDeleteFile(BNProject* project, BNProjectFile* file);

	BINARYNINJACOREAPI BNProjectFolder* BNProjectCreateFolderFromPath(BNProject* project, const char* path, BNProjectFolder* parent, const char* description, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNProjectFolder* BNProjectCreateFolder(BNProject* project, BNProjectFolder* parent, const char* name, const char* description);
	BINARYNINJACOREAPI BNProjectFolder* BNProjectCreateFolderUnsafe(BNProject* project, BNProjectFolder* parent, const char* name, const char* description, const char* id);
	BINARYNINJACOREAPI BNProjectFolder** BNProjectGetFolders(BNProject* project, size_t* count);
	BINARYNINJACOREAPI BNProjectFolder* BNProjectGetFolderById(BNProject* project, const char* id);
	BINARYNINJACOREAPI void BNProjectPushFolder(BNProject* project, BNProjectFolder* folder);
	BINARYNINJACOREAPI bool BNProjectDeleteFolder(BNProject* project, BNProjectFolder* folder, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));

	BINARYNINJACOREAPI void BNProjectBeginBulkOperation(BNProject* project);
	BINARYNINJACOREAPI void BNProjectEndBulkOperation(BNProject* project);

	// ProjectFile object
	BINARYNINJACOREAPI BNProjectFile* BNNewProjectFileReference(BNProjectFile* file);
	BINARYNINJACOREAPI void BNFreeProjectFile(BNProjectFile* file);
	BINARYNINJACOREAPI void BNFreeProjectFileList(BNProjectFile** files, size_t count);
	BINARYNINJACOREAPI char* BNProjectFileGetPathOnDisk(BNProjectFile* file);
	BINARYNINJACOREAPI bool BNProjectFileExistsOnDisk(BNProjectFile* file);
	BINARYNINJACOREAPI char* BNProjectFileGetName(BNProjectFile* file);
	BINARYNINJACOREAPI bool BNProjectFileSetName(BNProjectFile* file, const char* name);
	BINARYNINJACOREAPI char* BNProjectFileGetDescription(BNProjectFile* file);
	BINARYNINJACOREAPI bool BNProjectFileSetDescription(BNProjectFile* file, const char* description);
	BINARYNINJACOREAPI char* BNProjectFileGetId(BNProjectFile* file);
	BINARYNINJACOREAPI BNProjectFolder* BNProjectFileGetFolder(BNProjectFile* file);
	BINARYNINJACOREAPI bool BNProjectFileSetFolder(BNProjectFile* file, BNProjectFolder* folder);
	BINARYNINJACOREAPI BNProject* BNProjectFileGetProject(BNProjectFile* file);
	BINARYNINJACOREAPI bool BNProjectFileExport(BNProjectFile* file, const char* destination);
	BINARYNINJACOREAPI int64_t BNProjectFileGetCreationTimestamp(BNProjectFile* file);


	// ProjectFolder object
	BINARYNINJACOREAPI BNProjectFolder* BNNewProjectFolderReference(BNProjectFolder* folder);
	BINARYNINJACOREAPI void BNFreeProjectFolder(BNProjectFolder* folder);
	BINARYNINJACOREAPI void BNFreeProjectFolderList(BNProjectFolder** folders, size_t count);
	BINARYNINJACOREAPI char* BNProjectFolderGetId(BNProjectFolder* folder);
	BINARYNINJACOREAPI char* BNProjectFolderGetName(BNProjectFolder* folder);
	BINARYNINJACOREAPI bool BNProjectFolderSetName(BNProjectFolder* folder, const char* name);
	BINARYNINJACOREAPI char* BNProjectFolderGetDescription(BNProjectFolder* folder);
	BINARYNINJACOREAPI bool BNProjectFolderSetDescription(BNProjectFolder* folder, const char* description);
	BINARYNINJACOREAPI BNProjectFolder* BNProjectFolderGetParent(BNProjectFolder* folder);
	BINARYNINJACOREAPI bool BNProjectFolderSetParent(BNProjectFolder* folder, BNProjectFolder* parent);
	BINARYNINJACOREAPI BNProject* BNProjectFolderGetProject(BNProjectFolder* folder);
	BINARYNINJACOREAPI bool BNProjectFolderExport(BNProjectFolder* folder, const char* destination, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total));

	// ExternalLibrary object
	BINARYNINJACOREAPI BNExternalLibrary* BNNewExternalLibraryReference(BNExternalLibrary* lib);
	BINARYNINJACOREAPI void BNFreeExternalLibrary(BNExternalLibrary* lib);
	BINARYNINJACOREAPI void BNFreeExternalLibraryList(BNExternalLibrary** libs, size_t count);
	BINARYNINJACOREAPI char* BNExternalLibraryGetName(BNExternalLibrary* lib);
	BINARYNINJACOREAPI void BNExternalLibrarySetBackingFile(BNExternalLibrary* lib, BNProjectFile* file);
	BINARYNINJACOREAPI BNProjectFile* BNExternalLibraryGetBackingFile(BNExternalLibrary* lib);

	// ExternalLocation object
	BINARYNINJACOREAPI BNExternalLocation* BNNewExternalLocationReference(BNExternalLocation*loc);
	BINARYNINJACOREAPI void BNFreeExternalLocation(BNExternalLocation*loc);
	BINARYNINJACOREAPI void BNFreeExternalLocationList(BNExternalLocation**locs, size_t count);
	BINARYNINJACOREAPI BNSymbol* BNExternalLocationGetSourceSymbol(BNExternalLocation* loc);
	BINARYNINJACOREAPI uint64_t BNExternalLocationGetTargetAddress(BNExternalLocation* loc);
	BINARYNINJACOREAPI char* BNExternalLocationGetTargetSymbol(BNExternalLocation* loc);
	BINARYNINJACOREAPI BNExternalLibrary* BNExternalLocationGetExternalLibrary(BNExternalLocation* loc);
	BINARYNINJACOREAPI bool BNExternalLocationHasTargetAddress(BNExternalLocation* loc);
	BINARYNINJACOREAPI bool BNExternalLocationHasTargetSymbol(BNExternalLocation* loc);
	BINARYNINJACOREAPI bool BNExternalLocationSetTargetAddress(BNExternalLocation* loc, uint64_t* address);
	BINARYNINJACOREAPI bool BNExternalLocationSetTargetSymbol(BNExternalLocation* loc, const char* symbol);
	BINARYNINJACOREAPI void BNExternalLocationSetExternalLibrary(BNExternalLocation* loc, BNExternalLibrary* library);

	// Database object
	BINARYNINJACOREAPI BNDatabase* BNNewDatabaseReference(BNDatabase* database);
	BINARYNINJACOREAPI void BNFreeDatabase(BNDatabase* database);
	BINARYNINJACOREAPI void BNSetDatabaseCurrentSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI BNSnapshot* BNGetDatabaseCurrentSnapshot(BNDatabase* database);
	BINARYNINJACOREAPI BNSnapshot** BNGetDatabaseSnapshots(BNDatabase* database, size_t* count);
	BINARYNINJACOREAPI BNSnapshot* BNGetDatabaseSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI int64_t BNWriteDatabaseSnapshotData(BNDatabase* database, int64_t* parents, size_t parentCount,
	    BNBinaryView* file, const char* name, BNKeyValueStore* data, bool autoSave, void* ctxt,
	    BNProgressFunction progress);
	BINARYNINJACOREAPI bool BNTrimDatabaseSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI bool BNRemoveDatabaseSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI char** BNGetDatabaseGlobalKeys(BNDatabase* database, size_t* count);
	BINARYNINJACOREAPI int BNDatabaseHasGlobal(BNDatabase* database, const char* key);
	BINARYNINJACOREAPI char* BNReadDatabaseGlobal(BNDatabase* database, const char* key);
	BINARYNINJACOREAPI bool BNWriteDatabaseGlobal(BNDatabase* database, const char* key, const char* val);
	BINARYNINJACOREAPI BNDataBuffer* BNReadDatabaseGlobalData(BNDatabase* database, const char* key);
	BINARYNINJACOREAPI bool BNWriteDatabaseGlobalData(BNDatabase* database, const char* key, BNDataBuffer* val);
	BINARYNINJACOREAPI BNFileMetadata* BNGetDatabaseFile(BNDatabase* database);
	BINARYNINJACOREAPI void BNDatabaseReloadConnection(BNDatabase* database);
	BINARYNINJACOREAPI BNKeyValueStore* BNReadDatabaseAnalysisCache(BNDatabase* database);
	BINARYNINJACOREAPI bool BNWriteDatabaseAnalysisCache(BNDatabase* database, BNKeyValueStore* val);
	BINARYNINJACOREAPI bool BNSnapshotHasData(BNDatabase* db, int64_t id);

	// Database snapshots
	BINARYNINJACOREAPI BNSnapshot* BNNewSnapshotReference(BNSnapshot* snapshot);
	BINARYNINJACOREAPI void BNFreeSnapshot(BNSnapshot* snapshot);
	BINARYNINJACOREAPI void BNFreeSnapshotList(BNSnapshot** snapshots, size_t count);
	BINARYNINJACOREAPI BNDatabase* BNGetSnapshotDatabase(BNSnapshot* snapshot);
	BINARYNINJACOREAPI int64_t BNGetSnapshotId(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNSnapshot* BNGetSnapshotFirstParent(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNSnapshot** BNGetSnapshotParents(BNSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNSnapshot** BNGetSnapshotChildren(BNSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI char* BNGetSnapshotName(BNSnapshot* snapshot);
	BINARYNINJACOREAPI void BNSetSnapshotName(BNSnapshot* snapshot, const char* name);
	BINARYNINJACOREAPI bool BNIsSnapshotAutoSave(BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNSnapshotHasContents(BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNSnapshotHasUndo(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNDataBuffer* BNGetSnapshotFileContents(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNDataBuffer* BNGetSnapshotFileContentsHash(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNKeyValueStore* BNReadSnapshotData(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNKeyValueStore* BNReadSnapshotDataWithProgress(
	    BNSnapshot* snapshot, void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNDataBuffer* BNGetSnapshotUndoData(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNUndoEntry** BNGetSnapshotUndoEntries(BNSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNUndoEntry** BNGetSnapshotUndoEntriesWithProgress(
	    BNSnapshot* snapshot, void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total), size_t* count);
	BINARYNINJACOREAPI bool BNSnapshotHasAncestor(BNSnapshot* snapshot, BNSnapshot* other);
	BINARYNINJACOREAPI bool BNSnapshotStoreData(BNSnapshot* snapshot, BNKeyValueStore* data,
		void* ctxt, BNProgressFunction progress);

	// Undo actions
	BINARYNINJACOREAPI BNUndoAction* BNNewUndoActionReference(BNUndoAction* action);
	BINARYNINJACOREAPI void BNFreeUndoAction(BNUndoAction* action);
	BINARYNINJACOREAPI void BNFreeUndoActionList(BNUndoAction** actions, size_t count);
	BINARYNINJACOREAPI char* BNUndoActionGetSummaryText(BNUndoAction* action);
	BINARYNINJACOREAPI BNInstructionTextToken* BNUndoActionGetSummary(BNUndoAction* action, size_t* tokenCount);

	// Undo entries
	BINARYNINJACOREAPI BNUndoEntry* BNNewUndoEntryReference(BNUndoEntry* entry);
	BINARYNINJACOREAPI void BNFreeUndoEntry(BNUndoEntry* entry);
	BINARYNINJACOREAPI void BNFreeUndoEntryList(BNUndoEntry** entrys, size_t count);
	BINARYNINJACOREAPI char* BNUndoEntryGetId(BNUndoEntry* entry);
	BINARYNINJACOREAPI BNUndoAction** BNUndoEntryGetActions(BNUndoEntry* entry, size_t* count);
	BINARYNINJACOREAPI uint64_t BNUndoEntryGetTimestamp(BNUndoEntry* entry);

	BINARYNINJACOREAPI bool BNRebase(BNBinaryView* data, uint64_t address);
	BINARYNINJACOREAPI bool BNRebaseWithProgress(
	    BNBinaryView* data, uint64_t address, void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI bool BNCreateSnapshotedView(BNBinaryView* data, const char* viewName);
	BINARYNINJACOREAPI bool BNCreateSnapshotedViewWithProgress(BNBinaryView* data, const char* viewName, void* ctxt,
															   bool (*progress)(void* ctxt, size_t progress, size_t total));

	BINARYNINJACOREAPI char* BNGetOriginalFilename(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetOriginalFilename(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI char* BNGetFilename(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetFilename(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI BNProjectFile* BNGetProjectFile(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetProjectFile(BNFileMetadata* file, BNProjectFile* pfile);

	BINARYNINJACOREAPI char* BNBeginUndoActions(BNFileMetadata* file, bool anonymousAllowed);
	BINARYNINJACOREAPI void BNCommitUndoActions(BNFileMetadata* file, const char* id);
	BINARYNINJACOREAPI void BNRevertUndoActions(BNFileMetadata* file, const char* id);
	BINARYNINJACOREAPI void BNForgetUndoActions(BNFileMetadata* file, const char* id);

	BINARYNINJACOREAPI bool BNCanUndo(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNUndo(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNCanRedo(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNRedo(BNFileMetadata* file);

	BINARYNINJACOREAPI BNUndoEntry** BNGetUndoEntries(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI BNUndoEntry** BNGetRedoEntries(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI BNUndoEntry* BNGetLastUndoEntry(BNFileMetadata* file);
	BINARYNINJACOREAPI BNUndoEntry* BNGetLastRedoEntry(BNFileMetadata* file);
	BINARYNINJACOREAPI char* BNGetLastUndoEntryTitle(BNFileMetadata* file);
	BINARYNINJACOREAPI char* BNGetLastRedoEntryTitle(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNFreeUndoEntries(BNUndoEntry** entries, size_t count);
	BINARYNINJACOREAPI void BNClearUndoEntries(BNFileMetadata* file);

	BINARYNINJACOREAPI BNUser* BNNewUserReference(BNUser* user);
	BINARYNINJACOREAPI void BNFreeUser(BNUser* user);
	BINARYNINJACOREAPI BNUser** BNGetUsers(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI void BNFreeUserList(BNUser** users, size_t count);
	BINARYNINJACOREAPI char* BNGetUserName(BNUser* user);
	BINARYNINJACOREAPI char* BNGetUserEmail(BNUser* user);
	BINARYNINJACOREAPI char* BNGetUserId(BNUser* user);

	BINARYNINJACOREAPI char* BNGetCurrentView(BNFileMetadata* file);
	BINARYNINJACOREAPI uint64_t BNGetCurrentOffset(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNNavigate(BNFileMetadata* file, const char* view, uint64_t offset);

	BINARYNINJACOREAPI BNBinaryView* BNGetFileViewOfType(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI char** BNGetExistingViews(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI size_t BNFileMetadataGetSessionId(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNIsSnapshotDataAppliedWithoutError(BNFileMetadata* view);

	BINARYNINJACOREAPI void BNUnregisterViewOfType(BNFileMetadata* file, const char* type, BNBinaryView* view);

	// Memory Map
	BINARYNINJACOREAPI char* BNGetMemoryMapDescription(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNAddBinaryMemoryRegion(BNBinaryView* view, const char* name, uint64_t start, BNBinaryView* data, uint32_t flags);
	BINARYNINJACOREAPI bool BNAddDataMemoryRegion(BNBinaryView* view, const char* name, uint64_t start, BNDataBuffer* data, uint32_t flags);
	BINARYNINJACOREAPI bool BNAddRemoteMemoryRegion(BNBinaryView* view, const char* name, uint64_t start, BNFileAccessor* accessor, uint32_t flags);
	BINARYNINJACOREAPI bool BNRemoveMemoryRegion(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI char* BNGetActiveMemoryRegionAt(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint32_t BNGetMemoryRegionFlags(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI bool BNSetMemoryRegionFlags(BNBinaryView* view, const char* name, uint32_t flags);
	BINARYNINJACOREAPI bool BNIsMemoryRegionEnabled(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI bool BNSetMemoryRegionEnabled(BNBinaryView* view, const char* name, bool enable);
	BINARYNINJACOREAPI bool BNIsMemoryRegionRebaseable(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI bool BNSetMemoryRegionRebaseable(BNBinaryView* view, const char* name, bool rebaseable);
	BINARYNINJACOREAPI uint8_t BNGetMemoryRegionFill(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI bool BNSetMemoryRegionFill(BNBinaryView* view, const char* name, uint8_t fill);
	BINARYNINJACOREAPI void BNResetMemoryMap(BNBinaryView* view);

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

	BINARYNINJACOREAPI size_t BNGetEntropy(
	    BNBinaryView* view, uint64_t offset, size_t len, size_t blockSize, float* result);

	BINARYNINJACOREAPI BNModificationStatus BNGetModification(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI size_t BNGetModificationArray(
	    BNBinaryView* view, uint64_t offset, BNModificationStatus* result, size_t len);

	BINARYNINJACOREAPI bool BNIsValidOffset(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetReadable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetWritable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetExecutable(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetBackedByFile(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetCodeSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetExternSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI bool BNIsOffsetWritableSemantics(BNBinaryView* view, uint64_t offset);
	BINARYNINJACOREAPI uint64_t BNGetNextValidOffset(BNBinaryView* view, uint64_t offset);

	BINARYNINJACOREAPI uint64_t BNGetImageBase(BNBinaryView* view);
	BINARYNINJACOREAPI uint64_t BNGetOriginalImageBase(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetOriginalImageBase(BNBinaryView* view, uint64_t imageBase);
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

	BINARYNINJACOREAPI void BNDefineRelocation(BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* info, uint64_t target, uint64_t reloc);
	BINARYNINJACOREAPI void BNDefineSymbolRelocation(BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* info, BNSymbol* target, uint64_t reloc);
	BINARYNINJACOREAPI BNRange* BNGetRelocationRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNRange* BNGetRelocationRangesAtAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNRange* BNGetRelocationRangesInRange(BNBinaryView* view, uint64_t addr, uint64_t size, size_t* count);
	BINARYNINJACOREAPI bool BNRangeContainsRelocation(BNBinaryView* view, uint64_t addr, size_t size);
	BINARYNINJACOREAPI BNRelocation** BNGetRelocationsAt(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeRelocationList(BNRelocation** relocations, size_t count);
	BINARYNINJACOREAPI void BNFreeRelocationRanges(BNRange* ranges);

	BINARYNINJACOREAPI void BNRegisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notify);
	BINARYNINJACOREAPI void BNUnregisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notify);

	BINARYNINJACOREAPI void BNRegisterProjectNotification(BNProject* project, BNProjectNotification* notify);
	BINARYNINJACOREAPI void BNUnregisterProjectNotification(BNProject* project, BNProjectNotification* notify);

	BINARYNINJACOREAPI bool BNCanAssemble(BNBinaryView* view, BNArchitecture* arch);

	BINARYNINJACOREAPI bool BNIsNeverBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsAlwaysBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsInvertBranchPatchAvailable(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsSkipAndReturnZeroPatchAvailable(
	    BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNIsSkipAndReturnValuePatchAvailable(
	    BNBinaryView* view, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNConvertToNop(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNAlwaysBranch(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNInvertBranch(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI bool BNSkipAndReturnValue(
	    BNBinaryView* view, BNArchitecture* arch, uint64_t addr, uint64_t value);

	BINARYNINJACOREAPI size_t BNGetInstructionLength(BNBinaryView* view, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNFindNextData(
	    BNBinaryView* view, uint64_t start, BNDataBuffer* data, uint64_t* result, BNFindFlag flags);
	BINARYNINJACOREAPI bool BNFindNextText(BNBinaryView* view, uint64_t start, const char* data, uint64_t* result,
	    BNDisassemblySettings* settings, BNFindFlag flags, BNFunctionGraphType graph);
	BINARYNINJACOREAPI bool BNFindNextConstant(BNBinaryView* view, uint64_t start, uint64_t constant, uint64_t* result,
	    BNDisassemblySettings* settings, BNFunctionGraphType graph);

	BINARYNINJACOREAPI bool BNFindNextDataWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    BNDataBuffer* data, uint64_t* result, BNFindFlag flags, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total));
	BINARYNINJACOREAPI bool BNFindNextTextWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    const char* data, uint64_t* result, BNDisassemblySettings* settings, BNFindFlag flags,
	    BNFunctionGraphType graph, void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total));
	BINARYNINJACOREAPI bool BNFindNextConstantWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    uint64_t constant, uint64_t* result, BNDisassemblySettings* settings, BNFunctionGraphType graph, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total));

	BINARYNINJACOREAPI bool BNFindAllDataWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    BNDataBuffer* data, BNFindFlag flags, void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total),
	    void* matchCtxt, bool (*matchCallback)(void* matchCtxt, uint64_t addr, BNDataBuffer* match));
	BINARYNINJACOREAPI bool BNFindAllTextWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    const char* data, BNDisassemblySettings* settings, BNFindFlag flags, BNFunctionGraphType graph, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total), void* matchCtxt,
	    bool (*matchCallback)(void* matchCtxt, uint64_t addr, const char* match, BNLinearDisassemblyLine* line));
	BINARYNINJACOREAPI bool BNFindAllConstantWithProgress(BNBinaryView* view, uint64_t start, uint64_t end,
	    uint64_t constant, BNDisassemblySettings* settings, BNFunctionGraphType graph, void* ctxt,
	    bool (*progress)(void* ctxt, size_t current, size_t total), void* matchCtxt,
	    bool (*matchCallback)(void* matchCtxt, uint64_t addr, BNLinearDisassemblyLine* line));

	BINARYNINJACOREAPI bool BNSearch(BNBinaryView* view, const char* query, void* context, bool (*callback)(void*, uint64_t, BNDataBuffer*));
	BINARYNINJACOREAPI bool BNPerformSearch(const char* query, const uint8_t* buffer, size_t size, bool(*callback)(void*, size_t, size_t), void* context);

	BINARYNINJACOREAPI void BNAddAutoSegment(BNBinaryView* view, uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
	BINARYNINJACOREAPI void BNRemoveAutoSegment(BNBinaryView* view, uint64_t start, uint64_t length);
	BINARYNINJACOREAPI void BNAddUserSegment(BNBinaryView* view, uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
	BINARYNINJACOREAPI void BNRemoveUserSegment(BNBinaryView* view, uint64_t start, uint64_t length);
	BINARYNINJACOREAPI BNSegment** BNGetSegments(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeSegmentList(BNSegment** segments, size_t count);
	BINARYNINJACOREAPI BNSegment* BNGetSegmentAt(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI bool BNGetAddressForDataOffset(BNBinaryView* view, uint64_t offset, uint64_t* addr);

	BINARYNINJACOREAPI BNComponent* BNGetComponentByGuid(BNBinaryView* view, const char *guid);
	BINARYNINJACOREAPI BNComponent* BNGetRootComponent(BNBinaryView* view);
	BINARYNINJACOREAPI BNComponent* BNCreateComponent(BNBinaryView* view);
	BINARYNINJACOREAPI BNComponent* BNCreateComponentWithParent(BNBinaryView* view, const char* parentGUID);
	BINARYNINJACOREAPI BNComponent* BNCreateComponentWithName(BNBinaryView* view, const char *name);
	BINARYNINJACOREAPI BNComponent* BNCreateComponentWithParentAndName(BNBinaryView* view, const char* parentGUID, const char *name);
	BINARYNINJACOREAPI BNComponent* BNGetComponentByPath(BNBinaryView* view, const char* path);
	BINARYNINJACOREAPI bool BNRemoveComponent(BNBinaryView* view, BNComponent* component);
	BINARYNINJACOREAPI bool BNRemoveComponentByGuid(BNBinaryView* view, const char *guid);

	BINARYNINJACOREAPI void BNAddAutoSection(BNBinaryView* view, const char* name, uint64_t start, uint64_t length,
	    BNSectionSemantics semantics, const char* type, uint64_t align, uint64_t entrySize, const char* linkedSection,
	    const char* infoSection, uint64_t infoData);
	BINARYNINJACOREAPI void BNRemoveAutoSection(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI void BNAddUserSection(BNBinaryView* view, const char* name, uint64_t start, uint64_t length,
	    BNSectionSemantics semantics, const char* type, uint64_t align, uint64_t entrySize, const char* linkedSection,
	    const char* infoSection, uint64_t infoData);
	BINARYNINJACOREAPI void BNRemoveUserSection(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNSection** BNGetSections(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNSection** BNGetSectionsAt(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeSectionList(BNSection** sections, size_t count);
	BINARYNINJACOREAPI BNSection* BNGetSectionByName(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI char** BNGetUniqueSectionNames(BNBinaryView* view, const char** names, size_t count);

	BINARYNINJACOREAPI BNAddressRange* BNGetAllocatedRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNAddressRange* BNGetMappedAddressRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNAddressRange* BNGetBackedAddressRanges(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeAddressRanges(BNAddressRange* ranges);

	BINARYNINJACOREAPI BNNameSpace* BNGetNameSpaces(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeNameSpaceList(BNNameSpace* nameSpace, size_t count);
	BINARYNINJACOREAPI BNNameSpace BNGetExternalNameSpace(void);
	BINARYNINJACOREAPI BNNameSpace BNGetInternalNameSpace(void);
	BINARYNINJACOREAPI void BNFreeNameSpace(BNNameSpace* name);

	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetGlobalPointerValue(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNUserGlobalPointerValueSet(BNBinaryView* view);
	BINARYNINJACOREAPI void BNClearUserGlobalPointerValue(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetUserGlobalPointerValue(BNBinaryView* view, BNRegisterValueWithConfidence value);

	// Raw binary data view
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataView(BNFileMetadata* file);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromBuffer(BNFileMetadata* file, BNDataBuffer* buf);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromData(BNFileMetadata* file, const void* data, size_t len);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromFilename(BNFileMetadata* file, const char* filename);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromFile(BNFileMetadata* file, BNFileAccessor* accessor);

	// Creation of new types of binary views
	BINARYNINJACOREAPI BNBinaryView* BNCreateCustomBinaryView(
	    const char* name, BNFileMetadata* file, BNBinaryView* parent, BNCustomBinaryView* view);

	BINARYNINJACOREAPI BNBinaryViewType* BNGetBinaryViewTypeByName(const char* name);
	BINARYNINJACOREAPI BNBinaryViewType** BNGetBinaryViewTypes(size_t* count);
	BINARYNINJACOREAPI BNBinaryViewType** BNGetBinaryViewTypesForData(BNBinaryView* data, size_t* count);
	BINARYNINJACOREAPI void BNFreeBinaryViewTypeList(BNBinaryViewType** types);
	BINARYNINJACOREAPI char* BNGetBinaryViewTypeName(BNBinaryViewType* type);
	BINARYNINJACOREAPI char* BNGetBinaryViewTypeLongName(BNBinaryViewType* type);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeDeprecated(BNBinaryViewType* type);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryViewOfType(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI BNBinaryView* BNParseBinaryViewOfType(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeValidForData(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeForceLoadable(BNBinaryViewType* type);
	BINARYNINJACOREAPI BNSettings* BNGetBinaryViewDefaultLoadSettingsForData(
	    BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI BNSettings* BNGetBinaryViewLoadSettingsForData(BNBinaryViewType* type, BNBinaryView* data);

	BINARYNINJACOREAPI BNBinaryViewType* BNRegisterBinaryViewType(
	    const char* name, const char* longName, BNCustomBinaryViewType* type);

	BINARYNINJACOREAPI void BNRegisterArchitectureForViewType(BNBinaryViewType* type, uint32_t id, BNEndianness endian,
	    BNArchitecture* arch);  // Deprecated, use BNRegisterPlatformRecognizerForViewType
	BINARYNINJACOREAPI BNArchitecture* BNGetArchitectureForViewType(BNBinaryViewType* type, uint32_t id,
	    BNEndianness endian);  // Deprecated, use BNRecognizePlatformForViewType

	BINARYNINJACOREAPI void BNRegisterPlatformForViewType(BNBinaryViewType* type, uint32_t id, BNArchitecture* arch,
	    BNPlatform* platform);  // Deprecated, use BNRegisterPlatformRecognizerForViewType
	BINARYNINJACOREAPI BNPlatform* BNGetPlatformForViewType(
	    BNBinaryViewType* type, uint32_t id, BNArchitecture* arch);  // Deprecated, use BNRecognizePlatformForViewType

	BINARYNINJACOREAPI void BNRegisterDefaultPlatformForViewType(
	    BNBinaryViewType* type, BNArchitecture* arch, BNPlatform* platform);

	// Expanded identification of Platform for BinaryViewTypes. Supersedes BNRegisterArchitectureForViewType
	// and BNRegisterPlatformForViewType, as these have certain edge cases (overloaded elf families, for example)
	// that can't be represented.
	//
	// The callback returns a Platform object or null (failure), and most recently added callbacks are called first
	// to allow plugins to override any default behaviors. When a callback returns a platform, architecture will be
	// derived from the identified platform.
	//
	// The BinaryView pointer is the *parent* view (usually 'Raw') that the BinaryView is being created for. This
	// means that generally speaking the callbacks need to be aware of the underlying file format, however the
	// BinaryView implementation may have created datavars in the 'Raw' view by the time the callback is invoked.
	// Behavior regarding when this callback is invoked and what has been made available in the BinaryView passed as an
	// argument to the callback is up to the discretion of the BinaryView implementation.
	//
	// The 'id' ind 'endian' arguments are used as a filter to determine which registered Platform recognizer callbacks
	// are invoked.
	//
	// Support for this API tentatively requires explicit support in the BinaryView implementation.
	BINARYNINJACOREAPI void BNRegisterPlatformRecognizerForViewType(BNBinaryViewType* type, uint64_t id,
	    BNEndianness endian, BNPlatform* (*callback)(void* ctx, BNBinaryView* view, BNMetadata* metadata), void* ctx);

	// BinaryView* passed in here should be the parent view (not the partially constructed object!), and this function
	// should be called from the BNCustomBinaryView::init implementation.
	//
	// 'id' and 'endianness' are used to determine which registered callbacks are actually invoked to eliminate some
	// common sources of boilerplate that all callbacks would have to implement otherwise. If these aren't applicable to
	// your binaryviewtype just use constants here and document them so that people registering Platform recognizers for
	// your view type know what to use.
	BINARYNINJACOREAPI BNPlatform* BNRecognizePlatformForViewType(
	    BNBinaryViewType* type, uint64_t id, BNEndianness endian, BNBinaryView* view, BNMetadata* metadata);


	BINARYNINJACOREAPI void BNRegisterBinaryViewEvent(
	    BNBinaryViewEventType type, void (*callback)(void* ctx, BNBinaryView* view), void* ctx);

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
	BINARYNINJACOREAPI bool BNReadPointer(BNBinaryView* view, BNBinaryReader* stream, uint64_t* result);

	BINARYNINJACOREAPI uint64_t BNGetReaderPosition(BNBinaryReader* stream);
	BINARYNINJACOREAPI void BNSeekBinaryReader(BNBinaryReader* stream, uint64_t offset);
	BINARYNINJACOREAPI void BNSeekBinaryReaderRelative(BNBinaryReader* stream, int64_t offset);
	BINARYNINJACOREAPI uint64_t BNGetBinaryReaderVirtualBase(BNBinaryReader* stream);
	BINARYNINJACOREAPI void BNSetBinaryReaderVirtualBase(BNBinaryReader* stream, uint64_t base);
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
	BINARYNINJACOREAPI BNTransform* BNRegisterTransformType(
	    BNTransformType type, const char* name, const char* longName, const char* group, BNCustomTransform* xform);

	BINARYNINJACOREAPI BNTransformType BNGetTransformType(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformLongName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformGroup(BNTransform* xform);
	BINARYNINJACOREAPI BNTransformParameterInfo* BNGetTransformParameterList(BNTransform* xform, size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformParameterList(BNTransformParameterInfo* params, size_t count);
	BINARYNINJACOREAPI bool BNDecode(
	    BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
	BINARYNINJACOREAPI bool BNEncode(
	    BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

	// Architectures
	BINARYNINJACOREAPI BNArchitecture* BNGetArchitectureByName(const char* name);
	BINARYNINJACOREAPI BNArchitecture** BNGetArchitectureList(size_t* count);
	BINARYNINJACOREAPI void BNFreeArchitectureList(BNArchitecture** archs);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitecture(const char* name, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitectureExtension(
	    const char* name, BNArchitecture* base, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI void BNAddArchitectureRedirection(
	    BNArchitecture* arch, BNArchitecture* from, BNArchitecture* to);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitectureHook(BNArchitecture* base, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI void BNFinalizeArchitectureHook(BNArchitecture* base);
	BINARYNINJACOREAPI BNArchitecture* BNGetNativeTypeParserArchitecture(void);

	BINARYNINJACOREAPI char* BNGetArchitectureName(BNArchitecture* arch);
	BINARYNINJACOREAPI BNEndianness BNGetArchitectureEndianness(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureAddressSize(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureDefaultIntegerSize(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureInstructionAlignment(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureMaxInstructionLength(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureOpcodeDisplayLength(BNArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNGetAssociatedArchitectureByAddress(BNArchitecture* arch, uint64_t* addr);
	BINARYNINJACOREAPI bool BNGetInstructionInfo(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
	BINARYNINJACOREAPI bool BNGetInstructionText(BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t* len,
	    BNInstructionTextToken** result, size_t* count);
	BINARYNINJACOREAPI bool BNGetInstructionLowLevelIL(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI void BNFreeInstructionText(BNInstructionTextToken* tokens, size_t count);
	BINARYNINJACOREAPI void BNFreeInstructionTextLines(BNInstructionTextLine* lines, size_t count);
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
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsRequiredForFlagCondition(
	    BNArchitecture* arch, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsRequiredForSemanticFlagGroup(
	    BNArchitecture* arch, uint32_t semGroup, size_t* count);
	BINARYNINJACOREAPI BNFlagConditionForSemanticClass* BNGetArchitectureFlagConditionsForSemanticFlagGroup(
	    BNArchitecture* arch, uint32_t semGroup, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlagConditionsForSemanticFlagGroup(BNFlagConditionForSemanticClass* conditions);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsWrittenByFlagWriteType(
	    BNArchitecture* arch, uint32_t writeType, size_t* count);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureSemanticClassForFlagWriteType(
	    BNArchitecture* arch, uint32_t writeType);
	BINARYNINJACOREAPI size_t BNGetArchitectureFlagWriteLowLevelIL(BNArchitecture* arch, BNLowLevelILOperation op,
	    size_t size, uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
	    BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetDefaultArchitectureFlagWriteLowLevelIL(BNArchitecture* arch,
	    BNLowLevelILOperation op, size_t size, BNFlagRole role, BNRegisterOrConstant* operands, size_t operandCount,
	    BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetArchitectureFlagConditionLowLevelIL(
	    BNArchitecture* arch, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetDefaultArchitectureFlagConditionLowLevelIL(
	    BNArchitecture* arch, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetArchitectureSemanticFlagGroupLowLevelIL(
	    BNArchitecture* arch, uint32_t semGroup, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI uint32_t* BNGetModifiedArchitectureRegistersOnWrite(
	    BNArchitecture* arch, uint32_t reg, size_t* count);
	BINARYNINJACOREAPI void BNFreeRegisterList(uint32_t* regs);
	BINARYNINJACOREAPI BNRegisterInfo BNGetArchitectureRegisterInfo(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureStackPointerRegister(BNArchitecture* arch);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureLinkRegister(BNArchitecture* arch);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureGlobalRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI bool BNIsArchitectureGlobalRegister(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureSystemRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI bool BNIsArchitectureSystemRegister(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureRegisterByName(BNArchitecture* arch, const char* name);

	BINARYNINJACOREAPI char* BNGetArchitectureRegisterStackName(BNArchitecture* arch, uint32_t regStack);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureRegisterStacks(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNRegisterStackInfo BNGetArchitectureRegisterStackInfo(BNArchitecture* arch, uint32_t regStack);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureRegisterStackForRegister(BNArchitecture* arch, uint32_t reg);

	BINARYNINJACOREAPI BNIntrinsicClass BNGetArchitectureIntrinsicClass(BNArchitecture* arch, uint32_t intrinsic);
	BINARYNINJACOREAPI char* BNGetArchitectureIntrinsicName(BNArchitecture* arch, uint32_t intrinsic);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureIntrinsics(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNNameAndType* BNGetArchitectureIntrinsicInputs(
	    BNArchitecture* arch, uint32_t intrinsic, size_t* count);
	BINARYNINJACOREAPI void BNFreeNameAndTypeList(BNNameAndType* nt, size_t count);
	BINARYNINJACOREAPI BNTypeWithConfidence* BNGetArchitectureIntrinsicOutputs(
	    BNArchitecture* arch, uint32_t intrinsic, size_t* count);
	BINARYNINJACOREAPI void BNFreeOutputTypeList(BNTypeWithConfidence* types, size_t count);

	BINARYNINJACOREAPI bool BNCanArchitectureAssemble(BNArchitecture* arch);
	BINARYNINJACOREAPI bool BNAssemble(
	    BNArchitecture* arch, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);

	BINARYNINJACOREAPI bool BNIsArchitectureNeverBranchPatchAvailable(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureAlwaysBranchPatchAvailable(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureInvertBranchPatchAvailable(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureSkipAndReturnZeroPatchAvailable(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureSkipAndReturnValuePatchAvailable(
	    BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);

	BINARYNINJACOREAPI bool BNArchitectureConvertToNop(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureAlwaysBranch(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureInvertBranch(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureSkipAndReturnValue(
	    BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len, uint64_t value);
	BINARYNINJACOREAPI void BNRegisterArchitectureFunctionRecognizer(BNArchitecture* arch, BNFunctionRecognizer* rec);

	BINARYNINJACOREAPI void BNArchitectureRegisterRelocationHandler(
	    BNArchitecture* arch, const char* viewName, BNRelocationHandler* handler);
	BINARYNINJACOREAPI BNRelocationHandler* BNCreateRelocationHandler(BNCustomRelocationHandler* handler);
	BINARYNINJACOREAPI BNRelocationHandler* BNArchitectureGetRelocationHandler(
	    BNArchitecture* arch, const char* viewName);
	BINARYNINJACOREAPI BNRelocationHandler* BNNewRelocationHandlerReference(BNRelocationHandler* handler);
	BINARYNINJACOREAPI void BNFreeRelocationHandler(BNRelocationHandler* handler);
	BINARYNINJACOREAPI bool BNRelocationHandlerGetRelocationInfo(BNRelocationHandler* handler, BNBinaryView* data,
	    BNArchitecture* arch, BNRelocationInfo* info, size_t infoCount);
	BINARYNINJACOREAPI bool BNRelocationHandlerApplyRelocation(BNRelocationHandler* handler, BNBinaryView* view,
	    BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
	BINARYNINJACOREAPI bool BNRelocationHandlerDefaultApplyRelocation(BNRelocationHandler* handler, BNBinaryView* view,
	    BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
	BINARYNINJACOREAPI size_t BNRelocationHandlerGetOperandForExternalRelocation(BNRelocationHandler* handler,
	    const uint8_t* data, uint64_t addr, size_t length, const BNLowLevelILFunction* il, BNRelocation* relocation);
	// Analysis
	BINARYNINJACOREAPI void BNAddAnalysisOption(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNFunction* BNAddFunctionForAnalysis(
		BNBinaryView* view, BNPlatform* platform, uint64_t addr, bool autoDiscovered, BNType* type);
	BINARYNINJACOREAPI void BNAddEntryPointForAnalysis(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNRemoveAnalysisFunction(BNBinaryView* view, BNFunction* func, bool updateRefs);
	BINARYNINJACOREAPI BNFunction* BNCreateUserFunction(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI void BNRemoveUserFunction(BNBinaryView* view, BNFunction* func);
	BINARYNINJACOREAPI bool BNHasInitialAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetAnalysisHold(BNBinaryView* view, bool enable);
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
	BINARYNINJACOREAPI bool BNHasSymbols(BNBinaryView* view);
	BINARYNINJACOREAPI bool BNHasDataVariables(BNBinaryView* view);
	BINARYNINJACOREAPI BNFunction* BNGetAnalysisFunction(BNBinaryView* view, BNPlatform* platform, uint64_t addr);
	BINARYNINJACOREAPI BNFunction* BNGetRecentAnalysisFunctionForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionsForAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNFunction** BNGetAnalysisFunctionsContainingAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNFunction* BNGetAnalysisEntryPoint(BNBinaryView* view);
	BINARYNINJACOREAPI BNFunction** BNGetAllEntryFunctions(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNAddToEntryFunctions(BNBinaryView* view, BNFunction* func);

	BINARYNINJACOREAPI char* BNGetGlobalCommentForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t* BNGetGlobalCommentedAddresses(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNSetGlobalCommentForAddress(BNBinaryView* view, uint64_t addr, const char* comment);

	BINARYNINJACOREAPI BNBinaryView* BNGetFunctionData(BNFunction* func);
	BINARYNINJACOREAPI BNArchitecture* BNGetFunctionArchitecture(BNFunction* func);
	BINARYNINJACOREAPI BNPlatform* BNGetFunctionPlatform(BNFunction* func);
	BINARYNINJACOREAPI uint64_t BNGetFunctionStart(BNFunction* func);
	BINARYNINJACOREAPI BNSymbol* BNGetFunctionSymbol(BNFunction* func);
	BINARYNINJACOREAPI bool BNWasFunctionAutomaticallyDiscovered(BNFunction* func);
	BINARYNINJACOREAPI bool BNFunctionHasUserAnnotations(BNFunction* func);
	BINARYNINJACOREAPI BNBoolWithConfidence BNCanFunctionReturn(BNFunction* func);
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsFunctionPure(BNFunction* func);
	BINARYNINJACOREAPI void BNSetFunctionAutoType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI void BNSetFunctionUserType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI bool BNFunctionHasUserType(BNFunction* func);

	BINARYNINJACOREAPI char* BNGetFunctionComment(BNFunction* func);
	BINARYNINJACOREAPI char* BNGetCommentForAddress(BNFunction* func, uint64_t addr);
	BINARYNINJACOREAPI uint64_t* BNGetCommentedAddresses(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeAddressList(uint64_t* addrs);
	BINARYNINJACOREAPI void BNSetFunctionComment(BNFunction* func, const char* comment);
	BINARYNINJACOREAPI void BNSetCommentForAddress(BNFunction* func, uint64_t addr, const char* comment);

	BINARYNINJACOREAPI void BNAddUserCodeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, uint64_t toAddr);
	BINARYNINJACOREAPI void BNRemoveUserCodeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

	BINARYNINJACOREAPI void BNAddUserTypeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNRemoveUserTypeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNAddUserTypeFieldReference(BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr,
	    BNQualifiedName* name, uint64_t offset, size_t size);
	BINARYNINJACOREAPI void BNRemoveUserTypeFieldReference(BNFunction* func, BNArchitecture* fromArch,
	    uint64_t fromAddr, BNQualifiedName* name, uint64_t offset, size_t size);

	BINARYNINJACOREAPI BNBasicBlock* BNNewBasicBlockReference(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNFreeBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetFunctionBasicBlockList(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeBasicBlockList(BNBasicBlock** blocks, size_t count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetFunctionBasicBlockAtAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNBasicBlock* BNGetRecentBasicBlockForAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlocksForAddress(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlocksStartingAtAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);

	BINARYNINJACOREAPI uint64_t BNGetFunctionHighestAddress(BNFunction* func);
	BINARYNINJACOREAPI uint64_t BNGetFunctionLowestAddress(BNFunction* func);
	BINARYNINJACOREAPI BNAddressRange* BNGetFunctionAddressRanges(BNFunction* func, size_t* count);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLowLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLowLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILInstructionsForAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILExitsForInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeILInstructionList(size_t* list);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMediumLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMediumLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMappedMediumLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMappedMediumLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetFunctionHighLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetFunctionHighLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNGetFunctionLanguageRepresentation(BNFunction* func);
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNGetFunctionLanguageRepresentationIfAvailable(BNFunction* func);

	BINARYNINJACOREAPI BNDataBuffer* BNGetConstantData(BNFunction* func, BNRegisterValueType state, uint64_t value, size_t size);

	BINARYNINJACOREAPI BNRegisterValue BNGetRegisterValueAtInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t reg);
	BINARYNINJACOREAPI BNRegisterValue BNGetRegisterValueAfterInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t reg);
	BINARYNINJACOREAPI BNRegisterValue BNGetStackContentsAtInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t offset, size_t size);
	BINARYNINJACOREAPI BNRegisterValue BNGetStackContentsAfterInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t offset, size_t size);
	BINARYNINJACOREAPI BNRegisterValue BNGetParameterValueAtInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNType* functionType, size_t i);
	BINARYNINJACOREAPI BNRegisterValue BNGetParameterValueAtLowLevelILInstruction(
	    BNFunction* func, size_t instr, BNType* functionType, size_t i);
	BINARYNINJACOREAPI void BNFreePossibleValueSet(BNPossibleValueSet* value);
	BINARYNINJACOREAPI uint32_t* BNGetRegistersReadByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetRegistersWrittenByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNStackVariableReference* BNGetStackVariablesReferencedByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNStackVariableReference* BNGetStackVariablesReferencedByInstructionIfAvailable(
		BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeStackVariableReferenceList(BNStackVariableReference* refs, size_t count);
	BINARYNINJACOREAPI BNConstantReference* BNGetConstantsReferencedByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNConstantReference* BNGetConstantsReferencedByInstructionIfAvailable(
		BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeConstantReferenceList(BNConstantReference* refs);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLiftedIL(BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLiftedILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI size_t BNGetLiftedILForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t* BNGetLiftedILInstructionsForAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLiftedILFlagUsesForDefinition(
	    BNFunction* func, size_t i, uint32_t flag, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLiftedILFlagDefinitionsForUse(
	    BNFunction* func, size_t i, uint32_t flag, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFlagsReadByLiftedILInstruction(BNFunction* func, size_t i, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFlagsWrittenByLiftedILInstruction(BNFunction* func, size_t i, size_t* count);

	BINARYNINJACOREAPI BNType* BNGetFunctionType(BNFunction* func);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetFunctionReturnType(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterSetWithConfidence BNGetFunctionReturnRegisters(BNFunction* func);
	BINARYNINJACOREAPI BNCallingConventionWithConfidence BNGetFunctionCallingConvention(BNFunction* func);
	BINARYNINJACOREAPI BNParameterVariablesWithConfidence BNGetFunctionParameterVariables(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeParameterVariables(BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI BNBoolWithConfidence BNFunctionHasVariableArguments(BNFunction* func);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetFunctionStackAdjustment(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterStackAdjustment* BNGetFunctionRegisterStackAdjustments(
	    BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeRegisterStackAdjustments(BNRegisterStackAdjustment* adjustments);
	BINARYNINJACOREAPI BNRegisterSetWithConfidence BNGetFunctionClobberedRegisters(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeRegisterSet(BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNSetAutoFunctionReturnType(BNFunction* func, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetAutoFunctionReturnRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);
	BINARYNINJACOREAPI void BNSetAutoFunctionCallingConvention(
	    BNFunction* func, BNCallingConventionWithConfidence* convention);
	BINARYNINJACOREAPI void BNSetAutoFunctionParameterVariables(
	    BNFunction* func, BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI void BNSetAutoFunctionHasVariableArguments(BNFunction* func, BNBoolWithConfidence* varArgs);
	BINARYNINJACOREAPI void BNSetAutoFunctionCanReturn(BNFunction* func, BNBoolWithConfidence* returns);
	BINARYNINJACOREAPI void BNSetAutoFunctionPure(BNFunction* func, BNBoolWithConfidence* pure);
	BINARYNINJACOREAPI void BNSetAutoFunctionStackAdjustment(BNFunction* func, BNOffsetWithConfidence* stackAdjust);
	BINARYNINJACOREAPI void BNSetAutoFunctionRegisterStackAdjustments(
	    BNFunction* func, BNRegisterStackAdjustment* adjustments, size_t count);
	BINARYNINJACOREAPI void BNSetAutoFunctionClobberedRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNSetUserFunctionReturnType(BNFunction* func, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetUserFunctionReturnRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);
	BINARYNINJACOREAPI void BNSetUserFunctionCallingConvention(
	    BNFunction* func, BNCallingConventionWithConfidence* convention);
	BINARYNINJACOREAPI void BNSetUserFunctionParameterVariables(
	    BNFunction* func, BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI void BNSetUserFunctionHasVariableArguments(BNFunction* func, BNBoolWithConfidence* varArgs);
	BINARYNINJACOREAPI void BNSetUserFunctionCanReturn(BNFunction* func, BNBoolWithConfidence* returns);
	BINARYNINJACOREAPI void BNSetUserFunctionPure(BNFunction* func, BNBoolWithConfidence* pure);
	BINARYNINJACOREAPI void BNSetUserFunctionStackAdjustment(BNFunction* func, BNOffsetWithConfidence* stackAdjust);
	BINARYNINJACOREAPI void BNSetUserFunctionRegisterStackAdjustments(
	    BNFunction* func, BNRegisterStackAdjustment* adjustments, size_t count);
	BINARYNINJACOREAPI void BNSetUserFunctionClobberedRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNApplyImportedTypes(BNFunction* func, BNSymbol* sym, BNType* type);
	BINARYNINJACOREAPI void BNApplyAutoDiscoveredFunctionType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI bool BNFunctionHasExplicitlyDefinedType(BNFunction* func);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetFunctionTypeTokens(
	    BNFunction* func, BNDisassemblySettings* settings, size_t* count);

	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetFunctionGlobalPointerValue(BNFunction* func);
	BINARYNINJACOREAPI bool BNFunctionUsesIncomingGlobalPointer(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetFunctionRegisterValueAtExit(BNFunction* func, uint32_t reg);

	BINARYNINJACOREAPI BNBoolWithConfidence BNIsFunctionInlinedDuringAnalysis(BNFunction* func);
	BINARYNINJACOREAPI void BNSetAutoFunctionInlinedDuringAnalysis(BNFunction* func, BNBoolWithConfidence inlined);
	BINARYNINJACOREAPI void BNSetUserFunctionInlinedDuringAnalysis(BNFunction* func, BNBoolWithConfidence inlined);

	BINARYNINJACOREAPI bool BNGetInstructionContainingAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint64_t* start);

	BINARYNINJACOREAPI BNFunction* BNGetBasicBlockFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNArchitecture* BNGetBasicBlockArchitecture(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockSource(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockStart(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockEnd(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockLength(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlockEdge* BNGetBasicBlockOutgoingEdges(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlockEdge* BNGetBasicBlockIncomingEdges(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI void BNFreeBasicBlockEdgeList(BNBasicBlockEdge* edges, size_t count);
	BINARYNINJACOREAPI bool BNBasicBlockHasUndeterminedOutgoingEdges(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNBasicBlockCanExit(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNBasicBlockSetCanExit(BNBasicBlock* block, bool value);
	BINARYNINJACOREAPI bool BNBasicBlockHasInvalidInstructions(BNBasicBlock* block);
	BINARYNINJACOREAPI size_t BNGetBasicBlockIndex(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominators(BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockStrictDominators(BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockImmediateDominator(BNBasicBlock* block, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominatorTreeChildren(
	    BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominanceFrontier(BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockIteratedDominanceFrontier(
	    BNBasicBlock** blocks, size_t incomingCount, size_t* outputCount);
	BINARYNINJACOREAPI bool BNIsILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsLowLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsMediumLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsHighLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI BNFunctionGraphType BNGetBasicBlockFunctionGraphType(BNBasicBlock* block);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetBasicBlockLowLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetBasicBlockMediumLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetBasicBlockHighLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNGetBasicBlockInstructionContainingAddress(
	    BNBasicBlock* block, uint64_t addr, uint64_t* start);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockSourceBlock(BNBasicBlock* block);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetBasicBlockDisassemblyText(
	    BNBasicBlock* block, BNDisassemblySettings* settings, size_t* count);
	BINARYNINJACOREAPI void BNFreeDisassemblyTextLines(BNDisassemblyTextLine* lines, size_t count);

	BINARYNINJACOREAPI char* BNGetDisplayStringForInteger(
	    BNBinaryView* binaryView, BNIntegerDisplayType type, uint64_t value, size_t inputWidth, bool isSigned);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateDisassemblyTextRenderer(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateLowLevelILDisassemblyTextRenderer(
	    BNLowLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateMediumLevelILDisassemblyTextRenderer(
	    BNMediumLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateHighLevelILDisassemblyTextRenderer(
	    BNHighLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNNewDisassemblyTextRendererReference(
	    BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI void BNFreeDisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNFunction* BNGetDisassemblyTextRendererFunction(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetDisassemblyTextRendererLowLevelILFunction(
	    BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetDisassemblyTextRendererMediumLevelILFunction(
	    BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetDisassemblyTextRendererHighLevelILFunction(
	    BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNBasicBlock* BNGetDisassemblyTextRendererBasicBlock(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNArchitecture* BNGetDisassemblyTextRendererArchitecture(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNDisassemblySettings* BNGetDisassemblyTextRendererSettings(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI void BNSetDisassemblyTextRendererBasicBlock(
	    BNDisassemblyTextRenderer* renderer, BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetDisassemblyTextRendererArchitecture(
	    BNDisassemblyTextRenderer* renderer, BNArchitecture* arch);
	BINARYNINJACOREAPI void BNSetDisassemblyTextRendererSettings(
	    BNDisassemblyTextRenderer* renderer, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI bool BNIsILDisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI bool BNDisassemblyTextRendererHasDataFlow(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetDisassemblyTextRendererInstructionAnnotations(
	    BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI bool BNGetDisassemblyTextRendererInstructionText(
	    BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t* len, BNDisassemblyTextLine** result, size_t* count);
	BINARYNINJACOREAPI bool BNGetDisassemblyTextRendererLines(
	    BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t* len, BNDisassemblyTextLine** result, size_t* count);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNPostProcessDisassemblyTextRendererLines(
	    BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t len, BNDisassemblyTextLine* inLines, size_t inCount,
	    size_t* outCount, const char* indentSpaces);
	BINARYNINJACOREAPI void BNResetDisassemblyTextRendererDeduplicatedComments(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI bool BNGetDisassemblyTextRendererSymbolTokens(BNDisassemblyTextRenderer* renderer, uint64_t addr,
	    size_t size, size_t operand, BNInstructionTextToken** result, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetDisassemblyTextRendererStackVariableReferenceTokens(
	    BNDisassemblyTextRenderer* renderer, BNStackVariableReference* ref, size_t* count);
	BINARYNINJACOREAPI bool BNIsIntegerToken(BNInstructionTextTokenType type);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetDisassemblyTextRendererIntegerTokens(
	    BNDisassemblyTextRenderer* renderer, BNInstructionTextToken* token, BNArchitecture* arch, uint64_t addr,
	    size_t* count);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNDisassemblyTextRendererWrapComment(BNDisassemblyTextRenderer* renderer,
	    const BNDisassemblyTextLine* inLine, size_t* outLineCount, const char* comment, bool hasAutoAnnotations,
	    const char* leadingSpaces, const char* indentSpaces);

	BINARYNINJACOREAPI void BNMarkFunctionAsRecentlyUsed(BNFunction* func);
	BINARYNINJACOREAPI void BNMarkBasicBlockAsRecentlyUsed(BNBasicBlock* block);

	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferences(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferencesInRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNFreeCodeReferences(BNReferenceSource* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferences(BNTypeFieldReference* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeILReferences(BNILReferenceSource* refs, size_t count);
	BINARYNINJACOREAPI uint64_t* BNGetCodeReferencesFrom(BNBinaryView* view, BNReferenceSource* src, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetCodeReferencesFromInRange(
	    BNBinaryView* view, BNReferenceSource* src, uint64_t len, size_t* count);

	BINARYNINJACOREAPI uint64_t* BNGetDataReferences(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesInRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesFrom(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesFromInRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNAddUserDataReference(BNBinaryView* view, uint64_t fromAddr, uint64_t toAddr);
	BINARYNINJACOREAPI void BNRemoveUserDataReference(BNBinaryView* view, uint64_t fromAddr, uint64_t toAddr);
	BINARYNINJACOREAPI void BNFreeDataReferences(uint64_t* refs);

	BINARYNINJACOREAPI void BNFreeTypeReferences(BNTypeReferenceSource* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceSizeInfo(BNTypeFieldReferenceSizeInfo* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceTypeInfo(BNTypeFieldReferenceTypeInfo* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceSizes(size_t* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeFieldReferenceTypes(BNTypeWithConfidence* refs, size_t count);

	// References to type
	BINARYNINJACOREAPI BNReferenceSource* BNGetCodeReferencesForType(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesForType(BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetTypeReferencesForType(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);

	// References to type field
	BINARYNINJACOREAPI BNTypeFieldReference* BNGetCodeReferencesForTypeField(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesForTypeField(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetDataReferencesFromForTypeField(
		BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetTypeReferencesForTypeField(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);

	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFrom(
	    BNBinaryView* view, BNReferenceSource* addr, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFromInRange(
	    BNBinaryView* view, BNReferenceSource* addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFieldsFrom(
	    BNBinaryView* view, BNReferenceSource* addr, size_t* count);
	BINARYNINJACOREAPI BNTypeReferenceSource* BNGetCodeReferencesForTypeFieldsFromInRange(
	    BNBinaryView* view, BNReferenceSource* addr, uint64_t len, size_t* count);

	BINARYNINJACOREAPI uint64_t* BNGetAllFieldsReferenced(BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNTypeFieldReferenceSizeInfo* BNGetAllSizesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNTypeFieldReferenceTypeInfo* BNGetAllTypesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetSizesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);
	BINARYNINJACOREAPI BNTypeWithConfidence* BNGetTypesReferenced(
	    BNBinaryView* view, BNQualifiedName* type, uint64_t offset, size_t* count);

	BINARYNINJACOREAPI BNQualifiedName* BNGetOutgoingDirectTypeReferences(BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNQualifiedName* BNGetOutgoingRecursiveTypeReferences(BNBinaryView* view, BNQualifiedName* types, size_t typeCount, size_t* count);
	BINARYNINJACOREAPI BNQualifiedName* BNGetIncomingDirectTypeReferences(BNBinaryView* view, BNQualifiedName* type, size_t* count);
	BINARYNINJACOREAPI BNQualifiedName* BNGetIncomingRecursiveTypeReferences(BNBinaryView* view, BNQualifiedName* types, size_t typeCount, size_t* count);

	BINARYNINJACOREAPI void BNRegisterGlobalFunctionRecognizer(BNFunctionRecognizer* rec);

	BINARYNINJACOREAPI bool BNGetStringAtAddress(BNBinaryView* view, uint64_t addr, BNStringReference* strRef);
	BINARYNINJACOREAPI BNStringReference* BNGetStrings(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNStringReference* BNGetStringsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t len, size_t* count);
	BINARYNINJACOREAPI void BNFreeStringReferenceList(BNStringReference* strings);

	BINARYNINJACOREAPI BNVariableNameAndType* BNGetStackLayout(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeVariableNameAndTypeList(BNVariableNameAndType* vars, size_t count);
	BINARYNINJACOREAPI void BNCreateAutoStackVariable(
	    BNFunction* func, int64_t offset, BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNCreateUserStackVariable(
	    BNFunction* func, int64_t offset, BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNDeleteAutoStackVariable(BNFunction* func, int64_t offset);
	BINARYNINJACOREAPI void BNDeleteUserStackVariable(BNFunction* func, int64_t offset);
	BINARYNINJACOREAPI bool BNGetStackVariableAtFrameOffset(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t offset, BNVariableNameAndType* var);
	BINARYNINJACOREAPI void BNFreeVariableNameAndType(BNVariableNameAndType* var);

	BINARYNINJACOREAPI BNVariableNameAndType* BNGetFunctionVariables(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNCreateAutoVariable(
	    BNFunction* func, const BNVariable* var, BNTypeWithConfidence* type, const char* name, bool ignoreDisjointUses);
	BINARYNINJACOREAPI void BNCreateUserVariable(
	    BNFunction* func, const BNVariable* var, BNTypeWithConfidence* type, const char* name, bool ignoreDisjointUses);
	BINARYNINJACOREAPI void BNDeleteUserVariable(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI bool BNIsVariableUserDefined(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetVariableType(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI char* BNGetVariableName(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI char* BNGetVariableNameOrDefault(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI char* BNGetLastSeenVariableNameOrDefault(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI uint64_t BNToVariableIdentifier(const BNVariable* var);
	BINARYNINJACOREAPI BNVariable BNFromVariableIdentifier(uint64_t id);
	BINARYNINJACOREAPI BNDeadStoreElimination BNGetFunctionVariableDeadStoreElimination(
	    BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI void BNSetFunctionVariableDeadStoreElimination(
	    BNFunction* func, const BNVariable* var, BNDeadStoreElimination mode);
	BINARYNINJACOREAPI BNMergedVariable* BNGetMergedVariables(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeMergedVariableList(BNMergedVariable* vars, size_t count);
	BINARYNINJACOREAPI void BNMergeVariables(BNFunction* func, const BNVariable* target, const BNVariable* sources,
		size_t sourceCount);
	BINARYNINJACOREAPI void BNUnmergeVariables(BNFunction* func, const BNVariable* target, const BNVariable* sources,
		size_t sourceCount);
	BINARYNINJACOREAPI BNVariable* BNGetSplitVariables(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNSplitVariable(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI void BNUnsplitVariable(BNFunction* func, const BNVariable* var);

	BINARYNINJACOREAPI BNReferenceSource* BNGetFunctionCallSites(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI uint64_t* BNGetCallees(BNBinaryView* view, BNReferenceSource* callSite, size_t* count);
	BINARYNINJACOREAPI BNReferenceSource* BNGetCallers(BNBinaryView* view, uint64_t callee, size_t* count);

	BINARYNINJACOREAPI void BNSetAutoIndirectBranches(BNFunction* func, BNArchitecture* sourceArch, uint64_t source,
	    BNArchitectureAndAddress* branches, size_t count);
	BINARYNINJACOREAPI void BNSetUserIndirectBranches(BNFunction* func, BNArchitecture* sourceArch, uint64_t source,
	    BNArchitectureAndAddress* branches, size_t count);

	BINARYNINJACOREAPI BNIndirectBranchInfo* BNGetIndirectBranches(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNIndirectBranchInfo* BNGetIndirectBranchesAt(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeIndirectBranchList(BNIndirectBranchInfo* branches);

	BINARYNINJACOREAPI uint64_t* BNGetUnresolvedIndirectBranches(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI bool BNHasUnresolvedIndirectBranches(BNFunction* func);

	BINARYNINJACOREAPI void BNSetAutoCallTypeAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetUserCallTypeAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetAutoCallStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetUserCallStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetAutoCallRegisterStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNRegisterStackAdjustment* adjust, size_t count);
	BINARYNINJACOREAPI void BNSetUserCallRegisterStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNRegisterStackAdjustment* adjust, size_t count);
	BINARYNINJACOREAPI void BNSetAutoCallRegisterStackAdjustmentForRegisterStack(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t regStack, int32_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetUserCallRegisterStackAdjustmentForRegisterStack(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t regStack, int32_t adjust, uint8_t confidence);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetCallTypeAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetCallStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNRegisterStackAdjustment* BNGetCallRegisterStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNRegisterStackAdjustment BNGetCallRegisterStackAdjustmentForRegisterStack(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t regStack);
	BINARYNINJACOREAPI bool BNIsCallInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI BNInstructionTextLine* BNGetFunctionBlockAnnotations(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);

	BINARYNINJACOREAPI BNIntegerDisplayType BNGetIntegerConstantDisplayType(
	    BNFunction* func, BNArchitecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
	BINARYNINJACOREAPI void BNSetIntegerConstantDisplayType(BNFunction* func, BNArchitecture* arch, uint64_t instrAddr,
	    uint64_t value, size_t operand, BNIntegerDisplayType type, const char* typeID);
	BINARYNINJACOREAPI char* BNGetIntegerConstantDisplayTypeEnumerationType(
		BNFunction* func, BNArchitecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);

	BINARYNINJACOREAPI bool BNIsFunctionTooLarge(BNFunction* func);
	BINARYNINJACOREAPI bool BNIsFunctionAnalysisSkipped(BNFunction* func);
	BINARYNINJACOREAPI BNAnalysisSkipReason BNGetAnalysisSkipReason(BNFunction* func);
	BINARYNINJACOREAPI BNFunctionAnalysisSkipOverride BNGetFunctionAnalysisSkipOverride(BNFunction* func);
	BINARYNINJACOREAPI void BNSetFunctionAnalysisSkipOverride(BNFunction* func, BNFunctionAnalysisSkipOverride skip);

	BINARYNINJACOREAPI char* BNGetGotoLabelName(BNFunction* func, uint64_t labelId);
	BINARYNINJACOREAPI void BNSetUserGotoLabelName(BNFunction* func, uint64_t labelId, const char* name);

	BINARYNINJACOREAPI BNAnalysisParameters BNGetParametersForAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetParametersForAnalysis(BNBinaryView* view, BNAnalysisParameters params);
	BINARYNINJACOREAPI uint64_t BNGetMaxFunctionSizeForAnalysis(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetMaxFunctionSizeForAnalysis(BNBinaryView* view, uint64_t size);
	BINARYNINJACOREAPI bool BNGetNewAutoFunctionAnalysisSuppressed(BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetNewAutoFunctionAnalysisSuppressed(BNBinaryView* view, bool suppress);

	BINARYNINJACOREAPI BNAnalysisCompletionEvent* BNAddAnalysisCompletionEvent(
	    BNBinaryView* view, void* ctxt, void (*callback)(void* ctxt));
	BINARYNINJACOREAPI BNAnalysisCompletionEvent* BNNewAnalysisCompletionEventReference(
	    BNAnalysisCompletionEvent* event);
	BINARYNINJACOREAPI void BNFreeAnalysisCompletionEvent(BNAnalysisCompletionEvent* event);
	BINARYNINJACOREAPI void BNCancelAnalysisCompletionEvent(BNAnalysisCompletionEvent* event);

	BINARYNINJACOREAPI BNAnalysisInfo* BNGetAnalysisInfo(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeAnalysisInfo(BNAnalysisInfo* info);
	BINARYNINJACOREAPI BNAnalysisProgress BNGetAnalysisProgress(BNBinaryView* view);
	BINARYNINJACOREAPI BNBackgroundTask* BNGetBackgroundAnalysisTask(BNBinaryView* view);

	BINARYNINJACOREAPI uint64_t BNGetNextFunctionStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextBasicBlockStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextDataAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetNextDataVariableStartAfterAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousFunctionStartBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousBasicBlockStartBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousBasicBlockEndBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousDataBeforeAddress(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI uint64_t BNGetPreviousDataVariableStartBeforeAddress(BNBinaryView* view, uint64_t addr);

	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewDisassembly(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLiftedIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLowLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLowLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMediumLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMediumLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMappedMediumLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMappedMediumLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewHighLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewHighLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLanguageRepresentation(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewDataOnly(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionDisassembly(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLiftedIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLowLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLowLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMediumLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMappedMediumLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMappedMediumLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionHighLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionHighLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLanguageRepresentation(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNNewLinearViewObjectReference(BNLinearViewObject* obj);
	BINARYNINJACOREAPI void BNFreeLinearViewObject(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetFirstLinearViewObjectChild(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLastLinearViewObjectChild(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetPreviousLinearViewObjectChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetNextLinearViewObjectChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForAddress(
	    BNLinearViewObject* parent, uint64_t addr);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForIdentifier(
	    BNLinearViewObject* parent, BNLinearViewObjectIdentifier* id);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetLinearViewObjectLines(
	    BNLinearViewObject* obj, BNLinearViewObject* prev, BNLinearViewObject* next, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearDisassemblyLines(BNLinearDisassemblyLine* lines, size_t count);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectStart(BNLinearViewObject* obj);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectEnd(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObjectIdentifier BNGetLinearViewObjectIdentifier(BNLinearViewObject* obj);
	BINARYNINJACOREAPI void BNFreeLinearViewObjectIdentifier(BNLinearViewObjectIdentifier* id);
	BINARYNINJACOREAPI int BNCompareLinearViewObjectChildren(
	    BNLinearViewObject* obj, BNLinearViewObject* a, BNLinearViewObject* b);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectOrderingIndexTotal(BNLinearViewObject* obj);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectOrderingIndexForChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForOrderingIndex(
	    BNLinearViewObject* parent, uint64_t idx);

	BINARYNINJACOREAPI BNLinearViewCursor* BNCreateLinearViewCursor(BNLinearViewObject* root);
	BINARYNINJACOREAPI BNLinearViewCursor* BNDuplicateLinearViewCursor(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewCursor* BNNewLinearViewCursorReference(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNFreeLinearViewCursor(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNIsLinearViewCursorBeforeBegin(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNIsLinearViewCursorAfterEnd(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewCursorCurrentObject(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewObjectIdentifier* BNGetLinearViewCursorPath(
	    BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearViewCursorPath(BNLinearViewObjectIdentifier* objs, size_t count);
	BINARYNINJACOREAPI BNLinearViewObject** BNGetLinearViewCursorPathObjects(BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearViewCursorPathObjects(BNLinearViewObject** objs, size_t count);
	BINARYNINJACOREAPI BNAddressRange BNGetLinearViewCursorOrderingIndex(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewCursorOrderingIndexTotal(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToBegin(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToEnd(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToAddress(BNLinearViewCursor* cursor, uint64_t addr);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToPath(
	    BNLinearViewCursor* cursor, BNLinearViewObjectIdentifier* ids, size_t count);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToPathAndAddress(
	    BNLinearViewCursor* cursor, BNLinearViewObjectIdentifier* ids, size_t count, uint64_t addr);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToCursorPath(BNLinearViewCursor* cursor, BNLinearViewCursor* path);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToCursorPathAndAddress(
	    BNLinearViewCursor* cursor, BNLinearViewCursor* path, uint64_t addr);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToOrderingIndex(BNLinearViewCursor* cursor, uint64_t idx);
	BINARYNINJACOREAPI bool BNLinearViewCursorNext(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNLinearViewCursorPrevious(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetLinearViewCursorLines(BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI int BNCompareLinearViewCursors(BNLinearViewCursor* a, BNLinearViewCursor* b);

	BINARYNINJACOREAPI void BNDefineDataVariable(BNBinaryView* view, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNDefineUserDataVariable(BNBinaryView* view, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNUndefineDataVariable(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI void BNUndefineUserDataVariable(BNBinaryView* view, uint64_t addr);
	BINARYNINJACOREAPI BNDataVariable* BNGetDataVariables(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeDataVariable(BNDataVariable* var);
	BINARYNINJACOREAPI void BNFreeDataVariables(BNDataVariable* vars, size_t count);
	BINARYNINJACOREAPI void BNFreeDataVariableAndName(BNDataVariableAndName* var);
	BINARYNINJACOREAPI void BNFreeDataVariablesAndName(BNDataVariableAndName* vars, size_t count);
	BINARYNINJACOREAPI void BNFreeDataVariableAndNameAndDebugParserList(
		BNDataVariableAndNameAndDebugParser* vars, size_t count);
	BINARYNINJACOREAPI bool BNGetDataVariableAtAddress(BNBinaryView* view, uint64_t addr, BNDataVariable* var);

	BINARYNINJACOREAPI bool BNParseTypeString(BNBinaryView* view, const char* text, BNQualifiedNameAndType* result,
	    char** errors, BNQualifiedNameList* typesAllowRedefinition, bool importDepencencies);
	BINARYNINJACOREAPI bool BNParseTypesString(BNBinaryView* view, const char* text, const char* const* options, size_t optionCount,
		const char* const* includeDirs, size_t includeDirCount, BNTypeParserResult* result, char** errors,
		BNQualifiedNameList* typesAllowRedefinition, bool importDepencencies);
	BINARYNINJACOREAPI void BNFreeQualifiedNameAndType(BNQualifiedNameAndType* obj);
	BINARYNINJACOREAPI void BNFreeQualifiedNameAndTypeArray(BNQualifiedNameAndType* obj, size_t count);
	BINARYNINJACOREAPI void BNFreeQualifiedNameTypeAndId(BNQualifiedNameTypeAndId* obj);
	BINARYNINJACOREAPI char* BNEscapeTypeName(const char* name, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI char* BNUnescapeTypeName(const char* name, BNTokenEscapingType escaping);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetAnalysisTypeList(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetAnalysisDependencySortedTypeList(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeAndNameList(BNQualifiedNameAndType* types, size_t count);
	BINARYNINJACOREAPI void BNFreeTypeIdList(BNQualifiedNameTypeAndId* types, size_t count);
	BINARYNINJACOREAPI BNQualifiedName* BNGetAnalysisTypeNames(BNBinaryView* view, size_t* count, const char* matching);
	BINARYNINJACOREAPI void BNFreeTypeNameList(BNQualifiedName* names, size_t count);
	BINARYNINJACOREAPI BNTypeContainer* BNGetAnalysisTypeContainer(BNBinaryView* view);
	BINARYNINJACOREAPI BNTypeContainer* BNGetAnalysisAutoTypeContainer(BNBinaryView* view);
	BINARYNINJACOREAPI BNTypeContainer* BNGetAnalysisUserTypeContainer(BNBinaryView* view);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeByName(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeByRef(BNBinaryView* view, BNNamedTypeReference* ref);
	BINARYNINJACOREAPI BNType* BNGetAnalysisTypeById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI char* BNGetAnalysisTypeId(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNGetAnalysisTypeNameById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI bool BNIsAnalysisTypeAutoDefined(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI BNQualifiedName BNDefineAnalysisType(
	    BNBinaryView* view, const char* id, BNQualifiedName* defaultName, BNType* type);
	BINARYNINJACOREAPI void BNDefineUserAnalysisType(BNBinaryView* view, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI size_t BNDefineAnalysisTypes(BNBinaryView* view, BNQualifiedNameTypeAndId* types, size_t count, BNProgressFunction progress, void* progressContext, char*** resultIds, BNQualifiedName** resultNames);
	BINARYNINJACOREAPI void BNDefineUserAnalysisTypes(BNBinaryView* view, BNQualifiedNameAndType* types, size_t count, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI void BNUndefineAnalysisType(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI void BNUndefineUserAnalysisType(BNBinaryView* view, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNRenameAnalysisType(
	    BNBinaryView* view, BNQualifiedName* oldName, BNQualifiedName* newName);
	BINARYNINJACOREAPI char* BNGenerateAutoTypeId(const char* source, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGenerateAutoPlatformTypeId(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGenerateAutoDemangledTypeId(BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoPlatformTypeIdSource(BNPlatform* platform);
	BINARYNINJACOREAPI char* BNGetAutoDemangledTypeIdSource(void);
	BINARYNINJACOREAPI char* BNGenerateAutoDebugTypeId(BNQualifiedName* name);
	BINARYNINJACOREAPI char* BNGetAutoDebugTypeIdSource(void);

	BINARYNINJACOREAPI void BNRegisterPlatformTypes(BNBinaryView* view, BNPlatform* platform);
	BINARYNINJACOREAPI bool BNLookupImportedTypePlatform(BNBinaryView* view, const BNQualifiedName* typeName, BNPlatform** platform, BNQualifiedName* resultName);

	BINARYNINJACOREAPI void BNReanalyzeAllFunctions(BNBinaryView* view);
	BINARYNINJACOREAPI void BNReanalyzeFunction(BNFunction* func, BNFunctionUpdateType type);
	BINARYNINJACOREAPI void BNMarkUpdatesRequired(BNFunction* func, BNFunctionUpdateType type);
	BINARYNINJACOREAPI void BNMarkCallerUpdatesRequired(BNFunction* func, BNFunctionUpdateType type);

	BINARYNINJACOREAPI BNWorkflow* BNGetWorkflowForBinaryView(BNBinaryView* view);
	BINARYNINJACOREAPI BNWorkflow* BNGetWorkflowForFunction(BNFunction* func);
	BINARYNINJACOREAPI char* BNPostWorkflowRequestForFunction(BNFunction* func, const char* request);
	BINARYNINJACOREAPI char* BNGetProvenanceString(BNFunction* func);

	BINARYNINJACOREAPI BNHighlightColor BNGetInstructionHighlight(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNSetAutoInstructionHighlight(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNHighlightColor color);
	BINARYNINJACOREAPI void BNSetUserInstructionHighlight(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNHighlightColor color);
	BINARYNINJACOREAPI BNHighlightColor BNGetBasicBlockHighlight(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetAutoBasicBlockHighlight(BNBasicBlock* block, BNHighlightColor color);
	BINARYNINJACOREAPI void BNSetUserBasicBlockHighlight(BNBasicBlock* block, BNHighlightColor color);

	BINARYNINJACOREAPI void BNFreeTypeContainer(BNTypeContainer* container);
	BINARYNINJACOREAPI BNTypeContainer* BNDuplicateTypeContainer(BNTypeContainer* container);
	BINARYNINJACOREAPI char* BNTypeContainerGetId(BNTypeContainer* container);
	BINARYNINJACOREAPI char* BNTypeContainerGetName(BNTypeContainer* container);
	BINARYNINJACOREAPI BNTypeContainerType BNTypeContainerGetType(BNTypeContainer* container);
	BINARYNINJACOREAPI bool BNTypeContainerIsMutable(BNTypeContainer* container);
	BINARYNINJACOREAPI BNPlatform* BNTypeContainerGetPlatform(BNTypeContainer* container);
	BINARYNINJACOREAPI bool BNTypeContainerAddTypes(BNTypeContainer* container, const BNQualifiedName* typeNames, BNType** types, size_t typeCount, bool(*progress)(void*, size_t, size_t), void* progressContext, BNQualifiedName** resultNames, char*** resultIds, size_t* resultCount);
	BINARYNINJACOREAPI bool BNTypeContainerRenameType(BNTypeContainer* container, const char* typeId, const BNQualifiedName* newName);
	BINARYNINJACOREAPI bool BNTypeContainerDeleteType(BNTypeContainer* container, const char* typeId);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeId(BNTypeContainer* container, const BNQualifiedName* typeName, char** result);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeName(BNTypeContainer* container, const char* typeId, BNQualifiedName* result);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeById(BNTypeContainer* container, const char* typeId, BNType** result);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypes(BNTypeContainer* container, char*** typeIds, BNQualifiedName** typeNames, BNType*** types, size_t* count);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeByName(BNTypeContainer* container, const BNQualifiedName* typeName, BNType** result);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeIds(BNTypeContainer* container, char*** typeIds, size_t* count);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeNames(BNTypeContainer* container, BNQualifiedName** typeNames, size_t* count);
	BINARYNINJACOREAPI bool BNTypeContainerGetTypeNamesAndIds(BNTypeContainer* container, char*** typeIds, BNQualifiedName** typeNames, size_t* count);
	BINARYNINJACOREAPI bool BNTypeContainerParseTypeString(BNTypeContainer* container,
		const char* source, bool importDepencencies, BNQualifiedNameAndType* result,
		BNTypeParserError** errors, size_t* errorCount
	);
	BINARYNINJACOREAPI bool BNTypeContainerParseTypesFromSource(BNTypeContainer* container,
		const char* source, const char* fileName,
		const char* const* options, size_t optionCount,
		const char* const* includeDirs, size_t includeDirCount,
		const char* autoTypeSource, bool importDepencencies, BNTypeParserResult* result,
		BNTypeParserError** errors, size_t* errorCount
	);

	BINARYNINJACOREAPI BNTagType* BNCreateTagType(BNBinaryView* view);
	BINARYNINJACOREAPI BNTagType* BNNewTagTypeReference(BNTagType* tagType);
	BINARYNINJACOREAPI void BNFreeTagType(BNTagType* tagType);
	BINARYNINJACOREAPI void BNFreeTagTypeList(BNTagType** tagTypes, size_t count);
	BINARYNINJACOREAPI BNBinaryView* BNTagTypeGetView(BNTagType* tagType);
	BINARYNINJACOREAPI char* BNTagTypeGetId(BNTagType* tagType);
	BINARYNINJACOREAPI char* BNTagTypeGetName(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetName(BNTagType* tagType, const char* name);
	BINARYNINJACOREAPI char* BNTagTypeGetIcon(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetIcon(BNTagType* tagType, const char* icon);
	BINARYNINJACOREAPI bool BNTagTypeGetVisible(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetVisible(BNTagType* tagType, bool visible);
	BINARYNINJACOREAPI BNTagTypeType BNTagTypeGetType(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetType(BNTagType* tagType, BNTagTypeType type);

	BINARYNINJACOREAPI BNTag* BNCreateTag(BNTagType* type, const char* data);
	BINARYNINJACOREAPI BNTag* BNNewTagReference(BNTag* tag);
	BINARYNINJACOREAPI void BNFreeTag(BNTag* tag);
	BINARYNINJACOREAPI void BNFreeTagList(BNTag** tags, size_t count);
	BINARYNINJACOREAPI char* BNTagGetId(BNTag* tag);
	BINARYNINJACOREAPI BNTagType* BNTagGetType(BNTag* tag);
	BINARYNINJACOREAPI char* BNTagGetData(BNTag* tag);
	BINARYNINJACOREAPI void BNTagSetData(BNTag* tag, const char* data);

	BINARYNINJACOREAPI void BNAddTagType(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI void BNRemoveTagType(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI BNTagType* BNGetTagType(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNTagType* BNGetTagTypeWithType(BNBinaryView* view, const char* name, BNTagTypeType type);
	BINARYNINJACOREAPI BNTagType* BNGetTagTypeById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI BNTagType* BNGetTagTypeByIdWithType(BNBinaryView* view, const char* id, BNTagTypeType type);
	BINARYNINJACOREAPI BNTagType** BNGetTagTypes(BNBinaryView* view, size_t* count);

	BINARYNINJACOREAPI void BNAddTag(BNBinaryView* view, BNTag* tag, bool user);
	BINARYNINJACOREAPI BNTag* BNGetTag(BNBinaryView* view, const char* tagId);
	BINARYNINJACOREAPI void BNRemoveTag(BNBinaryView* view, BNTag* tag, bool user);

	BINARYNINJACOREAPI BNTagReference* BNGetAllTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAllAddressTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAllFunctionTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAllTagReferencesOfType(
	    BNBinaryView* view, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetTagReferencesOfType(BNBinaryView* view, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetDataTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoDataTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserDataTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNRemoveTagReference(BNBinaryView* view, BNTagReference ref);
	BINARYNINJACOREAPI void BNFreeTagReferences(BNTagReference* refs, size_t count);
	BINARYNINJACOREAPI BNTag** BNGetDataTags(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoDataTags(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserDataTags(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetDataTagsOfType(
	    BNBinaryView* view, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoDataTagsOfType(
	    BNBinaryView* view, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserDataTagsOfType(
	    BNBinaryView* view, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetDataTagsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoDataTagsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserDataTagsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI void BNAddAutoDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoDataTagsOfType(BNBinaryView* view, uint64_t addr, BNTagType* tagType);
	BINARYNINJACOREAPI void BNAddUserDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserDataTagsOfType(BNBinaryView* view, uint64_t addr, BNTagType* tagType);

	BINARYNINJACOREAPI size_t BNGetTagReferencesOfTypeCount(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI size_t BNGetAllTagReferencesOfTypeCount(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI void BNGetAllTagReferenceTypeCounts(
	    BNBinaryView* view, BNTagType*** tagTypes, size_t** counts, size_t* count);
	BINARYNINJACOREAPI void BNFreeTagReferenceTypeCounts(BNTagType** tagTypes, size_t* counts);

	BINARYNINJACOREAPI BNTagReference* BNGetFunctionAllTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetFunctionTagReferencesOfType(
	    BNFunction* func, BNTagType* tagType, size_t* count);

	BINARYNINJACOREAPI BNTagReference* BNGetAddressTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoAddressTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserAddressTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAddressTags(BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoAddressTags(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserAddressTags(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAddressTagsInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoAddressTagsInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserAddressTagsInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI void BNAddAutoAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType);
	BINARYNINJACOREAPI void BNAddUserAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType);

	BINARYNINJACOREAPI BNTagReference* BNGetFunctionTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoFunctionTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserFunctionTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetFunctionTags(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoFunctionTags(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserFunctionTags(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetFunctionTagsOfType(BNFunction* func, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoFunctionTagsOfType(BNFunction* func, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserFunctionTagsOfType(BNFunction* func, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI void BNAddAutoFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoFunctionTagsOfType(BNFunction* func, BNTagType* tagType);
	BINARYNINJACOREAPI void BNAddUserFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserFunctionTagsOfType(BNFunction* func, BNTagType* tagType);

	BINARYNINJACOREAPI BNPerformanceInfo* BNGetFunctionAnalysisPerformanceInfo(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeAnalysisPerformanceInfo(BNPerformanceInfo* info, size_t count);

	BINARYNINJACOREAPI BNFlowGraph* BNGetUnresolvedStackAdjustmentGraph(BNFunction* func);

	BINARYNINJACOREAPI void BNSetUserVariableValue(BNFunction* func, const BNVariable* var,
	    const BNArchitectureAndAddress* defSite, const BNPossibleValueSet* value);
	BINARYNINJACOREAPI void BNClearUserVariableValue(
	    BNFunction* func, const BNVariable* var, const BNArchitectureAndAddress* defSite);
	BINARYNINJACOREAPI BNUserVariableValue* BNGetAllUserVariableValues(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeUserVariableValues(BNUserVariableValue* result);
	BINARYNINJACOREAPI bool BNParsePossibleValueSet(BNBinaryView* view, const char* valueText,
	    BNRegisterValueType state, BNPossibleValueSet* result, uint64_t here, char** errors);

	BINARYNINJACOREAPI void BNRequestFunctionDebugReport(BNFunction* func, const char* name);

	BINARYNINJACOREAPI BNILReferenceSource* BNGetMediumLevelILVariableReferences(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesFrom(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNILReferenceSource* BNGetMediumLevelILVariableReferencesIfAvailable(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesFromIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesInRangeIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);

	BINARYNINJACOREAPI BNILReferenceSource* BNGetHighLevelILVariableReferences(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesFrom(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNILReferenceSource* BNGetHighLevelILVariableReferencesIfAvailable(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesFromIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesInRangeIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);

	BINARYNINJACOREAPI void BNFreeVariableList(BNVariable* vars);
	BINARYNINJACOREAPI void BNFreeVariableReferenceSourceList(BNVariableReferenceSource* vars, size_t count);

	// Analysis Context
	BINARYNINJACOREAPI BNAnalysisContext* BNCreateAnalysisContext(void);
	BINARYNINJACOREAPI BNAnalysisContext* BNNewAnalysisContextReference(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI void BNFreeAnalysisContext(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNFunction* BNAnalysisContextGetFunction(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNAnalysisContextGetLowLevelILFunction(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNAnalysisContextGetMediumLevelILFunction(
	    BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNAnalysisContextGetHighLevelILFunction(
	    BNAnalysisContext* analysisContext);

	BINARYNINJACOREAPI void BNSetBasicBlockList(
	    BNAnalysisContext* analysisContext, BNBasicBlock** basicBlocks, size_t count);
	BINARYNINJACOREAPI void BNSetLiftedILFunction(BNAnalysisContext* analysisContext, BNLowLevelILFunction* liftedIL);
	BINARYNINJACOREAPI void BNSetLowLevelILFunction(
	    BNAnalysisContext* analysisContext, BNLowLevelILFunction* lowLevelIL);
	BINARYNINJACOREAPI void BNSetMediumLevelILFunction(
	    BNAnalysisContext* analysisContext, BNMediumLevelILFunction* mediumLevelIL);
	BINARYNINJACOREAPI void BNSetHighLevelILFunction(
	    BNAnalysisContext* analysisContext, BNHighLevelILFunction* highLevelIL);
	BINARYNINJACOREAPI bool BNAnalysisContextInform(BNAnalysisContext* analysisContext, const char* request);

	// Activity
	BINARYNINJACOREAPI BNActivity* BNCreateActivity(const char* configuration, void* ctxt, void (*action)(void*, BNAnalysisContext*));
	BINARYNINJACOREAPI BNActivity* BNNewActivityReference(BNActivity* activity);
	BINARYNINJACOREAPI void BNFreeActivity(BNActivity* activity);

	BINARYNINJACOREAPI char* BNActivityGetName(BNActivity* activity);

	// Workflow
	BINARYNINJACOREAPI BNWorkflow* BNCreateWorkflow(const char* name);
	BINARYNINJACOREAPI BNWorkflow* BNNewWorkflowReference(BNWorkflow* workflow);
	BINARYNINJACOREAPI void BNFreeWorkflow(BNWorkflow* workflow);

	BINARYNINJACOREAPI BNWorkflow** BNGetWorkflowList(size_t* count);
	BINARYNINJACOREAPI void BNFreeWorkflowList(BNWorkflow** workflows, size_t count);
	BINARYNINJACOREAPI BNWorkflow* BNWorkflowInstance(const char* name);
	BINARYNINJACOREAPI bool BNRegisterWorkflow(BNWorkflow* workflow, const char* configuration);

	BINARYNINJACOREAPI BNWorkflow* BNWorkflowClone(BNWorkflow* workflow, const char* name, const char* activity);
	BINARYNINJACOREAPI BNActivity* BNWorkflowRegisterActivity(BNWorkflow* workflow, BNActivity* activity, const char** subactivities, size_t size);

	BINARYNINJACOREAPI bool BNWorkflowContains(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI char* BNWorkflowGetConfiguration(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI char* BNGetWorkflowName(BNWorkflow* workflow);
	BINARYNINJACOREAPI bool BNWorkflowIsRegistered(BNWorkflow* workflow);
	BINARYNINJACOREAPI size_t BNWorkflowSize(BNWorkflow* workflow);

	BINARYNINJACOREAPI BNActivity* BNWorkflowGetActivity(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI const char** BNWorkflowGetActivityRoots(
	    BNWorkflow* workflow, const char* activity, size_t* inoutSize);
	BINARYNINJACOREAPI const char** BNWorkflowGetSubactivities(
	    BNWorkflow* workflow, const char* activity, bool immediate, size_t* inoutSize);
	BINARYNINJACOREAPI bool BNWorkflowAssignSubactivities(
	    BNWorkflow* workflow, const char* activity, const char** activities, size_t size);
	BINARYNINJACOREAPI bool BNWorkflowClear(BNWorkflow* workflow);
	BINARYNINJACOREAPI bool BNWorkflowInsert(
	    BNWorkflow* workflow, const char* activity, const char** activities, size_t size);
	BINARYNINJACOREAPI bool BNWorkflowRemove(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI bool BNWorkflowReplace(BNWorkflow* workflow, const char* activity, const char* newActivity);

	BINARYNINJACOREAPI BNFlowGraph* BNWorkflowGetGraph(BNWorkflow* workflow, const char* activity, bool sequential);
	BINARYNINJACOREAPI void BNWorkflowShowReport(BNWorkflow* workflow, const char* name);

	// Disassembly settings
	BINARYNINJACOREAPI BNDisassemblySettings* BNCreateDisassemblySettings(void);
	BINARYNINJACOREAPI BNDisassemblySettings* BNNewDisassemblySettingsReference(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblySettings* BNDuplicateDisassemblySettings(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNFreeDisassemblySettings(BNDisassemblySettings* settings);

	BINARYNINJACOREAPI bool BNIsDisassemblySettingsOptionSet(
	    BNDisassemblySettings* settings, BNDisassemblyOption option);
	BINARYNINJACOREAPI void BNSetDisassemblySettingsOption(
	    BNDisassemblySettings* settings, BNDisassemblyOption option, bool state);

	BINARYNINJACOREAPI size_t BNGetDisassemblyWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyWidth(BNDisassemblySettings* settings, size_t width);
	BINARYNINJACOREAPI size_t BNGetDisassemblyMaximumSymbolWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyMaximumSymbolWidth(BNDisassemblySettings* settings, size_t width);
	BINARYNINJACOREAPI size_t BNGetDisassemblyGutterWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyGutterWidth(BNDisassemblySettings* settings, size_t width);
	BINARYNINJACOREAPI BNDisassemblyAddressMode BNGetDisassemblyAddressMode(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyAddressMode(BNDisassemblySettings* settings, BNDisassemblyAddressMode mode);
	BINARYNINJACOREAPI uint64_t BNGetDisassemblyAddressBaseOffset(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyAddressBaseOffset(BNDisassemblySettings* settings, uint64_t addressBaseOffset);
	BINARYNINJACOREAPI BNDisassemblyCallParameterHints BNGetDisassemblyCallParameterHints(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyCallParameterHints(BNDisassemblySettings* settings, BNDisassemblyCallParameterHints hints);

	// Flow graphs
	BINARYNINJACOREAPI BNFlowGraph* BNCreateFlowGraph(void);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateFunctionGraph(
	    BNFunction* func, BNFunctionGraphType type, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateLowLevelILFunctionGraph(
	    BNLowLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateMediumLevelILFunctionGraph(
	    BNMediumLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateHighLevelILFunctionGraph(
	    BNHighLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateCustomFlowGraph(BNCustomFlowGraph* callbacks);
	BINARYNINJACOREAPI BNFlowGraph* BNNewFlowGraphReference(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNFreeFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNFunction* BNGetFunctionForFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetFunctionForFlowGraph(BNFlowGraph* graph, BNFunction* func);
	BINARYNINJACOREAPI BNBinaryView* BNGetViewForFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetViewForFlowGraph(BNFlowGraph* graph, BNBinaryView* view);

	BINARYNINJACOREAPI int BNGetHorizontalFlowGraphNodeMargin(BNFlowGraph* graph);
	BINARYNINJACOREAPI int BNGetVerticalFlowGraphNodeMargin(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetFlowGraphNodeMargins(BNFlowGraph* graph, int horiz, int vert);

	BINARYNINJACOREAPI BNFlowGraphLayoutRequest* BNStartFlowGraphLayout(
	    BNFlowGraph* graph, void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI bool BNIsFlowGraphLayoutComplete(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNFlowGraphLayoutRequest* BNNewFlowGraphLayoutRequestReference(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI void BNFreeFlowGraphLayoutRequest(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI bool BNIsFlowGraphLayoutRequestComplete(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI BNFlowGraph* BNGetGraphForFlowGraphLayoutRequest(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI void BNAbortFlowGraphLayoutRequest(BNFlowGraphLayoutRequest* graph);
	BINARYNINJACOREAPI bool BNIsILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNIsLowLevelILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNIsMediumLevelILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNIsHighLevelILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFlowGraphLowLevelILFunction(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFlowGraphMediumLevelILFunction(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetFlowGraphHighLevelILFunction(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetFlowGraphLowLevelILFunction(BNFlowGraph* graph, BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNSetFlowGraphMediumLevelILFunction(BNFlowGraph* graph, BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNSetFlowGraphHighLevelILFunction(BNFlowGraph* graph, BNHighLevelILFunction* func);

	BINARYNINJACOREAPI BNFlowGraphNode** BNGetFlowGraphNodes(BNFlowGraph* graph, size_t* count);
	BINARYNINJACOREAPI BNFlowGraphNode* BNGetFlowGraphNode(BNFlowGraph* graph, size_t i);
	BINARYNINJACOREAPI BNFlowGraphNode** BNGetFlowGraphNodesInRegion(
	    BNFlowGraph* graph, int left, int top, int right, int bottom, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlowGraphNodeList(BNFlowGraphNode** nodes, size_t count);
	BINARYNINJACOREAPI bool BNFlowGraphHasNodes(BNFlowGraph* graph);
	BINARYNINJACOREAPI size_t BNAddFlowGraphNode(BNFlowGraph* graph, BNFlowGraphNode* node);

	BINARYNINJACOREAPI int BNGetFlowGraphWidth(BNFlowGraph* graph);
	BINARYNINJACOREAPI int BNGetFlowGraphHeight(BNFlowGraph* graph);

	BINARYNINJACOREAPI BNFlowGraphNode* BNCreateFlowGraphNode(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNFlowGraphNode* BNNewFlowGraphNodeReference(BNFlowGraphNode* node);
	BINARYNINJACOREAPI void BNFreeFlowGraphNode(BNFlowGraphNode* node);
	BINARYNINJACOREAPI BNFlowGraph* BNGetFlowGraphNodeOwner(BNFlowGraphNode* node);

	BINARYNINJACOREAPI BNBasicBlock* BNGetFlowGraphBasicBlock(BNFlowGraphNode* node);
	BINARYNINJACOREAPI void BNSetFlowGraphBasicBlock(BNFlowGraphNode* node, BNBasicBlock* block);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeX(BNFlowGraphNode* node);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeY(BNFlowGraphNode* node);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeWidth(BNFlowGraphNode* node);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeHeight(BNFlowGraphNode* node);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetFlowGraphNodeLines(BNFlowGraphNode* node, size_t* count);
	BINARYNINJACOREAPI void BNSetFlowGraphNodeLines(BNFlowGraphNode* node, BNDisassemblyTextLine* lines, size_t count);
	BINARYNINJACOREAPI BNFlowGraphEdge* BNGetFlowGraphNodeOutgoingEdges(BNFlowGraphNode* node, size_t* count);
	BINARYNINJACOREAPI BNFlowGraphEdge* BNGetFlowGraphNodeIncomingEdges(BNFlowGraphNode* node, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlowGraphNodeEdgeList(BNFlowGraphEdge* edges, size_t count);
	BINARYNINJACOREAPI void BNAddFlowGraphNodeOutgoingEdge(
	    BNFlowGraphNode* node, BNBranchType type, BNFlowGraphNode* target, BNEdgeStyle edgeStyle);

	BINARYNINJACOREAPI BNHighlightColor BNGetFlowGraphNodeHighlight(BNFlowGraphNode* node);
	BINARYNINJACOREAPI void BNSetFlowGraphNodeHighlight(BNFlowGraphNode* node, BNHighlightColor color);

	BINARYNINJACOREAPI void BNFinishPrepareForLayout(BNFlowGraph* graph);

	BINARYNINJACOREAPI bool BNFlowGraphUpdateQueryMode(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNFlowGraphHasUpdates(BNFlowGraph* graph);

	BINARYNINJACOREAPI BNFlowGraph* BNUpdateFlowGraph(BNFlowGraph* graph);

	BINARYNINJACOREAPI void BNSetFlowGraphOption(BNFlowGraph* graph, BNFlowGraphOption option, bool value);
	BINARYNINJACOREAPI bool BNIsFlowGraphOptionSet(BNFlowGraph* graph, BNFlowGraphOption option);

	BINARYNINJACOREAPI bool BNIsNodeValidForFlowGraph(BNFlowGraph* graph, BNFlowGraphNode* node);

	// Symbols
	BINARYNINJACOREAPI BNSymbol* BNCreateSymbol(BNSymbolType type, const char* shortName, const char* fullName,
	    const char* rawName, uint64_t addr, BNSymbolBinding binding, const BNNameSpace* nameSpace, uint64_t ordinal);
	BINARYNINJACOREAPI BNSymbol* BNNewSymbolReference(BNSymbol* sym);
	BINARYNINJACOREAPI void BNFreeSymbol(BNSymbol* sym);
	BINARYNINJACOREAPI BNSymbolType BNGetSymbolType(BNSymbol* sym);
	BINARYNINJACOREAPI BNSymbolBinding BNGetSymbolBinding(BNSymbol* sym);
	BINARYNINJACOREAPI BNNameSpace BNGetSymbolNameSpace(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolShortName(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolFullName(BNSymbol* sym);
	BINARYNINJACOREAPI char* BNGetSymbolRawName(BNSymbol* sym);
	BINARYNINJACOREAPI void* BNGetSymbolRawBytes(BNSymbol* sym, size_t* count);
	BINARYNINJACOREAPI void BNFreeSymbolRawBytes(void* bytes);

	BINARYNINJACOREAPI uint64_t BNGetSymbolAddress(BNSymbol* sym);
	BINARYNINJACOREAPI uint64_t BNGetSymbolOrdinal(BNSymbol* sym);
	BINARYNINJACOREAPI bool BNIsSymbolAutoDefined(BNSymbol* sym);

	BINARYNINJACOREAPI BNSymbol* BNGetSymbolByAddress(BNBinaryView* view, uint64_t addr, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol* BNGetSymbolByRawName(
	    BNBinaryView* view, const char* name, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsByName(
	    BNBinaryView* view, const char* name, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsByRawName(
	    BNBinaryView* view, const char* name, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbols(BNBinaryView* view, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t len, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsOfType(
	    BNBinaryView* view, BNSymbolType type, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI BNSymbol** BNGetSymbolsOfTypeInRange(BNBinaryView* view, BNSymbolType type, uint64_t start,
	    uint64_t len, size_t* count, const BNNameSpace* nameSpace);
	BINARYNINJACOREAPI void BNFreeSymbolList(BNSymbol** syms, size_t count);
	BINARYNINJACOREAPI BNSymbol** BNGetVisibleSymbols(BNBinaryView* view, size_t* count, const BNNameSpace* nameSpace);

	BINARYNINJACOREAPI void BNDefineAutoSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNUndefineAutoSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNDefineUserSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNUndefineUserSymbol(BNBinaryView* view, BNSymbol* sym);
	BINARYNINJACOREAPI void BNDefineImportedFunction(
	    BNBinaryView* view, BNSymbol* importAddressSym, BNFunction* func, BNType* type);
	BINARYNINJACOREAPI BNSymbol* BNDefineAutoSymbolAndVariableOrFunction(
	    BNBinaryView* view, BNPlatform* platform, BNSymbol* sym, BNType* type);
	BINARYNINJACOREAPI void BNBeginBulkModifySymbols(BNBinaryView* view);
	BINARYNINJACOREAPI void BNEndBulkModifySymbols(BNBinaryView* view);

	BINARYNINJACOREAPI BNDebugInfo* BNGetDebugInfo(BNBinaryView* view);
	BINARYNINJACOREAPI void BNApplyDebugInfo(BNBinaryView* view, BNDebugInfo* newDebugInfo);
	BINARYNINJACOREAPI void BNSetDebugInfo(BNBinaryView* view, BNDebugInfo* newDebugInfo);
	BINARYNINJACOREAPI bool BNIsApplyingDebugInfo(BNBinaryView* view);

	BINARYNINJACOREAPI BNSymbol* BNImportedFunctionFromImportAddressSymbol(BNSymbol* sym, uint64_t addr);

	// Low-level IL
	BINARYNINJACOREAPI BNLowLevelILFunction* BNCreateLowLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNNewLowLevelILFunctionReference(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeLowLevelILFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetLowLevelILOwnerFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNLowLevelILGetCurrentAddress(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNLowLevelILSetCurrentAddress(
	    BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNLowLevelILSetCurrentSourceBlock(BNLowLevelILFunction* func, BNBasicBlock* source);
	BINARYNINJACOREAPI size_t BNLowLevelILGetInstructionStart(
	    BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNLowLevelILClearIndirectBranches(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNLowLevelILSetIndirectBranches(
	    BNLowLevelILFunction* func, BNArchitectureAndAddress* branches, size_t count);
	BINARYNINJACOREAPI size_t BNLowLevelILAddExpr(BNLowLevelILFunction* func, BNLowLevelILOperation operation,
	    size_t size, uint32_t flags, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
	BINARYNINJACOREAPI size_t BNLowLevelILAddExprWithLocation(BNLowLevelILFunction* func, uint64_t addr,
	    uint32_t sourceOperand, BNLowLevelILOperation operation, size_t size, uint32_t flags, uint64_t a, uint64_t b,
	    uint64_t c, uint64_t d);
	BINARYNINJACOREAPI void BNLowLevelILSetExprSourceOperand(BNLowLevelILFunction* func, size_t expr, uint32_t operand);
	BINARYNINJACOREAPI size_t BNLowLevelILAddInstruction(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNLowLevelILGoto(BNLowLevelILFunction* func, BNLowLevelILLabel* label);
	BINARYNINJACOREAPI size_t BNLowLevelILGotoWithLocation(
	    BNLowLevelILFunction* func, BNLowLevelILLabel* label, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI size_t BNLowLevelILIf(
	    BNLowLevelILFunction* func, uint64_t op, BNLowLevelILLabel* t, BNLowLevelILLabel* f);
	BINARYNINJACOREAPI size_t BNLowLevelILIfWithLocation(BNLowLevelILFunction* func, uint64_t op, BNLowLevelILLabel* t,
	    BNLowLevelILLabel* f, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI void BNLowLevelILInitLabel(BNLowLevelILLabel* label);
	BINARYNINJACOREAPI void BNLowLevelILMarkLabel(BNLowLevelILFunction* func, BNLowLevelILLabel* label);
	BINARYNINJACOREAPI void BNFinalizeLowLevelILFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateLowLevelILSSAForm(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI void BNPrepareToCopyLowLevelILFunction(BNLowLevelILFunction* func, BNLowLevelILFunction* src);
	BINARYNINJACOREAPI void BNPrepareToCopyLowLevelILBasicBlock(BNLowLevelILFunction* func, BNBasicBlock* block);
	BINARYNINJACOREAPI BNLowLevelILLabel* BNGetLabelForLowLevelILSourceInstruction(
	    BNLowLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNLowLevelILAddLabelMap(
	    BNLowLevelILFunction* func, uint64_t* values, BNLowLevelILLabel** labels, size_t count);
	BINARYNINJACOREAPI size_t BNLowLevelILAddOperandList(BNLowLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNLowLevelILGetOperandList(
	    BNLowLevelILFunction* func, size_t expr, size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNLowLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNLowLevelILInstruction BNGetLowLevelILByIndex(BNLowLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetLowLevelILIndexForInstruction(BNLowLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionForExpr(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionCount(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILExprCount(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI void BNUpdateLowLevelILOperand(
	    BNLowLevelILFunction* func, size_t instr, size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNReplaceLowLevelILExpr(BNLowLevelILFunction* func, size_t expr, size_t newExpr);
	BINARYNINJACOREAPI void BNSetLowLevelILExprAttributes(BNLowLevelILFunction* func, size_t expr, uint32_t attributes);

	BINARYNINJACOREAPI void BNAddLowLevelILLabelForAddress(
	    BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNLowLevelILLabel* BNGetLowLevelILLabelForAddress(
	    BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNGetLowLevelILExprText(
	    BNLowLevelILFunction* func, BNArchitecture* arch, size_t i, BNDisassemblySettings* settings,
	    BNInstructionTextToken** tokens, size_t* count);
	BINARYNINJACOREAPI bool BNGetLowLevelILInstructionText(BNLowLevelILFunction* il, BNFunction* func,
	    BNArchitecture* arch, size_t i, BNDisassemblySettings* settings, BNInstructionTextToken** tokens, size_t* count);

	BINARYNINJACOREAPI uint32_t BNGetLowLevelILTemporaryRegisterCount(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI uint32_t BNGetLowLevelILTemporaryFlagCount(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI BNBasicBlock** BNGetLowLevelILBasicBlockList(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetLowLevelILBasicBlockForInstruction(BNLowLevelILFunction* func, size_t i);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILSSAForm(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILNonSSAForm(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILNonSSAInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAExprIndex(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILNonSSAExprIndex(BNLowLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetLowLevelILSSARegisterDefinition(
	    BNLowLevelILFunction* func, uint32_t reg, size_t version);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAFlagDefinition(
	    BNLowLevelILFunction* func, uint32_t reg, size_t version);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAMemoryDefinition(BNLowLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSARegisterUses(
	    BNLowLevelILFunction* func, uint32_t reg, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSAFlagUses(
	    BNLowLevelILFunction* func, uint32_t reg, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSAMemoryUses(BNLowLevelILFunction* func, size_t version, size_t* count);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILSSARegisterValue(
	    BNLowLevelILFunction* func, uint32_t reg, size_t version);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILSSAFlagValue(
	    BNLowLevelILFunction* func, uint32_t flag, size_t version);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILExprValue(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleExprValues(
	    BNLowLevelILFunction* func, size_t expr, BNDataFlowQueryOption* options, size_t optionCount);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILRegisterValueAtInstruction(
	    BNLowLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILRegisterValueAfterInstruction(
	    BNLowLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleRegisterValuesAtInstruction(
	    BNLowLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleRegisterValuesAfterInstruction(
	    BNLowLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILFlagValueAtInstruction(
	    BNLowLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILFlagValueAfterInstruction(
	    BNLowLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleFlagValuesAtInstruction(
	    BNLowLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleFlagValuesAfterInstruction(
	    BNLowLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILStackContentsAtInstruction(
	    BNLowLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILStackContentsAfterInstruction(
	    BNLowLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleStackContentsAtInstruction(BNLowLevelILFunction* func,
	    int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleStackContentsAfterInstruction(
	    BNLowLevelILFunction* func, int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options,
	    size_t optionCount);

	BINARYNINJACOREAPI uint32_t* BNGetLowLevelRegisters(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetLowLevelRegisterStacks(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetLowLevelFlags(BNLowLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI uint32_t* BNGetLowLevelSSARegistersWithoutVersions(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetLowLevelSSARegisterStacksWithoutVersions(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetLowLevelSSAFlagsWithoutVersions(BNLowLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetLowLevelRegisterSSAVersions(
	    BNLowLevelILFunction* func, const uint32_t var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelRegisterStackSSAVersions(
	    BNLowLevelILFunction* func, const uint32_t var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelFlagSSAVersions(
	    BNLowLevelILFunction* func, const uint32_t var, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetLowLevelMemoryVersions(BNLowLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI void BNFreeLLILVariablesList(uint32_t* vars);
	BINARYNINJACOREAPI void BNFreeLLILVariableVersionList(size_t* versions);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILForLowLevelIL(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMappedMediumLevelIL(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprIndex(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILExprIndexes(BNLowLevelILFunction* func, size_t expr, size_t* count);
	BINARYNINJACOREAPI size_t BNGetMappedMediumLevelILInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMappedMediumLevelILExprIndex(BNLowLevelILFunction* func, size_t expr);

	// Medium-level IL
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNCreateMediumLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNNewMediumLevelILFunctionReference(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeMediumLevelILFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetMediumLevelILOwnerFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNMediumLevelILGetCurrentAddress(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNMediumLevelILSetCurrentAddress(
	    BNMediumLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNMediumLevelILGetInstructionStart(
	    BNMediumLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddExpr(BNMediumLevelILFunction* func, BNMediumLevelILOperation operation,
	    size_t size, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddExprWithLocation(BNMediumLevelILFunction* func,
	    BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size, uint64_t a, uint64_t b,
	    uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddInstruction(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNMediumLevelILGoto(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI size_t BNMediumLevelILGotoWithLocation(
	    BNMediumLevelILFunction* func, BNMediumLevelILLabel* label, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI size_t BNMediumLevelILIf(
	    BNMediumLevelILFunction* func, uint64_t op, BNMediumLevelILLabel* t, BNMediumLevelILLabel* f);
	BINARYNINJACOREAPI size_t BNMediumLevelILIfWithLocation(BNMediumLevelILFunction* func, uint64_t op,
	    BNMediumLevelILLabel* t, BNMediumLevelILLabel* f, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI void BNMediumLevelILInitLabel(BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI void BNMediumLevelILMarkLabel(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI void BNFinalizeMediumLevelILFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateMediumLevelILSSAForm(BNMediumLevelILFunction* func, bool analyzeConditionals,
	    bool handleAliases, BNVariable* knownNotAliases, size_t knownNotAliasCount, BNVariable* knownAliases,
	    size_t knownAliasCount);

	BINARYNINJACOREAPI void BNPrepareToCopyMediumLevelILFunction(
	    BNMediumLevelILFunction* func, BNMediumLevelILFunction* src);
	BINARYNINJACOREAPI void BNPrepareToCopyMediumLevelILBasicBlock(BNMediumLevelILFunction* func, BNBasicBlock* block);
	BINARYNINJACOREAPI BNMediumLevelILLabel* BNGetLabelForMediumLevelILSourceInstruction(
	    BNMediumLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNMediumLevelILAddLabelMap(
	    BNMediumLevelILFunction* func, uint64_t* values, BNMediumLevelILLabel** labels, size_t count);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddOperandList(
	    BNMediumLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNMediumLevelILGetOperandList(
	    BNMediumLevelILFunction* func, size_t expr, size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNMediumLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNMediumLevelILInstruction BNGetMediumLevelILByIndex(BNMediumLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILIndexForInstruction(BNMediumLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionForExpr(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionCount(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprCount(BNMediumLevelILFunction* func);

	BINARYNINJACOREAPI void BNUpdateMediumLevelILOperand(
	    BNMediumLevelILFunction* func, size_t instr, size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNMarkMediumLevelILInstructionForRemoval(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI void BNReplaceMediumLevelILInstruction(BNMediumLevelILFunction* func, size_t instr, size_t expr);
	BINARYNINJACOREAPI void BNReplaceMediumLevelILExpr(BNMediumLevelILFunction* func, size_t expr, size_t newExpr);
	BINARYNINJACOREAPI void BNSetMediumLevelILExprAttributes(BNMediumLevelILFunction* func, size_t expr, uint32_t attributes);

	BINARYNINJACOREAPI bool BNGetMediumLevelILExprText(BNMediumLevelILFunction* func, BNArchitecture* arch, size_t i,
	    BNInstructionTextToken** tokens, size_t* count, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI bool BNGetMediumLevelILInstructionText(BNMediumLevelILFunction* il, BNFunction* func,
	    BNArchitecture* arch, size_t i, BNInstructionTextToken** tokens, size_t* count,
	    BNDisassemblySettings* settings);

	BINARYNINJACOREAPI BNBasicBlock** BNGetMediumLevelILBasicBlockList(BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetMediumLevelILBasicBlockForInstruction(
	    BNMediumLevelILFunction* func, size_t i);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILSSAForm(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILNonSSAForm(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILNonSSAInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILNonSSAExprIndex(BNMediumLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAVarDefinition(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAMemoryDefinition(BNMediumLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILSSAVarUses(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILSSAMemoryUses(
	    BNMediumLevelILFunction* func, size_t version, size_t* count);
	BINARYNINJACOREAPI bool BNIsMediumLevelILSSAVarLive(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI bool BNIsMediumLevelILSSAVarLiveAt(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t version, const size_t instr);
	BINARYNINJACOREAPI bool BNIsMediumLevelILVarLiveAt(
	    BNMediumLevelILFunction* func, const BNVariable* var, const size_t instr);

	BINARYNINJACOREAPI BNVariable* BNGetMediumLevelILVariables(BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNVariable* BNGetMediumLevelILAliasedVariables(BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableSSAVersions(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableDefinitions(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableUses(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILLiveInstructionsForVariable(
		BNMediumLevelILFunction* func, const BNVariable* var, bool includeLastUse, size_t* count);
	BINARYNINJACOREAPI uint32_t BNGetDefaultIndexForMediumLevelILVariableDefinition(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t instrIndex);

	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILSSAVarValue(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILExprValue(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleSSAVarValues(BNMediumLevelILFunction* func,
	    const BNVariable* var, size_t version, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleExprValues(
	    BNMediumLevelILFunction* func, size_t expr, BNDataFlowQueryOption* options, size_t optionCount);

	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAVarVersionAtILInstruction(
	    BNMediumLevelILFunction* func, const BNVariable* var, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAMemoryVersionAtILInstruction(
	    BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForRegisterAtInstruction(
	    BNMediumLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForFlagAtInstruction(
	    BNMediumLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForStackLocationAtInstruction(
	    BNMediumLevelILFunction* func, int64_t offset, size_t instr);

	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILRegisterValueAtInstruction(
	    BNMediumLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILRegisterValueAfterInstruction(
	    BNMediumLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleRegisterValuesAtInstruction(
	    BNMediumLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(
	    BNMediumLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILFlagValueAtInstruction(
	    BNMediumLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILFlagValueAfterInstruction(
	    BNMediumLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleFlagValuesAtInstruction(
	    BNMediumLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleFlagValuesAfterInstruction(
	    BNMediumLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILStackContentsAtInstruction(
	    BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILStackContentsAfterInstruction(
	    BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleStackContentsAtInstruction(
	    BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options,
	    size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleStackContentsAfterInstruction(
	    BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options,
	    size_t optionCount);

	BINARYNINJACOREAPI BNILBranchDependence BNGetMediumLevelILBranchDependence(
	    BNMediumLevelILFunction* func, size_t curInstr, size_t branchInstr);
	BINARYNINJACOREAPI BNILBranchInstructionAndDependence* BNGetAllMediumLevelILBranchDependence(
	    BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreeILBranchDependenceList(BNILBranchInstructionAndDependence* branches);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILForMediumLevelIL(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILExprIndexes(BNMediumLevelILFunction* func, size_t expr, size_t* count);

	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetHighLevelILForMediumLevelIL(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetHighLevelILInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILExprIndexes(BNMediumLevelILFunction* func, size_t expr, size_t* count);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetMediumLevelILExprType(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI void BNSetMediumLevelILExprType(BNMediumLevelILFunction* func, size_t expr, BNTypeWithConfidence* type);

	// High-level IL
	BINARYNINJACOREAPI BNHighLevelILFunction* BNCreateHighLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNNewHighLevelILFunctionReference(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeHighLevelILFunction(BNHighLevelILFunction* func);

	BINARYNINJACOREAPI BNFunction* BNGetHighLevelILOwnerFunction(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNHighLevelILGetCurrentAddress(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNHighLevelILSetCurrentAddress(
	    BNHighLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNHighLevelILAddExpr(BNHighLevelILFunction* func, BNHighLevelILOperation operation,
	    size_t size, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNHighLevelILAddExprWithLocation(BNHighLevelILFunction* func,
	    BNHighLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size, uint64_t a, uint64_t b,
	    uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNGetHighLevelILRootExpr(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNSetHighLevelILRootExpr(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI void BNFinalizeHighLevelILFunction(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateHighLevelILSSAForm(BNHighLevelILFunction* func, BNVariable* aliases, size_t aliasCount);

	BINARYNINJACOREAPI size_t BNHighLevelILAddOperandList(
	    BNHighLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNHighLevelILGetOperandList(
	    BNHighLevelILFunction* func, size_t expr, size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNHighLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNHighLevelILInstruction BNGetHighLevelILByIndex(
	    BNHighLevelILFunction* func, size_t i, bool asFullAst);
	BINARYNINJACOREAPI size_t BNGetHighLevelILIndexForInstruction(BNHighLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetHighLevelILInstructionForExpr(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILInstructionCount(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetHighLevelILExprCount(BNHighLevelILFunction* func);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILForHighLevelILFunction(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprIndexFromHighLevelIL(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILExprIndexesFromHighLevelIL(
	    BNHighLevelILFunction* func, size_t expr, size_t* count);

	BINARYNINJACOREAPI void BNUpdateHighLevelILOperand(
	    BNHighLevelILFunction* func, size_t instr, size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNReplaceHighLevelILExpr(BNHighLevelILFunction* func, size_t expr, size_t newExpr);
	BINARYNINJACOREAPI void BNSetHighLevelILExprAttributes(BNHighLevelILFunction* func, size_t expr, uint32_t attributes);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetHighLevelILExprText(
	    BNHighLevelILFunction* func, size_t expr, bool asFullAst, size_t* count, BNDisassemblySettings* settings);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetHighLevelILExprType(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI void BNSetHighLevelILExprType(BNHighLevelILFunction* func, size_t expr, BNTypeWithConfidence* type);

	BINARYNINJACOREAPI BNBasicBlock** BNGetHighLevelILBasicBlockList(BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetHighLevelILBasicBlockForInstruction(BNHighLevelILFunction* func, size_t i);

	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetHighLevelILSSAForm(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetHighLevelILNonSSAForm(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAInstructionIndex(BNHighLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILNonSSAInstructionIndex(BNHighLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAExprIndex(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILNonSSAExprIndex(BNHighLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAVarDefinition(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAMemoryDefinition(BNHighLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILSSAVarUses(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILSSAMemoryUses(
	    BNHighLevelILFunction* func, size_t version, size_t* count);
	BINARYNINJACOREAPI bool BNIsHighLevelILSSAVarLive(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI bool BNIsHighLevelILSSAVarLiveAt(
	    BNHighLevelILFunction* func, const BNVariable* var, const size_t version, const size_t instr);
	BINARYNINJACOREAPI bool BNIsHighLevelILVarLiveAt(
	    BNHighLevelILFunction* func, const BNVariable* var, const size_t instr);

	BINARYNINJACOREAPI BNVariable* BNGetHighLevelILVariables(BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNVariable* BNGetHighLevelILAliasedVariables(BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILVariableSSAVersions(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetHighLevelILVariableDefinitions(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILVariableUses(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAVarVersionAtILInstruction(
	    BNHighLevelILFunction* func, const BNVariable* var, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAMemoryVersionAtILInstruction(
	    BNHighLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNGetHighLevelILExprIndexForLabel(BNHighLevelILFunction* func, uint64_t label);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILUsesForLabel(BNHighLevelILFunction* func, uint64_t label, size_t* count);

	BINARYNINJACOREAPI bool BNHighLevelILExprLessThan(
	    BNHighLevelILFunction* leftFunc, size_t leftExpr, BNHighLevelILFunction* rightFunc, size_t rightExpr);
	BINARYNINJACOREAPI bool BNHighLevelILExprEqual(
	    BNHighLevelILFunction* leftFunc, size_t leftExpr, BNHighLevelILFunction* rightFunc, size_t rightExpr);

	// Type Libraries
	BINARYNINJACOREAPI BNTypeLibrary* BNNewTypeLibrary(BNArchitecture* arch, const char* name);
	BINARYNINJACOREAPI BNTypeLibrary* BNNewTypeLibraryReference(BNTypeLibrary* lib);
	BINARYNINJACOREAPI BNTypeLibrary* BNDuplicateTypeLibrary(BNTypeLibrary* lib);
	BINARYNINJACOREAPI BNTypeLibrary* BNLoadTypeLibraryFromFile(const char* path);
	BINARYNINJACOREAPI bool BNTypeLibraryDecompressToFile(const char* file, const char* output);
	BINARYNINJACOREAPI void BNFreeTypeLibrary(BNTypeLibrary* lib);

	BINARYNINJACOREAPI BNTypeLibrary* BNLookupTypeLibraryByName(BNArchitecture* arch, const char* name);
	BINARYNINJACOREAPI BNTypeLibrary* BNLookupTypeLibraryByGuid(BNArchitecture* arch, const char* guid);

	BINARYNINJACOREAPI BNTypeLibrary** BNGetArchitectureTypeLibraries(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeLibraryList(BNTypeLibrary** lib, size_t count);

	BINARYNINJACOREAPI bool BNFinalizeTypeLibrary(BNTypeLibrary* lib);

	BINARYNINJACOREAPI BNArchitecture* BNGetTypeLibraryArchitecture(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNSetTypeLibraryName(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char* BNGetTypeLibraryName(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNAddTypeLibraryAlternateName(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char** BNGetTypeLibraryAlternateNames(BNTypeLibrary* lib, size_t* count);  // BNFreeStringList

	BINARYNINJACOREAPI void BNSetTypeLibraryDependencyName(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char* BNGetTypeLibraryDependencyName(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNSetTypeLibraryGuid(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char* BNGetTypeLibraryGuid(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNClearTypeLibraryPlatforms(BNTypeLibrary* lib);
	BINARYNINJACOREAPI void BNAddTypeLibraryPlatform(BNTypeLibrary* lib, BNPlatform* platform);
	BINARYNINJACOREAPI char** BNGetTypeLibraryPlatforms(BNTypeLibrary* lib, size_t* count);  // BNFreeStringList

	BINARYNINJACOREAPI void BNTypeLibraryStoreMetadata(BNTypeLibrary* lib, const char* key, BNMetadata* value);
	BINARYNINJACOREAPI BNMetadata* BNTypeLibraryQueryMetadata(BNTypeLibrary* lib, const char* key);
	BINARYNINJACOREAPI BNMetadata* BNTypeLibraryGetMetadata(BNTypeLibrary* lib);
	BINARYNINJACOREAPI void BNTypeLibraryRemoveMetadata(BNTypeLibrary* lib, const char* key);

	BINARYNINJACOREAPI BNTypeContainer* BNGetTypeLibraryTypeContainer(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNAddTypeLibraryNamedObject(BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNAddTypeLibraryNamedType(BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNAddTypeLibraryNamedTypeSource(BNTypeLibrary* lib, BNQualifiedName* name, const char* source);

	BINARYNINJACOREAPI BNType* BNGetTypeLibraryNamedObject(BNTypeLibrary* lib, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetTypeLibraryNamedType(BNTypeLibrary* lib, BNQualifiedName* name);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetTypeLibraryNamedObjects(BNTypeLibrary* lib, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetTypeLibraryNamedTypes(BNTypeLibrary* lib, size_t* count);

	BINARYNINJACOREAPI bool BNWriteTypeLibraryToFile(BNTypeLibrary* lib, const char* path);

	BINARYNINJACOREAPI void BNAddBinaryViewTypeLibrary(BNBinaryView* view, BNTypeLibrary* lib);
	BINARYNINJACOREAPI BNTypeLibrary* BNGetBinaryViewTypeLibrary(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNTypeLibrary** BNGetBinaryViewTypeLibraries(BNBinaryView* view, size_t* count);

	BINARYNINJACOREAPI BNType* BNBinaryViewImportTypeLibraryType(
	    BNBinaryView* view, BNTypeLibrary** lib, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNBinaryViewImportTypeLibraryObject(
	    BNBinaryView* view, BNTypeLibrary** lib, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNBinaryViewImportTypeLibraryTypeByGuid(
		BNBinaryView* view, const char* guid);
	BINARYNINJACOREAPI BNQualifiedName BNBinaryViewGetTypeNameByGuid(
		BNBinaryView* view, const char* guid);

	BINARYNINJACOREAPI void BNBinaryViewExportTypeToTypeLibrary(
	    BNBinaryView* view, BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNBinaryViewExportObjectToTypeLibrary(
	    BNBinaryView* view, BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);

	BINARYNINJACOREAPI void BNBinaryViewSetManualDependencies(BNBinaryView* view,
			BNQualifiedName* viewTypeNames, BNQualifiedName* libTypeNames, char** libNames, size_t count);

	BINARYNINJACOREAPI void BNBinaryViewRecordImportedObjectLibrary(
		BNBinaryView* view, BNPlatform* tgtPlatform, uint64_t tgtAddr, BNTypeLibrary* lib, BNQualifiedName* name);
	BINARYNINJACOREAPI bool BNBinaryViewLookupImportedObjectLibrary(
		BNBinaryView* view, BNPlatform* tgtPlatform, uint64_t tgtAddr, BNTypeLibrary** lib, BNQualifiedName* name);
	BINARYNINJACOREAPI bool BNBinaryViewLookupImportedTypeLibrary(
		BNBinaryView* view, const BNQualifiedName* typeName, BNTypeLibrary** lib, BNQualifiedName* resultName);

	// Language Representation
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNCreateLanguageRepresentationFunction(
	    BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNNewLanguageRepresentationFunctionReference(
	    BNLanguageRepresentationFunction* func);
	BINARYNINJACOREAPI void BNFreeLanguageRepresentationFunction(BNLanguageRepresentationFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetLanguageRepresentationOwnerFunction(BNLanguageRepresentationFunction* func);

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
	    BNRegisterSetWithConfidence* returnRegs, BNNameType ft, BNBoolWithConfidence* pure);
	BINARYNINJACOREAPI BNType* BNNewTypeReference(BNType* type);
	BINARYNINJACOREAPI BNType* BNDuplicateType(BNType* type);
	BINARYNINJACOREAPI char* BNGetTypeAndName(BNType* type, BNQualifiedName* name, BNTokenEscapingType escaping);
	BINARYNINJACOREAPI void BNFreeType(BNType* type);
	BINARYNINJACOREAPI void BNFreeTypeList(BNType** types, size_t count);

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
		BNRegisterSetWithConfidence* returnRegs, BNNameType ft, BNBoolWithConfidence* pure);
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
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypePure(BNType* type);
	BINARYNINJACOREAPI BNStructure* BNGetTypeStructure(BNType* type);
	BINARYNINJACOREAPI BNEnumeration* BNGetTypeEnumeration(BNType* type);
	BINARYNINJACOREAPI BNNamedTypeReference* BNGetTypeNamedTypeReference(BNType* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeElementCount(BNType* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeOffset(BNType* type);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetTypeStackAdjustment(BNType* type);
	BINARYNINJACOREAPI BNQualifiedName BNTypeGetStructureName(BNType* type);
	BINARYNINJACOREAPI BNNamedTypeReference* BNGetRegisteredTypeName(BNType* type);
	BINARYNINJACOREAPI BNReferenceType BNTypeGetReferenceType(BNType* type);
	BINARYNINJACOREAPI BNPointerBaseType BNTypeGetPointerBaseType(BNType* type);
	BINARYNINJACOREAPI int64_t BNTypeGetPointerBaseOffset(BNType* type);
	BINARYNINJACOREAPI char* BNGetTypeAlternateName(BNType* type);
	BINARYNINJACOREAPI uint32_t BNTypeGetSystemCallNumber(BNType* type);
	BINARYNINJACOREAPI bool BNTypeIsSystemCall(BNType* type);
	BINARYNINJACOREAPI BNPointerSuffix* BNGetTypePointerSuffix(BNType* type, size_t* count);
	BINARYNINJACOREAPI char* BNGetTypePointerSuffixString(BNType* type);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypePointerSuffixTokens(BNType* type, uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI void BNFreePointerSuffixList(BNPointerSuffix* suffix, size_t count);

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
	BINARYNINJACOREAPI BNTypeDefinitionLine* BNGetTypeLines(BNType* type, BNTypeContainer* types, const char* name, int paddingCols, bool collapsed, BNTokenEscapingType escaping, size_t* count);
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
	BINARYNINJACOREAPI BNBoolWithConfidence BNIsTypeBuilderPure(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNStructure* BNGetTypeBuilderStructure(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNEnumeration* BNGetTypeBuilderEnumeration(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNNamedTypeReference* BNGetTypeBuilderNamedTypeReference(BNTypeBuilder* type);
	BINARYNINJACOREAPI void BNSetTypeBuilderNamedTypeReference(BNTypeBuilder* type, BNNamedTypeReference* ntr);
	BINARYNINJACOREAPI uint64_t BNGetTypeBuilderElementCount(BNTypeBuilder* type);
	BINARYNINJACOREAPI uint64_t BNGetTypeBuilderOffset(BNTypeBuilder* type);
	BINARYNINJACOREAPI void BNSetTypeBuilderOffset(BNTypeBuilder* type, uint64_t offset);
	BINARYNINJACOREAPI void BNSetTypeBuilderPointerBase(BNTypeBuilder* type, BNPointerBaseType baseType, int64_t baseOffset);
	BINARYNINJACOREAPI void BNSetFunctionTypeBuilderCanReturn(BNTypeBuilder* type, BNBoolWithConfidence* canReturn);
	BINARYNINJACOREAPI void BNSetTypeBuilderPure(BNTypeBuilder* type, BNBoolWithConfidence* pure);
	BINARYNINJACOREAPI void BNSetFunctionTypeBuilderParameters(
	    BNTypeBuilder* type, BNFunctionParameter* params, size_t paramCount);
	BINARYNINJACOREAPI void BNTypeBuilderSetWidth(BNTypeBuilder* type, size_t width);
	BINARYNINJACOREAPI void BNTypeBuilderSetAlignment(BNTypeBuilder* type, size_t alignment);
	BINARYNINJACOREAPI void BNTypeBuilderSetConst(BNTypeBuilder* type, BNBoolWithConfidence* cnst);
	BINARYNINJACOREAPI void BNTypeBuilderSetVolatile(BNTypeBuilder* type, BNBoolWithConfidence* vltl);
	BINARYNINJACOREAPI void BNTypeBuilderSetSigned(BNTypeBuilder* type, BNBoolWithConfidence* sign);
	BINARYNINJACOREAPI void BNTypeBuilderSetChildType(BNTypeBuilder* type, BNTypeWithConfidence* child);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetTypeBuilderStackAdjustment(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNQualifiedName BNTypeBuilderGetStructureName(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNReferenceType BNTypeBuilderGetReferenceType(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNPointerBaseType BNTypeBuilderGetPointerBaseType(BNTypeBuilder* type);
	BINARYNINJACOREAPI int64_t BNTypeBuilderGetPointerBaseOffset(BNTypeBuilder* type);
	BINARYNINJACOREAPI char* BNGetTypeBuilderAlternateName(BNTypeBuilder* type);
	BINARYNINJACOREAPI bool BNTypeBuilderIsSystemCall(BNTypeBuilder* type);
	BINARYNINJACOREAPI uint32_t BNTypeBuilderGetSystemCallNumber(BNTypeBuilder* type);
	BINARYNINJACOREAPI void BNTypeBuilderSetStackAdjustment(BNTypeBuilder* type, BNOffsetWithConfidence* adjust);
	BINARYNINJACOREAPI BNPointerSuffix* BNGetTypeBuilderPointerSuffix(BNTypeBuilder* type, size_t* count);
	BINARYNINJACOREAPI char* BNGetTypeBuilderPointerSuffixString(BNTypeBuilder* type);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetTypeBuilderPointerSuffixTokens(BNTypeBuilder* type, uint8_t baseConfidence, size_t* count);
	BINARYNINJACOREAPI void BNAddTypeBuilderPointerSuffix(BNTypeBuilder* type, BNPointerSuffix ps);
	BINARYNINJACOREAPI void BNSetTypeBuilderPointerSuffix(BNTypeBuilder* type, BNPointerSuffix* suffix, size_t count);

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
	BINARYNINJACOREAPI void BNFreeQualifiedNameArray(BNQualifiedName* names, size_t count);
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
	BINARYNINJACOREAPI BNInheritedStructureMember* BNGetStructureMembersIncludingInherited(
		BNStructure* s, BNTypeContainer* types, size_t* count);
	BINARYNINJACOREAPI void BNFreeInheritedStructureMemberList(BNInheritedStructureMember* members, size_t count);
	BINARYNINJACOREAPI BNInheritedStructureMember* BNGetMemberIncludingInheritedAtOffset(BNStructure* s,
		BNBinaryView* view, int64_t offset);
	BINARYNINJACOREAPI void BNFreeInheritedStructureMember(BNInheritedStructureMember* members);
	BINARYNINJACOREAPI uint64_t BNGetStructureWidth(BNStructure* s);
	BINARYNINJACOREAPI int64_t BNGetStructurePointerOffset(BNStructure* s);
	BINARYNINJACOREAPI size_t BNGetStructureAlignment(BNStructure* s);
	BINARYNINJACOREAPI bool BNIsStructurePacked(BNStructure* s);
	BINARYNINJACOREAPI bool BNIsStructureUnion(BNStructure* s);
	BINARYNINJACOREAPI bool BNStructurePropagatesDataVariableReferences(BNStructure* s);
	BINARYNINJACOREAPI BNStructureVariant BNGetStructureType(BNStructure* s);
	BINARYNINJACOREAPI BNBaseStructure* BNGetBaseStructuresForStructure(BNStructure* s, size_t* count);
	BINARYNINJACOREAPI void BNFreeBaseStructureList(BNBaseStructure* bases, size_t count);

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
	BINARYNINJACOREAPI int64_t BNGetStructureBuilderPointerOffset(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderPointerOffset(BNStructureBuilder* s, int64_t offset);
	BINARYNINJACOREAPI size_t BNGetStructureBuilderAlignment(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderAlignment(BNStructureBuilder* s, size_t align);
	BINARYNINJACOREAPI bool BNIsStructureBuilderPacked(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderPacked(BNStructureBuilder* s, bool packed);
	BINARYNINJACOREAPI bool BNIsStructureBuilderUnion(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderType(BNStructureBuilder* s, BNStructureVariant type);
	BINARYNINJACOREAPI bool BNStructureBuilderPropagatesDataVariableReferences(BNStructureBuilder* s);
	BINARYNINJACOREAPI void BNSetStructureBuilderPropagatesDataVariableReferences(BNStructureBuilder* s, bool value);
	BINARYNINJACOREAPI BNStructureVariant BNGetStructureBuilderType(BNStructureBuilder* s);
	BINARYNINJACOREAPI BNBaseStructure* BNGetBaseStructuresForStructureBuilder(BNStructureBuilder* s, size_t* count);
	BINARYNINJACOREAPI void BNSetBaseStructuresForStructureBuilder(
		BNStructureBuilder* s, BNBaseStructure* bases, size_t count);

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
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetEnumerationTokensForValue(BNEnumeration* e, uint64_t value,
		uint64_t width, size_t* count, BNType* type);
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

	BINARYNINJACOREAPI void BNAddExpressionParserMagicValue(BNBinaryView* view, const char* name, uint64_t value);
	BINARYNINJACOREAPI void BNRemoveExpressionParserMagicValue(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI void BNAddExpressionParserMagicValues(BNBinaryView* view, const char** names, uint64_t* values,
		size_t count);
	BINARYNINJACOREAPI void BNRemoveExpressionParserMagicValues(BNBinaryView* view, const char** names, size_t count);
	BINARYNINJACOREAPI bool BNGetExpressionParserMagicValue(BNBinaryView* view, const char* name, uint64_t* value);

	BINARYNINJACOREAPI BNComponent** BNGetFunctionParentComponents(BNBinaryView* view, BNFunction *func, size_t* count);
	BINARYNINJACOREAPI BNComponent** BNGetDataVariableParentComponents(BNBinaryView* view, uint64_t dataVariable, size_t* count);
	BINARYNINJACOREAPI bool BNCheckForStringAnnotationType(BNBinaryView* view, uint64_t addr, char** value, BNStringType* strType,
		bool allowShortStrings, bool allowLargeStrings, size_t childWidth);

	BINARYNINJACOREAPI BNBinaryView* BNLoadFilename(const char* const filename, const bool updateAnalysis, const char* options, bool (*progress)(size_t, size_t));
	BINARYNINJACOREAPI BNBinaryView* BNLoadProjectFile(BNProjectFile* projectFile, const bool updateAnalysis, const char* options, bool (*progress)(size_t, size_t));
	BINARYNINJACOREAPI BNBinaryView* BNLoadBinaryView(BNBinaryView* view, const bool updateAnalysis, const char* options, bool (*progress)(size_t, size_t));

	BINARYNINJACOREAPI BNExternalLibrary* BNBinaryViewAddExternalLibrary(BNBinaryView* view, const char* name, BNProjectFile* backingFile, bool isAuto);
	BINARYNINJACOREAPI void BNBinaryViewRemoveExternalLibrary(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNExternalLibrary* BNBinaryViewGetExternalLibrary(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNExternalLibrary** BNBinaryViewGetExternalLibraries(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNExternalLocation* BNBinaryViewAddExternalLocation(BNBinaryView* view, BNSymbol* sourceSymbol, BNExternalLibrary* library, const char* targetSymbol, uint64_t* targetAddress, bool isAuto);
	BINARYNINJACOREAPI void BNBinaryViewRemoveExternalLocation(BNBinaryView* view, BNSymbol* sourceSymbol);
	BINARYNINJACOREAPI BNExternalLocation* BNBinaryViewGetExternalLocation(BNBinaryView* view, BNSymbol* sourceSymbol);
	BINARYNINJACOREAPI BNExternalLocation** BNBinaryViewGetExternalLocations(BNBinaryView* view, size_t* count);

	// Source code processing
	BINARYNINJACOREAPI bool BNPreprocessSource(const char* source, const char* fileName, char** output, char** errors,
	    const char** includeDirs, size_t includeDirCount);
	BINARYNINJACOREAPI bool BNParseTypesFromSource(BNPlatform* platform, const char* source, const char* fileName,
	    BNTypeParserResult* result, char** errors, const char** includeDirs, size_t includeDirCount,
	    const char* autoTypeSource);
	BINARYNINJACOREAPI bool BNParseTypesFromSourceFile(BNPlatform* platform, const char* fileName,
	    BNTypeParserResult* result, char** errors, const char** includeDirs, size_t includeDirCount,
	    const char* autoTypeSource);

	BINARYNINJACOREAPI BNTypeParser* BNRegisterTypeParser(
		const char* name, BNTypeParserCallbacks* callbacks);
	BINARYNINJACOREAPI BNTypeParser** BNGetTypeParserList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeParserList(BNTypeParser** parsers);
	BINARYNINJACOREAPI BNTypeParser* BNGetTypeParserByName(const char* name);
	BINARYNINJACOREAPI BNTypeParser* BNGetDefaultTypeParser(void);

	BINARYNINJACOREAPI char* BNGetTypeParserName(BNTypeParser* parser);

	BINARYNINJACOREAPI bool BNGetTypeParserOptionText(BNTypeParser* parser, BNTypeParserOption option,
	    const char* value, char** result);
	BINARYNINJACOREAPI bool BNTypeParserPreprocessSource(BNTypeParser* parser,
	    const char* source, const char* fileName, BNPlatform* platform,
	    BNTypeContainer* existingTypes,
	    const char* const* options, size_t optionCount,
	    const char* const* includeDirs, size_t includeDirCount,
	    char** output, BNTypeParserError** errors, size_t* errorCount
	);
	BINARYNINJACOREAPI bool BNTypeParserParseTypesFromSource(BNTypeParser* parser,
	    const char* source, const char* fileName, BNPlatform* platform,
	    BNTypeContainer* existingTypes,
	    const char* const* options, size_t optionCount,
	    const char* const* includeDirs, size_t includeDirCount,
	    const char* autoTypeSource, BNTypeParserResult* result,
	    BNTypeParserError** errors, size_t* errorCount
	);
	BINARYNINJACOREAPI bool BNTypeParserParseTypeString(BNTypeParser* parser,
	    const char* source, BNPlatform* platform,
	    BNTypeContainer* existingTypes,
	    BNQualifiedNameAndType* result,
	    BNTypeParserError** errors, size_t* errorCount
	);
	BINARYNINJACOREAPI char** BNParseTypeParserOptionsText(const char* optionsText, size_t* count);
	BINARYNINJACOREAPI char* BNFormatTypeParserParseErrors(BNTypeParserError* errors, size_t count);

	BINARYNINJACOREAPI BNTypePrinter* BNRegisterTypePrinter(
		const char* name, BNTypePrinterCallbacks* callbacks);
	BINARYNINJACOREAPI BNTypePrinter** BNGetTypePrinterList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTypePrinterList(BNTypePrinter** printers);
	BINARYNINJACOREAPI BNTypePrinter* BNGetTypePrinterByName(const char* name);

	BINARYNINJACOREAPI char* BNGetTypePrinterName(BNTypePrinter* printer);

	BINARYNINJACOREAPI bool BNGetTypePrinterTypeTokens(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNQualifiedName* name,
		uint8_t baseConfidence, BNTokenEscapingType escaping,
		BNInstructionTextToken** result, size_t* resultCount);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeTokensBeforeName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
		BNTokenEscapingType escaping, BNInstructionTextToken** result,
		size_t* resultCount);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeTokensAfterName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
		BNTokenEscapingType escaping, BNInstructionTextToken** result,
		size_t* resultCount);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeString(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNQualifiedName* name,
		BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeStringBeforeName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeStringAfterName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeLines(BNTypePrinter* printer,
		BNType* type, BNTypeContainer* types, BNQualifiedName* name,
		int paddingCols, bool collapsed, BNTokenEscapingType escaping,
		BNTypeDefinitionLine** result, size_t* resultCount);
	BINARYNINJACOREAPI bool BNTypePrinterPrintAllTypes(BNTypePrinter* printer, BNQualifiedName* names, BNType** types,
		size_t typeCount, BNBinaryView* data, int paddingCols, BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNTypePrinterDefaultPrintAllTypes(BNTypePrinter* printer, BNQualifiedName* names, BNType** types,
		size_t typeCount, BNBinaryView* data, int paddingCols, BNTokenEscapingType escaping, char** result);

	BINARYNINJACOREAPI void BNFreeTypeParserResult(BNTypeParserResult* result);
	BINARYNINJACOREAPI void BNFreeTypeParserErrors(BNTypeParserError* errors, size_t count);
	// Updates
	BINARYNINJACOREAPI BNUpdateChannel* BNGetUpdateChannels(size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelList(BNUpdateChannel* list, size_t count);
	BINARYNINJACOREAPI BNUpdateVersion* BNGetUpdateChannelVersions(const char* channel, size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelVersionList(BNUpdateVersion* list, size_t count);
	BINARYNINJACOREAPI BNUpdateChannelFullInfo* BNGetFullInfoUpdateChannels(size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeFullInfoUpdateChannels(BNUpdateChannelFullInfo* list, size_t count);

	BINARYNINJACOREAPI bool BNAreUpdatesAvailable(
	    const char* channel, uint64_t* expireTime, uint64_t* serverTime, char** errors);

	BINARYNINJACOREAPI BNUpdateResult BNUpdateToVersion(const char* channel, const char* version, char** errors,
	    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total), void* context);
	BINARYNINJACOREAPI BNUpdateResult BNUpdateToLatestVersion(const char* channel, char** errors,
	    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total), void* context);

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
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILInstruction(const char* name,
	    const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForHighLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForHighLevelILInstruction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr), void* context);

	BINARYNINJACOREAPI BNPluginCommand* BNGetAllPluginCommands(size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommands(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForFunction(
	    BNBinaryView* view, BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILFunction(
	    BNBinaryView* view, BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILInstruction(
	    BNBinaryView* view, BNLowLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILFunction(
	    BNBinaryView* view, BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILInstruction(
	    BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForHighLevelILFunction(
	    BNBinaryView* view, BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForHighLevelILInstruction(
	    BNBinaryView* view, BNHighLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreePluginCommandList(BNPluginCommand* commands);

	// Calling conventions
	BINARYNINJACOREAPI BNCallingConvention* BNCreateCallingConvention(
	    BNArchitecture* arch, const char* name, BNCustomCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI BNCallingConvention* BNNewCallingConventionReference(BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNFreeCallingConvention(BNCallingConvention* cc);

	BINARYNINJACOREAPI BNCallingConvention** BNGetArchitectureCallingConventions(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI void BNFreeCallingConventionList(BNCallingConvention** list, size_t count);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureCallingConventionByName(
	    BNArchitecture* arch, const char* name);

	BINARYNINJACOREAPI BNArchitecture* BNGetCallingConventionArchitecture(BNCallingConvention* cc);
	BINARYNINJACOREAPI char* BNGetCallingConventionName(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t* BNGetCallerSavedRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetCalleeSavedRegisters(BNCallingConvention* cc, size_t* count);

	BINARYNINJACOREAPI uint32_t* BNGetIntegerArgumentRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFloatArgumentRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI bool BNAreArgumentRegistersSharedIndex(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNAreArgumentRegistersUsedForVarArgs(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsStackReservedForArgumentRegisters(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsStackAdjustedOnReturn(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsEligibleForHeuristics(BNCallingConvention* cc);

	BINARYNINJACOREAPI uint32_t BNGetIntegerReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetHighIntegerReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetFloatReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetGlobalPointerRegister(BNCallingConvention* cc);

	BINARYNINJACOREAPI uint32_t* BNGetImplicitlyDefinedRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI BNRegisterValue BNGetIncomingRegisterValue(
	    BNCallingConvention* cc, uint32_t reg, BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValue BNGetIncomingFlagValue(BNCallingConvention* cc, uint32_t reg, BNFunction* func);

	BINARYNINJACOREAPI BNVariable* BNGetVariablesForParametersDefaultPermittedArgs(
		BNCallingConvention* cc, const BNFunctionParameter* params, size_t paramCount, size_t* count);
	BINARYNINJACOREAPI BNVariable* BNGetVariablesForParameters(BNCallingConvention* cc,
		const BNFunctionParameter* params, size_t paramCount, const uint32_t* permittedArgs, size_t permittedArgCount,
		size_t* count);
	BINARYNINJACOREAPI BNVariable* BNGetParameterOrderingForVariables(
	    BNCallingConvention* cc, const BNVariable* paramVars, const BNType** paramTypes,
	    size_t paramCount, size_t* count);
	BINARYNINJACOREAPI int64_t BNGetStackAdjustmentForVariables(
	    BNCallingConvention* cc, const BNVariable* paramVars, const BNType** paramTypes,
	    size_t paramCount);
	BINARYNINJACOREAPI size_t BNGetRegisterStackAdjustments(
	    BNCallingConvention* cc, const uint32_t* returnRegs, size_t returnRegCount, BNType* returnType,
	    const BNVariable* params, size_t paramCount, const BNType** types, size_t typeCount,
	    uint32_t** resultRegisters, uint32_t** resultAdjustments);

	BINARYNINJACOREAPI BNVariable BNGetIncomingVariableForParameterVariable(
	    BNCallingConvention* cc, const BNVariable* var, BNFunction* func);
	BINARYNINJACOREAPI BNVariable BNGetParameterVariableForIncomingVariable(
	    BNCallingConvention* cc, const BNVariable* var, BNFunction* func);
	BINARYNINJACOREAPI BNVariable BNGetDefaultIncomingVariableForParameterVariable(
	    BNCallingConvention* cc, const BNVariable* var);
	BINARYNINJACOREAPI BNVariable BNGetDefaultParameterVariableForIncomingVariable(
	    BNCallingConvention* cc, const BNVariable* var);

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
	BINARYNINJACOREAPI BNPlatform* BNCreatePlatformWithTypes(
	    BNArchitecture* arch, const char* name, const char* typeFile, const char** includeDirs, size_t includeDirCount);
	BINARYNINJACOREAPI BNPlatform* BNCreateCustomPlatform(BNArchitecture* arch, const char* name, BNCustomPlatform* impl);
	BINARYNINJACOREAPI BNPlatform* BNCreateCustomPlatformWithTypes(
	    BNArchitecture* arch, const char* name, BNCustomPlatform* impl,
			const char* typeFile, const char** includeDirs, size_t includeDirCount);
	BINARYNINJACOREAPI void BNRegisterPlatform(const char* os, BNPlatform* platform);
	BINARYNINJACOREAPI BNPlatform* BNNewPlatformReference(BNPlatform* platform);
	BINARYNINJACOREAPI void BNFreePlatform(BNPlatform* platform);

	BINARYNINJACOREAPI char* BNGetPlatformName(BNPlatform* platform);
	BINARYNINJACOREAPI BNArchitecture* BNGetPlatformArchitecture(BNPlatform* platform);

	BINARYNINJACOREAPI BNPlatform* BNGetPlatformByName(const char* name);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformList(size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByArchitecture(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByOS(const char* os, size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByOSAndArchitecture(
	    const char* os, BNArchitecture* arch, size_t* count);
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

	BINARYNINJACOREAPI uint32_t* BNGetPlatformGlobalRegisters(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNType* BNGetPlatformGlobalRegisterType(BNPlatform* platform, uint32_t reg);
	BINARYNINJACOREAPI void BNPlatformAdjustTypeParserInput(
		BNPlatform* platform,
		BNTypeParser* parser,
		const char* const* argumentsIn,
		size_t argumentsLenIn,
		const char* const* sourceFileNamesIn,
		const char* const* sourceFileValuesIn,
		size_t sourceFilesLenIn,
		char*** argumentsOut,
		size_t* argumentsLenOut,
		char*** sourceFileNamesOut,
		char*** sourceFileValuesOut,
		size_t* sourceFilesLenOut
	);

	BINARYNINJACOREAPI BNPlatform* BNGetArchitectureStandalonePlatform(BNArchitecture* arch);

	BINARYNINJACOREAPI BNPlatform* BNGetRelatedPlatform(BNPlatform* platform, BNArchitecture* arch);
	BINARYNINJACOREAPI void BNAddRelatedPlatform(BNPlatform* platform, BNArchitecture* arch, BNPlatform* related);
	BINARYNINJACOREAPI BNPlatform** BNGetRelatedPlatforms(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNPlatform* BNGetAssociatedPlatformByAddress(BNPlatform* platform, uint64_t* addr);

	BINARYNINJACOREAPI BNTypeContainer* BNGetPlatformTypeContainer(BNPlatform* platform);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformTypes(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformVariables(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformFunctions(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNSystemCallInfo* BNGetPlatformSystemCalls(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI void BNFreeSystemCallList(BNSystemCallInfo* syscalls, size_t count);
	BINARYNINJACOREAPI BNType* BNGetPlatformTypeByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetPlatformVariableByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetPlatformFunctionByName(
	    BNPlatform* platform, BNQualifiedName* name, bool exactMatch);
	BINARYNINJACOREAPI char* BNGetPlatformSystemCallName(BNPlatform* platform, uint32_t number);
	BINARYNINJACOREAPI BNType* BNGetPlatformSystemCallType(BNPlatform* platform, uint32_t number);

	BINARYNINJACOREAPI BNTypeLibrary** BNGetPlatformTypeLibraries(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNTypeLibrary** BNGetPlatformTypeLibrariesByName(
	    BNPlatform* platform, const char* depName, size_t* count);

	// Demangler
	BINARYNINJACOREAPI bool BNDemangleMS(BNArchitecture* arch, const char* mangledName, BNType** outType,
	    char*** outVarName, size_t* outVarNameElements, const bool simplify);
	BINARYNINJACOREAPI bool BNDemangleMSWithOptions(BNArchitecture* arch, const char* mangledName, BNType** outType,
	    char*** outVarName, size_t* outVarNameElements, const BNBinaryView* const view);
	BINARYNINJACOREAPI bool BNDemangleMSPlatform(BNPlatform* platform, const char* mangledName, BNType** outType,
	    char*** outVarName, size_t* outVarNameElements, const bool simplify);

	// Download providers
	BINARYNINJACOREAPI BNDownloadProvider* BNRegisterDownloadProvider(
	    const char* name, BNDownloadProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadProvider** BNGetDownloadProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeDownloadProviderList(BNDownloadProvider** providers);
	BINARYNINJACOREAPI BNDownloadProvider* BNGetDownloadProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetDownloadProviderName(BNDownloadProvider* provider);
	BINARYNINJACOREAPI BNDownloadInstance* BNCreateDownloadProviderInstance(BNDownloadProvider* provider);

	BINARYNINJACOREAPI BNDownloadInstance* BNInitDownloadInstance(
	    BNDownloadProvider* provider, BNDownloadInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadInstance* BNNewDownloadInstanceReference(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstanceResponse(BNDownloadInstanceResponse* response);
	BINARYNINJACOREAPI int BNPerformDownloadRequest(
	    BNDownloadInstance* instance, const char* url, BNDownloadInstanceOutputCallbacks* callbacks);
	BINARYNINJACOREAPI int BNPerformCustomRequest(BNDownloadInstance* instance, const char* method, const char* url,
	    uint64_t headerCount, const char* const* headerKeys, const char* const* headerValues,
	    BNDownloadInstanceResponse** response, BNDownloadInstanceInputOutputCallbacks* callbacks);
	BINARYNINJACOREAPI int64_t BNReadDataForDownloadInstance(BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI uint64_t BNWriteDataForDownloadInstance(
	    BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNNotifyProgressForDownloadInstance(
	    BNDownloadInstance* instance, uint64_t progress, uint64_t total);
	BINARYNINJACOREAPI char* BNGetErrorForDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNSetErrorForDownloadInstance(BNDownloadInstance* instance, const char* error);

	// Websocket providers
	BINARYNINJACOREAPI BNWebsocketProvider* BNRegisterWebsocketProvider(
	    const char* name, BNWebsocketProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNWebsocketProvider** BNGetWebsocketProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeWebsocketProviderList(BNWebsocketProvider** providers);
	BINARYNINJACOREAPI BNWebsocketProvider* BNGetWebsocketProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetWebsocketProviderName(BNWebsocketProvider* provider);
	BINARYNINJACOREAPI BNWebsocketClient* BNCreateWebsocketProviderClient(BNWebsocketProvider* provider);

	BINARYNINJACOREAPI BNWebsocketClient* BNInitWebsocketClient(
	    BNWebsocketProvider* provider, BNWebsocketClientCallbacks* callbacks);
	BINARYNINJACOREAPI BNWebsocketClient* BNNewWebsocketClientReference(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNFreeWebsocketClient(BNWebsocketClient* client);
	BINARYNINJACOREAPI bool BNConnectWebsocketClient(BNWebsocketClient* client, const char* url, uint64_t headerCount,
	    const char* const* headerKeys, const char* const* headerValues, BNWebsocketClientOutputCallbacks* callbacks);
	BINARYNINJACOREAPI bool BNNotifyWebsocketClientConnect(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNNotifyWebsocketClientDisconnect(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNNotifyWebsocketClientError(BNWebsocketClient* client, const char* msg);
	BINARYNINJACOREAPI bool BNNotifyWebsocketClientReadData(BNWebsocketClient* client, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI uint64_t BNWriteWebsocketClientData(
	    BNWebsocketClient* client, const uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNDisconnectWebsocketClient(BNWebsocketClient* client);

	// Scripting providers
	BINARYNINJACOREAPI BNScriptingProvider* BNRegisterScriptingProvider(
	    const char* name, const char* apiName, BNScriptingProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingProvider** BNGetScriptingProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeScriptingProviderList(BNScriptingProvider** providers);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByName(const char* name);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByAPIName(const char* name);

	BINARYNINJACOREAPI char* BNGetScriptingProviderName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI char* BNGetScriptingProviderAPIName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI BNScriptingInstance* BNCreateScriptingProviderInstance(BNScriptingProvider* provider);
	BINARYNINJACOREAPI bool BNLoadScriptingProviderModule(
	    BNScriptingProvider* provider, const char* repository, const char* module, bool force);
	BINARYNINJACOREAPI bool BNInstallScriptingProviderModules(BNScriptingProvider* provider, const char* modules);

	BINARYNINJACOREAPI BNScriptingInstance* BNInitScriptingInstance(
	    BNScriptingProvider* provider, BNScriptingInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingInstance* BNNewScriptingInstanceReference(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNFreeScriptingInstance(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNNotifyOutputForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyWarningForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyErrorForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyInputReadyStateForScriptingInstance(
	    BNScriptingInstance* instance, BNScriptingProviderInputReadyState state);

	BINARYNINJACOREAPI void BNRegisterScriptingInstanceOutputListener(
	    BNScriptingInstance* instance, BNScriptingOutputListener* callbacks);
	BINARYNINJACOREAPI void BNUnregisterScriptingInstanceOutputListener(
	    BNScriptingInstance* instance, BNScriptingOutputListener* callbacks);

	BINARYNINJACOREAPI const char* BNGetScriptingInstanceDelimiters(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNSetScriptingInstanceDelimiters(BNScriptingInstance* instance, const char* delimiters);

	BINARYNINJACOREAPI BNScriptingProviderInputReadyState BNGetScriptingInstanceInputReadyState(
	    BNScriptingInstance* instance);
	BINARYNINJACOREAPI BNScriptingProviderExecuteResult BNExecuteScriptInput(
		BNScriptingInstance* instance, const char* input);
	BINARYNINJACOREAPI BNScriptingProviderExecuteResult BNExecuteScriptInputFromFilename(
		BNScriptingInstance* instance, const char* filename);
	BINARYNINJACOREAPI void BNCancelScriptInput(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNScriptingInstanceReleaseBinaryView(BNScriptingInstance* instance, BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBinaryView(BNScriptingInstance* instance, BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentFunction(BNScriptingInstance* instance, BNFunction* func);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBasicBlock(BNScriptingInstance* instance, BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentAddress(BNScriptingInstance* instance, uint64_t addr);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentSelection(
	    BNScriptingInstance* instance, uint64_t begin, uint64_t end);
	BINARYNINJACOREAPI char* BNScriptingInstanceCompleteInput(
	    BNScriptingInstance* instance, const char* text, uint64_t state);
	BINARYNINJACOREAPI void BNStopScriptingInstance(BNScriptingInstance* instance);
	BINARYNINJACOREAPI size_t BNFuzzyMatchSingle(const char* target, const char* query);

	// Main thread actions
	BINARYNINJACOREAPI void BNRegisterMainThread(BNMainThreadCallbacks* callbacks);
	BINARYNINJACOREAPI BNMainThreadAction* BNNewMainThreadActionReference(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNFreeMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNExecuteMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI bool BNIsMainThreadActionDone(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNWaitForMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI BNMainThreadAction* BNExecuteOnMainThread(void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI void BNExecuteOnMainThreadAndWait(void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI bool BNIsMainThread(void);

	// Worker thread queue management
	BINARYNINJACOREAPI void BNWorkerEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerEnqueueNamed(void* ctxt, void (*action)(void* ctxt), const char* name);
	BINARYNINJACOREAPI void BNWorkerPriorityEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerPriorityEnqueueNamed(void* ctxt, void (*action)(void* ctxt), const char* name);
	BINARYNINJACOREAPI void BNWorkerInteractiveEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerInteractiveEnqueueNamed(void* ctxt, void (*action)(void* ctxt), const char* name);

	BINARYNINJACOREAPI size_t BNGetWorkerThreadCount(void);
	BINARYNINJACOREAPI void BNSetWorkerThreadCount(size_t count);

	BINARYNINJACOREAPI void BNSetThreadName(const char* name);

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
	BINARYNINJACOREAPI uint64_t BNGetBackgroundTaskRuntimeSeconds(BNBackgroundTask* task);
	BINARYNINJACOREAPI bool BNCanCancelBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNCancelBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI bool BNIsBackgroundTaskFinished(BNBackgroundTask* task);

	// Interaction APIs
	BINARYNINJACOREAPI void BNRegisterInteractionHandler(BNInteractionHandlerCallbacks* callbacks);
	BINARYNINJACOREAPI char* BNMarkdownToHTML(const char* contents);
	BINARYNINJACOREAPI void BNShowPlainTextReport(BNBinaryView* view, const char* title, const char* contents);
	BINARYNINJACOREAPI void BNShowMarkdownReport(
	    BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNShowHTMLReport(
	    BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNShowGraphReport(BNBinaryView* view, const char* title, BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNShowReportCollection(const char* title, BNReportCollection* reports);
	BINARYNINJACOREAPI bool BNGetTextLineInput(char** result, const char* prompt, const char* title);
	BINARYNINJACOREAPI bool BNGetIntegerInput(int64_t* result, const char* prompt, const char* title);
	BINARYNINJACOREAPI bool BNGetAddressInput(
	    uint64_t* result, const char* prompt, const char* title, BNBinaryView* view, uint64_t currentAddr);
	BINARYNINJACOREAPI bool BNGetChoiceInput(
		size_t* result, const char* prompt, const char* title, const char** choices, size_t count);
	BINARYNINJACOREAPI bool BNGetLargeChoiceInput(
		size_t* result, const char* prompt, const char* title, const char** choices, size_t count);
	BINARYNINJACOREAPI bool BNGetOpenFileNameInput(char** result, const char* prompt, const char* ext);
	BINARYNINJACOREAPI bool BNGetSaveFileNameInput(
	    char** result, const char* prompt, const char* ext, const char* defaultName);
	BINARYNINJACOREAPI bool BNGetDirectoryNameInput(char** result, const char* prompt, const char* defaultName);
	BINARYNINJACOREAPI bool BNGetFormInput(BNFormInputField* fields, size_t count, const char* title);
	BINARYNINJACOREAPI void BNFreeFormInputResults(BNFormInputField* fields, size_t count);
	BINARYNINJACOREAPI BNMessageBoxButtonResult BNShowMessageBox(
	    const char* title, const char* text, BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon);
	BINARYNINJACOREAPI bool BNOpenUrl(const char* url);
	BINARYNINJACOREAPI bool BNRunProgressDialog(const char* title, bool canCancel,
		void (*task)(void* taskCtxt, bool(*progress)(void* progressCtxt, size_t cur, size_t max), void* progressCtxt), void* taskCtxt);

	BINARYNINJACOREAPI BNReportCollection* BNCreateReportCollection(void);
	BINARYNINJACOREAPI BNReportCollection* BNNewReportCollectionReference(BNReportCollection* reports);
	BINARYNINJACOREAPI void BNFreeReportCollection(BNReportCollection* reports);
	BINARYNINJACOREAPI size_t BNGetReportCollectionCount(BNReportCollection* reports);
	BINARYNINJACOREAPI BNReportType BNGetReportType(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI BNBinaryView* BNGetReportView(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI char* BNGetReportTitle(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI char* BNGetReportContents(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI char* BNGetReportPlainText(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI BNFlowGraph* BNGetReportFlowGraph(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI void BNAddPlainTextReportToCollection(
	    BNReportCollection* reports, BNBinaryView* view, const char* title, const char* contents);
	BINARYNINJACOREAPI void BNAddMarkdownReportToCollection(BNReportCollection* reports, BNBinaryView* view,
	    const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNAddHTMLReportToCollection(BNReportCollection* reports, BNBinaryView* view,
	    const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNAddGraphReportToCollection(
	    BNReportCollection* reports, BNBinaryView* view, const char* title, BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNUpdateReportFlowGraph(BNReportCollection* reports, size_t i, BNFlowGraph* graph);

	BINARYNINJACOREAPI bool BNIsGNU3MangledString(const char* mangledName);
	BINARYNINJACOREAPI bool BNDemangleGNU3(BNArchitecture* arch, const char* mangledName, BNType** outType,
	    char*** outVarName, size_t* outVarNameElements, const bool simplify);
	BINARYNINJACOREAPI bool BNDemangleGNU3WithOptions(BNArchitecture* arch, const char* mangledName, BNType** outType,
	    char*** outVarName, size_t* outVarNameElements, const BNBinaryView* const view);
	BINARYNINJACOREAPI void BNFreeDemangledName(char*** name, size_t nameElements);

	BINARYNINJACOREAPI bool BNDemangleLLVM(const char* mangledName,
		char*** outVarName, size_t* outVarNameElements, const bool simplify);
	BINARYNINJACOREAPI bool BNDemangleLLVMWithOptions(const char* mangledName,
	char*** outVarName, size_t* outVarNameElements, const BNBinaryView* const view);

	// Plugin repository APIs
	BINARYNINJACOREAPI char** BNPluginGetApis(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI const char* BNPluginGetAuthor(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetDescription(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLicenseText(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLongdescription(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNVersionInfo BNPluginGetMinimumVersionInfo(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNVersionInfo BNPluginGetMaximumVersionInfo(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNVersionInfo BNParseVersionString(const char* v);
	BINARYNINJACOREAPI bool BNVersionLessThan(const BNVersionInfo smaller, const BNVersionInfo larger);
	BINARYNINJACOREAPI const char* BNPluginGetName(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetProjectUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetPackageUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetAuthorUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetVersion(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetCommit(BNRepoPlugin* p);
	BINARYNINJACOREAPI void BNFreePluginTypes(BNPluginType* r);
	BINARYNINJACOREAPI BNRepoPlugin* BNNewPluginReference(BNRepoPlugin* r);
	BINARYNINJACOREAPI void BNFreePlugin(BNRepoPlugin* plugin);
	BINARYNINJACOREAPI const char* BNPluginGetPath(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetSubdir(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetDependencies(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsInstalled(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsEnabled(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNPluginStatus BNPluginGetPluginStatus(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNPluginType* BNPluginGetPluginTypes(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI bool BNPluginEnable(BNRepoPlugin* p, bool force);
	BINARYNINJACOREAPI bool BNPluginDisable(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginInstall(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginInstallDependencies(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginUninstall(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginUpdate(BNRepoPlugin* p);
	BINARYNINJACOREAPI char** BNPluginGetPlatforms(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI void BNFreePluginPlatforms(char** platforms, size_t count);
	BINARYNINJACOREAPI const char* BNPluginGetRepository(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsBeingDeleted(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsBeingUpdated(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsRunning(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsUpdatePending(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsDisablePending(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsDeletePending(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsUpdateAvailable(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginAreDependenciesBeingInstalled(BNRepoPlugin* p);

	BINARYNINJACOREAPI char* BNPluginGetProjectData(BNRepoPlugin* p);
	BINARYNINJACOREAPI uint64_t BNPluginGetLastUpdate(BNRepoPlugin* p);

	BINARYNINJACOREAPI BNRepository* BNNewRepositoryReference(BNRepository* r);
	BINARYNINJACOREAPI void BNFreeRepository(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetUrl(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetRepoPath(BNRepository* r);
	BINARYNINJACOREAPI BNRepoPlugin** BNRepositoryGetPlugins(BNRepository* r, size_t* count);
	BINARYNINJACOREAPI void BNFreeRepositoryPluginList(BNRepoPlugin** r);
	BINARYNINJACOREAPI void BNRepositoryFreePluginDirectoryList(char** list, size_t count);
	BINARYNINJACOREAPI BNRepoPlugin* BNRepositoryGetPluginByPath(BNRepository* r, const char* pluginPath);
	BINARYNINJACOREAPI const char* BNRepositoryGetPluginsPath(BNRepository* r);

	BINARYNINJACOREAPI BNRepositoryManager* BNCreateRepositoryManager(const char* enabledPluginsPath);
	BINARYNINJACOREAPI BNRepositoryManager* BNNewRepositoryManagerReference(BNRepositoryManager* r);
	BINARYNINJACOREAPI void BNFreeRepositoryManager(BNRepositoryManager* r);
	BINARYNINJACOREAPI bool BNRepositoryManagerCheckForUpdates(BNRepositoryManager* r);
	BINARYNINJACOREAPI BNRepository** BNRepositoryManagerGetRepositories(BNRepositoryManager* r, size_t* count);
	BINARYNINJACOREAPI void BNFreeRepositoryManagerRepositoriesList(BNRepository** r);
	BINARYNINJACOREAPI bool BNRepositoryManagerAddRepository(
	    BNRepositoryManager* r, const char* url, const char* repoPath);
	BINARYNINJACOREAPI BNRepository* BNRepositoryGetRepositoryByPath(BNRepositoryManager* r, const char* repoPath);
	BINARYNINJACOREAPI BNRepositoryManager* BNGetRepositoryManager(void);

	BINARYNINJACOREAPI BNRepository* BNRepositoryManagerGetDefaultRepository(BNRepositoryManager* r);

	// Components

	BINARYNINJACOREAPI BNComponent* BNNewComponentReference(BNComponent *component);
	BINARYNINJACOREAPI void BNFreeComponent(BNComponent *component);

	BINARYNINJACOREAPI BNFunction** BNComponentGetContainedFunctions(BNComponent *component, size_t *count);
	BINARYNINJACOREAPI BNComponent** BNComponentGetContainedComponents(BNComponent *component, size_t *count);
	BINARYNINJACOREAPI BNDataVariable* BNComponentGetContainedDataVariables(BNComponent *component, size_t *count);

	BINARYNINJACOREAPI BNDataVariable* BNComponentGetReferencedDataVariables(BNComponent *component, size_t *count);
	BINARYNINJACOREAPI BNDataVariable* BNComponentGetReferencedDataVariablesRecursive(BNComponent *component, size_t *count);
	BINARYNINJACOREAPI BNType** BNComponentGetReferencedTypes(BNComponent *component, size_t *count);
	BINARYNINJACOREAPI BNType** BNComponentGetReferencedTypesRecursive(BNComponent *component, size_t *count);

	BINARYNINJACOREAPI void BNFreeComponents(BNComponent** components, size_t count);
	BINARYNINJACOREAPI void BNComponentFreeReferencedTypes(BNType** types, size_t count);

	BINARYNINJACOREAPI BNComponent* BNComponentGetParent(BNComponent* component);

	BINARYNINJACOREAPI bool BNComponentContainsFunction(BNComponent* component, BNFunction *function);
	BINARYNINJACOREAPI bool BNComponentContainsComponent(BNComponent *parent, BNComponent *component);
	BINARYNINJACOREAPI bool BNComponentContainsDataVariable(BNComponent* component, uint64_t address);

	BINARYNINJACOREAPI bool BNComponentAddFunctionReference(BNComponent* component, BNFunction* function);
	BINARYNINJACOREAPI bool BNComponentAddComponent(BNComponent* parent, BNComponent* component);
	BINARYNINJACOREAPI bool BNComponentAddDataVariable(BNComponent* component, uint64_t address);

	BINARYNINJACOREAPI bool BNComponentRemoveComponent(BNComponent* component);
	BINARYNINJACOREAPI bool BNComponentRemoveFunctionReference(BNComponent* component, BNFunction* function);
	BINARYNINJACOREAPI void BNComponentRemoveAllFunctions(BNComponent* component);
	BINARYNINJACOREAPI bool BNComponentRemoveDataVariable(BNComponent* component, uint64_t address);

	BINARYNINJACOREAPI void BNComponentAddAllMembersFromComponent(BNComponent* component, BNComponent* fromComponent);
	BINARYNINJACOREAPI char* BNComponentGetGuid(BNComponent* component);
	BINARYNINJACOREAPI bool BNComponentsEqual(BNComponent* a, BNComponent* b);
	BINARYNINJACOREAPI bool BNComponentsNotEqual(BNComponent* a, BNComponent* b);
	BINARYNINJACOREAPI char* BNComponentGetDisplayName(BNComponent* component);
	BINARYNINJACOREAPI char* BNComponentGetOriginalName(BNComponent* component);
	BINARYNINJACOREAPI void BNComponentSetName(BNComponent* component, const char* name);
	BINARYNINJACOREAPI BNBinaryView* BNComponentGetView(BNComponent* component);

	// LLVM Services APIs
	BINARYNINJACOREAPI void BNLlvmServicesInit(void);

	BINARYNINJACOREAPI int BNLlvmServicesAssemble(const char* src, int dialect, const char* triplet, int codeModel,
	    int relocMode, char** outBytes, int* outBytesLen, char** err, int* errLen);

	BINARYNINJACOREAPI void BNLlvmServicesAssembleFree(char* outBytes, char* err);

	// Filesystem functionality
	BINARYNINJACOREAPI bool BNDeleteFile(const char* path);
	BINARYNINJACOREAPI bool BNDeleteDirectory(const char* path);
	BINARYNINJACOREAPI bool BNCreateDirectory(const char* path, bool createSubdirectories);
	BINARYNINJACOREAPI bool BNPathExists(const char* path);
	BINARYNINJACOREAPI char* BNGetParentPath(const char* path);
	BINARYNINJACOREAPI bool BNIsPathDirectory(const char* path);
	BINARYNINJACOREAPI bool BNIsPathRegularFile(const char* path);
	BINARYNINJACOREAPI bool BNFileSize(const char* path, uint64_t* size);
	BINARYNINJACOREAPI bool BNRenameFile(const char* source, const char* dest);
	BINARYNINJACOREAPI bool BNCopyFile(const char* source, const char* dest);
	BINARYNINJACOREAPI char* BNGetFileName(const char* path);
	BINARYNINJACOREAPI char* BNGetFileExtension(const char* path);
	BINARYNINJACOREAPI char** BNGetFilePathsInDirectory(const char* path, size_t* count);
	BINARYNINJACOREAPI char* BNAppendPath(const char* path, const char* part);
	BINARYNINJACOREAPI void BNFreePath(char* path);

	// Settings APIs
	BINARYNINJACOREAPI BNSettings* BNCreateSettings(const char* schemaId);
	BINARYNINJACOREAPI BNSettings* BNNewSettingsReference(BNSettings* settings);
	BINARYNINJACOREAPI void BNFreeSettings(BNSettings* settings);
	BINARYNINJACOREAPI bool BNLoadSettingsFile(BNSettings* settings, const char* fileName, BNSettingsScope scope, BNBinaryView* view);
	BINARYNINJACOREAPI void BNSettingsSetResourceId(BNSettings* settings, const char* resourceId);
	BINARYNINJACOREAPI bool BNSettingsRegisterGroup(BNSettings* settings, const char* group, const char* title);
	BINARYNINJACOREAPI bool BNSettingsRegisterSetting(BNSettings* settings, const char* key, const char* properties);
	BINARYNINJACOREAPI bool BNSettingsContains(BNSettings* settings, const char* key);
	BINARYNINJACOREAPI bool BNSettingsIsEmpty(BNSettings* settings);
	BINARYNINJACOREAPI const char** BNSettingsKeysList(BNSettings* settings, size_t* inoutSize);
	BINARYNINJACOREAPI const char** BNSettingsQueryPropertyStringList(
	    BNSettings* settings, const char* key, const char* property, size_t* inoutSize);
	BINARYNINJACOREAPI bool BNSettingsUpdateProperty(BNSettings* settings, const char* key, const char* property);
	BINARYNINJACOREAPI bool BNSettingsUpdateBoolProperty(
	    BNSettings* settings, const char* key, const char* property, bool value);
	BINARYNINJACOREAPI bool BNSettingsUpdateDoubleProperty(
	    BNSettings* settings, const char* key, const char* property, double value);
	BINARYNINJACOREAPI bool BNSettingsUpdateInt64Property(
	    BNSettings* settings, const char* key, const char* property, int64_t value);
	BINARYNINJACOREAPI bool BNSettingsUpdateUInt64Property(
	    BNSettings* settings, const char* key, const char* property, uint64_t value);
	BINARYNINJACOREAPI bool BNSettingsUpdateStringProperty(
	    BNSettings* settings, const char* key, const char* property, const char* value);
	BINARYNINJACOREAPI bool BNSettingsUpdateStringListProperty(
	    BNSettings* settings, const char* key, const char* property, const char** value, size_t size);

	BINARYNINJACOREAPI bool BNSettingsDeserializeSchema(
	    BNSettings* settings, const char* schema, BNSettingsScope scope, bool merge);
	BINARYNINJACOREAPI char* BNSettingsSerializeSchema(BNSettings* settings);
	BINARYNINJACOREAPI bool BNDeserializeSettings(
	    BNSettings* settings, const char* contents, BNBinaryView* view, BNSettingsScope scope);
	BINARYNINJACOREAPI char* BNSerializeSettings(BNSettings* settings, BNBinaryView* view, BNSettingsScope scope);

	BINARYNINJACOREAPI bool BNSettingsReset(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope scope);
	BINARYNINJACOREAPI bool BNSettingsResetAll(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, bool schemaOnly);

	BINARYNINJACOREAPI bool BNSettingsGetBool(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI double BNSettingsGetDouble(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI int64_t BNSettingsGetInt64(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI uint64_t BNSettingsGetUInt64(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI char* BNSettingsGetString(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI const char** BNSettingsGetStringList(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope, size_t* inoutSize);

	BINARYNINJACOREAPI char* BNSettingsGetJson(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);

	BINARYNINJACOREAPI bool BNSettingsSetBool(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, bool value);
	BINARYNINJACOREAPI bool BNSettingsSetDouble(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, double value);
	BINARYNINJACOREAPI bool BNSettingsSetInt64(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, int64_t value);
	BINARYNINJACOREAPI bool BNSettingsSetUInt64(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, uint64_t value);
	BINARYNINJACOREAPI bool BNSettingsSetString(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, const char* value);
	BINARYNINJACOREAPI bool BNSettingsSetStringList(BNSettings* settings, BNBinaryView* view, BNSettingsScope scope,
	    const char* key, const char** value, size_t size);
	BINARYNINJACOREAPI bool BNSettingsSetJson(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, const char* value);

	// Metadata APIs

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
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataBooleanListData(bool* data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataUnsignedIntegerListData(uint64_t* data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataSignedIntegerListData(int64_t* data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataDoubleListData(double* data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataStringListData(const char** data, size_t size);

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
	BINARYNINJACOREAPI void BNFreeMetadataBooleanList(bool*, size_t);
	BINARYNINJACOREAPI void BNFreeMetadataUnsignedIntegerList(uint64_t*, size_t);
	BINARYNINJACOREAPI void BNFreeMetadataSignedIntegerList(int64_t*, size_t);
	BINARYNINJACOREAPI void BNFreeMetadataDoubleList(double*, size_t);
	BINARYNINJACOREAPI void BNFreeMetadataStringList(char**, size_t);

	// Retrieve Structured Data
	BINARYNINJACOREAPI bool BNMetadataGetBoolean(BNMetadata* data);
	BINARYNINJACOREAPI char* BNMetadataGetString(BNMetadata* data);
	BINARYNINJACOREAPI uint64_t BNMetadataGetUnsignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI int64_t BNMetadataGetSignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI double BNMetadataGetDouble(BNMetadata* data);
	BINARYNINJACOREAPI bool* BNMetadataGetBooleanList(BNMetadata* data, size_t *);
	BINARYNINJACOREAPI char** BNMetadataGetStringList(BNMetadata* data, size_t *);
	BINARYNINJACOREAPI uint64_t* BNMetadataGetUnsignedIntegerList(BNMetadata* data, size_t *);
	BINARYNINJACOREAPI int64_t* BNMetadataGetSignedIntegerList(BNMetadata* data, size_t *);
	BINARYNINJACOREAPI double* BNMetadataGetDoubleList(BNMetadata* data, size_t *);
	BINARYNINJACOREAPI uint8_t* BNMetadataGetRaw(BNMetadata* data, size_t* size);
	BINARYNINJACOREAPI BNMetadata** BNMetadataGetArray(BNMetadata* data, size_t* size);
	BINARYNINJACOREAPI BNMetadataValueStore* BNMetadataGetValueStore(BNMetadata* data);
	BINARYNINJACOREAPI char* BNMetadataGetJsonString(BNMetadata* data);

	// Query type of Metadata
	BINARYNINJACOREAPI BNMetadataType BNMetadataGetType(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsBoolean(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsString(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsUnsignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsSignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsDouble(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsBooleanList(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsStringList(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsUnsignedIntegerList(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsSignedIntegerList(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsDoubleList(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsRaw(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsArray(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsKeyValueStore(BNMetadata* data);

	// Store/Query structured data to/from a BinaryView
	BINARYNINJACOREAPI void BNBinaryViewStoreMetadata(
	    BNBinaryView* view, const char* key, BNMetadata* value, bool isAuto);
	BINARYNINJACOREAPI BNMetadata* BNBinaryViewQueryMetadata(BNBinaryView* view, const char* key);
	BINARYNINJACOREAPI void BNBinaryViewRemoveMetadata(BNBinaryView* view, const char* key);
	BINARYNINJACOREAPI BNMetadata* BNBinaryViewGetMetadata(BNBinaryView* view);
	BINARYNINJACOREAPI BNMetadata* BNBinaryViewGetAutoMetadata(BNBinaryView* view);

	BINARYNINJACOREAPI char** BNBinaryViewGetLoadSettingsTypeNames(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNSettings* BNBinaryViewGetLoadSettings(BNBinaryView* view, const char* typeName);
	BINARYNINJACOREAPI void BNBinaryViewSetLoadSettings(BNBinaryView* view, const char* typeName, BNSettings* settings);

	// Relocation object methods
	BINARYNINJACOREAPI BNRelocation* BNNewRelocationReference(BNRelocation* reloc);
	BINARYNINJACOREAPI void BNFreeRelocation(BNRelocation* reloc);
	BINARYNINJACOREAPI BNRelocationInfo BNRelocationGetInfo(BNRelocation* reloc);
	BINARYNINJACOREAPI BNArchitecture* BNRelocationGetArchitecture(BNRelocation* reloc);
	BINARYNINJACOREAPI uint64_t BNRelocationGetTarget(BNRelocation* reloc);
	BINARYNINJACOREAPI uint64_t BNRelocationGetReloc(BNRelocation* reloc);
	BINARYNINJACOREAPI BNSymbol* BNRelocationGetSymbol(BNRelocation* reloc);

	// Segment object methods
	BINARYNINJACOREAPI BNSegment* BNCreateSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags, bool autoDefined);
	BINARYNINJACOREAPI BNSegment* BNNewSegmentReference(BNSegment* seg);
	BINARYNINJACOREAPI void BNFreeSegment(BNSegment* seg);
	BINARYNINJACOREAPI uint64_t BNSegmentGetStart(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetLength(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetEnd(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetDataEnd(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetDataOffset(BNSegment* segment);
	BINARYNINJACOREAPI uint64_t BNSegmentGetDataLength(BNSegment* segment);
	BINARYNINJACOREAPI uint32_t BNSegmentGetFlags(BNSegment* segment);
	BINARYNINJACOREAPI bool BNSegmentIsAutoDefined(BNSegment* segment);

	// Section object methods
	BINARYNINJACOREAPI BNSection* BNNewSectionReference(BNSection* section);
	BINARYNINJACOREAPI void BNFreeSection(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetName(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetType(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetStart(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetLength(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetEnd(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetLinkedSection(BNSection* section);
	BINARYNINJACOREAPI char* BNSectionGetInfoSection(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetInfoData(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetAlign(BNSection* section);
	BINARYNINJACOREAPI uint64_t BNSectionGetEntrySize(BNSection* section);
	BINARYNINJACOREAPI BNSectionSemantics BNSectionGetSemantics(BNSection* section);
	BINARYNINJACOREAPI bool BNSectionIsAutoDefined(BNSection* section);

	// Custom Data Render methods
	BINARYNINJACOREAPI BNDataRenderer* BNCreateDataRenderer(BNCustomDataRenderer* renderer);
	BINARYNINJACOREAPI BNDataRenderer* BNNewDataRendererReference(BNDataRenderer* renderer);
	BINARYNINJACOREAPI bool BNIsValidForData(
	    void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetLinesForData(void* ctxt, BNBinaryView* view, uint64_t addr,
	    BNType* type, const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
	    BNTypeContext* typeCtx, size_t ctxCount);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNRenderLinesForData(BNBinaryView* data, uint64_t addr, BNType* type,
	    const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count, BNTypeContext* typeCtx,
	    size_t ctxCount);
	BINARYNINJACOREAPI void BNFreeDataRenderer(BNDataRenderer* renderer);
	BINARYNINJACOREAPI BNDataRendererContainer* BNGetDataRendererContainer(void);
	BINARYNINJACOREAPI void BNRegisterGenericDataRenderer(BNDataRendererContainer* container, BNDataRenderer* renderer);
	BINARYNINJACOREAPI void BNRegisterTypeSpecificDataRenderer(
	    BNDataRendererContainer* container, BNDataRenderer* renderer);

	BINARYNINJACOREAPI bool BNParseExpression(
	    BNBinaryView* view, const char* expression, uint64_t* offset, uint64_t here, char** errorString);
	BINARYNINJACOREAPI void BNFreeParseError(char* errorString);

	BINARYNINJACOREAPI char* BNGetCurrentStackTraceString(void);
	BINARYNINJACOREAPI void* BNRegisterObjectRefDebugTrace(const char* typeName);
	BINARYNINJACOREAPI void BNUnregisterObjectRefDebugTrace(const char* typeName, void* trace);
	BINARYNINJACOREAPI BNMemoryUsageInfo* BNGetMemoryUsageInfo(size_t* count);
	BINARYNINJACOREAPI void BNFreeMemoryUsageInfo(BNMemoryUsageInfo* info, size_t count);

	BINARYNINJACOREAPI uint32_t BNGetAddressRenderedWidth(uint64_t addr);

	BINARYNINJACOREAPI BNQualifiedName BNRustSimplifyStrToFQN(const char* const, bool);
	BINARYNINJACOREAPI char* BNRustSimplifyStrToStr(const char* const);

	BINARYNINJACOREAPI BNDebugInfoParser* BNRegisterDebugInfoParser(const char* name,
		bool (*isValid)(void*, BNBinaryView*),
		bool (*parseInfo)(void*, BNDebugInfo*, BNBinaryView*, BNBinaryView*, bool (*)(void*, size_t, size_t), void*),
		void* context);
	BINARYNINJACOREAPI void BNUnregisterDebugInfoParser(const char* rawName);
	BINARYNINJACOREAPI BNDebugInfoParser* BNGetDebugInfoParserByName(const char* name);
	BINARYNINJACOREAPI BNDebugInfoParser** BNGetDebugInfoParsers(size_t* count);
	BINARYNINJACOREAPI BNDebugInfoParser** BNGetDebugInfoParsersForView(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI char* BNGetDebugInfoParserName(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI bool BNIsDebugInfoParserValidForView(BNDebugInfoParser* parser, BNBinaryView* view);
	BINARYNINJACOREAPI BNDebugInfo* BNParseDebugInfo(BNDebugInfoParser* parser, BNBinaryView* view, BNBinaryView* debugFile,
		BNDebugInfo* existingDebugInfo, BNProgressFunction progress, void* progressCtxt);
	BINARYNINJACOREAPI BNDebugInfoParser* BNNewDebugInfoParserReference(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI void BNFreeDebugInfoParserReference(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI void BNFreeDebugInfoParserList(BNDebugInfoParser** parsers, size_t count);

	BINARYNINJACOREAPI BNDebugInfo* BNNewDebugInfoReference(BNDebugInfo* debugInfo);
	BINARYNINJACOREAPI void BNFreeDebugInfoReference(BNDebugInfo* debugInfo);
	BINARYNINJACOREAPI char** BNGetDebugParserNames(BNDebugInfo* const debugInfo, size_t* count);
	BINARYNINJACOREAPI BNTypeContainer* BNGetDebugInfoTypeContainer(BNDebugInfo* debugInfo, const char* const parserName);
	BINARYNINJACOREAPI bool BNRemoveDebugParserInfo(BNDebugInfo* const debugInfo, const char* const parserName);
	BINARYNINJACOREAPI bool BNRemoveDebugParserTypes(BNDebugInfo* const debugInfo, const char* const parserName);
	BINARYNINJACOREAPI bool BNRemoveDebugParserFunctions(BNDebugInfo* const debugInfo, const char* const parserName);
	BINARYNINJACOREAPI bool BNRemoveDebugParserDataVariables(
		BNDebugInfo* const debugInfo, const char* const parserName);
	BINARYNINJACOREAPI bool BNAddDebugType(
		BNDebugInfo* const debugInfo, const char* const name, const BNType* const type, const char** const components, size_t components_count);
	BINARYNINJACOREAPI BNNameAndType* BNGetDebugTypes(
		BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI BNType* BNGetDebugTypeByName(
		BNDebugInfo* const debugInfo, const char* const parserName, const char* const typeName);
	BINARYNINJACOREAPI BNNameAndType* BNGetDebugTypesByName(
		BNDebugInfo* const debugInfo, const char* const typeName, size_t* count);
	BINARYNINJACOREAPI bool BNRemoveDebugTypeByName(
		BNDebugInfo* const debugInfo, const char* const parserName, const char* typeName);
	BINARYNINJACOREAPI void BNFreeDebugTypes(BNNameAndType* types, size_t count);
	BINARYNINJACOREAPI bool BNAddDebugFunction(BNDebugInfo* const debugInfo, BNDebugFunctionInfo* func);
	BINARYNINJACOREAPI BNDebugFunctionInfo* BNGetDebugFunctions(
		BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI bool BNRemoveDebugFunctionByIndex(
		BNDebugInfo* const debugInfo, const char* const parserName, const size_t index);
	BINARYNINJACOREAPI void BNFreeDebugFunctions(BNDebugFunctionInfo* functions, size_t count);
	BINARYNINJACOREAPI bool BNAddDebugDataVariable(
		BNDebugInfo* const debugInfo, uint64_t address, const BNType* const type, const char* name, const char** const components, size_t components_count);
	BINARYNINJACOREAPI bool BNAddDebugDataVariableInfo(
		BNDebugInfo* const debugInfo, const BNDataVariableAndName* var);
	BINARYNINJACOREAPI BNDataVariableAndName* BNGetDebugDataVariables(
		BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI BNDataVariableAndName* BNGetDebugDataVariableByName(
		BNDebugInfo* const debugInfo, const char* const parserName, const char* const variableName);
	BINARYNINJACOREAPI BNDataVariableAndName* BNGetDebugDataVariableByAddress(
		BNDebugInfo* const debugInfo, const char* const parserName, const uint64_t address);
	BINARYNINJACOREAPI BNDataVariableAndName* BNGetDebugDataVariablesByName(
		BNDebugInfo* const debugInfo, const char* const variableName, size_t* count);
	BINARYNINJACOREAPI BNDataVariableAndNameAndDebugParser* BNGetDebugDataVariablesByAddress(
		BNDebugInfo* const debugInfo, const uint64_t address, size_t* count);
	BINARYNINJACOREAPI bool BNRemoveDebugDataVariableByAddress(
		BNDebugInfo* const debugInfo, const char* const parserName, const uint64_t address);

	// Secrets providers
	BINARYNINJACOREAPI BNSecretsProvider* BNRegisterSecretsProvider(
	    const char* name, BNSecretsProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNSecretsProvider** BNGetSecretsProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeSecretsProviderList(BNSecretsProvider** providers);
	BINARYNINJACOREAPI BNSecretsProvider* BNGetSecretsProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetSecretsProviderName(BNSecretsProvider* provider);

	BINARYNINJACOREAPI bool BNSecretsProviderHasData(BNSecretsProvider* provider, const char* key);
	BINARYNINJACOREAPI char* BNGetSecretsProviderData(BNSecretsProvider* provider, const char* key);
	BINARYNINJACOREAPI bool BNStoreSecretsProviderData(BNSecretsProvider* provider, const char* key, const char* data);
	BINARYNINJACOREAPI bool BNDeleteSecretsProviderData(BNSecretsProvider* provider, const char* key);

	BINARYNINJACOREAPI BNSymbolQueue* BNCreateSymbolQueue(void);
	BINARYNINJACOREAPI void BNDestroySymbolQueue(BNSymbolQueue* queue);
	BINARYNINJACOREAPI void BNAppendSymbolQueue(BNSymbolQueue* queue,
		void (*resolve)(void* ctxt, BNSymbol** symbol, BNType** type), void* resolveContext,
		void (*add)(void* ctxt, BNSymbol* symbol, BNType* type), void* addContext);
	BINARYNINJACOREAPI void BNProcessSymbolQueue(BNSymbolQueue* queue);

	BINARYNINJACOREAPI bool BNCoreEnumToString(const char* enumName, size_t value, char** result);
	BINARYNINJACOREAPI bool BNCoreEnumFromString(const char* enumName, const char* value, size_t* result);

	// Type Archives
	BINARYNINJACOREAPI BNTypeArchive* BNNewTypeArchiveReference(BNTypeArchive* archive);
	BINARYNINJACOREAPI void BNFreeTypeArchiveReference(BNTypeArchive* archive);
	BINARYNINJACOREAPI void BNFreeTypeArchiveList(BNTypeArchive** archives, size_t count);
	BINARYNINJACOREAPI BNTypeArchive* BNOpenTypeArchive(const char* path);
	BINARYNINJACOREAPI BNTypeArchive* BNCreateTypeArchive(const char* path, BNPlatform* platform);
	BINARYNINJACOREAPI BNTypeArchive* BNCreateTypeArchiveWithId(const char* path, BNPlatform* platform, const char* id);
	BINARYNINJACOREAPI BNTypeArchive* BNLookupTypeArchiveById(const char* id);
	BINARYNINJACOREAPI void BNCloseTypeArchive(BNTypeArchive* archive);
	BINARYNINJACOREAPI bool BNIsTypeArchive(const char* path);
	BINARYNINJACOREAPI char* BNGetTypeArchiveId(BNTypeArchive* archive);
	BINARYNINJACOREAPI char* BNGetTypeArchivePath(BNTypeArchive* archive);
	BINARYNINJACOREAPI BNPlatform* BNGetTypeArchivePlatform(BNTypeArchive* archive);
	BINARYNINJACOREAPI char* BNGetTypeArchiveCurrentSnapshotId(BNTypeArchive* archive);
	BINARYNINJACOREAPI void BNSetTypeArchiveCurrentSnapshot(BNTypeArchive* archive, const char* id);
	BINARYNINJACOREAPI char** BNGetTypeArchiveAllSnapshotIds(BNTypeArchive* archive, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveSnapshotParentIds(BNTypeArchive* archive, const char* id, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveSnapshotChildIds(BNTypeArchive* archive, const char* id, size_t* count);
	BINARYNINJACOREAPI BNTypeContainer* BNGetTypeArchiveTypeContainer(BNTypeArchive* archive);
	BINARYNINJACOREAPI bool BNAddTypeArchiveTypes(BNTypeArchive* archive, const BNQualifiedNameAndType* types, size_t count);
	BINARYNINJACOREAPI bool BNRenameTypeArchiveType(BNTypeArchive* archive, const char* id, const BNQualifiedName* newName);
	BINARYNINJACOREAPI bool BNDeleteTypeArchiveType(BNTypeArchive* archive, const char* id);
	BINARYNINJACOREAPI BNType* BNGetTypeArchiveTypeById(BNTypeArchive* archive, const char* id, const char* snapshot);
	BINARYNINJACOREAPI BNType* BNGetTypeArchiveTypeByName(BNTypeArchive* archive, const BNQualifiedName* name, const char* snapshot);
	BINARYNINJACOREAPI char* BNGetTypeArchiveTypeId(BNTypeArchive* archive, const BNQualifiedName* name, const char* snapshot);
	BINARYNINJACOREAPI BNQualifiedName BNGetTypeArchiveTypeName(BNTypeArchive* archive, const char* id, const char* snapshot);
	BINARYNINJACOREAPI BNQualifiedNameTypeAndId* BNGetTypeArchiveTypes(BNTypeArchive* archive, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveTypeIds(BNTypeArchive* archive, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI BNQualifiedName* BNGetTypeArchiveTypeNames(BNTypeArchive* archive, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI bool BNGetTypeArchiveTypeNamesAndIds(BNTypeArchive* archive, const char* snapshot, BNQualifiedName** names, char*** ids, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveOutgoingDirectTypeReferences(BNTypeArchive* archive, const char* id, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveOutgoingRecursiveTypeReferences(BNTypeArchive* archive, const char* id, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveIncomingDirectTypeReferences(BNTypeArchive* archive, const char* id, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI char** BNGetTypeArchiveIncomingRecursiveTypeReferences(BNTypeArchive* archive, const char* id, const char* snapshot, size_t* count);
	BINARYNINJACOREAPI char* BNTypeArchiveNewSnapshotTransaction(BNTypeArchive* archive, bool(*func)(void* context, const char* id), void* context, const char* const* parents, size_t parentCount);
	BINARYNINJACOREAPI void BNRegisterTypeArchiveNotification(BNTypeArchive* archive, BNTypeArchiveNotification* notification);
	BINARYNINJACOREAPI void BNUnregisterTypeArchiveNotification(BNTypeArchive* archive, BNTypeArchiveNotification* notification);
	BINARYNINJACOREAPI bool BNTypeArchiveStoreMetadata(BNTypeArchive* archive, const char* key, BNMetadata* value);
	BINARYNINJACOREAPI BNMetadata* BNTypeArchiveQueryMetadata(BNTypeArchive* archive, const char* key);
	BINARYNINJACOREAPI bool BNTypeArchiveRemoveMetadata(BNTypeArchive* archive, const char* key);
	BINARYNINJACOREAPI BNDataBuffer* BNTypeArchiveSerializeSnapshot(BNTypeArchive* archive, const char* snapshot);
	BINARYNINJACOREAPI char* BNTypeArchiveDeserializeSnapshot(BNTypeArchive* archive, BNDataBuffer* buffer);
	BINARYNINJACOREAPI bool BNTypeArchiveMergeSnapshots(
		BNTypeArchive* archive,
		const char* baseSnapshot,
		const char* firstSnapshot,
		const char* secondSnapshot,
		const char* const* mergeConflictKeysIn,
		const char* const* mergeConflictValuesIn,
		size_t mergeConflictCountIn,
		char*** mergeConflictsOut,
		size_t* mergeConflictCountOut,
		char** result,
		BNProgressFunction progress,
		void* context
	);

	BINARYNINJACOREAPI BNTypeArchive* BNBinaryViewAttachTypeArchive(BNBinaryView* view, const char* id, const char* path);
	BINARYNINJACOREAPI bool BNBinaryViewDetachTypeArchive(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI BNTypeArchive* BNBinaryViewGetTypeArchive(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI size_t BNBinaryViewGetTypeArchives(BNBinaryView* view, char*** ids, char*** paths);
	BINARYNINJACOREAPI char* BNBinaryViewGetTypeArchivePath(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI size_t BNBinaryViewGetTypeArchiveTypeNameList(BNBinaryView* view, BNQualifiedName** names);
	BINARYNINJACOREAPI size_t BNBinaryViewGetTypeArchiveTypeNames(BNBinaryView* view, BNQualifiedName* name, char*** archiveIds, char*** archiveTypeIds);
	BINARYNINJACOREAPI size_t BNBinaryViewGetAssociatedTypeArchiveTypes(BNBinaryView* view, char*** typeIds, char*** archiveIds, char*** archiveTypeIds);
	BINARYNINJACOREAPI size_t BNBinaryViewGetAssociatedTypesFromArchive(BNBinaryView* view, const char* archiveId, char*** typeIds, char*** archiveTypeIds);
	BINARYNINJACOREAPI bool BNBinaryViewGetAssociatedTypeArchiveTypeTarget(BNBinaryView* view, const char* typeId, char** archiveId, char** archiveTypeId);
	BINARYNINJACOREAPI bool BNBinaryViewGetAssociatedTypeArchiveTypeSource(BNBinaryView* view, const char* archiveId, const char* archiveTypeId, char** typeId);
	BINARYNINJACOREAPI BNSyncStatus BNBinaryViewGetTypeArchiveSyncStatus(BNBinaryView* view, const char* typeId);
	BINARYNINJACOREAPI bool BNBinaryViewDisassociateTypeArchiveType(BNBinaryView* view, const char* typeId);
	BINARYNINJACOREAPI bool BNBinaryViewPullTypeArchiveTypes(BNBinaryView* view, const char* archiveId, const char* const* archiveTypeIds, size_t archiveTypeIdCount, char*** updatedArchiveTypeIds, char*** updatedAnalysisTypeIds,  size_t* updatedTypeCount);
	BINARYNINJACOREAPI bool BNBinaryViewPushTypeArchiveTypes(BNBinaryView* view, const char* archiveId, const char* const* typeIds, size_t typeIdCount, char*** updatedAnalysisTypeIds, char*** updatedArchiveTypeIds,  size_t* updatedTypeCount);

	// Base Address Detection
	BINARYNINJACOREAPI BNBaseAddressDetection* BNCreateBaseAddressDetection(BNBinaryView *view);
	BINARYNINJACOREAPI bool BNDetectBaseAddress(BNBaseAddressDetection* bad, BNBaseAddressDetectionSettings& settings);
	BINARYNINJACOREAPI size_t BNGetBaseAddressDetectionScores(BNBaseAddressDetection* bad, BNBaseAddressDetectionScore* scores, size_t count,
		BNBaseAddressDetectionConfidence* confidence, uint64_t* lastTestedBaseAddress);
	BINARYNINJACOREAPI BNBaseAddressDetectionReason* BNGetBaseAddressDetectionReasons(BNBaseAddressDetection* bad,
		uint64_t baseAddress, size_t* count);
	BINARYNINJACOREAPI void BNFreeBaseAddressDetectionReasons(BNBaseAddressDetectionReason* reasons);
	BINARYNINJACOREAPI void BNAbortBaseAddressDetection(BNBaseAddressDetection* bad);
	BINARYNINJACOREAPI bool BNIsBaseAddressDetectionAborted(BNBaseAddressDetection* bad);
	BINARYNINJACOREAPI void BNFreeBaseAddressDetection(BNBaseAddressDetection* bad);

	// Collaboration
	BINARYNINJACOREAPI BNRemote* BNCollaborationGetActiveRemote();
	BINARYNINJACOREAPI void BNCollaborationSetActiveRemote(BNRemote* remote);
	BINARYNINJACOREAPI bool BNCollaborationStoreDataInKeychain(const char* key, const char** dataKeys, const char** dataValues, size_t dataCount);
	BINARYNINJACOREAPI bool BNCollaborationHasDataInKeychain(const char* key);
	BINARYNINJACOREAPI size_t BNCollaborationGetDataFromKeychain(const char* key, char*** foundKeys, char*** foundValues);
	BINARYNINJACOREAPI bool BNCollaborationDeleteDataFromKeychain(const char* key);
	BINARYNINJACOREAPI bool BNCollaborationLoadRemotes();
	BINARYNINJACOREAPI BNRemote** BNCollaborationGetRemotes(size_t* count);
	BINARYNINJACOREAPI BNRemote* BNCollaborationGetRemoteById(const char* remoteId);
	BINARYNINJACOREAPI BNRemote* BNCollaborationGetRemoteByAddress(const char* remoteAddress);
	BINARYNINJACOREAPI BNRemote* BNCollaborationGetRemoteByName(const char* name);
	BINARYNINJACOREAPI BNRemote* BNCollaborationCreateRemote(const char* name, const char* address);
	BINARYNINJACOREAPI void BNCollaborationRemoveRemote(BNRemote* remote);
	BINARYNINJACOREAPI void BNCollaborationSaveRemotes();
	BINARYNINJACOREAPI bool BNCollaborationSyncDatabase(BNDatabase* database, BNRemoteFile* file, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressCtxt, BNCollaborationNameChangesetFunction nameChangeset, void* nameChangesetCtxt);
	BINARYNINJACOREAPI bool BNCollaborationSyncTypeArchive(BNTypeArchive* archive, BNRemoteFile* file, bool(*conflictHandler)(void*, BNTypeArchiveMergeConflict** conflicts, size_t conflictCount), void* conflictHandlerCtxt, BNProgressFunction progress, void* progressCtxt);
	BINARYNINJACOREAPI bool BNCollaborationPushTypeArchive(BNTypeArchive* archive, BNRemoteFile* file, size_t* count, BNProgressFunction progress, void* progressCtxt);
	BINARYNINJACOREAPI bool BNCollaborationPullTypeArchive(BNTypeArchive* archive, BNRemoteFile* file, size_t* count, bool(*conflictHandler)(void*, BNTypeArchiveMergeConflict** conflicts, size_t conflictCount), void* conflictHandlerCtxt, BNProgressFunction progress, void* progressCtxt);
	BINARYNINJACOREAPI bool BNCollaborationIsCollaborationTypeArchive(BNTypeArchive* archive);
	BINARYNINJACOREAPI BNRemote* BNCollaborationGetRemoteForLocalTypeArchive(BNTypeArchive* archive);
	BINARYNINJACOREAPI BNRemoteProject* BNCollaborationGetRemoteProjectForLocalTypeArchive(BNTypeArchive* archive);
	BINARYNINJACOREAPI BNRemoteFile* BNCollaborationGetRemoteFileForLocalTypeArchive(BNTypeArchive* archive);
	BINARYNINJACOREAPI BNCollaborationSnapshot* BNCollaborationGetRemoteSnapshotFromLocalTypeArchive(BNTypeArchive* archive, const char* snapshotId);
	BINARYNINJACOREAPI char* BNCollaborationGetLocalSnapshotFromRemoteTypeArchive(BNCollaborationSnapshot* snapshot, BNTypeArchive* archive);
	BINARYNINJACOREAPI bool BNCollaborationIsTypeArchiveSnapshotIgnored(BNTypeArchive* archive, const char* snapshot);
	BINARYNINJACOREAPI bool BNCollaborationSetSnapshotAuthor(BNDatabase* database, BNSnapshot* snapshot, const char* author);
	BINARYNINJACOREAPI char* BNCollaborationDefaultProjectPath(BNRemoteProject* project);
	BINARYNINJACOREAPI char* BNCollaborationDefaultFilePath(BNRemoteFile* file);
	BINARYNINJACOREAPI BNFileMetadata* BNCollaborationDownloadFile(BNRemoteFile* file, const char* dbPath, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNRemoteFile* BNCollaborationUploadDatabase(BNFileMetadata* metadata, BNRemoteProject* project, BNRemoteFolder* folder, BNProgressFunction progress, void* progressContext, BNCollaborationNameChangesetFunction nameChangeset, void* nameChangesetContext);
	BINARYNINJACOREAPI bool BNCollaborationIsCollaborationDatabase(BNDatabase* database);
	BINARYNINJACOREAPI bool BNCollaborationGetRemoteForLocalDatabase(BNDatabase* database, BNRemote** result);
	BINARYNINJACOREAPI bool BNCollaborationGetRemoteProjectForLocalDatabase(BNDatabase* database, BNRemoteProject** result);
	BINARYNINJACOREAPI bool BNCollaborationGetRemoteFileForLocalDatabase(BNDatabase* database, BNRemoteFile** result);
	BINARYNINJACOREAPI bool BNCollaborationAssignSnapshotMap(BNSnapshot* localSnapshot, BNCollaborationSnapshot* remoteSnapshot);
	BINARYNINJACOREAPI bool BNCollaborationGetRemoteSnapshotFromLocal(BNSnapshot* snapshot, BNCollaborationSnapshot** result);
	BINARYNINJACOREAPI bool BNCollaborationGetLocalSnapshotFromRemote(BNCollaborationSnapshot* snapshot, BNDatabase* database, BNSnapshot** result);
	BINARYNINJACOREAPI bool BNCollaborationDownloadTypeArchive(BNRemoteFile* file, const char* dbPath, BNProgressFunction progress, void* progressContext, BNTypeArchive** result);
	BINARYNINJACOREAPI bool BNCollaborationUploadTypeArchive(BNTypeArchive* archive, BNRemoteProject* project, BNRemoteFolder* folder, BNProgressFunction progress, void* progressContext, BNProjectFile* coreFile, BNRemoteFile** result);
	BINARYNINJACOREAPI bool BNCollaborationDownloadDatabaseForFile(BNRemoteFile* file, const char* dbPath, bool force, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNSnapshot* BNCollaborationMergeSnapshots(BNSnapshot* first, BNSnapshot* second, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNCollaborationPullDatabase(BNDatabase* database, BNRemoteFile* file, size_t* count, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressContext, BNCollaborationNameChangesetFunction nameChangeset, void* nameChangesetContext);
	BINARYNINJACOREAPI bool BNCollaborationMergeDatabase(BNDatabase* database, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNCollaborationPushDatabase(BNDatabase* database, BNRemoteFile* file, size_t* count, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNCollaborationDumpDatabase(BNDatabase* database);
	BINARYNINJACOREAPI bool BNCollaborationIgnoreSnapshot(BNDatabase* database, BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNCollaborationIsSnapshotIgnored(BNDatabase* database, BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNCollaborationGetSnapshotAuthor(BNDatabase* database, BNSnapshot* snapshot, char** result);
	BINARYNINJACOREAPI void BNCollaborationFreeIdList(uint64_t* ids, size_t size);
	BINARYNINJACOREAPI void BNCollaborationFreeSnapshotIdList(int64_t* ids, size_t size);

	// LazyT
	BINARYNINJACOREAPI BNCollaborationLazyT* BNCollaborationLazyTCreate(void*(*ctor)(void*), void* context);
	BINARYNINJACOREAPI void* BNCollaborationLazyTDereference(BNCollaborationLazyT* lazyT);
	BINARYNINJACOREAPI void  BNCollaborationFreeLazyT(BNCollaborationLazyT* lazyT);

	// Remote
	BINARYNINJACOREAPI BNRemote* BNNewRemoteReference(BNRemote* remote);
	BINARYNINJACOREAPI void BNFreeRemote(BNRemote* remote);
	BINARYNINJACOREAPI void BNFreeRemoteList(BNRemote** remotes, size_t count);
	BINARYNINJACOREAPI char* BNRemoteGetUniqueId(BNRemote* remote);
	BINARYNINJACOREAPI char* BNRemoteGetName(BNRemote* remote);
	BINARYNINJACOREAPI char* BNRemoteGetAddress(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteHasLoadedMetadata(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteIsConnected(BNRemote* remote);
	BINARYNINJACOREAPI char* BNRemoteGetUsername(BNRemote* remote);
	BINARYNINJACOREAPI char* BNRemoteGetToken(BNRemote* remote);
	BINARYNINJACOREAPI int BNRemoteGetServerVersion(BNRemote* remote);
	BINARYNINJACOREAPI char* BNRemoteGetServerBuildId(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteGetAuthBackends(BNRemote* remote, char*** backendIds, char*** backendNames, size_t* count);
	BINARYNINJACOREAPI bool BNRemoteHasPulledProjects(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteHasPulledUsers(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteHasPulledGroups(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteIsAdmin(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteIsEnterprise(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteLoadMetadata(BNRemote* remote);
	BINARYNINJACOREAPI char* BNRemoteRequestAuthenticationToken(BNRemote* remote, const char* username, const char* password);
	BINARYNINJACOREAPI bool BNRemoteConnect(BNRemote* remote, const char* username, const char* token);
	BINARYNINJACOREAPI bool BNRemoteDisconnect(BNRemote* remote);
	BINARYNINJACOREAPI BNRemoteProject** BNRemoteGetProjects(BNRemote* remote, size_t* count);
	BINARYNINJACOREAPI BNRemoteProject* BNRemoteGetProjectById(BNRemote* remote, const char* id);
	BINARYNINJACOREAPI BNRemoteProject* BNRemoteGetProjectByName(BNRemote* remote, const char* name);
	BINARYNINJACOREAPI bool BNRemotePullProjects(BNRemote* remote, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNRemoteProject* BNRemoteCreateProject(BNRemote* remote, const char* name, const char* description);
	BINARYNINJACOREAPI BNRemoteProject* BNRemoteImportLocalProject(BNRemote* remote, BNProject* localProject, bool (*progress)(void*, size_t, size_t), void* progressCtxt);
	BINARYNINJACOREAPI bool BNRemotePushProject(BNRemote* remote, BNRemoteProject* project, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount);
	BINARYNINJACOREAPI bool BNRemoteDeleteProject(BNRemote* remote, BNRemoteProject* project);
	BINARYNINJACOREAPI BNCollaborationGroup** BNRemoteGetGroups(BNRemote* remote, size_t* count);
	BINARYNINJACOREAPI BNCollaborationGroup* BNRemoteGetGroupById(BNRemote* remote, uint64_t id);
	BINARYNINJACOREAPI BNCollaborationGroup* BNRemoteGetGroupByName(BNRemote* remote, const char* name);
	BINARYNINJACOREAPI bool BNRemoteSearchGroups(BNRemote* remote, const char* prefix, uint64_t** groupIds, char*** groupNames, size_t* count);
	BINARYNINJACOREAPI bool BNRemotePullGroups(BNRemote* remote, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNCollaborationGroup* BNRemoteCreateGroup(BNRemote* remote, const char* name, const char** usernames, size_t usernameCount);
	BINARYNINJACOREAPI bool BNRemotePushGroup(BNRemote* remote, BNCollaborationGroup* group, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount);
	BINARYNINJACOREAPI bool BNRemoteDeleteGroup(BNRemote* remote, BNCollaborationGroup* group);
	BINARYNINJACOREAPI BNCollaborationUser** BNRemoteGetUsers(BNRemote* remote, size_t* count);
	BINARYNINJACOREAPI BNCollaborationUser* BNRemoteGetUserById(BNRemote* remote, const char* id);
	BINARYNINJACOREAPI BNCollaborationUser* BNRemoteGetUserByUsername(BNRemote* remote, const char* username);
	BINARYNINJACOREAPI BNCollaborationUser* BNRemoteGetCurrentUser(BNRemote* remote);
	BINARYNINJACOREAPI bool BNRemoteSearchUsers(BNRemote* remote, const char* prefix, char*** userIds, char*** usernames, size_t* count);
	BINARYNINJACOREAPI bool BNRemotePullUsers(BNRemote* remote, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNCollaborationUser* BNRemoteCreateUser(BNRemote* remote, const char* username, const char* email, bool isActive, const char* password, const uint64_t* groupIds, size_t groupIdCount, const uint64_t* userPermissionIds, size_t userPermissionIdCount);
	BINARYNINJACOREAPI bool BNRemotePushUser(BNRemote* remote, BNCollaborationUser* user, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount);
	BINARYNINJACOREAPI int BNRemoteRequest(BNRemote* remote, void* request, void* ret);

	// CollabGroup
	BINARYNINJACOREAPI BNCollaborationGroup* BNNewCollaborationGroupReference(BNCollaborationGroup* group);
	BINARYNINJACOREAPI void BNFreeCollaborationGroup(BNCollaborationGroup* group);
	BINARYNINJACOREAPI void BNFreeCollaborationGroupList(BNCollaborationGroup** group, size_t count);
	BINARYNINJACOREAPI BNRemote* BNCollaborationGroupGetRemote(BNCollaborationGroup* group);
	BINARYNINJACOREAPI char* BNCollaborationGroupGetUrl(BNCollaborationGroup* group);
	BINARYNINJACOREAPI uint64_t BNCollaborationGroupGetId(BNCollaborationGroup* group);
	BINARYNINJACOREAPI char* BNCollaborationGroupGetName(BNCollaborationGroup* group);
	BINARYNINJACOREAPI void BNCollaborationGroupSetName(BNCollaborationGroup* group, const char* name);
	BINARYNINJACOREAPI bool BNCollaborationGroupGetUsers(BNCollaborationGroup* group, char*** userIds, char*** usernames, size_t* count);
	BINARYNINJACOREAPI bool BNCollaborationGroupSetUsernames(BNCollaborationGroup* group, const char** names, size_t count);
	BINARYNINJACOREAPI bool BNCollaborationGroupContainsUser(BNCollaborationGroup* group, const char* username);

	// CollabUser
	BINARYNINJACOREAPI BNCollaborationUser* BNNewCollaborationUserReference(BNCollaborationUser* user);
	BINARYNINJACOREAPI void BNFreeCollaborationUser(BNCollaborationUser* user);
	BINARYNINJACOREAPI void BNFreeCollaborationUserList(BNCollaborationUser** users, size_t count);
	BINARYNINJACOREAPI BNRemote* BNCollaborationUserGetRemote(BNCollaborationUser* user);
	BINARYNINJACOREAPI char* BNCollaborationUserGetUrl(BNCollaborationUser* user);
	BINARYNINJACOREAPI char* BNCollaborationUserGetId(BNCollaborationUser* user);
	BINARYNINJACOREAPI char* BNCollaborationUserGetUsername(BNCollaborationUser* user);
	BINARYNINJACOREAPI char* BNCollaborationUserGetEmail(BNCollaborationUser* user);
	BINARYNINJACOREAPI char* BNCollaborationUserGetLastLogin(BNCollaborationUser* user);
	BINARYNINJACOREAPI bool BNCollaborationUserIsActive(BNCollaborationUser* user);
	BINARYNINJACOREAPI bool BNCollaborationUserSetUsername(BNCollaborationUser* user, const char* username);
	BINARYNINJACOREAPI bool BNCollaborationUserSetEmail(BNCollaborationUser* user, const char* email);
	BINARYNINJACOREAPI bool BNCollaborationUserSetIsActive(BNCollaborationUser* user, bool isActive);

	// RemoteProject
	BINARYNINJACOREAPI BNRemoteProject* BNNewRemoteProjectReference(BNRemoteProject* project);
	BINARYNINJACOREAPI void BNFreeRemoteProject(BNRemoteProject* project);
	BINARYNINJACOREAPI void BNFreeRemoteProjectList(BNRemoteProject** projects, size_t count);
	BINARYNINJACOREAPI BNProject* BNRemoteProjectGetCoreProject(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectIsOpen(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectOpen(BNRemoteProject* project, bool (*progress)(void*, size_t, size_t), void* progressCtxt);
	BINARYNINJACOREAPI void BNRemoteProjectClose(BNRemoteProject* project);
	BINARYNINJACOREAPI BNRemote* BNRemoteProjectGetRemote(BNRemoteProject* project);
	BINARYNINJACOREAPI char* BNRemoteProjectGetUrl(BNRemoteProject* project);
	BINARYNINJACOREAPI int64_t BNRemoteProjectGetCreated(BNRemoteProject* project);
	BINARYNINJACOREAPI int64_t BNRemoteProjectGetLastModified(BNRemoteProject* project);
	BINARYNINJACOREAPI char* BNRemoteProjectGetId(BNRemoteProject* project);
	BINARYNINJACOREAPI char* BNRemoteProjectGetName(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectSetName(BNRemoteProject* project, const char* name);
	BINARYNINJACOREAPI char* BNRemoteProjectGetDescription(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectSetDescription(BNRemoteProject* project, const char* description);
	BINARYNINJACOREAPI uint64_t BNRemoteProjectGetReceivedFileCount(BNRemoteProject* project);
	BINARYNINJACOREAPI uint64_t BNRemoteProjectGetReceivedFolderCount(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectHasPulledFiles(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectHasPulledFolders(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectHasPulledGroupPermissions(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectHasPulledUserPermissions(BNRemoteProject* project);
	BINARYNINJACOREAPI bool BNRemoteProjectIsAdmin(BNRemoteProject* project);
	BINARYNINJACOREAPI BNRemoteFile** BNRemoteProjectGetFiles(BNRemoteProject* project, size_t* count);
	BINARYNINJACOREAPI BNRemoteFile* BNRemoteProjectGetFileById(BNRemoteProject* project, const char* id);
	BINARYNINJACOREAPI BNRemoteFile* BNRemoteProjectGetFileByName(BNRemoteProject* project, const char* name);
	BINARYNINJACOREAPI bool BNRemoteProjectPullFiles(BNRemoteProject* project, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNRemoteFile* BNRemoteProjectCreateFile(BNRemoteProject* project, const char* filename, uint8_t* contents, size_t contentsSize, const char* name, const char* description, BNRemoteFolder* folder, BNRemoteFileType type, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNRemoteProjectPushFile(BNRemoteProject* project, BNRemoteFile* file, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount);
	BINARYNINJACOREAPI bool BNRemoteProjectDeleteFile(BNRemoteProject* project, BNRemoteFile* file);
	BINARYNINJACOREAPI BNRemoteFolder** BNRemoteProjectGetFolders(BNRemoteProject* project, size_t* count);
	BINARYNINJACOREAPI BNRemoteFolder* BNRemoteProjectGetFolderById(BNRemoteProject* project, const char* id);
	BINARYNINJACOREAPI bool BNRemoteProjectPullFolders(BNRemoteProject* project, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNRemoteFolder* BNRemoteProjectCreateFolder(BNRemoteProject* project, const char* name, const char* description, BNRemoteFolder* parent, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNRemoteProjectPushFolder(BNRemoteProject* project, BNRemoteFolder* folder, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount);
	BINARYNINJACOREAPI bool BNRemoteProjectDeleteFolder(BNRemoteProject* project, BNRemoteFolder* folder);
	BINARYNINJACOREAPI BNCollaborationPermission** BNRemoteProjectGetGroupPermissions(BNRemoteProject* project, size_t* count);
	BINARYNINJACOREAPI BNCollaborationPermission** BNRemoteProjectGetUserPermissions(BNRemoteProject* project, size_t* count);
	BINARYNINJACOREAPI BNCollaborationPermission* BNRemoteProjectGetPermissionById(BNRemoteProject* project, const char* id);
	BINARYNINJACOREAPI bool BNRemoteProjectPullGroupPermissions(BNRemoteProject* project, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNRemoteProjectPullUserPermissions(BNRemoteProject* project, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNCollaborationPermission* BNRemoteProjectCreateGroupPermission(BNRemoteProject* project, int64_t groupId, BNCollaborationPermissionLevel level, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNCollaborationPermission* BNRemoteProjectCreateUserPermission(BNRemoteProject* project, const char* userId, BNCollaborationPermissionLevel level, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNRemoteProjectPushPermission(BNRemoteProject* project, BNCollaborationPermission* permission, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount);
	BINARYNINJACOREAPI bool BNRemoteProjectDeletePermission(BNRemoteProject* project, BNCollaborationPermission* permission);
	BINARYNINJACOREAPI bool BNRemoteProjectCanUserView(BNRemoteProject* project, const char* username);
	BINARYNINJACOREAPI bool BNRemoteProjectCanUserEdit(BNRemoteProject* project, const char* username);
	BINARYNINJACOREAPI bool BNRemoteProjectCanUserAdmin(BNRemoteProject* project, const char* username);

	// RemoteFile
	BINARYNINJACOREAPI BNRemoteFile* BNNewRemoteFileReference(BNRemoteFile* file);
	BINARYNINJACOREAPI void BNFreeRemoteFile(BNRemoteFile* file);
	BINARYNINJACOREAPI void BNFreeRemoteFileList(BNRemoteFile** files, size_t count);
	BINARYNINJACOREAPI BNProjectFile* BNRemoteFileGetCoreFile(BNRemoteFile* file);
	BINARYNINJACOREAPI BNRemoteProject* BNRemoteFileGetProject(BNRemoteFile* file);
	BINARYNINJACOREAPI BNRemoteFolder* BNRemoteFileGetFolder(BNRemoteFile* file);
	BINARYNINJACOREAPI BNRemote* BNRemoteFileGetRemote(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetUrl(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetChatLogUrl(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetUserPositionsUrl(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetId(BNRemoteFile* file);
	BINARYNINJACOREAPI BNRemoteFileType BNRemoteFileGetType(BNRemoteFile* file);
	BINARYNINJACOREAPI int64_t BNRemoteFileGetCreated(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetCreatedBy(BNRemoteFile* file);
	BINARYNINJACOREAPI int64_t BNRemoteFileGetLastModified(BNRemoteFile* file);
	BINARYNINJACOREAPI int64_t BNRemoteFileGetLastSnapshot(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetLastSnapshotBy(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetLastSnapshotName(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetHash(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetName(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetDescription(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileGetMetadata(BNRemoteFile* file);
	BINARYNINJACOREAPI uint64_t BNRemoteFileGetSize(BNRemoteFile* file);
	BINARYNINJACOREAPI bool BNRemoteFileHasPulledSnapshots(BNRemoteFile* file);
	BINARYNINJACOREAPI bool BNRemoteFileSetName(BNRemoteFile* file, const char* name);
	BINARYNINJACOREAPI bool BNRemoteFileSetDescription(BNRemoteFile* file, const char* description);
	BINARYNINJACOREAPI bool BNRemoteFileSetFolder(BNRemoteFile* file, BNRemoteFolder* folder);
	BINARYNINJACOREAPI bool BNRemoteFileSetMetadata(BNRemoteFile* file, const char* metadata);
	BINARYNINJACOREAPI BNCollaborationSnapshot** BNRemoteFileGetSnapshots(BNRemoteFile* file, size_t* count);
	BINARYNINJACOREAPI BNCollaborationSnapshot* BNRemoteFileGetSnapshotById(BNRemoteFile* file, const char* id);
	BINARYNINJACOREAPI bool BNRemoteFilePullSnapshots(BNRemoteFile* file, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNCollaborationSnapshot* BNRemoteFileCreateSnapshot(BNRemoteFile* file, const char* name, uint8_t* contents, size_t contentsSize, uint8_t* analysisCacheContents, size_t analysisCacheContentsSize, uint8_t* fileContents, size_t fileContentsSize, const char** parentIds, size_t parentIdCount, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI bool BNRemoteFileDeleteSnapshot(BNRemoteFile* file, BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNRemoteFileDownload(BNRemoteFile* file, BNProgressFunction progress, void* progressCtxt, uint8_t** data, size_t* size);
	BINARYNINJACOREAPI char* BNRemoteFileRequestUserPositions(BNRemoteFile* file);
	BINARYNINJACOREAPI char* BNRemoteFileRequestChatLog(BNRemoteFile* file);

	// RemoteFolder
	BINARYNINJACOREAPI BNRemoteFolder* BNNewRemoteFolderReference(BNRemoteFolder* folder);
	BINARYNINJACOREAPI void BNFreeRemoteFolder(BNRemoteFolder* folder);
	BINARYNINJACOREAPI void BNFreeRemoteFolderList(BNRemoteFolder** folders, size_t count);
	BINARYNINJACOREAPI BNProjectFolder* BNRemoteFolderGetCoreFolder(BNRemoteFolder* folder);
	BINARYNINJACOREAPI BNRemoteProject* BNRemoteFolderGetProject(BNRemoteFolder* folder);
	BINARYNINJACOREAPI BNRemote* BNRemoteFolderGetRemote(BNRemoteFolder* folder);
	BINARYNINJACOREAPI bool BNRemoteFolderGetParent(BNRemoteFolder* folder, BNRemoteFolder** parent);
	BINARYNINJACOREAPI char* BNRemoteFolderGetUrl(BNRemoteFolder* folder);
	BINARYNINJACOREAPI char* BNRemoteFolderGetId(BNRemoteFolder* folder);
	BINARYNINJACOREAPI bool BNRemoteFolderGetParentId(BNRemoteFolder* folder, char** result);
	BINARYNINJACOREAPI char* BNRemoteFolderGetName(BNRemoteFolder* folder);
	BINARYNINJACOREAPI char* BNRemoteFolderGetDescription(BNRemoteFolder* folder);
	BINARYNINJACOREAPI bool BNRemoteFolderSetName(BNRemoteFolder* folder, const char* name);
	BINARYNINJACOREAPI bool BNRemoteFolderSetDescription(BNRemoteFolder* folder, const char* description);
	BINARYNINJACOREAPI bool BNRemoteFolderSetParent(BNRemoteFolder* folder, BNRemoteFolder* parent);

	// CollabPermission
	BINARYNINJACOREAPI BNCollaborationPermission* BNNewCollaborationPermissionReference(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI void BNFreeCollaborationPermission(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI void BNFreeCollaborationPermissionList(BNCollaborationPermission** permissions, size_t count);
	BINARYNINJACOREAPI BNRemoteProject* BNCollaborationPermissionGetProject(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI BNRemote* BNCollaborationPermissionGetRemote(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI char* BNCollaborationPermissionGetId(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI char* BNCollaborationPermissionGetUrl(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI uint64_t BNCollaborationPermissionGetGroupId(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI char* BNCollaborationPermissionGetGroupName(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI char* BNCollaborationPermissionGetUserId(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI char* BNCollaborationPermissionGetUsername(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI BNCollaborationPermissionLevel BNCollaborationPermissionGetLevel(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI void BNCollaborationPermissionSetLevel(BNCollaborationPermission* permission, BNCollaborationPermissionLevel level);
	BINARYNINJACOREAPI bool BNCollaborationPermissionCanView(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI bool BNCollaborationPermissionCanEdit(BNCollaborationPermission* permission);
	BINARYNINJACOREAPI bool BNCollaborationPermissionCanAdmin(BNCollaborationPermission* permission);

	// AnalysisMergeConflict
	BINARYNINJACOREAPI BNAnalysisMergeConflict* BNNewAnalysisMergeConflictReference(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI void BNFreeAnalysisMergeConflict(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI void BNFreeAnalysisMergeConflictList(BNAnalysisMergeConflict** conflicts, size_t count);
	BINARYNINJACOREAPI BNDatabase* BNAnalysisMergeConflictGetDatabase(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictGetType(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictGetKey(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNMergeConflictDataType BNAnalysisMergeConflictGetDataType(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictGetBase(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictGetFirst(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictGetSecond(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNFileMetadata* BNAnalysisMergeConflictGetBaseFile(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNFileMetadata* BNAnalysisMergeConflictGetFirstFile(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNFileMetadata* BNAnalysisMergeConflictGetSecondFile(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNSnapshot* BNAnalysisMergeConflictGetBaseSnapshot(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNSnapshot* BNAnalysisMergeConflictGetFirstSnapshot(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI BNSnapshot* BNAnalysisMergeConflictGetSecondSnapshot(BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictGetPathItemString(BNAnalysisMergeConflict* conflict, const char* path);
	BINARYNINJACOREAPI void* BNAnalysisMergeConflictGetPathItem(BNAnalysisMergeConflict* conflict, const char* path);
	BINARYNINJACOREAPI bool BNAnalysisMergeConflictSuccess(BNAnalysisMergeConflict* conflict, const char* value);

	// TypeArchiveMergeConflict
	BINARYNINJACOREAPI BNTypeArchiveMergeConflict* BNNewTypeArchiveMergeConflictReference(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI void BNFreeTypeArchiveMergeConflict(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI void BNFreeTypeArchiveMergeConflictList(BNTypeArchiveMergeConflict** conflicts, size_t count);
	BINARYNINJACOREAPI BNTypeArchive* BNTypeArchiveMergeConflictGetTypeArchive(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNTypeArchiveMergeConflictGetTypeId(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNTypeArchiveMergeConflictGetBaseSnapshotId(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNTypeArchiveMergeConflictGetFirstSnapshotId(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI char* BNTypeArchiveMergeConflictGetSecondSnapshotId(BNTypeArchiveMergeConflict* conflict);
	BINARYNINJACOREAPI bool BNTypeArchiveMergeConflictSuccess(BNTypeArchiveMergeConflict* conflict, const char* value);

	// CollabSnapshot
	BINARYNINJACOREAPI BNCollaborationSnapshot* BNNewCollaborationSnapshotReference(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI void BNFreeCollaborationSnapshot(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI void BNFreeCollaborationSnapshotList(BNCollaborationSnapshot** snapshots, size_t count);
	BINARYNINJACOREAPI BNRemoteFile* BNCollaborationSnapshotGetFile(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI BNRemoteProject* BNCollaborationSnapshotGetProject(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI BNRemote* BNCollaborationSnapshotGetRemote(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetUrl(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetId(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetName(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetAuthor(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI int64_t BNCollaborationSnapshotGetCreated(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI int64_t BNCollaborationSnapshotGetLastModified(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetHash(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetSnapshotFileHash(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotHasPulledUndoEntries(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotIsFinalized(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char** BNCollaborationSnapshotGetParentIds(BNCollaborationSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI char** BNCollaborationSnapshotGetChildIds(BNCollaborationSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI uint64_t BNCollaborationSnapshotGetAnalysisCacheBuildId(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetTitle(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetDescription(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI char* BNCollaborationSnapshotGetAuthorUsername(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI BNCollaborationSnapshot** BNCollaborationSnapshotGetParents(BNCollaborationSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNCollaborationSnapshot** BNCollaborationSnapshotGetChildren(BNCollaborationSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNCollaborationUndoEntry** BNCollaborationSnapshotGetUndoEntries(BNCollaborationSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNCollaborationUndoEntry* BNCollaborationSnapshotGetUndoEntryById(BNCollaborationSnapshot* snapshot, uint64_t id);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotPullUndoEntries(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext);
	BINARYNINJACOREAPI BNCollaborationUndoEntry* BNCollaborationSnapshotCreateUndoEntry(BNCollaborationSnapshot* snapshot, bool hasParent, uint64_t parent, const char* data);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotFinalize(BNCollaborationSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotDownloadSnapshotFile(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext, uint8_t** data, size_t* size);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotDownload(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext, uint8_t** data, size_t* size);
	BINARYNINJACOREAPI bool BNCollaborationSnapshotDownloadAnalysisCache(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext, uint8_t** data, size_t* size);

	// CollabUndoEntry
	BINARYNINJACOREAPI BNCollaborationUndoEntry* BNNewCollaborationUndoEntryReference(BNCollaborationUndoEntry* entry);
	BINARYNINJACOREAPI void BNFreeCollaborationUndoEntry(BNCollaborationUndoEntry* entry);
	BINARYNINJACOREAPI void BNFreeCollaborationUndoEntryList(BNCollaborationUndoEntry** entries, size_t count);
	BINARYNINJACOREAPI BNCollaborationSnapshot* BNCollaborationUndoEntryGetSnapshot(BNCollaborationUndoEntry* undoEntry);
	BINARYNINJACOREAPI BNRemoteFile* BNCollaborationUndoEntryGetFile(BNCollaborationUndoEntry* undoEntry);
	BINARYNINJACOREAPI BNRemoteProject* BNCollaborationUndoEntryGetProject(BNCollaborationUndoEntry* undoEntry);
	BINARYNINJACOREAPI BNRemote* BNCollaborationUndoEntryGetRemote(BNCollaborationUndoEntry* undoEntry);
	BINARYNINJACOREAPI char* BNCollaborationUndoEntryGetUrl(BNCollaborationUndoEntry* undoEntry);
	BINARYNINJACOREAPI uint64_t BNCollaborationUndoEntryGetId(BNCollaborationUndoEntry* undoEntry);
	BINARYNINJACOREAPI bool BNCollaborationUndoEntryGetParentId(BNCollaborationUndoEntry* undoEntry, uint64_t* parentId);
	BINARYNINJACOREAPI bool BNCollaborationUndoEntryGetData(BNCollaborationUndoEntry* undoEntry, char** data);
	BINARYNINJACOREAPI BNCollaborationUndoEntry* BNCollaborationUndoEntryGetParent(BNCollaborationUndoEntry* undoEntry);

	// CollabChangeset
	BINARYNINJACOREAPI BNCollaborationChangeset* BNNewCollaborationChangesetReference(BNCollaborationChangeset* changeset);
	BINARYNINJACOREAPI void BNFreeCollaborationChangeset(BNCollaborationChangeset* changeset);
	BINARYNINJACOREAPI void BNFreeCollaborationChangesetList(BNCollaborationChangeset** changesets, size_t count);
	BINARYNINJACOREAPI BNDatabase* BNCollaborationChangesetGetDatabase(BNCollaborationChangeset* changeset);
	BINARYNINJACOREAPI BNRemoteFile* BNCollaborationChangesetGetFile(BNCollaborationChangeset* changeset);
	BINARYNINJACOREAPI int64_t* BNCollaborationChangesetGetSnapshotIds(BNCollaborationChangeset* changeset, size_t* count);
	BINARYNINJACOREAPI BNCollaborationUser* BNCollaborationChangesetGetAuthor(BNCollaborationChangeset* changeset);
	BINARYNINJACOREAPI char* BNCollaborationChangesetGetName(BNCollaborationChangeset* changeset);
	BINARYNINJACOREAPI bool BNCollaborationChangesetSetName(BNCollaborationChangeset* changeset, const char* name);

	// AnalysisMergeConflictSplitter
	BINARYNINJACOREAPI BNAnalysisMergeConflictSplitter* BNRegisterAnalysisMergeConflictSplitter(BNAnalysisMergeConflictSplitterCallbacks* callbacks);
	BINARYNINJACOREAPI BNAnalysisMergeConflictSplitter** BNGetAnalysisMergeConflictSplitterList(size_t* count);
	BINARYNINJACOREAPI void BNFreeAnalysisMergeConflictSplitterList(BNAnalysisMergeConflictSplitter** splitters, size_t count);
	BINARYNINJACOREAPI char* BNAnalysisMergeConflictSplitterGetName(BNAnalysisMergeConflictSplitter* splitter);
	BINARYNINJACOREAPI bool BNAnalysisMergeConflictSplitterCanSplit(BNAnalysisMergeConflictSplitter* splitter, const char* key, BNAnalysisMergeConflict* conflict);
	BINARYNINJACOREAPI bool BNAnalysisMergeConflictSplitterSplit(BNAnalysisMergeConflictSplitter* splitter, const char* originalKey, BNAnalysisMergeConflict* originalConflict, BNKeyValueStore* result, char*** newKeys, BNAnalysisMergeConflict*** newConflicts, size_t* newCount);

#ifdef __cplusplus
}
#endif

/*!
	@}
*/

#endif
