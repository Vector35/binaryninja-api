import enum


class ActionType(enum.IntEnum):
	TemporaryAction = 0
	DataModificationAction = 1
	AnalysisAction = 2
	DataModificationAndAnalysisAction = 3


class AnalysisMode(enum.IntEnum):
	FullAnalysisMode = 0
	IntermediateAnalysisMode = 1
	BasicAnalysisMode = 2
	ControlFlowAnalysisMode = 3


class AnalysisSkipReason(enum.IntEnum):
	NoSkipReason = 0
	AlwaysSkipReason = 1
	ExceedFunctionSizeSkipReason = 2
	ExceedFunctionAnalysisTimeSkipReason = 3
	ExceedFunctionUpdateCountSkipReason = 4
	NewAutoFunctionAnalysisSuppressedReason = 5
	BasicAnalysisSkipReason = 6
	IntermediateAnalysisSkipReason = 7
	AnalysisPipelineSuspendedReason = 8


class AnalysisState(enum.IntEnum):
	InitialState = 0
	HoldState = 1
	IdleState = 2
	DiscoveryState = 3
	DisassembleState = 4
	AnalyzeState = 5
	ExtendedAnalyzeState = 6


class AnalysisWarningActionType(enum.IntEnum):
	NoAnalysisWarningAction = 0
	ForceAnalysisWarningAction = 1
	ShowStackGraphWarningAction = 2
	DisableGuidedAnalysisWarningAction = 3


class BaseAddressDetectionAnalysisMode(enum.IntEnum):
	InstructionAnalysisBaseAddressDetection = 0
	SamplingBaseAddressDetection = 1


class BaseAddressDetectionConfidence(enum.IntEnum):
	NoConfidence = 0
	LowConfidence = 1
	HighConfidence = 2


class BaseAddressDetectionPOISetting(enum.IntEnum):
	POIAnalysisStringsOnly = 0
	POIAnalysisFunctionsOnly = 1
	POIAnalysisAll = 2


class BaseAddressDetectionPOIType(enum.IntEnum):
	POIString = 0
	POIFunction = 1
	POIDataVariable = 2
	POIFileStart = 3
	POIFileEnd = 4


class BinaryViewEventType(enum.IntEnum):
	BinaryViewFinalizationEvent = 0
	BinaryViewInitialAnalysisCompletionEvent = 1


class BraceRequirement(enum.IntEnum):
	OptionalBraces = 0
	BracesNotAllowed = 1
	BracesAlwaysRequired = 2


class BranchType(enum.IntEnum):
	UnconditionalBranch = 0
	FalseBranch = 1
	TrueBranch = 2
	CallDestination = 3
	FunctionReturn = 4
	SystemCall = 5
	IndirectBranch = 6
	ExceptionBranch = 7
	UnresolvedBranch = 127
	UserDefinedBranch = 128


class BuiltinType(enum.IntEnum):
	BuiltinNone = 0
	BuiltinMemcpy = 1
	BuiltinMemset = 2
	BuiltinStrncpy = 3
	BuiltinStrcpy = 4
	BuiltinWcscpy = 5
	BuiltinWmemcpy = 6


class CallingConventionName(enum.IntEnum):
	NoCallingConvention = 0
	CdeclCallingConvention = 1
	PascalCallingConvention = 2
	ThisCallCallingConvention = 3
	STDCallCallingConvention = 4
	FastcallCallingConvention = 5
	CLRCallCallingConvention = 6
	EabiCallCallingConvention = 7
	VectorCallCallingConvention = 8
	SwiftCallingConvention = 9
	SwiftAsyncCallingConvention = 10


class CollaborationPermissionLevel(enum.IntEnum):
	AdminPermission = 1
	EditPermission = 2
	ViewPermission = 3


class DataFlowQueryOption(enum.IntEnum):
	FromAddressesInLookupTableQueryOption = 0
	AllowReadingWritableMemoryQueryOption = 1


class DeadStoreElimination(enum.IntEnum):
	DefaultDeadStoreElimination = 0
	PreventDeadStoreElimination = 1
	AllowDeadStoreElimination = 2


class DerivedStringLocationType(enum.IntEnum):
	DataBackedStringLocation = 0
	CodeStringLocation = 1


class DisassemblyAddressMode(enum.IntEnum):
	AbsoluteDisassemblyAddressMode = 0
	RelativeToBinaryStartDisassemblyAddressMode = 1
	RelativeToSegmentStartDisassemblyAddressMode = 2
	RelativeToSectionStartDisassemblyAddressMode = 3
	RelativeToFunctionStartDisassemblyAddressMode = 4
	RelativeToAddressBaseOffsetDisassemblyAddressMode = 5
	RelativeToDataStartDisassemblyAddressMode = 6
	DisassemblyAddressModeMask = 65535
	IncludeNameDisassemblyAddressModeFlag = 65536
	DecimalDisassemblyAddressModeFlag = 131072
	DisassemblyAddressModeFlagsMask = 4294901760


class DisassemblyBlockLabels(enum.IntEnum):
	NeverShowDefaultBlockLabels = 0
	AlwaysShowBlockLabels = 1
	NeverShowBlockLabels = 2


class DisassemblyCallParameterHints(enum.IntEnum):
	NeverShowMatchingParameterHints = 0
	AlwaysShowParameterHints = 1
	NeverShowParameterHints = 2


class DisassemblyOption(enum.IntEnum):
	ShowAddress = 0
	ShowOpcode = 1
	ExpandLongOpcode = 2
	ShowVariablesAtTopOfGraph = 3
	ShowVariableTypesWhenAssigned = 4
	ShowRegisterHighlight = 7
	ShowFunctionAddress = 8
	ShowFunctionHeader = 9
	ShowTypeCasts = 10
	GroupLinearDisassemblyFunctions = 64
	HighLevelILLinearDisassembly = 65
	WaitForIL = 66
	IndentHLILBody = 67
	DisableLineFormatting = 68
	ShowFlagUsage = 128
	ShowStackPointer = 129
	ShowILTypes = 130
	ShowILOpcodes = 131
	ShowCollapseIndicators = 132


class EarlyReturn(enum.IntEnum):
	DefaultEarlyReturn = 0
	PreventEarlyReturn = 1
	SmallestSideEarlyReturn = 2
	TrueSideEarlyReturn = 3
	FalseSideEarlyReturn = 4


class EdgePenStyle(enum.IntEnum):
	NoPen = 0
	SolidLine = 1
	DashLine = 2
	DotLine = 3
	DashDotLine = 4
	DashDotDotLine = 5


class Endianness(enum.IntEnum):
	LittleEndian = 0
	BigEndian = 1


class ExprFolding(enum.IntEnum):
	DefaultExprFolding = 0
	PreventExprFolding = 1
	AllowExprFolding = 2


class FindFlag(enum.IntFlag):
	FindCaseSensitive = 0
	FindCaseInsensitive = 1
	FindIgnoreWhitespace = 2


class FindRangeType(enum.IntEnum):
	AllRangeType = 0
	CustomRangeType = 1
	CurrentFunctionRangeType = 2


class FindType(enum.IntEnum):
	FindTypeRawString = 0
	FindTypeEscapedString = 1
	FindTypeText = 2
	FindTypeConstant = 3
	FindTypeBytes = 4


class FirmwareNinjaMemoryAccessType(enum.IntEnum):
	NoMemoryAccessType = 0
	ReadMemoryAccessType = 1
	WriteMemoryAccessType = 2


class FirmwareNinjaMemoryHeuristic(enum.IntEnum):
	NoMemoryHeuristic = 0
	HasReadBarrierMemoryHeuristic = 1
	HasWriteBarrierMemoryHeuristic = 2
	StoreToOOBMemoryMemoryHeuristic = 3
	LoadFromOOBMemoryMemoryHeuristic = 4
	RepeatLoadStoreMemoryHeuristic = 5
	CallParamOOBPointerMemoryHeuristic = 6


class FirmwareNinjaSectionAnalysisMode(enum.IntEnum):
	DefaultSectionAnalysisMode = 0
	IgnorePaddingSectionAnalysisMode = 1
	DetectStringsSectionAnalysisMode = 2


class FirmwareNinjaSectionType(enum.IntEnum):
	CodeSectionType = 0
	DataSectionType = 1
	CompressionSectionType = 2
	PaddingSectionType = 3


class FlagRole(enum.IntEnum):
	SpecialFlagRole = 0
	ZeroFlagRole = 1
	PositiveSignFlagRole = 2
	NegativeSignFlagRole = 3
	CarryFlagRole = 4
	OverflowFlagRole = 5
	HalfCarryFlagRole = 6
	EvenParityFlagRole = 7
	OddParityFlagRole = 8
	OrderedFlagRole = 9
	UnorderedFlagRole = 10
	CarryFlagWithInvertedSubtractRole = 11


class FlowGraphOption(enum.IntEnum):
	FlowGraphUsesBlockHighlights = 0
	FlowGraphUsesInstructionHighlights = 1
	FlowGraphIncludesUserComments = 2
	FlowGraphAllowsPatching = 3
	FlowGraphAllowsInlineInstructionEditing = 4
	FlowGraphShowsSecondaryRegisterHighlighting = 5
	FlowGraphIsAddressable = 6
	FlowGraphIsWorkflowGraph = 7


class ForceVersionReason(enum.IntEnum):
	UserForceVersionReason = 0
	PartialAccessAnalysisForceVersionReason = 1


class FormInputFieldType(enum.IntEnum):
	LabelFormField = 0
	SeparatorFormField = 1
	TextLineFormField = 2
	MultilineTextFormField = 3
	IntegerFormField = 4
	AddressFormField = 5
	ChoiceFormField = 6
	OpenFileNameFormField = 7
	SaveFileNameFormField = 8
	DirectoryNameFormField = 9
	CheckboxFormField = 10


class FunctionAnalysisSkipOverride(enum.IntEnum):
	DefaultFunctionAnalysisSkip = 0
	NeverSkipFunctionAnalysis = 1
	AlwaysSkipFunctionAnalysis = 2


class FunctionGraphType(enum.IntEnum):
	InvalidILViewType = -1
	NormalFunctionGraph = 0
	LowLevelILFunctionGraph = 1
	LiftedILFunctionGraph = 2
	LowLevelILSSAFormFunctionGraph = 3
	MediumLevelILFunctionGraph = 4
	MediumLevelILSSAFormFunctionGraph = 5
	MappedMediumLevelILFunctionGraph = 6
	MappedMediumLevelILSSAFormFunctionGraph = 7
	HighLevelILFunctionGraph = 8
	HighLevelILSSAFormFunctionGraph = 9
	HighLevelLanguageRepresentationFunctionGraph = 10


class FunctionUpdateType(enum.IntEnum):
	UserFunctionUpdate = 0
	FullAutoFunctionUpdate = 1
	IncrementalAutoFunctionUpdate = 2


class HighLevelILOperation(enum.IntEnum):
	HLIL_NOP = 0
	HLIL_BLOCK = 1
	HLIL_IF = 2
	HLIL_WHILE = 3
	HLIL_DO_WHILE = 4
	HLIL_FOR = 5
	HLIL_SWITCH = 6
	HLIL_CASE = 7
	HLIL_BREAK = 8
	HLIL_CONTINUE = 9
	HLIL_JUMP = 10
	HLIL_RET = 11
	HLIL_NORET = 12
	HLIL_GOTO = 13
	HLIL_LABEL = 14
	HLIL_VAR_DECLARE = 15
	HLIL_VAR_INIT = 16
	HLIL_ASSIGN = 17
	HLIL_ASSIGN_UNPACK = 18
	HLIL_FORCE_VER = 19
	HLIL_ASSERT = 20
	HLIL_VAR = 21
	HLIL_STRUCT_FIELD = 22
	HLIL_ARRAY_INDEX = 23
	HLIL_SPLIT = 24
	HLIL_DEREF = 25
	HLIL_DEREF_FIELD = 26
	HLIL_ADDRESS_OF = 27
	HLIL_PASS_BY_REF = 28
	HLIL_RETURN_BY_REF = 29
	HLIL_CONST = 30
	HLIL_CONST_DATA = 31
	HLIL_CONST_PTR = 32
	HLIL_EXTERN_PTR = 33
	HLIL_FLOAT_CONST = 34
	HLIL_IMPORT = 35
	HLIL_ADD = 36
	HLIL_ADC = 37
	HLIL_SUB = 38
	HLIL_SBB = 39
	HLIL_AND = 40
	HLIL_OR = 41
	HLIL_XOR = 42
	HLIL_LSL = 43
	HLIL_LSR = 44
	HLIL_ASR = 45
	HLIL_ROL = 46
	HLIL_RLC = 47
	HLIL_ROR = 48
	HLIL_RRC = 49
	HLIL_MUL = 50
	HLIL_MULU_DP = 51
	HLIL_MULS_DP = 52
	HLIL_DIVU = 53
	HLIL_DIVU_DP = 54
	HLIL_DIVS = 55
	HLIL_DIVS_DP = 56
	HLIL_MODU = 57
	HLIL_MODU_DP = 58
	HLIL_MODS = 59
	HLIL_MODS_DP = 60
	HLIL_NEG = 61
	HLIL_NOT = 62
	HLIL_SX = 63
	HLIL_ZX = 64
	HLIL_LOW_PART = 65
	HLIL_CALL = 66
	HLIL_CMP_E = 67
	HLIL_CMP_NE = 68
	HLIL_CMP_SLT = 69
	HLIL_CMP_ULT = 70
	HLIL_CMP_SLE = 71
	HLIL_CMP_ULE = 72
	HLIL_CMP_SGE = 73
	HLIL_CMP_UGE = 74
	HLIL_CMP_SGT = 75
	HLIL_CMP_UGT = 76
	HLIL_TEST_BIT = 77
	HLIL_BOOL_TO_INT = 78
	HLIL_ADD_OVERFLOW = 79
	HLIL_SYSCALL = 80
	HLIL_TAILCALL = 81
	HLIL_INTRINSIC = 82
	HLIL_BP = 83
	HLIL_TRAP = 84
	HLIL_UNDEF = 85
	HLIL_UNIMPL = 86
	HLIL_UNIMPL_MEM = 87
	HLIL_STRUCT_INIT = 88
	HLIL_STRUCT_INIT_FIELD = 89
	HLIL_FADD = 90
	HLIL_FSUB = 91
	HLIL_FMUL = 92
	HLIL_FDIV = 93
	HLIL_FSQRT = 94
	HLIL_FNEG = 95
	HLIL_FABS = 96
	HLIL_FLOAT_TO_INT = 97
	HLIL_INT_TO_FLOAT = 98
	HLIL_FLOAT_CONV = 99
	HLIL_ROUND_TO_INT = 100
	HLIL_FLOOR = 101
	HLIL_CEIL = 102
	HLIL_FTRUNC = 103
	HLIL_FCMP_E = 104
	HLIL_FCMP_NE = 105
	HLIL_FCMP_LT = 106
	HLIL_FCMP_LE = 107
	HLIL_FCMP_GE = 108
	HLIL_FCMP_GT = 109
	HLIL_FCMP_O = 110
	HLIL_FCMP_UO = 111
	HLIL_UNREACHABLE = 112
	HLIL_WHILE_SSA = 113
	HLIL_DO_WHILE_SSA = 114
	HLIL_FOR_SSA = 115
	HLIL_VAR_INIT_SSA = 116
	HLIL_ASSIGN_MEM_SSA = 117
	HLIL_ASSIGN_UNPACK_MEM_SSA = 118
	HLIL_FORCE_VER_SSA = 119
	HLIL_ASSERT_SSA = 120
	HLIL_VAR_SSA = 121
	HLIL_VAR_SSA_PARTIAL = 122
	HLIL_ARRAY_INDEX_SSA = 123
	HLIL_DEREF_SSA = 124
	HLIL_DEREF_FIELD_SSA = 125
	HLIL_CALL_SSA = 126
	HLIL_SYSCALL_SSA = 127
	HLIL_INTRINSIC_SSA = 128
	HLIL_VAR_PHI = 129
	HLIL_MEM_PHI = 130
	HLIL_BSWAP = 131
	HLIL_POPCNT = 132
	HLIL_CLZ = 133
	HLIL_CTZ = 134
	HLIL_RBIT = 135
	HLIL_CLS = 136
	HLIL_MINS = 137
	HLIL_MAXS = 138
	HLIL_MINU = 139
	HLIL_MAXU = 140
	HLIL_ABS = 141


class HighlightColorStyle(enum.IntEnum):
	StandardHighlightColor = 0
	MixedHighlightColor = 1
	CustomHighlightColor = 2


class HighlightStandardColor(enum.IntEnum):
	NoHighlightColor = 0
	BlueHighlightColor = 1
	GreenHighlightColor = 2
	CyanHighlightColor = 3
	RedHighlightColor = 4
	MagentaHighlightColor = 5
	YellowHighlightColor = 6
	OrangeHighlightColor = 7
	WhiteHighlightColor = 8
	BlackHighlightColor = 9


class ILBranchDependence(enum.IntEnum):
	NotBranchDependent = 0
	TrueBranchDependent = 1
	FalseBranchDependent = 2


class ILInstructionAttribute(enum.IntFlag):
	ILAllowDeadStoreElimination = 1
	ILPreventDeadStoreElimination = 2
	MLILAssumePossibleUse = 4
	MLILUnknownSize = 8
	SrcInstructionUsesPointerAuth = 16
	ILPreventAliasAnalysis = 32
	ILIsCFGProtected = 64
	MLILPossiblyUnusedIntermediate = 128
	HLILFoldableExpr = 256
	HLILInvertableCondition = 512
	HLILEarlyReturnPossible = 1024
	HLILSwitchRecoveryPossible = 2048
	ILTransparentCopy = 4096
	MLILCallingConventionImplicit = 8192
	ILStackReturn = 16384


class ImplicitRegisterExtend(enum.IntEnum):
	NoExtend = 0
	ZeroExtendToFullWidth = 1
	SignExtendToFullWidth = 2


class InlineDuringAnalysis(enum.IntEnum):
	DoNotInlineCall = 0
	InlinePreservingTargetInstructionAddresses = 1
	InlineUsingCallAddress = 2


class InstructionTextTokenContext(enum.IntEnum):
	NoTokenContext = 0
	LocalVariableTokenContext = 1
	DataVariableTokenContext = 2
	FunctionReturnTokenContext = 3
	InstructionAddressTokenContext = 4
	ILInstructionIndexTokenContext = 5
	ConstDataTokenContext = 6
	ConstStringDataTokenContext = 7
	StringReferenceTokenContext = 8
	StringDataVariableTokenContext = 9
	StringDisplayTokenContext = 10
	ContentCollapsedContext = 11
	ContentExpandedContext = 12
	ContentCollapsiblePadding = 13
	DerivedStringReferenceTokenContext = 14


class InstructionTextTokenType(enum.IntEnum):
	TextToken = 0
	InstructionToken = 1
	OperandSeparatorToken = 2
	RegisterToken = 3
	IntegerToken = 4
	PossibleAddressToken = 5
	BeginMemoryOperandToken = 6
	EndMemoryOperandToken = 7
	FloatingPointToken = 8
	AnnotationToken = 9
	CodeRelativeAddressToken = 10
	ArgumentNameToken = 11
	HexDumpByteValueToken = 12
	HexDumpSkippedByteToken = 13
	HexDumpInvalidByteToken = 14
	HexDumpTextToken = 15
	OpcodeToken = 16
	StringToken = 17
	CharacterConstantToken = 18
	KeywordToken = 19
	TypeNameToken = 20
	FieldNameToken = 21
	NameSpaceToken = 22
	NameSpaceSeparatorToken = 23
	TagToken = 24
	StructOffsetToken = 25
	StructOffsetByteValueToken = 26
	StructureHexDumpTextToken = 27
	GotoLabelToken = 28
	CommentToken = 29
	PossibleValueToken = 30
	PossibleValueTypeToken = 31
	ArrayIndexToken = 32
	IndentationToken = 33
	UnknownMemoryToken = 34
	EnumerationMemberToken = 35
	OperationToken = 36
	BaseStructureNameToken = 37
	BaseStructureSeparatorToken = 38
	BraceToken = 39
	ValueLocationToken = 40
	CodeSymbolToken = 64
	DataSymbolToken = 65
	LocalVariableToken = 66
	ImportToken = 67
	AddressDisplayToken = 68
	IndirectImportToken = 69
	ExternalSymbolToken = 70
	StackVariableToken = 71
	AddressSeparatorToken = 72
	CollapsedInformationToken = 73
	CollapseStateIndicatorToken = 74
	NewLineToken = 75


class IntegerDisplayType(enum.IntEnum):
	DefaultIntegerDisplayType = 0
	BinaryDisplayType = 1
	SignedOctalDisplayType = 2
	UnsignedOctalDisplayType = 3
	SignedDecimalDisplayType = 4
	UnsignedDecimalDisplayType = 5
	SignedHexadecimalDisplayType = 6
	UnsignedHexadecimalDisplayType = 7
	CharacterConstantDisplayType = 8
	PointerDisplayType = 9
	FloatDisplayType = 10
	DoubleDisplayType = 11
	EnumerationDisplayType = 12
	InvertedCharacterConstantDisplayType = 13
	UnsignedComplementDecimalDisplayType = 14
	UnsignedComplementHexadecimalDisplayType = 15


class IntrinsicClass(enum.IntEnum):
	GeneralIntrinsicClass = 0
	MemoryIntrinsicClass = 1


class LinearDisassemblyLineType(enum.IntEnum):
	BlankLineType = 0
	BasicLineType = 1
	CodeDisassemblyLineType = 2
	DataVariableLineType = 3
	HexDumpLineType = 4
	FunctionHeaderLineType = 5
	FunctionHeaderStartLineType = 6
	FunctionHeaderEndLineType = 7
	FunctionContinuationLineType = 8
	LocalVariableLineType = 9
	LocalVariableListEndLineType = 10
	FunctionEndLineType = 11
	NoteStartLineType = 12
	NoteLineType = 13
	NoteEndLineType = 14
	SectionStartLineType = 15
	SectionEndLineType = 16
	SectionSeparatorLineType = 17
	NonContiguousSeparatorLineType = 18
	AnalysisWarningLineType = 19
	CollapsedFunctionEndLineType = 20


class LinearSweepAnalysisCapability(enum.IntEnum):
	BNLinearSweepCallTargetAnalysis = 1
	BNLinearSweepGenericControlFlowAnalysis = 2


class LinearViewObjectIdentifierType(enum.IntEnum):
	SingleLinearViewObject = 0
	AddressLinearViewObject = 1
	AddressRangeLinearViewObject = 2


class LogLevel(enum.IntEnum):
	DebugLog = 0
	InfoLog = 1
	WarningLog = 2
	ErrorLog = 3
	AlertLog = 4


class LowLevelILFlagCondition(enum.IntEnum):
	LLFC_E = 0
	LLFC_NE = 1
	LLFC_SLT = 2
	LLFC_ULT = 3
	LLFC_SLE = 4
	LLFC_ULE = 5
	LLFC_SGE = 6
	LLFC_UGE = 7
	LLFC_SGT = 8
	LLFC_UGT = 9
	LLFC_NEG = 10
	LLFC_POS = 11
	LLFC_O = 12
	LLFC_NO = 13
	LLFC_FE = 14
	LLFC_FNE = 15
	LLFC_FLT = 16
	LLFC_FLE = 17
	LLFC_FGE = 18
	LLFC_FGT = 19
	LLFC_FO = 20
	LLFC_FUO = 21


class LowLevelILOperation(enum.IntEnum):
	LLIL_NOP = 0
	LLIL_SET_REG = 1
	LLIL_SET_REG_SPLIT = 2
	LLIL_SET_FLAG = 3
	LLIL_SET_REG_STACK_REL = 4
	LLIL_REG_STACK_PUSH = 5
	LLIL_ASSERT = 6
	LLIL_FORCE_VER = 7
	LLIL_LOAD = 8
	LLIL_STORE = 9
	LLIL_PUSH = 10
	LLIL_POP = 11
	LLIL_REG = 12
	LLIL_REG_SPLIT = 13
	LLIL_REG_STACK_REL = 14
	LLIL_REG_STACK_POP = 15
	LLIL_REG_STACK_FREE_REG = 16
	LLIL_REG_STACK_FREE_REL = 17
	LLIL_CONST = 18
	LLIL_CONST_PTR = 19
	LLIL_EXTERN_PTR = 20
	LLIL_FLOAT_CONST = 21
	LLIL_FLAG = 22
	LLIL_FLAG_BIT = 23
	LLIL_ADD = 24
	LLIL_ADC = 25
	LLIL_SUB = 26
	LLIL_SBB = 27
	LLIL_AND = 28
	LLIL_OR = 29
	LLIL_XOR = 30
	LLIL_LSL = 31
	LLIL_LSR = 32
	LLIL_ASR = 33
	LLIL_ROL = 34
	LLIL_RLC = 35
	LLIL_ROR = 36
	LLIL_RRC = 37
	LLIL_MUL = 38
	LLIL_MULU_DP = 39
	LLIL_MULS_DP = 40
	LLIL_DIVU = 41
	LLIL_DIVU_DP = 42
	LLIL_DIVS = 43
	LLIL_DIVS_DP = 44
	LLIL_MODU = 45
	LLIL_MODU_DP = 46
	LLIL_MODS = 47
	LLIL_MODS_DP = 48
	LLIL_NEG = 49
	LLIL_NOT = 50
	LLIL_SX = 51
	LLIL_ZX = 52
	LLIL_LOW_PART = 53
	LLIL_JUMP = 54
	LLIL_JUMP_TO = 55
	LLIL_CALL = 56
	LLIL_CALL_STACK_ADJUST = 57
	LLIL_TAILCALL = 58
	LLIL_RET = 59
	LLIL_NORET = 60
	LLIL_IF = 61
	LLIL_GOTO = 62
	LLIL_FLAG_COND = 63
	LLIL_FLAG_GROUP = 64
	LLIL_CMP_E = 65
	LLIL_CMP_NE = 66
	LLIL_CMP_SLT = 67
	LLIL_CMP_ULT = 68
	LLIL_CMP_SLE = 69
	LLIL_CMP_ULE = 70
	LLIL_CMP_SGE = 71
	LLIL_CMP_UGE = 72
	LLIL_CMP_SGT = 73
	LLIL_CMP_UGT = 74
	LLIL_TEST_BIT = 75
	LLIL_BOOL_TO_INT = 76
	LLIL_ADD_OVERFLOW = 77
	LLIL_SYSCALL = 78
	LLIL_BP = 79
	LLIL_TRAP = 80
	LLIL_INTRINSIC = 81
	LLIL_UNDEF = 82
	LLIL_UNIMPL = 83
	LLIL_UNIMPL_MEM = 84
	LLIL_FADD = 85
	LLIL_FSUB = 86
	LLIL_FMUL = 87
	LLIL_FDIV = 88
	LLIL_FSQRT = 89
	LLIL_FNEG = 90
	LLIL_FABS = 91
	LLIL_FLOAT_TO_INT = 92
	LLIL_INT_TO_FLOAT = 93
	LLIL_FLOAT_CONV = 94
	LLIL_ROUND_TO_INT = 95
	LLIL_FLOOR = 96
	LLIL_CEIL = 97
	LLIL_FTRUNC = 98
	LLIL_FCMP_E = 99
	LLIL_FCMP_NE = 100
	LLIL_FCMP_LT = 101
	LLIL_FCMP_LE = 102
	LLIL_FCMP_GE = 103
	LLIL_FCMP_GT = 104
	LLIL_FCMP_O = 105
	LLIL_FCMP_UO = 106
	LLIL_SET_REG_SSA = 107
	LLIL_SET_REG_SSA_PARTIAL = 108
	LLIL_SET_REG_SPLIT_SSA = 109
	LLIL_SET_REG_STACK_REL_SSA = 110
	LLIL_SET_REG_STACK_ABS_SSA = 111
	LLIL_REG_SPLIT_DEST_SSA = 112
	LLIL_REG_STACK_DEST_SSA = 113
	LLIL_REG_SSA = 114
	LLIL_REG_SSA_PARTIAL = 115
	LLIL_REG_SPLIT_SSA = 116
	LLIL_REG_STACK_REL_SSA = 117
	LLIL_REG_STACK_ABS_SSA = 118
	LLIL_REG_STACK_FREE_REL_SSA = 119
	LLIL_REG_STACK_FREE_ABS_SSA = 120
	LLIL_SET_FLAG_SSA = 121
	LLIL_ASSERT_SSA = 122
	LLIL_FORCE_VER_SSA = 123
	LLIL_FLAG_SSA = 124
	LLIL_FLAG_BIT_SSA = 125
	LLIL_CALL_SSA = 126
	LLIL_SYSCALL_SSA = 127
	LLIL_TAILCALL_SSA = 128
	LLIL_CALL_PARAM = 129
	LLIL_CALL_STACK_SSA = 130
	LLIL_CALL_OUTPUT_SSA = 131
	LLIL_SEPARATE_PARAM_LIST_SSA = 132
	LLIL_SHARED_PARAM_SLOT_SSA = 133
	LLIL_MEMORY_INTRINSIC_OUTPUT_SSA = 134
	LLIL_LOAD_SSA = 135
	LLIL_STORE_SSA = 136
	LLIL_INTRINSIC_SSA = 137
	LLIL_MEMORY_INTRINSIC_SSA = 138
	LLIL_REG_PHI = 139
	LLIL_REG_STACK_PHI = 140
	LLIL_FLAG_PHI = 141
	LLIL_MEM_PHI = 142
	LLIL_BSWAP = 143
	LLIL_POPCNT = 144
	LLIL_CLZ = 145
	LLIL_CTZ = 146
	LLIL_RBIT = 147
	LLIL_CLS = 148
	LLIL_MINS = 149
	LLIL_MAXS = 150
	LLIL_MINU = 151
	LLIL_MAXU = 152
	LLIL_ABS = 153


class MediumLevelILOperation(enum.IntEnum):
	MLIL_NOP = 0
	MLIL_SET_VAR = 1
	MLIL_SET_VAR_FIELD = 2
	MLIL_SET_VAR_SPLIT = 3
	MLIL_ASSERT = 4
	MLIL_FORCE_VER = 5
	MLIL_LOAD = 6
	MLIL_LOAD_STRUCT = 7
	MLIL_STORE = 8
	MLIL_STORE_STRUCT = 9
	MLIL_VAR = 10
	MLIL_VAR_FIELD = 11
	MLIL_VAR_SPLIT = 12
	MLIL_ADDRESS_OF = 13
	MLIL_ADDRESS_OF_FIELD = 14
	MLIL_PASS_BY_REF = 15
	MLIL_RETURN_BY_REF = 16
	MLIL_CONST = 17
	MLIL_CONST_DATA = 18
	MLIL_CONST_PTR = 19
	MLIL_EXTERN_PTR = 20
	MLIL_FLOAT_CONST = 21
	MLIL_IMPORT = 22
	MLIL_ADD = 23
	MLIL_ADC = 24
	MLIL_SUB = 25
	MLIL_SBB = 26
	MLIL_AND = 27
	MLIL_OR = 28
	MLIL_XOR = 29
	MLIL_LSL = 30
	MLIL_LSR = 31
	MLIL_ASR = 32
	MLIL_ROL = 33
	MLIL_RLC = 34
	MLIL_ROR = 35
	MLIL_RRC = 36
	MLIL_MUL = 37
	MLIL_MULU_DP = 38
	MLIL_MULS_DP = 39
	MLIL_DIVU = 40
	MLIL_DIVU_DP = 41
	MLIL_DIVS = 42
	MLIL_DIVS_DP = 43
	MLIL_MODU = 44
	MLIL_MODU_DP = 45
	MLIL_MODS = 46
	MLIL_MODS_DP = 47
	MLIL_NEG = 48
	MLIL_NOT = 49
	MLIL_SX = 50
	MLIL_ZX = 51
	MLIL_LOW_PART = 52
	MLIL_JUMP = 53
	MLIL_JUMP_TO = 54
	MLIL_RET_HINT = 55
	MLIL_CALL = 56
	MLIL_CALL_UNTYPED = 57
	MLIL_CALL_PARAM = 58
	MLIL_SEPARATE_PARAM_LIST = 59
	MLIL_SHARED_PARAM_SLOT = 60
	MLIL_VAR_OUTPUT = 61
	MLIL_VAR_OUTPUT_FIELD = 62
	MLIL_STORE_OUTPUT = 63
	MLIL_RET = 64
	MLIL_NORET = 65
	MLIL_IF = 66
	MLIL_GOTO = 67
	MLIL_CMP_E = 68
	MLIL_CMP_NE = 69
	MLIL_CMP_SLT = 70
	MLIL_CMP_ULT = 71
	MLIL_CMP_SLE = 72
	MLIL_CMP_ULE = 73
	MLIL_CMP_SGE = 74
	MLIL_CMP_UGE = 75
	MLIL_CMP_SGT = 76
	MLIL_CMP_UGT = 77
	MLIL_TEST_BIT = 78
	MLIL_BOOL_TO_INT = 79
	MLIL_ADD_OVERFLOW = 80
	MLIL_SYSCALL = 81
	MLIL_SYSCALL_UNTYPED = 82
	MLIL_TAILCALL = 83
	MLIL_TAILCALL_UNTYPED = 84
	MLIL_INTRINSIC = 85
	MLIL_FREE_VAR_SLOT = 86
	MLIL_BP = 87
	MLIL_TRAP = 88
	MLIL_UNDEF = 89
	MLIL_UNIMPL = 90
	MLIL_UNIMPL_MEM = 91
	MLIL_FADD = 92
	MLIL_FSUB = 93
	MLIL_FMUL = 94
	MLIL_FDIV = 95
	MLIL_FSQRT = 96
	MLIL_FNEG = 97
	MLIL_FABS = 98
	MLIL_FLOAT_TO_INT = 99
	MLIL_INT_TO_FLOAT = 100
	MLIL_FLOAT_CONV = 101
	MLIL_ROUND_TO_INT = 102
	MLIL_FLOOR = 103
	MLIL_CEIL = 104
	MLIL_FTRUNC = 105
	MLIL_FCMP_E = 106
	MLIL_FCMP_NE = 107
	MLIL_FCMP_LT = 108
	MLIL_FCMP_LE = 109
	MLIL_FCMP_GE = 110
	MLIL_FCMP_GT = 111
	MLIL_FCMP_O = 112
	MLIL_FCMP_UO = 113
	MLIL_SET_VAR_SSA = 114
	MLIL_SET_VAR_SSA_FIELD = 115
	MLIL_SET_VAR_SPLIT_SSA = 116
	MLIL_SET_VAR_ALIASED = 117
	MLIL_SET_VAR_ALIASED_FIELD = 118
	MLIL_VAR_SSA = 119
	MLIL_VAR_SSA_FIELD = 120
	MLIL_VAR_ALIASED = 121
	MLIL_VAR_ALIASED_FIELD = 122
	MLIL_VAR_SPLIT_SSA = 123
	MLIL_ASSERT_SSA = 124
	MLIL_FORCE_VER_SSA = 125
	MLIL_CALL_SSA = 126
	MLIL_CALL_UNTYPED_SSA = 127
	MLIL_SYSCALL_SSA = 128
	MLIL_SYSCALL_UNTYPED_SSA = 129
	MLIL_TAILCALL_SSA = 130
	MLIL_TAILCALL_UNTYPED_SSA = 131
	MLIL_CALL_PARAM_SSA = 132
	MLIL_CALL_OUTPUT_SSA = 133
	MLIL_VAR_OUTPUT_SSA = 134
	MLIL_VAR_OUTPUT_SSA_FIELD = 135
	MLIL_VAR_OUTPUT_ALIASED = 136
	MLIL_VAR_OUTPUT_ALIASED_FIELD = 137
	MLIL_MEMORY_INTRINSIC_OUTPUT_SSA = 138
	MLIL_LOAD_SSA = 139
	MLIL_LOAD_STRUCT_SSA = 140
	MLIL_STORE_SSA = 141
	MLIL_STORE_STRUCT_SSA = 142
	MLIL_INTRINSIC_SSA = 143
	MLIL_MEMORY_INTRINSIC_SSA = 144
	MLIL_FREE_VAR_SLOT_SSA = 145
	MLIL_VAR_PHI = 146
	MLIL_MEM_PHI = 147
	MLIL_BLOCK_TO_EXPAND = 148
	MLIL_BSWAP = 149
	MLIL_POPCNT = 150
	MLIL_CLZ = 151
	MLIL_CTZ = 152
	MLIL_RBIT = 153
	MLIL_CLS = 154
	MLIL_MINS = 155
	MLIL_MAXS = 156
	MLIL_MINU = 157
	MLIL_MAXU = 158
	MLIL_ABS = 159


class MemberAccess(enum.IntEnum):
	NoAccess = 0
	PrivateAccess = 1
	ProtectedAccess = 2
	PublicAccess = 3


class MemberScope(enum.IntEnum):
	NoScope = 0
	StaticScope = 1
	VirtualScope = 2
	ThunkScope = 3
	FriendScope = 4


class MergeConflictDataType(enum.IntEnum):
	TextConflictDataType = 0
	JsonConflictDataType = 1
	BinaryConflictDataType = 2


class MessageBoxButtonResult(enum.IntEnum):
	NoButton = 0
	YesButton = 1
	OKButton = 2
	CancelButton = 3


class MessageBoxButtonSet(enum.IntEnum):
	OKButtonSet = 0
	YesNoButtonSet = 1
	YesNoCancelButtonSet = 2


class MessageBoxIcon(enum.IntEnum):
	InformationIcon = 0
	QuestionIcon = 1
	WarningIcon = 2
	ErrorIcon = 3


class MetadataStoreFlag(enum.IntFlag):
	MetadataStoreEphemeral = 0
	MetadataStorePersistent = 1
	MetadataStoreMarksAnalysisChanged = 2


class MetadataType(enum.IntEnum):
	InvalidDataType = 0
	BooleanDataType = 1
	StringDataType = 2
	UnsignedIntegerDataType = 3
	SignedIntegerDataType = 4
	DoubleDataType = 5
	RawDataType = 6
	KeyValueDataType = 7
	ArrayDataType = 8


class ModificationStatus(enum.IntEnum):
	Original = 0
	Changed = 1
	Inserted = 2


class NameType(enum.IntEnum):
	NoNameType = 0
	ConstructorNameType = 1
	DestructorNameType = 2
	OperatorNewNameType = 3
	OperatorDeleteNameType = 4
	OperatorAssignNameType = 5
	OperatorRightShiftNameType = 6
	OperatorLeftShiftNameType = 7
	OperatorNotNameType = 8
	OperatorEqualNameType = 9
	OperatorNotEqualNameType = 10
	OperatorArrayNameType = 11
	OperatorArrowNameType = 12
	OperatorStarNameType = 13
	OperatorIncrementNameType = 14
	OperatorDecrementNameType = 15
	OperatorMinusNameType = 16
	OperatorPlusNameType = 17
	OperatorBitAndNameType = 18
	OperatorArrowStarNameType = 19
	OperatorDivideNameType = 20
	OperatorModulusNameType = 21
	OperatorLessThanNameType = 22
	OperatorLessThanEqualNameType = 23
	OperatorGreaterThanNameType = 24
	OperatorGreaterThanEqualNameType = 25
	OperatorCommaNameType = 26
	OperatorParenthesesNameType = 27
	OperatorTildeNameType = 28
	OperatorXorNameType = 29
	OperatorBitOrNameType = 30
	OperatorLogicalAndNameType = 31
	OperatorLogicalOrNameType = 32
	OperatorStarEqualNameType = 33
	OperatorPlusEqualNameType = 34
	OperatorMinusEqualNameType = 35
	OperatorDivideEqualNameType = 36
	OperatorModulusEqualNameType = 37
	OperatorRightShiftEqualNameType = 38
	OperatorLeftShiftEqualNameType = 39
	OperatorAndEqualNameType = 40
	OperatorOrEqualNameType = 41
	OperatorXorEqualNameType = 42
	VFTableNameType = 43
	VBTableNameType = 44
	VCallNameType = 45
	TypeofNameType = 46
	LocalStaticGuardNameType = 47
	StringNameType = 48
	VBaseDestructorNameType = 49
	VectorDeletingDestructorNameType = 50
	DefaultConstructorClosureNameType = 51
	ScalarDeletingDestructorNameType = 52
	VectorConstructorIteratorNameType = 53
	VectorDestructorIteratorNameType = 54
	VectorVBaseConstructorIteratorNameType = 55
	VirtualDisplacementMapNameType = 56
	EHVectorConstructorIteratorNameType = 57
	EHVectorDestructorIteratorNameType = 58
	EHVectorVBaseConstructorIteratorNameType = 59
	CopyConstructorClosureNameType = 60
	UDTReturningNameType = 61
	LocalVFTableNameType = 62
	LocalVFTableConstructorClosureNameType = 63
	OperatorNewArrayNameType = 64
	OperatorDeleteArrayNameType = 65
	PlacementDeleteClosureNameType = 66
	PlacementDeleteClosureArrayNameType = 67
	OperatorReturnTypeNameType = 68
	RttiTypeDescriptor = 69
	RttiBaseClassDescriptor = 70
	RttiBaseClassArray = 71
	RttiClassHierarchyDescriptor = 72
	RttiCompleteObjectLocator = 73
	OperatorUnaryMinusNameType = 74
	OperatorUnaryPlusNameType = 75
	OperatorUnaryBitAndNameType = 76
	OperatorUnaryStarNameType = 77
	OmniCallSigNameType = 78
	ManagedVectorConstructorIteratorNameType = 79
	ManagedVectorDestructorIteratorNameType = 80
	EHVectorCopyConstructorIteratorNameType = 81
	EHVectorVBaseCopyConstructorIteratorNameType = 82
	DynamicInitializerNameType = 83
	DynamicAtExitDestructorNameType = 84
	VectorCopyConstructorIteratorNameType = 85
	VectorVBaseCopyConstructorIteratorNameType = 86
	ManagedVectorCopyConstructorIteratorNameType = 87
	LocalStaticThreadGuardNameType = 88
	UserDefinedLiteralOperatorNameType = 89


class NamedTypeReferenceClass(enum.IntEnum):
	UnknownNamedTypeClass = 0
	TypedefNamedTypeClass = 1
	ClassNamedTypeClass = 2
	StructNamedTypeClass = 3
	UnionNamedTypeClass = 4
	EnumNamedTypeClass = 5


class OperatorPrecedence(enum.IntEnum):
	TopLevelOperatorPrecedence = 0
	AssignmentOperatorPrecedence = 1
	TernaryOperatorPrecedence = 2
	LogicalOrOperatorPrecedence = 3
	LogicalAndOperatorPrecedence = 4
	BitwiseOrOperatorPrecedence = 5
	BitwiseXorOperatorPrecedence = 6
	BitwiseAndOperatorPrecedence = 7
	EqualityOperatorPrecedence = 8
	CompareOperatorPrecedence = 9
	ShiftOperatorPrecedence = 10
	AddOperatorPrecedence = 11
	SubOperatorPrecedence = 12
	MultiplyOperatorPrecedence = 13
	DivideOperatorPrecedence = 14
	LowUnaryOperatorPrecedence = 15
	UnaryOperatorPrecedence = 16
	HighUnaryOperatorPrecedence = 17
	MemberAndFunctionOperatorPrecedence = 18
	ScopeOperatorPrecedence = 19


class PluginCommandType(enum.IntEnum):
	DefaultPluginCommand = 0
	AddressPluginCommand = 1
	RangePluginCommand = 2
	FunctionPluginCommand = 3
	LowLevelILFunctionPluginCommand = 4
	LowLevelILInstructionPluginCommand = 5
	MediumLevelILFunctionPluginCommand = 6
	MediumLevelILInstructionPluginCommand = 7
	HighLevelILFunctionPluginCommand = 8
	HighLevelILInstructionPluginCommand = 9
	ProjectPluginCommand = 10
	GlobalPluginCommand = 11


class PluginDependencyConflictStatus(enum.IntEnum):
	PluginDependencyProvenConflict = 0
	PluginDependencyUnknownCompatibility = 1


class PluginDependencyDecision(enum.IntEnum):
	PluginDependencyReinstall = 0
	PluginDependencyDisable = 1
	PluginDependencyLoadAnyway = 2


class PluginLoadPhase(enum.IntEnum):
	NativePluginLoadPhase = 0
	ScriptingProviderLoadPhase = 1
	ScriptPluginLoadPhase = 2


class PluginOrigin(enum.IntEnum):
	OfficialPluginOrigin = 0
	CommunityPluginOrigin = 1
	OtherPluginOrigin = 2


class PluginStatus(enum.IntFlag):
	NotInstalledPluginStatus = 0
	InstalledPluginStatus = 1
	EnabledPluginStatus = 2
	UpdateAvailablePluginStatus = 16
	DeletePendingPluginStatus = 32
	UpdatePendingPluginStatus = 64
	DisablePendingPluginStatus = 128
	PendingRestartPluginStatus = 512
	BeingUpdatedPluginStatus = 1024
	BeingDeletedPluginStatus = 2048
	DependenciesBeingInstalledStatus = 4096


class PluginType(enum.IntEnum):
	CorePluginType = 0
	UiPluginType = 1
	ArchitecturePluginType = 2
	BinaryViewPluginType = 3
	HelperPluginType = 4
	SyncPluginType = 5


class PointerBaseType(enum.IntEnum):
	AbsolutePointerBaseType = 0
	RelativeToConstantPointerBaseType = 1
	RelativeToBinaryStartPointerBaseType = 2
	RelativeToVariableAddressPointerBaseType = 3


class PointerSuffix(enum.IntEnum):
	Ptr64Suffix = 0
	UnalignedSuffix = 1
	RestrictSuffix = 2
	ReferenceSuffix = 3
	LvalueSuffix = 4


class ReferenceType(enum.IntEnum):
	PointerReferenceType = 0
	ReferenceReferenceType = 1
	RValueReferenceType = 2
	NoReference = 3


class RegisterValueType(enum.IntEnum):
	UndeterminedValue = 0
	EntryValue = 1
	ConstantValue = 2
	ConstantPointerValue = 3
	ExternalPointerValue = 4
	StackFrameOffset = 5
	ReturnAddressValue = 6
	ImportedAddressValue = 7
	ResultPointerValue = 8
	ParameterPointerValue = 9
	SignedRangeValue = 10
	UnsignedRangeValue = 11
	LookupTableValue = 12
	InSetOfValues = 13
	NotInSetOfValues = 14
	ConstantDataValue = 32768
	ConstantDataZeroExtendValue = 32769
	ConstantDataSignExtendValue = 32770
	ConstantDataAggregateValue = 32771


class RelocationType(enum.IntEnum):
	ELFGlobalRelocationType = 0
	ELFCopyRelocationType = 1
	ELFJumpSlotRelocationType = 2
	StandardRelocationType = 3
	IgnoredRelocation = 4
	UnhandledRelocation = 5


class RemoteFileType(enum.IntEnum):
	RawDataFileType = 0
	BinaryViewAnalysisFileType = 1
	TypeArchiveFileType = 2
	UnknownFileType = 3


class RenderLayerDefaultEnableState(enum.IntEnum):
	DisabledByDefaultRenderLayerDefaultEnableState = 0
	EnabledByDefaultRenderLayerDefaultEnableState = 1
	AlwaysEnabledRenderLayerDefaultEnableState = 2


class ReportType(enum.IntEnum):
	PlainTextReportType = 0
	MarkdownReportType = 1
	HTMLReportType = 2
	FlowGraphReportType = 3


class SaveOption(enum.IntFlag):
	RemoveUndoData = 0
	TrimSnapshots = 1
	PurgeOriginalFilenamePath = 2


class ScopeType(enum.IntEnum):
	OneLineScopeType = 0
	HasSubScopeScopeType = 1
	BlockScopeType = 2
	SwitchScopeType = 3
	CaseScopeType = 4


class ScriptingProviderExecuteResult(enum.IntEnum):
	InvalidScriptInput = 0
	IncompleteScriptInput = 1
	SuccessfulScriptExecution = 2
	ScriptExecutionCancelled = 3


class ScriptingProviderInputReadyState(enum.IntEnum):
	NotReadyForInput = 0
	ReadyForScriptExecution = 1
	ReadyForScriptProgramInput = 2


class SectionSemantics(enum.IntEnum):
	DefaultSectionSemantics = 0
	ReadOnlyCodeSectionSemantics = 1
	ReadOnlyDataSectionSemantics = 2
	ReadWriteDataSectionSemantics = 3
	ExternalSectionSemantics = 4


class SegmentFlag(enum.IntFlag):
	SegmentExecutable = 1
	SegmentWritable = 2
	SegmentReadable = 4
	SegmentContainsData = 8
	SegmentContainsCode = 16
	SegmentDenyWrite = 32
	SegmentDenyExecute = 64


class SettingsScope(enum.IntFlag):
	SettingsInvalidScope = 0
	SettingsAutoScope = 1
	SettingsDefaultScope = 2
	SettingsUserScope = 4
	SettingsProjectScope = 8
	SettingsResourceScope = 16


class SimilarityAnnotationType(enum.IntEnum):
	SimilarityAnnotationAdded = 0
	SimilarityAnnotationRemoved = 1
	SimilarityAnnotationChanged = 2


class SimilarityApplyStatus(enum.IntEnum):
	SimilarityApplySuccess = 0
	SimilarityApplyNodeInactive = 1
	SimilarityApplyEntityNotFound = 2
	SimilarityApplyUnsupported = 3
	SimilarityApplyFailed = 4


class SimilarityEntityType(enum.IntEnum):
	SimilarityEntityFunction = 0


class SimilarityViewType(enum.IntEnum):
	SimilarityViewFlowGraph = 0
	SimilarityViewLinear = 1


class StringType(enum.IntEnum):
	AsciiString = 0
	Utf16String = 1
	Utf32String = 2
	Utf8String = 3


class StructureVariant(enum.IntEnum):
	ClassStructureType = 0
	StructStructureType = 1
	UnionStructureType = 2


class SwitchRecovery(enum.IntEnum):
	DefaultSwitchRecovery = 0
	PreventSwitchRecovery = 1
	AllowSwitchRecovery = 2


class SymbolBinding(enum.IntEnum):
	NoBinding = 0
	LocalBinding = 1
	GlobalBinding = 2
	WeakBinding = 3


class SymbolDisplayResult(enum.IntEnum):
	NoSymbolAvailable = 0
	DataSymbolResult = 1
	OtherSymbolResult = 2


class SymbolDisplayType(enum.IntEnum):
	DisplaySymbolOnly = 0
	AddressOfDataSymbols = 1
	DereferenceNonDataSymbols = 2


class SymbolType(enum.IntEnum):
	FunctionSymbol = 0
	ImportAddressSymbol = 1
	ImportedFunctionSymbol = 2
	DataSymbol = 3
	ImportedDataSymbol = 4
	ExternalSymbol = 5
	LibraryFunctionSymbol = 6
	SymbolicFunctionSymbol = 7
	LocalLabelSymbol = 8


class SyncStatus(enum.IntEnum):
	NotSyncedSyncStatus = 0
	NoChangesSyncStatus = 1
	UnknownSyncStatus = 2
	CanPushSyncStatus = 3
	CanPullSyncStatus = 4
	CanPushAndPullSyncStatus = 5
	ConflictSyncStatus = 6


class TagReferenceType(enum.IntEnum):
	AddressTagReference = 0
	FunctionTagReference = 1
	DataTagReference = 2


class TagTypeType(enum.IntEnum):
	UserTagType = 0
	NotificationTagType = 1
	BookmarksTagType = 2


class ThemeColor(enum.IntEnum):
	AddressColor = 0
	ModifiedColor = 1
	InsertedColor = 2
	NotPresentColor = 3
	SelectionColor = 4
	OutlineColor = 5
	BackgroundHighlightDarkColor = 6
	BackgroundHighlightLightColor = 7
	BoldBackgroundHighlightDarkColor = 8
	BoldBackgroundHighlightLightColor = 9
	AlphanumericHighlightColor = 10
	PrintableHighlightColor = 11
	GraphBackgroundDarkColor = 12
	GraphBackgroundLightColor = 13
	GraphNodeDarkColor = 14
	GraphNodeLightColor = 15
	GraphNodeOutlineColor = 16
	GraphNodeShadowColor = 17
	GraphEntryNodeIndicatorColor = 18
	GraphExitNodeIndicatorColor = 19
	GraphExitNoreturnNodeIndicatorColor = 20
	TrueBranchColor = 21
	FalseBranchColor = 22
	UnconditionalBranchColor = 23
	AltTrueBranchColor = 24
	AltFalseBranchColor = 25
	AltUnconditionalBranchColor = 26
	InstructionColor = 27
	RegisterColor = 28
	NumberColor = 29
	CodeSymbolColor = 30
	DataSymbolColor = 31
	LocalVariableColor = 32
	StackVariableColor = 33
	ImportColor = 34
	ExportColor = 35
	InstructionHighlightColor = 36
	RelatedInstructionHighlightColor = 37
	TokenHighlightColor = 38
	TokenSelectionColor = 39
	AnnotationColor = 40
	OpcodeColor = 41
	LinearDisassemblyFunctionHeaderColor = 42
	LinearDisassemblyBlockColor = 43
	LinearDisassemblyNoteColor = 44
	LinearDisassemblySeparatorColor = 45
	LinearDisassemblyCodeFoldColor = 46
	StringColor = 47
	TypeNameColor = 48
	FieldNameColor = 49
	KeywordColor = 50
	UncertainColor = 51
	NameSpaceColor = 52
	NameSpaceSeparatorColor = 53
	GotoLabelColor = 54
	CommentColor = 55
	OperationColor = 56
	BaseStructureNameColor = 57
	IndentationLineColor = 58
	IndentationLineHighlightColor = 59
	ScriptConsoleOutputColor = 60
	ScriptConsoleWarningColor = 61
	ScriptConsoleErrorColor = 62
	ScriptConsoleEchoColor = 63
	BlueStandardHighlightColor = 64
	GreenStandardHighlightColor = 65
	CyanStandardHighlightColor = 66
	RedStandardHighlightColor = 67
	MagentaStandardHighlightColor = 68
	YellowStandardHighlightColor = 69
	OrangeStandardHighlightColor = 70
	WhiteStandardHighlightColor = 71
	BlackStandardHighlightColor = 72
	MiniGraphOverlayColor = 73
	FeatureMapBaseColor = 74
	FeatureMapNavLineColor = 75
	FeatureMapNavHighlightColor = 76
	FeatureMapDataVariableColor = 77
	FeatureMapAsciiStringColor = 78
	FeatureMapUnicodeStringColor = 79
	FeatureMapFunctionColor = 80
	FeatureMapImportColor = 81
	FeatureMapExternColor = 82
	FeatureMapLibraryColor = 83
	SidebarBackgroundColor = 84
	SidebarInactiveIconColor = 85
	SidebarHoverIconColor = 86
	SidebarActiveIconColor = 87
	SidebarFocusedIconColor = 88
	SidebarHoverBackgroundColor = 89
	SidebarActiveBackgroundColor = 90
	SidebarFocusedBackgroundColor = 91
	SidebarActiveIndicatorLineColor = 92
	SidebarHeaderBackgroundColor = 93
	SidebarHeaderTextColor = 94
	SidebarWidgetBackgroundColor = 95
	ActivePaneBackgroundColor = 96
	InactivePaneBackgroundColor = 97
	FocusedPaneBackgroundColor = 98
	TabBarTabActiveColor = 99
	TabBarTabHoverColor = 100
	TabBarTabInactiveColor = 101
	TabBarTabBorderColor = 102
	TabBarTabGlowColor = 103
	StatusBarServerConnectedColor = 104
	StatusBarServerDisconnectedColor = 105
	StatusBarServerWarningColor = 106
	StatusBarProjectColor = 107
	BraceOption1Color = 108
	BraceOption2Color = 109
	BraceOption3Color = 110
	BraceOption4Color = 111
	BraceOption5Color = 112
	BraceOption6Color = 113
	VoidTypeColor = 114
	StructureTypeColor = 115
	EnumerationTypeColor = 116
	FunctionTypeColor = 117
	BoolTypeColor = 118
	IntegerTypeColor = 119
	FloatTypeColor = 120
	PointerTypeColor = 121
	ArrayTypeColor = 122
	VarArgsTypeColor = 123
	ValueTypeColor = 124
	NamedTypeReferenceColor = 125
	WideCharTypeColor = 126


class TokenEscapingType(enum.IntEnum):
	NoTokenEscapingType = 0
	BackticksTokenEscapingType = 1
	QuotedStringEscapingType = 2
	ReplaceInvalidCharsEscapingType = 3


class TransformCapabilities(enum.IntFlag):
	TransformNoCapabilities = 0
	TransformSupportsDetection = 1
	TransformSupportsContext = 2


class TransformResult(enum.IntEnum):
	TransformSuccess = 0
	TransformNotAttempted = 1
	TransformFailure = 2
	TransformRequiresPassword = 3


class TransformSessionMode(enum.IntEnum):
	TransformSessionModeDisabled = 0
	TransformSessionModeFull = 1
	TransformSessionModeInteractive = 2


class TransformType(enum.IntEnum):
	BinaryCodecTransform = 0
	TextCodecTransform = 1
	UnicodeCodecTransform = 2
	DecodeTransform = 3
	BinaryEncodeTransform = 4
	TextEncodeTransform = 5
	EncryptTransform = 6
	InvertingTransform = 7
	HashTransform = 8


class TypeClass(enum.IntEnum):
	VoidTypeClass = 0
	BoolTypeClass = 1
	IntegerTypeClass = 2
	FloatTypeClass = 3
	StructureTypeClass = 4
	EnumerationTypeClass = 5
	PointerTypeClass = 6
	ArrayTypeClass = 7
	FunctionTypeClass = 8
	VarArgsTypeClass = 9
	ValueTypeClass = 10
	NamedTypeReferenceClass = 11
	WideCharTypeClass = 12
	FragmentTypeClass = 13


class TypeContainerType(enum.IntEnum):
	AnalysisTypeContainerType = 0
	AnalysisAutoTypeContainerType = 1
	AnalysisUserTypeContainerType = 2
	TypeLibraryTypeContainerType = 3
	TypeArchiveTypeContainerType = 4
	DebugInfoTypeContainerType = 5
	PlatformTypeContainerType = 6
	EmptyTypeContainerType = 7
	OtherTypeContainerType = 8


class TypeDefinitionLineType(enum.IntEnum):
	TypedefLineType = 0
	StructDefinitionLineType = 1
	StructFieldLineType = 2
	StructDefinitionEndLineType = 3
	EnumDefinitionLineType = 4
	EnumMemberLineType = 5
	EnumDefinitionEndLineType = 6
	PaddingLineType = 7
	UndefinedXrefLineType = 8
	CollapsedPaddingLineType = 9
	EmptyLineType = 10


class TypeParserErrorSeverity(enum.IntEnum):
	IgnoredSeverity = 0
	NoteSeverity = 1
	RemarkSeverity = 2
	WarningSeverity = 3
	ErrorSeverity = 4
	FatalSeverity = 5


class TypeParserOption(enum.IntEnum):
	IncludeSystemTypes = 0
	BuiltinMacros = 1


class TypeReferenceType(enum.IntEnum):
	DirectTypeReferenceType = 0
	IndirectTypeReferenceType = 1
	UnknownTypeReferenceType = 2


class UpdateResult(enum.IntEnum):
	UpdateFailed = 0
	UpdateSuccess = 1
	AlreadyUpToDate = 2
	UpdateAvailable = 3


class ValueLocationSource(enum.IntEnum):
	DefaultLocationSource = 0
	PassByValueLocationSource = 1
	PassByReferenceLocationSource = 2
	CustomLocationSource = 3


class VariableSourceType(enum.IntEnum):
	StackVariableSourceType = 0
	RegisterVariableSourceType = 1
	FlagVariableSourceType = 2
	CompositeReturnValueSourceType = 3
	CompositeParameterSourceType = 4


class PluginLoadStatus(enum.IntEnum):
	NotAttemptedStatus = 0
	LoadSucceededStatus = 1
	LoadFailedStatus = 2
