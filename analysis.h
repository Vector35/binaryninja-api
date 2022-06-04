#pragma once


extern "C" {
	struct BNFunction;
	struct BNBinaryView;
	struct BNBackgroundTask;

	enum BNAnalysisState
	{
		InitialState,
		HoldState,
		IdleState,
		DisassembleState,
		AnalyzeState,
		ExtendedAnalyzeState
	};

	struct BNActiveAnalysisInfo
	{
		BNFunction* func;
		uint64_t analysisTime;
		size_t updateCount;
		size_t submitCount;
	};

	struct BNAnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		BNActiveAnalysisInfo* activeInfo;
		size_t count;
	};

	struct BNAnalysisProgress
	{
		BNAnalysisState state;
		size_t count, total;
	};

	enum BNAnalysisMode
	{
		FullAnalysisMode,
		IntermediateAnalysisMode,
		BasicAnalysisMode,
		ControlFlowAnalysisMode
	};

	struct BNAnalysisParameters
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
	};

	BINARYNINJACOREAPI BNAnalysisInfo* BNGetAnalysisInfo(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeAnalysisInfo(BNAnalysisInfo* info);
	BINARYNINJACOREAPI BNAnalysisProgress BNGetAnalysisProgress(BNBinaryView* view);
	BINARYNINJACOREAPI BNBackgroundTask* BNGetBackgroundAnalysisTask(BNBinaryView* view);
}