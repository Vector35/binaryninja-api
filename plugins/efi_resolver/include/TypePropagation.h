#pragma once

#include "Utils.h"
#include "AnalysisUpdates.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

class TypePropagation
{
	Ref<BinaryView> m_view;
	AnalysisUpdates m_updates;
	using FunctionKey = std::pair<std::string, uint64_t>;
	using PendingFunctionTypes = std::map<FunctionKey, Ref<Type>>;
	std::deque<FunctionKey> m_queue;
	std::set<FunctionKey> m_processed;

	bool propagateFuncParamTypes(Function* func);
	bool propagateFuncParamTypes(Function* func, SSAVariable ssa_var, PendingFunctionTypes& pendingTypes);

public:
	TypePropagation(BinaryView* view, bool automatic = false);
	const AnalysisUpdates& GetUpdates() const { return m_updates; }
	void QueueFunction(Function* func);
	bool HasPendingFunctions() const { return !m_queue.empty(); }
	// The caller must complete analysis before each call, including for newly queued roots.
	void ProcessNextFunction();
	Ref<Metadata> SaveState() const;
	void RestoreState(Ref<Metadata> metadata);
};
