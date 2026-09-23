#pragma once

#include "Utils.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

class TypePropagation
{
	Ref<BinaryView> m_view;
	using FunctionKey = std::pair<std::string, uint64_t>;
	std::deque<FunctionKey> m_queue;
	std::set<FunctionKey> m_processed;

	bool propagateFuncParamTypes(Function* func);
	bool propagateFuncParamTypes(Function* func, SSAVariable ssa_var);

public:
	TypePropagation(BinaryView* view);
	void QueueFunction(Function* func);
	bool HasPendingFunctions() const { return !m_queue.empty(); }
	// The caller must complete analysis before each call, including for newly queued roots.
	void ProcessNextFunction();
	Ref<Metadata> SaveState() const;
	void RestoreState(Ref<Metadata> metadata);
};
