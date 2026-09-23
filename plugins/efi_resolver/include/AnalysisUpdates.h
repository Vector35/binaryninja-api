#pragma once

#include "binaryninjaapi.h"
#include <functional>

// Apply discovered annotations before the resolver continues inspecting the view.
// Automatic analysis uses short main-thread undo scopes; manual commands retain
// their normal mutation and undo behavior.
class AnalysisUpdates
{
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	bool m_automatic;

public:
	AnalysisUpdates(BinaryNinja::BinaryView* view, bool automatic) : m_view(view), m_automatic(automatic) {}

	// Only mutations belong in this callback. Compute types, names, and targets on
	// the calling thread, and never wait for analysis inside it. This is synchronous
	// so subsequent resolver reads see these writes and reference captures are safe.
	void Apply(const std::function<void()>& update) const;
	void CreateUserVariable(BinaryNinja::Ref<BinaryNinja::Function> func, const BinaryNinja::Variable& variable,
		const BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>& type, const std::string& name) const;
};
