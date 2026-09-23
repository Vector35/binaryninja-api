#include "AnalysisUpdates.h"
#include <exception>

using namespace BinaryNinja;

void AnalysisUpdates::Apply(const std::function<void()>& update) const
{
	if (!m_automatic)
	{
		update();
		return;
	}

	std::exception_ptr error;
	ExecuteOnMainThreadAndWait([&]() {
		try
		{
			// Undo scopes are file-wide. Open and close this scope within a single
			// UI callback so UI edits cannot enter it between resolver writes.
			struct UndoScope
			{
				Ref<BinaryView> view;
				std::string id;
				~UndoScope() { view->ForgetUndoActions(id); }
			} undoScope {m_view, m_view->BeginUndoActions(false)};
			update();
		}
		catch (...)
		{
			// Report errors on the workflow thread after restoring the dirty flags.
			error = std::current_exception();
		}
	});
	if (error)
		std::rethrow_exception(error);
}

void AnalysisUpdates::CreateUserVariable(Ref<Function> func, const Variable& variable,
	const Confidence<Ref<Type>>& type, const std::string& name) const
{
	Apply([&]() { func->CreateUserVariable(variable, type, name); });
}
