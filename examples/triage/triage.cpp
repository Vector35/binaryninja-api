#include "uitypes.h"
#include "view.h"
#include "files.h"
#include "byte.h"


extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

#ifdef DEMO_EDITION
	bool TriagePluginInit()
#else
	BINARYNINJAPLUGIN bool UIPluginInit()
#endif
	{
		SettingsRef settings = BinaryNinja::Settings::Instance();
		settings->RegisterGroup("triage", "Triage");
		settings->RegisterSetting("triage.preferSummaryView",
		    R"({
				"title" : "Always Prefer Triage Summary View",
				"type" : "boolean",
				"default" : false,
				"description" : "Always prefer opening binaries in Triage Summary view, even when performing full analysis."
			})");

		settings->RegisterSetting("triage.preferSummaryViewForRaw",
		    R"({
				"title" : "Prefer Triage Summary View for Raw Files",
				"type" : "boolean",
				"default" : false,
				"description" : "Prefer opening raw files in Triage Summary view."
			})");

		ViewType::registerViewType(new TriageViewType());

		settings->RegisterSetting("triage.analysisMode",
		    R"({
				"title" : "Triage Analysis Mode",
				"type" : "string",
				"default" : "basic",
				"description" : "Controls the amount of analysis performed on functions when opening for triage.",
				"enum" : ["controlFlow", "basic", "full"],
				"enumDescriptions" : [
					"Only perform control flow analysis on the binary. Cross references are valid only for direct function calls.",
					"Perform fast initial analysis of the binary. This mode does not analyze types or data flow through stack variables.",
					"Perform full analysis of the binary." ]
			})");

		settings->RegisterSetting("triage.linearSweep",
		    R"({
				"title" : "Triage Linear Sweep Mode",
				"type" : "string",
				"default" : "partial",
				"description" : "Controls the level of linear sweep performed when opening for triage.",
				"enum" : ["none", "partial", "full"],
				"enumDescriptions" : [
					"Do not perform linear sweep of the binary.",
					"Perform linear sweep on the binary, but skip the control flow graph analysis phase.",
					"Perform full linear sweep on the binary." ]
			})");

		settings->RegisterSetting("triage.hiddenFiles",
		    R"({
				"title" : "Triage Shows Hidden Files",
				"type" : "boolean",
				"default" : false,
				"description" : "Whether the Triage file picker shows hidden files."
			})");

		UIAction::registerAction("Open for Triage...", QKeySequence("Ctrl+Alt+O"));
		UIAction::registerAction("Open Selected Files");

		UIActionHandler::globalActions()->bindAction("Open for Triage...", UIAction([](const UIActionContext& context) {
			UIContext* currentContext = context.context;
			if (!currentContext)
				return;

			// Do not try to set the parent window when creating tabs, as this will create a parent relationship in
			// the bindings and will cause the widget to be destructed early. The correct parent will be assigned
			// when createTabForWidget is called.
			TriageFilePicker* fp = new TriageFilePicker(currentContext);
			currentContext->createTabForWidget("Open for Triage", fp);
		}));

		Menu::mainMenu("File")->addAction("Open for Triage...", "Open");

		UIContext::registerFileOpenMode(
		    "Triage...", "Open file(s) for quick analysis in the Triage Summary view.", "Open for Triage...");

		ViewType::registerViewType(new ByteViewType());
		return true;
	}
}
