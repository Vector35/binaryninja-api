#pragma once

#include "uitypes.h"

#include <optional>
#include <string>
#include <vector>


// Captures user settings and intent for opening a container file, and provides
// policy decisions (e.g. whether to show the container browser) after processing.
class BINARYNINJAUIAPI ContainerOpenRequest
{
public:
	enum Action {
		Cancel,
		AutoOpen,
		BrowseContainer,
		SelectArchitecture,
	};

	explicit ContainerOpenRequest(const std::string& path, bool forceContainerBrowser = false);
	explicit ContainerOpenRequest(ProjectFileRef projectFile, bool forceContainerBrowser = false);

	TransformSessionRef session() const { return m_session; }

	// Create the session, process it, and determine what action the caller
	// should take. Returns Cancel if the session could not be created.
	Action resolve();

	// Get the default selection from a processed session. If no selection has
	// been made (e.g. because the session auto-opened), selects the current leaf.
	std::vector<TransformContextRef> selectedContexts();

	// When the container is a universal binary, the available architectures and the
	// index of the preferred one (if any).
	const std::vector<TransformContextRef>& architectureContexts() const { return m_archContexts; }
	std::optional<size_t> preferredArchitectureIndex() const { return m_preferredArch; }

private:
	Action resolveUniversal(TransformContextRef universalCtx);

	TransformSessionRef m_session;
	std::vector<TransformContextRef> m_archContexts;
	std::optional<size_t> m_preferredArch;
	bool m_forceContainerBrowser = false;
	bool m_autoOpen = false;
};
