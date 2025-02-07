#pragma once

#include "binaryninjaapi.h"

// Current ABI version for linking to the UI API. This is incremented any time
// there are changes to the API that affect linking, including new functions,
// new types, modifications to existing functions or types, or new versions
// of the Qt libraries.
#define BN_CURRENT_UI_ABI_VERSION 9

// Minimum ABI version that is supported for loading of plugins. Plugins that
// are linked to an ABI version less than this will not be able to load and
// will require rebuilding. The minimum version is increased when there are
// incompatible changes that break binary compatibility, such as changes to
// existing types or functions, or a new version of Qt.
#define BN_MINIMUM_UI_ABI_VERSION 9

#ifdef __GNUC__
	#ifdef BINARYNINJAUI_LIBRARY
		#define BINARYNINJAUIAPI __attribute__((visibility("default")))
	#else
		#define BINARYNINJAUIAPI
	#endif
#else
	#ifdef _MSC_VER
		#ifndef DEMO_EDITION
			#ifdef BINARYNINJAUI_LIBRARY
				#define BINARYNINJAUIAPI __declspec(dllexport)
			#else
				#define BINARYNINJAUIAPI __declspec(dllimport)
			#endif
		#else
			#define BINARYNINJAUIAPI
		#endif
	#else
		#define BINARYNINJAUIAPI
	#endif
#endif

#ifdef BINARYNINJAUI_PYTHON_BINDINGS
	#include "bindings.h"
#endif

// The BN_DECLARE_UI_ABI_VERSION must be included in native UI plugin modules. If
// the ABI version is not declared, the UI will not load the plugin.
#ifdef DEMO_EDITION
	#define BN_DECLARE_UI_ABI_VERSION
#else
	#define BN_DECLARE_UI_ABI_VERSION \
		extern "C" \
		{ \
			BINARYNINJAPLUGIN uint32_t UIPluginABIVersion() { return BN_CURRENT_UI_ABI_VERSION; } \
		}
#endif

/*!
    @addtogroup UITypes
    \ingroup uiapi
    @{
*/

// The Python bindings generator does not recognize automatic conversion of API types into their
// Python equivalents if using templates (Ref<*>), so we typedef all API references so that
// the Python bindings can be easily generated for them.
typedef BinaryNinja::Ref<BinaryNinja::Architecture> ArchitectureRef;
typedef BinaryNinja::Ref<BinaryNinja::BackgroundTask> BackgroundTaskRef;
typedef BinaryNinja::Ref<BinaryNinja::BasicBlock> BasicBlockRef;
typedef BinaryNinja::Ref<BinaryNinja::BinaryData> BinaryDataRef;
typedef BinaryNinja::Ref<BinaryNinja::BinaryView> BinaryViewRef;
typedef BinaryNinja::Ref<BinaryNinja::BinaryViewType> BinaryViewTypeRef;
typedef BinaryNinja::Ref<BinaryNinja::Component> ComponentRef;
typedef BinaryNinja::Ref<BinaryNinja::Database> DatabaseRef;
typedef BinaryNinja::Ref<BinaryNinja::DebugInfo> DebugInfoRef;
typedef BinaryNinja::Ref<BinaryNinja::DisassemblySettings> DisassemblySettingsRef;
typedef BinaryNinja::Ref<BinaryNinja::DownloadInstance> DownloadInstanceRef;
typedef BinaryNinja::Ref<BinaryNinja::DownloadProvider> DownloadProviderRef;
typedef BinaryNinja::Ref<BinaryNinja::Enumeration> EnumerationRef;
typedef BinaryNinja::Ref<BinaryNinja::ExternalLibrary> ExternalLibraryRef;
typedef BinaryNinja::Ref<BinaryNinja::ExternalLocation> ExternalLocationRef;
typedef BinaryNinja::Ref<BinaryNinja::FileMetadata> FileMetadataRef;
typedef BinaryNinja::Ref<BinaryNinja::FlowGraph> FlowGraphRef;
typedef BinaryNinja::Ref<BinaryNinja::FlowGraphLayoutRequest> FlowGraphLayoutRequestRef;
typedef BinaryNinja::Ref<BinaryNinja::FlowGraphNode> FlowGraphNodeRef;
typedef BinaryNinja::Ref<BinaryNinja::Function> FunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::KeyValueStore> KeyValueStoreRef;
typedef BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> LowLevelILFunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::MainThreadAction> MainThreadActionRef;
typedef BinaryNinja::Ref<BinaryNinja::MediumLevelILFunction> MediumLevelILFunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::HighLevelILFunction> HighLevelILFunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::Platform> PlatformRef;
typedef BinaryNinja::Ref<BinaryNinja::Project> ProjectRef;
typedef BinaryNinja::Ref<BinaryNinja::ProjectFile> ProjectFileRef;
typedef BinaryNinja::Ref<BinaryNinja::ProjectFolder> ProjectFolderRef;
typedef BinaryNinja::Ref<BinaryNinja::ReportCollection> ReportCollectionRef;
typedef BinaryNinja::Ref<BinaryNinja::SaveSettings> SaveSettingsRef;
typedef BinaryNinja::Ref<BinaryNinja::ScriptingInstance> ScriptingInstanceRef;
typedef BinaryNinja::Ref<BinaryNinja::ScriptingProvider> ScriptingProviderRef;
typedef BinaryNinja::Ref<BinaryNinja::SecretsProvider> SecretsProviderRef;
typedef BinaryNinja::Ref<BinaryNinja::Section> SectionRef;
typedef BinaryNinja::Ref<BinaryNinja::Segment> SegmentRef;
typedef BinaryNinja::Ref<BinaryNinja::Settings> SettingsRef;
typedef BinaryNinja::Ref<BinaryNinja::Snapshot> SnapshotRef;
typedef BinaryNinja::Ref<BinaryNinja::Structure> StructureRef;
typedef BinaryNinja::Ref<BinaryNinja::Symbol> SymbolRef;
typedef BinaryNinja::Ref<BinaryNinja::Tag> TagRef;
typedef BinaryNinja::Ref<BinaryNinja::TagType> TagTypeRef;
typedef BinaryNinja::Ref<BinaryNinja::TemporaryFile> TemporaryFileRef;
typedef BinaryNinja::Ref<BinaryNinja::Transform> TransformRef;
typedef BinaryNinja::Ref<BinaryNinja::Type> TypeRef;
typedef BinaryNinja::Ref<BinaryNinja::TypeArchive> TypeArchiveRef;
typedef BinaryNinja::Ref<BinaryNinja::TypeLibrary> TypeLibraryRef;
typedef BinaryNinja::Ref<BinaryNinja::WebsocketClient> WebsocketClientRef;
typedef BinaryNinja::Ref<BinaryNinja::WebsocketProvider> WebsocketProviderRef;
typedef BinaryNinja::Ref<BinaryNinja::RepoPlugin> RepoPluginRef;
typedef BinaryNinja::Ref<BinaryNinja::Repository> RepositoryRef;
typedef BinaryNinja::Ref<BinaryNinja::RepositoryManager> RepositoryManagerRef;
typedef BinaryNinja::Ref<BinaryNinja::Logger> LoggerRef;
typedef BinaryNinja::Ref<BinaryNinja::UndoAction> UndoActionRef;
typedef BinaryNinja::Ref<BinaryNinja::UndoEntry> UndoEntryRef;

typedef BinaryNinja::Ref<BinaryNinja::Collaboration::Remote> RemoteRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::RemoteProject> RemoteProjectRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::RemoteFile> RemoteFileRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::RemoteFolder> RemoteFolderRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::CollabGroup> GroupRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::CollabPermission> PermissionRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::CollabUser> CollabUserRef;
typedef BinaryNinja::Ref<BinaryNinja::Collaboration::CollabSnapshot> CollabSnapshotRef;
/*!
	@}
*/
