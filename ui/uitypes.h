#pragma once

#include "binaryninjaapi.h"

#ifdef __GNUC__
#  ifdef BINARYNINJAUI_LIBRARY
#    define BINARYNINJAUIAPI __attribute__((visibility("default")))
#  else
#    define BINARYNINJAUIAPI
#  endif
#else
#ifdef _MSC_VER
#  ifndef DEMO_VERSION
#   ifdef BINARYNINJAUI_LIBRARY
#     define BINARYNINJAUIAPI __declspec(dllexport)
#   else
#     define BINARYNINJAUIAPI __declspec(dllimport)
#   endif
#  else
#   define BINARYNINJAUIAPI
#  endif
#else
#define BINARYNINJAUIAPI
#endif
#endif

#ifdef BINARYNINJAUI_PYTHON_BINDINGS
#include "bindings.h"
#endif

// The Python bindings generator does not recognize automatic conversion of API types into their
// Python equivalents if using templates (Ref<*>), so we typedef all API references so that
// the Python bindings can be easily generated for them.
typedef BinaryNinja::Ref<BinaryNinja::Architecture> ArchitectureRef;
typedef BinaryNinja::Ref<BinaryNinja::BackgroundTask> BackgroundTaskRef;
typedef BinaryNinja::Ref<BinaryNinja::BasicBlock> BasicBlockRef;
typedef BinaryNinja::Ref<BinaryNinja::BinaryData> BinaryDataRef;
typedef BinaryNinja::Ref<BinaryNinja::BinaryView> BinaryViewRef;
typedef BinaryNinja::Ref<BinaryNinja::BinaryViewType> BinaryViewTypeRef;
typedef BinaryNinja::Ref<BinaryNinja::DisassemblySettings> DisassemblySettingsRef;
typedef BinaryNinja::Ref<BinaryNinja::DownloadProvider> DownloadProviderRef;
typedef BinaryNinja::Ref<BinaryNinja::FileMetadata> FileMetadataRef;
typedef BinaryNinja::Ref<BinaryNinja::FlowGraph> FlowGraphRef;
typedef BinaryNinja::Ref<BinaryNinja::FlowGraphLayoutRequest> FlowGraphLayoutRequestRef;
typedef BinaryNinja::Ref<BinaryNinja::FlowGraphNode> FlowGraphNodeRef;
typedef BinaryNinja::Ref<BinaryNinja::Function> FunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> LowLevelILFunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::MainThreadAction> MainThreadActionRef;
typedef BinaryNinja::Ref<BinaryNinja::MediumLevelILFunction> MediumLevelILFunctionRef;
typedef BinaryNinja::Ref<BinaryNinja::Platform> PlatformRef;
typedef BinaryNinja::Ref<BinaryNinja::ReportCollection> ReportCollectionRef;
typedef BinaryNinja::Ref<BinaryNinja::ScriptingInstance> ScriptingInstanceRef;
typedef BinaryNinja::Ref<BinaryNinja::ScriptingProvider> ScriptingProviderRef;
typedef BinaryNinja::Ref<BinaryNinja::Section> SectionRef;
typedef BinaryNinja::Ref<BinaryNinja::Segment> SegmentRef;
typedef BinaryNinja::Ref<BinaryNinja::Structure> StructureRef;
typedef BinaryNinja::Ref<BinaryNinja::Symbol> SymbolRef;
typedef BinaryNinja::Ref<BinaryNinja::TemporaryFile> TemporaryFileRef;
typedef BinaryNinja::Ref<BinaryNinja::Transform> TransformRef;
typedef BinaryNinja::Ref<BinaryNinja::Type> TypeRef;
typedef BinaryNinja::Ref<BinaryNinja::RepoPlugin> RepoPluginRef;
typedef BinaryNinja::Ref<BinaryNinja::Repository> RepositoryRef;
typedef BinaryNinja::Ref<BinaryNinja::RepositoryManager> RepositoryManagerRef;
