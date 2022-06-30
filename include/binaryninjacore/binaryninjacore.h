// Copyright (c) 2015-2022 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#ifndef __BINARYNINJACORE_H__
#define __BINARYNINJACORE_H__

#ifndef BN_TYPE_PARSER
#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif
#endif

#include "activity.h"
#include "analysis.h"
#include "architecture.h"
#include "backgroundtask.h"
#include "basicblock.h"
#include "binaryninja_defs.h"
#include "binaryreader.h"
#include "binaryview.h"
#include "binaryviewtype.h"
#include "binarywriter.h"
#include "callingconvention.h"
#include "database.h"
#include "databuffer.h"
#include "datarenderer.h"
#include "datavariable.h"
#include "debuginfo.h"
#include "demangle.h"
#include "downloadprovider.h"
#include "fileaccessor.h"
#include "filemetadata.h"
#include "flowgraph.h"
#include "function.h"
#include "functionrecognizer.h"
#include "highlevelil.h"
#include "ilsourcelocation.h"
#include "interaction.h"
#include "languagerepresentation.h"
#include "linearviewobject.h"
#include "log.h"
#include "lowlevelil.h"
#include "mainthread.h"
#include "mediumlevelil.h"
#include "metadata.h"
#include "navigationhandler.h"
#include "platform.h"
#include "plugincommand.h"
#include "pluginmanager.h"
#include "qualifiedname.h"
#include "rapidjsonwrapper.h"
#include "registervalue.h"
#include "relocationhandler.h"
#include "scriptingprovider.h"
#include "secretsprovider.h"
#include "settings.h"
#include "symbol.h"
#include "tag.h"
#include "tempfile.h"
#include "transform.h"
#include "type.h"
#include "typeparser.h"
#include "typeprinter.h"
#include "update.h"
#include "user.h"
#include "websocketprovider.h"
#include "workflow.h"

// Current ABI version for linking to the core. This is incremented any time
// there are changes to the API that affect linking, including new functions,
// new types, or modifications to existing functions or types.
#define BN_CURRENT_CORE_ABI_VERSION 21

// Minimum ABI version that is supported for loading of plugins. Plugins that
// are linked to an ABI version less than this will not be able to load and
// will require rebuilding. The minimum version is increased when there are
// incompatible changes that break binary compatibility, such as changes to
// existing types or functions.
#define BN_MINIMUM_CORE_ABI_VERSION 20


#ifdef WIN32
	#define PATH_SEP "\\"
#else
	#define PATH_SEP "/"
#endif

#define BN_MAX_STORED_DATA_LENGTH 0x3fffffff
#define BN_NULL_ID                -1


#define BN_AUTOCOERCE_EXTERN_PTR 0xfffffffd
#define BN_NOCOERCE_EXTERN_PTR   0xfffffffe
#define BN_INVALID_OPERAND       0xffffffff


#define BN_MAX_STRING_LENGTH 128

#define LLVM_SVCS_CB_NOTE    0
#define LLVM_SVCS_CB_WARNING 1
#define LLVM_SVCS_CB_ERROR   2

#define LLVM_SVCS_DIALECT_UNSPEC 0
#define LLVM_SVCS_DIALECT_ATT    1
#define LLVM_SVCS_DIALECT_INTEL  2

#define LLVM_SVCS_CM_DEFAULT 0
#define LLVM_SVCS_CM_SMALL   1
#define LLVM_SVCS_CM_KERNEL  2
#define LLVM_SVCS_CM_MEDIUM  3
#define LLVM_SVCS_CM_LARGE   4

#define LLVM_SVCS_RM_STATIC         0
#define LLVM_SVCS_RM_PIC            1
#define LLVM_SVCS_RM_DYNAMIC_NO_PIC 2

#define BN_MAX_VARIABLE_OFFSET 0x7fffffffffLL
#define BN_MAX_VARIABLE_INDEX  0xfffff


// The BN_DECLARE_CORE_ABI_VERSION must be included in native plugin modules. If
// the ABI version is not declared, the core will not load the plugin.
#ifdef DEMO_VERSION
	#define BN_DECLARE_CORE_ABI_VERSION
#else
	#define BN_DECLARE_CORE_ABI_VERSION \
		extern "C" \
		{ \
			BINARYNINJAPLUGIN uint32_t CorePluginABIVersion() { return BN_CURRENT_CORE_ABI_VERSION; } \
		}
#endif


#ifdef __cplusplus
extern "C"
{
#endif
	enum BNPluginLoadOrder
	{
		EarlyPluginLoadOrder,
		NormalPluginLoadOrder,
		LatePluginLoadOrder
	};

	enum PluginLoadStatus
	{
		NotAttemptedStatus,
		LoadSucceededStatus,
		LoadFailedStatus
	};

	typedef bool (*BNCorePluginInitFunction)(void);
	typedef void (*BNCorePluginDependencyFunction)(void);
	typedef uint32_t (*BNCorePluginABIVersionFunction)(void);

	struct BNBinaryView;
	struct BNBinaryViewType;
	struct BNBinaryReader;
	struct BNBinaryWriter;
	struct BNKeyValueStore;
	struct BNSnapshot;
	struct BNDatabase;
	struct BNFileMetadata;
	struct BNTransform;
	struct BNArchitecture;
	struct BNFunction;
	struct BNBasicBlock;
	struct BNDownloadProvider;
	struct BNDownloadInstance;
	struct BNWebsocketProvider;
	struct BNTypeParser;
	struct BNTypePrinter;
	struct BNFlowGraph;
	struct BNFlowGraphNode;
	struct BNSymbol;
	struct BNTemporaryFile;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;
	struct BNHighLevelILFunction;
	struct BNLanguageRepresentationFunction;
	struct BNType;
	struct BNTypeBuilder;
	struct BNTypeLibrary;
	struct BNTypeLibraryMapping;
	struct BNStructure;
	struct BNStructureBuilder;
	struct BNTagType;
	struct BNTag;
	struct BNTagReference;
	struct BNUser;
	struct BNNamedTypeReference;
	struct BNNamedTypeReferenceBuilder;
	struct BNEnumeration;
	struct BNEnumerationBuilder;
	struct BNCallingConvention;
	struct BNPlatform;
	struct BNActivity;
	struct BNAnalysisContext;
	struct BNWorkflow;
	struct BNDisassemblySettings;
	struct BNSaveSettings;
	struct BNScriptingProvider;
	struct BNScriptingInstance;
	struct BNBackgroundTask;
	struct BNRepository;
	struct BNRepoPlugin;
	struct BNRepositoryManager;
	struct BNSettings;
	struct BNMetadata;
	struct BNReportCollection;
	struct BNRelocation;
	struct BNSegment;
	struct BNSection;
	struct BNRelocationHandler;
	struct BNDataBuffer;
	struct BNDataRenderer;
	struct BNDataRendererContainer;
	struct BNDisassemblyTextRenderer;
	struct BNLinearViewObject;
	struct BNLinearViewCursor;
	struct BNDebugInfo;
	struct BNDebugInfoParser;
	struct BNLogger;
	struct BNInstructionTextLine;

	enum BNAnalysisWarningActionType
	{
		NoAnalysisWarningAction = 0,
		ForceAnalysisWarningAction = 1,
		ShowStackGraphWarningAction = 2
	};

	enum BNCallingConventionName
	{
		NoCallingConvention,
		CdeclCallingConvention,
		PascalCallingConvention,
		ThisCallCallingConvention,
		STDCallCallingConvention,
		FastcallCallingConvention,
		CLRCallCallingConvention,
		EabiCallCallingConvention,
		VectorCallCallingConvention
	};




	struct BNTypeDefinitionLine;

	struct BNNameAndType;




	struct BNTypeFieldReference;

	struct BNTypeField
	{
		BNQualifiedName name;
		uint64_t offset;
	};


	struct BNMergeResult;


	struct BNStackVariableReference;

	enum BNWorkflowState
	{
		WorkflowInitial,
		WorkflowIdle,
		WorkflowRun,
		WorkflowHalt,
		WorkflowHold,
		WorkflowInvalid
	};


	enum BNFindRangeType
	{
		AllRangeType,
		CustomRangeType,
		CurrentFunctionRangeType
	};

	enum BNFindType
	{
		FindTypeRawString,
		FindTypeEscapedString,
		FindTypeText,
		FindTypeConstant,
		FindTypeBytes
	};



	struct BNObjectDestructionCallbacks
	{
		void* context;
		// The provided pointers have a reference count of zero. Do not add additional references, doing so
		// can lead to a double free. These are provided only for freeing additional state related to the
		// objects passed.
		void (*destructBinaryView)(void* ctxt, BNBinaryView* view);
		void (*destructFileMetadata)(void* ctxt, BNFileMetadata* file);
		void (*destructFunction)(void* ctxt, BNFunction* func);
	};

	enum BNSegmentFlag
	{
		SegmentExecutable = 1,
		SegmentWritable = 2,
		SegmentReadable = 4,
		SegmentContainsData = 8,
		SegmentContainsCode = 0x10,
		SegmentDenyWrite = 0x20,
		SegmentDenyExecute = 0x40
	};

	struct BNMemoryUsageInfo
	{
		char* name;
		uint64_t value;
	};


	struct BNCallingConvention;
	

	BINARYNINJACOREAPI char* BNAllocString(const char* contents);
	BINARYNINJACOREAPI void BNFreeString(char* str);
	BINARYNINJACOREAPI char** BNAllocStringList(const char** contents, size_t size);
	BINARYNINJACOREAPI void BNFreeStringList(char** strs, size_t count);

	BINARYNINJACOREAPI void BNShutdown(void);
	BINARYNINJACOREAPI bool BNIsShutdownRequested(void);

	BINARYNINJACOREAPI char* BNGetVersionString(void);
	BINARYNINJACOREAPI uint32_t BNGetBuildId(void);
	BINARYNINJACOREAPI uint32_t BNGetCurrentCoreABIVersion(void);
	BINARYNINJACOREAPI uint32_t BNGetMinimumCoreABIVersion(void);

	BINARYNINJACOREAPI char* BNGetSerialNumber(void);
	BINARYNINJACOREAPI uint64_t BNGetLicenseExpirationTime(void);
	BINARYNINJACOREAPI bool BNIsLicenseValidated(void);
	BINARYNINJACOREAPI char* BNGetLicensedUserEmail(void);
	BINARYNINJACOREAPI char* BNGetProduct(void);
	BINARYNINJACOREAPI char* BNGetProductType(void);
	BINARYNINJACOREAPI int BNGetLicenseCount(void);
	BINARYNINJACOREAPI bool BNIsUIEnabled(void);
	BINARYNINJACOREAPI void BNSetLicense(const char* licenseData);

	BINARYNINJACOREAPI bool BNAuthenticateEnterpriseServerWithCredentials(
	    const char* username, const char* password, bool remember);
	BINARYNINJACOREAPI bool BNAuthenticateEnterpriseServerWithMethod(const char* method, bool remember);
	BINARYNINJACOREAPI size_t BNGetEnterpriseServerAuthenticationMethods(char*** methods, char*** names);
	BINARYNINJACOREAPI bool BNDeauthenticateEnterpriseServer(void);
	BINARYNINJACOREAPI void BNCancelEnterpriseServerAuthentication(void);
	BINARYNINJACOREAPI bool BNConnectEnterpriseServer(void);
	BINARYNINJACOREAPI bool BNAcquireEnterpriseServerLicense(uint64_t timeout);
	BINARYNINJACOREAPI bool BNReleaseEnterpriseServerLicense(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerConnected(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerAuthenticated(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerUsername(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerToken(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerUrl(void);
	BINARYNINJACOREAPI bool BNSetEnterpriseServerUrl(const char* url);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerName(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerId(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerVersion(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerBuildId(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerLicenseExpirationTime(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerLicenseDuration(void);
	BINARYNINJACOREAPI uint64_t BNGetEnterpriseServerReservationTimeLimit(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerLicenseStillActivated(void);
	BINARYNINJACOREAPI char* BNGetEnterpriseServerLastError(void);
	BINARYNINJACOREAPI bool BNIsEnterpriseServerInitialized(void);

	BINARYNINJACOREAPI void BNRegisterObjectDestructionCallbacks(BNObjectDestructionCallbacks* callbacks);
	BINARYNINJACOREAPI void BNUnregisterObjectDestructionCallbacks(BNObjectDestructionCallbacks* callbacks);

	BINARYNINJACOREAPI char* BNGetUniqueIdentifierString(void);

	// Plugin initialization
	BINARYNINJACOREAPI bool BNInitPlugins(bool allowUserPlugins);
	BINARYNINJACOREAPI bool BNInitCorePlugins(void);  // Deprecated, use BNInitPlugins
	BINARYNINJACOREAPI void BNDisablePlugins(void);
	BINARYNINJACOREAPI bool BNIsPluginsEnabled(void);
	BINARYNINJACOREAPI void BNInitUserPlugins(void);  // Deprecated, use BNInitPlugins
	BINARYNINJACOREAPI void BNInitRepoPlugins(void);

	BINARYNINJACOREAPI char* BNGetInstallDirectory(void);
	BINARYNINJACOREAPI char* BNGetBundledPluginDirectory(void);
	BINARYNINJACOREAPI void BNSetBundledPluginDirectory(const char* path);
	BINARYNINJACOREAPI char* BNGetUserDirectory(void);
	BINARYNINJACOREAPI char* BNGetUserPluginDirectory(void);
	BINARYNINJACOREAPI char* BNGetRepositoriesDirectory(void);
	BINARYNINJACOREAPI char* BNGetSettingsFileName(void);
	BINARYNINJACOREAPI void BNSaveLastRun(void);

	BINARYNINJACOREAPI char* BNGetPathRelativeToBundledPluginDirectory(const char* path);
	BINARYNINJACOREAPI char* BNGetPathRelativeToUserPluginDirectory(const char* path);
	BINARYNINJACOREAPI char* BNGetPathRelativeToUserDirectory(const char* path);

	BINARYNINJACOREAPI bool BNExecuteWorkerProcess(const char* path, const char* args[], BNDataBuffer* input,
	    char** output, char** error, bool stdoutIsText, bool stderrIsText);

	BINARYNINJACOREAPI void BNSetCurrentPluginLoadOrder(BNPluginLoadOrder order);
	BINARYNINJACOREAPI void BNAddRequiredPluginDependency(const char* name);
	BINARYNINJACOREAPI void BNAddOptionalPluginDependency(const char* name);

	struct BNQualifiedNameAndType;

	// Disassembly settings

	BINARYNINJACOREAPI BNDebugInfo* BNGetDebugInfo(BNBinaryView* view);
	BINARYNINJACOREAPI void BNApplyDebugInfo(BNBinaryView* view, BNDebugInfo* newDebugInfo);
	BINARYNINJACOREAPI void BNSetDebugInfo(BNBinaryView* view, BNDebugInfo* newDebugInfo);

	
	BINARYNINJACOREAPI void BNFreeLLILVariablesList(uint32_t* vars);
	BINARYNINJACOREAPI void BNFreeLLILVariableVersionList(size_t* versions);

	// Type Libraries
	BINARYNINJACOREAPI BNTypeLibrary* BNNewTypeLibrary(BNArchitecture* arch, const char* name);
	BINARYNINJACOREAPI BNTypeLibrary* BNNewTypeLibraryReference(BNTypeLibrary* lib);
	BINARYNINJACOREAPI BNTypeLibrary* BNDuplicateTypeLibrary(BNTypeLibrary* lib);
	BINARYNINJACOREAPI BNTypeLibrary* BNLoadTypeLibraryFromFile(const char* path);
	BINARYNINJACOREAPI void BNFreeTypeLibrary(BNTypeLibrary* lib);

	BINARYNINJACOREAPI BNTypeLibrary* BNLookupTypeLibraryByName(BNArchitecture* arch, const char* name);
	BINARYNINJACOREAPI BNTypeLibrary* BNLookupTypeLibraryByGuid(BNArchitecture* arch, const char* guid);

	BINARYNINJACOREAPI BNTypeLibrary** BNGetArchitectureTypeLibraries(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeLibraryList(BNTypeLibrary** lib, size_t count);

	BINARYNINJACOREAPI void BNFinalizeTypeLibrary(BNTypeLibrary* lib);

	BINARYNINJACOREAPI BNArchitecture* BNGetTypeLibraryArchitecture(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNSetTypeLibraryName(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char* BNGetTypeLibraryName(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNAddTypeLibraryAlternateName(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char** BNGetTypeLibraryAlternateNames(BNTypeLibrary* lib, size_t* count);  // BNFreeStringList

	BINARYNINJACOREAPI void BNSetTypeLibraryDependencyName(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char* BNGetTypeLibraryDependencyName(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNSetTypeLibraryGuid(BNTypeLibrary* lib, const char* name);
	BINARYNINJACOREAPI char* BNGetTypeLibraryGuid(BNTypeLibrary* lib);

	BINARYNINJACOREAPI void BNClearTypeLibraryPlatforms(BNTypeLibrary* lib);
	BINARYNINJACOREAPI void BNAddTypeLibraryPlatform(BNTypeLibrary* lib, BNPlatform* platform);
	BINARYNINJACOREAPI char** BNGetTypeLibraryPlatforms(BNTypeLibrary* lib, size_t* count);  // BNFreeStringList

	BINARYNINJACOREAPI void BNTypeLibraryStoreMetadata(BNTypeLibrary* lib, const char* key, BNMetadata* value);
	BINARYNINJACOREAPI BNMetadata* BNTypeLibraryQueryMetadata(BNTypeLibrary* lib, const char* key);
	BINARYNINJACOREAPI void BNTypeLibraryRemoveMetadata(BNTypeLibrary* lib, const char* key);

	BINARYNINJACOREAPI void BNAddTypeLibraryNamedObject(BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNAddTypeLibraryNamedType(BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNAddTypeLibraryNamedTypeSource(BNTypeLibrary* lib, BNQualifiedName* name, const char* source);

	BINARYNINJACOREAPI BNType* BNGetTypeLibraryNamedObject(BNTypeLibrary* lib, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetTypeLibraryNamedType(BNTypeLibrary* lib, BNQualifiedName* name);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetTypeLibraryNamedObjects(BNTypeLibrary* lib, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetTypeLibraryNamedTypes(BNTypeLibrary* lib, size_t* count);

	BINARYNINJACOREAPI void BNWriteTypeLibraryToFile(BNTypeLibrary* lib, const char* path);

	BINARYNINJACOREAPI void BNAddBinaryViewTypeLibrary(BNBinaryView* view, BNTypeLibrary* lib);
	BINARYNINJACOREAPI BNTypeLibrary* BNGetBinaryViewTypeLibrary(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNTypeLibrary** BNGetBinaryViewTypeLibraries(BNBinaryView* view, size_t* count);

	BINARYNINJACOREAPI BNType* BNBinaryViewImportTypeLibraryType(
	    BNBinaryView* view, BNTypeLibrary* lib, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNBinaryViewImportTypeLibraryObject(
	    BNBinaryView* view, BNTypeLibrary* lib, BNQualifiedName* name);

	BINARYNINJACOREAPI void BNBinaryViewExportTypeToTypeLibrary(
	    BNBinaryView* view, BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);
	BINARYNINJACOREAPI void BNBinaryViewExportObjectToTypeLibrary(
	    BNBinaryView* view, BNTypeLibrary* lib, BNQualifiedName* name, BNType* type);

	// Worker thread queue management
	BINARYNINJACOREAPI void BNWorkerEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerPriorityEnqueue(void* ctxt, void (*action)(void* ctxt));
	BINARYNINJACOREAPI void BNWorkerInteractiveEnqueue(void* ctxt, void (*action)(void* ctxt));

	BINARYNINJACOREAPI size_t BNGetWorkerThreadCount(void);
	BINARYNINJACOREAPI void BNSetWorkerThreadCount(size_t count);

	// LLVM Services APIs
	BINARYNINJACOREAPI void BNLlvmServicesInit(void);

	BINARYNINJACOREAPI int BNLlvmServicesAssemble(const char* src, int dialect, const char* triplet, int codeModel,
	    int relocMode, char** outBytes, int* outBytesLen, char** err, int* errLen);

	BINARYNINJACOREAPI void BNLlvmServicesAssembleFree(char* outBytes, char* err);


	BINARYNINJACOREAPI void* BNRegisterObjectRefDebugTrace(const char* typeName);
	BINARYNINJACOREAPI void BNUnregisterObjectRefDebugTrace(const char* typeName, void* trace);
	BINARYNINJACOREAPI BNMemoryUsageInfo* BNGetMemoryUsageInfo(size_t* count);
	BINARYNINJACOREAPI void BNFreeMemoryUsageInfo(BNMemoryUsageInfo* info, size_t count);

	BINARYNINJACOREAPI uint32_t BNGetAddressRenderedWidth(uint64_t addr);

#ifdef __cplusplus
}
#endif

#endif
