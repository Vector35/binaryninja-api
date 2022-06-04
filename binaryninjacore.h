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

#include "binaryninja_defs.h"
#include "qualifiedname.h"
#include "analysis.h"
#include "platform.h"
#include "registervalue.h"
#include "binaryview.h"
#include "type.h"

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
	struct BNWebsocketClient;
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
	struct BNMainThreadAction;
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
	struct BNSecretsProvider;
	struct BNLogger;
	struct BNInstructionTextLine;

	enum BNTransformType
	{
		BinaryCodecTransform = 0,   // Two-way transform of data, binary input/output
		TextCodecTransform = 1,     // Two-way transform of data, encoder output is text
		UnicodeCodecTransform = 2,  // Two-way transform of data, encoder output is Unicode string (as UTF8)
		DecodeTransform = 3,        // One-way decode only
		BinaryEncodeTransform = 4,  // One-way encode only, output is binary
		TextEncodeTransform = 5,    // One-way encode only, output is text
		EncryptTransform = 6,       // Two-way encryption
		InvertingTransform = 7,     // Transform that can be undone by performing twice
		HashTransform = 8           // Hash function
	};



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



	struct BNTransformParameterInfo
	{
		char* name;
		char* longName;
		size_t fixedLength;  // Variable length if zero
	};

	struct BNTransformParameter
	{
		const char* name;
		BNDataBuffer* value;
	};

	struct BNCustomTransform
	{
		void* context;
		BNTransformParameterInfo* (*getParameters)(void* ctxt, size_t* count);
		void (*freeParameters)(BNTransformParameterInfo* params, size_t count);
		bool (*decode)(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		bool (*encode)(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
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


	enum BNUpdateResult
	{
		UpdateFailed = 0,
		UpdateSuccess = 1,
		AlreadyUpToDate = 2,
		UpdateAvailable = 3
	};

	struct BNUpdateChannel
	{
		char* name;
		char* description;
		char* latestVersion;
	};

	struct BNUpdateVersion
	{
		char* version;
		char* notes;
		uint64_t time;
	};

	enum BNPluginCommandType
	{
		DefaultPluginCommand,
		AddressPluginCommand,
		RangePluginCommand,
		FunctionPluginCommand,
		LowLevelILFunctionPluginCommand,
		LowLevelILInstructionPluginCommand,
		MediumLevelILFunctionPluginCommand,
		MediumLevelILInstructionPluginCommand,
		HighLevelILFunctionPluginCommand,
		HighLevelILInstructionPluginCommand
	};

	struct BNPluginCommand
	{
		char* name;
		char* description;
		BNPluginCommandType type;
		void* context;

		void (*defaultCommand)(void* ctxt, BNBinaryView* view);
		void (*addressCommand)(void* ctxt, BNBinaryView* view, uint64_t addr);
		void (*rangeCommand)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		void (*functionCommand)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*lowLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		void (*lowLevelILInstructionCommand)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		void (*mediumLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		void (*mediumLevelILInstructionCommand)(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		void (*highLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		void (*highLevelILInstructionCommand)(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		bool (*defaultIsValid)(void* ctxt, BNBinaryView* view);
		bool (*addressIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr);
		bool (*rangeIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		bool (*functionIsValid)(void* ctxt, BNBinaryView* view, BNFunction* func);
		bool (*lowLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		bool (*lowLevelILInstructionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		bool (*mediumLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		bool (*mediumLevelILInstructionIsValid)(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		bool (*highLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		bool (*highLevelILInstructionIsValid)(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);
	};

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

	struct BNDownloadInstanceResponse
	{
		uint16_t statusCode;
		uint64_t headerCount;
		char** headerKeys;
		char** headerValues;
	};

	struct BNDownloadInstanceInputOutputCallbacks
	{
		int64_t (*readCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* readContext;
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	};

	struct BNDownloadInstanceOutputCallbacks
	{
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	};

	struct BNDownloadInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		int (*performRequest)(void* ctxt, const char* url);
		int (*performCustomRequest)(void* ctxt, const char* method, const char* url, uint64_t headerCount,
		    const char* const* headerKeys, const char* const* headerValues, BNDownloadInstanceResponse** response);
		void (*freeResponse)(void* ctxt, BNDownloadInstanceResponse* response);
	};

	struct BNDownloadProviderCallbacks
	{
		void* context;
		BNDownloadInstance* (*createInstance)(void* ctxt);
	};

	struct BNWebsocketClientOutputCallbacks
	{
		void* context;
		bool (*connectedCallback)(void* ctxt);
		void (*disconnectedCallback)(void* ctxt);
		void (*errorCallback)(const char* msg, void* ctxt);
		bool (*readCallback)(uint8_t* data, uint64_t len, void* ctxt);
	};

	struct BNWebsocketClientCallbacks
	{
		void* context;
		void (*destroyClient)(void* ctxt);
		bool (*connect)(void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys,
		    const char* const* headerValues);
		bool (*write)(const uint8_t* data, uint64_t len, void* ctxt);
		bool (*disconnect)(void* ctxt);
	};

	struct BNWebsocketProviderCallbacks
	{
		void* context;
		BNWebsocketClient* (*createClient)(void* ctxt);
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

	enum BNScriptingProviderInputReadyState
	{
		NotReadyForInput,
		ReadyForScriptExecution,
		ReadyForScriptProgramInput
	};

	enum BNScriptingProviderExecuteResult
	{
		InvalidScriptInput,
		IncompleteScriptInput,
		SuccessfulScriptExecution,
		ScriptExecutionCancelled
	};


	struct BNScriptingInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
		BNScriptingProviderExecuteResult (*executeScriptInput)(void* ctxt, const char* input);
		void (*cancelScriptInput)(void* ctxt);
		void (*setCurrentBinaryView)(void* ctxt, BNBinaryView* view);
		void (*setCurrentFunction)(void* ctxt, BNFunction* func);
		void (*setCurrentBasicBlock)(void* ctxt, BNBasicBlock* block);
		void (*setCurrentAddress)(void* ctxt, uint64_t addr);
		void (*setCurrentSelection)(void* ctxt, uint64_t begin, uint64_t end);
		char* (*completeInput)(void* ctxt, const char* text, uint64_t state);
		void (*stop)(void* ctxt);
	};

	struct BNScriptingProviderCallbacks
	{
		void* context;
		BNScriptingInstance* (*createInstance)(void* ctxt);
		bool (*loadModule)(void* ctxt, const char* repoPath, const char* pluginPath, bool force);
		bool (*installModules)(void* ctxt, const char* modules);
	};

	struct BNScriptingOutputListener
	{
		void* context;
		void (*output)(void* ctxt, const char* text);
		void (*error)(void* ctxt, const char* text);
		void (*inputReadyStateChanged)(void* ctxt, BNScriptingProviderInputReadyState state);
	};

	struct BNMainThreadCallbacks
	{
		void* context;
		void (*addAction)(void* ctxt, BNMainThreadAction* action);
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

	enum BNLinearViewObjectIdentifierType
	{
		SingleLinearViewObject,
		AddressLinearViewObject,
		AddressRangeLinearViewObject
	};

	struct BNLinearViewObjectIdentifier
	{
		char* name;
		BNLinearViewObjectIdentifierType type;
		uint64_t start, end;
	};

	struct BNCallingConvention;
	struct BNDebugFunctionInfo
	{
		char* shortName;
		char* fullName;
		char* rawName;
		uint64_t address;
		BNType* returnType;
		char** parameterNames;
		BNType** parameterTypes;
		size_t parameterCount;
		bool variableParameters;
		BNCallingConvention* callingConvention;
		BNPlatform* platform;
	};

	struct BNSecretsProviderCallbacks
	{
		void* context;
		bool (*hasData)(void* ctxt, const char* key);
		char* (*getData)(void* ctxt, const char* key);
		bool (*storeData)(void* ctxt, const char* key, const char* data);
		bool (*deleteData)(void* ctxt, const char* key);
	};

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

	// Temporary files
	BINARYNINJACOREAPI BNTemporaryFile* BNCreateTemporaryFile(void);
	BINARYNINJACOREAPI BNTemporaryFile* BNCreateTemporaryFileWithContents(BNDataBuffer* data);
	BINARYNINJACOREAPI BNTemporaryFile* BNNewTemporaryFileReference(BNTemporaryFile* file);
	BINARYNINJACOREAPI void BNFreeTemporaryFile(BNTemporaryFile* file);
	BINARYNINJACOREAPI char* BNGetTemporaryFilePath(BNTemporaryFile* file);
	BINARYNINJACOREAPI BNDataBuffer* BNGetTemporaryFileContents(BNTemporaryFile* file);


	// Transforms
	BINARYNINJACOREAPI BNTransform* BNGetTransformByName(const char* name);
	BINARYNINJACOREAPI BNTransform** BNGetTransformTypeList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformTypeList(BNTransform** xforms);
	BINARYNINJACOREAPI BNTransform* BNRegisterTransformType(
	    BNTransformType type, const char* name, const char* longName, const char* group, BNCustomTransform* xform);

	BINARYNINJACOREAPI BNTransformType BNGetTransformType(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformLongName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformGroup(BNTransform* xform);
	BINARYNINJACOREAPI BNTransformParameterInfo* BNGetTransformParameterList(BNTransform* xform, size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformParameterList(BNTransformParameterInfo* params, size_t count);
	BINARYNINJACOREAPI bool BNDecode(
	    BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
	BINARYNINJACOREAPI bool BNEncode(
	    BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewDisassembly(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLiftedIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLowLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLowLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMediumLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMediumLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMappedMediumLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewMappedMediumLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewHighLevelIL(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewHighLevelILSSAForm(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewLanguageRepresentation(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewDataOnly(
	    BNBinaryView* view, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionDisassembly(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLiftedIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLowLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLowLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMediumLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMappedMediumLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionMappedMediumLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionHighLevelIL(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionHighLevelILSSAForm(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNCreateLinearViewSingleFunctionLanguageRepresentation(
	    BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNLinearViewObject* BNNewLinearViewObjectReference(BNLinearViewObject* obj);
	BINARYNINJACOREAPI void BNFreeLinearViewObject(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetFirstLinearViewObjectChild(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLastLinearViewObjectChild(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetPreviousLinearViewObjectChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetNextLinearViewObjectChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForAddress(
	    BNLinearViewObject* parent, uint64_t addr);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForIdentifier(
	    BNLinearViewObject* parent, BNLinearViewObjectIdentifier* id);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetLinearViewObjectLines(
	    BNLinearViewObject* obj, BNLinearViewObject* prev, BNLinearViewObject* next, size_t* count);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectStart(BNLinearViewObject* obj);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectEnd(BNLinearViewObject* obj);
	BINARYNINJACOREAPI BNLinearViewObjectIdentifier BNGetLinearViewObjectIdentifier(BNLinearViewObject* obj);
	BINARYNINJACOREAPI void BNFreeLinearViewObjectIdentifier(BNLinearViewObjectIdentifier* id);
	BINARYNINJACOREAPI int BNCompareLinearViewObjectChildren(
	    BNLinearViewObject* obj, BNLinearViewObject* a, BNLinearViewObject* b);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectOrderingIndexTotal(BNLinearViewObject* obj);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewObjectOrderingIndexForChild(
	    BNLinearViewObject* parent, BNLinearViewObject* child);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewObjectChildForOrderingIndex(
	    BNLinearViewObject* parent, uint64_t idx);

	BINARYNINJACOREAPI BNLinearViewCursor* BNCreateLinearViewCursor(BNLinearViewObject* root);
	BINARYNINJACOREAPI BNLinearViewCursor* BNDuplicateLinearViewCursor(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewCursor* BNNewLinearViewCursorReference(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNFreeLinearViewCursor(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNIsLinearViewCursorBeforeBegin(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNIsLinearViewCursorAfterEnd(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewObject* BNGetLinearViewCursorCurrentObject(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearViewObjectIdentifier* BNGetLinearViewCursorPath(
	    BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearViewCursorPath(BNLinearViewObjectIdentifier* objs, size_t count);
	BINARYNINJACOREAPI BNLinearViewObject** BNGetLinearViewCursorPathObjects(BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI void BNFreeLinearViewCursorPathObjects(BNLinearViewObject** objs, size_t count);
	BINARYNINJACOREAPI BNAddressRange BNGetLinearViewCursorOrderingIndex(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI uint64_t BNGetLinearViewCursorOrderingIndexTotal(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToBegin(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToEnd(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToAddress(BNLinearViewCursor* cursor, uint64_t addr);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToPath(
	    BNLinearViewCursor* cursor, BNLinearViewObjectIdentifier* ids, size_t count);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToPathAndAddress(
	    BNLinearViewCursor* cursor, BNLinearViewObjectIdentifier* ids, size_t count, uint64_t addr);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToCursorPath(BNLinearViewCursor* cursor, BNLinearViewCursor* path);
	BINARYNINJACOREAPI bool BNSeekLinearViewCursorToCursorPathAndAddress(
	    BNLinearViewCursor* cursor, BNLinearViewCursor* path, uint64_t addr);
	BINARYNINJACOREAPI void BNSeekLinearViewCursorToOrderingIndex(BNLinearViewCursor* cursor, uint64_t idx);
	BINARYNINJACOREAPI bool BNLinearViewCursorNext(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI bool BNLinearViewCursorPrevious(BNLinearViewCursor* cursor);
	BINARYNINJACOREAPI BNLinearDisassemblyLine* BNGetLinearViewCursorLines(BNLinearViewCursor* cursor, size_t* count);
	BINARYNINJACOREAPI int BNCompareLinearViewCursors(BNLinearViewCursor* a, BNLinearViewCursor* b);

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

	// Updates
	BINARYNINJACOREAPI BNUpdateChannel* BNGetUpdateChannels(size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelList(BNUpdateChannel* list, size_t count);
	BINARYNINJACOREAPI BNUpdateVersion* BNGetUpdateChannelVersions(const char* channel, size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelVersionList(BNUpdateVersion* list, size_t count);

	BINARYNINJACOREAPI bool BNAreUpdatesAvailable(
	    const char* channel, uint64_t* expireTime, uint64_t* serverTime, char** errors);

	BINARYNINJACOREAPI BNUpdateResult BNUpdateToVersion(const char* channel, const char* version, char** errors,
	    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total), void* context);
	BINARYNINJACOREAPI BNUpdateResult BNUpdateToLatestVersion(const char* channel, char** errors,
	    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total), void* context);

	BINARYNINJACOREAPI bool BNAreAutoUpdatesEnabled(void);
	BINARYNINJACOREAPI void BNSetAutoUpdatesEnabled(bool enabled);
	BINARYNINJACOREAPI uint64_t BNGetTimeSinceLastUpdateCheck(void);
	BINARYNINJACOREAPI void BNUpdatesChecked(void);

	BINARYNINJACOREAPI char* BNGetActiveUpdateChannel(void);
	BINARYNINJACOREAPI void BNSetActiveUpdateChannel(const char* channel);

	BINARYNINJACOREAPI bool BNIsUpdateInstallationPending(void);
	BINARYNINJACOREAPI void BNInstallPendingUpdate(char** errors);

	// Plugin commands
	BINARYNINJACOREAPI void BNRegisterPluginCommand(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view), bool (*isValid)(void* ctxt, BNBinaryView* view), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForAddress(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, uint64_t addr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, uint64_t addr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForRange(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForLowLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForLowLevelILInstruction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILInstruction(const char* name,
	    const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForHighLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForHighLevelILInstruction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr), void* context);

	BINARYNINJACOREAPI BNPluginCommand* BNGetAllPluginCommands(size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommands(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForFunction(
	    BNBinaryView* view, BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILFunction(
	    BNBinaryView* view, BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILInstruction(
	    BNBinaryView* view, BNLowLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILFunction(
	    BNBinaryView* view, BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILInstruction(
	    BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForHighLevelILFunction(
	    BNBinaryView* view, BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForHighLevelILInstruction(
	    BNBinaryView* view, BNHighLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreePluginCommandList(BNPluginCommand* commands);

	// Download providers
	BINARYNINJACOREAPI BNDownloadProvider* BNRegisterDownloadProvider(
	    const char* name, BNDownloadProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadProvider** BNGetDownloadProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeDownloadProviderList(BNDownloadProvider** providers);
	BINARYNINJACOREAPI BNDownloadProvider* BNGetDownloadProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetDownloadProviderName(BNDownloadProvider* provider);
	BINARYNINJACOREAPI BNDownloadInstance* BNCreateDownloadProviderInstance(BNDownloadProvider* provider);

	BINARYNINJACOREAPI BNDownloadInstance* BNInitDownloadInstance(
	    BNDownloadProvider* provider, BNDownloadInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadInstance* BNNewDownloadInstanceReference(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstanceResponse(BNDownloadInstanceResponse* response);
	BINARYNINJACOREAPI int BNPerformDownloadRequest(
	    BNDownloadInstance* instance, const char* url, BNDownloadInstanceOutputCallbacks* callbacks);
	BINARYNINJACOREAPI int BNPerformCustomRequest(BNDownloadInstance* instance, const char* method, const char* url,
	    uint64_t headerCount, const char* const* headerKeys, const char* const* headerValues,
	    BNDownloadInstanceResponse** response, BNDownloadInstanceInputOutputCallbacks* callbacks);
	BINARYNINJACOREAPI int64_t BNReadDataForDownloadInstance(BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI uint64_t BNWriteDataForDownloadInstance(
	    BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNNotifyProgressForDownloadInstance(
	    BNDownloadInstance* instance, uint64_t progress, uint64_t total);
	BINARYNINJACOREAPI char* BNGetErrorForDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNSetErrorForDownloadInstance(BNDownloadInstance* instance, const char* error);

	// Websocket providers
	BINARYNINJACOREAPI BNWebsocketProvider* BNRegisterWebsocketProvider(
	    const char* name, BNWebsocketProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNWebsocketProvider** BNGetWebsocketProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeWebsocketProviderList(BNWebsocketProvider** providers);
	BINARYNINJACOREAPI BNWebsocketProvider* BNGetWebsocketProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetWebsocketProviderName(BNWebsocketProvider* provider);
	BINARYNINJACOREAPI BNWebsocketClient* BNCreateWebsocketProviderClient(BNWebsocketProvider* provider);

	BINARYNINJACOREAPI BNWebsocketClient* BNInitWebsocketClient(
	    BNWebsocketProvider* provider, BNWebsocketClientCallbacks* callbacks);
	BINARYNINJACOREAPI BNWebsocketClient* BNNewWebsocketClientReference(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNFreeWebsocketClient(BNWebsocketClient* client);
	BINARYNINJACOREAPI bool BNConnectWebsocketClient(BNWebsocketClient* client, const char* url, uint64_t headerCount,
	    const char* const* headerKeys, const char* const* headerValues, BNWebsocketClientOutputCallbacks* callbacks);
	BINARYNINJACOREAPI bool BNNotifyWebsocketClientConnect(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNNotifyWebsocketClientDisconnect(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNNotifyWebsocketClientError(BNWebsocketClient* client, const char* msg);
	BINARYNINJACOREAPI bool BNNotifyWebsocketClientReadData(BNWebsocketClient* client, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI uint64_t BNWriteWebsocketClientData(
	    BNWebsocketClient* client, const uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNDisconnectWebsocketClient(BNWebsocketClient* client);

	// Scripting providers
	BINARYNINJACOREAPI BNScriptingProvider* BNRegisterScriptingProvider(
	    const char* name, const char* apiName, BNScriptingProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingProvider** BNGetScriptingProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeScriptingProviderList(BNScriptingProvider** providers);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByName(const char* name);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByAPIName(const char* name);

	BINARYNINJACOREAPI char* BNGetScriptingProviderName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI char* BNGetScriptingProviderAPIName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI BNScriptingInstance* BNCreateScriptingProviderInstance(BNScriptingProvider* provider);
	BINARYNINJACOREAPI bool BNLoadScriptingProviderModule(
	    BNScriptingProvider* provider, const char* repository, const char* module, bool force);
	BINARYNINJACOREAPI bool BNInstallScriptingProviderModules(BNScriptingProvider* provider, const char* modules);

	BINARYNINJACOREAPI BNScriptingInstance* BNInitScriptingInstance(
	    BNScriptingProvider* provider, BNScriptingInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingInstance* BNNewScriptingInstanceReference(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNFreeScriptingInstance(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNNotifyOutputForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyErrorForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyInputReadyStateForScriptingInstance(
	    BNScriptingInstance* instance, BNScriptingProviderInputReadyState state);

	BINARYNINJACOREAPI void BNRegisterScriptingInstanceOutputListener(
	    BNScriptingInstance* instance, BNScriptingOutputListener* callbacks);
	BINARYNINJACOREAPI void BNUnregisterScriptingInstanceOutputListener(
	    BNScriptingInstance* instance, BNScriptingOutputListener* callbacks);

	BINARYNINJACOREAPI const char* BNGetScriptingInstanceDelimiters(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNSetScriptingInstanceDelimiters(BNScriptingInstance* instance, const char* delimiters);

	BINARYNINJACOREAPI BNScriptingProviderInputReadyState BNGetScriptingInstanceInputReadyState(
	    BNScriptingInstance* instance);
	BINARYNINJACOREAPI BNScriptingProviderExecuteResult BNExecuteScriptInput(
	    BNScriptingInstance* instance, const char* input);
	BINARYNINJACOREAPI void BNCancelScriptInput(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBinaryView(BNScriptingInstance* instance, BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentFunction(BNScriptingInstance* instance, BNFunction* func);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBasicBlock(BNScriptingInstance* instance, BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentAddress(BNScriptingInstance* instance, uint64_t addr);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentSelection(
	    BNScriptingInstance* instance, uint64_t begin, uint64_t end);
	BINARYNINJACOREAPI char* BNScriptingInstanceCompleteInput(
	    BNScriptingInstance* instance, const char* text, uint64_t state);
	BINARYNINJACOREAPI void BNStopScriptingInstance(BNScriptingInstance* instance);

	// Main thread actions
	BINARYNINJACOREAPI void BNRegisterMainThread(BNMainThreadCallbacks* callbacks);
	BINARYNINJACOREAPI BNMainThreadAction* BNNewMainThreadActionReference(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNFreeMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNExecuteMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI bool BNIsMainThreadActionDone(BNMainThreadAction* action);
	BINARYNINJACOREAPI void BNWaitForMainThreadAction(BNMainThreadAction* action);
	BINARYNINJACOREAPI BNMainThreadAction* BNExecuteOnMainThread(void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI void BNExecuteOnMainThreadAndWait(void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI bool BNIsMainThread(void);

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

	BINARYNINJACOREAPI BNDebugInfoParser* BNRegisterDebugInfoParser(const char* name,
	    bool (*isValid)(void*, BNBinaryView*), void (*parseInfo)(void*, BNDebugInfo*, BNBinaryView*), void* context);
	BINARYNINJACOREAPI void BNUnregisterDebugInfoParser(const char* rawName);
	BINARYNINJACOREAPI BNDebugInfoParser* BNGetDebugInfoParserByName(const char* name);
	BINARYNINJACOREAPI BNDebugInfoParser** BNGetDebugInfoParsers(size_t* count);
	BINARYNINJACOREAPI BNDebugInfoParser** BNGetDebugInfoParsersForView(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI char* BNGetDebugInfoParserName(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI bool BNIsDebugInfoParserValidForView(BNDebugInfoParser* parser, BNBinaryView* view);
	BINARYNINJACOREAPI BNDebugInfo* BNParseDebugInfo(
	    BNDebugInfoParser* parser, BNBinaryView* view, BNDebugInfo* existingDebugInfo);
	BINARYNINJACOREAPI BNDebugInfoParser* BNNewDebugInfoParserReference(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI void BNFreeDebugInfoParserReference(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI void BNFreeDebugInfoParserList(BNDebugInfoParser** parsers, size_t count);

	BINARYNINJACOREAPI BNDebugInfo* BNNewDebugInfoReference(BNDebugInfo* debugInfo);
	BINARYNINJACOREAPI void BNFreeDebugInfoReference(BNDebugInfo* debugInfo);
	BINARYNINJACOREAPI bool BNAddDebugType(
	    BNDebugInfo* const debugInfo, const char* const name, const BNType* const type);
	BINARYNINJACOREAPI BNNameAndType* BNGetDebugTypes(
	    BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI void BNFreeDebugTypes(BNNameAndType* types, size_t count);
	BINARYNINJACOREAPI bool BNAddDebugFunction(BNDebugInfo* const debugInfo, BNDebugFunctionInfo* func);
	BINARYNINJACOREAPI BNDebugFunctionInfo* BNGetDebugFunctions(
	    BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI void BNFreeDebugFunctions(BNDebugFunctionInfo* functions, size_t count);
	BINARYNINJACOREAPI bool BNAddDebugDataVariable(
	    BNDebugInfo* const debugInfo, uint64_t address, const BNType* const type, const char* name);

	// Secrets providers
	BINARYNINJACOREAPI BNSecretsProvider* BNRegisterSecretsProvider(
	    const char* name, BNSecretsProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNSecretsProvider** BNGetSecretsProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeSecretsProviderList(BNSecretsProvider** providers);
	BINARYNINJACOREAPI BNSecretsProvider* BNGetSecretsProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetSecretsProviderName(BNSecretsProvider* provider);

	BINARYNINJACOREAPI bool BNSecretsProviderHasData(BNSecretsProvider* provider, const char* key);
	BINARYNINJACOREAPI char* BNGetSecretsProviderData(BNSecretsProvider* provider, const char* key);
	BINARYNINJACOREAPI bool BNStoreSecretsProviderData(BNSecretsProvider* provider, const char* key, const char* data);
	BINARYNINJACOREAPI bool BNDeleteSecretsProviderData(BNSecretsProvider* provider, const char* key);

#ifdef __cplusplus
}
#endif

#endif
