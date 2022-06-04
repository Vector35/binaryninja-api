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

#pragma once
#ifdef WIN32
	#define NOMINMAX
	#include <windows.h>
#endif
#include <stddef.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <functional>
#include <set>
#include <mutex>
#include <atomic>
#include <memory>
#include <cstdint>
#include <type_traits>
#include <variant>
#include <optional>
#include <memory>
#include "json/json.h"
#include "binaryninjacore.h"
#include "binaryninja_defs.h"

#include "refcount.hpp"
#include "confidence.hpp"
#include "activity.hpp"
#include "workflow.hpp"
#include "log.hpp"
#include "databuffer.hpp"
#include "filemetadata.hpp"
#include "binaryview.hpp"
#include "typeparser.hpp"
#include "function.hpp"
#include "lowlevelil.hpp"
#include "mediumlevelil.hpp"
#include "highlevelil.hpp"
#include "type.hpp"
#include "callingconvention.hpp"
#include "interaction.h"

#ifdef _MSC_VER
	#define NOEXCEPT
#else
	#define NOEXCEPT noexcept
#endif

//#define BN_REF_COUNT_DEBUG  // Mac OS X only, prints stack trace of leaked references


namespace BinaryNinja {

	class Architecture;
	class BackgroundTask;
	class Platform;
	class Settings;
	class Workflow;
	class Type;
	class DataBuffer;
	class MainThreadAction;
	class MainThreadActionHandler;
	class InteractionHandler;
	class QualifiedName;
	class FlowGraph;
	class ReportCollection;
	struct FormInputField;
	class FileMetadata;
	class BinaryView;
	class NameAndType;

	void DisablePlugins();
	bool IsPluginsEnabled();
	bool InitPlugins(bool allowUserPlugins = true);
	void InitCorePlugins();  // Deprecated, use InitPlugins
	void InitUserPlugins();  // Deprecated, use InitPlugins
	void InitRepoPlugins();

	std::string GetBundledPluginDirectory();
	void SetBundledPluginDirectory(const std::string& path);
	std::string GetUserDirectory();

	std::string GetSettingsFileName();
	std::string GetRepositoriesDirectory();
	std::string GetInstallDirectory();
	std::string GetUserPluginDirectory();

	std::string GetPathRelativeToBundledPluginDirectory(const std::string& path);
	std::string GetPathRelativeToUserPluginDirectory(const std::string& path);
	std::string GetPathRelativeToUserDirectory(const std::string& path);

	bool ExecuteWorkerProcess(const std::string& path, const std::vector<std::string>& args, const DataBuffer& input,
	    std::string& output, std::string& errors, bool stdoutIsText = false, bool stderrIsText = true);

	std::string GetVersionString();
	std::string GetLicensedUserEmail();
	std::string GetProduct();
	std::string GetProductType();
	std::string GetSerialNumber();
	int GetLicenseCount();
	bool IsUIEnabled();
	uint32_t GetBuildId();

	bool AreAutoUpdatesEnabled();
	void SetAutoUpdatesEnabled(bool enabled);
	uint64_t GetTimeSinceLastUpdateCheck();
	void UpdatesChecked();

	std::string GetActiveUpdateChannel();
	void SetActiveUpdateChannel(const std::string& channel);

	void SetCurrentPluginLoadOrder(BNPluginLoadOrder order);
	void AddRequiredPluginDependency(const std::string& name);
	void AddOptionalPluginDependency(const std::string& name);

	void RegisterMainThread(MainThreadActionHandler* handler);
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);
	bool IsMainThread();

	void WorkerEnqueue(const std::function<void()>& action);
	void WorkerEnqueue(RefCountObject* owner, const std::function<void()>& action);
	void WorkerPriorityEnqueue(const std::function<void()>& action);
	void WorkerPriorityEnqueue(RefCountObject* owner, const std::function<void()>& action);
	void WorkerInteractiveEnqueue(const std::function<void()>& action);
	void WorkerInteractiveEnqueue(RefCountObject* owner, const std::function<void()>& action);

	size_t GetWorkerThreadCount();
	void SetWorkerThreadCount(size_t count);

	/*!
	    Split a single progress function into equally sized subparts.
	    This function takes the original progress function and returns a new function whose signature
	    is the same but whose output is shortened to correspond to the specified subparts.

	    E.g. If subpart = 0 and subpartCount = 3, this returns a function that calls originalFn and has
	    all of its progress multiplied by 1/3 and 0/3 added.

	    Internally this works by calling originalFn with total = 1000000 and doing math on the current value

	    \param originalFn Original progress function (usually updates a UI)
	    \param subpart Index of subpart whose function to return, from 0 to (subpartCount - 1)
	    \param subpartCount Total number of subparts
	    \return A function that will call originalFn() within a modified progress region
	 */
	std::function<bool(size_t, size_t)> SplitProgress(
	    std::function<bool(size_t, size_t)> originalFn, size_t subpart, size_t subpartCount);


	/*!
	    Split a single progress function into subparts.
	    This function takes the original progress function and returns a new function whose signature
	    is the same but whose output is shortened to correspond to the specified subparts.

	    The length of a subpart is proportional to the sum of all the weights.
	    E.g. If subpart = 1 and subpartWeights = { 0.25, 0.5, 0.25 }, this will return a function that calls
	    originalFn and maps its progress to the range [0.25, 0.75]

	    Internally this works by calling originalFn with total = 1000000 and doing math on the current value

	    \param originalFn Original progress function (usually updates a UI)
	    \param subpart Index of subpart whose function to return, from 0 to (subpartWeights.size() - 1)
	    \param subpartWeights Weights of subparts, described above
	    \return A function that will call originalFn() within a modified progress region
	 */
	std::function<bool(size_t, size_t)> SplitProgress(
	    std::function<bool(size_t, size_t)> originalFn, size_t subpart, std::vector<double> subpartWeights);


	std::map<std::string, uint64_t> GetMemoryUsageInfo();

	class DataBuffer;
	class TemporaryFile : public CoreRefCountObject<BNTemporaryFile, BNNewTemporaryFileReference, BNFreeTemporaryFile>
	{
	  public:
		TemporaryFile();
		TemporaryFile(const DataBuffer& contents);
		TemporaryFile(const std::string& contents);
		TemporaryFile(BNTemporaryFile* file);

		bool IsValid() const { return m_object != nullptr; }
		std::string GetPath() const;
		DataBuffer GetContents();
	};
	struct InstructionTextToken;
	struct UndoEntry;




	class FileMetadata;
	class Function;
	struct DataVariable;
	struct DataVariableAndName;
	class Symbol;
	class Tag;
	class TagType;
	struct TagReference;

	class Function;
	class BasicBlock;

	// TODO: This describes how the xref source references the target
	enum ReferenceType
	{
		UnspecifiedReferenceType = 0x0,
		ReadReferenceType = 0x1,
		WriteReferenceType = 0x2,
		ExecuteReferenceType = 0x4,

		// A type is referenced by a data variable
		DataVariableReferenceType = 0x8,

		// A type is referenced by another type
		DirectTypeReferenceType = 0x10,
		IndirectTypeReferenceType = 0x20,
	};

	class Tag;

	class DisassemblySettings;


	struct QualifiedNameAndType;
	struct PossibleValueSet;
	class Metadata;
	class Structure;

	struct TransformParameter
	{
		std::string name, longName;
		size_t fixedLength;  // Variable length if zero
	};

	class Transform : public StaticCoreRefCountObject<BNTransform>
	{
	  protected:
		BNTransformType m_typeForRegister;
		std::string m_nameForRegister, m_longNameForRegister, m_groupForRegister;

		Transform(BNTransform* xform);

		static BNTransformParameterInfo* GetParametersCallback(void* ctxt, size_t* count);
		static void FreeParametersCallback(BNTransformParameterInfo* params, size_t count);
		static bool DecodeCallback(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		static bool EncodeCallback(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

		static std::vector<TransformParameter> EncryptionKeyParameters(size_t fixedKeyLength = 0);
		static std::vector<TransformParameter> EncryptionKeyAndIVParameters(
		    size_t fixedKeyLength = 0, size_t fixedIVLength = 0);

	  public:
		Transform(BNTransformType type, const std::string& name, const std::string& longName, const std::string& group);

		static void Register(Transform* xform);
		static Ref<Transform> GetByName(const std::string& name);
		static std::vector<Ref<Transform>> GetTransformTypes();

		BNTransformType GetType() const;
		std::string GetName() const;
		std::string GetLongName() const;
		std::string GetGroup() const;

		virtual std::vector<TransformParameter> GetParameters() const;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>());
		virtual bool Encode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>());
	};

	class CoreTransform : public Transform
	{
	  public:
		CoreTransform(BNTransform* xform);
		virtual std::vector<TransformParameter> GetParameters() const override;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>()) override;
		virtual bool Encode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>()) override;
	};

	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class LanguageRepresentationFunction;
	class FunctionRecognizer;
	class CallingConvention;
	class RelocationHandler;

	typedef size_t ExprId;

	class FlowGraph;
	struct SSAVariable;


	struct LowLevelILInstruction;
	struct RegisterOrFlag;
	struct SSARegister;
	struct SSARegisterStack;
	struct SSAFlag;
	struct SSARegisterOrFlag;

	class UpdateException : public std::exception
	{
		const std::string m_desc;

	  public:
		UpdateException(const std::string& desc) : std::exception(), m_desc(desc) {}
		virtual const char* what() const NOEXCEPT { return m_desc.c_str(); }
	};

	struct UpdateChannel
	{
		std::string name;
		std::string description;
		std::string latestVersion;

		static std::vector<UpdateChannel> GetList();

		bool AreUpdatesAvailable(uint64_t* expireTime, uint64_t* serverTime);

		BNUpdateResult UpdateToVersion(const std::string& version);
		BNUpdateResult UpdateToVersion(
		    const std::string& version, const std::function<bool(uint64_t progress, uint64_t total)>& progress);
		BNUpdateResult UpdateToLatestVersion();
		BNUpdateResult UpdateToLatestVersion(const std::function<bool(uint64_t progress, uint64_t total)>& progress);
	};

	/*! UpdateVersion documentation
	 */
	struct UpdateVersion
	{
		std::string version;
		std::string notes;
		time_t time;

		static std::vector<UpdateVersion> GetChannelVersions(const std::string& channel);
	};

	struct PluginCommandContext
	{
		Ref<BinaryView> binaryView;
		uint64_t address, length;
		size_t instrIndex;
		Ref<Function> function;
		Ref<LowLevelILFunction> lowLevelILFunction;
		Ref<MediumLevelILFunction> mediumLevelILFunction;
		Ref<HighLevelILFunction> highLevelILFunction;

		PluginCommandContext();
	};

	class HighLevelILInstruction;
	class PluginCommand
	{
		BNPluginCommand m_command;

		struct RegisteredDefaultCommand
		{
			std::function<void(BinaryView*)> action;
			std::function<bool(BinaryView*)> isValid;
		};

		struct RegisteredAddressCommand
		{
			std::function<void(BinaryView*, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t)> isValid;
		};

		struct RegisteredRangeCommand
		{
			std::function<void(BinaryView*, uint64_t, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t, uint64_t)> isValid;
		};

		struct RegisteredFunctionCommand
		{
			std::function<void(BinaryView*, Function*)> action;
			std::function<bool(BinaryView*, Function*)> isValid;
		};

		struct RegisteredLowLevelILFunctionCommand
		{
			std::function<void(BinaryView*, LowLevelILFunction*)> action;
			std::function<bool(BinaryView*, LowLevelILFunction*)> isValid;
		};

		struct RegisteredLowLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const LowLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const LowLevelILInstruction&)> isValid;
		};

		struct RegisteredMediumLevelILFunctionCommand
		{
			std::function<void(BinaryView*, MediumLevelILFunction*)> action;
			std::function<bool(BinaryView*, MediumLevelILFunction*)> isValid;
		};

		struct RegisteredMediumLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const MediumLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const MediumLevelILInstruction&)> isValid;
		};

		struct RegisteredHighLevelILFunctionCommand
		{
			std::function<void(BinaryView*, HighLevelILFunction*)> action;
			std::function<bool(BinaryView*, HighLevelILFunction*)> isValid;
		};

		struct RegisteredHighLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const HighLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const HighLevelILInstruction&)> isValid;
		};

		static void DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view);
		static void AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static void RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static void FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static void LowLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static void LowLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static void MediumLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static void MediumLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static void HighLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static void HighLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		static bool DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view);
		static bool AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static bool RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static bool FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static bool LowLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static bool LowLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static bool MediumLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static bool MediumLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static bool HighLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static bool HighLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

	  public:
		PluginCommand(const BNPluginCommand& cmd);
		PluginCommand(const PluginCommand& cmd);
		~PluginCommand();

		PluginCommand& operator=(const PluginCommand& cmd);

		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action);
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action, const std::function<bool(BinaryView* view)>& isValid);
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action);
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr)>& isValid);
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action);
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid);
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action);
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action,
		    const std::function<bool(BinaryView* view, Function* func)>& isValid);
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action);
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid);
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action);
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid);
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action);
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid);
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action);
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid);
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action);
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, HighLevelILFunction* func)>& isValid);
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action);
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const HighLevelILInstruction& instr)>& isValid);

		static std::vector<PluginCommand> GetList();
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		std::string GetName() const { return m_command.name; }
		std::string GetDescription() const { return m_command.description; }
		BNPluginCommandType GetType() const { return m_command.type; }
		const BNPluginCommand* GetObject() const { return &m_command; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};

	// DownloadProvider
	class DownloadProvider;

	class DownloadInstance :
	    public CoreRefCountObject<BNDownloadInstance, BNNewDownloadInstanceReference, BNFreeDownloadInstance>
	{
	  public:
		struct Response
		{
			uint16_t statusCode;
			std::unordered_map<std::string, std::string> headers;
		};

	  protected:
		DownloadInstance(DownloadProvider* provider);
		DownloadInstance(BNDownloadInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static int PerformRequestCallback(void* ctxt, const char* url);
		static int PerformCustomRequestCallback(void* ctxt, const char* method, const char* url, uint64_t headerCount,
		    const char* const* headerKeys, const char* const* headerValues, BNDownloadInstanceResponse** response);
		static void PerformFreeResponse(void* ctxt, BNDownloadInstanceResponse* response);
		/*!
		    Cleanup any resources created by the instance
		 */
		virtual void DestroyInstance();
		/*!
		    Virtual method to synchronously perform a GET request to a url, overridden by a subclass
		    \param url Full url to request
		    \return Zero on successful request, negative on failed request
		 */
		virtual int PerformRequest(const std::string& url) = 0;
		/*!
		    Virtual method to synchronously perform a request to a url, overridden by a subclass
		    \param method Request method e.g. GET
		    \param url Full url to request
		    \param headers HTTP headers as keys/values
		    \param response Structure into which the response status code and headers should be stored
		    \return Zero on successful request, negative on failed request
		 */
		virtual int PerformCustomRequest(const std::string& method, const std::string& url,
		    const std::unordered_map<std::string, std::string>& headers, Response& response) = 0;

		int64_t ReadDataCallback(uint8_t* data, uint64_t len);
		uint64_t WriteDataCallback(uint8_t* data, uint64_t len);
		bool NotifyProgressCallback(uint64_t progress, uint64_t total);
		void SetError(const std::string& error);

	  public:
		/*!
		    Send a GET request to a url, synchronously
		    \param url Full url to request
		    \param callbacks Structure with callback functions for output data
		    \return Zero on successful request, negative on failed request
		 */
		int PerformRequest(const std::string& url, BNDownloadInstanceOutputCallbacks* callbacks);
		/*!
		    Send a request to a url, synchronously
		    \param method Request method e.g. GET
		    \param url Full url to request
		    \param headers HTTP headers as keys/values
		    \param response Structure into which the response status code and headers are stored
		    \param callbacks Structure with callback functions for input and output data
		    \return Zero on successful request, negative on failed request
		 */
		int PerformCustomRequest(const std::string& method, const std::string& url,
		    const std::unordered_map<std::string, std::string>& headers, Response& response,
		    BNDownloadInstanceInputOutputCallbacks* callbacks);
		/*!
		    Retrieve the error from the last request sent by this instance
		 */
		std::string GetError() const;
	};

	class CoreDownloadInstance : public DownloadInstance
	{
	  public:
		CoreDownloadInstance(BNDownloadInstance* instance);
		virtual ~CoreDownloadInstance() {};

		virtual int PerformRequest(const std::string& url) override;
		virtual int PerformCustomRequest(const std::string& method, const std::string& url,
		    const std::unordered_map<std::string, std::string>& headers, DownloadInstance::Response& response) override;
	};

	class DownloadProvider : public StaticCoreRefCountObject<BNDownloadProvider>
	{
		std::string m_nameForRegister;

	  protected:
		DownloadProvider(const std::string& name);
		DownloadProvider(BNDownloadProvider* provider);

		static BNDownloadInstance* CreateInstanceCallback(void* ctxt);

	  public:
		virtual Ref<DownloadInstance> CreateNewInstance() = 0;

		static std::vector<Ref<DownloadProvider>> GetList();
		static Ref<DownloadProvider> GetByName(const std::string& name);
		static void Register(DownloadProvider* provider);
	};

	class CoreDownloadProvider : public DownloadProvider
	{
	  public:
		CoreDownloadProvider(BNDownloadProvider* provider);
		virtual Ref<DownloadInstance> CreateNewInstance() override;
	};

	// WebsocketProvider
	class WebsocketProvider;

	class WebsocketClient :
	    public CoreRefCountObject<BNWebsocketClient, BNNewWebsocketClientReference, BNFreeWebsocketClient>
	{
	  protected:
		WebsocketClient(WebsocketProvider* provider);
		WebsocketClient(BNWebsocketClient* instance);

		static void DestroyClientCallback(void* ctxt);
		static bool ConnectCallback(void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys,
		    const char* const* headerValues);
		static bool WriteCallback(const uint8_t* data, uint64_t len, void* ctxt);
		static bool DisconnectCallback(void* ctxt);
		static void ErrorCallback(const char* msg, void* ctxt);
		bool ReadData(uint8_t* data, uint64_t len);

		/*!
		    Cleanup any resources created by the client
		 */
		virtual void DestroyClient();
		/*!
		    Virtual method for performing the connection, overridden by a subclass.
		    \param host Full url with scheme, domain, optionally port, and path
		    \param headers HTTP header keys and values
		    \return True if the connection has started, but not necessarily if it succeeded
		 */
		virtual bool Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers) = 0;

	  public:
		/*!
		    Connect to a given url, asynchronously. The connection will be run in a separate thread managed by the
		   websocket provider.

		    Callbacks will be called **on the thread of the connection**, so be sure to ExecuteOnMainThread any
		   long-running or gui operations in the callbacks.

		    If the connection succeeds, connectedCallback will be called. On normal termination, disconnectedCallback
		   will be called. If the connection succeeds, but later fails, disconnectedCallback will not be called, and
		   errorCallback will be called instead. If the connection fails, neither connectedCallback nor
		   disconnectedCallback will be called, and errorCallback will be called instead.

		    If connectedCallback or readCallback return false, the connection will be aborted.

		    \param host Full url with scheme, domain, optionally port, and path
		    \param headers HTTP header keys and values
		    \param callbacks Structure with callbacks for various websocket events
		    \return True if the connection has started, but not necessarily if it succeeded
		 */
		bool Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers,
		    BNWebsocketClientOutputCallbacks* callbacks);

		/*!
		    Write some data to the websocket
		    \param data Data to write
		    \return True if successful
		 */
		virtual bool Write(const std::vector<uint8_t>& data) = 0;
		/*!
		    Disconnect the websocket
		    \return True if successful
		 */
		virtual bool Disconnect() = 0;
	};

	class CoreWebsocketClient : public WebsocketClient
	{
	  public:
		CoreWebsocketClient(BNWebsocketClient* instance);
		virtual ~CoreWebsocketClient() {};

		virtual bool Connect(
		    const std::string& host, const std::unordered_map<std::string, std::string>& headers) override;
		virtual bool Write(const std::vector<uint8_t>& data) override;
		virtual bool Disconnect() override;
	};

	class WebsocketProvider : public StaticCoreRefCountObject<BNWebsocketProvider>
	{
		std::string m_nameForRegister;

	  protected:
		WebsocketProvider(const std::string& name);
		WebsocketProvider(BNWebsocketProvider* provider);

		static BNWebsocketClient* CreateClientCallback(void* ctxt);

	  public:
		virtual Ref<WebsocketClient> CreateNewClient() = 0;

		static std::vector<Ref<WebsocketProvider>> GetList();
		static Ref<WebsocketProvider> GetByName(const std::string& name);
		static void Register(WebsocketProvider* provider);
	};

	class CoreWebsocketProvider : public WebsocketProvider
	{
	  public:
		CoreWebsocketProvider(BNWebsocketProvider* provider);
		virtual Ref<WebsocketClient> CreateNewClient() override;
	};

	// Scripting Provider
	class ScriptingOutputListener
	{
		BNScriptingOutputListener m_callbacks;

		static void OutputCallback(void* ctxt, const char* text);
		static void ErrorCallback(void* ctxt, const char* text);
		static void InputReadyStateChangedCallback(void* ctxt, BNScriptingProviderInputReadyState state);

	  public:
		ScriptingOutputListener();
		BNScriptingOutputListener& GetCallbacks() { return m_callbacks; }

		virtual void NotifyOutput(const std::string& text);
		virtual void NotifyError(const std::string& text);
		virtual void NotifyInputReadyStateChanged(BNScriptingProviderInputReadyState state);
	};

	class ScriptingProvider;

	class ScriptingInstance :
	    public CoreRefCountObject<BNScriptingInstance, BNNewScriptingInstanceReference, BNFreeScriptingInstance>
	{
	  protected:
		ScriptingInstance(ScriptingProvider* provider);
		ScriptingInstance(BNScriptingInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static BNScriptingProviderExecuteResult ExecuteScriptInputCallback(void* ctxt, const char* input);
		static void CancelScriptInputCallback(void* ctxt);
		static void SetCurrentBinaryViewCallback(void* ctxt, BNBinaryView* view);
		static void SetCurrentFunctionCallback(void* ctxt, BNFunction* func);
		static void SetCurrentBasicBlockCallback(void* ctxt, BNBasicBlock* block);
		static void SetCurrentAddressCallback(void* ctxt, uint64_t addr);
		static void SetCurrentSelectionCallback(void* ctxt, uint64_t begin, uint64_t end);
		static char* CompleteInputCallback(void* ctxt, const char* text, uint64_t state);
		static void StopCallback(void* ctxt);

		virtual void DestroyInstance();

	  public:
		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) = 0;
		virtual void CancelScriptInput();
		virtual void SetCurrentBinaryView(BinaryView* view);
		virtual void SetCurrentFunction(Function* func);
		virtual void SetCurrentBasicBlock(BasicBlock* block);
		virtual void SetCurrentAddress(uint64_t addr);
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end);
		virtual std::string CompleteInput(const std::string& text, uint64_t state);
		virtual void Stop();

		void Output(const std::string& text);
		void Error(const std::string& text);
		void InputReadyStateChanged(BNScriptingProviderInputReadyState state);
		BNScriptingProviderInputReadyState GetInputReadyState();

		void RegisterOutputListener(ScriptingOutputListener* listener);
		void UnregisterOutputListener(ScriptingOutputListener* listener);

		std::string GetDelimiters();
		void SetDelimiters(const std::string& delimiters);
	};

	class CoreScriptingInstance : public ScriptingInstance
	{
	  public:
		CoreScriptingInstance(BNScriptingInstance* instance);
		virtual ~CoreScriptingInstance() {};

		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) override;
		virtual void CancelScriptInput() override;
		virtual void SetCurrentBinaryView(BinaryView* view) override;
		virtual void SetCurrentFunction(Function* func) override;
		virtual void SetCurrentBasicBlock(BasicBlock* block) override;
		virtual void SetCurrentAddress(uint64_t addr) override;
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end) override;
		virtual std::string CompleteInput(const std::string& text, uint64_t state) override;
		virtual void Stop() override;
	};

	class ScriptingProvider : public StaticCoreRefCountObject<BNScriptingProvider>
	{
		std::string m_nameForRegister;
		std::string m_apiNameForRegister;

	  protected:
		ScriptingProvider(const std::string& name, const std::string& apiName);
		ScriptingProvider(BNScriptingProvider* provider);

		static BNScriptingInstance* CreateInstanceCallback(void* ctxt);
		static bool LoadModuleCallback(void* ctxt, const char* repository, const char* module, bool force);
		static bool InstallModulesCallback(void* ctxt, const char* modules);

	  public:
		virtual Ref<ScriptingInstance> CreateNewInstance() = 0;
		virtual bool LoadModule(const std::string& repository, const std::string& module, bool force) = 0;
		virtual bool InstallModules(const std::string& modules) = 0;

		std::string GetName();
		std::string GetAPIName();

		static std::vector<Ref<ScriptingProvider>> GetList();
		static Ref<ScriptingProvider> GetByName(const std::string& name);
		static Ref<ScriptingProvider> GetByAPIName(const std::string& apiName);
		static void Register(ScriptingProvider* provider);
	};

	class CoreScriptingProvider : public ScriptingProvider
	{
	  public:
		CoreScriptingProvider(BNScriptingProvider* provider);
		virtual Ref<ScriptingInstance> CreateNewInstance() override;
		virtual bool LoadModule(const std::string& repository, const std::string& module, bool force) override;
		virtual bool InstallModules(const std::string& modules) override;
	};

	class MainThreadAction :
	    public CoreRefCountObject<BNMainThreadAction, BNNewMainThreadActionReference, BNFreeMainThreadAction>
	{
	  public:
		MainThreadAction(BNMainThreadAction* action);
		void Execute();
		bool IsDone() const;
		void Wait();
	};

	class MainThreadActionHandler
	{
	  public:
		virtual void AddMainThreadAction(MainThreadAction* action) = 0;
	};


	struct LinearViewObjectIdentifier
	{
		std::string name;
		BNLinearViewObjectIdentifierType type;
		uint64_t start, end;

		LinearViewObjectIdentifier();
		LinearViewObjectIdentifier(const std::string& name);
		LinearViewObjectIdentifier(const std::string& name, uint64_t addr);
		LinearViewObjectIdentifier(const std::string& name, uint64_t start, uint64_t end);
		LinearViewObjectIdentifier(const LinearViewObjectIdentifier& other);
	};

	class LinearViewObject :
	    public CoreRefCountObject<BNLinearViewObject, BNNewLinearViewObjectReference, BNFreeLinearViewObject>
	{
	  public:
		LinearViewObject(BNLinearViewObject* obj);

		Ref<LinearViewObject> GetFirstChild();
		Ref<LinearViewObject> GetLastChild();
		Ref<LinearViewObject> GetPreviousChild(LinearViewObject* obj);
		Ref<LinearViewObject> GetNextChild(LinearViewObject* obj);

		Ref<LinearViewObject> GetChildForAddress(uint64_t addr);
		Ref<LinearViewObject> GetChildForIdentifier(const LinearViewObjectIdentifier& id);
		int CompareChildren(LinearViewObject* a, LinearViewObject* b);

		std::vector<LinearDisassemblyLine> GetLines(LinearViewObject* prev, LinearViewObject* next);

		uint64_t GetStart() const;
		uint64_t GetEnd() const;

		LinearViewObjectIdentifier GetIdentifier() const;

		uint64_t GetOrderingIndexTotal() const;
		uint64_t GetOrderingIndexForChild(LinearViewObject* obj) const;
		Ref<LinearViewObject> GetChildForOrderingIndex(uint64_t idx);

		static Ref<LinearViewObject> CreateDisassembly(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLiftedIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLowLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLowLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMediumLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMappedMediumLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMappedMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateHighLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateHighLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLanguageRepresentation(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateDataOnly(BinaryView* view, DisassemblySettings* settings);

		static Ref<LinearViewObject> CreateSingleFunctionDisassembly(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLiftedIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLowLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLowLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMediumLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMediumLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMappedMediumLevelIL(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMappedMediumLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionHighLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionHighLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLanguageRepresentation(
		    Function* func, DisassemblySettings* settings);
	};

	class LinearViewCursor :
	    public CoreRefCountObject<BNLinearViewCursor, BNNewLinearViewCursorReference, BNFreeLinearViewCursor>
	{
	  public:
		LinearViewCursor(LinearViewObject* root);
		LinearViewCursor(BNLinearViewCursor* cursor);

		bool IsBeforeBegin() const;
		bool IsAfterEnd() const;
		bool IsValid() const;

		Ref<LinearViewObject> GetCurrentObject() const;
		std::vector<LinearViewObjectIdentifier> GetPath() const;
		std::vector<Ref<LinearViewObject>> GetPathObjects() const;
		BNAddressRange GetOrderingIndex() const;
		uint64_t GetOrderingIndexTotal() const;

		void SeekToBegin();
		void SeekToEnd();
		void SeekToAddress(uint64_t addr);
		bool SeekToPath(const std::vector<LinearViewObjectIdentifier>& path);
		bool SeekToPath(const std::vector<LinearViewObjectIdentifier>& path, uint64_t addr);
		bool SeekToPath(LinearViewCursor* cursor);
		bool SeekToPath(LinearViewCursor* cursor, uint64_t addr);
		void SeekToOrderingIndex(uint64_t idx);
		bool Next();
		bool Previous();

		std::vector<LinearDisassemblyLine> GetLines();

		Ref<LinearViewCursor> Duplicate();

		static int Compare(LinearViewCursor* a, LinearViewCursor* b);
	};

	struct FindParameters
	{
		BNFindType type;
		BNFindRangeType rangeType;
		BNFunctionGraphType ilType;
		std::string string;
		BNFindFlag flags;
		bool findAll;

		uint64_t findConstant;
		DataBuffer findBuffer;

		std::vector<BNAddressRange> ranges;
		uint64_t totalLength;
	};

	struct DebugFunctionInfo
	{
		std::string shortName;
		std::string fullName;
		std::string rawName;
		uint64_t address;
		Ref<Type> returnType;
		std::vector<std::tuple<std::string, Ref<Type>>> parameters;
		bool variableParameters;
		Ref<CallingConvention> callingConvention;
		Ref<Platform> platform;

		DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
		    Ref<Type> returnType, std::vector<std::tuple<std::string, Ref<Type>>> parameters, bool variableParameters,
		    Ref<CallingConvention> callingConvention, Ref<Platform> platform);
	};

	class DebugInfo : public CoreRefCountObject<BNDebugInfo, BNNewDebugInfoReference, BNFreeDebugInfoReference>
	{
	  public:
		DebugInfo(BNDebugInfo* debugInfo);

		std::vector<NameAndType> GetTypes(const std::string& parserName = "");
		std::vector<DebugFunctionInfo> GetFunctions(const std::string& parserName = "");
		std::vector<DataVariableAndName> GetDataVariables(const std::string& parserName = "");

		bool AddType(const std::string& name, Ref<Type> type);
		bool AddFunction(const DebugFunctionInfo& function);
		bool AddDataVariable(uint64_t address, Ref<Type> type, const std::string& name = "");
	};

	class DebugInfoParser :
	    public CoreRefCountObject<BNDebugInfoParser, BNNewDebugInfoParserReference, BNFreeDebugInfoParserReference>
	{
	  public:
		DebugInfoParser(BNDebugInfoParser* parser);

		static Ref<DebugInfoParser> GetByName(const std::string& name);
		static std::vector<Ref<DebugInfoParser>> GetList();
		static std::vector<Ref<DebugInfoParser>> GetListForView(const Ref<BinaryView> data);

		std::string GetName() const;
		Ref<DebugInfo> Parse(Ref<BinaryView> view, Ref<DebugInfo> existingDebugInfo = nullptr) const;

		bool IsValidForView(const Ref<BinaryView> view) const;
	};

	class CustomDebugInfoParser : public DebugInfoParser
	{
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static void ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view);
		BNDebugInfoParser* Register(const std::string& name);

	  public:
		CustomDebugInfoParser(const std::string& name);
		virtual ~CustomDebugInfoParser() {}

		virtual bool IsValid(Ref<BinaryView>) = 0;
		virtual void ParseInfo(Ref<DebugInfo>, Ref<BinaryView>) = 0;
	};

	/*!
	    Class for storing secrets (e.g. tokens) in a system-specific manner
	 */
	class SecretsProvider : public StaticCoreRefCountObject<BNSecretsProvider>
	{
		std::string m_nameForRegister;

	  protected:
		SecretsProvider(const std::string& name);
		SecretsProvider(BNSecretsProvider* provider);

		static bool HasDataCallback(void* ctxt, const char* key);
		static char* GetDataCallback(void* ctxt, const char* key);
		static bool StoreDataCallback(void* ctxt, const char* key, const char* data);
		static bool DeleteDataCallback(void* ctxt, const char* key);

	  public:
		/*!
		    Check if data for a specific key exists, but do not retrieve it
		    \param key Key for data
		    \return True if data exists
		 */
		virtual bool HasData(const std::string& key) = 0;
		/*!
		    Retrieve data for the given key, if it exists
		    \param key Key for data
		    \return Optional with data, if it exists, or empty optional if it does not exist
		            or otherwise could not be retrieved.
		 */
		virtual std::optional<std::string> GetData(const std::string& key) = 0;
		/*!
		    Store data with the given key
		    \param key Key for data
		    \param data Data to store
		    \return True if the data was stored
		 */
		virtual bool StoreData(const std::string& key, const std::string& data) = 0;
		/*!
		    Delete stored data with the given key
		    \param key Key for data
		    \return True if it was deleted
		 */
		virtual bool DeleteData(const std::string& key) = 0;

		/*!
		    Retrieve the list of providers
		    \return A list of registered providers
		 */
		static std::vector<Ref<SecretsProvider>> GetList();
		/*!
		    Retrieve a provider by name
		    \param name Name of provider
		    \return Provider object, if one with the given name is regestered, or nullptr if not
		 */
		static Ref<SecretsProvider> GetByName(const std::string& name);
		/*!
		    Register a new provider
		    \param provider New provider to register
		 */
		static void Register(SecretsProvider* provider);
	};

	class CoreSecretsProvider : public SecretsProvider
	{
	  public:
		CoreSecretsProvider(BNSecretsProvider* provider);

		virtual bool HasData(const std::string& key) override;
		virtual std::optional<std::string> GetData(const std::string& key) override;
		virtual bool StoreData(const std::string& key, const std::string& data) override;
		virtual bool DeleteData(const std::string& key) override;
	};
}  // namespace BinaryNinja
