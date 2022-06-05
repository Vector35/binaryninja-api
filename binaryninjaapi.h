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
}  // namespace BinaryNinja
