// Copyright (c) 2015-2024 Vector 35 Inc
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
#ifndef NOMINMAX
	#define NOMINMAX
#endif
	#include <windows.h>
#endif
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <set>
#include <cstdint>
#include <typeinfo>
#include <type_traits>
#include <optional>
#include "binaryninjacore.h"
#include "exceptions.h"
#include "vendor/nlohmann/json.hpp"
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/core.h>
#include "confidence.h"
#include "refcount.h"
#include "logging.h"
#include "collaboration.h"
#include "metadata.h"
#include "project.h"
#include "database.h"
#include "namelist.h"
#include "binaryview.h"
#include "tag.h"
#include "demangle.h"
#include "settings.h"
#include "filemetadata.h"
#include "typearchive.h"
#include "architecture.h"
#include "commonil.h"
#include "lowlevelil.h"
#include "mediumlevelil.h"
#include "function.h"
#include "type.h"
#include "interaction.h"
#include "platform.h"
#include "plugin.h"
#include "workflow.h"
#include "typeparser.h"
#include "overload.h"
#include "flowgraph.h"
#include "highlevelil.h"
#include "typeprinter.h"
#include "basicblock.h"
#include "databuffer.h"
#include "callingconvention.h"
#include "scriptingprovider.h"
#include "pluginmanager.h"
#include "debuginfo.h"
#include "downloadprovider.h"

#ifdef _MSC_VER
	#define NOEXCEPT
#else
	#define NOEXCEPT noexcept
#endif

//#define BN_REF_COUNT_DEBUG  // Mac OS X only, prints stack trace of leaked references

#ifdef DOXYGEN_INCLUDE_MAINPAGE
#include ".doxygen.h"
#endif

namespace BinaryNinja {
#ifdef __GNUC__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	static inline uint16_t ToLE16(uint16_t val) { return val; }
	static inline uint32_t ToLE32(uint32_t val) { return val; }
	static inline uint64_t ToLE64(uint64_t val) { return val; }
	static inline uint16_t ToBE16(uint16_t val) { return __builtin_bswap16(val); }
	static inline uint32_t ToBE32(uint32_t val) { return __builtin_bswap32(val); }
	static inline uint64_t ToBE64(uint64_t val) { return __builtin_bswap64(val); }
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	static inline uint16_t ToBE16(uint16_t val) { return val; }
	static inline uint32_t ToBE32(uint32_t val) { return val; }
	static inline uint64_t ToBE64(uint64_t val) { return val; }
	static inline uint16_t ToLE16(uint16_t val) { return __builtin_bswap16(val); }
	static inline uint32_t ToLE32(uint32_t val) { return __builtin_bswap32(val); }
	static inline uint64_t ToLE64(uint64_t val) { return __builtin_bswap64(val); }
#endif
#elif defined(_MSC_VER)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	static inline uint16_t ToLE16(uint16_t val) { return val; }
	static inline uint32_t ToLE32(uint32_t val) { return val; }
	static inline uint64_t ToLE64(uint64_t val) { return val; }
	static inline uint16_t ToBE16(uint16_t val) { return _byteswap_ushort(val); }
	static inline uint32_t ToBE32(uint32_t val) { return _byteswap_ulong(val); }
	static inline uint64_t ToBE64(uint64_t val) { return _byteswap_uint64(val); }
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	static inline uint16_t ToBE16(uint16_t val) { return val; }
	static inline uint32_t ToBE32(uint32_t val) { return val; }
	static inline uint64_t ToBE64(uint64_t val) { return val; }
	static inline uint16_t ToLE16(uint16_t val) { return _byteswap_ushort(val); }
	static inline uint32_t ToLE32(uint32_t val) { return _byteswap_ulong(val); }
	static inline uint64_t ToLE64(uint64_t val) { return _byteswap_uint64(val); }
#endif
#endif

	/*!
		@addtogroup coreapi
	 	@{
	*/
	std::string EscapeString(const std::string& s);
	std::string UnescapeString(const std::string& s);

	bool PreprocessSource(const std::string& source, const std::string& fileName, std::string& output,
	    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>());

	void DisablePlugins();
	bool IsPluginsEnabled();
	bool InitPlugins(bool allowUserPlugins = true);
	/*!
		\deprecated Use `InitPlugins()`
	*/
	void InitCorePlugins();  // Deprecated, use InitPlugins
	/*!
		\deprecated Use `InitPlugins()`
	*/
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

	template<typename T>
	std::string CoreEnumName()
	{
		// Extremely implementation-defined. Best-effort is made for our relevant platforms
#ifdef WIN32
		// "enum TestEnum"
		return std::string(typeid(T).name()).substr(5);
#else
		// "19BNWhateverItsCalled"
		auto name = std::string(typeid(T).name());
		while (std::isdigit(name[0]))
		{
			name.erase(0, 1);
		}
		return name;
#endif
	}

	template<typename T>
	std::optional<std::string> CoreEnumToString(T value)
	{
		auto name = CoreEnumName<T>();
		char* result;
		if (!BNCoreEnumToString(name.c_str(), (size_t)value, &result))
			return std::nullopt;
		auto cppResult = std::string(result);
		BNFreeString(result);
		return cppResult;
	}

	template<typename T>
	std::optional<T> CoreEnumFromString(const std::string& value)
	{
		auto name = CoreEnumName<T>();
		size_t result;
		if (!BNCoreEnumFromString(name.c_str(), value.c_str(), &result))
			return std::nullopt;
		return result;
	}

	std::optional<size_t> FuzzyMatchSingle(const std::string& target, const std::string& query);

	/*!
		@}
	*/

	class BinaryView;

	/*! OpenView opens a file on disk and returns a BinaryView, attempting to use the most
	    relevant BinaryViewType and generating default load options (which are overridable).

	    @threadmainonly

	    If there is any error loading the file, nullptr will be returned and a log error will
	    be printed.

	    \warn You will need to call bv->GetFile()->Close() when you are finished using the
	    view returned by this function to free the resources it opened.

	    If no BinaryViewType is available to load the file, the `Mapped` view type will
	    attempt to load it, and will try to auto-detect the architecture. If no architecture
	    is detected or specified in the load options, the `Mapped` type will fail and this
	    function will also return nullptr.

	    \note Although general container file support is not complete, support for Universal
	    archives exists. It's possible to control the architecture preference with the
	    `files.universal.architecturePreference` setting. This setting is scoped to
	    SettingsUserScope and can be modified as follows:

	 	\code{.cpp}
		Metadata options = {{"files.universal.architecturePreference", Metadata({"arm64"})}};
		Ref<BinaryView> bv = Load("/bin/ls", true, {}, options);
	 	\endcode

	    \param filename Path to filename or BNDB to open.
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param options A Json string whose keys are setting identifiers and whose values are the desired settings.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel Load.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	*/
	Ref<BinaryView> Load(const std::string& filename, bool updateAnalysis = true, const std::string& options = "{}", std::function<bool(size_t, size_t)> progress = {});
	/*! Open a BinaryView from a raw data buffer, initializing data views and loading settings.

	    @threadmainonly

	    \see BinaryNinja::Load(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
	    for discussion of this function.

	    \param rawData Buffer with raw binary data to load (cannot load from bndb)
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param options A Json string whose keys are setting identifiers and whose values are the desired settings.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel Load.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	*/
	Ref<BinaryView> Load(const DataBuffer& rawData, bool updateAnalysis = true, const std::string& options = "{}", std::function<bool(size_t, size_t)> progress = {});


	/*! Open a BinaryView from a raw BinaryView, initializing data views and loading settings.

	    @threadmainonly

	    \see BinaryNinja::Load(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
	    for discussion of this function.

	    \param rawData BinaryView with raw binary data to load
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param options A Json string whose keys are setting identifiers and whose values are the desired settings.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel Load.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	*/
	Ref<BinaryView> Load(Ref<BinaryView> rawData, bool updateAnalysis = true, const std::string& options = "{}", std::function<bool(size_t, size_t)> progress = {});

	/*!
		Deprecated. Use non-metadata version.
	*/
	Ref<BinaryView> Load(const std::string& filename, bool updateAnalysis, std::function<bool(size_t, size_t)> progress, Ref<Metadata> options = new Metadata(MetadataType::KeyValueDataType));

	/*!
		Deprecated. Use non-metadata version.
	*/
	Ref<BinaryView> Load(const DataBuffer& rawData, bool updateAnalysis, std::function<bool(size_t, size_t)> progress, Ref<Metadata> options = new Metadata(MetadataType::KeyValueDataType));

	/*!
		Deprecated. Use non-metadata version.
	*/
	Ref<BinaryView> Load(Ref<BinaryView> rawData, bool updateAnalysis, std::function<bool(size_t, size_t)> progress, Ref<Metadata> options = new Metadata(MetadataType::KeyValueDataType), bool isDatabase = false);

	/*!
		\ingroup mainthread
	*/
	void RegisterMainThread(MainThreadActionHandler* handler);

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	bool IsMainThread();

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerEnqueue(const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerEnqueue(RefCountObject* owner, const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerPriorityEnqueue(const std::function<void()>& action, const std::string& name = "");

	/*!
		\ingroup mainthread
	*/
	void WorkerPriorityEnqueue(RefCountObject* owner, const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerInteractiveEnqueue(const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerInteractiveEnqueue(RefCountObject* owner, const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	size_t GetWorkerThreadCount();

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void SetWorkerThreadCount(size_t count);

	/*!
	    @threadsafe
	*/
	std::string MarkdownToHTML(const std::string& contents);

	/*! Run a given task in a background thread, and show an updating progress bar which the user can cancel

		@threadsafe

		\param title Dialog title
		\param canCancel If the task can be cancelled
		\param task Function to perform the task, taking as a parameter a function which should be called to report progress
		            updates and check for cancellation. If the progress function returns false, the user has requested
		            to cancel, and the task should handle this appropriately.
		\return True if not cancelled
	*/
	bool RunProgressDialog(const std::string& title, bool canCancel, std::function<void(std::function<bool(size_t, size_t)> progress)> task);

	/*!
	    Split a single progress function into equally sized subparts.
	    This function takes the original progress function and returns a new function whose signature
	    is the same but whose output is shortened to correspond to the specified subparts.

		@threadsafe

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

		@threadsafe

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

	struct ProgressContext
	{
		std::function<bool(size_t, size_t)> callback;
	};

	bool ProgressCallback(void* ctxt, size_t current, size_t total);

	std::string GetUniqueIdentifierString();

	std::map<std::string, uint64_t> GetMemoryUsageInfo();

	void SetThreadName(const std::string& name);

	/*! TemporaryFile is used for creating temporary files, stored (temporarily) in the system's default temporary file
	 		directory.

	 	\ingroup tempfile
	*/
	class TemporaryFile : public CoreRefCountObject<BNTemporaryFile, BNNewTemporaryFileReference, BNFreeTemporaryFile>
	{
	  public:
		TemporaryFile();

		/*! Create a new temporary file with BinaryNinja::DataBuffer contents.

	    	\param contents DataBuffer with contents to write to the file.
		*/
		TemporaryFile(const DataBuffer& contents);

		/*! Create a new temporary file with string contents.

	        \param contents std::string with contents to write to the file.
		*/
		TemporaryFile(const std::string& contents);
		TemporaryFile(BNTemporaryFile* file);

		bool IsValid() const { return m_object != nullptr; }

		/*! Path to the TemporaryFile on the filesystem.
		*/
		std::string GetPath() const;

		/*! DataBuffer with contents of the file.
		*/
		DataBuffer GetContents();
	};

	/*!

		\ingroup coreapi
	*/
	class User : public CoreRefCountObject<BNUser, BNNewUserReference, BNFreeUser>
	{
	  private:
		std::string m_id;
		std::string m_name;
		std::string m_email;

	  public:
		User(BNUser* user);
		std::string GetName();
		std::string GetEmail();
		std::string GetId();
	};

	/*! `InstructionTextToken` is used to tell the core about the various components in the disassembly views.

		The below table is provided for documentation purposes but the complete list of TokenTypes is available at
		`InstructionTextTokenType`. Note that types marked as `Not emitted by architectures` are not intended to be used
		by Architectures during lifting. Rather, they are added by the core during analysis or display. UI plugins,
		however, may make use of them as appropriate.

		Uses of tokens include plugins that parse the output of an architecture (though parsing IL is recommended),
	 	or additionally, applying color schemes appropriately.

			========================== ============================================
			InstructionTextTokenType   Description
			========================== ============================================
			AddressDisplayToken        **Not emitted by architectures**
			AnnotationToken            **Not emitted by architectures**
			ArgumentNameToken          **Not emitted by architectures**
			BeginMemoryOperandToken    The start of memory operand
			CharacterConstantToken     A printable character
			CodeRelativeAddressToken   **Not emitted by architectures**
			CodeSymbolToken            **Not emitted by architectures**
			DataSymbolToken            **Not emitted by architectures**
			EndMemoryOperandToken      The end of a memory operand
			ExternalSymbolToken        **Not emitted by architectures**
			FieldNameToken             **Not emitted by architectures**
			FloatingPointToken         Floating point number
			HexDumpByteValueToken      **Not emitted by architectures**
			HexDumpInvalidByteToken    **Not emitted by architectures**
			HexDumpSkippedByteToken    **Not emitted by architectures**
			HexDumpTextToken           **Not emitted by architectures**
			ImportToken                **Not emitted by architectures**
			IndirectImportToken        **Not emitted by architectures**
			InstructionToken           The instruction mnemonic
			IntegerToken               Integers
			KeywordToken               **Not emitted by architectures**
			LocalVariableToken         **Not emitted by architectures**
			StackVariableToken         **Not emitted by architectures**
			NameSpaceSeparatorToken    **Not emitted by architectures**
			NameSpaceToken             **Not emitted by architectures**
			OpcodeToken                **Not emitted by architectures**
			OperandSeparatorToken      The comma or delimiter that separates tokens
			PossibleAddressToken       Integers that are likely addresses
			RegisterToken              Registers
			StringToken                **Not emitted by architectures**
			StructOffsetToken          **Not emitted by architectures**
			TagToken                   **Not emitted by architectures**
			TextToken                  Used for anything not of another type.
			CommentToken               Comments
			TypeNameToken              **Not emitted by architectures**
			AddressSeparatorToken      **Not emitted by architectures**
			========================== ============================================
	*/
	struct InstructionTextToken
	{
		enum
		{
			WidthIsByteCount = 0
		};

		BNInstructionTextTokenType type;
		std::string text;
		uint64_t value;
		uint64_t width;
		size_t size, operand;
		BNInstructionTextTokenContext context;
		uint8_t confidence;
		uint64_t address;
		std::vector<std::string> typeNames;
		size_t exprIndex;

		InstructionTextToken();
		InstructionTextToken(uint8_t confidence, BNInstructionTextTokenType t, const std::string& txt);
		InstructionTextToken(BNInstructionTextTokenType type, const std::string& text, uint64_t value = 0,
		    size_t size = 0, size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE,
		    const std::vector<std::string>& typeName = {}, uint64_t width = WidthIsByteCount);
		InstructionTextToken(BNInstructionTextTokenType type, BNInstructionTextTokenContext context,
		    const std::string& text, uint64_t address, uint64_t value = 0, size_t size = 0,
		    size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE,
		    const std::vector<std::string>& typeName = {}, uint64_t width = WidthIsByteCount);
		InstructionTextToken(const BNInstructionTextToken& token);

		InstructionTextToken WithConfidence(uint8_t conf);
		static BNInstructionTextToken* CreateInstructionTextTokenList(const std::vector<InstructionTextToken>& tokens);
		static void FreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertAndFreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertInstructionTextTokenList(
		    const BNInstructionTextToken* tokens, size_t count);
	};

	class UndoEntry;


	/*!

		\ingroup undo
	*/
	class UndoAction : public CoreRefCountObject<BNUndoAction, BNNewUndoActionReference, BNFreeUndoAction>
	{
	  public:
		UndoAction(BNUndoAction* action);

		std::string GetSummaryText();
		std::vector<InstructionTextToken> GetSummary();
	};

	/*!

		\ingroup undo
	*/
	class UndoEntry : public CoreRefCountObject<BNUndoEntry, BNNewUndoEntryReference, BNFreeUndoEntry>
	{
	  public:
		UndoEntry(BNUndoEntry* entry);

		std::string GetId();
		std::vector<Ref<UndoAction>> GetActions();
		uint64_t GetTimestamp();
	};

	struct DataVariable;
	class Tag;
	class TagType;
	struct TagReference;
	class Section;
	class Segment;
	class Component;

	/*!
		\ingroup fileaccessor
	*/
	class FileAccessor
	{
	  protected:
		BNFileAccessor m_callbacks;

	  private:
		static uint64_t GetLengthCallback(void* ctxt);
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);

	  public:
		FileAccessor();
		FileAccessor(BNFileAccessor* accessor);
		virtual ~FileAccessor() {}

		BNFileAccessor* GetCallbacks() { return &m_callbacks; }

		virtual bool IsValid() const = 0;
		virtual uint64_t GetLength() const = 0;
		virtual size_t Read(void* dest, uint64_t offset, size_t len) = 0;
		virtual size_t Write(uint64_t offset, const void* src, size_t len) = 0;
	};

	/*!

		\ingroup fileaccessor
	*/
	class CoreFileAccessor : public FileAccessor
	{
	  public:
		CoreFileAccessor(BNFileAccessor* accessor);

		virtual bool IsValid() const override { return true; }
		virtual uint64_t GetLength() const override;
		virtual size_t Read(void* dest, uint64_t offset, size_t len) override;
		virtual size_t Write(uint64_t offset, const void* src, size_t len) override;
	};

	/*!
		\ingroup types
	*/
	class Symbol : public CoreRefCountObject<BNSymbol, BNNewSymbolReference, BNFreeSymbol>
	{
	  public:
		Symbol(BNSymbolType type, const std::string& shortName, const std::string& fullName, const std::string& rawName,
		    uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbol* sym);

		/*!
			Symbols are defined as one of the following types:

				=========================== =================================================================
				BNSymbolType                Description
				=========================== =================================================================
				FunctionSymbol              Symbol for function that exists in the current binary
				ImportAddressSymbol         Symbol defined in the Import Address Table
				ImportedFunctionSymbol      Symbol for a function that is not defined in the current binary
				DataSymbol                  Symbol for data in the current binary
				ImportedDataSymbol          Symbol for data that is not defined in the current binary
				ExternalSymbol              Symbols for data and code that reside outside the BinaryView
				LibraryFunctionSymbol       Symbols for functions identified as belonging to a shared library
				SymbolicFunctionSymbol      Symbols for functions without a concrete implementation or which have been abstractly represented
				LocalLabelSymbol            Symbol for a local label in the current binary
				=========================== =================================================================

		    \return Symbol type
		*/
		BNSymbolType GetType() const;

		/*!
		    \return Symbol binding
		*/
		BNSymbolBinding GetBinding() const;

		/*!
		    \return Symbol short name
		*/
		std::string GetShortName() const;

		/*!
		    \return Symbol full name
		*/
		std::string GetFullName() const;

		/*!
		    \return Symbol raw name
		*/
		std::string GetRawName() const;

		/*!
			\return Symbol Address
		*/
		uint64_t GetAddress() const;

		/*!
		    \return Symbol ordinal
		*/
		uint64_t GetOrdinal() const;

		/*!
		    \return Whether the symbol was auto-defined
		*/
		bool IsAutoDefined() const;

		/*!
		    \return Symbol NameSpace
		*/
		NameSpace GetNameSpace() const;

		static Ref<Symbol> ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr);
	};

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

	// ReferenceSource describes code reference source; TypeReferenceSource describes type reference source.
	// When we query references, code references return vector<ReferenceSource>, data references return
	// vector<uint64_t>, type references return vector<TypeReferenceSource>.

	struct ReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
	};

	struct TypeFieldReference
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
		size_t size;
		Confidence<Ref<Type>> incomingType;
	};

	struct ILReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
		BNFunctionGraphType type;
		size_t exprId;
	};

	struct TypeReferenceSource
	{
		QualifiedName name;
		uint64_t offset;
		BNTypeReferenceType type;
	};


	class Tag;
	struct DisassemblyTextLineTypeInfo
	{
		bool hasTypeInfo;
		BinaryNinja::Ref<BinaryNinja::Type> parentType;
		size_t fieldIndex;
		uint64_t offset;

		DisassemblyTextLineTypeInfo() : hasTypeInfo(false), parentType(nullptr), fieldIndex(-1), offset(0) {}
	};

	struct DisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		std::vector<InstructionTextToken> tokens;
		BNHighlightColor highlight;
		std::vector<Ref<Tag>> tags;
		DisassemblyTextLineTypeInfo typeInfo;

		DisassemblyTextLine();
	};

	/*!
		\ingroup lineardisassembly
	*/
	struct LinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		Ref<Function> function;
		Ref<BasicBlock> block;
		DisassemblyTextLine contents;

		static LinearDisassemblyLine FromAPIObject(BNLinearDisassemblyLine* line);
	};

	class NamedTypeReference;

	struct TypeDefinitionLine
	{
		BNTypeDefinitionLineType lineType;
		std::vector<InstructionTextToken> tokens;
		Ref<Type> type, parentType, rootType;
		std::string rootTypeName;
		Ref<NamedTypeReference> baseType;
		uint64_t baseOffset;
		uint64_t offset;
		size_t fieldIndex;

		static TypeDefinitionLine FromAPIObject(BNTypeDefinitionLine* line);
		static BNTypeDefinitionLine* CreateTypeDefinitionLineList(
		    const std::vector<TypeDefinitionLine>& lines);
		static void FreeTypeDefinitionLineList(
		    BNTypeDefinitionLine* lines, size_t count);
	};

	class DisassemblySettings;

	struct QualifiedNameAndType;
	struct PossibleValueSet;
	class Structure;
	struct ParsedType;
	struct TypeParserResult;
	class Component;
	class DebugInfo;
	class TypeLibrary;
	class MemoryMap;

	class QueryMetadataException : public ExceptionWithStackTrace
	{
	  public:
		QueryMetadataException(const std::string& error) : ExceptionWithStackTrace(error) {}
	};

	class MemoryMap
	{
		BNBinaryView* m_object;

	public:
		MemoryMap(BNBinaryView* view): m_object(view) {}
		~MemoryMap() = default;

		bool AddBinaryMemoryRegion(const std::string& name, uint64_t start, Ref<BinaryView> source, uint32_t flags = 0)
		{
			return BNAddBinaryMemoryRegion(m_object, name.c_str(), start, source->GetObject(), flags);
		}

		bool AddDataMemoryRegion(const std::string& name, uint64_t start, const DataBuffer& source, uint32_t flags = 0)
		{
			return BNAddDataMemoryRegion(m_object, name.c_str(), start, source.GetBufferObject(), flags);
		}

		bool AddRemoteMemoryRegion(const std::string& name, uint64_t start, FileAccessor* source, uint32_t flags = 0)
		{
			return BNAddRemoteMemoryRegion(m_object, name.c_str(), start, source->GetCallbacks(), flags);
		}

		bool RemoveMemoryRegion(const std::string& name)
		{
			return BNRemoveMemoryRegion(m_object, name.c_str());
		}

		std::string GetActiveMemoryRegionAt(uint64_t addr)
		{
			char* name = BNGetActiveMemoryRegionAt(m_object, addr);
			std::string result = name;
			BNFreeString(name);
			return result;
		}

		uint32_t GetMemoryRegionFlags(const std::string& name)
		{
			return BNGetMemoryRegionFlags(m_object, name.c_str());
		}

		bool SetMemoryRegionFlags(const std::string& name, uint32_t flags)
		{
			return BNSetMemoryRegionFlags(m_object, name.c_str(), flags);
		}

		bool IsMemoryRegionEnabled(const std::string& name)
		{
			return BNIsMemoryRegionEnabled(m_object, name.c_str());
		}

		bool SetMemoryRegionEnabled(const std::string& name, bool enabled)
		{
			return BNSetMemoryRegionEnabled(m_object, name.c_str(), enabled);
		}

		bool IsMemoryRegionRebaseable(const std::string& name)
		{
			return BNIsMemoryRegionRebaseable(m_object, name.c_str());
		}

		bool SetMemoryRegionRebaseable(const std::string& name, bool rebaseable)
		{
			return BNSetMemoryRegionRebaseable(m_object, name.c_str(), rebaseable);
		}

		uint8_t GetMemoryRegionFill(const std::string& name)
		{
			return BNGetMemoryRegionFill(m_object, name.c_str());
		}

		bool SetMemoryRegionFill(const std::string& name, uint8_t fill)
		{
			return BNSetMemoryRegionFill(m_object, name.c_str(), fill);
		}

		void Reset()
		{
			BNResetMemoryMap(m_object);
		}
	};

	/*!
		\ingroup transform
	*/
	struct TransformParameter
	{
		std::string name, longName;
		size_t fixedLength;  // Variable length if zero
	};

	/*! Allows users to implement custom transformations.

	    New transformations may be added at runtime, so an instance of a transform is created like

		\code{.cpp}

	 	DataBuffer inputData = binaryView->ReadBuffer(0, 32); // Read the first 32 bytes of the file
	 	DataBuffer outputDataHash;

		Transform::GetByName("SHA512")->Encode(inputData, outputDataHash); // Writes the SHA512 hash to outputDataHash

		\endcode

	 	Getting a list of registered transforms:

	 	<b> From the interactive python console: </b>
	 	\code{.py}
	 	list(Transform)
	 	\endcode

	 	<b> At Runtime: </b>
	 	\code{.cpp}
	    std::vector<Ref<Transform>> registeredTypes = Transform::GetTransformTypes();
	 	\endcode

		\ingroup transform
	*/
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

	/*!
		\ingroup transform
	*/
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

	struct InstructionInfo : public BNInstructionInfo
	{
		InstructionInfo();
		void AddBranch(BNBranchType type, uint64_t target = 0, Architecture* arch = nullptr, uint8_t delaySlots = 0);
	};

	struct NameAndType
	{
		std::string name;
		Confidence<Ref<Type>> type;

		NameAndType() {}
		NameAndType(const Confidence<Ref<Type>>& t) : type(t) {}
		NameAndType(const std::string& n, const Confidence<Ref<Type>>& t) : name(n), type(t) {}
	};

	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class LanguageRepresentationFunction;
	class FunctionRecognizer;
	class CallingConvention;
	class RelocationHandler;

	typedef size_t ExprId;

	class Structure;
	class NamedTypeReference;
	class Enumeration;

	struct VariableReferenceSource
	{
		Variable var;
		ILReferenceSource source;
	};

	struct FunctionParameter
	{
		std::string name;
		Confidence<Ref<Type>> type;
		bool defaultLocation;
		Variable location;

		FunctionParameter() = default;
		FunctionParameter(const std::string& name, Confidence<Ref<Type>> type): name(name), type(type), defaultLocation(true)
		{}

		FunctionParameter(const std::string& name, const Confidence<Ref<Type>>& type, bool defaultLocation,
		    const Variable& location):
		    name(name), type(type), defaultLocation(defaultLocation), location(location)
		{}
	};

	struct QualifiedNameAndType
	{
		QualifiedName name;
		Ref<Type> type;

		QualifiedNameAndType() = default;
		QualifiedNameAndType(const std::string& name, const Ref<Type>& type): name(name), type(type)
		{}
		QualifiedNameAndType(const QualifiedName& name, const Ref<Type>& type): name(name), type(type)
		{}

		bool operator<(const QualifiedNameAndType& other) const
		{
			return name < other.name;
		}
		bool operator==(const QualifiedNameAndType& other) const
		{
			return name == other.name && type == other.type;
		}
	};

	struct TypeAndId
	{
		std::string id;
		Ref<Type> type;

		TypeAndId() = default;
		TypeAndId(const std::string& id, const Ref<Type>& type): id(id), type(type)
		{}
	};



	class DisassemblySettings :
	    public CoreRefCountObject<BNDisassemblySettings, BNNewDisassemblySettingsReference, BNFreeDisassemblySettings>
	{
	  public:
		DisassemblySettings();
		DisassemblySettings(BNDisassemblySettings* settings);
		DisassemblySettings* Duplicate();

		bool IsOptionSet(BNDisassemblyOption option) const;
		void SetOption(BNDisassemblyOption option, bool state = true);

		size_t GetWidth() const;
		void SetWidth(size_t width);
		size_t GetMaximumSymbolWidth() const;
		void SetMaximumSymbolWidth(size_t width);
		size_t GetGutterWidth() const;
		void SetGutterWidth(size_t width);
		BNDisassemblyAddressMode GetAddressMode() const;
		void SetAddressMode(BNDisassemblyAddressMode mode);
		uint64_t GetAddressBaseOffset() const;
		void SetAddressBaseOffset(uint64_t addressBaseOffset);
		BNDisassemblyCallParameterHints GetCallParameterHints() const;
		void SetCallParameterHints(BNDisassemblyCallParameterHints hints);
	};


	struct LowLevelILInstruction;
	struct RegisterOrFlag;
	struct SSARegister;
	struct SSARegisterStack;
	struct SSAFlag;
	struct SSARegisterOrFlag;

	/*!
		\ingroup functionrecognizer
	*/
	class FunctionRecognizer
	{
		static bool RecognizeLowLevelILCallback(
		    void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		static bool RecognizeMediumLevelILCallback(
		    void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);

	  public:
		FunctionRecognizer();

		static void RegisterGlobalRecognizer(FunctionRecognizer* recog);
		static void RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog);

		virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il);
		virtual bool RecognizeMediumLevelIL(BinaryView* data, Function* func, MediumLevelILFunction* il);
	};

	class RelocationHandler :
	    public CoreRefCountObject<BNRelocationHandler, BNNewRelocationHandlerReference, BNFreeRelocationHandler>
	{
		static bool GetRelocationInfoCallback(
		    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* result, size_t resultCount);
		static bool ApplyRelocationCallback(
		    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
		static size_t GetOperandForExternalRelocationCallback(void* ctxt, const uint8_t* data, uint64_t addr,
		    size_t length, BNLowLevelILFunction* il, BNRelocation* relocation);

	  protected:
		RelocationHandler();
		RelocationHandler(BNRelocationHandler* handler);
		static void FreeCallback(void* ctxt);

	  public:
		virtual bool GetRelocationInfo(
		    Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result);
		virtual bool ApplyRelocation(
		    Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len);
		virtual size_t GetOperandForExternalRelocation(
		    const uint8_t* data, uint64_t addr, size_t length, Ref<LowLevelILFunction> il, Ref<Relocation> relocation);
	};

	class CoreRelocationHandler : public RelocationHandler
	{
	  public:
		CoreRelocationHandler(BNRelocationHandler* handler);
		virtual bool GetRelocationInfo(
		    Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result) override;
		virtual bool ApplyRelocation(
		    Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override;
		virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		    Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override;
	};

	class UpdateException : public ExceptionWithStackTrace
	{
	  public:
		UpdateException(const std::string& desc) : ExceptionWithStackTrace(desc) {}
	};

	/*!
		\ingroup update
	*/
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
		\ingroup update
	*/
	struct UpdateVersion
	{
		std::string version;
		std::string notes;
		time_t time;

		static std::vector<UpdateVersion> GetChannelVersions(const std::string& channel);
	};

	// WebsocketProvider
	class WebsocketProvider;

	/*!
		\ingroup websocketprovider
	*/
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

	/*!
		\ingroup websocketprovider
	*/
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

	/*!
		\ingroup websocketprovider
	*/
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

	/*!

		\ingroup coreapi
	*/
	class ReportCollection :
	    public CoreRefCountObject<BNReportCollection, BNNewReportCollectionReference, BNFreeReportCollection>
	{
	  public:
		ReportCollection();
		ReportCollection(BNReportCollection* reports);

		size_t GetCount() const;
		BNReportType GetType(size_t i) const;
		Ref<BinaryView> GetView(size_t i) const;
		std::string GetTitle(size_t i) const;
		std::string GetContents(size_t i) const;
		std::string GetPlainText(size_t i) const;
		Ref<FlowGraph> GetFlowGraph(size_t i) const;

		void AddPlainTextReport(Ref<BinaryView> view, const std::string& title, const std::string& contents);
		void AddMarkdownReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
		    const std::string& plainText = "");
		void AddHTMLReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
		    const std::string& plainText = "");
		void AddGraphReport(Ref<BinaryView> view, const std::string& title, Ref<FlowGraph> graph);

		void UpdateFlowGraph(size_t i, Ref<FlowGraph> graph);
	};

	/*! DataRenderer objects tell the Linear View how to render specific types.

		The `IsValidForData` method returns a boolean to indicate if your derived class
		is able to render the type, given the `addr` and `context`. The `context` is a list of Type
		objects which represents the chain of nested objects that is being displayed.

		The `GetLinesForData` method returns a list of `DisassemblyTextLine` objects, each one
		representing a single line of Linear View output. The `prefix` variable is a list of `InstructionTextToken`'s
		which have already been generated by other `DataRenderer`'s.

		After defining the `DataRenderer` subclass you must then register it with the core. This is done by calling
		either `DataRendererContainer::RegisterGenericDataRenderer()` or
	 	`DataRendererContainer::RegisterTypeSpecificDataRenderer()`.
	 	A "generic" type renderer is able to be overridden by a "type specific" renderer. For instance there is a
	 	generic struct render which renders any struct that hasn't been explicitly overridden by a "type specific" renderer.

		\ingroup datarenderer
	*/
	class DataRenderer : public CoreRefCountObject<BNDataRenderer, BNNewDataRendererReference, BNFreeDataRenderer>
	{
		static bool IsValidForDataCallback(
		    void* ctxt, BNBinaryView* data, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
		static BNDisassemblyTextLine* GetLinesForDataCallback(void* ctxt, BNBinaryView* data, uint64_t addr,
		    BNType* type, const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
		    BNTypeContext* typeCxt, size_t ctxCount);
		static void FreeCallback(void* ctxt);
		static void FreeLinesCallback(void* ctxt, BNDisassemblyTextLine* lines, size_t count);

	  public:
		DataRenderer();
		DataRenderer(BNDataRenderer* renderer);
		virtual bool IsValidForData(
		    BinaryView* data, uint64_t addr, Type* type, std::vector<std::pair<Type*, size_t>>& context);
		virtual std::vector<DisassemblyTextLine> GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
		    const std::vector<InstructionTextToken>& prefix, size_t width,
		    std::vector<std::pair<Type*, size_t>>& context);
		std::vector<DisassemblyTextLine> RenderLinesForData(BinaryView* data, uint64_t addr, Type* type,
		    const std::vector<InstructionTextToken>& prefix, size_t width,
		    std::vector<std::pair<Type*, size_t>>& context);

		static bool IsStructOfTypeName(
		    Type* type, const QualifiedName& name, std::vector<std::pair<Type*, size_t>>& context);
		static bool IsStructOfTypeName(
		    Type* type, const std::string& name, std::vector<std::pair<Type*, size_t>>& context);
	};

	/*! Used for registering DataRenderers

		\see DataRenderer

		\ingroup datarenderer
	*/
	class DataRendererContainer
	{
	  public:
		static void RegisterGenericDataRenderer(DataRenderer* renderer);
		static void RegisterTypeSpecificDataRenderer(DataRenderer* renderer);
	};

	/*!

		\ingroup coreapi
	*/
	class DisassemblyTextRenderer :
	    public CoreRefCountObject<BNDisassemblyTextRenderer, BNNewDisassemblyTextRendererReference,
	        BNFreeDisassemblyTextRenderer>
	{
	  public:
		DisassemblyTextRenderer(Function* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(LowLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(MediumLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(HighLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);

		Ref<Function> GetFunction() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		Ref<BasicBlock> GetBasicBlock() const;
		Ref<Architecture> GetArchitecture() const;
		Ref<DisassemblySettings> GetSettings() const;
		void SetBasicBlock(BasicBlock* block);
		void SetArchitecture(Architecture* arch);
		void SetSettings(DisassemblySettings* settings);

		virtual bool IsIL() const;
		virtual bool HasDataFlow() const;

		virtual void GetInstructionAnnotations(std::vector<InstructionTextToken>& tokens, uint64_t addr);
		virtual bool GetInstructionText(uint64_t addr, size_t& len, std::vector<DisassemblyTextLine>& lines);
		std::vector<DisassemblyTextLine> PostProcessInstructionTextLines(uint64_t addr, size_t len,
		    const std::vector<DisassemblyTextLine>& lines, const std::string& indentSpaces = "");

		virtual bool GetDisassemblyText(uint64_t addr, size_t& len, std::vector<DisassemblyTextLine>& lines);
		void ResetDeduplicatedComments();

		bool AddSymbolToken(std::vector<InstructionTextToken>& tokens, uint64_t addr, size_t size, size_t operand);
		void AddStackVariableReferenceTokens(
		    std::vector<InstructionTextToken>& tokens, const StackVariableReference& ref);

		static bool IsIntegerToken(BNInstructionTextTokenType type);
		void AddIntegerToken(std::vector<InstructionTextToken>& tokens, const InstructionTextToken& token,
		    Architecture* arch, uint64_t addr);

		void WrapComment(DisassemblyTextLine& line, std::vector<DisassemblyTextLine>& lines, const std::string& comment,
		    bool hasAutoAnnotations, const std::string& leadingSpaces = "  ", const std::string& indentSpaces = "");
		static std::string GetDisplayStringForInteger(Ref<BinaryView> binaryView, BNIntegerDisplayType type,
		    uint64_t value, size_t inputWidth, bool isSigned = true);
	};

	/*!
		\ingroup lineardisassembly
	*/
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

	/*!
		\ingroup lineardisassembly
	*/
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

	/*!
		\ingroup lineardisassembly
	*/
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

	/*!

		\ingroup simplifyname
	*/
	class SimplifyName
	{
	  public:
		// Use these functions to interface with the simplifier
		static std::string to_string(const std::string& input);
		static std::string to_string(const QualifiedName& input);
		static QualifiedName to_qualified_name(const std::string& input, bool simplify);
		static QualifiedName to_qualified_name(const QualifiedName& input);

		// Below is everything for the above APIs to work
		enum SimplifierDest
		{
			str,
			fqn
		};

		SimplifyName(const std::string&, const SimplifierDest, const bool);
		~SimplifyName();

		operator std::string() const;
		operator QualifiedName();

	  private:
		const char* m_rust_string;
		const char** m_rust_array;
		uint64_t m_length;
	};

	struct FindParameters
	{
		BNFindType type;
		BNFindRangeType rangeType;
		BNFunctionGraphType ilType;
		std::string string;
		BNFindFlag flags;
		bool findAll;
		bool advancedSearch;
		bool overlap;
		int alignment;

		uint64_t findConstant;
		DataBuffer findBuffer;

		std::vector<BNAddressRange> ranges;
		uint64_t totalLength;
	};

	/*! Class for storing secrets (e.g. tokens) in a system-specific manner

	 	\ingroup secretsprovider
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
		/*! Check if data for a specific key exists, but do not retrieve it

		    \param key Key for data
		    \return True if data exists
		*/
		virtual bool HasData(const std::string& key) = 0;

		/*! Retrieve data for the given key, if it exists

		    \param key Key for data
		    \return Optional with data, if it exists, or empty optional if it does not exist
		            or otherwise could not be retrieved.
		*/
		virtual std::optional<std::string> GetData(const std::string& key) = 0;

		/*! Store data with the given key

		    \param key Key for data
		    \param data Data to store
		    \return True if the data was stored
		*/
		virtual bool StoreData(const std::string& key, const std::string& data) = 0;

		/*! Delete stored data with the given key

		    \param key Key for data
		    \return True if it was deleted
		*/
		virtual bool DeleteData(const std::string& key) = 0;

		/*! Retrieve the list of providers

		    \return A list of registered providers
		*/
		static std::vector<Ref<SecretsProvider>> GetList();
		/*! Retrieve a provider by name

		    \param name Name of provider
		    \return Provider object, if one with the given name is regestered, or nullptr if not
		*/
		static Ref<SecretsProvider> GetByName(const std::string& name);
		/*! Register a new provider

		    \param provider New provider to register
		*/
		static void Register(SecretsProvider* provider);
	};

	/*!

		\ingroup secretsprovider
	*/
	class CoreSecretsProvider : public SecretsProvider
	{
	  public:
		CoreSecretsProvider(BNSecretsProvider* provider);

		virtual bool HasData(const std::string& key) override;
		virtual std::optional<std::string> GetData(const std::string& key) override;
		virtual bool StoreData(const std::string& key, const std::string& data) override;
		virtual bool DeleteData(const std::string& key) override;
	};

	/*! Components are objects that can contain Functions and other Components.

		\note Components should not be instantiated directly. Instead use BinaryView::CreateComponent()

		They can be queried for information about the functions contained within them.

	 	Components have a Guid, which persistent across saves and loads of the database, and should be
	 	used for retrieving components when such is required and a reference to the Component cannot be held.

	 	\ingroup coreapi

	*/
	class Component : public CoreRefCountObject<BNComponent, BNNewComponentReference, BNFreeComponent>
	{
	public:
		Component(BNComponent* type);

		/*! Get the unique identifier for this component.

			\return Component GUID
		*/
		std::string GetGuid();

		bool operator==(const Component& other) const;
		bool operator!=(const Component& other) const;

		Ref<BinaryView> GetView();

		/*! The displayed name for the component

		 	@threadunsafe

			This can differ from the GetOriginalName() value if the parent
		 	component also contains other components with the same name.

		 	Subsequent duplicates will return the original name with " (1)", " (2)" and so on appended.

		 	This name can change whenever a different duplicate is removed.

		 	\note For looking up Components, utilizing Guid is highly recommended, as it will *always* map to this component,
		 	and as Guid lookups are faster by nature.

			\return Component name
		*/
		std::string GetDisplayName();

		/*! The original name for the component

		 	@threadunsafe

			This may differ from Component::GetName() whenever the parent contains Components with the same original name.

		 	This function will always return the value originally set for this Component.

			\return Component name
		*/
		std::string GetName();

		/*! Set the name for the component

		 	@threadunsafe

			\see GetName(), GetOriginalName()

		    \param name New component name.
		*/
		void SetName(const std::string &name);

		/*! Get the parent component. If it's a top level component, it will return the "root" Component.

		 	@threadsafe

			\return Parent Component
		*/
		Ref<Component> GetParent();

		/*! Add a function to this component

		 	@threadsafe

			\param func Function to add.
			\return True if the function was successfully added.
		*/
		bool AddFunction(Ref<Function> func);

		/*! Move a component to this component.

		 	@threadsafe

			\param component Component to add.
			\return True if the component was successfully added.
		*/
		bool AddComponent(Ref<Component> component);

		bool AddDataVariable(DataVariable dataVariable);

		/*! Remove a Component from this Component, moving it to the root component.

		 	@threadsafe

			This will not remove a component from the tree entirely.

			\see BinaryView::GetRootComponent(), BinaryView::RemoveComponent()

			\param component Component to remove
			\return True if the component was successfully removed
		*/
		bool RemoveComponent(Ref<Component> component);

		/*! Remove a function

		 	@threadsafe

			\param func Function to remove
			\return True if the function was successfully removed.
		*/
		bool RemoveFunction(Ref<Function> func);

		bool RemoveDataVariable(DataVariable dataVariable);

		/*! Get a list of types referenced by the functions in this Component.

		 	@threadsafe

			\return vector of Type objects
		*/
		std::vector<Ref<Type>> GetReferencedTypes();

		/*! Get a list of components contained by this component.

		 	@threadsafe

			\return vector of Component objects
		*/
		std::vector<Ref<Component>> GetContainedComponents();

		/*! Get a list of functions contained within this Component.

		 	@threadsafe

			\return vector of Function objects
		*/
		std::vector<Ref<Function>> GetContainedFunctions();

		/*! Get a list of datavariables added to this component

		 	@threadsafe

			\return list of DataVariables
		*/
		std::vector<DataVariable> GetContainedDataVariables();

		/*! Get a list of DataVariables referenced by the functions in this Component.

		 	@threadsafe

			\return vector of DataVariable objects
		*/
		std::vector<DataVariable> GetReferencedDataVariables();
	};

	class TypeLibrary: public CoreRefCountObject<BNTypeLibrary, BNNewTypeLibraryReference, BNFreeTypeLibrary>
	{
	public:
		TypeLibrary(BNTypeLibrary* handle);

		/*! Creates an empty type library object with a random GUID and the provided name.

			\param arch
			\param name
		*/
		TypeLibrary(Ref<Architecture> arch, const std::string& name);

		/*! Decompresses a type library from a file

			\param path
			\return The string contents of the decompressed type library
		*/
		std::string Decompress(const std::string& path);

		/*! Decompresses a type library from a file

			\param path
			\param output
			\return True if the type library was successfully decompressed
		*/
		static bool DecompressToFile(const std::string& path, const std::string& output);

		/*! Loads a finalized type library instance from file

			\param path
			\return True if the type library was successfully loaded
		*/
		static Ref<TypeLibrary> LoadFromFile(const std::string& path);

		/*! Looks up the first type library found with a matching name. Keep in mind that names are
			not necessarily unique.

			\param arch
			\param name
			\return
		*/
		static Ref<TypeLibrary> LookupByName(Ref<Architecture> arch, const std::string& name);

		/*! Attempts to grab a type library associated with the provided Architecture and GUID pair

			\param arch
			\param guid
			\return
		*/
		static Ref<TypeLibrary> LookupByGuid(Ref<Architecture> arch, const std::string& guid);

		/*! Saves a finalized type library instance to file

			\param path
		*/
		bool WriteToFile(const std::string& path);

		/*! The Architecture this type library is associated with

			\return
		*/
		Ref<Architecture> GetArchitecture();

		/*! Returns the GUID associated with the type library

			\return
		*/
		std::string GetGuid();

		/*! The primary name associated with this type library

			\return
		*/
		std::string GetName();

		/*! A list of extra names that will be considered a match by ``Platform::GetTypeLibrariesByName``

			\return
		*/
		std::set<std::string> GetAlternateNames();

		/*! The dependency name of a library is the name used to record dependencies across
			type libraries. This allows, for example, a library with the name "musl_libc" to have
			dependencies on it recorded as "libc_generic", allowing a type library to be used across
			multiple platforms where each has a specific libc that also provides the name "libc_generic"
			as an `alternate_name`.

			\return
		*/
		std::string GetDependencyName();

		/*! Returns a list of all platform names that this type library will register with during platform
			type registration.

			This returns strings, not Platform objects, as type libraries can be distributed with support for
			Platforms that may not be present.

			\return
		*/
		std::set<std::string> GetPlatformNames();

		/*! Retrieves a metadata associated with the given key stored in the type library

			\param key Key to query
			\return Metadata associated with the key
		*/
		Ref<Metadata> QueryMetadata(const std::string& key);

		/*! Sets the GUID of a type library instance that has not been finalized

			\param guid
		*/
		void SetGuid(const std::string& guid);

		/*! Type Container for all TYPES within the Type Library. Objects are not included.
			The Type Container's Platform will be the first platform associated with the Type Library.
			\return Type Library Type Container
		 */
		TypeContainer GetTypeContainer();

		/*! Direct extracts a reference to a contained object -- when attempting to extract types from a library
			into a BinaryView, consider using BinaryView::ImportTypeLibraryObject instead.

			\param name
			\return
		*/
		Ref<Type> GetNamedObject(const QualifiedName& name);

		/*! Direct extracts a reference to a contained type -- when attempting to extract types from a library
			into a BinaryView, consider using BinaryView.ImportTypeLibraryType>` instead.

			\param name
			\return
		*/
		Ref<Type> GetNamedType(const QualifiedName& name);

		/*! A list containing all named objects (functions, exported variables) provided by a type library

			\return
		*/
		std::vector<QualifiedNameAndType> GetNamedObjects();

		/*! A list containing all named types provided by a type library

			\return
		*/
		std::vector<QualifiedNameAndType> GetNamedTypes();

		/*! Sets the name of a type library instance that has not been finalized

			\param name
		*/
		void SetName(const std::string& name);

		/*! Adds an extra name to this type library used during library lookups and dependency resolution

			\param alternate
		*/
		void AddAlternateName(const std::string& alternate);

		/*! Sets the dependency name of a type library instance that has not been finalized

			\param depName
		*/
		void SetDependencyName(const std::string& depName);

		/*! Clears the list of platforms associated with a type library instance that has not been finalized

		*/
		void ClearPlatforms();

		/*! Associate a platform with a type library instance that has not been finalized.

			This will cause the library to be searchable by Platform::GetTypeLibrariesByName when loaded.

			This does not have side affects until finalization of the type library.

			\param platform
		*/
		void AddPlatform(Ref<Platform> platform);

		/*! Stores an object for the given key in the current type library. Objects stored using StoreMetadata can be
			retrieved from any reference to the library.

			This is primarily intended as a way to store Platform specific information relevant to BinaryView implementations;
			for example the PE BinaryViewType uses type library metadata to retrieve ordinal information, when available.

			\param key Key value to associate the Metadata object with
			\param value Object to store.
		*/
		void StoreMetadata(const std::string& key, Ref<Metadata> value);

		/*! Removes the metadata associated with key from the current type library.

			\param key Key associated with metadata
		*/
		void RemoveMetadata(const std::string& key);

		/*! Returns a base Metadata object associated with the current type library.

			\return Metadata object associated with the type library
		*/
		Ref<Metadata> GetMetadata();

		/*! Directly inserts a named object into the type library's object store.
			This is not done recursively, so care should be taken that types referring to other types
			through NamedTypeReferences are already appropriately prepared.

			To add types and objects from an existing BinaryView, it is recommended to use
			BinaryView::ExportObjectToLibrary, which will automatically pull in all referenced types and record
			additional dependencies as needed.

			\param name
			\param type
		*/
		void AddNamedObject(const QualifiedName& name, Ref<Type> type);

		/*! Directly inserts a named object into the type library's object store.
			This is not done recursively, so care should be taken that types referring to other types
			through NamedTypeReferences are already appropriately prepared.

			To add types and objects from an existing BinaryView, it is recommended to use
			BinaryView::ExportTypeToLibrary, which will automatically pull in all referenced types and record
			additional dependencies as needed.

			\param name
			\param type
		*/
		void AddNamedType(const QualifiedName& name, Ref<Type> type);

		/*! Manually flag NamedTypeReferences to the given QualifiedName as originating from another source
			TypeLibrary with the given dependency name.

			\warning Use this api with extreme caution.

			\param name
			\param source
		*/
		void AddNamedTypeSource(const QualifiedName& name, const std::string& source);

		/*! Flags a newly created type library instance as finalized and makes it available for Platform and Architecture
			type library searches

		*/
		void Finalize();
	};

	/*! A TypeContainer is a generic interface to access various Binary Ninja models
		that contain types. Types are stored with both a unique id and a unique name.

		\ingroup types
	 */
	class TypeContainer
	{
		BNTypeContainer* m_object;

	public:
		explicit TypeContainer(BNTypeContainer* container);

		/*! Get the Type Container for a given BinaryView

			\param data BinaryView source
		 */
		TypeContainer(Ref<BinaryView> data);

		/*! Get the Type Container for a Type Library

			\note The Platform for the Type Container will be the first Platform
			      associated with the Type Library
			\param library TypeLibrary source
		 */
		TypeContainer(Ref<TypeLibrary> library);


		/*! Get the Type Container for a Type Archive

			\param archive TypeArchive source
		 */
		TypeContainer(Ref<TypeArchive> archive);

		/*! Get the Type Container for a Platform

			\param platform Platform source
		 */
		TypeContainer(Ref<Platform> platform);

		~TypeContainer();
		TypeContainer(const TypeContainer& other);
		TypeContainer(TypeContainer&& other);
		TypeContainer& operator=(const TypeContainer& other);
		TypeContainer& operator=(TypeContainer&& other);
		bool operator==(const TypeContainer& other) const { return GetId() == other.GetId(); }
		bool operator!=(const TypeContainer& other) const { return !operator==(other); }

		BNTypeContainer* GetObject() const { return m_object; }

		/*! Get an id string for the Type Container. This will be unique within a given
			analysis session, but may not be globally unique.

			\return Identifier string
		 */
		std::string GetId() const;

		/*! Get a user-friendly name for the Type Container.

			\return Display name
		 */
		std::string GetName() const;

		/*! Get the type of underlying model the Type Container is accessing.

			\return Container type enum
		 */
		BNTypeContainerType GetType() const;

		/*! Test if the Type Container supports mutable operations (add, rename, delete)

			\return True if mutable
		 */
		bool IsMutable() const;

		/*! Get the Platform object associated with this Type Container. All Type Containers
			have exactly one associated Platform (as opposed to, e.g. Type Libraries).

			\return Associated Platform object
		 */
		Ref<Platform> GetPlatform() const;


		/*! Add or update a single type in the Type Container. If the Type Container already contains
			a type with the same name as a type being added, the existing type will be
			replaced with the definition given to this function, and references will be
			updated in the source model.

			\param name Name of type to add
			\param type Definition of type to add
			\return String of added type's id, if successful, std::nullopt otherwise
		 */
		std::optional<std::string> AddType(QualifiedName name, Ref<Type> type);

		/*! Add or update types to a Type Container. If the Type Container already contains
			a type with the same name as a type being added, the existing type will be
			replaced with the definition given to this function, and references will be
			updated in the source model.

			An optional progress callback is included because adding many types can be a slow operation.

			\param types List of (name, definition) pairs of new types to add
			\param progress Optional function to call for progress updates
			\return Map of name -> id of type in Type Container for all added types if successful,
			        std::nullopt otherwise.
		 */
		std::optional<std::unordered_map<QualifiedName, std::string>> AddTypes(
			const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
			std::function<bool(size_t, size_t)> progress = {});

		/*! Rename a type in the Type Container. All references to this type will be updated
			(by id) to use the new name.

			\param typeId Id of type to update
			\param newName New name for the type
			\return True if successful
		 */
		bool RenameType(const std::string& typeId, const QualifiedName& newName);

		/*! Delete a type in the Type Container. Behavior of references to this type is
			not specified and you may end up with broken references if any still exist.

			\param typeId Id of type to delete
			\return True if successful
		 */
		bool DeleteType(const std::string& typeId);


		/*! Get the unique id of the type in the Type Container with the given name.
			If no type with that name exists, returns std::nullopt.

			\param typeName Name of type
			\return Type id, if exists, else, std::nullopt
		 */
		std::optional<std::string> GetTypeId(const QualifiedName& typeName) const;

		/*! Get the unique name of the type in the Type Container with the given id.
			If no type with that id exists, returns std::nullopt.

			\param typeId Id of type
			\return Type name, if exists, else, std::nullopt
		 */
		std::optional<QualifiedName> GetTypeName(const std::string& typeId) const;

		/*! Get the definition of the type in the Type Container with the given id.
			If no type with that id exists, returns std::nullopt.

			\param typeId Id of type
			\return Type object, if exists, else, std::nullopt
		 */
		std::optional<Ref<Type>> GetTypeById(const std::string& typeId) const;

		/*! Get a mapping of all types in a Type Container.

			\return All types in a map of type id -> (type name, type definition)
		 */
		std::optional<std::unordered_map<std::string, std::pair<QualifiedName, Ref<Type>>>> GetTypes() const;


		/*! Get the definition of the type in the Type Container with the given name.
			If no type with that name exists, returns None.

			\param typeName Name of type
			\return Type object, if exists, else, None
		 */
		std::optional<Ref<Type>> GetTypeByName(const QualifiedName& typeName) const;

		/*! Get all type ids in a Type Container.

			\return List of all type ids
		 */
		std::optional<std::unordered_set<std::string>> GetTypeIds() const;

		/*! Get all type names in a Type Container.

			\return List of all type names
		 */
		std::optional<std::unordered_set<QualifiedName>> GetTypeNames() const;

		/*! Get a mapping of all type ids and type names in a Type Container.

			\return Map of type id -> type name
		 */
		std::optional<std::unordered_map<std::string, QualifiedName>> GetTypeNamesAndIds() const;

		/*! Parse a single type and name from a string containing their definition,
			with knowledge of the types in the Type Container.

			\param source Source code to parse
			\param importDependencies If Type Library / Type Archive types should be imported during parsing
			\param result Reference into which the resulting type and name will be written
			\param errors Reference to a list into which any parse errors will be written
			\return True if parsing was successful
		 */
		bool ParseTypeString(
			const std::string& source,
			bool importDependencies,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		);

		/*!
			\deprecated Use `ParseTypeString` with the extra `importDependencies` param
		 */
		bool ParseTypeString(
			const std::string& source,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		);

		/*! Parse an entire block of source into types, variables, and functions, with
			knowledge of the types in the Type Container.

			\param text Source code to parse
			\param fileName Name of the file containing the source (optional: exists on disk)
			\param options Optional string arguments to pass as options, e.g. command line arguments
			\param includeDirs Optional list of directories to include in the header search path
			\param autoTypeSource Optional source of types if used for automatically generated types
			\param importDependencies If Type Library / Type Archive types should be imported during parsing
			\param result Reference to structure into which the results will be written
			\param errors Reference to a list into which any parse errors will be written
			\return True if successful
		 */
		bool ParseTypesFromSource(
			const std::string& text,
			const std::string& fileName,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			bool importDependencies,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		);

		/*!
			\deprecated Use `ParseTypesFromSource` with the extra `importDependencies` param
		 */
		bool ParseTypesFromSource(
			const std::string& text,
			const std::string& fileName,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		);
	};

	struct BaseAddressDetectionSettings
	{
		std::string Architecture;
		std::string Analysis;
		uint32_t MinStrlen;
		uint32_t Alignment;
		uint64_t LowerBoundary;
		uint64_t UpperBoundary;
		BNBaseAddressDetectionPOISetting POIAnalysis;
		uint32_t MaxPointersPerCluster;
	};

	/*!
		\ingroup baseaddressdetection
	*/
	class BaseAddressDetection
	{
		BNBaseAddressDetection* m_object;

	public:
		BaseAddressDetection(Ref<BinaryView> view);
		~BaseAddressDetection();

		/*! Analyze program, identify pointers and points-of-interest, and detect candidate base addresses

			\param settings Base address detection settings
			\return true on success, false otherwise
		 */
		bool DetectBaseAddress(BaseAddressDetectionSettings& settings);

		/*! Get the top 10 candidate base addresses and thier scores

			\param confidence Confidence level that indicates the likelihood the top base address candidate is correct
			\param lastTestedBaseAddress Last base address tested before analysis was aborted or completed
			\return Set of pairs containing candidate base addresses and their scores
		 */
		std::set<std::pair<size_t, uint64_t>> GetScores(BNBaseAddressDetectionConfidence* confidence, uint64_t *lastTestedBaseAddress);

		/*! Get a vector of BNBaseAddressDetectionReasons containing information that indicates why a base address was reported as a candidate

			\param baseAddress Base address to query reasons for
			\return Vector of reason structures containing information about why a base address was reported as a candidate
		 */
		std::vector<BNBaseAddressDetectionReason> GetReasonsForBaseAddress(uint64_t baseAddress);

		/*! Abort base address detection
		 */
		void Abort();

		/*! Determine if base address detection is aborted

			\return true if aborted by user, false otherwise
		 */
		bool IsAborted();
	};
}  // namespace BinaryNinja


namespace std
{
	template<> struct hash<BinaryNinja::QualifiedName>
	{
		typedef BinaryNinja::QualifiedName argument_type;
		size_t operator()(argument_type const& value) const
		{
			return std::hash<std::string>()(value.GetString());
		}
	};

	template<typename T> struct hash<BinaryNinja::Ref<T>>
	{
		typedef BinaryNinja::Ref<T> argument_type;
		size_t operator()(argument_type const& value) const
		{
			return std::hash<decltype(T::GetObject(value.GetPtr()))>()(T::GetObject(value.GetPtr()));
		}
	};
}  // namespace std


template<typename T> struct fmt::formatter<BinaryNinja::Ref<T>>
{
	format_context::iterator format(const BinaryNinja::Ref<T>& obj, format_context& ctx) const
	{
		return fmt::formatter<T>().format(*obj.GetPtr(), ctx);
	}
	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator { return ctx.begin(); }
};

template<typename T> struct fmt::formatter<BinaryNinja::Confidence<T>>
{
	format_context::iterator format(const BinaryNinja::Confidence<T>& obj, format_context& ctx) const
	{
		return fmt::format_to(ctx.out(), "{} ({} confidence)", obj.GetValue(), obj.GetConfidence());
	}
	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator { return ctx.begin(); }
};

template<> struct fmt::formatter<BinaryNinja::Metadata>
{
	format_context::iterator format(const BinaryNinja::Metadata& obj, format_context& ctx) const;
	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator { return ctx.begin(); }
};

template<> struct fmt::formatter<BinaryNinja::NameList>
{
	format_context::iterator format(const BinaryNinja::NameList& obj, format_context& ctx) const;
	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator { return ctx.begin(); }
};

template<typename T>
struct fmt::formatter<T, char, std::enable_if_t<std::is_enum_v<T>, void>>
{
	// s -> name, S -> scoped::name, d -> int, x -> hex
	char presentation = 's';
	format_context::iterator format(const T& obj, format_context& ctx) const
	{
		auto stringed = BinaryNinja::CoreEnumToString<T>(obj);
		if (stringed.has_value())
		{
			switch (presentation)
			{
			default:
			case 's':
				return fmt::format_to(ctx.out(), "{}", *stringed);
			case 'S':
				return fmt::format_to(ctx.out(), "{}::{}", BinaryNinja::CoreEnumName<T>(), *stringed);
			case 'd':
				return fmt::format_to(ctx.out(), "{}", (size_t)obj);
			case 'x':
				return fmt::format_to(ctx.out(), "{:#x}", (size_t)obj);
			}
		}
		else
		{
			return fmt::format_to(ctx.out(), "{}", (size_t)obj);
		}
	}

	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator
	{
		auto it = ctx.begin(), end = ctx.end();
		if (it != end && (*it == 's' || *it == 'S' || *it == 'd' || *it == 'x')) presentation = *it++;
		if (it != end && *it != '}') detail::throw_format_error("invalid format");
		return it;
	}
};
