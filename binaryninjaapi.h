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
#include <memory>
#include <cstdint>
#include <typeinfo>
#include <type_traits>
#include <variant>
#include <optional>
#include <memory>
#include "binaryninjacore.h"
#include "exceptions.h"
#include "json/json.h"
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

	/*!
		\ingroup databuffer
	*/
	class DataBuffer
	{
		BNDataBuffer* m_buffer;

	  public:
		DataBuffer();
		DataBuffer(size_t len);
		DataBuffer(const void* data, size_t len);
		DataBuffer(const DataBuffer& buf);
		DataBuffer(DataBuffer&& buf);
		DataBuffer(BNDataBuffer* buf);
		~DataBuffer();

		DataBuffer& operator=(const DataBuffer& buf);
		DataBuffer& operator=(DataBuffer&& buf);

		BNDataBuffer* GetBufferObject() const { return m_buffer; }

		/*! Get the raw pointer to the data contained within this buffer

			@threadunsafe
		*/
		void* GetData();

		/*! Get the raw pointer to the data contained within this buffer, as a const pointer.

			@threadunsafe
		*/
		const void* GetData() const;

		/*! Get the raw pointer to the data contained within this buffer, starting at a given offset

			@threadunsafe
		*/
		void* GetDataAt(size_t offset);

		/*! Get the const raw pointer to the data contained within this buffer, starting at a given offset

			@threadunsafe
		*/
		const void* GetDataAt(size_t offset) const;

		/*! Get the length of the data contained within this buffer

			@threadunsafe
		*/
		size_t GetLength() const;

		/*! Set the size of the data pointed to by this buffer

			@threadunsafe
		*/
		void SetSize(size_t len);

		/*! Clear the data contained by this buffer.

			\note This will call \c free() on this buffer's data pointer. You shouldn't call it yourself, typically ever.

			@threadunsafe
		*/
		void Clear();

		/*! Append \c len contents of the pointer \c data to the end of the buffer

			\note This will typically call \c realloc() on this buffer's data pointer. You should hold this DataBuffer and use it for accesses, instead of storing the raw pointer.

			@threadunsafe
		*/
		void Append(const void* data, size_t len);

		/*! Append the contents of databuffer \c buf to the current DataBuffer

			\note This will typically call \c realloc() on this buffer's data pointer. You should hold this DataBuffer and use it for accesses, instead of storing the raw pointer.

			@threadunsafe
		*/
		void Append(const DataBuffer& buf);

		/*! Append a single byte

			\note This will typically call \c realloc() on this buffer's data pointer. You should hold this DataBuffer and use it for accesses, instead of storing the raw pointer.

			@threadunsafe
		*/
		void AppendByte(uint8_t val);


		/*! Get the contents of a given slice of data, as a DataBuffer

			@threadunsafe
		*/
		DataBuffer GetSlice(size_t start, size_t len);

		uint8_t& operator[](size_t offset);
		const uint8_t& operator[](size_t offset) const;

		bool operator==(const DataBuffer& other) const;
		bool operator!=(const DataBuffer& other) const;

		/*! Convert the contents of the DataBuffer to a string

			\param nullTerminates Whether the decoder should stop and return the string after encountering a null (\x00) byte.

			@threadunsafe
		*/
		std::string ToEscapedString(bool nullTerminates = false) const;

		/*! Create a DataBuffer from a given escaped string.

			\param src Input string
			\returns Databuffer created from this string
		*/
		static DataBuffer FromEscapedString(const std::string& src);

		/*! Convert the contents of this DataBuffer to a base64 representation

			@threadunsafe
		*/
		std::string ToBase64() const;

		/*! Create a DataBuffer from a given base64 string.

			\param src Input base64 string
			\returns Databuffer created from this string
		*/
		static DataBuffer FromBase64(const std::string& src);

		/*! Compress this databuffer via ZLIB compression

			@threadunsafe

			\param[out] output Output DataBuffer the compressed contents will be stored in.
			\returns Whether compression was successful
		*/
		bool ZlibCompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via ZLIB compression

			@threadunsafe

			\param[out] output Output DataBuffer the decompressed contents will be stored in.
			\returns Whether decompression was successful
		*/
		bool ZlibDecompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via LZMA compression

		    @threadunsafe

		    \param[out] output Output DataBuffer the decompressed contents will be stored in.
		    \returns Whether decompression was successful
		*/
		bool LzmaDecompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via LZMA2 compression

		    @threadunsafe

		    \param[out] output Output DataBuffer the decompressed contents will be stored in.
		    \returns Whether decompression was successful
		*/
		bool Lzma2Decompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via XZ compression

		    @threadunsafe

		    \param[out] output Output DataBuffer the decompressed contents will be stored in.
		    \returns Whether decompression was successful
		*/
		bool XzDecompress(DataBuffer& output) const;
	};

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

	class BasicBlock;

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

	/*!
		\ingroup typeparser
	*/
	struct ParsedType
	{
		QualifiedName name;
		Ref<Type> type;
		bool isUser;

		ParsedType() = default;
		ParsedType(const std::string& name, const Ref<Type>& type, bool isUser): name(name), type(type), isUser(isUser)
		{}
		ParsedType(const QualifiedName& name, const Ref<Type>& type, bool isUser): name(name), type(type), isUser(isUser)
		{}

		bool operator<(const ParsedType& other) const
		{
			if (isUser != other.isUser)
				return isUser;
			return name < other.name;
		}
	};

	/*!
		\ingroup typeparser
	*/
	struct TypeParserResult
	{
		std::vector<ParsedType> types;
		std::vector<ParsedType> variables;
		std::vector<ParsedType> functions;
	};

	/*!
		\ingroup typeparser
	*/
	struct TypeParserError
	{
		BNTypeParserErrorSeverity severity;
		std::string message;
		std::string fileName;
		uint64_t line;
		uint64_t column;

		TypeParserError() = default;
		TypeParserError(BNTypeParserErrorSeverity severity, const std::string& message):
			severity(severity), message(message), fileName(""), line(0), column(0)
		{

		}
	};

#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
	template <class... Ts>
	struct overload : Ts...
	{
		using Ts::operator()...;
	};
	template <class... Ts>
	overload(Ts...) -> overload<Ts...>;
#endif

	/*!
		\ingroup workflow
	*/
	class AnalysisContext :
	    public CoreRefCountObject<BNAnalysisContext, BNNewAnalysisContextReference, BNFreeAnalysisContext>
	{
		std::unique_ptr<Json::CharReader> m_reader;
		Json::StreamWriterBuilder m_builder;

	  public:
		AnalysisContext(BNAnalysisContext* analysisContext);
		virtual ~AnalysisContext();

		/*! Get the Function for the current AnalysisContext

			\return The function for the current context
		*/
		Ref<Function> GetFunction();

		/*! Get the low level IL function for the current AnalysisContext

			\return The LowLevelILFunction for the current context
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction();

		/*! Get the medium level IL function for the current AnalysisContext

			\return The MediumLevelILFunction for the current context
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction();

		/*! Get the high level IL function for the current AnalysisContext

			\return The HighLevelILFunction for the current context
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction();

		/*! Set a new BasicBlock list for the current analysis context

			\param basicBlocks The new list of BasicBlocks
		*/
		void SetBasicBlockList(std::vector<Ref<BasicBlock>> basicBlocks);

		/*! Set new lifted IL for the current analysis context

			\param liftedIL The new lifted IL
		*/
		void SetLiftedILFunction(Ref<LowLevelILFunction> liftedIL);

		/*! Set the new Low Level IL for the current analysis context

			\param lowLevelIL the new Low Level IL
		*/
		void SetLowLevelILFunction(Ref<LowLevelILFunction> lowLevelIL);

		/*! Set the new Medium Level IL for the current analysis context

			\param mediumLevelIL the new Medium Level IL
		*/
		void SetMediumLevelILFunction(Ref<MediumLevelILFunction> mediumLevelIL);

		/*! Set the new High Level IL for the current analysis context

			\param highLevelIL the new High Level IL
		*/
		void SetHighLevelILFunction(Ref<HighLevelILFunction> highLevelIL);

		bool Inform(const std::string& request);

#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
		template <typename... Args>
		bool Inform(Args... args)
		{
			// using T = std::variant<Args...>; // FIXME: remove type duplicates
			using T = std::variant<std::string, const char*, uint64_t, Ref<Architecture>>;
			std::vector<T> unpackedArgs {args...};
			Json::Value request(Json::arrayValue);
			for (auto& arg : unpackedArgs)
				std::visit(overload {[&](Ref<Architecture> arch) { request.append(Json::Value(arch->GetName())); },
				               [&](uint64_t val) { request.append(Json::Value(val)); },
				               [&](auto& val) {
					               request.append(Json::Value(std::forward<decltype(val)>(val)));
				               }},
				    arg);

			return Inform(Json::writeString(m_builder, request));
		}
#endif
	};

	/*!
		\ingroup workflow
	*/
	class Activity : public CoreRefCountObject<BNActivity, BNNewActivityReference, BNFreeActivity>
	{
	  protected:
		std::function<void(Ref<AnalysisContext> analysisContext)> m_action;

		static void Run(void* ctxt, BNAnalysisContext* analysisContext);

	  public:
		/*!

			\code{.cpp}
		    MyClass::MyActionMethod(Ref<AnalysisContext> ac);
		    ...
		 	// Create a clone of the default workflow named "core.function.myWorkflowName"
		    Ref<Workflow> wf = BinaryNinja::Workflow::Instance()->Clone("core.function.myWorkflowName");
		 	wf->RegisterActivity(new BinaryNinja::Activity("core.function.myWorkflowName.resolveMethodCalls", &MyClass::MyActionMethod));
		 	\endcode

			\param configuration a JSON representation of the activity configuration
			\param action Workflow action, a function taking a Ref<AnalysisContext> as an argument.
		*/
		Activity(const std::string& configuration, const std::function<void(Ref<AnalysisContext>)>& action);
		Activity(BNActivity* activity);
		virtual ~Activity();

		/*! Get the Activity name

			\return Activity name
		*/
		std::string GetName() const;
	};

	/*! A Binary Ninja Workflow is an abstraction of a computational binary analysis pipeline and it provides the extensibility
		mechanism needed for tailored binary analysis and decompilation. More specifically, a Workflow is a repository of activities along with a
		unique strategy to execute them. Binary Ninja provides two Workflows named ``core.module.defaultAnalysis`` and ``core.function.defaultAnalysis``
		which expose the core analysis.

		A Workflow starts in the unregistered state from either creating a new empty Workflow, or cloning an existing Workflow. While unregistered
		it's possible to add and remove activities, as well as change the execution strategy. In order to use the Workflow on a binary it must be
		registered. Once registered the Workflow is immutable and available for use.

	 	\ingroup workflow
	*/
	class Workflow : public CoreRefCountObject<BNWorkflow, BNNewWorkflowReference, BNFreeWorkflow>
	{
	  public:
		Workflow(const std::string& name = "");
		Workflow(BNWorkflow* workflow);
		virtual ~Workflow() {}

		/*! Get a list of all workflows

			\return A list of Workflows
		*/
		static std::vector<Ref<Workflow>> GetList();

		/*! Get an instance of a workflow by name. If it is already registered, this will return the registered Workflow.
			If not, it will create and return a new Workflow.

			\param name Workflow name
			\return The registered workflow.
		*/
		static Ref<Workflow> Instance(const std::string& name = "");
		/*! Register a workflow, making it immutable and available for use

			\param workflow The workflow to register
			\param description A JSON description of the Workflow
			\return true on success, false otherwise
		*/
		static bool RegisterWorkflow(Ref<Workflow> workflow, const std::string& description = "");

		/*! Clone a workflow, copying all Activities and the execution strategy

			\param name Name for the new Workflow
			\param activity If specified, perform the clone with `activity` as the root
			\return A new Workflow
		*/
		Ref<Workflow> Clone(const std::string& name, const std::string& activity = "");

		/*! Register an Activity with this Workflow

			\param activity The Activity to register
			\param description A JSON description of the Activity
			\return
		*/

		/*! Register an Activity with this Workflow

			\param configuration a JSON representation of the activity configuration
			\param action Workflow action, a function taking a Ref<AnalysisContext> as an argument.
			\param subactivities The list of Activities to assign
			\return
		*/
		Ref<Activity> RegisterActivity(const std::string& configuration, const std::function<void(Ref<AnalysisContext>)>& action, const std::vector<std::string>& subactivities = {});

		/*! Register an Activity with this Workflow

			\param activity The Activity to register
			\param subactivities The list of Activities to assign
			\return
		*/
		Ref<Activity> RegisterActivity(Ref<Activity> activity, const std::vector<std::string>& subactivities = {});

		/*! Determine if an Activity exists in this Workflow

			\param activity The Activity name
			\return Whether the Activity exists in this workflow
		*/
		bool Contains(const std::string& activity);

		/*! Retrieve the configuration as an adjacency list in JSON for the Workflow,
			or if specified just for the given ``activity``.

			\param activity If specified, return the configuration for the ``activity``
			\return An adjacency list representation of the configuration in JSON
		*/
		std::string GetConfiguration(const std::string& activity = "");

		/*! Get the workflow name

			\return The workflow name
		*/
		std::string GetName() const;

		/*! Check whether the workflow is registered

			\return Whether the workflow is registered
		*/
		bool IsRegistered() const;

		/*! Get the amount of registered activities for this Workflow

			\return The amount of registered workflows
		*/
		size_t Size() const;

		/*! Retrieve an activity by name

			\param activity The Activity name
			\return The Activity object
		*/
		Ref<Activity> GetActivity(const std::string& activity);

		/*! Retrieve the list of activity roots for the Workflow, or if specified just for the given `activity`.

			\param activity If specified, return the roots for `activity`
			\return A list of root activity names.
		*/
		std::vector<std::string> GetActivityRoots(const std::string& activity = "");

		/*! Retrieve the list of all activities, or optionally a filtered list.

			\param activity If specified, return the direct children and optionally the descendants of the `activity` (includes `activity`)
			\param immediate whether to include only direct children of `activity` or all descendants
			\return A list of Activity names
		*/
		std::vector<std::string> GetSubactivities(const std::string& activity = "", bool immediate = true);

		/*! Assign the list of `activities` as the new set of children for the specified `activity`.

			\param activity The activity node to assign children
			\param subactivities the list of Activities to assign
			\return true on success, false otherwise
		*/
		bool AssignSubactivities(const std::string& activity, const std::vector<std::string>& subactivities = {});

		/*! Remove all activity nodes from this Workflow

			\return true on success, false otherwise
		*/
		bool Clear();

		/*! Insert an activity before the specified activity and at the same level.

			\param activity Name of the activity to insert the new one before
			\param newActivity Name of the new activity to be inserted
			\return true on success, false otherwise
		*/
		bool Insert(const std::string& activity, const std::string& newActivity);

		/*! Insert a list of activities before the specified activity and at the same level.

			\param activity Name of the activity to insert the new one before
			\param newActivity Name of the new activities to be inserted
			\return true on success, false otherwise
		*/
		bool Insert(const std::string& activity, const std::vector<std::string>& activities);

		/*! Remove an activity by name

			\param activity Name of the activity to remove
			\return true on success, false otherwise
		*/
		bool Remove(const std::string& activity);

		/*! Replace the activity name

			\param activity Name of the activity to replace
			\param newActivity Name of the new activity
			\return true on success, false otherwise
		*/
		bool Replace(const std::string& activity, const std::string& newActivity);

		/*! Generate a FlowGraph object for the current Workflow

			\param activity if specified, generate the Flowgraph using ``activity`` as the root
			\param sequential whether to generate a **Composite** or **Sequential** style graph
			\return FlowGraph on success
		*/
		Ref<FlowGraph> GetGraph(const std::string& activity = "", bool sequential = false);
		void ShowReport(const std::string& name);
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

	/*!
		\ingroup basicblocks
	*/
	struct BasicBlockEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target; //! The source or destination of the edge, depending on context
		bool backEdge;
		bool fallThrough;
	};

	/*!
		\ingroup basicblocks
	*/
	class BasicBlock : public CoreRefCountObject<BNBasicBlock, BNNewBasicBlockReference, BNFreeBasicBlock>
	{
	  public:
		BasicBlock(BNBasicBlock* block);

		/*! Basic block function

			\return The Function for this basic block
		*/
		Ref<Function> GetFunction() const;

		/*! Basic block architecture

			\return The Architecture for this Basic Block
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Starting address of the basic block

			\return Start address of the basic block
		*/
		uint64_t GetStart() const;

		/*! Ending address of the basic block

			\return Ending address of the basic block
		*/
		uint64_t GetEnd() const;

		/*! Length of the basic block

			\return Length of the basic block
		*/
		uint64_t GetLength() const;

		/*! Basic block index in list of blocks for the function

			\return Basic block index in list of blocks for the function
		*/
		size_t GetIndex() const;

		/*! List of basic block outgoing edges

			\return List of basic block outgoing edges
		*/
		std::vector<BasicBlockEdge> GetOutgoingEdges() const;

		/*! List of basic block incoming edges

			\return List of basic block incoming edges
		*/
		std::vector<BasicBlockEdge> GetIncomingEdges() const;

		/*! Whether basic block has undetermined outgoing edges

			\return Whether basic block has undetermined outgoing edges
		*/
		bool HasUndeterminedOutgoingEdges() const;

		/*! Whether basic block can return or is tagged as 'No Return'

			\return Whether basic block can return or is tagged as 'No Return'
		*/
		bool CanExit() const;

		/*! Sets whether basic block can return or is tagged as 'No Return'

			\param value Sets whether basic block can return or is tagged as 'No Return'
		*/
		void SetCanExit(bool value);

		/*! List of dominators for this basic block

			\param post Whether to get post dominators (default: false)
			\return Set of BasicBlock dominators
		*/
		std::set<Ref<BasicBlock>> GetDominators(bool post = false) const;

		/*! List of dominators for this basic block

			\param post Whether to get post dominators (default: false)
			\return Set of BasicBlock dominators
		*/
		std::set<Ref<BasicBlock>> GetStrictDominators(bool post = false) const;

		/*! Get the immediate dominator of this basic block

			\param post Whether to get the immediate post dominator
			\return Immediate dominator basic block
		*/
		Ref<BasicBlock> GetImmediateDominator(bool post = false) const;

		/*! List of child blocks in the dominator tree for this basic block

			\param post Whether to get the post dominator tree children
			\return Set of Tree children
		*/
		std::set<Ref<BasicBlock>> GetDominatorTreeChildren(bool post = false) const;

		/*! Get the dominance frontier for this basic block

			\param post Whether to get the post dominance frontier
			\return Post dominance frontier for this basic block
		*/
		std::set<Ref<BasicBlock>> GetDominanceFrontier(bool post = false) const;
		static std::set<Ref<BasicBlock>> GetIteratedDominanceFrontier(const std::set<Ref<BasicBlock>>& blocks);

		void MarkRecentUse();

		/*! List of automatic annotations for the start of this block

			\return List of automatic annotations for the start of this block
		*/
		std::vector<std::vector<InstructionTextToken>> GetAnnotations();

		/*! property which returns a list of DisassemblyTextLine objects for the current basic block.

			\param settings Disassembly settings to use when fetching the text
			\return Disassembly text
		*/
		std::vector<DisassemblyTextLine> GetDisassemblyText(DisassemblySettings* settings);

		/*! Get the current highlight color for the Basic Block

			\return The current highlight color for the Basic Block
		*/
		BNHighlightColor GetBasicBlockHighlight();

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
		*/
		void SetAutoBasicBlockHighlight(BNHighlightColor color);

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
			\param alpha Transparency for the color
		*/
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
			\param mixColor Highlight Color to mix with `color`
			\param mix Mix point
			\param alpha Transparency of the colors
		*/
		void SetAutoBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);

		/*! Set the analysis basic block highlight color

			\param r Red value, 0-255
			\param g Green value, 0-255
			\param b Blue value, 0-255
			\param alpha Transparency of the color
		*/
		void SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param color Highlight color
		*/
		void SetUserBasicBlockHighlight(BNHighlightColor color);

		/*! Set the basic block highlight color

			\param color Highlight color
			\param alpha Transparency of the color
		*/
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param color Highlight Color
			\param mixColor Highlight Color to mix with `color`
			\param mix Mix point
			\param alpha Transparency of the colors
		*/
		void SetUserBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param r Red value, 0-255
			\param g Green value, 0-255
			\param b Blue value, 0-255
			\param alpha Transparency of the color
		*/
		void SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		static bool IsBackEdge(BasicBlock* source, BasicBlock* target);

		/*! Whether the basic block contains IL

			\return Whether the basic block contains IL
		*/
		bool IsILBlock() const;

		/*! Whether the basic block contains Medium Level IL

			\return Whether the basic block contains Medium Level IL
		*/
		bool IsLowLevelILBlock() const;

		/*! Whether the basic block contains High Level IL

			\return Whether the basic block contains High Level IL
		*/
		bool IsMediumLevelILBlock() const;

		/*! Get the Low Level IL Function for this basic block

			\return Get the Low Level IL Function for this basic block
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;

		/*! Get the Medium Level IL Function for this basic block

			\return Get the Medium Level IL Function for this basic block
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;

		/*! Get the High Level IL Function for this basic block

			\return Get the High Level IL Function for this basic block
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		bool GetInstructionContainingAddress(uint64_t addr, uint64_t* start);

		/*! Gets the corresponding assembly-level basic block for this basic block
			(which is itself, if called on an assembly-level basic block).

			\return Basic Block
		*/
		Ref<BasicBlock> GetSourceBlock() const;
	};

	class FlowGraphNode;

	/*!
		\ingroup flowgraph
	*/
	struct FlowGraphEdge
	{
		BNBranchType type;
		Ref<FlowGraphNode> target;
		std::vector<BNPoint> points;
		bool backEdge;
		BNEdgeStyle style;
	};

	/*!
		\ingroup flowgraph
	*/
	class FlowGraphNode : public CoreRefCountObject<BNFlowGraphNode, BNNewFlowGraphNodeReference, BNFreeFlowGraphNode>
	{
		std::vector<DisassemblyTextLine> m_cachedLines;
		std::vector<FlowGraphEdge> m_cachedEdges, m_cachedIncomingEdges;
		bool m_cachedLinesValid, m_cachedEdgesValid, m_cachedIncomingEdgesValid;

	  public:
		FlowGraphNode(FlowGraph* graph);
		FlowGraphNode(BNFlowGraphNode* node);

		/*! Get the FlowGraph associated with this node

			\return The FlowGraph associated with this node
		*/
		Ref<FlowGraph> GetGraph() const;

		/*! Get the Basic Block associated with this node

			\return The BasicBlock associated with this node
		*/
		Ref<BasicBlock> GetBasicBlock() const;

		/*! Set the Basic Block associated with this node

			\param block The BasicBlock associated with this node
		*/
		void SetBasicBlock(BasicBlock* block);

		/*! Flow graph block X position

			\return Flow graph block X position
		*/
		int GetX() const;

		/*! Flow graph block Y position

			\return Flow graph block Y position
		*/
		int GetY() const;

		/*! Flow graph block width

			\return Flow graph block width
		*/
		int GetWidth() const;

		/*! Flow graph block height

			\return Flow graph block height
		*/
		int GetHeight() const;

		/*! Get the list of DisassemblyTextLines for this graph node.

			\return The list of DisassemblyTextLines for this graph node.
		*/
		const std::vector<DisassemblyTextLine>& GetLines();

		/*! Set the list of DisassemblyTextLines for this graph node.

			\param lines The list of DisassemblyTextLines for this graph node.
		*/
		void SetLines(const std::vector<DisassemblyTextLine>& lines);

		/*! Get the list of outgoing edges for this flow graph node

			\return The list of outgoing edges for this flow graph node
		*/
		const std::vector<FlowGraphEdge>& GetOutgoingEdges();

		/*! Get the list of incoming edges for this flow graph node

			\return The list of incoming edges for this flow graph node
		*/
		const std::vector<FlowGraphEdge>& GetIncomingEdges();

		/*! Connects two flow graph nodes with an edge

			\param type Type of edge to add
			\param target Target node object
			\param edgeStyle
		 	\parblock
		 	Custom style for this edge.

		 	Styling for graph edge Branch Type must be set to UserDefinedBranch
		 	\endparblock
		*/
		void AddOutgoingEdge(BNBranchType type, FlowGraphNode* target, BNEdgeStyle edgeStyle = BNEdgeStyle());

		/*! Get the highlight color for the node

			\return The highlight color for the node
		*/
		BNHighlightColor GetHighlight() const;

		/*! Set the highlight color for the node

			\param color The highlight color for the node
		*/
		void SetHighlight(const BNHighlightColor& color);

		bool IsValidForGraph(FlowGraph* graph) const;
	};

	/*!
		\ingroup flowgraph
	*/
	class FlowGraphLayoutRequest : public RefCountObject
	{
		BNFlowGraphLayoutRequest* m_object;
		std::function<void()> m_completeFunc;

		static void CompleteCallback(void* ctxt);

	  public:
		FlowGraphLayoutRequest(FlowGraph* graph, const std::function<void()>& completeFunc);
		virtual ~FlowGraphLayoutRequest();

		BNFlowGraphLayoutRequest* GetObject() const { return m_object; }

		Ref<FlowGraph> GetGraph() const;
		bool IsComplete() const;
		void Abort();
	};

	/*! FlowGraph implements a directed flow graph to be shown in the UI. This class allows plugins to
			create custom flow graphs and render them in the UI using the flow graph report API.

	 	\ingroup flowgraph
	*/
	class FlowGraph : public CoreRefCountObject<BNFlowGraph, BNNewFlowGraphReference, BNFreeFlowGraph>
	{
		std::map<BNFlowGraphNode*, Ref<FlowGraphNode>> m_cachedNodes;

		static void PrepareForLayoutCallback(void* ctxt);
		static void PopulateNodesCallback(void* ctxt);
		static void CompleteLayoutCallback(void* ctxt);
		static BNFlowGraph* UpdateCallback(void* ctxt);
		static void FreeObjectCallback(void* ctxt);

	  protected:
		bool m_queryMode = false;

		FlowGraph(BNFlowGraph* graph);

		void FinishPrepareForLayout();
		virtual void PrepareForLayout();
		virtual void PopulateNodes();
		virtual void CompleteLayout();

	  public:
		FlowGraph();

		/*! Get the Function associated with this FlowGraph

			\return The Function associated with this FlowGraph
		*/
		Ref<Function> GetFunction() const;

		/*! Get the BinaryView associated with this FlowGraph

			\return The BinaryView associated with this FlowGraph
		*/
		Ref<BinaryView> GetView() const;

		/*! Set the Function associated with this FlowGraph

			\param func The Function associated with this FlowGraph
		*/
		void SetFunction(Function* func);

		/*! Set the BinaryView associated with this FlowGraph

			\param view The BinaryView associated with this FlowGraph
		*/
		void SetView(BinaryView* view);

		int GetHorizontalNodeMargin() const;
		int GetVerticalNodeMargin() const;
		void SetNodeMargins(int horiz, int vert);

		/*! Starts rendering a graph for display. Once a layout is complete, each node will contain
			coordinates and extents that can be used to render a graph with minimum additional computation.
			This function does not wait for the graph to be ready to display, but a callback can be provided
			to signal when the graph is ready.

			\param func Callback to execute once layout is complete.
			\return
		*/
		Ref<FlowGraphLayoutRequest> StartLayout(const std::function<void()>& func);

		/*! Check whether layout is complete

			\return Whether layout is complete
		*/
		bool IsLayoutComplete();

		/*! Get the list of nodes in the graph

			\return List of nodes in the graph
		*/
		std::vector<Ref<FlowGraphNode>> GetNodes();

		/*! Retrieve node by index

			\param i Index of the node to retrieve
			\return The flow graph node at that index
		*/
		Ref<FlowGraphNode> GetNode(size_t i);

		/*! Whether the FlowGraph has any nodes added

			\return Whether the FlowGraph has any nodes added
		*/
		bool HasNodes() const;

		/*! Add a node to this flowgraph

			\param node Node to be added.
			\return Index of the node
		*/
		size_t AddNode(FlowGraphNode* node);

		/*! Flow graph width

			\return Flow graph width
		*/
		int GetWidth() const;

		/*! Flow graph height

			\return Flow graph height
		*/
		int GetHeight() const;
		std::vector<Ref<FlowGraphNode>> GetNodesInRegion(int left, int top, int right, int bottom);

		/*! Whether this graph is representing IL.

			\return Whether this graph is representing IL.
		*/
		bool IsILGraph() const;

		/*! Whether this graph is representing Low Level IL.

			\return Whether this graph is representing Low Level IL.
		*/
		bool IsLowLevelILGraph() const;

		/*! Whether this graph is representing Medium Level IL.

			\return Whether this graph is representing Medium Level IL.
		*/
		bool IsMediumLevelILGraph() const;

		/*! Whether this graph is representing High Level IL.

			\return Whether this graph is representing High Level IL.
		*/
		bool IsHighLevelILGraph() const;

		/*! Get the associated Low Level IL Function

			\return The associated Low Level IL Function
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;

		/*! Get the associated Medium Level IL Function

			\return The associated Medium Level IL Function
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;

		/*! Get the associated High Level IL Function

			\return The associated High Level IL Function
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		/*! Set the associated Low Level IL Function

			\param func The associated function
		*/
		void SetLowLevelILFunction(LowLevelILFunction* func);

		/*! Set the associated Medium Level IL Function

			\param func The associated function
		*/
		void SetMediumLevelILFunction(MediumLevelILFunction* func);

		/*! Set the associated High Level IL Function

			\param func The associated function
		*/
		void SetHighLevelILFunction(HighLevelILFunction* func);

		/*! Display a flowgraph with a given title.

			\param title Title for the flowgraph
		*/
		void Show(const std::string& title);

		virtual bool HasUpdates() const;

		virtual Ref<FlowGraph> Update();

		void SetOption(BNFlowGraphOption option, bool value = true);
		bool IsOptionSet(BNFlowGraphOption option);
	};

	/*!
		\ingroup flowgraph
	*/
	class CoreFlowGraph : public FlowGraph
	{
	  public:
		CoreFlowGraph(BNFlowGraph* graph);
		virtual bool HasUpdates() const override;
		virtual Ref<FlowGraph> Update() override;
	};


	struct LowLevelILInstruction;
	struct RegisterOrFlag;
	struct SSARegister;
	struct SSARegisterStack;
	struct SSAFlag;
	struct SSARegisterOrFlag;

	struct HighLevelILInstruction;

	/*!
		\ingroup highlevelil
	*/
	class HighLevelILFunction :
	    public CoreRefCountObject<BNHighLevelILFunction, BNNewHighLevelILFunctionReference, BNFreeHighLevelILFunction>
	{
	  public:
		HighLevelILFunction(Architecture* arch, Function* func = nullptr);
		HighLevelILFunction(BNHighLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);

		HighLevelILInstruction GetRootExpr();
		void SetRootExpr(ExprId expr);
		void SetRootExpr(const HighLevelILInstruction& expr);

		ExprId AddExpr(BNHighLevelILOperation operation, size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0,
		    ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNHighLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNHighLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Block(const std::vector<ExprId>& exprs, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(
		    ExprId condition, ExprId trueExpr, ExprId falseExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId While(ExprId condition, ExprId loopExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId WhileSSA(
		    ExprId conditionPhi, ExprId condition, ExprId loopExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DoWhile(ExprId loopExpr, ExprId condition, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DoWhileSSA(
		    ExprId loopExpr, ExprId conditionPhi, ExprId condition, const ILSourceLocation& loc = ILSourceLocation());
		ExprId For(ExprId initExpr, ExprId condition, ExprId updateExpr, ExprId loopExpr,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ForSSA(ExprId initExpr, ExprId conditionPhi, ExprId condition, ExprId updateExpr, ExprId loopExpr,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Switch(ExprId condition, ExprId defaultExpr, const std::vector<ExprId>& cases,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Case(
		    const std::vector<ExprId>& condition, ExprId expr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Break(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Continue(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unreachable(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Goto(uint64_t target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Label(uint64_t target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarDeclare(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarInit(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarInitSSA(
		    size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Assign(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignUnpack(
		    const std::vector<ExprId>& output, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignMemSSA(size_t size, ExprId dest, size_t destMemVersion, ExprId src, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignUnpackMemSSA(const std::vector<ExprId>& output, size_t destMemVersion, ExprId src,
		    size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarPhi(const SSAVariable& dest, const std::vector<SSAVariable>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemPhi(
		    size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StructField(size_t size, ExprId src, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArrayIndex(size_t size, ExprId src, ExprId idx, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArrayIndexSSA(size_t size, ExprId src, size_t srcMemVersion, ExprId idx,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Split(size_t size, ExprId high, ExprId low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Deref(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefField(size_t size, ExprId src, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefSSA(
		    size_t size, ExprId src, size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefFieldSSA(size_t size, ExprId src, size_t srcMemVersion, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstData(size_t size, const ConstantData& data, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddWithCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubWithBorrow(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(ExprId dest, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(
		    ExprId dest, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(ExprId dest, const std::vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t vector, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(
		    uint32_t intrinsic, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(uint32_t intrinsic, const std::vector<ExprId>& params, size_t destMemVersion,
		    size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddOperandList(const std::vector<ExprId>& operands);
		ExprId AddIndexList(const std::vector<size_t>& operands);
		ExprId AddSSAVariableList(const std::vector<SSAVariable>& vars);

		BNHighLevelILInstruction GetRawExpr(size_t i) const;
		BNHighLevelILInstruction GetRawNonASTExpr(size_t i) const;
		HighLevelILInstruction operator[](size_t i);
		HighLevelILInstruction GetInstruction(size_t i);
		HighLevelILInstruction GetExpr(size_t i, bool asFullAst = true);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<HighLevelILFunction> GetSSAForm() const;
		Ref<HighLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSAVarDefinition(const SSAVariable& var) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSAVarUses(const SSAVariable& var) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;
		bool IsSSAVarLive(const SSAVariable& var) const;
		bool IsSSAVarLiveAt(const SSAVariable& var, const size_t instr) const;
		bool IsVarLiveAt(const Variable& var, const size_t instr) const;

		std::set<size_t> GetVariableSSAVersions(const Variable& var) const;
		std::set<size_t> GetVariableDefinitions(const Variable& var) const;
		std::set<size_t> GetVariableUses(const Variable& var) const;
		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetMediumLevelILExprIndexes(size_t expr) const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void ReplaceExpr(size_t expr, size_t newExpr);
		void SetExprAttributes(size_t expr, uint32_t attributes);

		void Finalize();
		void GenerateSSAForm(const std::set<Variable>& aliases = std::set<Variable>());

		std::vector<DisassemblyTextLine> GetExprText(
		    ExprId expr, bool asFullAst = true, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetExprText(
		    const HighLevelILInstruction& instr, bool asFullAst = true, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetInstructionText(
		    size_t i, bool asFullAst = true, DisassemblySettings* settings = nullptr);

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const HighLevelILInstruction& expr);

		/*! SetExprType sets the type of a given expression.

			\warning This method is only meant for workflows or for debugging purposes, since the changes they make
			are not persistent and get lost after a database save and reload. To make persistent changes to the analysis,
			one should use other APIs to, for example, change the type of variables. The analysis will then propagate the
			type of the variable and update the type of related expressions.

		    \param expr index of the expression to set
		    \param type new type of the expression
		*/
		void SetExprType(size_t expr, const Confidence<Ref<Type>>& type);
		void SetExprType(const HighLevelILInstruction& expr, const Confidence<Ref<Type>>& type);

		void VisitAllExprs(const std::function<bool(const HighLevelILInstruction& expr)>& func);

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);

		size_t GetExprIndexForLabel(uint64_t label);
		std::set<size_t> GetUsesForLabel(uint64_t label);
	};

	class LanguageRepresentationFunction :
	    public CoreRefCountObject<BNLanguageRepresentationFunction, BNNewLanguageRepresentationFunctionReference,
	        BNFreeLanguageRepresentationFunction>
	{
	  public:
		LanguageRepresentationFunction(Architecture* arch, Function* func = nullptr);
		LanguageRepresentationFunction(BNLanguageRepresentationFunction* func);
	};

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

	/*!
		\ingroup plugin
	*/
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

	/*!
		The PluginCommand class is used for registering "commands" for Plugins, corresponding to code in those plugins
	 	to be executed.

	 	\ingroup plugin

	 	The proper way to use this class is via one of the \c "Register*" static methods.
	*/
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

		/*! Register a command for a given BinaryView.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::Register("MyPlugin\\MyAction", "Perform an action",
				   [](BinaryView* view)
				   {
					   // Perform an action on a view
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::Register("MyPlugin\\MySecondAction", "Perform an action", MyPlugin::MyCommand);
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action);

		/*! Register a command for a given BinaryView, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::Register("MyPlugin\\MyAction", "Perform an action",
					[](BinaryView* view)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::Register("MyPlugin\\MySecondAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Function that returns whether the command is allowed to be performed.
		*/
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action, const std::function<bool(BinaryView* view)>& isValid);

		/*! Register a command for a given BinaryView, when an address is selected.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForAddress("MyPlugin\\MyAddressAction", "Perform an action on an address",
				   [](BinaryView* view, uint64_t addr)
				   {
					   // Perform an action on a view and address
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForAddress("MyPlugin\\MySecondAddressAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action);

		/*! Register a command for a given BinaryView and an address, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForAddress("MyPlugin\\MyAddressAction", "Perform an action",
					[](BinaryView* view, uint64_t addr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, uint64_t addr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForAddress("MyPlugin\\MySecondAddressAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, uint64_t addr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr)>& isValid);

		/*! Register a command for a given BinaryView, when a range of address is selected.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRange("MyPlugin\\MyRangeAction", "Perform an action on a range",
				   [](BinaryView* view, uint64_t addr, uint64_t len)
				   {
					   // Perform an action on a view and address
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr, uint64_t len)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForRange("MyPlugin\\MySecondRangeAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action);

		/*! Register a command for a given BinaryView and a range, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForRange("MyPlugin\\MyRangeAction", "Perform an action",
					[](BinaryView* view, uint64_t addr, uint64_t len)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, uint64_t addr, uint64_t len)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr, uint64_t len)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForRange("MyPlugin\\MySecondRangeAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, uint64_t addr, uint64_t len){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid);

		/*! Register a command for a given BinaryView within a function.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForFunction("MyPlugin\\MyFunctionAction", "Perform an action on a function",
				   [](BinaryView* view, Function* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, Function* func)"
			void MyPlugin::MyCommand(BinaryView* view, Function* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForFunction("MyPlugin\\MySecondFunctionAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action);

		/*! Register a command for a given BinaryView and a function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForFunction("MyPlugin\\MyFunctionAction", "Perform an action",
					[](BinaryView* view, Function* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, Function* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, Function* func)"
			void MyPlugin::MyCommand(BinaryView* view, Function* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForFunction("MyPlugin\\MySecondFunctionAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, Function* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action,
		    const std::function<bool(BinaryView* view, Function* func)>& isValid);

		/*! Register a command for a given BinaryView within a LowLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MyLLILFunctionAction", "Perform an action on a llil function",
				   [](BinaryView* view, LowLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, LowLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a Low Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MyLLILFunctionAction", "Perform an action",
					[](BinaryView* view, LowLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, LowLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, LowLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, LowLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given LowLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForLowLevelILInstruction("MyPlugin\\MyLLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, LowLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a LowLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, LowLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a LowLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MyLLILInstructionAction", "Perform an action",
					[](BinaryView* view, LowLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, LowLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, LowLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MySecondLLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, LowLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid);

		/*! Register a command for a given BinaryView within a MediumLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MyMLILFunctionAction", "Perform an action on a mlil function",
				   [](BinaryView* view, MediumLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, MediumLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a Medium Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MyMLILFunctionAction", "Perform an action",
					[](BinaryView* view, MediumLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, MediumLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, MediumLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, MediumLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given MediumLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForMediumLevelILInstruction("MyPlugin\\MyMLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, MediumLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a MediumLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, MediumLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a MediumLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MyMLILInstructionAction", "Perform an action",
					[](BinaryView* view, MediumLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, MediumLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, MediumLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MySecondMLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, MediumLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid);

		/*! Register a command for a given BinaryView within a HighLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MyHLILFunctionAction", "Perform an action on a hlil function",
				   [](BinaryView* view, HighLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, HighLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a High Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MyHLILFunctionAction", "Perform an action",
					[](BinaryView* view, HighLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, HighLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, HighLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, HighLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, HighLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given HighLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForHighLevelILInstruction("MyPlugin\\MyHLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, HighLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a HighLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, HighLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a HighLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MyHLILInstructionAction", "Perform an action",
					[](BinaryView* view, HighLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, HighLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, HighLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MySecondHLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, HighLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const HighLevelILInstruction& instr)>& isValid);

		/*! Get the list of registered PluginCommands

			\return The list of registered PluginCommands
		*/
		static std::vector<PluginCommand> GetList();

		/*! Get the list of valid PluginCommands for a given context

			\param ctxt The context to be used for the checks
			\return The list of valid plugin commands.
		*/
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		/*! Get the name for the registered PluginCommand

			\return The name for the registered PluginCommand
		*/
		std::string GetName() const { return m_command.name; }

		/*! Get the description for the registered PluginCommand

			\return The description for the registered PluginCommand
		*/
		std::string GetDescription() const { return m_command.description; }

		/*! Get the type of the registered PluginCommand

			\return The type of the registered PluginCommand
		*/
		BNPluginCommandType GetType() const { return m_command.type; }
		const BNPluginCommand* GetObject() const { return &m_command; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};

	/*!
		\ingroup callingconvention
	*/
	class CallingConvention :
	    public CoreRefCountObject<BNCallingConvention, BNNewCallingConventionReference, BNFreeCallingConvention>
	{
	  protected:
		CallingConvention(BNCallingConvention* cc);
		CallingConvention(Architecture* arch, const std::string& name);

		static void FreeCallback(void* ctxt);

		static uint32_t* GetCallerSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetCalleeSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetIntegerArgumentRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetFloatArgumentRegistersCallback(void* ctxt, size_t* count);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);

		static bool AreArgumentRegistersSharedIndexCallback(void* ctxt);
		static bool AreArgumentRegistersUsedForVarArgsCallback(void* ctxt);
		static bool IsStackReservedForArgumentRegistersCallback(void* ctxt);
		static bool IsStackAdjustedOnReturnCallback(void* ctxt);
		static bool IsEligibleForHeuristicsCallback(void* ctxt);

		static uint32_t GetIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetHighIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetFloatReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetGlobalPointerRegisterCallback(void* ctxt);

		static uint32_t* GetImplicitlyDefinedRegistersCallback(void* ctxt, size_t* count);
		static void GetIncomingRegisterValueCallback(
		    void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		static void GetIncomingFlagValueCallback(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);

		static void GetIncomingVariableForParameterVariableCallback(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);
		static void GetParameterVariableForIncomingVariableCallback(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);

	  public:
		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		virtual std::vector<uint32_t> GetCallerSavedRegisters();
		virtual std::vector<uint32_t> GetCalleeSavedRegisters();

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters();
		virtual std::vector<uint32_t> GetFloatArgumentRegisters();
		virtual bool AreArgumentRegistersSharedIndex();
		virtual bool AreArgumentRegistersUsedForVarArgs();
		virtual bool IsStackReservedForArgumentRegisters();
		virtual bool IsStackAdjustedOnReturn();
		virtual bool IsEligibleForHeuristics();

		virtual uint32_t GetIntegerReturnValueRegister() = 0;
		virtual uint32_t GetHighIntegerReturnValueRegister();
		virtual uint32_t GetFloatReturnValueRegister();
		virtual uint32_t GetGlobalPointerRegister();

		virtual std::vector<uint32_t> GetImplicitlyDefinedRegisters();
		virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func);
		virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function* func);

		virtual Variable GetIncomingVariableForParameterVariable(const Variable& var, Function* func);
		virtual Variable GetParameterVariableForIncomingVariable(const Variable& var, Function* func);
	};

	/*!
		\ingroup callingconvention
	*/
	class CoreCallingConvention : public CallingConvention
	{
	  public:
		CoreCallingConvention(BNCallingConvention* cc);

		virtual std::vector<uint32_t> GetCallerSavedRegisters() override;
		virtual std::vector<uint32_t> GetCalleeSavedRegisters() override;

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override;
		virtual std::vector<uint32_t> GetFloatArgumentRegisters() override;
		virtual bool AreArgumentRegistersSharedIndex() override;
		virtual bool AreArgumentRegistersUsedForVarArgs() override;
		virtual bool IsStackReservedForArgumentRegisters() override;
		virtual bool IsStackAdjustedOnReturn() override;
		virtual bool IsEligibleForHeuristics() override;

		virtual uint32_t GetIntegerReturnValueRegister() override;
		virtual uint32_t GetHighIntegerReturnValueRegister() override;
		virtual uint32_t GetFloatReturnValueRegister() override;
		virtual uint32_t GetGlobalPointerRegister() override;

		virtual std::vector<uint32_t> GetImplicitlyDefinedRegisters() override;
		virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override;
		virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function* func) override;

		virtual Variable GetIncomingVariableForParameterVariable(const Variable& var, Function* func) override;
		virtual Variable GetParameterVariableForIncomingVariable(const Variable& var, Function* func) override;
	};

	/*!
	    Platform base class. This should be subclassed when creating a new platform

	 	\ingroup Platform
	*/
	class Platform : public CoreRefCountObject<BNPlatform, BNNewPlatformReference, BNFreePlatform>
	{
	  protected:
		Platform(Architecture* arch, const std::string& name);
		Platform(Architecture* arch, const std::string& name, const std::string& typeFile,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>());

		static void InitCallback(void *ctxt, BNPlatform*);
		static void InitViewCallback(void* ctxt, BNBinaryView* view);
		static uint32_t* GetGlobalRegistersCallback(void* ctxt, size_t* count);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs, size_t count);
		static BNType* GetGlobalRegisterTypeCallback(void* ctxt, uint32_t reg);
		static void AdjustTypeParserInputCallback(
			void* ctxt,
			BNTypeParser* parser,
			const char* const* argumentsIn,
			size_t argumentsLenIn,
			const char* const* sourceFileNamesIn,
			const char* const* sourceFileValuesIn,
			size_t sourceFilesLenIn,
			char*** argumentsOut,
			size_t* argumentsLenOut,
			char*** sourceFileNamesOut,
			char*** sourceFileValuesOut,
			size_t* sourceFilesLenOut
		);
		static void FreeTypeParserInputCallback(
			void* ctxt,
			char** arguments,
			size_t argumentsLen,
			char** sourceFileNames,
			char** sourceFileValues,
			size_t sourceFilesLen
		);
		static bool GetFallbackEnabledCallback(void* ctxt);

	  public:
		Platform(BNPlatform* platform);

		/*! Get the Architecture for this platform

			\return The platform architecture
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Get the name of this platform

			\return The platform namee
		*/
		std::string GetName() const;

		/*! Register a Platform

			\param os OS for the platform to register
			\param platform Platform to register
		*/
		static void Register(const std::string& os, Platform* platform);

		/*! Get a platform by name

			\param name Name of the platform to retrieve
			\return The Platform, if it exists
		*/
		static Ref<Platform> GetByName(const std::string& name);

		/*! Get the list of registered platforms

			\return The list of registered platforms
		*/
		static std::vector<Ref<Platform>> GetList();

		/*! Get the list of registered platforms by Architecture

			\param arch Architecture to get the registered platforms for
			\return The list of registered platforms by Architecture
		*/
		static std::vector<Ref<Platform>> GetList(Architecture* arch);

		/*! Get the list of registered platforms by os

			\param os OS to get the registered platforms for
			\return The list of registered platforms by Architecture
		*/
		static std::vector<Ref<Platform>> GetList(const std::string& os);

		/*! Get the list of registered platforms by OS and Architecture

			\param os OS to get the registered platforms for
			\param arch Architecture to get the registered platforms for
			\return The list of registered platforms
		*/
		static std::vector<Ref<Platform>> GetList(const std::string& os, Architecture* arch);

		/*! Get the list of operating systems

			\return The list of operating systems
		*/
		static std::vector<std::string> GetOSList();

		/*! Get the default calling convention for this platform

			\return The default calling convention
		*/
		Ref<CallingConvention> GetDefaultCallingConvention() const;

		/*! Get the cdecl CallingConvention

			\return The cdecl CallingConvention
		*/
		Ref<CallingConvention> GetCdeclCallingConvention() const;

		/*! Get the stdcall CallingConvention

			\return The stdcall CallingConvention
		*/
		Ref<CallingConvention> GetStdcallCallingConvention() const;

		/*! Get the fastcall CallingConvention

			\return The fastcall Calling Convention
		*/
		Ref<CallingConvention> GetFastcallCallingConvention() const;

		/*! Get the list of registered calling conventions

			\return The list of registered calling conventions
		*/
		std::vector<Ref<CallingConvention>> GetCallingConventions() const;

		/*! Get the syscall calling convention

			\return The syscall CallingConvention
		*/
		Ref<CallingConvention> GetSystemCallConvention() const;

		/*! Register a Calling Convention

			\param cc Calling Convention to register
		*/
		void RegisterCallingConvention(CallingConvention* cc);

		/*! Set the default calling convention

			\param cc The new default CallingConvention
		*/
		void RegisterDefaultCallingConvention(CallingConvention* cc);

		/*! Set the cdecl calling convention

			\param cc The new cdecl CallingConvention
		*/
		void RegisterCdeclCallingConvention(CallingConvention* cc);

		/*! Set the stdcall calling convention

			\param cc The new stdcall CallingConvention
		*/
		void RegisterStdcallCallingConvention(CallingConvention* cc);

		/*! Set the fastcall calling convention

			\param cc The new fastcall calling convention
		*/
		void RegisterFastcallCallingConvention(CallingConvention* cc);

		/*! Set the syscall calling convention

			\param cc The new syscall calling convention
		*/
		void SetSystemCallConvention(CallingConvention* cc);

		/*! Callback that will be called when the platform of a binaryview
		 * is set. Allows for the Platform to to do platform-specific
		 * processing of views just after finalization.
		 *
		 * \param view BinaryView that was just set to this Platform
		 */
		virtual void BinaryViewInit(BinaryView* view);

		/*! Get the global register list for this Platform
		 *
		 * Allows the Platform to override the global register list
		 * used by analysis.
		 */
		virtual std::vector<uint32_t> GetGlobalRegisters();

		/*! Get the type of a global register
		 *
		 * Called by analysis when the incoming register value of a
		 * global register is observed.
		 *
		 * \param reg The register being queried for type information.
		 */
		virtual Ref<Type> GetGlobalRegisterType(uint32_t reg);

		/*! Modify the input passed to the Type Parser with Platform-specific features.

			\param[in] parser Type Parser instance
			\param[in,out] arguments Arguments to the type parser
			\param[in,out] sourceFiles Source file names and contents
		 */
		virtual void AdjustTypeParserInput(
			Ref<class TypeParser> parser,
			std::vector<std::string>& arguments,
			std::vector<std::pair<std::string, std::string>>& sourceFiles
		);

		/*! Provide an option for platforms to decide whether to use
		 * the fallback type library.
		 *
		 * Allows the Platform to override it to false.
		 */
		virtual bool GetFallbackEnabled();

		Ref<Platform> GetRelatedPlatform(Architecture* arch);
		void AddRelatedPlatform(Architecture* arch, Platform* platform);
		/*! Get the list of related platforms for this platform

		 	\return A vector of Ref<Platform>s
		 */
		std::vector<Ref<Platform>> GetRelatedPlatforms();
		Ref<Platform> GetAssociatedPlatformByAddress(uint64_t& addr);

		/*! Get the list of platform-specific types

			\return A map of Platform Type QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetTypes();

		/*! Get the list of platform-specific variable definitions

			\return A map of Platform Variable QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetVariables();

		/*! Get the list of platform-specific function definitions

			\return A map of Platform Function QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetFunctions();

		/*! System calls for this platform

			\return A list of system calls for this platform
		*/
		std::map<uint32_t, QualifiedNameAndType> GetSystemCalls();

		std::vector<Ref<TypeLibrary>> GetTypeLibraries();

		std::vector<Ref<TypeLibrary>> GetTypeLibrariesByName(const std::string& name);

		/*! Type Container for all registered types in the Platform.
			\return Platform types Type Container
		 */
		TypeContainer GetTypeContainer();

		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetVariableByName(const QualifiedName& name);
		Ref<Type> GetFunctionByName(const QualifiedName& name, bool exactMatch = false);
		std::string GetSystemCallName(uint32_t n);
		Ref<Type> GetSystemCallType(uint32_t n);

		std::string GenerateAutoPlatformTypeId(const QualifiedName& name);
		Ref<NamedTypeReference> GenerateAutoPlatformTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
		std::string GetAutoPlatformTypeIdSource();

		/*! Parses the source string and any needed headers searching for them in
			the optional list of directories provided in ``includeDirs``.

		 	\note This API does not allow the source to rely on existing types that only exist in a specific view. Use BinaryView->ParseTypeString instead.

			\param source Source string to be parsed
			\param fileName Source Filename
			\param types map reference that Types will be copied into
			\param variables map reference that variables will be copied into
			\param functions map reference that functions will be copied into
			\param errors string reference that any errors will be copied into
			\param includeDirs optional list of directories to include for header searches
			\param autoTypeSource optional source of types if used for automatically generated types
			\return true on success, false otherwise
		*/
		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
		    std::map<QualifiedName, Ref<Type>>& types, std::map<QualifiedName, Ref<Type>>& variables,
		    std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");

		/*! Parses the source string and any needed headers searching for them in
			the optional list of directories provided in ``includeDirs``.

			\note This API does not allow the source to rely on existing types that only exist in a specific view. Use BinaryView->ParseTypeString instead.

			\param fileName Source Filename
			\param types map reference that Types will be copied into
			\param variables map reference that variables will be copied into
			\param functions map reference that functions will be copied into
			\param errors string reference that any errors will be copied into
			\param includeDirs optional list of directories to include for header searches
			\param autoTypeSource optional source of types if used for automatically generated types
			\return true on success, false otherwise
			\return
		*/
		bool ParseTypesFromSourceFile(const std::string& fileName, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");
	};


	class CorePlatform : public Platform
	{
	public:
		CorePlatform(BNPlatform* plat);

		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual Ref<Type> GetGlobalRegisterType(uint32_t reg) override;
		virtual void AdjustTypeParserInput(
			Ref<class TypeParser> parser,
			std::vector<std::string>& arguments,
			std::vector<std::pair<std::string, std::string>>& sourceFiles
		) override;
	};

	/*!
		\ingroup typeparser
	*/
	class TypeParser: public StaticCoreRefCountObject<BNTypeParser>
	{
		std::string m_nameForRegister;
	  protected:
		explicit TypeParser(const std::string& name);
		TypeParser(BNTypeParser* parser);

		static bool GetOptionTextCallback(void* ctxt, BNTypeParserOption option, const char* value, char** result);
		static bool PreprocessSourceCallback(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			char** output, BNTypeParserError** errors, size_t* errorCount
		);
		static bool ParseTypesFromSourceCallback(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			const char* autoTypeSource, BNTypeParserResult* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		static bool ParseTypeStringCallback(void* ctxt,
			const char* source, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			BNQualifiedNameAndType* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		static void FreeStringCallback(void* ctxt, char* result);
		static void FreeResultCallback(void* ctxt, BNTypeParserResult* result);
		static void FreeErrorListCallback(void* ctxt, BNTypeParserError* errors, size_t errorCount);

	  public:
		static void Register(TypeParser* parser);
		static std::vector<Ref<TypeParser>> GetList();
		static Ref<TypeParser> GetByName(const std::string& name);
		static Ref<TypeParser> GetDefault();

		/*!
		    Parse a space-separated string of options into a list
		    \param optionsText Space-separated options text
		    \return List of options
		*/
		static std::vector<std::string> ParseOptionsText(const std::string& optionsText);

		/*!
		    Format a list of parser errors into a big string
		    \param errors List of errors
		    \return String of formatted errors
		*/
		static std::string FormatParseErrors(const std::vector<TypeParserError>& errors);

		/*!
		    Get the Type Parser's registered name
		    \return Parser name
		 */
		std::string GetName() const;

		/**
		    Get the string representation of an option for passing to ParseTypes*
		    \param option Option type
		    \param value Option value
		    \param result String representing the option
		    \return True if the parser supports the option
		*/
		virtual bool GetOptionText(BNTypeParserOption option, std::string value, std::string& result) const;

		/*!
		    Preprocess a block of source, returning the source that would be parsed
		    \param source Source code to process
		    \param fileName Name of the file containing the source (does not need to exist on disk)
		    \param platform Platform to assume the source is relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param output Reference to a string into which the preprocessed source will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if preprocessing was successful
		*/
		virtual bool PreprocessSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			std::string& output,
			std::vector<TypeParserError>& errors
		) = 0;

		/*!
		    Parse an entire block of source into types, variables, and functions
		    \param source Source code to parse
		    \param fileName Name of the file containing the source (optional: exists on disk)
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param autoTypeSource Optional source of types if used for automatically generated types
		    \param result Reference to structure into which the results will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		virtual bool ParseTypesFromSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		) = 0;

		/*!
		    Parse an entire source file into types, variables, and functions
		    \param fileName Name of the file on disk containing the source
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param autoTypeSource Optional source of types if used for automatically generated types
		    \param result Reference to structure into which the results will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		bool ParseTypesFromSourceFile(
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		);

		/*!
		    Parse a single type and name from a string containing their definition.
		    \param source Source code to parse
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param result Reference into which the resulting type and name will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		virtual bool ParseTypeString(
			const std::string& source,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		) = 0;
	};

	/*!
		\ingroup typeparser
	*/
	class CoreTypeParser: public TypeParser
	{
	  public:
		CoreTypeParser(BNTypeParser* parser);
		virtual ~CoreTypeParser() {}

		virtual bool GetOptionText(BNTypeParserOption option, std::string value, std::string& result) const override;

		virtual bool PreprocessSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			std::string& output,
			std::vector<TypeParserError>& errors
		) override;

		virtual bool ParseTypesFromSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		) override;

		virtual bool ParseTypeString(
			const std::string& source,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		) override;
	};

	/*!
		\ingroup typeprinter
	*/
	class TypePrinter: public StaticCoreRefCountObject<BNTypePrinter>
	{
		std::string m_nameForRegister;
	  protected:
		explicit TypePrinter(const std::string& name);
		TypePrinter(BNTypePrinter* printer);

		static bool GetTypeTokensCallback(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, uint8_t baseConfidence, BNTokenEscapingType escaping,
			BNInstructionTextToken** result, size_t* resultCount);
		static bool GetTypeTokensBeforeNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		static bool GetTypeTokensAfterNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		static bool GetTypeStringCallback(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, BNTokenEscapingType escaping, char** result);
		static bool GetTypeStringBeforeNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		static bool GetTypeStringAfterNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		static bool GetTypeLinesCallback(void* ctxt, BNType* type, BNTypeContainer* types,
			BNQualifiedName* name, int paddingCols, bool collapsed,
			BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount);
		static bool PrintAllTypesCallback(void* ctxt, BNQualifiedName* names, BNType** types, size_t typeCount,
			BNBinaryView* data, int paddingCols, BNTokenEscapingType escaping, char** result);
		static void FreeTokensCallback(void* ctxt, BNInstructionTextToken* tokens, size_t count);
		static void FreeStringCallback(void* ctxt, char* string);
		static void FreeLinesCallback(void* ctxt, BNTypeDefinitionLine* lines, size_t count);

	  public:
		static void Register(TypePrinter* printer);
		static std::vector<Ref<TypePrinter>> GetList();
		static Ref<TypePrinter> GetByName(const std::string& name);
		static Ref<TypePrinter> GetDefault();

		/*!
		    Generate a single-line text representation of a type
		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param name Name of the type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		*/
		virtual std::vector<InstructionTextToken> GetTypeTokens(
			Ref<Type> type,
			Ref<Platform> platform,
			const QualifiedName& name,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the tokens that should
		    be printed before the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param parentType Type of the parent of this type, or nullptr
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		*/
		virtual std::vector<InstructionTextToken> GetTypeTokensBeforeName(
			Ref<Type> type,
			Ref<Platform> platform,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			Ref<Type> parentType = nullptr,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;
		/*!
		    In a single-line text representation of a type, generate the tokens that should
		    be printed after the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param parentType Type of the parent of this type, or nullptr
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		*/
		virtual std::vector<InstructionTextToken> GetTypeTokensAfterName(
			Ref<Type> type,
			Ref<Platform> platform,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			Ref<Type> parentType = nullptr,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;

		/*!
		    Generate a single-line text representation of a type
		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param name Name of the type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		*/
		virtual std::string GetTypeString(
			Ref<Type> type,
			Ref<Platform> platform,
			const QualifiedName& name,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the string that should
		    be printed before the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		*/
		virtual std::string GetTypeStringBeforeName(
			Ref<Type> type,
			Ref<Platform> platform,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the string that should
		    be printed after the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		*/
		virtual std::string GetTypeStringAfterName(
			Ref<Type> type,
			Ref<Platform> platform,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);

		/*!
		    Generate a multi-line representation of a type
		    \param type Type to print
		    \param types Type Container in which the type is defined
		    \param name Name of the type
		    \param paddingCols Maximum number of bytes represented by each padding line
		    \param collapsed Whether to collapse structure/enum blocks
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of type definition lines
		*/
		virtual std::vector<TypeDefinitionLine> GetTypeLines(
			Ref<Type> type,
			const TypeContainer& types,
			const QualifiedName& name,
			int paddingCols = 64,
			bool collapsed = false,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;

		/*!
		    Print all types to a single big string, including headers, sections, etc
		    \param types All types to print
		    \param data Binary View in which all the types are defined
		    \param paddingCols Maximum number of bytes represented by each padding line
		    \param escaping Style of escaping literals which may not be parsable
		    \return All the types in a string
		*/
		virtual std::string PrintAllTypes(
			const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
			Ref<BinaryView> data,
			int paddingCols = 64,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);

		/*!
		    Default implementation of PrintAllTypes
		    Print all types to a single big string, including headers, sections, etc
		    \param types All types to print
		    \param data Binary View in which all the types are defined
		    \param paddingCols Maximum number of bytes represented by each padding line
		    \param escaping Style of escaping literals which may not be parsable
		    \return All the types in a string
		*/
		std::string DefaultPrintAllTypes(
			const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
			Ref<BinaryView> data,
			int paddingCols = 64,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
	};

	/*!
		\ingroup typeprinter
	*/
	class CoreTypePrinter: public TypePrinter
	{
	  public:
		CoreTypePrinter(BNTypePrinter* printer);
		virtual ~CoreTypePrinter() {}

		virtual std::vector<InstructionTextToken> GetTypeTokens(Ref<Type> type,
			Ref<Platform> platform, const QualifiedName& name,
			uint8_t baseConfidence, BNTokenEscapingType escaping) override;
		virtual std::vector<InstructionTextToken> GetTypeTokensBeforeName(Ref<Type> type,
			Ref<Platform> platform, uint8_t baseConfidence,
			Ref<Type> parentType, BNTokenEscapingType escaping) override;
		virtual std::vector<InstructionTextToken> GetTypeTokensAfterName(Ref<Type> type,
			Ref<Platform> platform, uint8_t baseConfidence,
			Ref<Type> parentType, BNTokenEscapingType escaping) override;
		virtual std::string GetTypeString(Ref<Type> type, Ref<Platform> platform,
			const QualifiedName& name, BNTokenEscapingType escaping) override;
		virtual std::string GetTypeStringBeforeName(Ref<Type> type, Ref<Platform> platform,
			BNTokenEscapingType escaping) override;
		virtual std::string GetTypeStringAfterName(Ref<Type> type, Ref<Platform> platform,
			BNTokenEscapingType escaping) override;
		virtual std::vector<TypeDefinitionLine> GetTypeLines(Ref<Type> type,
			const TypeContainer& types, const QualifiedName& name, int paddingCols,
			bool collapsed, BNTokenEscapingType escaping) override;
		virtual std::string PrintAllTypes(const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
			Ref<BinaryView> data, int paddingCols, BNTokenEscapingType escaping) override;
	};

	// DownloadProvider
	class DownloadProvider;

	/*!
		\ingroup downloadprovider
	*/
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

	/*!
		\ingroup downloadprovider
	*/
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

	// Scripting Provider
	/*!
		\ingroup scriptingprovider
	*/
	class ScriptingOutputListener
	{
		BNScriptingOutputListener m_callbacks;

		static void OutputCallback(void* ctxt, const char* text);
		static void WarningCallback(void* ctxt, const char* text);
		static void ErrorCallback(void* ctxt, const char* text);
		static void InputReadyStateChangedCallback(void* ctxt, BNScriptingProviderInputReadyState state);

	  public:
		ScriptingOutputListener();
		BNScriptingOutputListener& GetCallbacks() { return m_callbacks; }

		virtual void NotifyOutput(const std::string& text);
		virtual void NotifyWarning(const std::string& text);
		virtual void NotifyError(const std::string& text);
		virtual void NotifyInputReadyStateChanged(BNScriptingProviderInputReadyState state);
	};

	class ScriptingProvider;

	/*!
		\ingroup scriptingprovider
	*/
	class ScriptingInstance :
	    public CoreRefCountObject<BNScriptingInstance, BNNewScriptingInstanceReference, BNFreeScriptingInstance>
	{
	  protected:
		ScriptingInstance(ScriptingProvider* provider);
		ScriptingInstance(BNScriptingInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static BNScriptingProviderExecuteResult ExecuteScriptInputCallback(void* ctxt, const char* input);
		static BNScriptingProviderExecuteResult ExecuteScriptFromFilenameCallback(void *ctxt, const char* filename);
		static void CancelScriptInputCallback(void* ctxt);
		static void ReleaseBinaryViewCallback(void* ctxt, BNBinaryView* view);
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
		virtual BNScriptingProviderExecuteResult ExecuteScriptInputFromFilename(const std::string& filename) = 0;
		virtual void CancelScriptInput();
		virtual void ReleaseBinaryView(BinaryView* view);
		virtual void SetCurrentBinaryView(BinaryView* view);
		virtual void SetCurrentFunction(Function* func);
		virtual void SetCurrentBasicBlock(BasicBlock* block);
		virtual void SetCurrentAddress(uint64_t addr);
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end);
		virtual std::string CompleteInput(const std::string& text, uint64_t state);
		virtual void Stop();

		void Output(const std::string& text);
		void Warning(const std::string& text);
		void Error(const std::string& text);
		void InputReadyStateChanged(BNScriptingProviderInputReadyState state);
		BNScriptingProviderInputReadyState GetInputReadyState();

		void RegisterOutputListener(ScriptingOutputListener* listener);
		void UnregisterOutputListener(ScriptingOutputListener* listener);

		std::string GetDelimiters();
		void SetDelimiters(const std::string& delimiters);
	};

	/*!
		\ingroup scriptingprovider
	*/
	class CoreScriptingInstance : public ScriptingInstance
	{
	  public:
		CoreScriptingInstance(BNScriptingInstance* instance);
		virtual ~CoreScriptingInstance() {};

		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) override;
		virtual BNScriptingProviderExecuteResult ExecuteScriptInputFromFilename(const std::string& filename) override;
		virtual void CancelScriptInput() override;
		virtual void ReleaseBinaryView(BinaryView* view) override;
		virtual void SetCurrentBinaryView(BinaryView* view) override;
		virtual void SetCurrentFunction(Function* func) override;
		virtual void SetCurrentBasicBlock(BasicBlock* block) override;
		virtual void SetCurrentAddress(uint64_t addr) override;
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end) override;
		virtual std::string CompleteInput(const std::string& text, uint64_t state) override;
		virtual void Stop() override;
	};

	/*!
		\ingroup scriptingprovider
	*/
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

	/*!
		\ingroup plugin
	*/
	class MainThreadAction :
	    public CoreRefCountObject<BNMainThreadAction, BNNewMainThreadActionReference, BNFreeMainThreadAction>
	{
	  public:
		MainThreadAction(BNMainThreadAction* action);
		void Execute();
		bool IsDone() const;
		void Wait();
	};

	/*!
		\ingroup plugin
	*/
	class MainThreadActionHandler
	{
	  public:
		virtual void AddMainThreadAction(MainThreadAction* action) = 0;
	};

	/*!
		\ingroup plugin
	*/
	class BackgroundTask :
	    public CoreRefCountObject<BNBackgroundTask, BNNewBackgroundTaskReference, BNFreeBackgroundTask>
	{
	  public:
		BackgroundTask(BNBackgroundTask *task);

		/*!
			Provides a mechanism for reporting progress of
			an optionally cancelable task to the user via the status bar in the UI.
			If canCancel is is `True`, then the task can be cancelled either
			programmatically or by the user via the UI.

			\note This API does not provide a means to execute a task. The caller is responsible to execute (and possibly cancel) the task.

			\param initialText Text description of the progress of the background task (displayed in status bar of the UI)
			\param canCancel Whether the task can be cancelled
		*/
		BackgroundTask(const std::string &initialText, bool canCancel);

		bool CanCancel() const;
		bool IsCancelled() const;
		bool IsFinished() const;
		std::string GetProgressText() const;
		uint64_t GetRuntimeSeconds() const;

		void Cancel();
		void Finish();
		void SetProgressText(const std::string& text);

		static std::vector<Ref<BackgroundTask>> GetRunningTasks();
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

	typedef BNPluginOrigin PluginOrigin;
	typedef BNPluginStatus PluginStatus;
	typedef BNPluginType PluginType;

	/*!
		\ingroup pluginmanager
	*/
	class RepoPlugin : public CoreRefCountObject<BNRepoPlugin, BNNewPluginReference, BNFreePlugin>
	{
	  public:
		RepoPlugin(BNRepoPlugin* plugin);
		PluginStatus GetPluginStatus() const;
		std::vector<std::string> GetApis() const;
		std::vector<std::string> GetInstallPlatforms() const;
		std::string GetPath() const;
		std::string GetSubdir() const;
		std::string GetDependencies() const;
		std::string GetPluginDirectory() const;
		std::string GetAuthor() const;
		std::string GetDescription() const;
		std::string GetLicenseText() const;
		std::string GetLongdescription() const;
		std::string GetName() const;
		std::vector<PluginType> GetPluginTypes() const;
		std::string GetPackageUrl() const;
		std::string GetProjectUrl() const;
		std::string GetAuthorUrl() const;
		std::string GetVersion() const;
		std::string GetCommit() const;
		std::string GetRepository() const;
		std::string GetProjectData();
		BNVersionInfo GetMinimumVersionInfo() const;
		BNVersionInfo GetMaximumVersionInfo() const;
		uint64_t GetLastUpdate();
		bool IsBeingDeleted() const;
		bool IsBeingUpdated() const;
		bool IsInstalled() const;
		bool IsEnabled() const;
		bool IsRunning() const;
		bool IsUpdatePending() const;
		bool IsDisablePending() const;
		bool IsDeletePending() const;
		bool IsUpdateAvailable() const;
		bool AreDependenciesBeingInstalled() const;

		bool Uninstall();
		bool Install();
		bool InstallDependencies();
		// `force` ignores optional checks for platform/api compliance
		bool Enable(bool force);
		bool Disable();
		bool Update();
	};

	/*!
		\ingroup pluginmanager
	*/
	class Repository : public CoreRefCountObject<BNRepository, BNNewRepositoryReference, BNFreeRepository>
	{
	  public:
		Repository(BNRepository* repository);
		std::string GetUrl() const;
		std::string GetRepoPath() const;
		std::string GetLocalReference() const;
		std::string GetRemoteReference() const;
		std::vector<Ref<RepoPlugin>> GetPlugins() const;
		std::string GetPluginDirectory() const;
		Ref<RepoPlugin> GetPluginByPath(const std::string& pluginPath);
		std::string GetFullPath() const;
	};

	/*!
		\ingroup pluginmanager
	*/
	class RepositoryManager :
	    public CoreRefCountObject<BNRepositoryManager, BNNewRepositoryManagerReference, BNFreeRepositoryManager>
	{
	  public:
		RepositoryManager(const std::string& enabledPluginsPath);
		RepositoryManager(BNRepositoryManager* repoManager);
		RepositoryManager();
		bool CheckForUpdates();
		std::vector<Ref<Repository>> GetRepositories();
		Ref<Repository> GetRepositoryByPath(const std::string& repoName);
		bool AddRepository(const std::string& url,  // URL to raw plugins.json file
		    const std::string& repoPath);           // Relative path within the repositories directory
		Ref<Repository> GetDefaultRepository();
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

	/*!
		\ingroup debuginfo
	*/
	struct DebugFunctionInfo
	{
		std::string shortName;
		std::string fullName;
		std::string rawName;
		uint64_t address;
		Ref<Type> type;
		Ref<Platform> platform;
		std::vector<std::string> components;
		std::vector<VariableNameAndType> localVariables;

		DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
		    Ref<Type> type, Ref<Platform> platform, const std::vector<std::string>& components,
			const std::vector<VariableNameAndType>& localVariables) :
		    shortName(shortName), fullName(fullName), rawName(rawName),
		    address(address), platform(platform), components(components),
			localVariables(localVariables)
		{}
	};

	/*!
		\ingroup debuginfo
	*/
	class DebugInfo : public CoreRefCountObject<BNDebugInfo, BNNewDebugInfoReference, BNFreeDebugInfoReference>
	{
	  public:
		DebugInfo(BNDebugInfo* debugInfo);

		std::vector<std::string> GetParsers() const;

		/*! Type Container for all types in the DebugInfo that resulted from the parse of
			the given parser.
			\param parserName Name of parser
			\return Type Container for types from that parser
		 */
		TypeContainer GetTypeContainer(const std::string& parserName);

		std::vector<NameAndType> GetTypes(const std::string& parserName = "") const;
		std::vector<DebugFunctionInfo> GetFunctions(const std::string& parserName = "") const;
		std::vector<DataVariableAndName> GetDataVariables(const std::string& parserName = "") const;

		Ref<Type> GetTypeByName(const std::string& parserName, const std::string& name) const;
		std::optional<std::tuple<uint64_t, Ref<Type>>> GetDataVariableByName(
			const std::string& parserName, const std::string& name) const;
		std::optional<std::tuple<std::string, Ref<Type>>> GetDataVariableByAddress(
			const std::string& parserName, const uint64_t address) const;

		std::vector<std::tuple<std::string, Ref<Type>>> GetTypesByName(const std::string& name) const;
		std::vector<std::tuple<std::string, uint64_t, Ref<Type>>> GetDataVariablesByName(const std::string& name) const;
		std::vector<std::tuple<std::string, std::string, Ref<Type>>> GetDataVariablesByAddress(
			const uint64_t address) const;

		bool RemoveParserInfo(const std::string& parserName);
		bool RemoveParserTypes(const std::string& parserName);
		bool RemoveParserFunctions(const std::string& parserName);
		bool RemoveParserDataVariables(const std::string& parserName);

		bool RemoveTypeByName(const std::string& parserName, const std::string& name);
		bool RemoveFunctionByIndex(const std::string& parserName, const size_t index);
		bool RemoveDataVariableByAddress(const std::string& parserName, const uint64_t address);

		bool AddType(const std::string& name, Ref<Type> type, const std::vector<std::string>& components = {});
		bool AddFunction(const DebugFunctionInfo& function);
		bool AddDataVariable(uint64_t address, Ref<Type> type, const std::string& name = "", const std::vector<std::string>& components = {});
	};

	/*!
		\ingroup debuginfo
	*/
	class DebugInfoParser :
	    public CoreRefCountObject<BNDebugInfoParser, BNNewDebugInfoParserReference, BNFreeDebugInfoParserReference>
	{
	  public:
		DebugInfoParser(BNDebugInfoParser* parser);

		static Ref<DebugInfoParser> GetByName(const std::string& name);
		static std::vector<Ref<DebugInfoParser>> GetList();
		static std::vector<Ref<DebugInfoParser>> GetListForView(const Ref<BinaryView> data);

		std::string GetName() const;
		Ref<DebugInfo> Parse(Ref<BinaryView> view, Ref<BinaryView> debugView, Ref<DebugInfo> existingDebugInfo = nullptr, std::function<bool(size_t, size_t)> progress = {}) const;

		bool IsValidForView(const Ref<BinaryView> view) const;
	};

	/*!
		\ingroup debuginfo
	*/
	class CustomDebugInfoParser : public DebugInfoParser
	{
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static bool ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view, BNBinaryView* debugFile, bool (*progress)(void*, size_t, size_t), void* progressCtxt);
		BNDebugInfoParser* Register(const std::string& name);

	  public:
		CustomDebugInfoParser(const std::string& name);
		virtual ~CustomDebugInfoParser() {}

		virtual bool IsValid(Ref<BinaryView>) = 0;
		virtual bool ParseInfo(
			Ref<DebugInfo>, Ref<BinaryView>, Ref<BinaryView>, std::function<bool(size_t, size_t)>) = 0;
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
