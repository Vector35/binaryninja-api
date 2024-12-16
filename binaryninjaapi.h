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
	#define FMT_UNICODE 0
#endif
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <exception>
#include <functional>
#include <set>
#include <mutex>
#include <atomic>
#include <memory>
#include <cstdint>
#include <typeinfo>
#include <type_traits>
#include <variant>
#include <optional>
#include <memory>
#include <any>
#include "binaryninjacore.h"
#include "exceptions.h"
#include "json/json.h"
#include "vendor/nlohmann/json.hpp"
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/core.h>

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
		\ingroup refcount
	*/
	class RefCountObject
	{
	  public:
		std::atomic<int> m_refs;
		RefCountObject() : m_refs(0) {}
		virtual ~RefCountObject() {}

		RefCountObject* GetObject() { return this; }
		static RefCountObject* GetObject(RefCountObject* obj) { return obj; }

		void AddRef() { m_refs.fetch_add(1); }

		void Release()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}
	};


	/*!
		\ingroup refcount
	*/
	template <class T, T* (*AddObjectReference)(T*), void (*FreeObjectReference)(T*)>
	class CoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
			{
				if (!m_registeredRef)
					delete this;
			}
		}

	  public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T* m_object;
		CoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~CoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(CoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		// This is needed by code like
		// bool operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }
		static T* GetObject(const CoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef()
		{
			if (m_object && (m_refs != 0))
				AddObjectReference(m_object);
			AddRefInternal();
		}

		void Release()
		{
			T* obj = m_object;
			ReleaseInternal();
			if (obj)
				FreeObjectReference(obj);
		}

		void AddRefForRegistration() { m_registeredRef = true; }

		void ReleaseForRegistration()
		{
			m_object = nullptr;
			m_registeredRef = false;
			if (m_refs == 0)
				delete this;
		}

		void AddRefForCallback() { AddRefInternal(); }
		void ReleaseForCallback() { ReleaseInternal(); }
	};

	/*!
		\ingroup refcount
	*/
	template <class T>
	class StaticCoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	  public:
		std::atomic<int> m_refs;
		T* m_object;
		StaticCoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~StaticCoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(StaticCoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
		void AddRefForCallback() {}
		void ReleaseForCallback() {}
	};

	/*!
		\ingroup refcount
	*/
	template <class T>
	class Ref
	{
		T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	  public:
		Ref() : m_obj(nullptr) {}

		Ref(T* obj) : m_obj(obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref(const Ref<T>& obj) : m_obj(obj.m_obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref(Ref<T>&& other) : m_obj(other.m_obj)
		{
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		~Ref()
		{
			if (m_obj)
			{
				m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
			}
		}

		Ref<T>& operator=(const Ref<T>& obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj.m_obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		Ref<T>& operator=(Ref<T>&& other)
		{
			if (m_obj)
			{
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
				m_obj->Release();
			}
			m_obj = other.m_obj;
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
			return *this;
		}

		Ref<T>& operator=(T* obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T*() const { return m_obj; }

		T* operator->() const { return m_obj; }

		T& operator*() const { return *m_obj; }

		bool operator!() const { return m_obj == nullptr; }

		bool operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }

		bool operator==(const Ref<T>& obj) const { return T::GetObject(m_obj) == T::GetObject(obj.m_obj); }

		bool operator!=(const T* obj) const { return T::GetObject(m_obj) != T::GetObject(obj); }

		bool operator!=(const Ref<T>& obj) const { return T::GetObject(m_obj) != T::GetObject(obj.m_obj); }

		bool operator<(const T* obj) const { return T::GetObject(m_obj) < T::GetObject(obj); }

		bool operator<(const Ref<T>& obj) const { return T::GetObject(m_obj) < T::GetObject(obj.m_obj); }

		T* GetPtr() const { return m_obj; }
	};

	/*!
	    \ingroup refcount
	*/
	template <class T>
	class CallbackRef
	{
		T* m_obj;

	public:
		CallbackRef(void* obj) : m_obj((T*)obj) { m_obj->AddRefForCallback(); }
		~CallbackRef() { m_obj->ReleaseForCallback(); }
		operator T*() const { return m_obj; }
		T* operator->() const { return m_obj; }
		T& operator*() const { return *m_obj; }
		bool operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }
		bool operator==(const Ref<T>& obj) const { return T::GetObject(m_obj) == T::GetObject(obj.m_obj); }
		bool operator!=(const T* obj) const { return T::GetObject(m_obj) != T::GetObject(obj); }
		bool operator!=(const Ref<T>& obj) const { return T::GetObject(m_obj) != T::GetObject(obj.m_obj); }
		bool operator<(const T* obj) const { return T::GetObject(m_obj) < T::GetObject(obj); }
		bool operator<(const Ref<T>& obj) const { return T::GetObject(m_obj) < T::GetObject(obj.m_obj); }
		T* GetPtr() const { return m_obj; }
	};

	/*!
		\ingroup confidence
	*/
	class ConfidenceBase
	{
	  protected:
		uint8_t m_confidence;

	  public:
		ConfidenceBase() : m_confidence(0) {}

		ConfidenceBase(uint8_t conf) : m_confidence(conf) {}

		static uint8_t Combine(uint8_t a, uint8_t b)
		{
			uint8_t result = (uint8_t)(((uint32_t)a * (uint32_t)b) / BN_FULL_CONFIDENCE);
			if ((a >= BN_MINIMUM_CONFIDENCE) && (b >= BN_MINIMUM_CONFIDENCE) && (result < BN_MINIMUM_CONFIDENCE))
				result = BN_MINIMUM_CONFIDENCE;
			return result;
		}

		uint8_t GetConfidence() const { return m_confidence; }
		uint8_t GetCombinedConfidence(uint8_t base) const { return Combine(m_confidence, base); }
		void SetConfidence(uint8_t conf) { m_confidence = conf; }
		bool IsUnknown() const { return m_confidence == 0; }
	};

	/*!
		\ingroup confidence
	*/
	template <class T>
	class Confidence : public ConfidenceBase
	{
		T m_value;

	  public:
		Confidence() {}

		Confidence(const T& value) : ConfidenceBase(BN_FULL_CONFIDENCE), m_value(value) {}

		Confidence(const T& value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Confidence<T>& v) : ConfidenceBase(v.m_confidence), m_value(v.m_value) {}

		operator T() const { return m_value; }
		T* operator->() { return &m_value; }
		const T* operator->() const { return &m_value; }

		// This MUST be a copy. There are subtle compiler scoping bugs that will cause nondeterministic failures
		// when using one of these objects as a temporary if a reference is returned here. Unfortunately, this has
		// negative performance implications. Make a local copy first if the template argument is a complex
		// object and it is needed repeatedly.
		T GetValue() const { return m_value; }

		void SetValue(const T& value) { m_value = value; }

		Confidence<T>& operator=(const Confidence<T>& v)
		{
			m_value = v.m_value;
			m_confidence = v.m_confidence;
			return *this;
		}

		Confidence<T>& operator=(const T& value)
		{
			m_value = value;
			m_confidence = BN_FULL_CONFIDENCE;
			return *this;
		}

		bool operator<(const Confidence<T>& a) const
		{
			if (m_value < a.m_value)
				return true;
			if (a.m_value < m_value)
				return false;
			return m_confidence < a.m_confidence;
		}

		bool operator==(const Confidence<T>& a) const
		{
			if (m_confidence != a.m_confidence)
				return false;
			return m_value == a.m_value;
		}

		bool operator!=(const Confidence<T>& a) const { return !(*this == a); }
	};

	/*!
		\ingroup confidence
	*/
	template <class T>
	class Confidence<Ref<T>> : public ConfidenceBase
	{
		Ref<T> m_value;

	  public:
		Confidence() {}

		Confidence(T* value) : ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value) {}

		Confidence(T* value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Ref<T>& value) : ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value) {}

		Confidence(const Ref<T>& value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Confidence<Ref<T>>& v) : ConfidenceBase(v.m_confidence), m_value(v.m_value) {}

		operator Ref<T>() const { return m_value; }
		operator T*() const { return m_value.GetPtr(); }
		T* operator->() const { return m_value.GetPtr(); }
		bool operator!() const { return !m_value; }

		const Ref<T>& GetValue() const { return m_value; }
		void SetValue(T* value) { m_value = value; }
		void SetValue(const Ref<T>& value) { m_value = value; }

		Confidence<Ref<T>>& operator=(const Confidence<Ref<T>>& v)
		{
			m_value = v.m_value;
			m_confidence = v.m_confidence;
			return *this;
		}

		Confidence<Ref<T>>& operator=(T* value)
		{
			m_value = value;
			m_confidence = value ? BN_FULL_CONFIDENCE : 0;
			return *this;
		}

		Confidence<Ref<T>>& operator=(const Ref<T>& value)
		{
			m_value = value;
			m_confidence = value ? BN_FULL_CONFIDENCE : 0;
			return *this;
		}

		bool operator<(const Confidence<Ref<T>>& a) const
		{
			if (m_value < a.m_value)
				return true;
			if (a.m_value < m_value)
				return false;
			return m_confidence < a.m_confidence;
		}

		bool operator==(const Confidence<Ref<T>>& a) const
		{
			if (m_confidence != a.m_confidence)
				return false;
			return m_value == a.m_value;
		}

		bool operator!=(const Confidence<Ref<T>>& a) const { return !(*this == a); }
	};

	/*!
		\ingroup logging
	*/
	class LogListener
	{
		static void LogMessageCallback(void* ctxt, size_t session, BNLogLevel level, const char* msg, const char* logger_name = "", size_t tid = 0);
		static void CloseLogCallback(void* ctxt);
		static BNLogLevel GetLogLevelCallback(void* ctxt);

	  public:
		virtual ~LogListener() {}

		static void RegisterLogListener(LogListener* listener);
		static void UnregisterLogListener(LogListener* listener);
		static void UpdateLogListeners();

		virtual void LogMessage(size_t session, BNLogLevel level, const std::string& msg, const std::string& logger_name = "", size_t tid = 0) = 0;
		virtual void CloseLog() {}
		virtual BNLogLevel GetLogLevel() { return WarningLog; }
	};

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

	/*! Logs to the error console with the given BNLogLevel.

	    @threadsafe

	    \ingroup logging

	    \param level BNLogLevel debug log level
	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(2, 3)
	void Log(BNLogLevel level, const char* fmt, ...);

	/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
	    Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogTrace(const char* fmt, ...);


	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
	    Log level DebugLog is the most verbose logging level in release builds.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogDebug(const char* fmt, ...);

	/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
	    Log level InfoLog is the second most verbose logging level.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogInfo(const char* fmt, ...);

	/*! LogWarn writes text to the error console including a warning icon,
	    and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogWarn(const char* fmt, ...);

	/*! LogError writes text to the error console and pops up the error console. Additionally,
	    Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogError(const char* fmt, ...);

	/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
	    LogAlert corresponds to the log level: AlertLog.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogAlert(const char* fmt, ...);

	// Implementation detail
	void LogFV(BNLogLevel level, fmt::string_view format, fmt::format_args args);
	void LogTraceFV(fmt::string_view format, fmt::format_args args);
	void LogDebugFV(fmt::string_view format, fmt::format_args args);
	void LogInfoFV(fmt::string_view format, fmt::format_args args);
	void LogWarnFV(fmt::string_view format, fmt::format_args args);
	void LogErrorFV(fmt::string_view format, fmt::format_args args);
	void LogAlertFV(fmt::string_view format, fmt::format_args args);

	/*! Logs to the error console with the given BNLogLevel.

		@threadsafe

		\ingroup logging

		\param level BNLogLevel debug log level
		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogF(BNLogLevel level, fmt::format_string<T...> format, T&&... args)
	{
		LogFV(level, format, fmt::make_format_args(args...));
	}

	/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
		Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogTraceF(fmt::format_string<T...> format, T&&... args)
	{
		LogTraceFV(format, fmt::make_format_args(args...));
	}

	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
		Log level DebugLog is the most verbose logging level in release builds.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogDebugF(fmt::format_string<T...> format, T&&... args)
	{
		LogDebugFV(format, fmt::make_format_args(args...));
	}

	/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
		Log level InfoLog is the second most verbose logging level.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogInfoF(fmt::format_string<T...> format, T&&... args)
	{
		LogInfoFV(format, fmt::make_format_args(args...));
	}

	/*! LogWarn writes text to the error console including a warning icon,
		and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogWarnF(fmt::format_string<T...> format, T&&... args)
	{
		LogWarnFV(format, fmt::make_format_args(args...));
	}

	/*! LogError writes text to the error console and pops up the error console. Additionally,
		Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogErrorF(fmt::format_string<T...> format, T&&... args)
	{
		LogErrorFV(format, fmt::make_format_args(args...));
	}

	/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
		LogAlert corresponds to the log level: AlertLog.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogAlertF(fmt::format_string<T...> format, T&&... args)
	{
		LogAlertFV(format, fmt::make_format_args(args...));
	}

	/*! Redirects the minimum level passed to standard out

	    @threadsafe

	    \ingroup logging

		\param minimumLevel minimum level to log to stdout
	*/
	void LogToStdout(BNLogLevel minimumLevel);

	/*! Redirects the minimum level passed to standard error

	    @threadsafe

	    \ingroup logging

		\param minimumLevel minimum level to log to stderr
	*/
	void LogToStderr(BNLogLevel minimumLevel);

	/*! Redirects minimum log level to the file at `path`, optionally appending rather than overwriting.

	    @threadsafe

	    \ingroup logging

		\param minimumLevel minimum level to log to stderr
		\param path Path to log to
		\param append Optional flag for specifying appending. True = append, False = overwrite.
	*/
	bool LogToFile(BNLogLevel minimumLevel, const std::string& path, bool append = false);

	/*! Close all log files

	    \ingroup logging
	*/
	void CloseLogs();

	class FileMetadata;
	class BinaryView;
	/*! Logger is a class allowing scoped logging to the console

		\ingroup logging
	*/
	class Logger: public CoreRefCountObject<BNLogger, BNNewLoggerReference, BNFreeLogger>
	{
			size_t GetThreadId() const;
			std::unordered_map<BNLogLevel, std::string> m_iterBuffer;
			friend struct Iterator;

			void LogFV(BNLogLevel level, fmt::string_view format, fmt::format_args args);
			void LogTraceFV(fmt::string_view format, fmt::format_args args);
			void LogDebugFV(fmt::string_view format, fmt::format_args args);
			void LogInfoFV(fmt::string_view format, fmt::format_args args);
			void LogWarnFV(fmt::string_view format, fmt::format_args args);
			void LogErrorFV(fmt::string_view format, fmt::format_args args);
			void LogAlertFV(fmt::string_view format, fmt::format_args args);

		public:
			Logger(BNLogger* logger);

			/*! Create a logger with the specified name and session ID

				\warning You may want to use LogRegistry::CreateLogger and LogRegistry::GetLogger instead of this. If
			 			 you already have access to a BinaryView, you may want to use bv->CreateLogger() instead of this.

				\see BinaryView::CreateLogger()

			 	\code{.cpp}
			 	auto logger = Logger("MyPluginName", 0);
			 	\endcode

			 	Session ID corresponds to the tab for the specified BinaryView, and the default of 0 will log to *all tabs*.

			 	\see FileMetadata::GetSessionId()

				\param loggerName Name of the logger to create
				\param sessionId Session ID for the logger.
			*/
			Logger(const std::string& loggerName, size_t sessionId = 0);

			/*! Logs to the error console with the given BNLogLevel.

	    			@threadsafe

				\param level BNLogLevel debug log level
	    		\param fmt C-style format string.
	    		\param ... Variable arguments corresponding to the format string.
			*/
			void Log(BNLogLevel level, const char* fmt, ...);

			/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
				Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogTrace(const char* fmt, ...);

			/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
				Log level DebugLog is the most verbose logging level in release builds.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogDebug(const char* fmt, ...);

			/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
				Log level InfoLog is the second most verbose logging level.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogInfo(const char* fmt, ...);

			/*! LogWarn writes text to the error console including a warning icon,
				and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogWarn(const char* fmt, ...);

			/*! LogError writes text to the error console and pops up the error console. Additionally,
				Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogError(const char* fmt, ...);

			/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
				LogAlert corresponds to the log level: AlertLog.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogAlert(const char* fmt, ...);

			/*! Logs to the error console with the given BNLogLevel.

					@threadsafe

				\param level BNLogLevel debug log level
				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogF(BNLogLevel level, fmt::format_string<T...> format, T&&... args)
			{
				LogFV(level, format, fmt::make_format_args(args...));
			}

			/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
				Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogTraceF(fmt::format_string<T...> format, T&&... args)
			{
				LogTraceFV(format, fmt::make_format_args(args...));
			}

			/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
				Log level DebugLog is the most verbose logging level in release builds.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogDebugF(fmt::format_string<T...> format, T&&... args)
			{
				LogDebugFV(format, fmt::make_format_args(args...));
			}

			/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
				Log level InfoLog is the second most verbose logging level.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogInfoF(fmt::format_string<T...> format, T&&... args)
			{
				LogInfoFV(format, fmt::make_format_args(args...));
			}

			/*! LogWarn writes text to the error console including a warning icon,
				and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogWarnF(fmt::format_string<T...> format, T&&... args)
			{
				LogWarnFV(format, fmt::make_format_args(args...));
			}

			/*! LogError writes text to the error console and pops up the error console. Additionally,
				Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogErrorF(fmt::format_string<T...> format, T&&... args)
			{
				LogErrorFV(format, fmt::make_format_args(args...));
			}

			/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
				LogAlert corresponds to the log level: AlertLog.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogAlertF(fmt::format_string<T...> format, T&&... args)
			{
				LogAlertFV(format, fmt::make_format_args(args...));
			}

			/*! Get the name registered for this Logger

	    			@threadsafe

				\return The logger name
			*/
			std::string GetName();

			/*! Get the session ID registered for this logger

	    			@threadsafe

				\return The logger session ID
			*/
			size_t GetSessionId();

			void Indent();
			void Dedent();
			void ResetIndent();
	};

	/*! A class allowing registering and retrieving Loggers

		\see BinaryView::CreateLogger

	 	\ingroup logging
	*/
	class LogRegistry
	{
	public:
		/*! Create a logger with the specified name and session ID

	    		@threadsafe

			\note If you already have a BinaryView, you may want to use \c BinaryView::CreateLogger instead of this.

			\code{.cpp}
			auto sessionID = bv->GetFile()->GetSessionId();
			auto logger = LogRegistry::CreateLogger("MyPluginName", sessionID);
			\endcode

			Session ID corresponds to the tab for the specified BinaryView, and the default of 0 will log to *all tabs*.

		 	\see FileMetadata::GetSessionId()

			\param loggerName Name of the logger to create
			\param sessionId Session ID for the logger
		 	\return The created logger
		*/
		static Ref<Logger> CreateLogger(const std::string& loggerName, size_t sessionId = 0);

		/*! Get a logger with the specified name and session ID

	    		@threadsafe

			\code{.cpp}
			auto sessionID = bv->GetFile()->GetSessionId();
			auto logger = LogRegistry::GetLogger("MyPluginName", sessionID);
			\endcode

			Session ID corresponds to the tab for the specified BinaryView, and the default of 0 will log to *all tabs*.

		 	\see FileMetadata::GetSessionId()

			\param loggerName Name of the logger to create
			\param sessionId Session ID for the logger
		 	\return The created logger
		*/
		static Ref<Logger> GetLogger(const std::string& loggerName, size_t sessionId = 0);

		/*! Get the list of registered Logger names

	    		@threadsafe

			\return a list of registered logger names
		*/
		static std::vector<std::string> GetLoggerNames();
	};

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

	class Metadata;
	typedef BNMetadataType MetadataType;

	/*!
	    \ingroup binaryview
	*/
	class Metadata : public CoreRefCountObject<BNMetadata, BNNewMetadataReference, BNFreeMetadata>
	{
	public:
		explicit Metadata(BNMetadata* structuredData);
		/*! Create a new Metadata object representing a bool

		    @threadsafe

		    \param data Bool to store

		*/
		explicit Metadata(bool data);

		/*! Create a new Metadata object representing a string

		    @threadsafe

		    \param data string to store

		*/
		explicit Metadata(const std::string& data);

		/*! Create a new Metadata object representing a uint64

		    @threadsafe

		    \param data - uint64 to store

		*/
		explicit Metadata(uint64_t data);

		/*! Create a new Metadata object representing an int64

		    @threadsafe

		    \param data - int64 to store

		*/
		explicit Metadata(int64_t data);

		/*! Create a new Metadata object representing a double

		    @threadsafe

		    \param data - double to store

		*/
		explicit Metadata(double data);

		/*! Create a new Metadata object representing a vector of bools

		    @threadsafe

		    \param data - list of bools to store

		*/
		explicit Metadata(const std::vector<bool>& data);

		/*! Create a new Metadata object representing a vector of strings

		    @threadsafe

		    \param data - list of strings to store

		*/
		explicit Metadata(const std::vector<std::string>& data);

		/*! Create a new Metadata object representing a vector of uint64s

		    @threadsafe

		    \param data - list of uint64s to store

		*/
		explicit Metadata(const std::vector<uint64_t>& data);

		/*! Create a new Metadata object representing a vector of int64s

		    @threadsafe

		    \param data - list of int64s to store

		*/
		explicit Metadata(const std::vector<int64_t>& data);

		/*! Create a new Metadata object representing a vector of doubles

		    @threadsafe

		    \param data - list of doubles to store

		*/
		explicit Metadata(const std::vector<double>& data);

		/*! Create a new Metadata object representing a vector of bytes to store

		    @threadsafe

		    \param data - list of bytes to store

		*/
		explicit Metadata(const std::vector<uint8_t>& data);

		/*! Create a new Metadata object representing a vector of children Metadata objects

		    @threadsafe

		    \param data - list of Metadata objects to store

		*/
		explicit Metadata(const std::vector<Ref<Metadata>>& data);

		/*! Create a new Metadata object representing a map of strings to metadata objects

		    @threadsafe

		    \param data - map of strings to metadata objects

		*/
		explicit Metadata(const std::map<std::string, Ref<Metadata>>& data);
		explicit Metadata(MetadataType type);
		virtual ~Metadata() {}

		bool operator==(const Metadata& rhs);
		Ref<Metadata> operator[](const std::string& key);
		Ref<Metadata> operator[](size_t idx);

		MetadataType GetType() const;
		bool GetBoolean() const;
		std::string GetString() const;
		uint64_t GetUnsignedInteger() const;
		int64_t GetSignedInteger() const;
		double GetDouble() const;
		std::vector<bool> GetBooleanList() const;
		std::vector<std::string> GetStringList() const;
		std::vector<uint64_t> GetUnsignedIntegerList() const;
		std::vector<int64_t> GetSignedIntegerList() const;
		std::vector<double> GetDoubleList() const;
		std::vector<uint8_t> GetRaw() const;
		std::vector<Ref<Metadata>> GetArray() const;
		std::map<std::string, Ref<Metadata>> GetKeyValueStore() const;
		std::string GetJsonString() const;

		// For key-value data only
		/*! Get a Metadata object by key. Only for if IsKeyValueStore == true

			@threadunsafewith{SetValueForKey and RemoveKey}

		    \param key
		    \return
		 */
		Ref<Metadata> Get(const std::string& key);
		/*! Set the value mapped to by a particular string. Only for if IsKeyValueStore == true

			@threadunsafewith{Get and RemoveKey}

		    \param key
		    \param data
		    \return
		 */
		bool SetValueForKey(const std::string& key, Ref<Metadata> data);

		/*! Remove a key from the map. Only for if IsKeyValueStore == true

			@threadunsafewith{SetValueForKey and Get}

		    \param key - Key to remove
		 */
		void RemoveKey(const std::string& key);

		// For array data only
		/*! Get an item at a given index

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \param index Index of the item to retrieve
		    \return Item at that index, if valid.
		 */
		Ref<Metadata> Get(size_t index);

		/*! Append an item to the array

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \param data Data to append
		    \return Whether the append was successful
		 */
		bool Append(Ref<Metadata> data);

		/*! Remove an item at a given index

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \param index Index of the item to remove
		 */
		void RemoveIndex(size_t index);

		/*! Get the size of the array

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \return Size of the array
		 */
		size_t Size() const;

		bool IsBoolean() const;
		bool IsString() const;
		bool IsUnsignedInteger() const;
		bool IsSignedInteger() const;
		bool IsDouble() const;
		bool IsBooleanList() const;
		bool IsStringList() const;
		bool IsUnsignedIntegerList() const;
		bool IsSignedIntegerList() const;
		bool IsDoubleList() const;
		bool IsRaw() const;
		bool IsArray() const;
		bool IsKeyValueStore() const;
	};

	class BinaryView;
	class ProjectFile;

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

	/*! Open a BinaryView from a ProjectFile, initializing data views and loading settings.

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
	Ref<BinaryView> Load(Ref<ProjectFile> rawData, bool updateAnalysis = true, const std::string& options = "{}", std::function<bool(size_t, size_t)> progress = {});

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

	/*! Attempt to demangle a mangled name, trying all relevant demanglers and using whichever one accepts it

		\see Demangler::Demangle for a discussion on which demangler will be used.

		\param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
		\param[in] mangledName a mangled Microsoft Visual Studio C++ name
		\param[out] outType Pointer to Type to output
		\param[out] outVarName QualifiedName reference to write the output name to.
		\param[in] view (Optional) view of the binary containing the mangled name
		\param[in] simplify (Optional) Whether to simplify demangled names.
		\return True if the name was demangled and written to the out* parameters

		\ingroup demangle
	*/
	bool DemangleGeneric(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
	                     Ref<BinaryView> view = nullptr, const bool simplify = false);

	/*! Demangles using LLVM's demangler

		\param[in] mangledName a mangled (msvc/itanium/rust/dlang) name
		\param[out] outVarName QualifiedName reference to write the output name to.
		\param[in] simplify Whether to simplify demangled names.
	    \return True if the name was demangled and written to the out* parameters

		\ingroup demangle
	*/
	bool DemangleLLVM(const std::string& mangledName, QualifiedName& outVarName, const bool simplify = false);

	/*! Demangles using LLVM's demangler

		\param[in] mangledName a mangled (msvc/itanium/rust/dlang) name
		\param[out] outVarName QualifiedName reference to write the output name to.
		\param[in] view View to check the analysis.types.templateSimplifier for
	    \return True if the name was demangled and written to the out* parameters

		\ingroup demangle
	*/
	bool DemangleLLVM(const std::string& mangledName, QualifiedName& outVarName, BinaryView* view);

	/*! Demangles a Microsoft Visual Studio C++ name

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled Microsoft Visual Studio C++ name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] simplify Whether to simplify demangled names.
	    \return True if the name was demangled and written to the out* parameters

	    \ingroup demangle
	*/
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
		const bool simplify = false);

	/*! Demangles a Microsoft Visual Studio C++ name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	        to determine whether to simplify the mangled name.

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled Microsoft Visual Studio C++ name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] view View to check the analysis.types.templateSimplifier for
	    \return True if the name was demangled and written to the out* parameters

	    \ingroup demangle
	*/
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
		BinaryView* view);

	/*! Demangles a GNU3 name

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled GNU3 name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] simplify Whether to simplify demangled names.
	    \return True if the name was demangled and written to the out* parameters

	    \ingroup demangle
	*/
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType,
		QualifiedName& outVarName, const bool simplify = false);

	/*! Demangles a GNU3 name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	        to determine whether to simplify the mangled name.

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled GNU3 name
	    \param[out] outType Reference to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] view View to check the analysis.types.templateSimplifier for
	    \return True if the name was demangled and written to the out* parameters

	    \ingroup demangle
	*/
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType,
		QualifiedName& outVarName, BinaryView* view);

	/*! Determines if a symbol name is a mangled GNU3 name

	    \param[in] mangledName a potentially mangled name

	    \ingroup demangle
	*/
	bool IsGNU3MangledString(const std::string& mangledName);

	/*!
		\ingroup demangle
	*/
	std::string SimplifyToString(const std::string& input);

	/*!
		\ingroup demangle
	*/
	std::string SimplifyToString(const QualifiedName& input);

	/*!
		\ingroup demangle
	*/
	QualifiedName SimplifyToQualifiedName(const std::string& input, bool simplify);

	/*!
		\ingroup demangle
	*/
	QualifiedName SimplifyToQualifiedName(const QualifiedName& input);

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

	void RegisterInteractionHandler(InteractionHandler* handler);

	/*! Displays contents to the user in the UI or on the command-line

		@threadsafe

		\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.

	 	\ingroup interaction

		\param title Title for the report
		\param contents Contents of the report
	*/
	void ShowPlainTextReport(const std::string& title, const std::string& contents);

	/*! Displays markdown contents to the user in the UI or on the command-line

		@threadsafe

	 	\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.

	 	\ingroup interaction

		\param title Title for the report
		\param contents Markdown contents of the report
		\param plainText Plaintext contents of the report (used on the command line)
	*/
	void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText = "");

	/*! Displays HTML contents to the user in the UI or on the command-line

		@threadsafe

		\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.
		\note This API doesn't support clickable references into an existing BinaryView.

	 	\ingroup interaction

		\param title Title for the report
		\param contents HTML contents of the report
		\param plainText Plaintext contents of the report (used on the command line)
	*/
	void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText = "");

	/*! Displays a flow graph in UI applications and nothing in command-line applications.

		@threadsafe

	 	\note This API doesn't support clickable references into an existing BinaryView.
	 	\note This API has no effect outside of the UI

	 	\ingroup interaction

		\param title Title for the report
		\param graph FlowGraph object to be rendered.
	*/
	void ShowGraphReport(const std::string& title, FlowGraph* graph);

	/*! Show a collection of reports

		@threadsafe

	 	\ingroup interaction

		\param title Title for the collection of reports
		\param reports Collection of reports to show
	*/
	void ShowReportCollection(const std::string& title, ReportCollection* reports);

	/*! Prompts the user to input a string with the given prompt and title

		@threadsafe

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether a line was successfully received
	*/
	bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to input an integer with the given prompt and title

		@threadsafe

	 	\ingroup interaction
		\param[out] result Reference to the int64_t the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether an integer was successfully received
	*/
	bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to input an unsigned integer with the given prompt and title

		@threadsafe

	 	\ingroup interaction
		\param[out] result Reference to the uint64_t the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether an integer was successfully received
	*/
	bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to select the one of the provided choices

		@threadsafe

	 	\ingroup interaction
		\param[out] idx Reference to the size_t the resulting index selected will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\param[in] choices List of string choices for the user to select from
		\return Whether a choice was successfully picked
	*/
	bool GetChoiceInput(
		size_t& idx, const std::string& prompt, const std::string& title, const std::vector<std::string>& choices);

	/*! Prompts the user to select the one of the provided choices out of a large list, with the option to filter choices

		\ingroup interaction
		\param[out] idx Reference to the size_t the resulting index selected will be copied to
		\param[in] title Title for the input popup / prompt for headless
		\param[in] prompt Prompt for the input (shown on the 'Select' button in UI)
		\param[in] choices List of string choices for the user to select from
		\return Whether a choice was successfully picked
	*/
	bool GetLargeChoiceInput(size_t& idx, const std::string& title, const std::string& prompt, const std::vector<std::string>& choices);

	/*! Prompts the user for a file name to open

		@threadsafe

		Multiple file selection groups can be included if separated by two semicolons. Multiple file wildcards may be
	 	specified by using a space within the parenthesis.

		Also, a simple selector of "\*.extension" by itself may also be used instead of specifying the description.

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] ext Optional, file extension
		\return Whether a filename was successfully received
	*/
	bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");

	/*! Prompts the user for a file name to save as, optionally providing a file extension and defaultName

		@threadsafe

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] ext Optional, file extension
		\param[in] defaultName Optional, default filename
		\return Whether a filename was successfully received
	*/
	bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
	    const std::string& defaultName = "");

	/*! Prompts the user for a directory name to save as, optionally providing a default_name

		@threadsafe

	 	\ingroup interaction
		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] defaultName Optional, default directory name
		\return Whether a directory was successfully received
	*/
	bool GetDirectoryNameInput(std::string& result, const std::string& prompt, const std::string& defaultName = "");

	/*! Prompts the user for a set of inputs specified in `fields` with given title.
		The fields parameter is a list containing FieldInputFields

		@threadsafe

	 	\ingroup interaction
		\param[in,out] fields reference to a list containing FieldInputFields
		\param[in] title Title of the Form
		\return Whether the form was successfully filled out
	*/
	bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title);

	/*! Displays a configurable message box in the UI, or prompts on the console as appropriate

		@threadsafe

		\param title Title for the message box
		\param text Contents of the message box
		\param buttons
	 	\parblock
	    Button Set type to display to the user

	    	OKButtonSet - Displays only an OK button
	    	YesNoButtonSet - Displays a Yes and a No button
	    	YesNoCancelButtonSet - Displays a Yes, No, and Cancel button
	    \endparblock
		\param icon Icons to display to the user

	 	\ingroup interaction

		\return Which button was selected'
	 	\retval NoButton No was clicked, or the box was closed and had type YesNoButtonSet
	 	\retval YesButton Yes was clicked
	 	\retval OKButton Ok Button was clicked, or the box was closed and had type OKButtonSet
	 	\retval CancelButton Cancel button was clicked or the dialog box was closed and had type YesNoCancelButtonSet
	*/
	BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
	    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon);

	/*! Opens a given url in the user's web browser, if available.

		@threadsafe

	 	\ingroup interaction

		\param url URL to open
		\return Whether a URL was successfully opened.
	*/
	bool OpenUrl(const std::string& url);

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

		    \param nullTerminates Whether the decoder should stop and return the string after encountering a null (\x00)
		   byte.

		    @threadunsafe
		*/
		std::string ToEscapedString(bool nullTerminates = false, bool escapePrintable = false) const;

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
		\ingroup filemetadata
	*/
	class NavigationHandler
	{
	  private:
		BNNavigationHandler m_callbacks;

		static char* GetCurrentViewCallback(void* ctxt);
		static uint64_t GetCurrentOffsetCallback(void* ctxt);
		static bool NavigateCallback(void* ctxt, const char* view, uint64_t offset);

	  public:
		NavigationHandler();
		virtual ~NavigationHandler() {}

		BNNavigationHandler* GetCallbacks() { return &m_callbacks; }

		virtual std::string GetCurrentView() = 0;
		virtual uint64_t GetCurrentOffset() = 0;
		virtual bool Navigate(const std::string& view, uint64_t offset) = 0;
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
		static void ConvertInstructionTextToken(const InstructionTextToken& token, BNInstructionTextToken* result);
		static BNInstructionTextToken* CreateInstructionTextTokenList(const std::vector<InstructionTextToken>& tokens);
		static void FreeInstructionTextToken(BNInstructionTextToken* token);
		static void FreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertAndFreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertInstructionTextTokenList(
		    const BNInstructionTextToken* tokens, size_t count);
	};

	class UndoEntry;

	/*!

		\ingroup database
	*/
	struct DatabaseException : ExceptionWithStackTrace
	{
		DatabaseException(const std::string& desc) : ExceptionWithStackTrace(desc.c_str()) {}
	};

	/*! Maintains access to the raw data stored in Snapshots and various
    	other Database-related structures.

		\ingroup database
	*/
	class KeyValueStore : public CoreRefCountObject<BNKeyValueStore, BNNewKeyValueStoreReference, BNFreeKeyValueStore>
	{
	  public:
		KeyValueStore();
		KeyValueStore(const DataBuffer& buffer);
		KeyValueStore(BNKeyValueStore* store);

		std::vector<std::string> GetKeys() const;

		bool HasValue(const std::string& name) const;
		Json::Value GetValue(const std::string& name) const;
		DataBuffer GetValueHash(const std::string& name) const;
		DataBuffer GetBuffer(const std::string& name) const;
		void SetValue(const std::string& name, const Json::Value& value);
		void SetBuffer(const std::string& name, const DataBuffer& value);

		DataBuffer GetSerializedData() const;

		void BeginNamespace(const std::string& name);
		void EndNamespace();

		bool IsEmpty() const;
		size_t ValueSize() const;
		size_t DataSize() const;
		size_t ValueStorageSize() const;
		size_t NamespaceSize() const;
	};

	class Database;

	/*! A model of an individual database snapshot, created on save.

		\ingroup database
	*/
	class Snapshot : public CoreRefCountObject<BNSnapshot, BNNewSnapshotReference, BNFreeSnapshot>
	{
	  public:
		Snapshot(BNSnapshot* snapshot);

		Ref<Database> GetDatabase();
		int64_t GetId();
		std::string GetName();
		void SetName(const std::string& name);
		bool IsAutoSave();
		bool HasContents();
		bool HasData();
		bool HasUndo();
		Ref<Snapshot> GetFirstParent();
		std::vector<Ref<Snapshot>> GetParents();
		std::vector<Ref<Snapshot>> GetChildren();
		DataBuffer GetFileContents();
		DataBuffer GetFileContentsHash();
		DataBuffer GetUndoData();
		std::vector<Ref<UndoEntry>> GetUndoEntries();
		std::vector<Ref<UndoEntry>> GetUndoEntries(const std::function<bool(size_t, size_t)>& progress);
		Ref<KeyValueStore> ReadData();
		Ref<KeyValueStore> ReadData(const std::function<bool(size_t, size_t)>& progress);
		bool StoreData(const Ref<KeyValueStore>& data, const std::function<bool(size_t, size_t)>& progress);
		bool HasAncestor(Ref<Snapshot> other);
	};

	class FileMetadata;

	/*! Provides lower level access to raw snapshot data used to construct analysis data

		\ingroup database
	*/
	class Database : public CoreRefCountObject<BNDatabase, BNNewDatabaseReference, BNFreeDatabase>
	{
	  public:
		Database(BNDatabase* database);

		bool SnapshotHasData(int64_t id);
		Ref<Snapshot> GetSnapshot(int64_t id);
		std::vector<Ref<Snapshot>> GetSnapshots();
		void SetCurrentSnapshot(int64_t id);
		Ref<Snapshot> GetCurrentSnapshot();
		int64_t WriteSnapshotData(std::vector<int64_t> parents, Ref<BinaryView> file, const std::string& name,
		    const Ref<KeyValueStore>& data, bool autoSave, const std::function<bool(size_t, size_t)>& progress);
		void TrimSnapshot(int64_t id);
		void RemoveSnapshot(int64_t id);

		std::vector<std::string> GetGlobalKeys() const;
		bool HasGlobal(const std::string& key) const;
		Json::Value ReadGlobal(const std::string& key) const;
		void WriteGlobal(const std::string& key, const Json::Value& val);
		DataBuffer ReadGlobalData(const std::string& key) const;
		void WriteGlobalData(const std::string& key, const DataBuffer& val);

		Ref<FileMetadata> GetFile();
		void ReloadConnection();

		Ref<KeyValueStore> ReadAnalysisCache() const;
		void WriteAnalysisCache(Ref<KeyValueStore> val);
	};


	/*!

		\ingroup project
	*/
	struct ProjectException : std::runtime_error
	{
		ProjectException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

	class ExternalLibrary;
	class Symbol;
	class Project;
	class ProjectFile;
	class ProjectFolder;

	/*!

	\ingroup project
	*/

	class ExternalLocation : public CoreRefCountObject<BNExternalLocation, BNNewExternalLocationReference, BNFreeExternalLocation>
	{
	public:
		ExternalLocation(BNExternalLocation* loc);

		Ref<Symbol> GetSourceSymbol();
		std::optional<uint64_t> GetTargetAddress();
		std::optional<std::string> GetTargetSymbol();
		Ref<ExternalLibrary> GetExternalLibrary();

		bool HasTargetAddress();
		bool HasTargetSymbol();

		bool SetTargetAddress(std::optional<uint64_t> address);
		bool SetTargetSymbol(std::optional<std::string> symbol);
		void SetExternalLibrary(Ref<ExternalLibrary> library);
	};

	/*!

	\ingroup project
	*/

	class ExternalLibrary : public CoreRefCountObject<BNExternalLibrary, BNNewExternalLibraryReference, BNFreeExternalLibrary>
	{
	public:
		ExternalLibrary(BNExternalLibrary* lib);

		std::string GetName() const;
		Ref<ProjectFile> GetBackingFile() const;

		void SetBackingFile(Ref<ProjectFile> file);
	};


	/*!
		\ingroup project
	*/
	class ProjectNotification
	{
	  private:
		BNProjectNotification m_callbacks;

		static bool BeforeOpenProjectCallback(void* ctxt, BNProject* project);
		static void AfterOpenProjectCallback(void* ctxt, BNProject* project);
		static bool BeforeCloseProjectCallback(void* ctxt, BNProject* project);
		static void AfterCloseProjectCallback(void* ctxt, BNProject* project);
		static bool BeforeProjectMetadataWrittenCallback(void* ctxt, BNProject* project, char* key, BNMetadata* value);
		static void AfterProjectMetadataWrittenCallback(void* ctxt, BNProject* project, char* key, BNMetadata* value);
		static bool BeforeProjectFileCreatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static void AfterProjectFileCreatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static bool BeforeProjectFileUpdatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static void AfterProjectFileUpdatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static bool BeforeProjectFileDeletedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static void AfterProjectFileDeletedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static bool BeforeProjectFolderCreatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static void AfterProjectFolderCreatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static bool BeforeProjectFolderUpdatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static void AfterProjectFolderUpdatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static bool BeforeProjectFolderDeletedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static void AfterProjectFolderDeletedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);

	  public:
		ProjectNotification();
		virtual ~ProjectNotification() {}

		BNProjectNotification* GetCallbacks() { return &m_callbacks; }

		virtual bool OnBeforeOpenProject(Project* project)
		{
			(void)project;
			return true;
		}

		virtual void OnAfterOpenProject(Project* project)
		{
			(void)project;
		}

		virtual bool OnBeforeCloseProject(Project* project)
		{
			(void)project;
			return true;
		}

		virtual void OnAfterCloseProject(Project* project)
		{
			(void)project;
		}

		virtual bool OnBeforeProjectMetadataWritten(Project* project, std::string& key, Metadata* value)
		{
			(void)project;
			(void)key;
			(void)value;
			return true;
		}

		virtual void OnAfterProjectMetadataWritten(Project* project, std::string& key, Metadata* value)
		{
			(void)project;
			(void)key;
			(void)value;
		}

		virtual bool OnBeforeProjectFileCreated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
			return true;
		}

		virtual void OnAfterProjectFileCreated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
		}

		virtual bool OnBeforeProjectFileUpdated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
			return true;
		}

		virtual void OnAfterProjectFileUpdated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
		}

		virtual bool OnBeforeProjectFileDeleted(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
			return true;
		}

		virtual void OnAfterProjectFileDeleted(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
		}

		virtual bool OnBeforeProjectFolderCreated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
			return true;
		}

		virtual void OnAfterProjectFolderCreated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
		}

		virtual bool OnBeforeProjectFolderUpdated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
			return true;
		}

		virtual void OnAfterProjectFolderUpdated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
		}

		virtual bool OnBeforeProjectFolderDeleted(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
			return true;
		}

		virtual void OnAfterProjectFolderDeleted(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
		}
	};

	/*!

	\ingroup project
	*/
	class ProjectFolder : public CoreRefCountObject<BNProjectFolder, BNNewProjectFolderReference, BNFreeProjectFolder>
	{
	public:
		ProjectFolder(BNProjectFolder* folder);

		Ref<Project> GetProject() const;
		std::string GetId() const;
		std::string GetName() const;
		std::string GetDescription() const;
		void SetName(const std::string& name);
		void SetDescription(const std::string& description);
		Ref<ProjectFolder> GetParent() const;
		void SetParent(Ref<ProjectFolder> parent);
		bool Export(const std::string& destination, const std::function<bool(size_t progress, size_t total)>& progressCallback = {}) const;
	};

	/*!

	\ingroup project
	*/
	class ProjectFile : public CoreRefCountObject<BNProjectFile, BNNewProjectFileReference, BNFreeProjectFile>
	{
	public:
		ProjectFile(BNProjectFile* file);

		Ref<Project> GetProject() const;
		std::string GetPathOnDisk() const;
		bool ExistsOnDisk() const;
		std::string GetName() const;
		std::string GetDescription() const;
		void SetName(const std::string& name);
		void SetDescription(const std::string& description);
		std::string GetId() const;
		Ref<ProjectFolder> GetFolder() const;
		void SetFolder(Ref<ProjectFolder> folder);
		bool Export(const std::string& destination) const;
		int64_t GetCreationTimestamp() const;
	};


	/*!

		\ingroup project
	*/
	class Project : public CoreRefCountObject<BNProject, BNNewProjectReference, BNFreeProject>
	{
	  public:
		Project(BNProject* project);

		static Ref<Project> CreateProject(const std::string& path, const std::string& name);
		static Ref<Project> OpenProject(const std::string& path);
		static std::vector<Ref<Project>> GetOpenProjects();

		bool Open();
		bool Close();
		std::string GetId() const;
		bool IsOpen() const;
		std::string GetPath() const;
		std::string GetName() const;
		void SetName(const std::string& name);
		std::string GetDescription() const;
		void SetDescription(const std::string& description);

		Ref<Metadata> QueryMetadata(const std::string& key);
		bool StoreMetadata(const std::string& key, Ref<Metadata> value);
		void RemoveMetadata(const std::string& key);

		Ref<ProjectFolder> CreateFolderFromPath(const std::string& path, Ref<ProjectFolder> parent, const std::string& description,
			const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFolder> CreateFolder(Ref<ProjectFolder> parent, const std::string& name, const std::string& description);
		Ref<ProjectFolder> CreateFolderUnsafe(Ref<ProjectFolder> parent, const std::string& name, const std::string& description, const std::string& id);
		std::vector<Ref<ProjectFolder>> GetFolders() const;
		Ref<ProjectFolder> GetFolderById(const std::string& id) const;
		void PushFolder(Ref<ProjectFolder> folder);
		bool DeleteFolder(Ref<ProjectFolder> folder, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});

		Ref<ProjectFile> CreateFileFromPath(const std::string& path, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFile> CreateFileFromPathUnsafe(const std::string& path, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::string& id, int64_t creationTimestamp, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFile> CreateFile_(const std::vector<uint8_t>& contents, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFile> CreateFileUnsafe(const std::vector<uint8_t>& contents, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::string& id, int64_t creationTimestamp, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		std::vector<Ref<ProjectFile>> GetFiles() const;
		Ref<ProjectFile> GetFileById(const std::string& id) const;
		Ref<ProjectFile> GetFileByPathOnDisk(const std::string& path);
		void PushFile(Ref<ProjectFile> file);
		bool DeleteFile_(Ref<ProjectFile> file);

		void RegisterNotification(ProjectNotification* notify);
		void UnregisterNotification(ProjectNotification* notify);

		void BeginBulkOperation();
		void EndBulkOperation();
	};

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

	/*!
		\ingroup filemetadata
	*/
	class SaveSettings : public CoreRefCountObject<BNSaveSettings, BNNewSaveSettingsReference, BNFreeSaveSettings>
	{
	  public:
		SaveSettings();
		SaveSettings(BNSaveSettings* settings);

		bool IsOptionSet(BNSaveOption option) const;
		void SetOption(BNSaveOption option, bool state = true);

		std::string GetName() const;
		void SetName(const std::string& name);
	};

	/*!
		\ingroup filemetadata
	*/
	class FileMetadata : public CoreRefCountObject<BNFileMetadata, BNNewFileReference, BNFreeFileMetadata>
	{
	  public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(Ref<ProjectFile> projectFile);
		FileMetadata(BNFileMetadata* file);

		/*! Close the underlying file handle
		*/
		void Close();

		void SetNavigationHandler(NavigationHandler* handler);

		/*! Get the original name of the binary opened if a bndb, otherwise the current filename

			\return The original name of the binary opened if a bndb, otherwise returns the current filename
		*/
		std::string GetOriginalFilename() const;

		/*! If the filename is not open in a BNDB, sets the filename for the current file.

			\param name New name
		*/
		void SetOriginalFilename(const std::string& name);

		/*!
			\return The name of the open bndb or binary filename
		*/
		std::string GetFilename() const;

		/*! Set the filename for the current BNDB or binary.

		 	\param name Set the filename for the current BNDB or binary.
		*/
		void SetFilename(const std::string& name);

		/*! Whether the file has unsaved modifications

			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*! Whether auto-analysis results have changed.

			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*! Mark file as having unsaved changes
		*/
		void MarkFileModified();

		/*! Mark file as having been saved (inverse of MarkFileModified)
		*/
		void MarkFileSaved();

		bool IsSnapshotDataAppliedWithoutError() const;

		/*! Whether the FileMetadata is backed by a database, or if specified,
		    	a specific BinaryView type

			\param binaryViewType Type for the BinaryView
		 	\return Whether the FileMetadata is backed by a database
		*/
		bool IsBackedByDatabase(const std::string& binaryViewType = "") const;

		/*! Writes the current database (.bndb) out to the specified file.

		 	\param name path and filename to write the bndb to. Should have ".bndb" appended to it.
		 	\param data BinaryView to save the database from
		 	\param settings Special save options
		 	\return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& name, BinaryView* data, Ref<SaveSettings> settings);

		/*! Writes the current database (.bndb) out to the specified file.

		    \param name path and filename to write the bndb to. Should have ".bndb" appended to it.
		    \param data BinaryView to save the database from
		    \param progressCallback callback function to send save progress to.
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& name, BinaryView* data,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);

		/*! Open an existing database from a given path

		 	\param path Path to the existing database
		 	\return The resulting BinaryView, if the load was successful
		*/
		Ref<BinaryView> OpenExistingDatabase(const std::string& path);

		/*! Open an existing database from a given path with a progress callback

		    \param path Path to the existing database
			\param progressCallback callback function to send load progress to.
		    \return The resulting BinaryView, if the load was successful
		*/
		Ref<BinaryView> OpenExistingDatabase(
		    const std::string& path, const std::function<bool(size_t progress, size_t total)>& progressCallback);
		Ref<BinaryView> OpenDatabaseForConfiguration(const std::string& path);

		/*! Save the current database to the already created file.

		 	Note: CreateDatabase should have been called prior to calling this.

			\param data BinaryView to save the data of
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool SaveAutoSnapshot(BinaryView* data, Ref<SaveSettings> settings);

		/*! Save the current database to the already created file.

		    Note: CreateDatabase should have been called prior to calling this.

		    \param data BinaryView to save the data of
		    \param settings Special save options
		    \param progressCallback callback function to send save progress to
		    \return Whether the save was successful
		*/
		bool SaveAutoSnapshot(BinaryView* data,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);
		void GetSnapshotData(
		    Ref<KeyValueStore> data, Ref<KeyValueStore> cache, const std::function<bool(size_t, size_t)>& progress);
		void ApplySnapshotData(BinaryView* file, Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
		    const std::function<bool(size_t, size_t)>& progress, bool openForConfiguration = false,
		    bool restoreRawView = true);
		Ref<Database> GetDatabase();

		/*! Rebase the given BinaryView to a new address

			\param data BinaryView to rebase
		    \param address Address to rebase to
		    \return Whether the rebase was successful
		*/
		bool Rebase(BinaryView* data, uint64_t address);

		/*! Rebase the given BinaryView to a new address

			\param data BinaryView to rebase
		    \param address Address to rebase to
		    \param progressCallback Callback function to pass rebase progress to
		    \return Whether the rebase was successful
		*/
		bool Rebase(BinaryView* data, uint64_t address,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName,
								  const std::function<bool(size_t progress, size_t total)>& progressCallback);

		/*! Run a function in a context in which any changes made to analysis will be added to an undo state.
			If the function returns false or throws an exception, any changes made within will be reverted.

			\param func Function to run in undo context
			\return Return status of function
			\throws std::exception If the called function throws an exception
		 */
		bool RunUndoableTransaction(std::function<bool()> func);

		/*! Start recording actions taken so they can be undone at some point

			\param anonymousAllowed Legacy interop: prevent empty calls to CommitUndoActions from affecting this
			                        undo state. Specifically for RunUndoableTransaction.
			\return Id of UndoEntry created, for passing to either CommitUndoActions or RevertUndoActions
		*/
		[[nodiscard]] std::string BeginUndoActions(bool anonymousAllowed = true);

		/*!  Commit the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void CommitUndoActions(const std::string& id);

		/*!  Revert the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void RevertUndoActions(const std::string& id);

		/*!  Forget the actions since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void ForgetUndoActions(const std::string& id);

		/*! \return Whether it is possible to perform an Undo
		*/
		bool CanUndo();

		/*! Undo the last committed action in the undo database.
		*/
		bool Undo();

		/*! \return Whether it is possible to perform a Redo
		*/
		bool CanRedo();

		/*! Redo the last committed action in the undo database.
		*/
		bool Redo();

		std::vector<Ref<User>> GetUsers();
		std::vector<Ref<UndoEntry>> GetUndoEntries();
		std::vector<Ref<UndoEntry>> GetRedoEntries();
		Ref<UndoEntry> GetLastUndoEntry();
		Ref<UndoEntry> GetLastRedoEntry();
		std::optional<std::string> GetLastUndoEntryTitle();
		std::optional<std::string> GetLastRedoEntryTitle();
		void ClearUndoEntries();

		/*! Get the current View name, e.g. ``Linear:ELF``, ``Graph:PE``

		    \return The current view name
		*/
		std::string GetCurrentView();

		/*! Get the current offset in the current view

		    \return The current offset
		*/
		uint64_t GetCurrentOffset();

		/*! Navigate to the specified virtual address in the specified view

		 	\param view View name. e.g. ``Linear:ELF``, ``Graph:PE``
		 	\param offset Virtual address to navigate to
		 	\return Whether the navigation was successful.
		*/
		bool Navigate(const std::string& view, uint64_t offset);

		/*! Get the BinaryView for a specific View type

		    \param name View name. e.g. ``Linear:ELF``, ``Graph:PE``
		    \return The BinaryView, if it exists
		*/
		BinaryNinja::Ref<BinaryNinja::BinaryView> GetViewOfType(const std::string& name);

		/*! List of View names that exist within the current file

		    \return List of View Names
		*/
		std::vector<std::string> GetExistingViews() const;

		/*! Get the current Session ID for this file.

		 	\see This is used in Logger and LogRegistry to determine what tab logs are sent to.

		    \return Current Session ID
		*/
		size_t GetSessionId() const;

		/*! Explicitly unregister a binary view of the given type from this file.

		    \note There is no need to unregister a binary view in ordinary situations. Binary views will be
		    automatically unregistered from the file when the file itself is about to be freed. Also, when a
		    binary view with the same type is created, the old one is automatically unregistered from the file.

		    Only use this function when you wish to explicitly remove the binary view from the file. For example,
		    in the debugger, this method is used to remove the Debugger view from the file after the target exits.

		    This also does not necessarily free the binary, because there could be other references to it.

		    \param type the type of the view to unregister
		    \param data the binary view to unregister
		*/
		void UnregisterViewOfType(const std::string& type, BinaryNinja::Ref<BinaryNinja::BinaryView> data);

		Ref<ProjectFile> GetProjectFile() const;
		void SetProjectFile(Ref<ProjectFile> projectFile);
	};

	class Function;
	struct DataVariable;
	class Tag;
	class TagType;
	struct TagReference;
	class Section;
	class Segment;
	class Component;
	class TypeArchive;

	/*!

		\ingroup binaryview
	*/
	class BinaryDataNotification
	{
	  private:
		BNBinaryDataNotification m_callbacks;

		static uint64_t NotificationBarrierCallback(void* ctxt, BNBinaryView* object);
		static void DataWrittenCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataInsertedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataRemovedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, uint64_t len);
		static void FunctionAddedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionRemovedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionUpdatedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionUpdateRequestedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void DataVariableAddedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void DataVariableRemovedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void DataVariableUpdatedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void SymbolAddedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolRemovedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolUpdatedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);

		static void DataMetadataUpdatedCallback(void* ctxt, BNBinaryView* object, uint64_t offset);
		static void TagTypeUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagType* tagType);
		static void TagAddedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagRemovedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);

		static void StringFoundCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void StringRemovedCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeReferenceChangedCallback(void* ctx, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeFieldReferenceChangedCallback(void* ctx, BNBinaryView* data, BNQualifiedName* name, uint64_t offset);
		static void SegmentAddedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SegmentRemovedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SegmentUpdatedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);

		static void SectionAddedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void SectionRemovedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void SectionUpdatedCallback(void* ctx, BNBinaryView* data, BNSection* section);

		static void ComponentNameUpdatedCallback(void* ctxt, BNBinaryView* data, char* previousName, BNComponent* component);
		static void ComponentAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component);
		static void ComponentRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* formerParent, BNComponent* component);
		static void ComponentMovedCallback(void* ctxt, BNBinaryView* data, BNComponent* formerParent, BNComponent* newParent, BNComponent* component);
		static void ComponentFunctionAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNFunction* function);
		static void ComponentFunctionRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNFunction* function);
		static void ComponentDataVariableAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNDataVariable* var);
		static void ComponentDataVariableRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNDataVariable* var);

		static void ExternalLibraryAddedCallback(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		static void ExternalLibraryUpdatedCallback(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		static void ExternalLibraryRemovedCallback(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		static void ExternalLocationAddedCallback(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		static void ExternalLocationUpdatedCallback(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		static void ExternalLocationRemovedCallback(void* ctxt, BNBinaryView* data, BNExternalLocation* location);

		static void TypeArchiveAttachedCallback(void* ctxt, BNBinaryView* data, const char* id, const char* path);
		static void TypeArchiveDetachedCallback(void* ctxt, BNBinaryView* data, const char* id, const char* path);
		static void TypeArchiveConnectedCallback(void* ctxt, BNBinaryView* data, BNTypeArchive* archive);
		static void TypeArchiveDisconnectedCallback(void* ctxt, BNBinaryView* data, BNTypeArchive* archive);

		static void UndoEntryAddedCallback(void* ctxt, BNBinaryView* data, BNUndoEntry* entry);
		static void UndoEntryTakenCallback(void* ctxt, BNBinaryView* data, BNUndoEntry* entry);
		static void RedoEntryTakenCallback(void* ctxt, BNBinaryView* data, BNUndoEntry* entry);

		static void RebasedCallback(void* ctxt, BNBinaryView* oldView, BNBinaryView* newView);

	  public:

		enum NotificationType : uint64_t
		{
			NotificationBarrier = 1ULL << 0,
			DataWritten = 1ULL << 1,
			DataInserted = 1ULL << 2,
			DataRemoved = 1ULL << 3,
			FunctionAdded = 1ULL << 4,
			FunctionRemoved = 1ULL << 5,
			FunctionUpdated = 1ULL << 6,
			FunctionUpdateRequested = 1ULL << 7,
			DataVariableAdded = 1ULL << 8,
			DataVariableRemoved = 1ULL << 9,
			DataVariableUpdated = 1ULL << 10,
			DataMetadataUpdated = 1ULL << 11,
			TagTypeUpdated = 1ULL << 12,
			TagAdded = 1ULL << 13,
			TagRemoved = 1ULL << 14,
			TagUpdated = 1ULL << 15,
			SymbolAdded = 1ULL << 16,
			SymbolRemoved = 1ULL << 17,
			SymbolUpdated = 1ULL << 18,
			StringFound = 1ULL << 19,
			StringRemoved = 1ULL << 20,
			TypeDefined = 1ULL << 21,
			TypeUndefined = 1ULL << 22,
			TypeReferenceChanged = 1ULL << 23,
			TypeFieldReferenceChanged = 1ULL << 24,
			SegmentAdded = 1ULL << 25,
			SegmentRemoved = 1ULL << 26,
			SegmentUpdated = 1ULL << 27,
			SectionAdded = 1ULL << 28,
			SectionRemoved = 1ULL << 29,
			SectionUpdated = 1ULL << 30,
			ComponentNameUpdated = 1ULL << 31,
			ComponentAdded = 1ULL << 32,
			ComponentRemoved = 1ULL << 33,
			ComponentMoved = 1ULL << 34,
			ComponentFunctionAdded = 1ULL << 35,
			ComponentFunctionRemoved = 1ULL << 36,
			ComponentDataVariableAdded = 1ULL << 37,
			ComponentDataVariableRemoved = 1ULL << 38,
			ExternalLibraryAdded = 1ULL << 39,
			ExternalLibraryRemoved = 1ULL << 40,
			ExternalLibraryUpdated = 1ULL << 41,
			ExternalLocationAdded = 1ULL << 42,
			ExternalLocationRemoved = 1ULL << 43,
			ExternalLocationUpdated = 1ULL << 44,
			TypeArchiveAttached = 1ULL << 45,
			TypeArchiveDetached = 1ULL << 46,
			TypeArchiveConnected = 1ULL << 47,
			TypeArchiveDisconnected = 1ULL << 48,
			UndoEntryAdded = 1ULL << 49,
			UndoEntryTaken = 1ULL << 50,
			RedoEntryTaken = 1ULL << 51,
			Rebased = 1ULL << 52,

			BinaryDataUpdates = DataWritten | DataInserted | DataRemoved,
			FunctionLifetime = FunctionAdded | FunctionRemoved,
			FunctionUpdates = FunctionLifetime | FunctionUpdated,
			DataVariableLifetime = DataVariableAdded | DataVariableRemoved,
			DataVariableUpdates = DataVariableLifetime | DataVariableUpdated,
			TagLifetime = TagAdded | TagRemoved,
			TagUpdates = TagLifetime | TagUpdated,
			SymbolLifetime = SymbolAdded | SymbolRemoved,
			SymbolUpdates = SymbolLifetime | SymbolUpdated,
			StringUpdates = StringFound | StringRemoved,
			TypeLifetime = TypeDefined | TypeUndefined,
			TypeUpdates = TypeLifetime | TypeReferenceChanged | TypeFieldReferenceChanged,
			SegmentLifetime = SegmentAdded | SegmentRemoved,
			SegmentUpdates = SegmentLifetime | SegmentUpdated,
			SectionLifetime = SectionAdded | SectionRemoved,
			SectionUpdates = SectionLifetime | SectionUpdated,
			ComponentUpdates = ComponentNameUpdated | ComponentAdded | ComponentRemoved | ComponentMoved | ComponentFunctionAdded | ComponentFunctionRemoved | ComponentDataVariableAdded | ComponentDataVariableRemoved,
			ExternalLibraryLifetime = ExternalLibraryAdded | ExternalLibraryRemoved,
			ExternalLibraryUpdates = ExternalLibraryLifetime | ExternalLibraryUpdated,
			ExternalLocationLifetime = ExternalLocationAdded | ExternalLocationRemoved,
			ExternalLocationUpdates = ExternalLocationLifetime | ExternalLocationUpdated,
			TypeArchiveUpdates = TypeArchiveAttached | TypeArchiveDetached | TypeArchiveConnected | TypeArchiveDisconnected,
			UndoUpdates = UndoEntryAdded | UndoEntryTaken | RedoEntryTaken
		};

		using NotificationTypes = uint64_t;

		BinaryDataNotification();
		BinaryDataNotification(NotificationTypes notifications);

		virtual ~BinaryDataNotification() {}

		BNBinaryDataNotification* GetCallbacks() { return &m_callbacks; }

		virtual uint64_t OnNotificationBarrier(BinaryView* view)
		{
			(void)view;
			return 0;
		}
		virtual void OnBinaryDataWritten(BinaryView* view, uint64_t offset, size_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnBinaryDataInserted(BinaryView* view, uint64_t offset, size_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnBinaryDataRemoved(BinaryView* view, uint64_t offset, uint64_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnAnalysisFunctionAdded(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionRemoved(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionUpdated(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionUpdateRequested(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnDataVariableAdded(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataVariableRemoved(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataVariableUpdated(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataMetadataUpdated(BinaryView* view, uint64_t offset)
		{
			(void)view;
			(void)offset;
		}
		virtual void OnTagTypeUpdated(BinaryView* view, Ref<TagType> tagTypeRef)
		{
			(void)view;
			(void)tagTypeRef;
		}
		virtual void OnTagAdded(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnTagRemoved(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnTagUpdated(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnSymbolAdded(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnSymbolRemoved(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnSymbolUpdated(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnStringFound(BinaryView* data, BNStringType type, uint64_t offset, size_t len)
		{
			(void)data;
			(void)type;
			(void)offset;
			(void)len;
		}
		virtual void OnStringRemoved(BinaryView* data, BNStringType type, uint64_t offset, size_t len)
		{
			(void)data;
			(void)type;
			(void)offset;
			(void)len;
		}
		virtual void OnTypeDefined(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeUndefined(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeReferenceChanged(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeFieldReferenceChanged(BinaryView* data, const QualifiedName& name, uint64_t offset)
		{
			(void)data;
			(void)name;
			(void)offset;
		}
		virtual void OnSegmentAdded(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSegmentRemoved(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSegmentUpdated(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSectionAdded(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}
		virtual void OnSectionRemoved(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}
		virtual void OnSectionUpdated(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}

		/*! This notification is posted after the display name for a component is updated.

			\param data BinaryView the Component is contained in
		 	\param previousName Previous name of the component
			\param component The component which was modified.
		*/
		virtual void OnComponentNameUpdated(BinaryView* data, std::string& previousName, Component* component)
		{
			(void)data;
			(void)previousName;
			(void)component;
		}

		/*! This notification is posted after a Component is added to the tree.

		 	\param data BinaryView the Component was added to
		 	\param component Component which was added.
		*/
		virtual void OnComponentAdded(BinaryView* data, Component* component)
		{
			(void)data;
			(void)component;
		}

		/*! This notification is posted after a Component is removed from the tree.

		 	\param data BinaryView the Component was removed from
		 	\param formerParent Former parent of the Component
		 	\param component
		 	\parblock
		    The removed and now "dead" Component object.

		    This "dead" Component can no longer be moved to other components or have components added to it. It
		    should not be used after this point for storing any objects, and will be destroyed once no more references
		    are held to it.
		 	\endparblock
		*/
		virtual void OnComponentRemoved(BinaryView* data, Component* formerParent, Component* component)
		{
			(void)data;
			(void)formerParent;
			(void)component;
		}

		/*! This notification is posted whenever a component is moved from one component to another.

		    \param data BinaryView the Component was removed from
		    \param formerParent Former parent of the Component
		 	\param newParent New parent which the Component was moved to
		 	\param component The component that was moved.
		*/
		virtual void OnComponentMoved(BinaryView* data, Component* formerParent, Component* newParent, Component* component)
		{
			(void)data;
			(void)formerParent;
			(void)newParent;
			(void)component;
		}

		/*! This notification is posted whenever a Function is added to a Component

		 	\param data BinaryView containing the Component and Function
		 	\param component Component the Function was added to
		 	\param function The Function which was added
		*/
		virtual void OnComponentFunctionAdded(BinaryView* data, Component* component, Function* function)
		{
			(void)data;
			(void)component;
			(void)function;
		}

		/*! This notification is posted whenever a Function is removed from a Component

		 	\param data BinaryView containing the Component and Function
		 	\param component Component the Function was removed from
		 	\param function The Function which was removed
		*/
		virtual void OnComponentFunctionRemoved(BinaryView* data, Component* component, Function* function)
		{
			(void)data;
			(void)component;
			(void)function;
		}

		/*! This notification is posted whenever a DataVariable is added to a Component

		    \param data BinaryView containing the Component and DataVariable
		    \param component Component the DataVariable was added to
		    \param var The DataVariable which was added
		 */
		virtual void OnComponentDataVariableAdded(BinaryView* data, Component* component, const DataVariable& var)
		{
			(void)data;
			(void)component;
			(void)var;
		}

		/*! This notification is posted whenever a DataVariable is removed from a Component

		    \param data BinaryView containing the Component and DataVariable
		    \param component Component the DataVariable was removed from
		    \param var The DataVariable which was removed
		 */
		virtual void OnComponentDataVariableRemoved(BinaryView* data, Component* component, const DataVariable& var)
		{
			(void)data;
			(void)component;
			(void)var;
		}

		virtual void OnExternalLibraryAdded(BinaryView* data, ExternalLibrary* library)
		{
			(void)data;
			(void)library;
		}

		virtual void OnExternalLibraryRemoved(BinaryView* data, ExternalLibrary* library)
		{
			(void)data;
			(void)library;
		}

		virtual void OnExternalLibraryUpdated(BinaryView* data, ExternalLibrary* library)
		{
			(void)data;
			(void)library;
		}

		virtual void OnExternalLocationAdded(BinaryView* data, ExternalLocation* location)
		{
			(void)data;
			(void)location;
		}

		virtual void OnExternalLocationRemoved(BinaryView* data, ExternalLocation* location)
		{
			(void)data;
			(void)location;
		}

		virtual void OnExternalLocationUpdated(BinaryView* data, ExternalLocation* location)
		{
			(void)data;
			(void)location;
		}

		/*! This notification is posted whenever a Type Archive is attached to a Binary View

		    \param data BinaryView target
		    \param id Id of the attached archive
		    \param path Path on disk of the attached archive
		 */
		virtual void OnTypeArchiveAttached(BinaryView* data, const std::string& id, const std::string& path)
		{
			(void)data;
			(void)id;
			(void)path;
		}

		/*! This notification is posted whenever a Type Archive is detached to a Binary View

		    \param data BinaryView target
		    \param id Id of the attached archive
		    \param path Path on disk of the attached archive
		 */
		virtual void OnTypeArchiveDetached(BinaryView* data, const std::string& id, const std::string& path)
		{
			(void)data;
			(void)id;
			(void)path;
		}
		/*! This notification is posted whenever a previously disconnected Type Archive
		    attached to the Binary View is connected

		    \param data BinaryView the archive is attached to
		    \param archive Attached archive
		 */
		virtual void OnTypeArchiveConnected(BinaryView* data, TypeArchive* archive)
		{
			(void)data;
			(void)archive;
		}
		/*! This notification is posted whenever a previously connected Type Archive
		    attached to the Binary View is disconnected

		    \param data BinaryView the archive is attached to
		    \param archive Previously attached archive
		 */
		virtual void OnTypeArchiveDisconnected(BinaryView* data, TypeArchive* archive)
		{
			(void)data;
			(void)archive;
		}

		/*! This notification is posted whenever an entry is added to undo history

		    \param data BinaryView the action was taken on
		    \param entry UndoEntry
		 */
		virtual void OnUndoEntryAdded(BinaryView* data, UndoEntry* entry)
		{
			(void)data;
			(void)entry;
		}

		/*! This notification is posted whenever an action is undone

		    \param data BinaryView the action was taken on
		    \param entry UndoEntry that was undone
		 */
		virtual void OnUndoEntryTaken(BinaryView* data, UndoEntry* entry)
		{
			(void)data;
			(void)entry;
		}

		/*! This notification is posted whenever an action is redone

		    \param data BinaryView the action was taken on
		    \param entry UndoEntry that was redone
		 */
		virtual void OnRedoEntryTaken(BinaryView* data, UndoEntry* entry)
		{
			(void)data;
			(void)entry;
		}

		/*! This notification is posted whenever a binary view is rebased

		    \param oldView BinaryView the old view
		    \param newView BinaryView the new view
		 */
		virtual void OnRebased(BinaryView* oldView, BinaryView* newView)
		{
			(void)oldView;
			(void)newView;
		}
	};

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

	class Function;
	class BasicBlock;

	/*!

		\ingroup namelist
	*/
	class NameList
	{
	  protected:
		std::string m_join;
		std::vector<std::string> m_name;

	  public:
		NameList(const BNQualifiedName* name);
		explicit NameList(const std::string& join, size_t size = 0);
		NameList(const std::string& name, const std::string& join);
		NameList(const std::vector<std::string>& name, const std::string& join);
		NameList(const NameList& name, const std::string& join);
		NameList(const NameList& name);
		virtual ~NameList();

		virtual NameList& operator=(const std::string& name);
		virtual NameList& operator=(const std::vector<std::string>& name);
		virtual NameList& operator=(const NameList& name);

		virtual bool operator==(const NameList& other) const;
		virtual bool operator!=(const NameList& other) const;
		virtual bool operator<(const NameList& other) const;
		virtual bool operator>(const NameList& other) const;

		virtual NameList operator+(const NameList& other) const;

		virtual std::string& operator[](size_t i);
		virtual const std::string& operator[](size_t i) const;
		virtual std::vector<std::string>::iterator begin();
		virtual std::vector<std::string>::iterator end();
		virtual std::vector<std::string>::const_iterator begin() const;
		virtual std::vector<std::string>::const_iterator end() const;
		virtual std::string& front();
		virtual const std::string& front() const;
		virtual std::string& back();
		virtual const std::string& back() const;
		virtual void insert(std::vector<std::string>::iterator loc, const std::string& name);
		virtual void insert(std::vector<std::string>::iterator loc, std::vector<std::string>::iterator b,
		    std::vector<std::string>::iterator e);
		virtual void erase(std::vector<std::string>::iterator i);
		virtual void clear();
		virtual void push_back(const std::string& name);
		virtual size_t size() const;
		virtual size_t StringSize() const;

		virtual std::string GetString(BNTokenEscapingType escaping = NoTokenEscapingType) const;
		virtual std::string GetJoinString() const { return m_join; }
		virtual bool IsEmpty() const { return m_name.size() == 0; }

		static std::string EscapeTypeName(const std::string& name, BNTokenEscapingType escaping);
		static std::string UnescapeTypeName(const std::string& name, BNTokenEscapingType escaping);

		BNNameList GetAPIObject() const;
		static void FreeAPIObject(BNNameList* name);
		static NameList FromAPIObject(BNNameList* name);
	};

	/*!

		\ingroup namelist
	*/
	class QualifiedName : public NameList
	{
		using NameList::operator+;
		using NameList::operator=;
	  public:

		QualifiedName();
		QualifiedName(const BNQualifiedName* name);
		QualifiedName(const std::string& name);
		QualifiedName(const std::vector<std::string>& name);
		QualifiedName(const QualifiedName& name);
		virtual ~QualifiedName();

		virtual QualifiedName& operator=(const std::string& name);
		virtual QualifiedName& operator=(const std::vector<std::string>& name);
		virtual QualifiedName& operator=(const QualifiedName& name);
		virtual QualifiedName operator+(const QualifiedName& other) const;

		BNQualifiedName GetAPIObject() const;
		static void FreeAPIObject(BNQualifiedName* name);
		static QualifiedName FromAPIObject(const BNQualifiedName* name);
	};

	/*!

		\ingroup namelist
	*/
	class NameSpace : public NameList
	{
		using NameList::operator+;
		using NameList::operator=;
	  public:

		NameSpace();
		NameSpace(const std::string& name);
		NameSpace(const std::vector<std::string>& name);
		NameSpace(const NameSpace& name);
		virtual ~NameSpace();

		virtual NameSpace& operator=(const std::string& name);
		virtual NameSpace& operator=(const std::vector<std::string>& name);
		virtual NameSpace& operator=(const NameSpace& name);
		virtual NameSpace operator+(const NameSpace& other) const;

		virtual bool IsDefaultNameSpace() const;
		BNNameSpace GetAPIObject() const;
		static void FreeAPIObject(BNNameSpace* name);
		static NameSpace FromAPIObject(const BNNameSpace* name);
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

	struct FunctionViewType
	{
		BNFunctionGraphType type;
		std::string name;

		FunctionViewType() : type(NormalFunctionGraph) {}
		FunctionViewType(BNFunctionGraphType viewType);
		FunctionViewType(const std::string& langName) :
			type(HighLevelLanguageRepresentationFunctionGraph), name(langName)
		{}
		FunctionViewType(const BNFunctionViewType& viewType);

		BNFunctionViewType ToAPIObject() const;

		BNFunctionGraphType GetBackingILType() const;

		bool IsValidForView(BinaryView* view) const;

		bool operator==(const FunctionViewType& other) const;
		bool operator!=(const FunctionViewType& other) const;
		bool operator<(const FunctionViewType& other) const;
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

	/*!
		\ingroup binaryview
	*/
	class AnalysisCompletionEvent :
	    public CoreRefCountObject<BNAnalysisCompletionEvent, BNNewAnalysisCompletionEventReference,
	        BNFreeAnalysisCompletionEvent>
	{
	  protected:
		std::function<void()> m_callback;
		std::recursive_mutex m_mutex;

		static void CompletionCallback(void* ctxt);

	  public:
		AnalysisCompletionEvent(BinaryView* view, const std::function<void()>& callback);
		void Cancel();
	};

	/*!
		\ingroup binaryview
	*/
	struct ActiveAnalysisInfo
	{
		Ref<Function> func;
		uint64_t analysisTime;
		size_t updateCount;
		size_t submitCount;

		ActiveAnalysisInfo(Ref<Function> f, uint64_t t, size_t uc, size_t sc) :
		    func(f), analysisTime(t), updateCount(uc), submitCount(sc)
		{}
	};

	/*!
		\ingroup binaryview
	*/
	struct AnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		std::vector<ActiveAnalysisInfo> activeInfo;
	};

	/*!
		\ingroup binaryview
	*/
	struct DataVariable
	{
		DataVariable() {}
		DataVariable(uint64_t a, Type* t, bool d) : address(a), type(t), autoDiscovered(d) {}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
	};

	/*!
		\ingroup binaryview
	*/
	struct DataVariableAndName
	{
		DataVariableAndName() {}
		DataVariableAndName(uint64_t a, Type* t, bool d, const std::string& n) :
		    address(a), type(t), autoDiscovered(d), name(n)
		{}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
		std::string name;
	};

	/*!
		\ingroup binaryview
	*/
	class TagType : public CoreRefCountObject<BNTagType, BNNewTagTypeReference, BNFreeTagType>
	{
	  public:
		typedef BNTagTypeType Type;

		TagType(BNTagType* tagType);
		TagType(BinaryView* view);
		TagType(BinaryView* view, const std::string& name, const std::string& icon, bool visible = true,
		    Type type = UserTagType);

		/*!
			\return BinaryView for this TagType
		*/
		BinaryView* GetView() const;

		/*!
		    \return Unique ID of the TagType
		*/
		std::string GetId() const;

		/*!
		    \return Name of the TagType
		*/
		std::string GetName() const;

		/*!
		    Set the name of the TagType

		    \param name New name
		*/
		void SetName(const std::string& name);

		/*!
		    \return Unicode string containing an emoji to be used as an icon
		*/
		std::string GetIcon() const;

		/*!
		    Set the icon to be used for a TagType

		    \param icon Unicode string containing an emoji to be used as an icon
		*/
		void SetIcon(const std::string& icon);

		/*!
		    \return Whether the tags of this type are visible
		*/
		bool GetVisible() const;

		/*!
		    Set whether the tags of this type are visible

		    \param visible Whether the tags of this type are visible
		*/
		void SetVisible(bool visible);

		/*!
			One of: UserTagType, NotificationTagType, BookmarksTagType

			\return Tag Type.
		*/
		Type GetType() const;

		/*!
		    \param type Tag Type. One of: UserTagType, NotificationTagType, BookmarksTagType
		*/
		void SetType(Type type);
	};

	class Tag : public CoreRefCountObject<BNTag, BNNewTagReference, BNFreeTag>
	{
	  public:
		Tag(BNTag* tag);
		Tag(Ref<TagType> type, const std::string& data = "");

		/*!
		    \return Unique ID of the Tag
		*/
		std::string GetId() const;

		/*!
		    \return TagType of this tag
		*/
		Ref<TagType> GetType() const;
		std::string GetData() const;
		void SetData(const std::string& data);

		static BNTag** CreateTagList(const std::vector<Ref<Tag>>& tags, size_t* count);
		static std::vector<Ref<Tag>> ConvertTagList(BNTag** tags, size_t count);
		static void FreeTagList(BNTag** tags, size_t count);
		static std::vector<Ref<Tag>> ConvertAndFreeTagList(BNTag** tags, size_t count);
	};

	class Architecture;
	class Function;

	/*!
		\ingroup binaryview
	*/
	struct TagReference
	{
		typedef BNTagReferenceType RefType;

		RefType refType;
		bool autoDefined;
		Ref<Tag> tag;
		Ref<Architecture> arch;
		Ref<Function> func;
		uint64_t addr;

		TagReference();
		TagReference(const BNTagReference& ref);

		bool EqualsByData(const TagReference& other) const;
		bool operator==(const TagReference& other) const;
		bool operator!=(const TagReference& other) const;

		operator BNTagReference() const;

		static BNTagReference* CreateTagReferenceList(const std::vector<TagReference>& tags, size_t* count);
		static std::vector<TagReference> ConvertTagReferenceList(BNTagReference* tags, size_t count);
		static void FreeTagReferenceList(BNTagReference* tags, size_t count);
		static std::vector<TagReference> ConvertAndFreeTagReferenceList(BNTagReference* tags, size_t count);
	};

	class Relocation;

	/*! The Segment object is returned during BinaryView creation and should not be directly instantiated.

		\ingroup binaryview
	*/
	class Segment : public CoreRefCountObject<BNSegment, BNNewSegmentReference, BNFreeSegment>
	{
	  public:
		Segment(BNSegment* seg);
		uint64_t GetStart() const;
		uint64_t GetLength() const;
		uint64_t GetEnd() const;
		uint64_t GetDataEnd() const;
		uint64_t GetDataOffset() const;
		uint64_t GetDataLength() const;
		uint32_t GetFlags() const;
		bool IsAutoDefined() const;
	};

	/*! The Section object is returned during BinaryView creation and should not be directly instantiated.

		\ingroup binaryview
	*/
	class Section : public CoreRefCountObject<BNSection, BNNewSectionReference, BNFreeSection>
	{
	  public:
		Section(BNSection* sec);
		Section(const std::string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
		    const std::string& type, uint64_t align, uint64_t entrySize, const std::string& linkedSection,
		    const std::string& infoSection, uint64_t infoData, bool autoDefined);
		std::string GetName() const;
		std::string GetType() const;
		uint64_t GetStart() const;
		uint64_t GetLength() const;
		uint64_t GetEnd() const;
		uint64_t GetInfoData() const;
		uint64_t GetAlignment() const;
		uint64_t GetEntrySize() const;
		std::string GetLinkedSection() const;
		std::string GetInfoSection() const;
		BNSectionSemantics GetSemantics() const;
		bool AutoDefined() const;
	};

	struct RegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		size_t size;

		bool operator==(const RegisterValue& a) const;
		bool operator!=(const RegisterValue& a) const;

		RegisterValue();

		bool IsConstant() const;
		bool IsConstantData() const;

		static RegisterValue FromAPIObject(const BNRegisterValue& value);
		BNRegisterValue ToAPIObject();
	};

	struct QualifiedNameAndType;
	struct PossibleValueSet;
	class Metadata;
	class Structure;
	struct ParsedType;
	struct TypeParserResult;
	class Component;
	class DebugInfo;
	class TypeLibrary;
	class TypeArchive;
	class MemoryMap;
	struct HighLevelILInstruction;

	class QueryMetadataException : public ExceptionWithStackTrace
	{
	  public:
		QueryMetadataException(const std::string& error) : ExceptionWithStackTrace(error) {}
	};

	/*! \c BinaryView implements a view on binary data, and presents a queryable interface of a binary file.

		One key job of BinaryView is file format parsing which allows Binary Ninja to read, write, insert, remove portions
		of the file given a virtual address. For the purposes of this documentation we define a virtual address as the
		memory address that the various pieces of the physical file will be loaded at.

		A binary file does not have to have just one BinaryView, thus much of the interface to manipulate disassembly exists
		within or is accessed through a BinaryView. All files are guaranteed to have at least the \c Raw BinaryView. The
		\c Raw BinaryView is simply a hex editor, but is helpful for manipulating binary files via their absolute addresses.

		BinaryViews are plugins and thus registered with Binary Ninja at startup, and thus should **never** be instantiated
		directly as this is already done. The list of available BinaryViews can be seen in the BinaryViewType class which
		provides an iterator and map of the various installed BinaryViews:

		\code{.cpp}
		// Getting a list of valid BinaryViewTypes
		vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypes()

		// Getting a list of valid BinaryViewTypes valid for given data
		vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypesForData(bv);

		Ref<BinaryViewType> machoType = BinaryViewType::GetByName("Mach-O");
		\endcode

		\see BinaryViewType

		\b In the python console:
		\code{.py}
		>>> list(BinaryViewType)
		[<view type: 'Raw'>, <view type: 'ELF'>, <view type: 'Mach-O'>, <view type: 'PE'>]
		>>> BinaryViewType['ELF']
		<view type: 'ELF'>
		\endcode

		To open a file with a given BinaryView the following code is recommended:

		\code{.cpp}
		auto bv = Load("/bin/ls");
		\endcode

		\remark By convention in the rest of this document we will use bv to mean an open and, analyzed, BinaryView of an executable file.

		When a BinaryView is open on an executable view analysis is automatically run unless specific named parameters are used
		to disable updates. If such a parameter is used, updates can be triggered using the \c UpdateAnalysisAndWait() method
		which disassembles the executable and returns when all disassembly and analysis is complete:

		\code{.cpp}
		bv->UpdateAnalysisAndWait();
		\endcode

		Since BinaryNinja's analysis is multi-threaded this can also be done in the background
		by using the \c UpdateAnalysis method instead.

		\note An important note on the \c \*User\*() methods. Binary Ninja makes a distinction between edits
		performed by the user and actions performed by auto analysis.  Auto analysis actions that can quickly be recalculated
		are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the
		database (e.g. \c RemoveUserFunction rather than \c RemoveFunction ). Thus use \c \*User\*() methods if saving
		to the database is desired.

		\ingroup binaryview
	*/
	class BinaryView : public CoreRefCountObject<BNBinaryView, BNNewViewReference, BNFreeBinaryView>
	{
		std::unique_ptr<MemoryMap> m_memoryMap;

	  protected:
		Ref<FileMetadata> m_file;  //!< The underlying file

		/*! BinaryView constructor
		   \param typeName name of the BinaryView (e.g. ELF, PE, Mach-O, ...)
		   \param file a file to create a view from
		   \param parentView optional view that contains the raw data used by this view
		*/
		BinaryView(const std::string& typeName, FileMetadata* file, BinaryView* parentView = nullptr);

		/*! PerformRead provides a mapping between the flat file and virtual offsets in the file.

		    \note This method **may** be overridden by custom BinaryViews. Use AddAutoSegment to provide
		    	  data without overriding this method.

			\warning This method **must not** be called directly.

		    \param dest the address to write len number of bytes.
		    \param offset the virtual offset to find and read len bytes from
		    \param len the number of bytes to read from offset and write to dest
		*/
		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len)
		{
			(void)dest;
			(void)offset;
			(void)len;
			return 0;
		}

		/*! PerformWrite provides a mapping between the flat file and virtual offsets in the file.

		    \note This method **may** be overridden by custom BinaryViews. Use AddAutoSegment to provide
		          data without overriding this method.

			\warning This method **must not** be called directly.
		    \param offset the virtual offset to find and write len bytes to
		    \param data the address to read len number of bytes from
		    \param len the number of bytes to read from data and write to offset
		    \return length of data written, 0 on error
		*/
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}

		/*! PerformInsert provides a mapping between the flat file and virtual offsets in the file,
				inserting `len` bytes from `data` to virtual address `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual offset to find and insert len bytes into
		    \param data the address to read len number of bytes from
		    \param len the number of bytes to read from data and insert at offset
		    \return length of data inserted, 0 on error
		*/
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}

		/*! PerformRemove provides a mapping between the flat file and virtual offsets in the file,
		    	removing `len` bytes from virtual address `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

			\param offset the virtual offset to find and remove bytes from
		    \param len the number of bytes to be removed
		    \return length of data removed, 0 on error
		*/
		virtual size_t PerformRemove(uint64_t offset, uint64_t len)
		{
			(void)offset;
			(void)len;
			return 0;
		}

		/*! PerformGetModification implements a query as to whether the virtual address `offset` is modified.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		virtual BNModificationStatus PerformGetModification(uint64_t offset)
		{
			(void)offset;
			return Original;
		}

		/*! PerformIsValidOffset implements a check as to whether a virtual address `offset` is valid

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		virtual bool PerformIsValidOffset(uint64_t offset);

		/*! PerformIsOffsetReadable implements a check as to whether a virtual address is readable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		virtual bool PerformIsOffsetReadable(uint64_t offset);

		/*! PerformIsOffsetWritable implements a check as to whether a virtual address is writable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		virtual bool PerformIsOffsetWritable(uint64_t offset);

		/*! PerformIsOffsetExecutable implements a check as to whether a virtual address is executable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is executable
		*/
		virtual bool PerformIsOffsetExecutable(uint64_t offset);

		/*! PerformIsOffsetBackedByFile implements a check as to whether a virtual address is backed by a file

		    \param offset the virtual address to check
		    \return whether the offset is backed by a file
		*/
		virtual bool PerformIsOffsetBackedByFile(uint64_t offset);

		/*! PerformGetNextValidOffset implements a query for the next valid readable, writable, or executable virtual memory address after `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);

		/*! PerformGetStart implements a query for the first readable, writable, or executable virtual address in the BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return the first virtual address in the BinaryView
		*/
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }

		/*! PerformIsExecutable implements a check which returns true if the BinaryView is executable.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return whether the BinaryView is executable
		*/
		virtual bool PerformIsExecutable() const { return false; }

		/*! PerformGetDefaultEndianness implements a check which returns the Endianness of the BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return either LittleEndian or BigEndian
		*/
		virtual BNEndianness PerformGetDefaultEndianness() const;

		/*! PerformIsRelocatable implements a check which returns true if the BinaryView is relocatable.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return whether the BinaryView is relocatable
		*/
		virtual bool PerformIsRelocatable() const;

		/*! PerformGetAddressSize implements a query for the address size for this BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return the address size for this BinaryView
		*/
		virtual size_t PerformGetAddressSize() const;

		virtual bool PerformSave(FileAccessor* file);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> sym, uint64_t reloc);

	  public:
		void NotifyDataWritten(uint64_t offset, size_t len);
		void NotifyDataInserted(uint64_t offset, size_t len);
		void NotifyDataRemoved(uint64_t offset, uint64_t len);

	  private:
		static bool InitCallback(void* ctxt);
		static void FreeCallback(void* ctxt);
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t RemoveCallback(void* ctxt, uint64_t offset, uint64_t len);
		static BNModificationStatus GetModificationCallback(void* ctxt, uint64_t offset);
		static bool IsValidOffsetCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetReadableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetWritableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetExecutableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetBackedByFileCallback(void* ctxt, uint64_t offset);
		static uint64_t GetNextValidOffsetCallback(void* ctxt, uint64_t offset);
		static uint64_t GetStartCallback(void* ctxt);
		static uint64_t GetLengthCallback(void* ctxt);
		static uint64_t GetEntryPointCallback(void* ctxt);
		static bool IsExecutableCallback(void* ctxt);
		static BNEndianness GetDefaultEndiannessCallback(void* ctxt);
		static bool IsRelocatableCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static bool SaveCallback(void* ctxt, BNFileAccessor* file);

	  public:
		BinaryView(BNBinaryView* view);

		virtual bool Init() { return true; }


		/*!
			\return FileMetadata for this BinaryView
		*/
		FileMetadata* GetFile() const { return m_file; }

		/*!
		    \return View that contains the raw data used by this view
		*/
		Ref<BinaryView> GetParentView() const;
		std::string GetTypeName() const;

		/*!
			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*!
			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*! Writes the current database (.bndb) out to the specified file.

		 	\param path path and filename to write the bndb to. Should have ".bndb" appended to it.
		 	\param settings Special save options
		 	\return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& path, Ref<SaveSettings> settings = new SaveSettings());

		/*! Writes the current database (.bndb) out to the specified file.

		    \param path path and filename to write the bndb to. Should have ".bndb" appended to it.
		    \param progressCallback callback function to send save progress to.
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& path,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback,
		    Ref<SaveSettings> settings = new SaveSettings());
		bool SaveAutoSnapshot(Ref<SaveSettings> settings = new SaveSettings());
		bool SaveAutoSnapshot(const std::function<bool(size_t progress, size_t total)>& progressCallback,
		    Ref<SaveSettings> settings = new SaveSettings());

		/*! Run a function in a context in which any changes made to analysis will be added to an undo state.
			If the function returns false or throws an exception, any changes made within will be reverted.

			\param func Function to run in undo context
			\return Return status of function
			\throws std::exception If the called function throws an exception
		 */
		bool RunUndoableTransaction(std::function<bool()> func);

		/*! Start recording actions taken so they can be undone at some point

			\param anonymousAllowed Legacy interop: prevent empty calls to CommitUndoActions from affecting this
			                        undo state. Specifically for RunUndoableTransaction.
			\return Id of UndoEntry created, for passing to either CommitUndoActions or RevertUndoActions
		*/
		[[nodiscard]] std::string BeginUndoActions(bool anonymousAllowed = true);

		/*!  Commit the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void CommitUndoActions(const std::string& id);

		/*!  Revert the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void RevertUndoActions(const std::string& id);

		/*!  Forget the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void ForgetUndoActions(const std::string& id);

		/*!
			\return Whether it is possible to perform an Undo
		*/
		bool CanUndo();

		/*! Undo the last committed action in the undo database.
		*/
		bool Undo();

		/*!
			\return Whether it is possible to perform a Redo
		*/
		bool CanRedo();

		/*! Redo the last committed action in the undo database.
		*/
		bool Redo();

		/*!
		    Get the current View name, e.g. ``Linear:ELF``, ``Graph:PE``

		    \return The current view name
		*/
		std::string GetCurrentView();

		/*!
		    Get the current offset in the current view

		    \return The current offset
		*/
		uint64_t GetCurrentOffset();

		/*!
			Navigate to the specified virtual address in the specified view

		 	\param view View name. e.g. ``Linear:ELF``, ``Graph:PE``
		 	\param offset Virtual address to navigate to
		 	\return Whether the navigation was successful.
		*/
		bool Navigate(const std::string& view, uint64_t offset);

		/*! Read writes `len` bytes at virtual address `offset` to address `dest`

		    \param dest Virtual address to write to
		    \param offset virtual address to read from
		    \param len number of bytes to read
		    \return amount of bytes read
		*/
		size_t Read(void* dest, uint64_t offset, size_t len);

		/*! ReadBuffer reads len bytes from a virtual address into a DataBuffer

		    \param offset virtual address to read from
		    \param len number of bytes to read
		    \return DataBuffer containing the read bytes
		*/
		DataBuffer ReadBuffer(uint64_t offset, size_t len);

		/*! Write writes `len` bytes data at address `dest` to virtual address `offset`

			\param offset virtual address to write to
			\param data address to read from
			\param len number of bytes to write
			\return amount of bytes written
		*/
		size_t Write(uint64_t offset, const void* data, size_t len);

		/*! WriteBuffer writes the contents of a DataBuffer into a virtual address

			\param offset virtual address to write to
		    \param data DataBuffer containing the bytes to write
		    \return amount of bytes written
		*/
		size_t WriteBuffer(uint64_t offset, const DataBuffer& data);

		/*! Insert inserts `len` bytes data at address `dest` starting from virtual address `offset`

			\param offset virtual address to start inserting from
			\param data address to read from
			\param len number of bytes to write
			\return amount of bytes written
		*/
		size_t Insert(uint64_t offset, const void* data, size_t len);

		/*! InsertBuffer inserts the contents of a DataBuffer starting from a virtual address

			\param offset virtual address to start inserting from
		    \param data DataBuffer containing the bytes to write
		    \return amount of bytes written
		*/
		size_t InsertBuffer(uint64_t offset, const DataBuffer& data);

		/*! PerformRemove removes `len` bytes from virtual address `offset`

			\param offset the virtual offset to find and remove bytes from
		    \param len the number of bytes to be removed
		    \return length of data removed, 0 on error
		*/
		size_t Remove(uint64_t offset, uint64_t len);

		std::vector<float> GetEntropy(uint64_t offset, size_t len, size_t blockSize);

		/*! GetModification checks whether the virtual address `offset` is modified.

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		BNModificationStatus GetModification(uint64_t offset);
		std::vector<BNModificationStatus> GetModification(uint64_t offset, size_t len);

		/*! IsValidOffset checks whether a virtual address `offset` is valid

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		bool IsValidOffset(uint64_t offset) const;

		/*! IsOffsetReadable checks whether a virtual address is readable

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		bool IsOffsetReadable(uint64_t offset) const;

		/*! IsOffsetWritable checks whether a virtual address is writable

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		bool IsOffsetWritable(uint64_t offset) const;

		/*! IsOffsetExecutable checks whether a virtual address is executable

		    \param offset the virtual address to check
		    \return whether the offset is executable
		*/
		bool IsOffsetExecutable(uint64_t offset) const;

		/*! IsOffsetBackedByFile checks whether a virtual address is backed by a file

		    \param offset the virtual address to check
		    \return whether the offset is backed by a file
		*/
		bool IsOffsetBackedByFile(uint64_t offset) const;
		bool IsOffsetCodeSemantics(uint64_t offset) const;
		bool IsOffsetWritableSemantics(uint64_t offset) const;
		bool IsOffsetExternSemantics(uint64_t offset) const;

		/*! GetNextValidOffset implements a query for the next valid readable, writable, or executable virtual memory address after `offset`

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		uint64_t GetNextValidOffset(uint64_t offset) const;

		/*! GetImageBase queries for the image base in the BinaryView

		    \return the image base of the BinaryView
		*/
		uint64_t GetImageBase() const;

		/*! GetOriginalImageBase queries for the original image base in the BinaryView, unaffected by any rebasing operations

		    \return the original image base of the BinaryView
		*/
		uint64_t GetOriginalImageBase() const;

		/*! SetOriginalBase sets the original image base in the BinaryView, unaffected by any rebasing operations.
		 * This is only intended to be used by Binary View implementations to provide this value. Regular users should
		 * NOT change this value.

		    \param imageBase the original image base of the binary view
		*/
		void SetOriginalImageBase(uint64_t imageBase);


		/*! GetOriginalBase queries for the original image base in the BinaryView, unaffected by any rebasing operations
		    \deprecated This API has been deprecated in favor of GetOriginalImageBase in 4.1.5902

		    \return the original image base of the BinaryView
		*/
		uint64_t GetOriginalBase() const;

		/*! SetOriginalBase sets the original image base in the BinaryView, unaffected by any rebasing operations.
		 * This is only intended to be used by Binary View implementations to provide this value. Regular users should
		 * NOT change this value.
		    \deprecated This API has been deprecated in favor of SetOriginalImageBase in 4.1.5902

		    \param base the original image base of the binary view
		*/
		void SetOriginalBase(uint64_t base);

		/*! GetStart queries for the first valid virtual address in the BinaryView

		    \return the start of the BinaryView
		*/
		uint64_t GetStart() const;

		/*! GetEnd queries for the end virtual address of the BinaryView

		    \return the end of the BinaryView
		*/
		uint64_t GetEnd() const;

		/*! GetLength queries for the total length of the BinaryView from start to end

		    \return the length of the BinaryView
		*/
		uint64_t GetLength() const;

		/*! GetEntryPoint returns the entry point of the executable in the BinaryView
					    \return the entry point
		*/
		uint64_t GetEntryPoint() const;

		/*! GetDefaultArchitecture returns the current "default architecture" for the BinaryView

		    \return the current default architecture
		*/
		Ref<Architecture> GetDefaultArchitecture() const;

		/*! SetDefaultArchitecture allows setting the default architecture for the BinaryView

		    \param arch the new default architecture
		*/
		void SetDefaultArchitecture(Architecture* arch);

		/*! GetDefaultPlatform returns the current default platform for the BinaryView

		    \return the current default Platform
		*/
		Ref<Platform> GetDefaultPlatform() const;

		/*! SetDefaultPlatform allows setting the default platform for the BinaryView

		    \param arch the new default platform
		*/
		void SetDefaultPlatform(Platform* platform);

		/*! GetDefaultEndianness returns the default endianness for the BinaryView

		    \return the current default Endianness, one of LittleEndian, BigEndian
		*/
		BNEndianness GetDefaultEndianness() const;

		/*! Whether the binary is relocatable

		    \return Whether the binary is relocatable
		*/
		bool IsRelocatable() const;

		/*! Address size of the binary

		    \return Address size of the binary
		*/
		size_t GetAddressSize() const;

		/*! Whether the binary is an executable

		    \return Whether the binary is an executable
		*/
		bool IsExecutable() const;

		/*! Save the original binary file to a FileAccessor

		    \param file a FileAccessor pointing to the location to save the binary
		    \return Whether the save was successful
		*/
		bool Save(FileAccessor* file);

		/*! Save the original binary file to the provided destination

		    \param path destination path and filename of the file to be written
		    \return Whether the save was successful
		*/
		bool Save(const std::string& path);

		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc);
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRanges() const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesAtAddress(uint64_t addr) const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesInRange(uint64_t addr, size_t size) const;
		bool RangeContainsRelocation(uint64_t addr, size_t size) const;
		std::vector<Ref<Relocation>> GetRelocationsAt(uint64_t addr) const;

		/*! Provides a mechanism for receiving callbacks for various analysis events.

		    \param notify An instance of a class Subclassing BinaryDataNotification
		*/
		void RegisterNotification(BinaryDataNotification* notify);

		/*! Unregister a notification passed to RegisterNotification

		    \param notify An instance of a class Subclassing BinaryDataNotification
		*/
		void UnregisterNotification(BinaryDataNotification* notify);

		/*! Adds an analysis option. Analysis options elaborate the analysis phase. The user must start analysis by calling either UpdateAnalysis or UpdateAnalysisAndWait

		    \param name Name of the analysis option. Available options are "linearsweep" and "signaturematcher"
		*/
		void AddAnalysisOption(const std::string& name);

		/*! Add a new function of the given platform at the virtual address

		    \param platform Platform for the function to be loaded
		    \param addr Virtual adddress of the function to be loaded
		    \param autoDiscovered true if function was automatically discovered, false if created by user
		    \param type optional function type
		*/
		Ref<Function> AddFunctionForAnalysis(
			Platform* platform, uint64_t addr, bool autoDiscovered = false, Type* type = nullptr);

		/*! adds an virtual address to start analysis from for a given platform

		    \param platform Platform for the entry point analysis
		    \param start virtual address to start analysis from
		*/
		void AddEntryPointForAnalysis(Platform* platform, uint64_t start);

		/*! adds an function to all entry function list

			\param func Function to add
		*/
		void AddToEntryFunctions(Function* func);

		/*! removes a function from the list of functions

		    \param func Function to be removed
		    \param updateRefs automatically update other functions that were referenced
		*/
		void RemoveAnalysisFunction(Function* func, bool updateRefs = false);

		/*! Add a new user function of the given platform at the virtual address

			\param platform Platform for the function to be loaded
		    \param addr Virtual adddress of the function to be loaded
		*/
		Ref<Function> CreateUserFunction(Platform* platform, uint64_t start);

		/*! removes a user function from the list of functions

		    \param func Function to be removed
		*/
		void RemoveUserFunction(Function* func);

		/*! check for the presence of an initial analysis in this BinaryView.

		    \return Whether the BinaryView has an initial analysis
		*/
		bool HasInitialAnalysis();

		/*! Controls the analysis hold for this BinaryView. Enabling analysis hold defers all future
		 	analysis updates, therefore causing UpdateAnalysis and UpdateAnalysisAndWait to take no action.

		    \param enable Whether to enable or disable the analysis hold
		*/
		void SetAnalysisHold(bool enable);

		bool GetFunctionAnalysisUpdateDisabled();
		void SetFunctionAnalysisUpdateDisabled(bool disabled);

		/*! start the analysis running and dont return till it is complete

			Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		 	UpdateAnalysis or UpdateAnalysisAndWait. An analysis update **must** be run after changes are made which could change
		    analysis results such as adding functions.
		*/
		void UpdateAnalysisAndWait();

		/*! asynchronously starts the analysis running and returns immediately.

			Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		 	UpdateAnalysis or UpdateAnalysisAndWait. An analysis update **must** be run after changes are made which could change
		    analysis results such as adding functions.
		*/
		void UpdateAnalysis();

		/*! Abort the currently running analysis

			This method should be considered non-recoverable and generally only used when shutdown is imminent after stopping.
		*/
		void AbortAnalysis();

		/*! Define a DataVariable at a given address with a set type

		    \param addr virtual address to define the DataVariable at
		    \param type Type for the DataVariable
		*/
		void DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);

		/*! Define a user DataVariable at a given address with a set type

		    \param addr virtual address to define the DataVariable at
		    \param type Type for the DataVariable
		*/
		void DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);

		/*! Undefine a DataVariable at a given address

		    \param addr virtual address of the DataVariable
		    \param blacklist whether to add the address to the data variable black list so that the auto analysis would
		    not recreate the variable on re-analysis
		*/
		void UndefineDataVariable(uint64_t addr, bool blacklist = true);

		/*! Undefine a user DataVariable at a given address

		    \param addr virtual address of the DataVariable
		*/
		void UndefineUserDataVariable(uint64_t addr);

		/*! Get a map of DataVariables defined in the current BinaryView

		    \return A map of addresses to the DataVariables defined at them
		*/
		std::map<uint64_t, DataVariable> GetDataVariables();

		/*! Get a DataVariable at a given address

		    \param addr Address for the DataVariable
		    \param var Reference to a DataVariable class to write to
		    \return Whether a DataVariable was successfully retrieved
		*/
		bool GetDataVariableAtAddress(uint64_t addr, DataVariable& var);

		/*! Get a list of functions within this BinaryView

		    \return vector of Functions within the BinaryView
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionList();

		/*! Check whether the BinaryView has any functions defined

		    \return Whether the BinaryView has any functions defined
		*/
		bool HasFunctions() const;


		/*! Gets a function object for the function starting at a virtual address

		    \param platform Platform for the desired function
		    \param addr Starting virtual address for the function
		    \return the Function, if it exists
		*/
		Ref<Function> GetAnalysisFunction(Platform* platform, uint64_t addr);

		/*! Get the most recently used Function starting at a virtual address

		    \param addr Starting virtual address for the function
		    \return the Function, if it exists
		*/
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);

		/*! Get a list of functions defined at an address

		    \param addr Starting virtual address for the function
		    \return vector of functions
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);

		/*! Get a list of functions containing an address

		    \param addr Address to check
		    \return vector of Functions
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionsContainingAddress(uint64_t addr);

		/*! Get the function defined as the Analysis entry point for the view

		    \return The analysis entry point function
		*/
		Ref<Function> GetAnalysisEntryPoint();

		/*! Get all entry functions (including user-defined ones)

		    \return vector of Functions
		*/
		std::vector<Ref<Function>> GetAllEntryFunctions();

		/*! Get most recently used Basic Block containing a virtual address

		    \param addr Address within the BasicBlock
		    \return The BasicBlock if it exists
		*/
		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);

		/*! Get a list of Basic Blocks containing a virtual address

		    \param addr Address to check
		    \return vector of basic blocks containing that address
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);

		/*! Get a list of basic blocks starting at a virtual address

		    \param addr Address to check
		    \return vector of basic blocks starting at that address
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocksStartingAtAddress(uint64_t addr);

		/*! Get a list of references made from code (instructions) to a virtual address

		    \param addr Address to check
		    \return vector of ReferenceSources referencing the virtual address
		*/
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);

		/*! Get a list of references from code (instructions) to a range of addresses

		    \param addr Address to check
		    \param len Length of query
		    \return vector of ReferenceSources referencing the virtual address range
		*/
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr, uint64_t len);

		/*! Get code references made by a particular "ReferenceSource"

			A ReferenceSource contains a given function, architecture of that function, and an address within it.

		    \param src reference source
		    \return List of virtual addresses referenced by this source
		*/
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src);

		/*! Get code references from a range of addresses.

			A ReferenceSource contains a given function, architecture of that function, and an address within it.

			The 2nd parameter is the length of the range. The start of the range is set in ReferenceSource::addr

		    \param src reference source
		    \param len Length of query
		    \return List of virtual addresses referenced by this source
		*/
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src, uint64_t len);

		/*! Get references made by data ('DataVariables') to a virtual address

		    \param addr Address to check
		    \return vector of virtual addresses referencing the virtual address
		*/
		std::vector<uint64_t> GetDataReferences(uint64_t addr);

		/*! Get references made by data ('DataVariables') in a given range, to a virtual address

		    \param addr Address to check
		    \param len Length of query
		    \return vector of virtual addresses referencing the virtual address range
		*/
		std::vector<uint64_t> GetDataReferences(uint64_t addr, uint64_t len);

		/*! Get references made by data ('DataVariables') located at a virtual address.

		    \param src reference source
		    \return List of virtual addresses referenced by this address
		*/
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr);

		/*! Get references made by data ('DataVariables') located in a range of virtual addresses.

		    \param src reference source
		    \param len Length of query
		    \return List of virtual addresses referenced by this address
		*/
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr, uint64_t len);

		/*! Add a user Data Reference from a virtual address to another virtual address

		    \param fromAddr Address referencing the toAddr value
		    \param toAddr virtual address being referenced
		*/
		void AddUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		/*! Remove a user Data Reference from a virtual address to another virtual address

		    \param fromAddr Address referencing the toAddr value
		    \param toAddr virtual address being referenced
		*/
		void RemoveUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		// References to type

		/*! Get code references to a Type

		    \param type QualifiedName for a Type
		    \return vector of ReferenceSources
		*/
		std::vector<ReferenceSource> GetCodeReferencesForType(const QualifiedName& type);

		/*! Get data references to a Type

		    \param type QualifiedName for a Type
		    \return vector of virtual addresses referencing this Type
		*/
		std::vector<uint64_t> GetDataReferencesForType(const QualifiedName& type);

		/*! Get Type references to a Type

		    \param type QualifiedName for a Type
		    \return vector of TypeReferenceSources to this Type
		*/
		std::vector<TypeReferenceSource> GetTypeReferencesForType(const QualifiedName& type);

		/*! Returns a list of references to a specific type field

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return vector of TypeFieldReferences
		*/
		std::vector<TypeFieldReference> GetCodeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of virtual addresses of data which references the type \c type .

			Note, the returned addresses are the actual start of the queried type field. For example, suppose there is a
			DataVariable at \c 0x1000 that has type \c A , and type \c A contains type \c B at offset \c 0x10 .
			Then <tt>GetDataReferencesForTypeField(bQualifiedName, 0x8)</tt> will return \c 0x1018 for it.

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return List of DataVariable start addresses containing references to the type field
		*/
		std::vector<uint64_t> GetDataReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of virtual addresses of data which are referenced from the type \c type .

		    Only data referenced by structures with the \c __data_var_refs attribute are included.

		    \param type QualifiedName of the type
		    \param offset Offset of the field, relative to the start of the type
		    \return List of addresses referenced from the type field
		*/
		std::vector<uint64_t> GetDataReferencesFromForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of type references to a specific type field

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetTypeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of types referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source of the reference to check
		 	\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src);

		/*! Returns a list of types referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\param len Length of the query
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src, uint64_t len);

		/*! Returns a list of type fields referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src);

		/*! Returns a list of type fields referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\param len Length of the query
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src, uint64_t len);

		/*! Returns a list of offsets in the QualifiedName specified by name, which are referenced by code.

			\param type Name of type to query for references
			\return List of offsets
		*/
		std::vector<uint64_t> GetAllFieldsReferenced(const QualifiedName& type);

		/*! Returns a map from field offset to a list of sizes of the accesses to the specified type.

			\param type Name of type to query for references
			\return A map from field offset to the	size of the code accesses to it
		*/
		std::map<uint64_t, std::vector<size_t>> GetAllSizesReferenced(const QualifiedName& type);

		/*! Returns a map from field offset to a list of incoming types written to the specified type.

			\param type Name of type to query for references
			\return A map from field offset to a list of incoming types written to it
		*/
		std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> GetAllTypesReferenced(const QualifiedName& type);

		/*! Returns a list of types related to the type field access.

			\param type Name of type to query for references
			\param offset Offset of the field, relative to the start of the type
			\return A list of sizes of accesses to the type
		*/
		std::vector<size_t> GetSizesReferenced(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of types referenced by a particular type field

			\param type Name of type to query for references
			\param offset Offset of the field, relative to the start of the type
			\return A list of types referenced
		*/
		std::vector<Confidence<Ref<Type>>> GetTypesReferenced(const QualifiedName& type, uint64_t offset);

		std::unordered_set<QualifiedName> GetOutgoingDirectTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetOutgoingRecursiveTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetOutgoingRecursiveTypeReferences(const std::unordered_set<QualifiedName>& types);
		std::unordered_set<QualifiedName> GetIncomingDirectTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetIncomingRecursiveTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetIncomingRecursiveTypeReferences(const std::unordered_set<QualifiedName>& types);

		Ref<Structure> CreateStructureBasedOnFieldAccesses(const QualifiedName& type); // Unimplemented!

		/*! Returns a list of virtual addresses called by the call site in the ReferenceSource

			If no function is specified, call sites from
			all functions and containing the address will be considered. If no architecture is specified, the
			architecture of the function will be used.

			\param addr ReferenceSource to get callees to
			\return A list of addresses referencing the ReferenceSource
		*/
		std::vector<uint64_t> GetCallees(ReferenceSource addr);

		/*! Returns a list of ReferenceSource objects (xrefs or cross-references) that call the provided virtual address

			In this case, tail calls, jumps, and ordinary calls are considered.

			\param addr Address to check callers for
			\return A list of ReferenceSources calling this address
		*/
		std::vector<ReferenceSource> GetCallers(uint64_t addr);

		/*! Returns the Symbol at the provided virtual address

			\param addr Virtual address to query for symbol
			\param nameSpace The optional namespace of the symbols to retrieve
			\return The symbol located at that address
		*/
		Ref<Symbol> GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a Symbol object for the given a raw (mangled) name.

			\param name Raw (mangled) name of the symbol
			\param nameSpace The optional namespace of the symbols to retrieve
			\return The symbol with that raw name
		*/
		Ref<Symbol> GetSymbolByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of symbols with a given name

			\param name Name to search for
			\param nameSpace The optional namespace of the symbols to retrieve
			\return List of symbols with that name
		*/
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves the list of all Symbol objects with a given raw name

			\param name RawName to search for
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols
		*/
		std::vector<Ref<Symbol>> GetSymbolsByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves the list of all Symbol objects

			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols
		*/
		std::vector<Ref<Symbol>> GetSymbols(const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of symbols in a given range

			\param start Virtual address start of the range
			\param len Length of the range
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type
		*/
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of all Symbol objects of the provided symbol type

			\param type The symbol type
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type
		*/
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of all Symbol objects of the provided symbol type in the given range

			\param type The symbol type
			\param start Virtual address start of the range
			\param len Length of the range
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type in the given range
		*/
		std::vector<Ref<Symbol>> GetSymbolsOfType(
		    BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());

		/*! Get the list of visible symbols

			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of visible symbols
		*/
		std::vector<Ref<Symbol>> GetVisibleSymbols(const NameSpace& nameSpace = NameSpace());

		/*! Adds a symbol to the internal list of automatically discovered Symbol objects in a given namespace

			\warning If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

			\param sym Symbol to define
		*/
		void DefineAutoSymbol(Ref<Symbol> sym);

		/*! Defines an "Auto" symbol, and a Variable/Function alongside it

			\param platform Platform for the Type being defined
			\param sym Symbol being definedd
			\param type Type being defined
			\return The defined symbol
		*/
		Ref<Symbol> DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type);

		/*! Undefine an automatically defined symbol

			\param sym The symbol to undefine
		*/
		void UndefineAutoSymbol(Ref<Symbol> sym);

		/*! Define a user symbol

			\param sym Symbol to define
		*/
		void DefineUserSymbol(Ref<Symbol> sym);

		/*! Undefine a user symbol

			\param sym Symbol to undefinee
		*/
		void UndefineUserSymbol(Ref<Symbol> sym);

		/*! Defines an imported Function \c func with a ImportedFunctionSymbol type

			\param importAddressSym Symbol for the imported function
			\param func Function to define as an imported function
			\param type Optional type for the function
		*/
		void DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func, Ref<Type> type = nullptr);

		/*! The current debug info object for this binary view

			\return The current debug info object for this binary view
		*/
		Ref<DebugInfo> GetDebugInfo();

		/*! Sets the debug info and applies its contents to the current BinaryView

			\param newDebugInfo
		*/
		void ApplyDebugInfo(Ref<DebugInfo> newDebugInfo);

		/*! Sets the debug info for the current binary view

			\param newDebugInfo Sets the debug info for the current binary view
		*/
		void SetDebugInfo(Ref<DebugInfo> newDebugInfo);

		/*! Determine is a debug info object is currently being applied

			\return True if a debug info object is currently being applied
		*/
		bool IsApplyingDebugInfo() const;

		void BeginBulkModifySymbols();
		void EndBulkModifySymbols();

		/*! Add a new TagType to this binaryview

			\param tagType TagType to add
		*/
		void AddTagType(Ref<TagType> tagType);

		/*! Remove a TagType from this binaryview

			\param tagType TagType to remove
		*/
		void RemoveTagType(Ref<TagType> tagType);

		/*! Get a TagType by name

			\param name Name of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagType(const std::string& name);

		/*! Get a TagType by name and TagType::Type

			\param name Name of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagType(const std::string& name, TagType::Type type);

		/*! Get a TagType by name

			\param name Name of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeByName(const std::string& name);

		/*! Get a TagType by name and TagType::Type

			\param name Name of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeByName(const std::string& name, TagType::Type type);

		/*! Get a TagType by its ID

			\param id ID of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeById(const std::string& id);

		/*! Get a TagType by its ID and TagType::Type

			\param id ID of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeById(const std::string& id, TagType::Type type);

		/*! Get the list of all defined TagTypes

			\return Get the list of all defined TagTypes
		*/
		std::vector<Ref<TagType>> GetTagTypes();

		/*! Add a Tag

			\param tag The tag to add
			\param user Whether this was added by a user or automatically by analysis
		*/
		void AddTag(Ref<Tag> tag, bool user = false);

		/*! Remove a tag

			\param tag The tag to remove
			\param user Whether the tag being removed is a user tag
		*/
		void RemoveTag(Ref<Tag> tag, bool user = false);

		/*! Get a tag by its ID

			\param tagId the tag ID
			\return The tag, if it was found
		*/
		Ref<Tag> GetTag(const std::string& tagId);

		std::vector<TagReference> GetAllTagReferences();
		std::vector<TagReference> GetAllAddressTagReferences();
		std::vector<TagReference> GetAllFunctionTagReferences();
		std::vector<TagReference> GetAllTagReferencesOfType(Ref<TagType> tagType);

		std::vector<TagReference> GetTagReferencesOfType(Ref<TagType> tagType);
		size_t GetTagReferencesOfTypeCount(Ref<TagType> tagType);
		size_t GetAllTagReferencesOfTypeCount(Ref<TagType> tagType);
		std::map<Ref<TagType>, size_t> GetAllTagReferenceTypeCounts();

		std::vector<TagReference> GetDataTagReferences();
		std::vector<TagReference> GetAutoDataTagReferences();
		std::vector<TagReference> GetUserDataTagReferences();
		std::vector<Ref<Tag>> GetDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetAutoDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetUserDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<TagReference> GetDataTagsInRange(uint64_t start, uint64_t end);
		std::vector<TagReference> GetAutoDataTagsInRange(uint64_t start, uint64_t end);
		std::vector<TagReference> GetUserDataTagsInRange(uint64_t start, uint64_t end);
		void AddAutoDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveAutoDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		void AddUserDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveUserDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		void RemoveTagReference(const TagReference& ref);

		Ref<Tag> CreateAutoDataTag(
		    uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserDataTag(
		    uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique = false);

		Ref<Tag> CreateAutoDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);

		/*! Lookup a component by its GUID

			\param guid GUID of the component to look up
			\return The component with that GUID
		*/
		std::optional<Ref<Component>> GetComponentByGuid(std::string guid);

		/*! Lookup a component by its pathname

			\note This is a convenience method, and for performance-sensitive lookups, GetComponentByGuid is very
		 	highly recommended.

		 	\see GetComponentByGuid, Component::GetGuid

			All lookups are absolute from the root component, and are case-sensitive. Pathnames are delimited with "/"

		 	Lookups are done using the display name of the component, which is liable to change when it or its siblings
		 	are moved around.

		 	\see Component::GetDisplayName

			\param path Path of the desired component
			\return The component at that path
		*/
		std::optional<Ref<Component>> GetComponentByPath(std::string path);

		/*! Get the root component for the BinaryView (read-only)

			This Component cannot be removed, and houses all unparented Components.

			\return The Root Component
		*/
		Ref<Component> GetRootComponent();

		/*! Create a component

			This component will be added to the root component and initialized with the name "Component"

			\return The created Component
		*/
		Ref<Component> CreateComponent();

		/*! Create a component as a subcomponent of the component with a given Guid

			This component will be initialized with the name "Component"

			\param parentGUID Guid of the component this component will be added to
			\return The created Component
		*/
		Ref<Component> CreateComponent(std::string parentGUID);

		/*! Create a component as a subcomponent of a given Component

		    This component will be initialized with the name "Component"

		 	\param parent Parent Component
		 	\return The created Component
		*/
		Ref<Component> CreateComponent(Ref<Component> parent);

		/*! Create a component with a given name and optional parent

		    \param name Name to initialize the component with
		    \param parentGUID Optional Guid of the component this component will be added to
		    \return The created Component
		*/
		Ref<Component> CreateComponentWithName(std::string name, std::string parentGUID = {});

		/*! Create a component with a given name and parent

		    \param name Name to initialize the component with
		    \param parentGUID Guid of the component this component will be added to
		    \return The created Component
		*/
		Ref<Component> CreateComponentWithName(std::string name, Ref<Component> parent);

		/*! Remove a component from the tree entirely. This will also by nature remove all subcomponents.

			\param component Component to remove
			\return Whether removal was successful
		*/
		bool RemoveComponent(Ref<Component> component);

		/*! Remove a component from the tree entirely. This will also by nature remove all subcomponents.

			\param guid Guid of the Component to remove
			\return Whether removal was successful
		*/
		bool RemoveComponent(std::string guid);

		std::vector<Ref<Component>> GetFunctionParentComponents(Ref<Function> function) const;
		std::vector<Ref<Component>> GetDataVariableParentComponents(DataVariable var) const;

		/*! Heuristically determine if a string exists at the given address. This API checks for the following settings:
			"analysis.unicode.utf8" - default true enables UTF-8 string detection
			"analysis.unicode.utf16" - default true enables UTF-16 string detection
			"analysis.unicode.utf32" - default true enables UTF-32 string detection
			"analysis.unicode.blocks" - selects the Unicode blocks to use for detection

			\param addr Address to check
			\param value String value to populate
			\param allowShortStrings Whether to allow short strings < 4 characters
			\param allowLargeStrings If false strings must be less than "rendering.strings.maxAnnotationLength" (default 32)
				If true strings must be less than "analysis.limits.maxStringLength" (default 16384)
			\param childWidth Width of the characters
			\return The type of string annotation found

		*/
		std::optional<BNStringType> CheckForStringAnnotationType(uint64_t addr, std::string& value,
			bool allowShortStrings, bool allowLargeStrings, size_t childWidth);

		/*! Check whether the given architecture supports assembling instructions

			\param arch Architecture to check
			\return Whether the given architecture supports assembling instructions
		*/
		bool CanAssemble(Architecture* arch);

		/*! Check whether the "Never Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Never Branch" patch is available
		*/
		bool IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Always Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Always Branch" patch is available
		*/
		bool IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Invert Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Invert Branch" patch is available
		*/
		bool IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Skip and Return Zero" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Skip and Return Zero" patch is available
		*/
		bool IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Skip and Return Value" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Skip and Return Value" patch is available
		*/
		bool IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr);

		/*! Convert the instruction at the given address to a nop

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool ConvertToNop(Architecture* arch, uint64_t addr);

		/*! Convert the conditional branch at the given address to always branch

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool AlwaysBranch(Architecture* arch, uint64_t addr);

		/*! Convert the conditional branch at the given address to branch under inverted conditions

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool InvertBranch(Architecture* arch, uint64_t addr);

		/*! Convert the given instruction to skip the rest of the function and return 0

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\param value Value to return
			\return Whether the patch was successful
		*/
		bool SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value);

		/*! Get the length of the instruction at a given address

			\param arch Architecture of the instruction
			\param addr Address of the start of the instruction
			\return The length of the instruction
		*/
		size_t GetInstructionLength(Architecture* arch, uint64_t addr);

		/*! Get the string at an address

			\param[in] addr Address of the string
			\param[out] strRef Reference to a StringReference the string reference will be writen to.
			\return Whether a string was at th given address
		*/
		bool GetStringAtAddress(uint64_t addr, BNStringReference& strRef);

		/*! Get the list of strings located within the view

			\return The list of strings
		*/
		std::vector<BNStringReference> GetStrings();

		/*! Get the list of strings located within a range

			\param start Starting virtual address of the range
			\param len Length of the range
			\return The list of strings
		*/
		std::vector<BNStringReference> GetStrings(uint64_t start, uint64_t len);

		/*! Sets up a call back function to be called when analysis has been completed.

			This is helpful when using `UpdateAnalysis` which does not wait for analysis completion before returning.

			The callee of this function is not responsible for maintaining the lifetime of the returned AnalysisCompletionEvent object

			\param callback A function to be called with no parameters when analysis has completed.
			\return An initialized AnalysisCompletionEvent object.
		*/
		Ref<AnalysisCompletionEvent> AddAnalysisCompletionEvent(const std::function<void()>& callback);

		AnalysisInfo GetAnalysisInfo();
		BNAnalysisProgress GetAnalysisProgress();
		Ref<BackgroundTask> GetBackgroundAnalysisTask();

		/*! Returns the virtual address of the Function that occurs after the virtual address `addr`

			\param addr Address to start searching
			\return Next function start
		*/
		uint64_t GetNextFunctionStartAfterAddress(uint64_t addr);

		/*! Returns the virtual address of the BasicBlock that occurs after the virtual address `addr`

			\param addr Address to start searching
			\return Next basic block start
		*/
		uint64_t GetNextBasicBlockStartAfterAddress(uint64_t addr);

		/*! Retrieves the virtual address of the next non-code byte.

			\param addr Address to start searching
			\return address of the next non-code byte
		*/
		uint64_t GetNextDataAfterAddress(uint64_t addr);

		/*! Retrieves the address of the next DataVariable.

			\param addr Address to start searching
			\return address of the next DataVariable
		*/
		uint64_t GetNextDataVariableStartAfterAddress(uint64_t addr);

		/*! Returns the virtual address of the Function that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return the virtual address of the previous Function
		*/
		uint64_t GetPreviousFunctionStartBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the Basic Block that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return The virtual address of the previous Basic Block
		*/
		uint64_t GetPreviousBasicBlockStartBeforeAddress(uint64_t addr);

		/*! Returns the ending virtual address of the Basic Block that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return The ending virtual address of the previous Basic Block
		*/
		uint64_t GetPreviousBasicBlockEndBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the previous data (non-code) byte

			\param addr Address to start searching
			\return The virtual address of the previous non-code byte
		*/
		uint64_t GetPreviousDataBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the previous DataVariable

			\param addr Address to start searching
			\return The virtual address of the previous DataVariable
		*/
		uint64_t GetPreviousDataVariableStartBeforeAddress(uint64_t addr);

		bool ParsePossibleValueSet(const std::string& value, BNRegisterValueType state, PossibleValueSet& result,
		    uint64_t here, std::string& errors);

		/*! Parse a single type and name from a string containing their definition

			\param[in] text Text containing the type definition
			\param[out] result Reference into which the resulting type and name will be written
			\param[out] errors Reference to a list into which any parse errors will be written
			\param[in] typesAllowRedefinition List of types whose names are allowed to be overwritten (legacy cruft?)
			\param[in] importDependencies If Type Library / Type Archive types should be imported during parsing
			\return Whether parsing was successful
		*/
		bool ParseTypeString(const std::string& text, QualifiedNameAndType& result, std::string& errors,
		    const std::set<QualifiedName>& typesAllowRedefinition = {}, bool importDependencies = true);

		/*! Parse an entire block of source into types, variables, and functions

			\param[in] text Source code to parse
			\param[out] types Reference to a map of QualifiedNames and Types the parsed types will be writen to
			\param[out] variables Reference to a list of QualifiedNames and Types the parsed variables will be writen to
			\param[out] functions Reference to a list of QualifiedNames and Types the parsed functions will be writen to
			\param[out] errors Reference to a list into which any parse errors will be written
			\param[in] typesAllowRedefinition List of types whose names are allowed to be overwritten (legacy cruft?)
			\param[in] importDependencies If Type Library / Type Archive types should be imported during parsing
			\return Whether parsing was successful
		*/
		bool ParseTypeString(const std::string& text, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {}, bool importDependencies = true);

		/*! Parse an entire block of source into a structure containing types, variables, and functions

			\param[in] text Source code to parse
			\param[out] result Reference to a TypeParserResult structure into which types, variables, and functions will be written
			\param[out] errors Reference to a list into which any parse errors will be written
			\param[in] typesAllowRedefinition List of types whose names are allowed to be overwritten (legacy cruft?)
			\param[in] importDependencies If Type Library / Type Archive types should be imported during parsing
			\return Whether parsing was successful
		*/
		bool ParseTypesFromSource(const std::string& text, const std::vector<std::string>& options, const std::vector<std::string>& includeDirs, TypeParserResult& result,
		    std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {}, bool importDependencies = true);

		/*! Type Container for all types (user and auto) in the BinaryView. Any auto types
			modified through the Type Container will be converted into user types.
			\return Full view Type Container
		 */
		class TypeContainer GetTypeContainer();

		/*! Type Container for ONLY auto types in the BinaryView. Any changes to types will
			NOT promote auto types to user types.
			\return Auto types only Type Container
		 */
		class TypeContainer GetAutoTypeContainer();

		/*! Type Container for ONLY user types in the BinaryView.
			\return User types only Type Container
		 */
		class TypeContainer GetUserTypeContainer();

		std::map<QualifiedName, Ref<Type>> GetTypes();
		/*! List of all types, sorted such that types are after all types on which they depend

			Order is guaranteed for any collection of types with no cycles. If you have cycles
			in type dependencies, order for types in a cycle is not guaranteed.

			\note Dependency order is based on named type references for all non-structure types, i.e.
			``struct Foo m_foo`` will induce a dependency, whereas ``struct Foo* m_pFoo`` will not.

			\return Sorted types as defined above
		*/
		std::vector<std::pair<QualifiedName, Ref<Type>>> GetDependencySortedTypes();
		std::vector<QualifiedName> GetTypeNames(const std::string& matching = "");
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetTypeByRef(Ref<NamedTypeReference> name);
		Ref<Type> GetTypeById(const std::string& id);
		std::string GetTypeId(const QualifiedName& name);
		QualifiedName GetTypeNameById(const std::string& id);
		bool IsTypeAutoDefined(const QualifiedName& name);
		QualifiedName DefineType(const std::string& id, const QualifiedName& defaultName, Ref<Type> type);
		std::unordered_map<std::string, QualifiedName> DefineTypes(const std::vector<std::pair<std::string, QualifiedNameAndType>>& types, std::function<bool(size_t, size_t)> progress = {});
		void DefineUserType(const QualifiedName& name, Ref<Type> type);
		void DefineUserTypes(const std::vector<QualifiedNameAndType>& types, std::function<bool(size_t, size_t)> progress = {});
		void DefineUserTypes(const std::vector<ParsedType>& types, std::function<bool(size_t, size_t)> progress = {});
		void UndefineType(const std::string& id);
		void UndefineUserType(const QualifiedName& name);
		void RenameType(const QualifiedName& oldName, const QualifiedName& newName);

		void RegisterPlatformTypes(Platform* platform);

		/*! Gives you details of which platform and name was imported to result in the given type name.

			\param name Name of type in the binary view
			\return A pair with the platform and the name of the type in the platform,
			        or std::nullopt if it was not imported
		*/
		std::optional<std::pair<Ref<Platform>, QualifiedName>> LookupImportedTypePlatform(const QualifiedName& name);

		/*! Make the contents of a type library available for type/import resolution

			\param lib library to register with the view
		*/
		void AddTypeLibrary(TypeLibrary* lib);
		/*! Get the type library with the given name

			\param name Library name to lookup
			\return The Type Library object, or nullptr if one has not been added with this name
		*/
		Ref<TypeLibrary> GetTypeLibrary(const std::string& name);
		/*! Get the list of imported type libraries

			\return All imported type libraries
		*/
		std::vector<Ref<TypeLibrary>> GetTypeLibraries();

		/*! Recursively imports a type from the specified type library, or, if no library was explicitly provided,
			the first type library associated with the current `BinaryView` that provides the name requested.

			This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
			when references to types provided by them are first encountered.

			Note that the name actually inserted into the view may not match the name as it exists in the type library in
			the event of a name conflict. To aid in this, the `Type` object returned is a `NamedTypeReference` to
			the deconflicted name used.

			\param lib
			\param name
			\return A `NamedTypeReference` to the type, taking into account any renaming performed
		*/
		Ref<Type> ImportTypeLibraryType(Ref<TypeLibrary>& lib, const QualifiedName& name);
		/*! Recursively imports an object from the specified type library, or, if no library was explicitly provided,
			the first type library associated with the current `BinaryView` that provides the name requested.

			This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
			when references to types provided by them are first encountered.

			.. note:: If you are implementing a custom BinaryView and use this method to import object types,
			you should then call ``RecordImportedObjectLibrary`` with the details of where the object is located.

			\param lib
			\param name
			\return The object type, with any interior `NamedTypeReferences` renamed as necessary to be appropriate for the current view
		*/
		Ref<Type> ImportTypeLibraryObject(Ref<TypeLibrary>& lib, const QualifiedName& name);


		/*! Recursively imports a type by guid from the current BinaryView's set of type libraries

			This API is dependent on the set of TypeLibraries for the current BinaryView's Platform,
			having appropriate metadata to resolve the type by guid. The key "type_guids" must contain
			a map(string(guid), string(type_name)) or
			  map(string(guid), tuple(sting(type_name), string(library_name))).

			\param guid
			\return The type, or nullptr if it was not found

		*/
		Ref<Type> ImportTypeLibraryTypeByGuid(const std::string& guid);


		/* Looks up the name of a type by its guid in the current BinaryView's set of type libraries

			\param guid
			\return The QualifedName of the type or std::nullopt if it was not found
		 */
		std::optional<QualifiedName> GetTypeNameByGuid(const std::string& guid);

		/*! Recursively exports ``type`` into ``lib`` as a type with name ``name``

			As other referenced types are encountered, they are either copied into the destination type library or
			else the type library that provided the referenced type is added as a dependency for the destination library.

			\param lib
			\param name
			\param type
		*/
		void ExportTypeToTypeLibrary(TypeLibrary* lib, const QualifiedName& name, Type* type);
		/*! Recursively exports ``type`` into ``lib`` as an object with name ``name``

			As other referenced types are encountered, they are either copied into the destination type library or
			else the type library that provided the referenced type is added as a dependency for the destination library.

			\param lib
			\param name
			\param type
		*/
		void ExportObjectToTypeLibrary(TypeLibrary* lib, const QualifiedName& name, Type* type);

		/*! Should be called by custom `BinaryView` implementations when they have successfully imported an object
			from a type library (eg a symbol's type). Values recorded with this function will then be queryable via ``LookupImportedObjectLibrary``.

			\param tgtPlatform Platform of symbol at import site
			\param tgtAddr Address of symbol at import site
			\param lib Type Library containing the imported type
			\param name Name of the object in the type library
		*/
		void RecordImportedObjectLibrary(Platform* tgtPlatform, uint64_t tgtAddr, TypeLibrary* lib, const QualifiedName& name);
		/*! Gives you details of which type library and name was used to determine the type of a symbol at a given address.

			\param tgtPlatform Platform of symbol at import site
			\param tgtAddr Address of symbol at import site
			\return A pair with the library and name used, or std::nullopt if it was not imported
		*/
		std::optional<std::pair<Ref<TypeLibrary>, QualifiedName>> LookupImportedObjectLibrary(Platform* tgtPlatform, uint64_t tgtAddr);

		/*! Gives you details of which type library and name was imported to result in the given type name.

			\param name Name of type in the binary view
			\return A pair with the library and the name of the type in the library,
			        or std::nullopt if it was not imported
		 */
		std::optional<std::pair<Ref<TypeLibrary>, QualifiedName>> LookupImportedTypeLibrary(const QualifiedName& name);
		/*! Attach a given type archive to the binary view. No types will actually be associated by calling this, just they
			will become available.

			\param id Expected id of archive
			\param path Path to archive
		 */
		Ref<TypeArchive> AttachTypeArchive(const std::string& id, const std::string& path);
		/*! Detach from a type archive, breaking all associations to types with the archive

			\param id Id of archive to detach
		 */
		void DetachTypeArchive(const std::string& id);
		/*! Look up a connected archive by its id

			\param id Id of archive
			\return Archive, if one exists with that id. Otherwise nullptr
		 */
		Ref<TypeArchive> GetTypeArchive(const std::string& id) const;
		/*! Get all attached type archives

			\return All attached archive (id, path) pairs
		 */
		std::unordered_map<std::string, std::string> GetTypeArchives() const;
		/*! Look up the path for an attached (but not necessarily connected) type archive by its id

			\param id Id of archive
			\return Archive path, if it is attached. Otherwise nullopt.
		 */
		std::optional<std::string> GetTypeArchivePath(const std::string& id) const;
		/*! Get a list of all available type names in all connected archives, and their archive/type id pair

			\return All type names in a map
		 */
		std::unordered_map<QualifiedName, std::map<std::string, std::string>> GetTypeArchiveTypeNames() const;

		/*! Get a list of all types in the analysis that are associated with a specific type archive

			\return Map of all analysis types to their corresponding archive id
		 */
		std::unordered_map<std::string, std::pair<std::string, std::string>> GetAssociatedTypeArchiveTypes() const;
		/*! Get a list of all types in the analysis that are associated with a specific type archive

		    \return Map of all analysis types to their corresponding archive id
		 */
		std::unordered_map<std::string, std::string> GetAssociatedTypesFromArchive(const std::string& archive) const;
		/*! Determine the target archive / type id of a given analysis type

		    \param id Id of analysis type
		    \return Pair of archive id and archive type id, if this type is associated. std::nullopt otherwise.
		 */
		std::optional<std::pair<std::string, std::string>> GetAssociatedTypeArchiveTypeTarget(const std::string& id) const;
		/*! Determine the local source type for a given archive type

		    \param archiveId Id of target archive
		    \param archiveTypeId Id of target archive type
		    \return Id of source analysis type, if this type is associated. std::nullopt otherwise.
		 */
		std::optional<std::string> GetAssociatedTypeArchiveTypeSource(const std::string& archiveId, const std::string& archiveTypeId) const;
		/*! Get the current status of any changes pending in a given type

		    \param id Id of type in analysis
		    \return Status of type
		 */
		BNSyncStatus GetTypeArchiveSyncStatus(const std::string& typeId) const;
		/*! Disassociate an associated type, so that it will no longer receive updates from its connected type archive

		    \param typeId Id of type in analysis
		    \return True if successful
		 */
		bool DisassociateTypeArchiveType(const std::string& typeId);
		/*! Pull a collection of types from a type archive, associating with them and any dependencies

			\param[in] archiveId Id of archive
			\param[in] archiveTypeIds Ids of desired types
			\param[out] updatedTypes List of types that were updated
			\return True if successful
		 */
		bool PullTypeArchiveTypes(const std::string& archiveId, const std::unordered_set<std::string>& archiveTypeIds, std::unordered_map<std::string, std::string>& updatedTypes);
		/*! Push a collection of types, and all their dependencies, into a type archive

			\param[in] archiveId Id of archive
			\param[in] typeIds List of ids of types in analysis
			\param[out] updatedTypes List of types that were updated
			\return True if successful
		 */
		bool PushTypeArchiveTypes(const std::string& archiveId, const std::unordered_set<std::string>& typeIds, std::unordered_map<std::string, std::string>& updatedTypes);

		bool FindNextData(
		    uint64_t start, const DataBuffer& data, uint64_t& result, BNFindFlag flags = FindCaseSensitive);
		bool FindNextText(uint64_t start, const std::string& data, uint64_t& result, Ref<DisassemblySettings> settings,
			BNFindFlag flags = FindCaseSensitive, const FunctionViewType& viewType = NormalFunctionGraph);
		bool FindNextConstant(uint64_t start, uint64_t constant, uint64_t& result, Ref<DisassemblySettings> settings,
			const FunctionViewType& viewType = NormalFunctionGraph);

		bool FindNextData(uint64_t start, uint64_t end, const DataBuffer& data, uint64_t& addr, BNFindFlag flags,
		    const std::function<bool(size_t current, size_t total)>& progress);
		bool FindNextText(uint64_t start, uint64_t end, const std::string& data, uint64_t& addr,
			Ref<DisassemblySettings> settings, BNFindFlag flags, const FunctionViewType& viewType,
		    const std::function<bool(size_t current, size_t total)>& progress);
		bool FindNextConstant(uint64_t start, uint64_t end, uint64_t constant, uint64_t& addr,
			Ref<DisassemblySettings> settings, const FunctionViewType& viewType,
		    const std::function<bool(size_t current, size_t total)>& progress);

		bool FindAllData(uint64_t start, uint64_t end, const DataBuffer& data, BNFindFlag flags,
		    const std::function<bool(size_t current, size_t total)>& progress,
		    const std::function<bool(uint64_t addr, const DataBuffer& match)>& matchCallback);
		bool FindAllText(uint64_t start, uint64_t end, const std::string& data, Ref<DisassemblySettings> settings,
			BNFindFlag flags, const FunctionViewType& viewType,
		    const std::function<bool(size_t current, size_t total)>& progress,
		    const std::function<bool(uint64_t addr, const std::string& match, const LinearDisassemblyLine& line)>&
		        matchCallback);
		bool FindAllConstant(uint64_t start, uint64_t end, uint64_t constant, Ref<DisassemblySettings> settings,
			const FunctionViewType& viewType, const std::function<bool(size_t current, size_t total)>& progress,
		    const std::function<bool(uint64_t addr, const LinearDisassemblyLine& line)>& matchCallback);

		bool Search(const std::string& query, const std::function<bool(uint64_t offset, const DataBuffer& buffer)>& otherCallback);

		void Reanalyze();

		Ref<Workflow> GetWorkflow();

		/*! Displays contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents Contents of the report
		*/
		void ShowPlainTextReport(const std::string& title, const std::string& contents);

		/*! Displays markdown contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents Markdown contents of the report
			\param plainText Plaintext contents of the report (used on the command line)
		*/
		void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText);

		/*! Displays HTML contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents HTML contents of the report
			\param plainText Plaintext contents of the report (used on the command line)
		*/
		void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText);

		/*! Displays a flow graph in UI applications and nothing in command-line applications.

			\note This API has no effect outside of the UI

			\param title Title for the report
			\param graph FlowGraph object to be rendered.
		*/
		void ShowGraphReport(const std::string& title, FlowGraph* graph);

		/*! Prompts the user to input an unsigned integer with the given prompt and title

			\param[out] result Reference to the uint64_t the result will be copied to
			\param[in] prompt Prompt for the input
			\param[in] title Title for the input popup when used in UI
			\return Whether an integer was successfully received
		*/
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);

		/*! Prompts the user to input an unsigned integer with the given prompt and title

			\param[out] result Reference to the uint64_t the result will be copied to
			\param[in] prompt Prompt for the input
			\param[in] title Title for the input popup when used in UI
		 	\param[in] currentAddress Address to use for relative inputs
			\return Whether an integer was successfully received
		*/
		bool GetAddressInput(
		    uint64_t& result, const std::string& prompt, const std::string& title, uint64_t currentAddress);

		/*! A mock object that is a placeholder during development of this feature.

			\return MemoryMap object
		*/
		MemoryMap* GetMemoryMap() { return m_memoryMap.get(); }

		/*! Begin a bulk segment addition operation.

			This function prepares the `BinaryView` for bulk addition of both auto and user-defined segments.
			During the bulk operation, segments can be added using `AddAutoSegment`, `AddAutoSegments`,
			`AddUserSegment`, or `AddUserSegments` without immediately triggering the MemoryMap update process.
			The queued segments will not take effect until `EndBulkAddSegments` is called.

			\sa EndBulkAddSegments
			\sa CancelBulkAddSegments
		*/
		void BeginBulkAddSegments();

		/*! Finalize and apply all queued segments (auto and user) added during a bulk segment addition operation.

			This function commits all segments that were queued since the last call to `BeginBulkAddSegments`.
			The MemoryMap update process is executed at this point, applying all changes in one batch for
			improved performance.

			\note This function must be called after `BeginBulkAddSegments` to apply the queued segments.

			\sa BeginBulkAddSegments
			\sa CancelBulkAddSegments
		*/
		void EndBulkAddSegments();

		/*! Cancel a bulk segment addition operation.

			This function discards all auto and user segments that were queued since the last call to
			`BeginBulkAddSegments` without applying them. It allows you to abandon the changes in case
			they are no longer needed.

			\note If no bulk operation is in progress, calling this function has no effect.

			\sa BeginBulkAddSegments
			\sa EndBulkAddSegments
		*/
		void CancelBulkAddSegments();

		/*! Add an analysis segment that specifies how data from the raw file is mapped into a virtual address space

			Note that the segment added may have different size attributes than requested

			\param start Starting virtual address
			\param length Length within the virtual address space
			\param dataOffset Data offset in the raw file
			\param dataLength Length of the data to map from the raw file
			\param flags Segment r/w/x flags
		*/
		void AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);

		/*! Add analysis segments that specify how data from the raw file is mapped into a virtual address space

			\param segments Segments to add to the BinaryView

			Note that the segments added may have different size attributes than requested
		*/
		void AddAutoSegments(const std::vector<BNSegmentInfo>& segments);

		/*! Removes an automatically generated segment from the current segment mapping

			\warning This action is not persistent across saving of a BNDB and must be re-applied each time a BNDB is loaded.

			\param start Virtual address of the start of the segment
			\param length Length of the segment
		*/
		void RemoveAutoSegment(uint64_t start, uint64_t length);

		/*! Creates a user-defined segment that specifies how data from the raw file is mapped into a virtual address space

			\param start Starting virtual address
			\param length Length within the virtual address space
			\param dataOffset Data offset in the raw file
			\param dataLength Length of the data to map from the raw file
			\param flags Segment r/w/x flags
		*/
		void AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);

		/*! Creates user-defined segments that specify how data from the raw file is mapped into a virtual address space

			\param segments Segments to add to the BinaryView
		*/
		void AddUserSegments(const std::vector<BNSegmentInfo>& segments);

		/*! Removes a user-defined segment from th current segment mapping

			\param start Virtual address of the start of the segment
			\param length Length of the segment
		*/
		void RemoveUserSegment(uint64_t start, uint64_t length);

		/*! Get the list of registered Segments

			\return The list of registered Segments
		*/
		std::vector<Ref<Segment>> GetSegments();

		/*! Gets the Segment a given virtual address is located in

			\param addr A virtual address
			\return The Segment that virtual address is located im
		*/
		Ref<Segment> GetSegmentAt(uint64_t addr);

		/*! Retrieves the virtual addreses that maps to the given file offset, if possible.

			\param[in] offset Raw file offset
			\param[out] addr Reference to a uint64_t the address will be written to
			\return Whether an address was successfully mapped
		*/
		bool GetAddressForDataOffset(uint64_t offset, uint64_t& addr);

		bool GetDataOffsetForAddress(uint64_t addr, uint64_t& offset);

		/*! Creates an analysis-defined section that can help inform analysis by clarifying what types of data exist in
			what ranges

		 	Note that all data specified must already be mapped by an existing segment.

			\param name Name of the section
			\param start Virtual address of the start of the section
			\param length Length of the section
			\param semantics SectionSemantics of the section
			\param type Optional type of the section
			\param align Optional byte alignment
			\param entrySize Entry Size of the section
			\param linkedSection Optional namee of a linked section
			\param infoSection Optional name of an associated informational section
			\param infoData Optional Info Data
		*/
		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);

		/*! Remove an automatically defined section by name

			\param name Name of the section
		*/
		void RemoveAutoSection(const std::string& name);

		/*! Creates a user-defined section that can help inform analysis by clarifying what types of data exist in
			what ranges

		 	Note that all data specified must already be mapped by an existing segment.

			\param name Name of the section
			\param start Virtual address of the start of the section
			\param length Length of the section
			\param semantics SectionSemantics of the section
			\param type Optional type of the section
			\param align Optional byte alignment
			\param entrySize Entry Size of the section
			\param linkedSection Optional namee of a linked section
			\param infoSection Optional name of an associated informational section
			\param infoData Optional Info Data
		*/
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);

		/*! Remove a user defined section by name

			\param name Name of the section to remove
		*/
		void RemoveUserSection(const std::string& name);

		/*! Get the list of defined sections

			\return The list of defined sections
		*/
		std::vector<Ref<Section>> GetSections();

		/*! Get the list of sections containing \c addr

			\param addr Address to check
			\return List of sections containing \c addr
		*/
		std::vector<Ref<Section>> GetSectionsAt(uint64_t addr);

		/*! Get a Section by name

			\param name Name of the Section
			\return The Section with that name
		*/
		Ref<Section> GetSectionByName(const std::string& name);

		/*! Create unique names for all items in the input list, modifying them if they are not unique

			\code{.cpp}
		    std::vector<std::string> names = bv.GetUniqueSectionNames({"sect1", "sect1", "sect2"});
			// names == {'sect1', 'sect1#1', 'sect2'}
		 	\endcode

			\param names List of names
			\return List of unique names
		*/
		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		/*! Get the list of allocated ranges
		   \deprecated This API has been deprecated in favor of GetMappedAddressRanges in 4.1.5902

			\return The list of allocated ranges
		*/
		std::vector<BNAddressRange> GetAllocatedRanges();

		/*! Get the list of ranges mapped into the address space

			\return The list of mapped ranges
		*/
		std::vector<BNAddressRange> GetMappedAddressRanges();

		/*! Get the list of ranges that are mapped into the address space and are backed by a target object

			\return The list of backed ranges
		*/
		std::vector<BNAddressRange> GetBackedAddressRanges();

		/*! Get the comment placed at an address

			\param addr Address at which to check for a comment
			\return Comment at that address
		*/
		std::string GetCommentForAddress(uint64_t addr) const;

		/*! Get the list of commented addresses

			\return list of addresses with comments defined at them
		*/
		std::vector<uint64_t> GetCommentedAddresses() const;

		/*! Set the comment at an address

			\param addr Address at which to place a comment
			\param comment Comment to place
		*/
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		void StoreMetadata(const std::string& key, Ref<Metadata> value, bool isAuto = false);
		Ref<Metadata> QueryMetadata(const std::string& key);
		void RemoveMetadata(const std::string& key);
		Ref<Metadata> GetMetadata();
		Ref<Metadata> GetAutoMetadata();
		std::string GetStringMetadata(const std::string& key);
		std::vector<uint8_t> GetRawMetadata(const std::string& key);
		uint64_t GetUIntMetadata(const std::string& key);

		std::vector<std::string> GetLoadSettingsTypeNames();
		Ref<Settings> GetLoadSettings(const std::string& typeName);
		void SetLoadSettings(const std::string& typeName, Ref<Settings> settings);

		BNAnalysisParameters GetParametersForAnalysis();
		void SetParametersForAnalysis(BNAnalysisParameters params);
		uint64_t GetMaxFunctionSizeForAnalysis();
		void SetMaxFunctionSizeForAnalysis(uint64_t size);
		bool GetNewAutoFunctionAnalysisSuppressed();
		void SetNewAutoFunctionAnalysisSuppressed(bool suppress);

		/*! Returns a list of namespaces for the current BinaryView

			\return A list of namespaces for the current BinaryView
		*/
		std::set<NameSpace> GetNameSpaces() const;

		/*! Internal namespace for the current BinaryView

			\return Internal namespace for the current BinaryView
		*/
		static NameSpace GetInternalNameSpace();

		/*! External namespace for the current BinaryView

			\return External namespace for the current BinaryView
		*/
		static NameSpace GetExternalNameSpace();

		/*! Evaluates a string expression to an integer value.

			The parser uses the following rules:

			- Symbols are defined by the lexer as ``[A-Za-z0-9_:<>][A-Za-z0-9_:$\-<>]+`` or anything enclosed in either single or double quotes
			- Symbols are everything in ``bv.GetSymbols()``, unnamed DataVariables (i.e. ``data_00005000``), unnamed functions (i.e. ``sub_00005000``), or section names (i.e. ``.text``)
			- Numbers are defaulted to hexadecimal thus `_printf + 10` is equivalent to `printf + 0x10` If decimal numbers required use the decimal prefix.
			- Since numbers and symbols can be ambiguous its recommended that you prefix your numbers with the following:

					- ``0x`` - Hexadecimal
					- ``0n`` - Decimal
					- ``0`` - Octal

			- In the case of an ambiguous number/symbol (one with no prefix) for instance ``12345`` we will first attempt
			  to look up the string as a symbol, if a symbol is found its address is used, otherwise we attempt to convert
			  it to a hexadecimal number.
			- The following operations are valid: ``+, -, \*, /, %, (), &, \|, ^, ~``
			- In addition to the above operators there are dereference operators similar to BNIL style IL:

					- ``[<expression>]`` - read the `current address size` at ``<expression>``
					- ``[<expression>].b`` - read the byte at ``<expression>``
					- ``[<expression>].w`` - read the word (2 bytes) at ``<expression>``
					- ``[<expression>].d`` - read the dword (4 bytes) at ``<expression>``
					- ``[<expression>].q`` - read the quadword (8 bytes) at ``<expression>``

			- The ``$here`` (or more succinctly: ``$``) keyword can be used in calculations and is defined as the ``here`` parameter, or the currently selected address
			- The ``$start``/``$end`` keyword represents the address of the first/last bytes in the file respectively


			\param[in] view View object for relative selections
			\param[in] expression Expression to parse
			\param[out] offset Parsed expression
			\param[in] here The location for $here
			\param[out] errorString Any errors that occurred during parsing
			\return Whether the parsing was successful
		*/
		static bool ParseExpression(Ref<BinaryView> view, const std::string& expression, uint64_t& offset,
		    uint64_t here, std::string& errorString);

		/*! Check whether this BinaryView has any defined symbols

			\return Whether this BinaryView has any defined symbols
		*/
		bool HasSymbols() const;

		/*! Check whether this BinaryView has any defined DataVariables

			\return Whether this BinaryView has any defined DataVariables
		*/
		bool HasDataVariables() const;

		Ref<Structure> CreateStructureFromOffsetAccess(const QualifiedName& type, bool* newMemberAdded) const;
		Confidence<Ref<Type>> CreateStructureMemberFromAccess(const QualifiedName& name, uint64_t offset) const;

		/*! Create a logger with a session ID tied to this BinaryView.

		 	Whenever this logger is used, if "Log Scope" is set to "Current Tab", it will only be shown for tabs
		 	Displaying this BinaryView

		 	\see Logger
		 	\see LogRegistry

			\param name Name for the logger
			\return The created Logger
		*/
		Ref<Logger> CreateLogger(const std::string& name);

		/*! Add a magic value to the expression parser

			If the magic value already exists, its value gets updated.
			The magic value can be used in the expression by a `$` followed by its name, e.g., `$foobar`.
		 	It is optional to include the `$` when calling this function, i.e., calling with `foobar` and `$foobar`
		 	has the same effect.

			\param name Name for the magic value to add or update
			\param value Value for the magic value
		*/
		void AddExpressionParserMagicValue(const std::string& name, uint64_t value);

		/*! Remove a magic value from the expression parser

			If the magic value gets referenced after removal, an error will occur during the parsing.

			\param name Name for the magic value to remove
			\param value Value for the magic value
		*/
		void RemoveExpressionParserMagicValue(const std::string& name);

		/*! Add a list of magic value to the expression parser

		 	The vector `names` and `values` must have the same size. The ith name in the `names` will correspond to
		 	the ith value in the `values`.

			If a magic value already exists, its value gets updated.
			The magic value can be used in the expression by a `$` followed by its name, e.g., `$foobar`.
		 	It is optional to include the `$` when calling this function, i.e., calling with `foobar` and `$foobar`
		 	has the same effect.

			\param name Names for the magic values to add or update
			\param value Values for the magic value
		*/
		void AddExpressionParserMagicValues(const std::vector<std::string>& names, const std::vector<uint64_t>& values);

		/*! Remove a list of magic value from the expression parser

			If any of the magic values gets referenced after removal, an error will occur during the parsing.

			\param name Names for the magic value to remove
		*/
		void RemoveExpressionParserMagicValues(const std::vector<std::string>& names);

		/*! Get the value of an expression parser magic value

		 	If the queried magic value exists, the function returns true and the magic value is returned in `value`.
		 	If the queried magic value does not exist, the function returns false.

			\param[in] name Name for the magic value to query
			\param[out] value Value for the magic value
		 	\return Whether the magic value exists
		*/
		bool GetExpressionParserMagicValue(const std::string& name, uint64_t* value);

		Ref<ExternalLibrary> AddExternalLibrary(const std::string& name, Ref<ProjectFile> backingFile, bool isAuto = false);
		void RemoveExternalLibrary(const std::string& name);
		Ref<ExternalLibrary> GetExternalLibrary(const std::string& name);
		std::vector<Ref<ExternalLibrary>> GetExternalLibraries();

		Ref<ExternalLocation> AddExternalLocation(Ref<Symbol> sourceSymbol, Ref<ExternalLibrary> library, std::optional<std::string> targetSymbol, std::optional<uint64_t> targetAddress, bool isAuto = false);
		void RemoveExternalLocation(Ref<Symbol> sourceSymbol);
		Ref<ExternalLocation> GetExternalLocation(Ref<Symbol> sourceSymbol);
		std::vector<Ref<ExternalLocation>> GetExternalLocations();

		Confidence<RegisterValue> GetGlobalPointerValue() const;
		bool UserGlobalPointerValueSet() const;
		void ClearUserGlobalPointerValue();
		void SetUserGlobalPointerValue(const Confidence<RegisterValue>& value);

		std::optional<std::pair<std::string, BNStringType>> StringifyUnicodeData(
			Architecture* arch, const DataBuffer& buffer, bool allowShortStrings = false);
	};

	class MemoryMap
	{
		BNBinaryView* m_object;

	public:
		MemoryMap(BNBinaryView* view): m_object(view) {}
		~MemoryMap() = default;

		void SetLogicalMemoryMapEnabled(bool enabled)
		{
			BNSetLogicalMemoryMapEnabled(m_object, enabled);
		}

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
		\ingroup binaryview
	*/
	class Relocation : public CoreRefCountObject<BNRelocation, BNNewRelocationReference, BNFreeRelocation>
	{
	  public:
		Relocation(BNRelocation* reloc);
		BNRelocationInfo GetInfo() const;
		Architecture* GetArchitecture() const;
		uint64_t GetTarget() const;
		uint64_t GetAddress() const;
		Ref<Symbol> GetSymbol() const;
	};


	/*!
		\ingroup binaryview
	*/
	class BinaryData : public BinaryView
	{
		BinaryData(BNBinaryView* view);

	  public:
		BinaryData(FileMetadata* file);
		BinaryData(FileMetadata* file, const DataBuffer& data);
		BinaryData(FileMetadata* file, const void* data, size_t len);
		BinaryData(FileMetadata* file, const std::string& path);
		BinaryData(FileMetadata* file, FileAccessor* accessor);

		/*!
			Open a raw file from a given path.
			This is lifted out into a method because this operation can fail.
			\param file Metadata structure
			\param path Path to file to open
			\return Reference to binary data if successful, nullptr reference otherwise
		 */
		static Ref<BinaryData> CreateFromFilename(FileMetadata* file, const std::string& path);

		/*!
			Open a raw file from a given path.
			This is lifted out into a method because this operation can fail.
			\param file Metadata structure
			\param accessor File accessor object for reading file contents
			\return Reference to binary data if successful, nullptr reference otherwise
		 */
		static Ref<BinaryData> CreateFromFile(FileMetadata* file, FileAccessor* accessor);
	};

	class Platform;

	/*! The \c BinaryViewType object is used internally and should not be directly instantiated.
		\ingroup binaryview
	*/
	class BinaryViewType : public StaticCoreRefCountObject<BNBinaryViewType>
	{
		struct BinaryViewEvent
		{
			std::function<void(BinaryView*)> action;
		};

		struct PlatformRecognizerFunction
		{
			std::function<Ref<Platform>(BinaryView*, Metadata*)> action;
		};

	  protected:
		std::string m_nameForRegister, m_longNameForRegister;

		static BNBinaryView* CreateCallback(void* ctxt, BNBinaryView* data);
		static BNBinaryView* ParseCallback(void* ctxt, BNBinaryView* data);
		static bool IsValidCallback(void* ctxt, BNBinaryView* data);
		static bool IsDeprecatedCallback(void* ctxt);
		static bool IsForceLoadableCallback(void *ctxt);
		static BNSettings* GetSettingsCallback(void* ctxt, BNBinaryView* data);

		BinaryViewType(BNBinaryViewType* type);

	  public:
		BinaryViewType(const std::string& name, const std::string& longName);
		virtual ~BinaryViewType() {}

		/*! Register a BinaryViewType

			\param type BinaryViewType to register
		*/
		static void Register(BinaryViewType* type);

		/*! Get a BinaryViewType by name

			\param name Name of the registered BinaryViewType
			\return The BinaryViewType, if one was registered
		*/
		static Ref<BinaryViewType> GetByName(const std::string& name);

		/*! Get the list of registered View Types

			\return Get the list of registered View Types
		*/
		static std::vector<Ref<BinaryViewType>> GetViewTypes();

		/*! Get the list of valid view types for a BinaryView

			\param data BinaryView for a binary
			\return List of valid view types
		*/
		static std::vector<Ref<BinaryViewType>> GetViewTypesForData(BinaryView* data);

		/*! Register an Architecture for a specific view type

			\param name Name of the view type
			\param id ID of the architecture
			\param endian Endianness of the architecture
			\param arch Architecture
		*/
		static void RegisterArchitecture(const std::string& name, uint32_t id, BNEndianness endian, Architecture* arch);

		/*! Register an Architecture for this view type

			\param id ID of the architecture
			\param endian Endianness of the architecture
			\param arch Architecture
		*/
		void RegisterArchitecture(uint32_t id, BNEndianness endian, Architecture* arch);

		/*! Get an Architecture for this BinaryViewType by id and endianness

		    \param id ID of the architecture
		    \param endian Endianness of the architecture
			\return The architecture, if it was found
		*/
		Ref<Architecture> GetArchitecture(uint32_t id, BNEndianness endian);

		/*! Register a Platform for a specific view type

			\param name Name of the BinaryViewType
			\param id ID of the platform
			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		static void RegisterPlatform(const std::string& name, uint32_t id, Architecture* arch, Platform* platform);

		/*! Register a Platform as a default for a specific view type

			\param name Name of the BinaryViewType
			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		static void RegisterDefaultPlatform(const std::string& name, Architecture* arch, Platform* platform);

		/*! Register a Platform for this view type

			\param id ID of the platform
			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		void RegisterPlatform(uint32_t id, Architecture* arch, Platform* platform);

		/*! Register a Platform as a default for this view type

			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		void RegisterDefaultPlatform(Architecture* arch, Platform* platform);

		/*! Get a platform by ID and architecture

			\param id ID of the platform
			\param arch Architecture of the Platform
			\return The Platform, if it was found.
		*/
		Ref<Platform> GetPlatform(uint32_t id, Architecture* arch);

		void RegisterPlatformRecognizer(uint64_t id, BNEndianness endian,
		    const std::function<Ref<Platform>(BinaryView* view, Metadata*)>& callback);
		Ref<Platform> RecognizePlatform(uint64_t id, BNEndianness endian, BinaryView* view, Metadata* metadata);

		/*! Get the name this platform was registered with

			\return The name of the platform
		*/
		std::string GetName();

		/*! Get the "Long Name" this platform was registered with

			\return The "Long Name" this platform was registered with
		*/
		std::string GetLongName();

		virtual bool IsDeprecated();

		/*! Create a BinaryView for this BinaryViewType given the data from an existing BinaryView

			\param data An existing BinaryView, typically with the \c Raw type
			\return The BinaryView created by this BinaryViewType
		*/
		virtual Ref<BinaryView> Create(BinaryView* data) = 0;

		/*! Create ephemeral BinaryView to generate information for preview

			\param data An existing BinaryView, typically with the \c Raw type
			\return The BinaryView created by this BinaryViewType
		*/
		virtual Ref<BinaryView> Parse(BinaryView* data);

		/*! Check whether this BinaryViewType is valid for given data

			\param data An existing BinaryView, typically with the \c Raw type
			\return Whether this BinaryViewType is valid for given data
		*/
		virtual bool IsTypeValidForData(BinaryView* data) = 0;

		/*! Check whether this BinaryViewType can be forced to load a binary, even if IsTypeValidForData returns false

			\return Whether this BinaryViewType can be forced to load a binary
		*/
		virtual bool IsForceLoadable();

		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data);
		Ref<Settings> GetDefaultLoadSettingsForData(BinaryView* data);

		static void RegisterBinaryViewFinalizationEvent(const std::function<void(BinaryView* view)>& callback);
		static void RegisterBinaryViewInitialAnalysisCompletionEvent(
		    const std::function<void(BinaryView* view)>& callback);

		static void BinaryViewEventCallback(void* ctxt, BNBinaryView* view);
		static BNPlatform* PlatformRecognizerCallback(void* ctxt, BNBinaryView* view, BNMetadata* metadata);
	};

	/*!
		\ingroup binaryview
	*/
	class CoreBinaryViewType : public BinaryViewType
	{
	  public:
		CoreBinaryViewType(BNBinaryViewType* type);
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual bool IsDeprecated() override;
		virtual bool IsForceLoadable() override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	/*! Thrown whenever a read is performed out of bounds.

		\ingroup binaryview
	*/
	class ReadException : public ExceptionWithStackTrace
	{
	  public:
		ReadException() : ExceptionWithStackTrace("read out of bounds") {}
	};

	/*! BinaryReader is a convenience class for reading binary data
		\ingroup binaryview
	*/
	class BinaryReader
	{
		Ref<BinaryView> m_view;
		BNBinaryReader* m_stream;

	  public:
		/*! Create a BinaryReader instance given a BinaryView and endianness.

			\param data BinaryView to read from
			\param endian Byte order to read with. One of LittleEndian, BigEndian
		*/
		BinaryReader(BinaryView* data, BNEndianness endian = LittleEndian);
		~BinaryReader();

		/*! Get the endianness set for this reader.

			\return The endianness set for this reader.
		*/
		BNEndianness GetEndianness() const;

		/*! Set the endianness for this reader

		    \param endian Byte order to read with. One of LittleEndian, BigEndian
		*/
		void SetEndianness(BNEndianness endian);

		/*! Read from the current cursor position into buffer `dest`

		    \throws ReadException
			\param dest Address to write the read bytes to
			\param len Number of bytes to write
		*/
		void Read(void* dest, size_t len);
		/*! Read from the current cursor position into a DataBuffer

		    \throws ReadException
			\param len Number of bytes to read
			\return DataBuffer containing the bytes read
		*/
		DataBuffer Read(size_t len);
		template <typename T>
		T Read();
		template <typename T>
		std::vector<T> ReadVector(size_t count);

		/*! Read a string of fixed length from the current cursor position

		    \throws ReadException
			\param len Length of the string
			\return the string
		*/
		std::string ReadString(size_t len);

		/*! Read a null-terminated string from the current cursor position

		    \throws ReadException
			\param maxLength Maximum length of the string, default is no limit (-1)
			\return the string
		*/
		std::string ReadCString(size_t maxLength = -1);

		/*! Read a uint8_t from the current cursor position and advance the cursor by 1 byte

		    \throws ReadException
			\return The read value
		*/
		uint8_t Read8();

		/*! Read a uint16_t from the current cursor position and advance the cursor by 2 bytes

		    \throws ReadException
			\return The read value
		*/
		uint16_t Read16();

		/*! Read a uint32_t from the current cursor position and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint32_t Read32();

		/*! Read a uint64_t from the current cursor position and advance the cursor by 8 bytes

		    \throws ReadException
			\return The read value
		*/
		uint64_t Read64();

		/*! Read a pointer (size of BinaryView::GetAddressSize()) from the current cursor position and advance
		    and advance it that many bytes

		    \throws ReadException
		    \return The value that was read
		*/
		uint64_t ReadPointer();

		/*! Read a uint16_t from the current cursor position, explicitly as a little endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint16_t ReadLE16();

		/*! Read a uint16_t from the current cursor position, explicitly as a little endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint32_t ReadLE32();

		/*! Read a uint16_t from the current cursor position, explicitly as a little endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint64_t ReadLE64();

		/*! Read a pointer (size of BinaryView::GetAddressSize()) as little-endian from the current cursor
		    position and advance and advance it that many bytes

		    \throws ReadException
		    \return The value that was read
		*/
		uint64_t ReadLEPointer();

		/*! Read a uint16_t from the current cursor position, explicitly as a big endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint16_t ReadBE16();

		/*! Read a uint16_t from the current cursor position, explicitly as a big endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint32_t ReadBE32();

		/*! Read a uint16_t from the current cursor position, explicitly as a big endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint64_t ReadBE64();

		/*! Read a pointer (size of BinaryView::GetAddressSize()) as big-endian from the current cursor
		    position and advance and advance it that many bytes

		    \throws ReadException
		    \return The value that was read
		*/
		uint64_t ReadBEPointer();

		/*! Try reading a value, returning false whenever that read fails

			\param dest Address to write the bytes to
			\param len Number of bytes to read
			\return Whether the read succeeded
		*/
		bool TryRead(void* dest, size_t len);

		/*! Try reading a value into a databuffer

			\param dest Reference to a DataBuffer to write to
			\param len Amount of bytes to read
			\return Whether the read succeeded
		*/
		bool TryRead(DataBuffer& dest, size_t len);

		/*! Try reading a string

			\param dest Reference to a string to write to
			\param len Length of the string to be read
			\return Whether the read succeeded
		*/
		bool TryReadString(std::string& dest, size_t len);

		/*! Try reading a uint8_t

			\param result Reference to a uint8_t to write to
			\return Whether the read succeeded.
		*/
		bool TryRead8(uint8_t& result);

		/*! Try reading a uint16_t

		    \param result Reference to a uint16_t to write to
		    \return Whether the read succeeded.
		*/
		bool TryRead16(uint16_t& result);

		/*! Try reading a uint32_t

			\param result Reference to a uint32_t to write to
			\return Whether the read succeeded.
		*/
		bool TryRead32(uint32_t& result);

		/*! Try reading a uint64_t

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryRead64(uint64_t& result);

		/*! Try reading a pointer (size of BinaryView::GetAddressSize())

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadPointer(uint64_t& result);

		/*! Try reading a uint16_t, explicitly as little endian

			\param result Reference to a uint16_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLE16(uint16_t& result);

		/*! Try reading a uint32_t, explicitly as little endian

			\param result Reference to a uint32_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLE32(uint32_t& result);

		/*! Try reading a uint64_t, explicitly as little endian

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLE64(uint64_t& result);

		/*! Try reading a pointer (size of BinaryView::GetAddressSize()) as little-endian

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLEPointer(uint64_t& result);

		/*! Try reading a uint16_t, explicitly as big endian

			\param result Reference to a uint16_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBE16(uint16_t& result);

		/*! Try reading a uint32_t, explicitly as big endian

			\param result Reference to a uint32_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBE32(uint32_t& result);

		/*! Try reading a uint64_t, explicitly as big endian

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBE64(uint64_t& result);

		/*! Try reading a pointer (size of BinaryView::GetAddressSize()) as big-endian

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBEPointer(uint64_t& result);

		/*! Get the current cursor position

			\return The current cursor position
		*/
		uint64_t GetOffset() const;

		/*! Set the cursor position

			\param offset The new cursor position
		*/
		void Seek(uint64_t offset);

		/*! Set the cursor position, relative to the current position

			\param offset Offset to the current cursor position
		*/
		void SeekRelative(int64_t offset);

		/*! Gets the virtual base offset for the stream

			\return The current virtual base
		*/
		uint64_t GetVirtualBase();

		/*! Sets a virtual base offset for the stream

			\param base The new virtual base
		*/
		void SetVirtualBase(uint64_t base);

		/*! Whether the current cursor position is at the end of the file.

		*/
		bool IsEndOfFile() const;
	};

	/*! Raised whenever a write is performed out of bounds.

		\ingroup binaryview
	*/
	class WriteException : public ExceptionWithStackTrace
	{
	  public:
		WriteException() : ExceptionWithStackTrace("write out of bounds") {}
	};

	/*! BinaryWriter is a convenience class for writing binary data
	 	\ingroup binaryview
	*/
	class BinaryWriter
	{
		Ref<BinaryView> m_view;
		BNBinaryWriter* m_stream;

	  public:

		/*! Create a BinaryWriter instance given a BinaryView and endianness.

			\param data BinaryView to write to
			\param endian Byte order to write with. One of LittleEndian, BigEndian
		*/
		BinaryWriter(BinaryView* data, BNEndianness endian = LittleEndian);
		~BinaryWriter();


		/*! Get the endianness set for this writer.

			\return The endianness set for this writer.
		*/
		BNEndianness GetEndianness() const;

		/*! Set the endianness for this writer

		    \param endian Byte order to write with. One of LittleEndian, BigEndian
		*/
		void SetEndianness(BNEndianness endian);

		/*! Write bytes from an address to the current cursor position

		 	\throws WriteException on out of bounds write
			\param src Address to read the bytes from
			\param len Amount of bytes to write
		*/
		void Write(const void* src, size_t len);

		/*! Write the contents of a DataBuffer to the current cursor position

		    \throws WriteException on out of bounds write
			\param buf DataBuffer to write from
		*/
		void Write(const DataBuffer& buf);

		/*! Write the contents of a string to the current cursor position

		    \throws WriteException on out of bounds write
			\param str String to write
		*/
		void Write(const std::string& str);

		/*! Write a uint8_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint8_t to write
		*/
		void Write8(uint8_t val);

		/*! Write a uint16_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint16_t to write
		*/
		void Write16(uint16_t val);

		/*! Write a uint32_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint32_t to write
		*/
		void Write32(uint32_t val);

		/*! Write a uint64_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint64_t to write
		*/
		void Write64(uint64_t val);

		/*! Write a uint16_t to the current cursor position, explicitly as little endian

		    \throws WriteException on out of bounds write
			\param val uint16_t to write
		*/
		void WriteLE16(uint16_t val);

		/*! Write a uint32_t to the current cursor position, explicitly as little endian

		    \throws WriteException on out of bounds write
			\param val uint32_t to write
		*/
		void WriteLE32(uint32_t val);

		/*! Write a uint64_t to the current cursor position, explicitly as little endian

		    \throws WriteException on out of bounds write
			\param val uint64_t to write
		*/
		void WriteLE64(uint64_t val);

		/*! Write a uint16_t to the current cursor position, explicitly as big endian

		    \throws WriteException on out of bounds write
			\param val uint16_t to write
		*/
		void WriteBE16(uint16_t val);

		/*! Write a uint32_t to the current cursor position, explicitly as big endian

		    \throws WriteException on out of bounds write
			\param val uint32_t to write
		*/
		void WriteBE32(uint32_t val);

		/*! Write a uint64_t to the current cursor position, explicitly as big endian

		    \throws WriteException on out of bounds write
			\param val uint64_t to write
		*/
		void WriteBE64(uint64_t val);

		/*! Write bytes from an address to the current cursor position

			\param src Address to read the bytes from
			\param len Amount of bytes to write
		 	\return Whether the write succeeded
		*/
		bool TryWrite(const void* src, size_t len);

		/*! Write from a DataBuffer to the current cursor position

			\param buf DataBuffer to write from
			\return Whether the write succeeded
		*/
		bool TryWrite(const DataBuffer& buf);

		/*! Write a string to the current cursor position

			\param str String to write
			\return Whether the write succeeded
		*/
		bool TryWrite(const std::string& str);

		/*! Write a uint8_t to the current cursor position

			\param val uint8_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite8(uint8_t val);

		/*! Write a uint16_t to the current cursor position

			\param val uint16_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite16(uint16_t val);

		/*! Write a uint32_t to the current cursor position

			\param val uint32_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite32(uint32_t val);

		/*! Write a uint64_t to the current cursor position

			\param val uint64_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite64(uint64_t val);
		bool TryWriteLE16(uint16_t val);
		bool TryWriteLE32(uint32_t val);
		bool TryWriteLE64(uint64_t val);
		bool TryWriteBE16(uint16_t val);
		bool TryWriteBE32(uint32_t val);
		bool TryWriteBE64(uint64_t val);

		/*! Get the current cursor position

			\return The current cursor position
		*/
		uint64_t GetOffset() const;

		/*! Set the current cursor position

			\param offset The new cursor position
		*/
		void Seek(uint64_t offset);

		/*! Set the cursor position relative to the current cursor position

			\param offset Offset to the current cursor position
		*/
		void SeekRelative(int64_t offset);
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

	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class LanguageRepresentationFunction;
	class FunctionRecognizer;
	class CallingConvention;
	class RelocationHandler;

	typedef size_t ExprId;

	/*! The Architecture class is the base class for all CPU architectures. This provides disassembly, assembly,
	    patching, and IL translation lifting for a given architecture.

	    \ingroup architectures
	*/
	class Architecture : public StaticCoreRefCountObject<BNArchitecture>
	{
	  protected:
		std::string m_nameForRegister;

		Architecture(BNArchitecture* arch);

		static void InitCallback(void* ctxt, BNArchitecture* obj);
		static BNEndianness GetEndiannessCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static size_t GetDefaultIntegerSizeCallback(void* ctxt);
		static size_t GetInstructionAlignmentCallback(void* ctxt);
		static size_t GetMaxInstructionLengthCallback(void* ctxt);
		static size_t GetOpcodeDisplayLengthCallback(void* ctxt);
		static BNArchitecture* GetAssociatedArchitectureByAddressCallback(void* ctxt, uint64_t* addr);
		static bool GetInstructionInfoCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
		static bool GetInstructionTextCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len,
		    BNInstructionTextToken** result, size_t* count);
		static void FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count);
		static bool GetInstructionLowLevelILCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
		static char* GetRegisterNameCallback(void* ctxt, uint32_t reg);
		static char* GetFlagNameCallback(void* ctxt, uint32_t flag);
		static char* GetFlagWriteTypeNameCallback(void* ctxt, uint32_t flags);
		static char* GetSemanticFlagClassNameCallback(void* ctxt, uint32_t semClass);
		static char* GetSemanticFlagGroupNameCallback(void* ctxt, uint32_t semGroup);
		static uint32_t* GetFullWidthRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagsCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagWriteTypesCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllSemanticFlagClassesCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllSemanticFlagGroupsCallback(void* ctxt, size_t* count);
		static BNFlagRole GetFlagRoleCallback(void* ctxt, uint32_t flag, uint32_t semClass);
		static uint32_t* GetFlagsRequiredForFlagConditionCallback(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
		static uint32_t* GetFlagsRequiredForSemanticFlagGroupCallback(void* ctxt, uint32_t semGroup, size_t* count);
		static BNFlagConditionForSemanticClass* GetFlagConditionsForSemanticFlagGroupCallback(
		    void* ctxt, uint32_t semGroup, size_t* count);
		static void FreeFlagConditionsForSemanticFlagGroupCallback(
		    void* ctxt, BNFlagConditionForSemanticClass* conditions, size_t count);
		static uint32_t* GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count);
		static uint32_t GetSemanticClassForFlagWriteTypeCallback(void* ctxt, uint32_t writeType);
		static size_t GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size,
		    uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
		    BNLowLevelILFunction* il);
		static size_t GetFlagConditionLowLevelILCallback(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
		static size_t GetSemanticFlagGroupLowLevelILCallback(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs, size_t len);
		static void GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		static uint32_t GetStackPointerRegisterCallback(void* ctxt);
		static uint32_t GetLinkRegisterCallback(void* ctxt);
		static uint32_t* GetGlobalRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetSystemRegistersCallback(void* ctxt, size_t* count);

		static char* GetRegisterStackNameCallback(void* ctxt, uint32_t regStack);
		static uint32_t* GetAllRegisterStacksCallback(void* ctxt, size_t* count);
		static void GetRegisterStackInfoCallback(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		static BNIntrinsicClass GetIntrinsicClassCallback(void* ctxt, uint32_t intrinsic);
		static char* GetIntrinsicNameCallback(void* ctxt, uint32_t intrinsic);
		static uint32_t* GetAllIntrinsicsCallback(void* ctxt, size_t* count);
		static BNNameAndType* GetIntrinsicInputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeNameAndTypeListCallback(void* ctxt, BNNameAndType* nt, size_t count);
		static BNTypeWithConfidence* GetIntrinsicOutputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeTypeListCallback(void* ctxt, BNTypeWithConfidence* types, size_t count);

		static bool CanAssembleCallback(void* ctxt);
		static bool AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);
		static bool IsNeverBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsAlwaysBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsInvertBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnZeroPatchAvailableCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnValuePatchAvailableCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t len);

		static bool ConvertToNopCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool AlwaysBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool InvertBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool SkipAndReturnValueCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		virtual void Register(BNCustomArchitecture* callbacks);

	  public:
		Architecture(const std::string& name);

		/*! Register an architecture

			\param arch Architecture to register
		*/
		static void Register(Architecture* arch);

		/*! Get an Architecture by name

			\param name Name of the architecture
			\return The architecture, if it was found.
		*/
		static Ref<Architecture> GetByName(const std::string& name);

		/*! Get the list of registered Architectures

			\return The list of registered architectures
		*/
		static std::vector<Ref<Architecture>> GetList();

		/*! Get the name of this architecture

			\return The name of this architecture
		*/
		std::string GetName() const;

		/*! Get the default endianness for this architecture

			\return The default endianness for this architecture
		*/
		virtual BNEndianness GetEndianness() const = 0;

		/*! Get the address size for this architecture

			\return The address size for this architecture
		*/
		virtual size_t GetAddressSize() const = 0;

		/*! Get the default integer size for this architecture

			\return The default integer size for this architecture
		*/
		virtual size_t GetDefaultIntegerSize() const;
		virtual size_t GetInstructionAlignment() const;

		/*! Get the maximum instruction length

			\return The maximum instruction length
		*/
		virtual size_t GetMaxInstructionLength() const;
		virtual size_t GetOpcodeDisplayLength() const;

		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr);

		/*! Retrieves an InstructionInfo struct for the instruction at the given virtual address

		 	\note Architecture subclasses should implement this method.
		 	\note The instruction info object should always set the InstructionInfo.length to the instruction length, \
					and the branches of the proper types should be added if the instruction is a branch.

			If the instruction is a branch instruction architecture plugins should add a branch of the proper type:

				===================== ===================================================
				BNBranchType          Description
				===================== ===================================================
				UnconditionalBranch   Branch will always be taken
				FalseBranch           False branch condition
				TrueBranch            True branch condition
				CallDestination       Branch is a call instruction (Branch with Link)
				FunctionReturn        Branch returns from a function
				SystemCall            System call instruction
				IndirectBranch        Branch destination is a memory address or register
				UnresolvedBranch      Branch destination is an unknown address
				===================== ===================================================

			\param[in] data pointer to the instruction data to retrieve info for
		    \param[in] addr address of the instruction data to retrieve info for
			\param[in] maxLen Maximum length of the instruction data to read
			\param[out] result Retrieved instruction info
			\return Whether instruction info was successfully retrieved.
		*/
		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;

		/*! Retrieves a list of InstructionTextTokens

			\param[in] data pointer to the instruction data to retrieve text for
			\param[in] addr address of the instruction data to retrieve text for
			\param[out] len will be written to with the length of the instruction data which was translated
			\param[out] result
			\return Whether instruction info was successfully retrieved.
		*/
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) = 0;

		/*! Translates an instruction at addr and appends it onto the LowLevelILFunction& il.

		    \note Architecture subclasses should implement this method.

		    \param[in] data pointer to the instruction data to be translated
		    \param[in] addr address of the instruction data to be translated
		    \param[out] len will be written to with the length of the instruction data which was translated
		    \param[in,out] il the LowLevelILFunction to appended to.
		*/
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il);

		/*! Gets a register name from a register index.

			\param reg Register index
			\return The register name
		*/
		virtual std::string GetRegisterName(uint32_t reg);

		/*! Gets a flag name from a flag index

			\param flag Flag index
			\return Flag name
		*/
		virtual std::string GetFlagName(uint32_t flag);

		/*! Gets the flag write type name for the given flag.

			\param flags flag
			\return Flag name
		*/
		virtual std::string GetFlagWriteTypeName(uint32_t flags);

		/*! Gets the name of a semantic flag class from the index.

			\param semClass Semantic class index
			\return The name of the semantic flag class
		*/
		virtual std::string GetSemanticFlagClassName(uint32_t semClass);

		/*! Gets the name of a semantic flag group from the index.

			\param semGroup Semantic flag group index
			\return Semantic flag group name
		*/
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup);

		/*! Get the list of full width register indices

			\return The list of full width register indices
		*/
		virtual std::vector<uint32_t> GetFullWidthRegisters();

		/*! Get the list of all register indices

			\return The list of all register indices
		*/
		virtual std::vector<uint32_t> GetAllRegisters();

		/*! Get the list of all flag indices

			\return The list of all flag indices
		*/
		virtual std::vector<uint32_t> GetAllFlags();

		/*! Get the list of all flag write type indices

			\return The list of all flag write type indices
		*/
		virtual std::vector<uint32_t> GetAllFlagWriteTypes();

		/*! Get the list of all semantic flag class indices

			\return The list of all semantic flag class indices
		*/
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses();

		/*! Get the list of all semantic flag group indices

			\return The list of all semantic flag group indices
		*/
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups();

		/*! Get the role of a given flag.

			\param flag Flag index
			\param semClass Optional semantic flag class
			\return Flag role
		*/
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup);
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup);
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType);
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType);
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		ExprId GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, BNFlagRole role,
		    BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		ExprId GetDefaultFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il);

		/*! Get the register info for a given register index

			\param reg Register index
			\return Register info
		*/
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);

		/*! Get the register index corresponding to the stack pointer (SP)

			\return The register index corresponding to the stack pointer
		*/
		virtual uint32_t GetStackPointerRegister();

		/*! Get the register index corresponding to the link register (LR)

			\return The register index corresponding to the link register
		*/
		virtual uint32_t GetLinkRegister();
		virtual std::vector<uint32_t> GetGlobalRegisters();
		bool IsGlobalRegister(uint32_t reg);

		/*! Get the list of system register indices

			\return The list of system register indices
		*/
		virtual std::vector<uint32_t> GetSystemRegisters();

		/*! Check whether a register is a system register

			\param reg Register index
			\return Whether a register is a system register
		*/
		bool IsSystemRegister(uint32_t reg);

		/*! Returns a list of register indices that are modified when \c reg is written to.

			\param reg Register index
			\return List of register indices modified on write.
		*/
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);

		/*! Get a register index by its name

			\param name Name of the register
			\return Index of the register
		*/
		uint32_t GetRegisterByName(const std::string& name);

		/*! Get a register stack name from a register stack number.

			\param regStack Register stack number
			\return The corresponding register string
		*/
		virtual std::string GetRegisterStackName(uint32_t regStack);
		virtual std::vector<uint32_t> GetAllRegisterStacks();
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack);
		uint32_t GetRegisterStackForRegister(uint32_t reg);

		virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic);
		virtual std::string GetIntrinsicName(uint32_t intrinsic);
		virtual std::vector<uint32_t> GetAllIntrinsics();
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic);
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic);

		/*! Check whether this architecture can assemble instructions

			\return Whether this architecture can assemble instructions
		*/
		virtual bool CanAssemble();

		/*! Converts the string of assembly instructions \c code loaded at virtual address \c addr to the
			byte representation of those instructions.

			\param[in] code String representation of the instructions to be assembled
			\param[in] addr Address of the instructions
			\param[out] result DataBuffer containing the compiled bytes
			\param[out] errors Any errors that occurred during assembly
			\return Whether assembly was successful
		*/
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors);

		/*! Returns true if the instruction at \c addr can be patched to never branch.

		    \note This is used in the UI to determine if "never branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the virtual address of the bytes, to be used when assembling
		    \param len amount of bytes to be checked
		    \return If the never branch patch is available
		*/
		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Returns true if the instruction at addr can be patched to always branch.

		    \note This is used in the UI to determine if "always branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
		    \return If the always branch patch is available
		*/
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Returns true if the instruction at addr can be patched to invert the branch.

		    \note This is used in the UI to determine if "invert branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
			\param len amount of bytes to be checked
			\return If the invert branch patch is available
		*/
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Checks if the instruction at addr is a call that can be patched to return zero.

			\note This is used in the UI to determine if "skip and return zero" should be displayed in the
		    right-click context menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
			\return If the skip and return zero patch is available
		*/
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Checks if the instruction at addr is a call that can be patched to return a value.

		    \note This is used in the UI to determine if "skip and return value" should be displayed in the
		    right-click context menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
			\return If the skip and return value patch is available
		*/
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Converts the instruction at addr to a no-operation instruction

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len);

		/*! Converts the conditional branch instruction at addr to an unconditional branch.

			\note This is called when the right-click context menu item "always branch" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! InvertBranch converts the conditional branch instruction at addr to its invert.

			\note This is called when the right-click context menu item "invert branch" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! SkipAndReturnValue converts the call instruction at addr to an instruction that simulates that call
		    returning a value.

		    \note This is called when the right-click context menu item "skip and return value" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \param[in] value Value to be returned
		    \return Whether the conversion was successful
		*/
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		void RegisterFunctionRecognizer(FunctionRecognizer* recog);
		void RegisterRelocationHandler(const std::string& viewName, RelocationHandler* handler);
		Ref<RelocationHandler> GetRelocationHandler(const std::string& viewName);

		// These three binary view type constant APIs are deprecated and should no longer be used. Their implementations
		// have been removed, and they now have no effects.
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no longer has any effect
		*/
		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no longer has any effect
		*/
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t defaultValue = 0);
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no longer has any effect
		*/
		void SetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t value);

		/*! Register a calling convention with this architecture

			\param cc calling convention to register
		*/
		void RegisterCallingConvention(CallingConvention* cc);

		/*! List of registered calling conventions

			\return The list of registered calling conventions
		*/
		std::vector<Ref<CallingConvention>> GetCallingConventions();

		/*! Get a calling convention by name

			\param name Name of the calling convention
			\return The calling convention
		*/
		Ref<CallingConvention> GetCallingConventionByName(const std::string& name);

		/*! Set the default calling convention

			\param cc The default calling convention
		*/
		void SetDefaultCallingConvention(CallingConvention* cc);

		/*! Set the cdecl calling convention

			\param cc The cdecl calling convention
		*/
		void SetCdeclCallingConvention(CallingConvention* cc);

		/*! Set the stdcall calling convention

			\param cc The stdcall calling convention
		*/
		void SetStdcallCallingConvention(CallingConvention* cc);

		/*! Set the fastcall calling convention

			\param cc The fastcall calling convention
		*/
		void SetFastcallCallingConvention(CallingConvention* cc);

		/*! Get the default calling convention

			\return The default calling convention
		*/
		Ref<CallingConvention> GetDefaultCallingConvention();

		/*! Get the cdecl calling convention

			\return The cdecl calling convention
		*/
		Ref<CallingConvention> GetCdeclCallingConvention();

		/*! Get the stdcall calling convention

			\return The stdcall calling convention
		*/
		Ref<CallingConvention> GetStdcallCallingConvention();

		/*! Get the fastcall calling convention

			\return The fastcall calling convention
		*/
		Ref<CallingConvention> GetFastcallCallingConvention();

		/*! Get the Architecture standalone platform

			\return Architecture standalone platform
		*/
		Ref<Platform> GetStandalonePlatform();

		std::vector<Ref<TypeLibrary>> GetTypeLibraries();

		void AddArchitectureRedirection(Architecture* from, Architecture* to);
	};

	/*!

	 	\ingroup architectures
	*/
	class CoreArchitecture : public Architecture
	{
	  public:
		CoreArchitecture(BNArchitecture* arch);
		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
		virtual size_t GetInstructionAlignment() const override;
		virtual size_t GetMaxInstructionLength() const override;
		virtual size_t GetOpcodeDisplayLength() const override;
		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
		virtual bool GetInstructionInfo(
		    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(
		    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;

		virtual std::string GetSemanticFlagClassName(uint32_t semClass) override;
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(
		    uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual std::vector<uint32_t> GetSystemRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic) override;
		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

		virtual bool CanAssemble() override;
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override;

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override;
	};

	/*!

		\ingroup architectures
	*/
	class ArchitectureExtension : public Architecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureExtension(const std::string& name, Architecture* base);

		Ref<Architecture> GetBaseArchitecture() const { return m_base; }

		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
		virtual size_t GetInstructionAlignment() const override;
		virtual size_t GetMaxInstructionLength() const override;
		virtual size_t GetOpcodeDisplayLength() const override;
		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
		virtual bool GetInstructionInfo(
		    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(
		    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;
		virtual std::string GetSemanticFlagClassName(uint32_t semClass) override;
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(
		    uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual std::vector<uint32_t> GetSystemRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic) override;
		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

		virtual bool CanAssemble() override;
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override;

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override;
	};

	/*!

		\ingroup architectures
	*/
	class ArchitectureHook : public CoreArchitecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureHook(Architecture* base);
	};

	class Structure;
	class NamedTypeReference;
	class Enumeration;

	/*!
		\ingroup variable
	*/
	struct Variable : public BNVariable
	{
		Variable();
		Variable(BNVariableSourceType type, uint32_t index, uint64_t storage);
		Variable(BNVariableSourceType type, uint64_t storage);
		Variable(const BNVariable& var);
		Variable(const Variable& var);

		Variable& operator=(const Variable& var);

		bool operator==(const Variable& var) const;
		bool operator!=(const Variable& var) const;
		bool operator<(const Variable& var) const;

		uint64_t ToIdentifier() const;
		static Variable FromIdentifier(uint64_t id);
	};

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

	/*!
		\ingroup types
	*/
	class Type : public CoreRefCountObject<BNType, BNNewTypeReference, BNFreeType>
	{
	  public:
		Type(BNType* type);

		bool operator==(const Type& other);
		bool operator!=(const Type& other);


		/*! Retrieve the Type Class for this Structure

		 	One of:

		        VoidTypeClass
				BoolTypeClass
				IntegerTypeClass
				FloatTypeClass
				StructureTypeClass
				EnumerationTypeClass
				PointerTypeClass
				ArrayTypeClass
				FunctionTypeClass
				VarArgsTypeClass
				ValueTypeClass
				NamedTypeReferenceClass
				WideCharTypeClass

		    \return The type class
		*/
		BNTypeClass GetClass() const;

		/*! Get the width in bytes of the Type

		    \return The type width
		*/
		uint64_t GetWidth() const;
		size_t GetAlignment() const;

		/*! Get the QualifiedName for the Type

		    \return The QualifiedName for the type
		*/
		QualifiedName GetTypeName() const;

		/*! Whether the type is signed
		*/
		Confidence<bool> IsSigned() const;

		/*! Whether the type is constant

		*/
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const; // Unimplemented!
		bool IsSystemCall() const;


		/*! Get the child type for this Type if one exists

		    \return The child type
		*/
		Confidence<Ref<Type>> GetChildType() const;

		/*! For Function Types, get the calling convention

		    \return The CallingConvention
		*/
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;

		/*! For Function Types, get the calling convention name

		    \return The calling convention name
		 */
		BNCallingConventionName GetCallingConventionName() const;

		/*! For Function Types, get a list of parameters

		    \return A vector of FunctionParameters
		*/
		std::vector<FunctionParameter> GetParameters() const;

		/*! For Function Types, whether the Function has variadic arguments

		    \return Whether the function has variable arguments
		*/
		Confidence<bool> HasVariableArguments() const;

		/*! Has no effect currently, just used by the demangler

		    \return If the type has the "has template arguments" flag set
		 */
		bool HasTemplateArguments() const;

		/*! For Function Types, whether a function can return (is not marked noreturn)

		    \return Whether the function can return
		*/
		Confidence<bool> CanReturn() const;

		/*! For Function Types, whether a function is pure (has no observable side-effects)

		    \return Whether the function is pure
		*/
		Confidence<bool> IsPure() const;

		/*! For Structure Types, the underlying Structure

		    \return The underlying structure
		*/
		Ref<Structure> GetStructure() const;

		/*! For Enumeration Types, the underlying Enumeration

		    \return The underlying enumeration
		*/
		Ref<Enumeration> GetEnumeration() const;

		/*! For NamedTypeReference Types, the underlying NamedTypeReference

		    \return The underlying NamedTypeReference
		*/
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const; // Unimplemented!
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;
		Ref<NamedTypeReference> GetRegisteredName() const;
		std::string GetAlternateName() const;
		uint32_t GetSystemCallNumber() const;
		BNIntegerDisplayType GetIntegerTypeDisplayType() const;
		BNNameType GetNameType() const;
		bool ShouldDisplayReturnType() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;
		BNPointerBaseType GetPointerBaseType() const;
		int64_t GetPointerBaseOffset() const;

		std::set<BNPointerSuffix> GetPointerSuffix() const;
		std::string GetPointerSuffixString() const;
		std::vector<InstructionTextToken> GetPointerSuffixTokens(uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		std::string GetString(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetTypeAndName(const QualifiedName& name, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetStringBeforeName(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetStringAfterName(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;

		std::vector<InstructionTextToken> GetTokens(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
		    BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
		    BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::vector<InstructionTextToken> GetTokensAfterName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
		    BNTokenEscapingType escaping = NoTokenEscapingType) const;

		Ref<Type> Duplicate() const;


		/*! Create a "void" type

		    \return The created Type object
		*/
		static Ref<Type> VoidType();

		/*! Create a "bool" type

		    \return The created Type object
		*/
		static Ref<Type> BoolType();

		/*! Create a signed or unsigned integer with a set width

		    \param width Width of the Type in bytes
		    \param sign Whether the integer is a signed or unsigned type
		    \param altName Alternative name for the type
		    \return The created Type object
		*/
		static Ref<Type> IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");

		/*! Create a float or double Type with a specified width

		    \param width Width of the Type in bytes
		    \param altName Alternative name for the type
		    \return The created Type object
		*/
		static Ref<Type> FloatType(size_t width, const std::string& altName = "");
		static Ref<Type> WideCharType(size_t width, const std::string& altName = "");

		/*! Create a Type object from a Structure object

		 	Structure objects can be generated using the StructureBuilder class.

		    \param strct Structure object
		    \return The created Type object
		*/
		static Ref<Type> StructureType(Structure* strct);
		static Ref<Type> NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static Ref<Type> NamedType(const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(BinaryView* view, const QualifiedName& name);
		static Ref<Type> EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0,
		    const Confidence<bool>& isSigned = Confidence<bool>(false, 0));
		static Ref<Type> EnumerationType(
		    Enumeration* enm, size_t width, const Confidence<bool>& isSigned = Confidence<bool>(false, 0));

		/*! Create a Pointer type, which points to another Type

			\code{.cpp}
		 	// Creating a "char *" type
		 	auto arch = bv->GetDefaultArchitecture();
		    auto charPointerType = Type::PointerType(arch, Type::IntegerType(1, false));
		 	\endcode

			\param arch Architecture, used to calculate the proper pointer width
			\param type Type that this Type points to
			\param cnst Whether this type is const
			\param vltl Whether this type is volatile
			\param refType Reference Type, one of "PointerReferenceType", "ReferenceReferenceType", "RValueReferenceType", "NoReference"
			\return The created type
		*/
		static Ref<Type> PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);

		/*! Create a Pointer type, which points to another Type

			\code{.cpp}
			// Creating a "char *" type in a binary compiled for 64 bit address spaces
			auto charPointerType = Type::PointerType(8, Type::IntegerType(1, false));
			\endcode

			\param width Width of the pointer in bytes
			\param type Type that this type points to
			\param cnst Whether this type is const
			\param vltl Whether this type is volatile
			\param refType Reference Type, one of "PointerReferenceType", "ReferenceReferenceType", "RValueReferenceType", "NoReference"
			\return The created type
		*/
		static Ref<Type> PointerType(size_t width, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);

		/*! Create an Array Type

			\param type Type for Elements contained in this Array
			\param elem Number of elements
			\return The created Type
		*/
		static Ref<Type> ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);

		/*! Create a Function Type

			\code{.cpp}
		    Ref<Type> retType = Type::VoidType();

			std::vector<FunctionParameter> params
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		    params.push_back({"arg0",
				Type::IntegerType(8, false),
				true,
				Variable()});

		    auto functionType = Type::FunctionType(retType, cc, params);
		    \endcode

			\param returnValue Return value Type
			\param callingConvention Calling convention for the function
			\param params list of FunctionParameter s
			\param varArg Whether this function has variadic arguments, default false
			\param stackAdjust Stack adjustment for this function, default 0
			\return The created function types
		*/
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& varArg = Confidence<bool>(false, 0),
		    const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));

		/*! Create a Function Type

			\code{.cpp}
		    Ref<Type> retType = Type::VoidType();

			std::vector<FunctionParameter> params
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		    params.push_back({"arg0",
				Type::IntegerType(8, false),
				true,
				Variable()});

		    auto functionType = Type::FunctionType(retType, cc, params);
		    \endcode

			\param returnValue Return value Type
			\param callingConvention Calling convention for the function
			\param params list of FunctionParameters
			\param varArg Whether this function has variadic arguments, default false
			\param stackAdjust Stack adjustment for this function, default 0
		 	\param regStackAdjust Register stack adjustmemt
		 	\param returnRegs Return registers
			\return The created function types
		*/
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention,
		    const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& hasVariableArguments,
		    const Confidence<bool>& canReturn,
		    const Confidence<int64_t>& stackAdjust,
		    const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
		    const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
		    BNNameType ft = NoNameType,
		    const Confidence<bool>& pure = Confidence<bool>(false, 0));
		static Ref<Type> VarArgsType();
		static Ref<Type> ValueType(const std::string& value);

		static std::string GetNameTypeString(BNNameType classFunctionType);

		static std::string GenerateAutoTypeId(const std::string& source, const QualifiedName& name);
		static std::string GenerateAutoDemangledTypeId(const QualifiedName& name);
		static std::string GetAutoDemangledTypeIdSource();
		static std::string GenerateAutoDebugTypeId(const QualifiedName& name);
		static std::string GetAutoDebugTypeIdSource();

		/*! Get this type wrapped in a Confidence template

			\param conf Confidence value between 0 and 255
			\return Confidence-wrapped Type
		*/
		Confidence<Ref<Type>> WithConfidence(uint8_t conf);

		/*! If this Type is a NamedTypeReference, check whether it is reference to a specific Type

			\param refType BNNamedTypeReference to check it against
			\return Whether it is a reference of this type
		*/
		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);

		/*! If this Type is a NamedTypeReference, check whether it refers to a Struct Type

			\return Whether it refers to a struct type.
		*/
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to an Enum Type

			\return Whether it refers to an Enum type.
		*/
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Union Type

			\return Whether it refers to a union type.
		*/
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Class Type

			\return Whether it refers to a class type.
		*/
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Typedef type

			\return Whether it refers to a typedef type.
		*/

		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Struct or Class Type

			\return Whether it refers to a struct or class type.
		*/
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		/*! Check whether this type is a Void type.

			\return Whether this->GetClass() == VoidTypeClass
		*/
		bool IsVoid() const { return GetClass() == VoidTypeClass; }

		/*! Check whether this type is a Boolean type.

			\return Whether this->GetClass() == BoolTypeClass
		*/
		bool IsBool() const { return GetClass() == BoolTypeClass; }

		/*! Check whether this type is an Integer type.

			\return Whether this->GetClass() == IntegerTypeClass
		*/
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }

		/*! Check whether this type is a Float type.

			\return Whether this->GetClass() == FloatTypeClass
		*/
		bool IsFloat() const { return GetClass() == FloatTypeClass; }

		/*! Check whether this type is a Structure type.

			\return Whether this->GetClass() == StructureTypeClass
		*/
		bool IsStructure() const { return GetClass() == StructureTypeClass; }

		/*! Check whether this type is an Enumeration type.

			\return Whether this->GetClass() == EnumerationTypeClass
		*/
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }

		/*! Check whether this type is a Pointer type.

			\return Whether this->GetClass() == PointerTypeClass
		*/
		bool IsPointer() const { return GetClass() == PointerTypeClass; }

		/*! Check whether this type is an Array type.

			\return Whether this->GetClass() == ArrayTypeClass
		*/
		bool IsArray() const { return GetClass() == ArrayTypeClass; }

		/*! Check whether this type is a Function type.

			\return Whether this->GetClass() == FunctionTypeClass
		*/
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }

		/*! Check whether this type is a Variadic Arguments type.

			\return Whether this->GetClass() == VarArgsTypeClass
		*/
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }

		/*! Check whether this type is a Value type.

			\return Whether this->GetClass() == ValueTypeClass
		*/
		bool IsValue() const { return GetClass() == ValueTypeClass; }

		/*! Check whether this type is a Named Type Reference type.

			\return Whether this->GetClass() == NamedTypeReferenceClass
		*/
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }

		/*! Check whether this type is a Wide Char type.

			\return Whether this->GetClass() == WideCharTypeClass
		*/
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }

		Ref<Type> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Type> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Type> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);

		bool AddTypeMemberTokens(BinaryView* data, std::vector<InstructionTextToken>& tokens, int64_t offset,
		    std::vector<std::string>& nameList, size_t size = 0, bool indirect = false);
		std::vector<TypeDefinitionLine> GetLines(const TypeContainer& types, const std::string& name,
			int paddingCols = 64, bool collapsed = false, BNTokenEscapingType escaping = NoTokenEscapingType);

		static std::string GetSizeSuffix(size_t size);
	};

	class EnumerationBuilder;
	class StructureBuilder;
	class NamedTypeReferenceBuilder;
	/*!
		\ingroup types
	*/
	class TypeBuilder
	{
		BNTypeBuilder* m_object;

	  public:
		TypeBuilder();
		~TypeBuilder();
		TypeBuilder(BNTypeBuilder* type);
		TypeBuilder(const TypeBuilder& type);
		TypeBuilder(TypeBuilder&& type);
		TypeBuilder(Type* type);
		TypeBuilder& operator=(const TypeBuilder& type);
		TypeBuilder& operator=(TypeBuilder&& type);
		TypeBuilder& operator=(Type* type);

		Ref<Type> Finalize();

		BNTypeClass GetClass() const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		QualifiedName GetTypeName() const;
		Confidence<bool> IsSigned() const;
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const;
		bool IsSystemCall() const;
		void SetIntegerTypeDisplayType(BNIntegerDisplayType displayType);

		Confidence<Ref<Type>> GetChildType() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		BNCallingConventionName GetCallingConventionName() const;
		std::vector<FunctionParameter> GetParameters() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<bool> CanReturn() const;
		Confidence<bool> IsPure() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const;
		BNNameType GetNameType() const;
		bool HasTemplateArguments() const;
		TypeBuilder& SetWidth(size_t width);
		TypeBuilder& SetAlignment(size_t alignment);
		TypeBuilder& SetNamedTypeReference(NamedTypeReference* ntr);
		TypeBuilder& SetScope(const Confidence<BNMemberScope>& scope);
		TypeBuilder& SetConst(const Confidence<bool>& cnst);
		TypeBuilder& SetVolatile(const Confidence<bool>& vltl);
		TypeBuilder& SetChildType(const Confidence<Ref<Type>>& child);
		TypeBuilder& SetCallingConvention(const Confidence<Ref<CallingConvention>>& cc);
		TypeBuilder& SetCallingConventionName(BNCallingConventionName cc);
		TypeBuilder& SetSigned(const Confidence<bool>& vltl);
		TypeBuilder& SetTypeName(const QualifiedName& name);
		TypeBuilder& SetAlternateName(const std::string& name);
		TypeBuilder& SetSystemCall(bool sc, uint32_t n = 0);
		TypeBuilder& SetNameType(BNNameType type);
		TypeBuilder& SetHasTemplateArguments(bool hasTemplateArguments);
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;
		uint32_t GetSystemCallNumber() const;
		BNPointerBaseType GetPointerBaseType() const;
		int64_t GetPointerBaseOffset() const;

		TypeBuilder& SetOffset(uint64_t offset);
		TypeBuilder& SetFunctionCanReturn(const Confidence<bool>& canReturn);
		TypeBuilder& SetPure(const Confidence<bool>& pure);
		TypeBuilder& SetParameters(const std::vector<FunctionParameter>& params);
		TypeBuilder& SetPointerBase(BNPointerBaseType baseType, int64_t baseOffset);

		std::set<BNPointerSuffix> GetPointerSuffix() const;
		std::string GetPointerSuffixString() const;
		std::vector<InstructionTextToken> GetPointerSuffixTokens(uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		TypeBuilder& AddPointerSuffix(BNPointerSuffix ps);
		TypeBuilder& SetPointerSuffix(const std::set<BNPointerSuffix>& suffix);

		std::string GetString(Platform* platform = nullptr) const;
		std::string GetTypeAndName(const QualifiedName& name) const;
		std::string GetStringBeforeName(Platform* platform = nullptr) const;
		std::string GetStringAfterName(Platform* platform = nullptr) const;

		std::vector<InstructionTextToken> GetTokens(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensAfterName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		static TypeBuilder VoidType();
		static TypeBuilder BoolType();
		static TypeBuilder IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");
		static TypeBuilder FloatType(size_t width, const std::string& typeName = "");
		static TypeBuilder WideCharType(size_t width, const std::string& typeName = "");
		static TypeBuilder StructureType(Structure* strct);
		static TypeBuilder StructureType(StructureBuilder* strct);
		static TypeBuilder NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static TypeBuilder NamedType(NamedTypeReferenceBuilder* ref, size_t width = 0, size_t align = 1,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static TypeBuilder NamedType(const QualifiedName& name, Type* type);
		static TypeBuilder NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static TypeBuilder NamedType(BinaryView* view, const QualifiedName& name);
		static TypeBuilder EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0,
		    const Confidence<bool>& issigned = Confidence<bool>(false, 0));
		static TypeBuilder EnumerationType(Architecture* arch, EnumerationBuilder* enm, size_t width = 0,
		    const Confidence<bool>& issigned = Confidence<bool>(false, 0));
		static TypeBuilder PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static TypeBuilder PointerType(size_t width, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static TypeBuilder ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);
		static TypeBuilder FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& varArg = Confidence<bool>(false, 0),
		    const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));
		static TypeBuilder FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention,
		    const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& hasVariableArguments,
		    const Confidence<bool>& canReturn,
		    const Confidence<int64_t>& stackAdjust,
		    const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
		    const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
		    BNNameType ft = NoNameType,
		    const Confidence<bool>& pure = Confidence<bool>(false, 0));
		static TypeBuilder VarArgsType();
		static TypeBuilder ValueType(const std::string& value);

		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }
		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		bool IsVoid() const { return GetClass() == VoidTypeClass; }
		bool IsBool() const { return GetClass() == BoolTypeClass; }
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }
		bool IsFloat() const { return GetClass() == FloatTypeClass; }
		bool IsStructure() const { return GetClass() == StructureTypeClass; }
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }
		bool IsPointer() const { return GetClass() == PointerTypeClass; }
		bool IsArray() const { return GetClass() == ArrayTypeClass; }
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }
		bool IsValue() const { return GetClass() == ValueTypeClass; }
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }
	};

	/*!
		\ingroup types
	*/
	class NamedTypeReference :
	    public CoreRefCountObject<BNNamedTypeReference, BNNewNamedTypeReference, BNFreeNamedTypeReference>
	{
	  public:
		NamedTypeReference(BNNamedTypeReference* nt);
		NamedTypeReference(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
		    const QualifiedName& name = QualifiedName());
		BNNamedTypeReferenceClass GetTypeReferenceClass() const;
		std::string GetTypeId() const;
		QualifiedName GetName() const;

		static Ref<NamedTypeReference> GenerateAutoTypeReference(
		    BNNamedTypeReferenceClass cls, const std::string& source, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDemangledTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDebugTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
	};

	/*!
		\ingroup types
	*/
	class NamedTypeReferenceBuilder
	{
		BNNamedTypeReferenceBuilder* m_object;

	  public:
		NamedTypeReferenceBuilder(BNNamedTypeReferenceBuilder* nt);
		NamedTypeReferenceBuilder(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
		    const QualifiedName& name = QualifiedName());
		~NamedTypeReferenceBuilder();
		BNNamedTypeReferenceBuilder* GetObject() { return m_object; };
		BNNamedTypeReferenceClass GetTypeReferenceClass() const;
		std::string GetTypeId() const;
		QualifiedName GetName() const;

		void SetTypeReferenceClass(BNNamedTypeReferenceClass type);
		void SetTypeId(const std::string& id);
		void SetName(const QualifiedName& name);

		Ref<NamedTypeReference> Finalize();
	};

	/*!
		\ingroup types
	*/
	struct StructureMember
	{
		Confidence<Ref<Type>> type;
		std::string name;
		uint64_t offset;
		BNMemberAccess access;
		BNMemberScope scope;
	};

	/*!
	    \ingroup types
	*/
	struct InheritedStructureMember
	{
		Ref<NamedTypeReference> base;
		uint64_t baseOffset;
		StructureMember member;
		size_t memberIndex;
	};

	/*!
	    \ingroup types
	*/
	struct BaseStructure
	{
		Ref<NamedTypeReference> type;
		uint64_t offset, width;

		BaseStructure(NamedTypeReference* type, uint64_t offset, uint64_t width);
		BaseStructure(Type* type, uint64_t offset);
	};

	/*! Structure is a class that wraps built structures and retrieves info about them.

		\see StructureBuilder is used for building structures
	 	\ingroup types
	*/
	class Structure : public CoreRefCountObject<BNStructure, BNNewStructureReference, BNFreeStructure>
	{
	  public:
		Structure(BNStructure* s);

		/*! Get a list of base structures. Offsets that are not defined by this structure will be filled
		    in by the fields of the base structure(s).

		    \return The list of base structures
		*/
		std::vector<BaseStructure> GetBaseStructures() const;

		/*! Get a list of Structure members, excluding those inherited from base structures

			\return The list of structure members
		*/
		std::vector<StructureMember> GetMembers() const;

		/*! Get a list of Structure members, including those inherited from base structures

		    \return The list of structure members
		*/
		std::vector<InheritedStructureMember> GetMembersIncludingInherited(const TypeContainer& types) const;

		/*! Get a structure member (including inherited members) at a certain offset

		 	\param view The relevant binary view
			\param offset Offset to check
			\param result Reference to a InheritedStructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberIncludingInheritedAtOffset(BinaryView* view, int64_t offset,
			InheritedStructureMember& result) const;

		/*! Get a structure member by name

			\param name Name of the member to retrieve
			\param result Reference to a StructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberByName(const std::string& name, StructureMember& result) const;

		/*! Get a structure member at a certain offset

			\param offset Offset to check
			\param result Reference to a StructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;

		/*! Get a structure member and its index at a certain offset

			\param offset Offset to check
			\param result Reference to a StructureMember to copy the result to
			\param idx Reference to a size_t to copy the index to
			\return Whether a member was found
		*/
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;

		/*! Get the structure width in bytes

			\return The structure width in bytes
		*/
		uint64_t GetWidth() const;

		/*! Get the structure pointer offset in bytes. Pointers to this structure will implicitly
		    have this offset subtracted from the pointer to arrive at the start of the structure.
		    Effectively, the pointer offset becomes the new start of the structure, and fields
		    before it are accessed using negative offsets from the pointer.

		    \return The structure pointer offset in bytes
		*/
		int64_t GetPointerOffset() const;

		/*! Get the structure alignment

			\return The structure alignment
		*/
		size_t GetAlignment() const;

		/*! Whether the structure is packed

			\return Whether the structure is packed
		*/
		bool IsPacked() const;

		/*! Whether the structure is a union

			\return Whether the structure is a union
		*/
		bool IsUnion() const;

		/*! Whether structure field references propagate the references to data variable field values

		    \return Whether the structure propagates data variable references
		*/
		bool PropagateDataVariableReferences() const;

		/*! Get the structure type

			\return The structure type
		*/
		BNStructureVariant GetStructureType() const;

		Ref<Structure> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Structure> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Structure> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);

		bool ResolveMemberOrBaseMember(BinaryView* data, uint64_t offset, size_t size,
			const std::function<void(NamedTypeReference* baseName, Structure* s, size_t memberIndex,
				uint64_t structOffset, uint64_t adjustedOffset, const StructureMember& member)>& resolveFunc,
			std::optional<size_t> memberIndexHint = std::nullopt);
	};

	/*! StructureBuilder is a convenience class used for building Structure Types.

	 	\b Example:
		\code{.cpp}
		StructureBuilder versionMinBuilder;
		versionMinBuilder.AddMember(Type::NamedType(bv, cmdTypeEnumQualName), "cmd");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "version");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "sdk");
		Ref<Structure> versionMinStruct = versionMinBuilder.Finalize();
		QualifiedName versionMinName = string("version_min");
		string versionMinTypeId = Type::GenerateAutoTypeId("macho", versionMinName);
		Ref<Type> versionMinType = Type::StructureType(versionMinStruct);
		QualifiedName versionMinQualName = bv->GetAnalysis()->DefineType(versionMinTypeId, versionMinName, versionMinType);
	 	\endcode

	 	\ingroup types
	*/
	class StructureBuilder
	{
		BNStructureBuilder* m_object;

	  public:
		StructureBuilder();
		StructureBuilder(BNStructureBuilder* s);
		StructureBuilder(BNStructureVariant type, bool packed = false);
		StructureBuilder(const StructureBuilder& s);
		StructureBuilder(StructureBuilder&& s);
		StructureBuilder(Structure* s);
		~StructureBuilder();
		StructureBuilder& operator=(const StructureBuilder& s);
		StructureBuilder& operator=(StructureBuilder&& s);
		StructureBuilder& operator=(Structure* s);
		BNStructureBuilder* GetObject() { return m_object; };

		/*! Complete the structure building process and return a Structure object

		    \return a built Structure object
		*/
		Ref<Structure> Finalize() const;

		std::vector<BaseStructure> GetBaseStructures() const;
		StructureBuilder& SetBaseStructures(const std::vector<BaseStructure>& bases);

		/*! GetMembers returns a list of structure members

		    \return vector of StructureMember objects
		*/
		std::vector<StructureMember> GetMembers() const;

		/*! GetMemberByName retrieves a structure member by name

		    \param name Name of the member (field)
		    \param result Reference to a StructureMember object the field will be passed to
		    \return Whether a StructureMember was successfully retrieved
		*/
		bool GetMemberByName(const std::string& name, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;
		uint64_t GetWidth() const;
		StructureBuilder& SetWidth(size_t width);
		int64_t GetPointerOffset() const;
		StructureBuilder& SetPointerOffset(int64_t offset);
		size_t GetAlignment() const;
		StructureBuilder& SetAlignment(size_t align);
		bool IsPacked() const;
		StructureBuilder& SetPacked(bool packed);
		bool IsUnion() const;
		bool PropagateDataVariableReferences() const;
		StructureBuilder& SetPropagateDataVariableReferences(bool value);

		/*! Set the structure type

		    \param type One of: ClassStructureType, StructStructureType, UnionStructureType
		    \return reference to this StructureBuilder
		*/
		StructureBuilder& SetStructureType(BNStructureVariant type);

		/*! Get the Structure Type

		    \return A BNStructureVariant
		    \retval ClassStructureType If this structure represents a class
		    \retval StructStructureType If this structure represents a structure
		    \retval UnionStructureType If this structure represents a union
		*/
		BNStructureVariant GetStructureType() const;

		/*! AddMember adds a member (field) to a structure

		    \param type Type of the Field
		    \param name Name of the field
		    \param access Optional, One of NoAccess, PrivateAccess, ProtectedAccess, PublicAccess
		    \param scope Optional, One of NoScope, StaticScope, VirtualScope, ThunkScope, FriendScope
		    \return reference to the Structure Builder
		*/
		StructureBuilder& AddMember(const Confidence<Ref<Type>>& type, const std::string& name,
		    BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);

		/*! AddMemberAtOffset adds a member at a specific offset within the struct

		    \param type Type of the Field
		    \param name Name of the field
		    \param offset Offset to add the member within the struct
		    \param overwriteExisting Whether to overwrite an existing member at that offset, Optional, default true
		    \param access One of NoAccess, PrivateAccess, ProtectedAccess, PublicAccess
		    \param scope One of NoScope, StaticScope, VirtualScope, ThunkScope, FriendScope
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& AddMemberAtOffset(const Confidence<Ref<Type>>& type, const std::string& name, uint64_t offset,
		    bool overwriteExisting = true, BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);

		/*! RemoveMember removes a member at a specified index

		    \param idx Index to remove
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& RemoveMember(size_t idx);

		/*! ReplaceMember replaces a member at an index

		    \param idx Index of the StructureMember to be replaced
		    \param type Type of the new Member
		    \param name Name of the new Member
		    \param overwriteExisting Whether to overwrite the existing member, default true
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& ReplaceMember(
		    size_t idx, const Confidence<Ref<Type>>& type, const std::string& name, bool overwriteExisting = true);
	};

	/*!
		\ingroup types
	*/
	struct EnumerationMember
	{
		std::string name;
		uint64_t value;
		bool isDefault;
	};

	/*!
		\ingroup types
	*/
	class Enumeration : public CoreRefCountObject<BNEnumeration, BNNewEnumerationReference, BNFreeEnumeration>
	{
	  public:
		Enumeration(BNEnumeration* e);

		std::vector<InstructionTextToken> GetTokensForValue(uint64_t value, size_t width, Ref<Type> type);
		std::vector<EnumerationMember> GetMembers() const;
	};

	/*! EnumerationBuilder is a convenience class used for building Enumeration Types.

	 	\b Example:
	 	\code{.cpp}
		EnumerationBuilder segFlagsTypeBuilder;
		segFlagsTypeBuilder.AddMemberWithValue("SG_HIGHVM", 0x1);
		segFlagsTypeBuilder.AddMemberWithValue("SG_FVMLIB", 0x2);
		segFlagsTypeBuilder.AddMemberWithValue("SG_NORELOC", 0x4);
		segFlagsTypeBuilder.AddMemberWithValue("SG_PROTECTED_VERSION_1", 0x8);
		Ref<Enumeration> segFlagsTypeEnum = segFlagsTypeBuilder.Finalize();
	 	\endcode

	 	\ingroup types
	*/
	class EnumerationBuilder
	{
		BNEnumerationBuilder* m_object;

	  public:
		EnumerationBuilder();
		EnumerationBuilder(BNEnumerationBuilder* e);
		EnumerationBuilder(const EnumerationBuilder& e);
		EnumerationBuilder(EnumerationBuilder&& e);
		EnumerationBuilder(Enumeration* e);
		~EnumerationBuilder();
		BNEnumerationBuilder* GetObject() { return m_object; }
		EnumerationBuilder& operator=(const EnumerationBuilder& e);
		EnumerationBuilder& operator=(EnumerationBuilder&& e);
		EnumerationBuilder& operator=(Enumeration* e);

		/*! Finalize the building process and return the built Enumeration

			\return the Enumeration
		*/
		Ref<Enumeration> Finalize() const;

		/*! Get a list of members in this enum

			\return list of EnumerationMember
		*/
		std::vector<EnumerationMember> GetMembers() const;

		/*! Add a member to the enum.

			\note If there is already a member in the Enum, the value of newly added ones will be the value of the previously added one + 1

			\param name Name of the enum member
			\return A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& AddMember(const std::string& name);

		/*! Add a member to the enum with a set value

			\param name Name of the enum member
			\param value Value of th enum member
			\return A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& AddMemberWithValue(const std::string& name, uint64_t value);

		/*! Remove a member from the enum

			\param idx Index to remove
			\return  A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& RemoveMember(size_t idx);

		/*! Replace a member at an index

			\param idx Index to replace
			\param name Name of the new member
			\param value Value of the new member
			\return  A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& ReplaceMember(size_t idx, const std::string& name, uint64_t value);
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

		/*! Get the BinaryView for the current AnalysisContext

			\return The binary view for the current context
		*/
		Ref<BinaryView> GetBinaryView();

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

	class WorkflowMachine
	{
		Ref<BinaryView> m_view;
		Ref<Function> m_function;

	public:
		WorkflowMachine(Ref<BinaryView> view);
		WorkflowMachine(Ref<Function> function);

		std::optional<bool> QueryOverride(const std::string& activity);
		bool SetOverride(const std::string& activity, bool enable);
		bool ClearOverride(const std::string& activity);
	};

	/*! Workflows are represented as Directed Acyclic Graphs (DAGs), where each node corresponds to an Activity (an individual analysis or action).
		Workflows are used to tailor the analysis process for :class:`BinaryView` or :class:`Function` objects, providing granular control over
		analysis tasks at module or function levels.

		A Workflow starts in an unregistered state, either by creating a new empty Workflow or by cloning an existing one. While unregistered, it
		is possible to add and remove Activity objects, as well as modify the execution strategy. To apply a Workflow to a binary, it must be
		registered. Once registered, the Workflow becomes immutable and is available for use.
	 	\ingroup workflow
	*/
	class Workflow : public CoreRefCountObject<BNWorkflow, BNNewWorkflowReference, BNFreeWorkflow>
	{
		std::unique_ptr<WorkflowMachine> m_machine;

	  public:
		Workflow(const std::string& name = "");
		Workflow(BNWorkflow* workflow);
		Workflow(BNWorkflow* workflow, Ref<BinaryView> view);
		Workflow(BNWorkflow* workflow, Ref<Function> function);
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

		std::vector<std::string> GetEligibilitySettings();

		WorkflowMachine* GetWorkflowMachine() const { return m_machine.get(); }
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

	/*!
		\ingroup function
	*/
	struct VariableNameAndType
	{
		Variable var;
		Confidence<Ref<Type>> type;
		std::string name;
		bool autoDefined;

		bool operator==(const VariableNameAndType& a)
		{
			return (var == a.var) && (type == a.type) && (name == a.name) && (autoDefined == a.autoDefined);
		}
		bool operator!=(const VariableNameAndType& a)
		{
			return !(*this == a);
		}
	};

	/*!
		\ingroup function
	*/
	struct StackVariableReference
	{
		uint32_t sourceOperand;
		Confidence<Ref<Type>> type;
		std::string name;
		Variable var;
		int64_t referencedOffset;
		size_t size;
	};

	/*!
		\ingroup function
	*/
	struct IndirectBranchInfo
	{
		Ref<Architecture> sourceArch;
		uint64_t sourceAddr;
		Ref<Architecture> destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

	/*!
		\ingroup function
	*/
	struct ArchAndAddr
	{
		Ref<Architecture> arch;
		uint64_t address;

		ArchAndAddr& operator=(const ArchAndAddr& a)
		{
			arch = a.arch;
			address = a.address;
			return *this;
		}
		bool operator==(const ArchAndAddr& a) const { return (arch == a.arch) && (address == a.address); }
		bool operator<(const ArchAndAddr& a) const
		{
			if (arch < a.arch)
				return true;
			if (arch > a.arch)
				return false;
			return address < a.address;
		}
		ArchAndAddr() : arch(nullptr), address(0) {}
		ArchAndAddr(Architecture* a, uint64_t addr) : arch(a), address(addr) {}
	};

	/*!
		\ingroup function
	*/
	struct LookupTableEntry
	{
		std::vector<int64_t> fromValues;
		int64_t toValue;
	};

	/*!
		\ingroup function
	*/
	struct ConstantData : public BNRegisterValue
	{
		Ref<Function> func = nullptr;

		ConstantData();
		ConstantData(BNRegisterValueType state, uint64_t value);
		ConstantData(BNRegisterValueType state, uint64_t value, size_t size, Ref<Function> func = nullptr);

		std::pair<DataBuffer, BNBuiltinType> ToDataBuffer() const;
		RegisterValue ToRegisterValue() const;
	};

	/*!
		\ingroup function
	*/
	struct PossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		size_t size;
		std::vector<BNValueRange> ranges;
		std::set<int64_t> valueSet;
		std::vector<LookupTableEntry> table;
		size_t count;

		static PossibleValueSet FromAPIObject(BNPossibleValueSet& value);
		BNPossibleValueSet ToAPIObject();
		static void FreeAPIObject(BNPossibleValueSet* value);
	};

	class FlowGraph;
	class Component;
	struct SSAVariable;

	/*!
		\ingroup function
	*/
	class Function : public CoreRefCountObject<BNFunction, BNNewFunctionReference, BNFreeFunction>
	{
		int m_advancedAnalysisRequests;

		bool IsRegionCollapsed(uint64_t hash) const;

	  public:
		Function(BNFunction* func);
		virtual ~Function();

		/*! Get the BinaryView this Function is defined in

			\return a BinaryView reference
		*/
		Ref<BinaryView> GetView() const;

		/*! Get the architecture this function was defined with

			\return an Architecture reference
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Get the platform this function was defined with

			\return a Platform reference
		*/
		Ref<Platform> GetPlatform() const;

		/*! Get the starting virtual address of this function

			\return the start address
		*/
		uint64_t GetStart() const;

		/*! Get the Symbol for this function

			\return a Symbol reference
		*/
		Ref<Symbol> GetSymbol() const;

		/*! Whether this function was automatically discovered by analysis

			\return Whether the function was automatically discovered
		*/
		bool WasAutomaticallyDiscovered() const;

		/*! Whether this function has user annotations

			\return Whether this function has user annotations
		*/
		bool HasUserAnnotations() const;

		/*! Whether this function can return

			\return Whether this function can return
		*/
		Confidence<bool> CanReturn() const;

		/*! Whether this function is pure

			\return Whether this function is pure
		*/
		Confidence<bool> IsPure() const;

		/*! Whether this function has an explicitly defined type

			\return Whether this function has an explicitly defined type
		*/
		bool HasExplicitlyDefinedType() const;

		/*! Whether this function needs update

			\return Whether this function needs update
		*/
		bool NeedsUpdate() const;

		/*! Get a list of Basic Blocks for this function

			\return a list of BasicBlock references for this function
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;

		/*! Get the basic block an address is located in

			\param arch Architecture for the basic block
			\param addr Address to check
			\return
		*/
		Ref<BasicBlock> GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const;

		/*! Mark this function as recently used
		*/
		void MarkRecentUse();

		/*! Get the function comment

			\return The function comment
		*/
		std::string GetComment() const;

		/*! Get a comment located at an address

		 	\return The comment at an address
		*/
		std::string GetCommentForAddress(uint64_t addr) const;

		/*! Get a list of addresses with comments

			\return A list of virtual addresses with comments
		*/
		std::vector<uint64_t> GetCommentedAddresses() const;

		/*! Set the comment for the function

			\param comment The new function comment
		*/
		void SetComment(const std::string& comment);

		/*! Set the comment at an address

			\param addr Address for the comment
			\param comment Text of the comment
		*/
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		/*! Get a list of callsites for this function

			\return a list of ReferenceSource
		*/
		std::vector<ReferenceSource> GetCallSites() const;

		/*! Places a user-defined cross-reference from the instruction at
			the given address and architecture to the specified target address.

		 	If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use `RemoveUserCodeReference`.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param toAddr Virtual address of the xref's destination.
		*/
		void AddUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

		/*! Removes a user-defined cross-reference.

		    If the given address is not contained within this function, or if there is no such user-defined
		    cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param toAddr Virtual address of the xref's destination.
		*/
		void RemoveUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

		/*! Places a user-defined type cross-reference from the instruction at
				the given address and architecture to the specified type.

		 	If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use `RemoveUserTypeReference`.

		    \param fromArch Architecture of the source instruction
		    \param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
		*/
		void AddUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);

		/*! Removes a user-defined type cross-reference.

			If the given address is not contained within this function, or if there is no
			such user-defined cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
		*/
		void RemoveUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);

		/*! Places a user-defined type field cross-reference from the
			instruction at the given address and architecture to the specified type.

			If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use :func:`remove_user_type_field_ref`.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
			\param offset Offset of the field, relative to the type
			\param size (Optional) size of the access
		*/
		void AddUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		/*! Removes a user-defined type field cross-reference.

		 	If the given address is not contained within this function, or if there is no
			such user-defined cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
			\param offset Offset of the field, relative to the type
			\param size (Optional) size of the access
		*/
		void RemoveUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		/*! Get the LLIL for this function

			\return a LowLevelILFunction reference
		*/
		Ref<LowLevelILFunction> GetLowLevelIL() const;

		/*! Get the LLIL for this function if it is available

			\return a LowLevelILFunction reference
		*/
		Ref<LowLevelILFunction> GetLowLevelILIfAvailable() const;

		/*! Get the Low Level IL Instruction start for an instruction at an address

			\param arch Architecture for the instruction
			\param addr Address of the instruction
			\return Start address of the instruction
		*/
		size_t GetLowLevelILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLowLevelILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::vector<size_t> GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr);

		std::pair<DataBuffer, BNBuiltinType> GetConstantData(
			BNRegisterValueType state, uint64_t value, size_t size = 0);

		RegisterValue GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetStackContentsAtInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetStackContentsAfterInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetParameterValueAtInstruction(Architecture* arch, uint64_t addr, Type* functionType, size_t i);
		RegisterValue GetParameterValueAtLowLevelILInstruction(size_t instr, Type* functionType, size_t i);
		std::vector<uint32_t> GetRegistersReadByInstruction(Architecture* arch, uint64_t addr);
		std::vector<uint32_t> GetRegistersWrittenByInstruction(Architecture* arch, uint64_t addr);
		std::vector<StackVariableReference> GetStackVariablesReferencedByInstruction(Architecture* arch, uint64_t addr);
		std::vector<StackVariableReference> GetStackVariablesReferencedByInstructionIfAvailable(
			Architecture* arch, uint64_t addr);
		std::vector<BNConstantReference> GetConstantsReferencedByInstruction(Architecture* arch, uint64_t addr);
		std::vector<BNConstantReference> GetConstantsReferencedByInstructionIfAvailable(
			Architecture* arch, uint64_t addr);

		std::vector<ILReferenceSource> GetMediumLevelILVariableReferences(const Variable& var);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesInRange(
		    Architecture* arch, uint64_t addr, uint64_t len);
		std::vector<ILReferenceSource> GetMediumLevelILVariableReferencesIfAvailable(const Variable& var);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesFromIfAvailable(
		    Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesInRangeIfAvailable(
		    Architecture* arch, uint64_t addr, uint64_t len);

		std::vector<ILReferenceSource> GetHighLevelILVariableReferences(const Variable& var);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesInRange(
		    Architecture* arch, uint64_t addr, uint64_t len);
		std::vector<ILReferenceSource> GetHighLevelILVariableReferencesIfAvailable(const Variable& var);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesFromIfAvailable(
		    Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesInRangeIfAvailable(
		    Architecture* arch, uint64_t addr, uint64_t len);

		/*! Retrieves a LowLevelILFunction used to represent lifted IL.

			\return LowLevelILFunction used to represent lifted IL.
		*/
		Ref<LowLevelILFunction> GetLiftedIL() const;

		/*! Retrieves a LowLevelILFunction used to represent lifted IL, or None if not loaded.

			\return LowLevelILFunction used to represent lifted IL, or None if not loaded.
		*/
		Ref<LowLevelILFunction> GetLiftedILIfAvailable() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		/*! Get the MLIL for this Function.

			\return The MLIL for this Function.
		*/
		Ref<MediumLevelILFunction> GetMediumLevelIL() const;

		/*! Get the MLIL for this Function if it's available.

			\return The MLIL for this Function if it's available.
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILIfAvailable() const;

		/*! Get the Mapped MLIL for this Function.

			\return The Mapped MLIL for this Function.
		*/
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;

		/*! Get the Mapped MLIL for this Function if it's available.

			\return The Mapped MLIL for this Function if it's available.
		*/
		Ref<MediumLevelILFunction> GetMappedMediumLevelILIfAvailable() const;

		/*! Get the HLIL for this Function.

			\return The HLIL for this Function.
		*/
		Ref<HighLevelILFunction> GetHighLevelIL() const;

		/*! Get the HLIL for this Function if it's available.

			\return The HLIL for this Function if it's available.
		*/
		Ref<HighLevelILFunction> GetHighLevelILIfAvailable() const;
		Ref<LanguageRepresentationFunction> GetLanguageRepresentation(const std::string& language = "Pseudo C") const;
		Ref<LanguageRepresentationFunction> GetLanguageRepresentationIfAvailable(
			const std::string& language = "Pseudo C") const;

		Ref<Type> GetType() const;
		Confidence<Ref<Type>> GetReturnType() const;
		Confidence<std::vector<uint32_t>> GetReturnRegisters() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		Confidence<std::vector<Variable>> GetParameterVariables() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<int64_t> GetStackAdjustment() const;
		std::map<uint32_t, Confidence<int32_t>> GetRegisterStackAdjustments() const;
		Confidence<std::set<uint32_t>> GetClobberedRegisters() const;

		void SetAutoType(Type* type);
		void SetAutoReturnType(const Confidence<Ref<Type>>& type);
		void SetAutoReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetAutoCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetAutoParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetAutoHasVariableArguments(const Confidence<bool>& varArgs);
		void SetAutoCanReturn(const Confidence<bool>& returns);
		void SetAutoPure(const Confidence<bool>& pure);
		void SetAutoStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetAutoRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetAutoClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void SetUserType(Type* type);
		void SetReturnType(const Confidence<Ref<Type>>& type);
		void SetReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetHasVariableArguments(const Confidence<bool>& varArgs);
		void SetCanReturn(const Confidence<bool>& returns);
		void SetPure(const Confidence<bool>& pure);
		void SetStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		bool HasUserType() const;

		void ApplyImportedTypes(Symbol* sym, Ref<Type> type = nullptr);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FlowGraph> CreateFunctionGraph(const FunctionViewType& type, DisassemblySettings* settings = nullptr);

		std::map<int64_t, std::vector<VariableNameAndType>> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(Architecture* arch, uint64_t addr, int64_t offset, VariableNameAndType& var);

		/*! List of Function Variables

			\return List of Function Variables
		*/
		std::map<Variable, VariableNameAndType> GetVariables();
		std::set<Variable> GetMediumLevelILVariables();
		std::set<Variable> GetMediumLevelILAliasedVariables();
		std::set<SSAVariable> GetMediumLevelILSSAVariables();
		std::set<Variable> GetHighLevelILVariables();
		std::set<Variable> GetHighLevelILAliasedVariables();
		std::set<SSAVariable> GetHighLevelILSSAVariables();

		std::set<Variable> GetMediumLevelILVariablesIfAvailable();
		std::set<Variable> GetMediumLevelILAliasedVariablesIfAvailable();
		std::set<SSAVariable> GetMediumLevelILSSAVariablesIfAvailable();
		std::set<Variable> GetHighLevelILVariablesIfAvailable();
		std::set<Variable> GetHighLevelILAliasedVariablesIfAvailable();
		std::set<SSAVariable> GetHighLevelILSSAVariablesIfAvailable();

		void CreateAutoVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
		    bool ignoreDisjointUses = false);
		void CreateUserVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
		    bool ignoreDisjointUses = false);
		void DeleteAutoVariable(const Variable& var);
		void DeleteUserVariable(const Variable& var);
		bool IsVariableUserDefinded(const Variable& var);
		Confidence<Ref<Type>> GetVariableType(const Variable& var);
		std::string GetVariableName(const Variable& var);
		std::string GetVariableNameOrDefault(const Variable& var);
		std::string GetLastSeenVariableNameOrDefault(const Variable& var);

		void SetAutoIndirectBranches(
		    Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);
		void SetUserIndirectBranches(
		    Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);

		std::vector<IndirectBranchInfo> GetIndirectBranches();
		std::vector<IndirectBranchInfo> GetIndirectBranchesAt(Architecture* arch, uint64_t addr);

		std::vector<uint64_t> GetUnresolvedIndirectBranches();
		bool HasUnresolvedIndirectBranches();

		void SetAutoCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust);
		void SetAutoCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust);
		void SetAutoCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetAutoCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, uint32_t regStack, const Confidence<int32_t>& adjust);
		void SetUserCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust);
		void SetUserCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust);
		void SetUserCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetUserCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, uint32_t regStack, const Confidence<int32_t>& adjust);

		Confidence<Ref<Type>> GetCallTypeAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int64_t> GetCallStackAdjustment(Architecture* arch, uint64_t addr);
		std::map<uint32_t, Confidence<int32_t>> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int32_t> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack);
		bool IsCallInstruction(Architecture* arch, uint64_t addr);

		std::vector<std::vector<InstructionTextToken>> GetBlockAnnotations(Architecture* arch, uint64_t addr);

		BNIntegerDisplayType GetIntegerConstantDisplayType(
		    Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
		Ref<Type> GetIntegerConstantDisplayTypeEnumType(
			Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
		void SetIntegerConstantDisplayType(
		    Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand, BNIntegerDisplayType type, Ref<Type> enumType = nullptr);
		std::pair<BNIntegerDisplayType, Ref<Type>> GetIntegerConstantDisplayTypeAndEnumType(Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);

		BNHighlightColor GetInstructionHighlight(Architecture* arch, uint64_t addr);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetAutoInstructionHighlight(
		    Architecture* arch, uint64_t addr, BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
		    BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(
		    Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetUserInstructionHighlight(
		    Architecture* arch, uint64_t addr, BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
		    BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetUserInstructionHighlight(
		    Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		std::vector<TagReference> GetAllTagReferences();
		std::vector<TagReference> GetTagReferencesOfType(Ref<TagType> tagType);

		std::vector<TagReference> GetAddressTagReferences();
		std::vector<TagReference> GetAutoAddressTagReferences();
		std::vector<TagReference> GetUserAddressTagReferences();
		std::vector<Ref<Tag>> GetAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetAutoAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetUserAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<TagReference> GetAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		std::vector<TagReference> GetAutoAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		std::vector<TagReference> GetUserAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		void AddAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		void AddUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);

		std::vector<TagReference> GetFunctionTagReferences();
		std::vector<TagReference> GetAutoFunctionTagReferences();
		std::vector<TagReference> GetUserFunctionTagReferences();
		std::vector<Ref<Tag>> GetFunctionTags();
		std::vector<Ref<Tag>> GetAutoFunctionTags();
		std::vector<Ref<Tag>> GetUserFunctionTags();
		std::vector<Ref<Tag>> GetFunctionTagsOfType(Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoFunctionTagsOfType(Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserFunctionTagsOfType(Ref<TagType> tagType);
		void AddAutoFunctionTag(Ref<Tag> tag);
		void RemoveAutoFunctionTag(Ref<Tag> tag);
		void RemoveAutoFunctionTagsOfType(Ref<TagType> tagType);
		void AddUserFunctionTag(Ref<Tag> tag);
		void RemoveUserFunctionTag(Ref<Tag> tag);
		void RemoveUserFunctionTagsOfType(Ref<TagType> tagType);

		Ref<Tag> CreateAutoAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName,
		    const std::string& data, bool unique = false);
		Ref<Tag> CreateUserAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName,
		    const std::string& data, bool unique = false);
		Ref<Tag> CreateAutoFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique = false);

		Ref<Tag> CreateAutoAddressTag(
		    Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserAddressTag(
		    Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateAutoFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique = false);

		void Reanalyze(BNFunctionUpdateType type = UserFunctionUpdate);
		void MarkUpdatesRequired(BNFunctionUpdateType type = UserFunctionUpdate);
		void MarkCallerUpdatesRequired(BNFunctionUpdateType type = UserFunctionUpdate);

		Ref<Workflow> GetWorkflow();

		void RequestAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData(size_t count);

		std::map<std::string, double> GetAnalysisPerformanceInfo();

		std::vector<DisassemblyTextLine> GetTypeTokens(DisassemblySettings* settings = nullptr);

		Confidence<RegisterValue> GetGlobalPointerValue() const;
		bool UsesIncomingGlobalPointer() const;
		Confidence<RegisterValue> GetRegisterValueAtExit(uint32_t reg) const;

		/*! Whether the function is too large to automatically perform analysis

			\return Whether the function is too large to automatically perform analysis
		*/
		bool IsFunctionTooLarge();

		/*! Whether automatic analysis was skipped for this function.

			\return Whether automatic analysis was skipped for this function.
		*/
		bool IsAnalysisSkipped();
		BNAnalysisSkipReason GetAnalysisSkipReason();
		BNFunctionAnalysisSkipOverride GetAnalysisSkipOverride();
		void SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride skip);

		Ref<FlowGraph> GetUnresolvedStackAdjustmentGraph();

		void SetUserVariableValue(const Variable& var, uint64_t defAddr, PossibleValueSet& value);
		void ClearUserVariableValue(const Variable& var, uint64_t defAddr);
		std::map<Variable, std::map<ArchAndAddr, PossibleValueSet>> GetAllUserVariableValues();
		void ClearAllUserVariableValues();

		void RequestDebugReport(const std::string& name);

		/*! Get the name for a given label ID

			\param labelId ID For the label. Saved in the highlight token value.
			\return Name for the label
		*/
		std::string GetGotoLabelName(uint64_t labelId);

		/*! Set the name for a given label ID

			\param labelId ID For the label. Saved in the highlight token value.
			\param name New name for the label
		*/
		void SetGotoLabelName(uint64_t labelId, const std::string& name);

		BNDeadStoreElimination GetVariableDeadStoreElimination(const Variable& var);
		void SetVariableDeadStoreElimination(const Variable& var, BNDeadStoreElimination mode);

		std::map<Variable, std::set<Variable>> GetMergedVariables();
		void MergeVariables(const Variable& target, const std::set<Variable>& sources);
		void UnmergeVariables(const Variable& target, const std::set<Variable>& sources);
		std::set<Variable> GetSplitVariables();
		void SplitVariable(const Variable& var);
		void UnsplitVariable(const Variable& var);

		/*! The highest (largest) virtual address contained in a function.

			\return The highest (largest) virtual address contained in a function.
		*/
		uint64_t GetHighestAddress();

		/*! The lowest (smallest) virtual address contained in a function.

			\return The lowest (smallest) virtual address contained in a function.
		*/
		uint64_t GetLowestAddress();

		/*! All of the address ranges covered by a function

			\return All of the address ranges covered by a function
		*/
		std::vector<BNAddressRange> GetAddressRanges();

		bool GetInstructionContainingAddress(Architecture* arch, uint64_t addr, uint64_t* start);

		Confidence<bool> IsInlinedDuringAnalysis();
		void SetAutoInlinedDuringAnalysis(Confidence<bool> inlined);
		void SetUserInlinedDuringAnalysis(Confidence<bool> inlined);

		// TODO: Documentation
		bool IsInstructionCollapsed(const HighLevelILInstruction& instr, uint64_t designator = 0) const;
		bool IsCollapsed() const;
		void ToggleRegion(uint64_t hash);
		void CollapseRegion(uint64_t hash);
		void ExpandRegion(uint64_t hash);
		void ExpandAll();
	};

	/*!
		\ingroup function
	*/
	class AdvancedFunctionAnalysisDataRequestor
	{
		Ref<Function> m_func;

	  public:
		AdvancedFunctionAnalysisDataRequestor(Function* func = nullptr);
		AdvancedFunctionAnalysisDataRequestor(const AdvancedFunctionAnalysisDataRequestor& req);
		~AdvancedFunctionAnalysisDataRequestor();
		AdvancedFunctionAnalysisDataRequestor& operator=(const AdvancedFunctionAnalysisDataRequestor& req);

		Ref<Function> GetFunction() { return m_func; }
		void SetFunction(Function* func);
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

		/*! Set flow graph block X position

			\param x Flow graph block X position
		*/
		void SetX(int x);

		/*! Set flow graph block Y position

			\param y Flow graph block Y position
		*/
		void SetY(int y);

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

		void SetVisibilityRegion(int x, int y, int w, int h);
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
		void SetWidth(int width);

		/*! Flow graph height

			\return Flow graph height
		*/
		int GetHeight() const;
		void SetHeight(int height);

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

		bool IsQueryModeEnabled() const { return m_queryMode; }

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

	class FlowGraphLayout : public StaticCoreRefCountObject<BNFlowGraphLayout>
	{
	  protected:
		FlowGraphLayout(BNFlowGraphLayout* layout);

		static bool LayoutCallback(void* ctxt, BNFlowGraph* graph, BNFlowGraphNode** nodes, size_t nodeCount);

		std::string m_nameForRegister;

	  public:
		FlowGraphLayout(const std::string& name);

		static void Register(FlowGraphLayout* layout);
		static Ref<FlowGraphLayout> GetByName(const std::string& name);
		static std::vector<Ref<FlowGraphLayout>> GetFlowGraphLayouts();

		std::string GetName() const;
		virtual bool Layout(Ref<FlowGraph> graph, std::vector<Ref<FlowGraphNode>>& nodes);
	};

	class CoreFlowGraphLayout : public FlowGraphLayout
	{
	  public:
		CoreFlowGraphLayout(BNFlowGraphLayout* layout);

		virtual bool Layout(Ref<FlowGraph> graph, std::vector<Ref<FlowGraphNode>>& nodes) override;
	};

	/*!
		\ingroup lowlevelil
	*/
	struct LowLevelILLabel : public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

	struct ILSourceLocation
	{
		uint64_t address;
		uint32_t sourceOperand;
		bool valid;

		ILSourceLocation() : valid(false) {}

		ILSourceLocation(uint64_t addr, uint32_t operand) : address(addr), sourceOperand(operand), valid(true) {}

		ILSourceLocation(const BNLowLevelILInstruction& instr) :
		    address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}

		ILSourceLocation(const BNMediumLevelILInstruction& instr) :
		    address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}

		ILSourceLocation(const BNHighLevelILInstruction& instr) :
		    address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}
	};

	struct LowLevelILInstruction;
	struct RegisterOrFlag;
	struct SSARegister;
	struct SSARegisterStack;
	struct SSAFlag;
	struct SSARegisterOrFlag;

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILFunction :
	    public CoreRefCountObject<BNLowLevelILFunction, BNNewLowLevelILFunctionReference, BNFreeLowLevelILFunction>
	{
	  public:
		LowLevelILFunction(Architecture* arch, Function* func = nullptr);
		LowLevelILFunction(BNLowLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		void PrepareToCopyFunction(LowLevelILFunction* func);
		void PrepareToCopyBlock(BasicBlock* block);

		/*! Get the LowLevelILLabel for a given source instruction. The returned pointer is to an internal object with
			the same lifetime as the containing LowLevelILFunction.

			\param i The source instruction index
			\return The LowLevelILLabel for the source instruction
		*/
		BNLowLevelILLabel* GetLabelForSourceInstruction(size_t i);

		/*! Get the current IL address.
		*/
		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void ClearIndirectBranches();
		void SetIndirectBranches(const std::vector<ArchAndAddr>& branches);

		/*! Get a list of registers used in the LLIL function

			\see Architecture::GetAllRegisters, Architecture::GetRegisterName, Architecture::GetRegisterInfo

			\return The list of used registers
		*/
		std::vector<uint32_t> GetRegisters();

		/*! Get a list of used register stacks used in the LLIL function

			\return List of used register stacks
		*/
		std::vector<uint32_t> GetRegisterStacks();

		/*! Get the list of flags used in this LLIL function

			\see Architecture::GetAllFlags, Architecture::GetFlagName, Architecture::GetFlagRole

			\return The list of used flags.
		*/
		std::vector<uint32_t> GetFlags();

		// Get a list of SSA registers used in the LLIL SSA function, without versions.
		std::vector<SSARegister> GetSSARegistersWithoutVersions();
		std::vector<SSARegisterStack> GetSSARegisterStacksWithoutVersions();
		std::vector<SSAFlag> GetSSAFlagsWithoutVersions();

		// Get a list of SSA registers used in the LLIL SSA function, with versions
		std::vector<SSARegister> GetSSARegisters();
		std::vector<SSARegisterStack> GetSSARegisterStacks();
		std::vector<SSAFlag> GetSSAFlags();

		ExprId AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags, ExprId a = 0, ExprId b = 0,
		    ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		    uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddInstruction(ExprId expr);

		/*! No operation, this instruction does nothing.

			\param loc Optional IL Location this instruction was added from.
			\return
		*/
		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the register \c reg of size \c size to the expression \c value

			\param size Size of the register parameter in bytes
			\param reg The register name
			\param val An expression to set the register to
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>reg = value</tt>
		*/
		ExprId SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Uses \c hi and \c lo as a single extended register setting \c hi:lo to the expression \c value .

			\param size Size of the register parameter in bytes
			\param high The high register name
			\param low The low register name
			\param val An expression to set the split registers to
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>hi:lo = value</tt>
		*/
		ExprId SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSA(
		    size_t size, const SSARegister& reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg, ExprId val,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low, ExprId val,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the top-relative entry \c entry of size \c size in register stack \c reg_stack to the expression
		 	\c value

			\param size Size of the register parameter in bytes
			\param regStack The register stack name
			\param entry An expression for which stack entry to set
			\param val An expression to set the entry to
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>reg_stack[entry] = value</tt>
		*/
		ExprId SetRegisterStackTopRelative(size_t size, uint32_t regStack, ExprId entry, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Pushes the expression \c value of size \c size onto the top of the register
			stack \c reg_stack

			\param size Size of the register parameter in bytes
			\param regStack The register stack name
			\param val An expression to push
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>reg_stack.push(value)</tt>
		*/
		ExprId RegisterStackPush(size_t size, uint32_t regStack, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		ExprId SetRegisterStackTopRelativeSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
		    ExprId entry, const SSARegister& top, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackAbsoluteSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
		    uint32_t reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the flag \c flag to the ExpressionIndex \c value

			\param flag Flag index
			\param val An expression to set the flag to
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>FLAG.flag = value</tt>
		*/
		ExprId SetFlag(uint32_t flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlagSSA(const SSAFlag& flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Reads \c size bytes from the expression \c addr

			\param size Number of bytes to read
			\param addr The expression to read memory from
			\param flags Flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c [addr].size
		*/
		ExprId Load(size_t size, ExprId addr, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(
		    size_t size, ExprId addr, size_t sourceMemoryVer, const ILSourceLocation& loc = ILSourceLocation());

		/*! Writes \c size bytes to expression \c addr read from expression \c val

			\param size Number of bytes to write
			\param addr The expression to write to
			\param val The expression to be written
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>[addr].size = value</tt>
		*/
		ExprId Store(
		    size_t size, ExprId addr, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId addr, ExprId val, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Writes \c size bytes from expression \c value to the stack, adjusting the stack by \c size .

			\param size Number of bytes to write and adjust the stack by
			\param val The expression to write
			\param flags Flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c push(value)
		*/
		ExprId Push(size_t size, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Reads ``size`` bytes from the stack, adjusting the stack by ``size``.

			\param size Number of bytes to read from the stack
			\param flags Flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c pop
		*/
		ExprId Pop(size_t size, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a register of size \c size with name \c reg

			\param size The size of the register in bytes
			\param reg The name of the register
			\param loc Optional IL Location this instruction was added from.
			\return A register expression for the given register
		*/
		ExprId Register(size_t size, uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSA(size_t size, const SSARegister& reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Combines registers of size ``size`` with names ``hi`` and ``lo``

			\param size The size of the register in bytes
			\param high Register holding high part of value
			\param low Register holding low part of value
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c hi:lo
		*/
		ExprId RegisterSplit(
		    size_t size, uint32_t high, uint32_t low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a register stack entry of size \c size at top-relative
			location \c entry in register stack with name \c regStack

			\param size The size of the register in bytes
			\param regStack The index of the register stack
			\param entry An expression for which stack entry to fetch
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c reg_stack[entry]
		*/
		ExprId RegisterStackTopRelative(
		    size_t size, uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the top entry of size \c size in register stack with name \c reg_stack , and
			removes the entry from the stack

			\param size The size of the register in bytes
			\param regStack The index of the register stack
			\param flags Any flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c reg_stack.pop
		*/
		ExprId RegisterStackPop(
		    size_t size, uint32_t regStack, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());


		ExprId RegisterStackFreeReg(uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelative(
		    uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelativeSSA(size_t size, const SSARegisterStack& regStack, ExprId entry,
		    const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackAbsoluteSSA(size_t size, const SSARegisterStack& regStack, uint32_t reg,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelativeSSA(uint32_t regStack, size_t destVersion, size_t srcVersion, ExprId entry,
		    const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeAbsoluteSSA(uint32_t regStack, size_t destVersion, size_t srcVersion, uint32_t reg,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant integer \c value with size \c size

			\param size The size of the constant in bytes
			\param val Integer value of the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant pointer \c value with size \c size

			\param size The size of the pointer in bytes
			\param val Address referenced by pointer
			\param loc Optional IL Location this instruction was added from.
			\return A constant pointer expression of given value and size
		*/
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant relocated pointer ``value`` with size ``size``

			\param size The size of the pointer in bytes
			\param val Address referenced by pointer
			\param offset
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant raw binary floating point
			value \c value with size \c size

		 	To clarify, \c value here is the representation of the float if its bits were instead interpreted as an integer.

			A given float \e could be converted to an integer value like so:

		 	\code{.cpp}
		    union {
				float floatValue;
				uint32_t integerValue;
				} bits;
			bits.floatValue = val;
		 	uint32_t myIntValueToPassToThisFunction = bits.integerValue;
		 	\endcode

		 	Do note this is exactly how FloatConstSingle and FloatConstDouble perform this conversion
		 		(and thus, converting it yourself is \e typically redundant.)

			\param size The size of the constant in bytes
			\param val Integer value for the raw binary representation of the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the single precision floating point value \c value

		 	\param val Float value for the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the double precision floating point value \c value

			\param val Float value for the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a flag expression for the given flag index.

			\param flag Flag index
			\param loc Optional IL Location this expression was added from.
			\return A flag expression for the given flag
		*/
		ExprId Flag(uint32_t flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagSSA(const SSAFlag& flag, const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the flag with index \c flag and size \c size to the constant integer value \c bit

			\param size The size of the flag
			\param flag Flag index
			\param bitIndex Bit of the flag to set
			\param loc Optional IL Location this expression was added from.
			\return A constant expression of given value and size <tt>FLAG.reg = bit</tt>
		*/
		ExprId FlagBit(size_t size, uint32_t flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBitSSA(
		    size_t size, const SSAFlag& flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());

		/*! Adds expression \c a to expression \c b potentially setting flags \c flags and returning
			an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags flags to set
			\param loc Optional IL Location this expression was added from.
			\return A constant expression of given value and size <tt>FLAG.reg = bit</tt>
		*/
		ExprId Add(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Adds with carry expression \c a to expression \c b potentially setting flags \c flags and
			returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>adc.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId AddCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Subtracts expression \c b from expression \c a potentially setting flags \c flags and returning
			an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sub.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Sub(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Subtracts with borrow expression \c b from expression \c a potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sbb.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId SubBorrow(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise and's expression \c a and expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>and.<size>{<flags>}(a, b)</tt>
		*/
		ExprId And(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise or's expression \c a and expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>or.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Or(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Xor's expression \c a with expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>xor.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Xor(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Shifts left expression \c a by expression \c b from expression \c a potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>lsl.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ShiftLeft(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Shifts logically right expression \c a by expression \c b potentially setting flags
			\c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>lsr.<size>{<flags>}(a, b)</tt>
		*/
		ExprId LogicalShiftRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Shifts arithmetic right expression \c a by expression \c b potentially setting flags
			\c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>asr.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ArithShiftRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates left expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>rol.<size>{<flags>}(a, b)</tt>
		*/
		ExprId RotateLeft(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates left with carry expression \c a by expression \c b potentially setting
			flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>rlc.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId RotateLeftCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates right expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>ror.<size>{<flags>}(a, b)</tt>
		*/
		ExprId RotateRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates right with carry expression \c a by expression \c b potentially setting
			flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>rrc.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId RotateRightCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies expression \c a by expression \c b potentially setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sbc.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Mult(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies unsigned with double precision expression \c a by expression \c b
			potentially setting flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mulu.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies signed with double precision expression \c a by expression \c b
			potentially setting flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>muls.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned divide expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>divu.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned double precision divide using expression \c a as
			a single double precision register by expression \c b potentially  setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mods.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed divide expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>divs.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed double precision divide using expression \c a as a
			single double precision register by expression \c b potentially setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>divs.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned modulus expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>modu.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned double precision modulus using expression \c a as
			a single double precision register by expression \c b potentially  setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>modu.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed modulus expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mods.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed double precision modulus using expression \c a as a single
			double precision register by expression \c b potentially  setting flags \c flags and returning an expression
			of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mods.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Two's complement sign negation of expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to negate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>neg.<size>{<flags>}(value)</tt>
		*/
		ExprId Neg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise inverse of expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to bitwise invert
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>not.<size>{<flags>}(value)</tt>
		*/
		ExprId Not(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Two's complement sign-extends the expression in \c value to \c size bytes

			\param size The size of the result in bytes
			\param a The expression to sign extend
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sx.<size>(value)</tt>
		*/
		ExprId SignExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Zero-extends the expression in \c value to \c size bytes

			\param size The size of the result in bytes
			\param a The expression to zero extend
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sx.<size>(value)</tt>
		*/
		ExprId ZeroExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Truncates \c value to \c size bytes

			\param size The size of the result in bytes
			\param a The expression to truncate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>zx.<size>(value)</tt>
		*/
		ExprId LowPart(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which jumps (branches) to the expression \c dest

			\param dest The expression to jump to
			\param loc Optional IL Location this expression was added from.
			\return The expression \c jump(dest)
		*/
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNLowLevelILLabel*>& targets,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which first pushes the address of the next instruction onto the stack then jumps
			(branches) to the expression \c dest

			\param dest The expression to call
			\param loc Optional IL Location this expression was added from.
			\return The expression \c call(dest)
		*/
		ExprId Call(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which first pushes the address of the next instruction onto the stack
			then jumps (branches) to the expression \c dest . After the function exits, \c stack_adjust is added to the
			stack pointer register.

			\param dest The expression to call
			\param adjust Stack adjustment
			\param regStackAdjust Register stack adjustment
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>call(dest), stack += stack_adjust</tt>
		*/
		ExprId CallStackAdjust(ExprId dest, int64_t adjust, const std::map<uint32_t, int32_t>& regStackAdjust,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which jumps (branches) to the expression \c dest

			\param dest The expression to jump to
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>tailcall(dest)</tt>
		*/
		ExprId TailCall(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSARegister>& output, ExprId dest, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SystemCallSSA(const std::vector<SSARegister>& output, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSARegister>& output, ExprId dest, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());

		ExprId SeparateParamListSSA(
			const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SharedParamSlotSSA(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which jumps (branches) to the expression \c dest . \c ret is a special alias for
			jump that makes the disassembler stop disassembling.

			\param dest The expression to jump to
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>jump(dest)</tt>
		*/
		ExprId Return(size_t dest, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression that halts disassembly

			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>noreturn</tt>
		*/
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a flag_condition expression for the given LowLevelILFlagCondition

			\param cond Flag condition expression to retrieve
			\param semClass Optional semantic flag class
			\param loc Optional IL Location this expression was added from.
			\return A flag_condition expression
		*/
		ExprId FlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a flag_group expression for the given semantic flag group

			\param semGroup Semantic flag group to access
			\param loc Optional IL Location this expression was added from.
			\return A flag_group expression
		*/
		ExprId FlagGroup(uint32_t semGroup, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is equal to
			expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is not equal to
			expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed less than expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			unsigned less than expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed less than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			unsigned less than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a
			is unsigned greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			unsigned greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a system call expression.

			\param loc Optional IL Location this expression was added from.
			\return System call expression.
		*/
		ExprId SystemCall(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an intrinsic expression. 'Intrinsics' are emitted and lifted as if they were builtin functions that
			do not exist in the binary.

			\param outputs Registers and/or flags set by this intrinsic call.
			\param intrinsic Index of the intrinsic. <b>See also:</b> Architecture::GetIntrinsicName, Architecture::GetAllIntrinsics
		    \param params Parameter items passed to this intrinsic
			\param flags Flags
			\param loc Optional IL Location this expression was added from.
			\return An intrinsic expression.
		*/
		ExprId Intrinsic(const std::vector<RegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryIntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a processor breakpoint expression.

			\param loc Optional IL Location this expression was added from.
			\return A breakpoint expression.
		*/
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a processor trap (interrupt) expression of the given integer \c value .

			\param num trap (interrupt) number
			\param loc Optional IL Location this expression was added from.
			\return A trap expression.
		*/
		ExprId Trap(int64_t num, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the undefined expression. This should be used for instructions which perform functions but
			aren't important for dataflow or partial emulation purposes.

			\param loc Optional IL Location this expression was added from.
			\return The Undefined expression
		*/
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the unimplemented expression. This should be used for instructions which aren't implemented

			\param loc Optional IL Location this expression was added from.
			\return The unimplemented expression
		*/
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());

		/*! A memory reference to expression \c addr of size \c size with unimplemented operation.

			\param size Size in bytes of the memory reference
			\param addr Expression to reference memory
			\param loc Optional IL Location this expression was added from.
			\return The unimplemented memory reference expression.
		*/
		ExprId UnimplementedMemoryRef(size_t size, ExprId addr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterPhi(const SSARegister& dest, const std::vector<SSARegister>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPhi(const SSARegisterStack& dest, const std::vector<SSARegisterStack>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagPhi(
		    const SSAFlag& dest, const std::vector<SSAFlag>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(
		    size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());

		/*! Adds floating point expression \c a to expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fadd.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatAdd(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Subtracts floating point expression \c b from expression \c a potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fsub.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatSub(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies floating point expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fmul.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatMult(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Divides floating point expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fdiv.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatDiv(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the square root of floating point expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to calculate the square root of
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sqrt.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatSqrt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns sign negation of floating point expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to negate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fneg.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatNeg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns absolute value of floating point expression \c value of size \c size potentially setting flags.

			\param size The size of the result in bytes
			\param a The expression to get the absolute value of
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fabs.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatAbs(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns integer value of floating point expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The float expression to convert to an int
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>int.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point value of integer expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The float expression to convert to a float
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>float.<size>{<flags>}(value)</tt>
		*/
		ExprId IntToFloat(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(
		    size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to the nearest integer

			\param size The size of the result in bytes
			\param a The expression to round to the nearest integer
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId RoundToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to an integer, towards negative infinity

			\param size The size of the result in bytes
			\param a The expression to round down
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId Floor(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to an integer, towards positive infinity

			\param size The size of the result in bytes
			\param a The expression to round up
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId Ceil(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to an integer towards zero

			\param size The size of the result in bytes
			\param a The expression to truncate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatTrunc(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f== b</tt>
		*/
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is not equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f!= b</tt>
		*/
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is less than expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f< b</tt>
		*/
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is less than or equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f<= b</tt>
		*/
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is greater than or equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f>= b</tt>
		*/
		ExprId FloatCompareGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is greater than expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f> b</tt>
		*/
		ExprId FloatCompareGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is ordered relative to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>is_ordered(a, b)</tt>
		*/
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is unordered relative to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>is_unordered(a, b)</tt>
		*/
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a goto expression which jumps to the provided LowLevelILLabel.

			\param label Label to jump to
			\param loc Optional IL Location this expression was added from.
			\return a Goto expression
		*/
		ExprId Goto(BNLowLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the \c if expression which depending on condition \c operand jumps to the LowLevelILLabel
			\c t when the condition expression \c operand is non-zero and \c f`` when it's zero.

			\param operand Comparison expression to evaluate.
			\param t Label for the true branch
			\param f Label for the false branch
			\param loc Optional IL Location this expression was added from.
			\return the ExpressionIndex for the if expression
		*/
		ExprId If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Assigns a LowLevelILLabel to the current IL address.

			\param label label to mark.
		*/
		void MarkLabel(BNLowLevelILLabel& label);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelMap(const std::map<uint64_t, BNLowLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);
		ExprId AddIndexList(const std::vector<size_t> operands);
		ExprId AddRegisterOrFlagList(const std::vector<RegisterOrFlag>& regs);
		ExprId AddSSARegisterList(const std::vector<SSARegister>& regs);
		ExprId AddSSARegisterStackList(const std::vector<SSARegisterStack>& regStacks);
		ExprId AddSSAFlagList(const std::vector<SSAFlag>& flags);
		ExprId AddSSARegisterOrFlagList(const std::vector<SSARegisterOrFlag>& regs);

		ExprId GetExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size);
		ExprId GetNegExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size);
		ExprId GetExprForFlagOrConstant(const BNRegisterOrConstant& operand);
		ExprId GetExprForRegisterOrConstantOperation(
		    BNLowLevelILOperation op, size_t size, BNRegisterOrConstant* operands, size_t operandCount);

		ExprId Operand(size_t n, ExprId expr);

		BNLowLevelILInstruction GetRawExpr(size_t i) const;
		LowLevelILInstruction operator[](size_t i);
		LowLevelILInstruction GetInstruction(size_t i);
		LowLevelILInstruction GetExpr(size_t i);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void ReplaceExpr(size_t expr, size_t newExpr);
		void SetExprAttributes(size_t expr, uint32_t attributes);

		void AddLabelForAddress(Architecture* arch, uint64_t addr);

		/*! Get the LowLevelILLabel for a given address. The returned pointer is to an internal object with
		    the same lifetime as the containing LowLevelILFunction.

			\param[in] arch Architecture for the address
			\param[in] addr Address to get the label for
			\return The LowLevelILLabel for the address
		*/
		BNLowLevelILLabel* GetLabelForAddress(Architecture* arch, uint64_t addr);

		/*! Ends the function and computes the list of basic blocks.
		*/
		void Finalize();
		/*! Generate SSA form given the current LLIL
		*/
		void GenerateSSAForm();

		/*! Get the list of InstructionTextTokens for a given expression

			\param[in] arch Architecture for the expression
			\param[in] expr Expression to get the text for
			\param[out] tokens Output reference to write the instruction tokens to
			\param[in] settings Optional structure with settings for rendering text
			\return True/False on success or failure
		*/
		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		/*! Get the list of InstructionTextTokens for a given instruction

			\param[in] func Function containing the instruction
			\param[in] arch Architecture for the instruction
		    \param[in] i Index of the instruction
			\param[out] tokens Output reference to write the instruction tokens to
			\param[in] settings Optional structure with settings for rendering text
			\return True/False on success or failure
		*/
		bool GetInstructionText(
		    Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		uint32_t GetTemporaryRegisterCount();
		uint32_t GetTemporaryFlagCount();

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<LowLevelILFunction> GetSSAForm() const;
		Ref<LowLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSARegisterDefinition(const SSARegister& reg) const;
		size_t GetSSAFlagDefinition(const SSAFlag& flag) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSARegisterUses(const SSARegister& reg) const;
		std::set<size_t> GetSSAFlagUses(const SSAFlag& flag) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;

		RegisterValue GetSSARegisterValue(const SSARegister& reg);
		RegisterValue GetSSAFlagValue(const SSAFlag& flag);

		RegisterValue GetExprValue(size_t expr);
		RegisterValue GetExprValue(const LowLevelILInstruction& expr);
		PossibleValueSet GetPossibleExprValues(
		    size_t expr, const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(const LowLevelILInstruction& expr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;
		size_t GetMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetMediumLevelILExprIndexes(size_t expr) const;
		size_t GetMappedMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMappedMediumLevelILExprIndex(size_t expr) const;

		static bool IsConstantType(BNLowLevelILOperation type)
		{
			return type == LLIL_CONST || type == LLIL_CONST_PTR || type == LLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILLabel : public BNMediumLevelILLabel
	{
		MediumLevelILLabel();
	};

	struct MediumLevelILInstruction;

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILFunction :
	    public CoreRefCountObject<BNMediumLevelILFunction, BNNewMediumLevelILFunctionReference,
	        BNFreeMediumLevelILFunction>
	{
	  public:
		MediumLevelILFunction(Architecture* arch, Function* func = nullptr);
		MediumLevelILFunction(BNMediumLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void PrepareToCopyFunction(MediumLevelILFunction* func);
		void PrepareToCopyBlock(BasicBlock* block);

		/*! Get the MediumLevelILLabel for a given source instruction. The returned pointer is to an internal object with
			the same lifetime as the containing MediumLevelILFunction.

			\param i Index of the source instruction
			\return The MediumLevelILLabel for the source instruction
		*/
		BNMediumLevelILLabel* GetLabelForSourceInstruction(size_t i);

		ExprId AddExpr(BNMediumLevelILOperation operation, size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0,
		    ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand,
		    size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVar(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarField(size_t size, const Variable& dest, uint64_t offset, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSplit(size_t size, const Variable& high, const Variable& low, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSA(
		    size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSAField(size_t size, const Variable& dest, size_t newVersion, size_t prevVersion, uint64_t offset,
		    ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSASplit(size_t size, const SSAVariable& high, const SSAVariable& low, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliased(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliasedField(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion,
		    uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStruct(size_t size, ExprId src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(size_t size, ExprId src, size_t memVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStructSSA(size_t size, ExprId src, uint64_t offset, size_t memVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStruct(
		    size_t size, ExprId dest, uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStructSSA(size_t size, ExprId dest, uint64_t offset, size_t newMemVersion, size_t prevMemVersion,
		    ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarField(
		    size_t size, const Variable& src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplit(
		    size_t size, const Variable& high, const Variable& low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSAField(
		    size_t size, const SSAVariable& src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliased(
		    size_t size, const Variable& src, size_t memVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliasedField(size_t size, const Variable& src, size_t memVersion, uint64_t offset,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplitSSA(size_t size, const SSAVariable& high, const SSAVariable& low,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOfField(const Variable& var, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNMediumLevelILLabel*>& targets,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ReturnHint(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<Variable>& output, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntyped(const std::vector<Variable>& output, const std::vector<ExprId>& params, ExprId stack,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
			size_t newMemVersion, size_t prevMemVersion, ExprId stack,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<SSAVariable>& output, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntypedSSA(const std::vector<SSAVariable>& output, const std::vector<ExprId>& params,
			size_t newMemVersion, size_t prevMemVersion, ExprId stack,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
			const std::vector<ExprId>& params, size_t newMemVersion, size_t prevMemVersion, ExprId stack,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SeparateParamList(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SharedParamSlot(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId Intrinsic(const std::vector<Variable>& outputs, uint32_t intrinsic, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSAVariable>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryIntrinsicSSA(const std::vector<SSAVariable>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlot(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlotSSA(const Variable& var, size_t newVersion, size_t prevVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarPhi(const SSAVariable& dest, const std::vector<SSAVariable>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(size_t destMemVersion, const std::vector<size_t>& sourceMemVersions,
		    const ILSourceLocation& loc = ILSourceLocation());
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

		ExprId Goto(BNMediumLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f,
		    const ILSourceLocation& loc = ILSourceLocation());
		void MarkLabel(BNMediumLevelILLabel& label);

		ExprId AddInstruction(ExprId expr);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelMap(const std::map<uint64_t, BNMediumLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);
		ExprId AddIndexList(const std::vector<size_t>& operands);
		ExprId AddVariableList(const std::vector<Variable>& vars);
		ExprId AddSSAVariableList(const std::vector<SSAVariable>& vars);

		BNMediumLevelILInstruction GetRawExpr(size_t i) const;
		MediumLevelILInstruction operator[](size_t i);
		MediumLevelILInstruction GetInstruction(size_t i);
		MediumLevelILInstruction GetExpr(size_t i);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void MarkInstructionForRemoval(size_t i);
		void ReplaceInstruction(size_t i, ExprId expr);
		void ReplaceExpr(size_t expr, size_t newExpr);
		void SetExprAttributes(size_t expr, uint32_t attributes);

		void Finalize();
		void GenerateSSAForm(bool analyzeConditionals = true, bool handleAliases = true,
		    const std::set<Variable>& knownNotAliases = std::set<Variable>(),
		    const std::set<Variable>& knownAliases = std::set<Variable>());

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);
		bool GetInstructionText(Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		void VisitInstructions(
		    const std::function<void(BasicBlock* block, const MediumLevelILInstruction& instr)>& func);
		void VisitAllExprs(const std::function<bool(BasicBlock* block, const MediumLevelILInstruction& expr)>& func);

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<MediumLevelILFunction> GetSSAForm() const;
		Ref<MediumLevelILFunction> GetNonSSAForm() const;
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

		RegisterValue GetSSAVarValue(const SSAVariable& var);
		RegisterValue GetExprValue(size_t expr);
		RegisterValue GetExprValue(const MediumLevelILInstruction& expr);
		PossibleValueSet GetPossibleSSAVarValues(const SSAVariable& var, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(
		    size_t expr, const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(const MediumLevelILInstruction& expr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;
		Variable GetVariableForRegisterAtInstruction(uint32_t reg, size_t instr) const;
		Variable GetVariableForFlagAtInstruction(uint32_t flag, size_t instr) const;
		Variable GetVariableForStackLocationAtInstruction(int64_t offset, size_t instr) const;

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		BNILBranchDependence GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const;
		std::unordered_map<size_t, BNILBranchDependence> GetAllBranchDependenceAtInstruction(size_t instr) const;

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		size_t GetLowLevelILInstructionIndex(size_t instr) const;
		size_t GetLowLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetLowLevelILExprIndexes(size_t expr) const;
		Ref<HighLevelILFunction> GetHighLevelIL() const;
		size_t GetHighLevelILInstructionIndex(size_t instr) const;
		size_t GetHighLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetHighLevelILExprIndexes(size_t expr) const;

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const MediumLevelILInstruction& expr);

		/*! SetExprType sets the type of a given expression.

			\warning This method is only meant for workflows or for debugging purposes, since the changes they make
			are not persistent and get lost after a database save and reload. To make persistent changes to the analysis,
			one should use other APIs to, for example, change the type of variables. The analysis will then propagate the
			type of the variable and update the type of related expressions.

		    \param expr index of the expression to set
		    \param type new type of the expression
		*/
		void SetExprType(size_t expr, const Confidence<Ref<Type>>& type);
		void SetExprType(const MediumLevelILInstruction& expr, const Confidence<Ref<Type>>& type);

		static bool IsConstantType(BNMediumLevelILOperation op)
		{
			return op == MLIL_CONST || op == MLIL_CONST_PTR || op == MLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);

		std::set<size_t> GetLiveInstructionsForVariable(const Variable& var, bool includeLastUse = true);

		Variable GetSplitVariableForDefinition(const Variable& var, size_t instrIndex);
	};

	struct HighLevelILInstruction;
	class HighLevelILTokenEmitter;

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
		static bool HasSideEffects(const HighLevelILInstruction& instr);
		static BNScopeType GetExprScopeType(const HighLevelILInstruction& instr);

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
			const HighLevelILInstruction& instr, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetInstructionText(size_t i, DisassemblySettings* settings = nullptr);

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

		std::set<Variable> GetVariables();
		std::set<Variable> GetAliasedVariables();
		std::set<SSAVariable> GetSSAVariables();
	};

	/*! LanguageRepresentationFunction represents a single function in a registered high level language.

	    \ingroup highlevelil
	*/
	class LanguageRepresentationFunction :
	    public CoreRefCountObject<BNLanguageRepresentationFunction, BNNewLanguageRepresentationFunctionReference,
	        BNFreeLanguageRepresentationFunction>
	{
	public:
		LanguageRepresentationFunction(Architecture* arch, Function* func, HighLevelILFunction* highLevelIL);
		LanguageRepresentationFunction(BNLanguageRepresentationFunction* func);

		/*! Gets the lines of tokens for a given High Level IL instruction.

		    \param instr The instruction to emit lines for.
		    \param settings The settings for disassembly (optional).
		    \param precedence The current operator precedence level.
		    \param statement Whether the instruction is a statement or an expression.
		    \return A list of lines of tokens for the instruction.
		*/
		std::vector<DisassemblyTextLine> GetExprText(const HighLevelILInstruction& instr, DisassemblySettings* settings,
			BNOperatorPrecedence precedence = TopLevelOperatorPrecedence, bool statement = false);

		/*! Generates lines for the given High Level IL instruction in the style of the linear view. To get the lines
		    for the entire function, pass the root instruction of a HighLevelILFunction.

		    \param instr The instruction to emit lines for.
		    \param settings The settings for disassembly (optional).
		    \return A list of lines of tokens for the instruction.
		*/
		std::vector<DisassemblyTextLine> GetLinearLines(
			const HighLevelILInstruction& instr, DisassemblySettings* settings);

		/*! Generates lines for a single High Level IL basic block.

		    \param block The basic block to emit lines for.
		    \param settings The settings for disassembly (optional).
		    \return A list of lines of tokens for the basic block.
		*/
		std::vector<DisassemblyTextLine> GetBlockLines(BasicBlock* block, DisassemblySettings* settings);

		/*! Gets the highlight color for a given basic block.

		    \param block The basic block to get the highlight color for.
		    \return The highlight color for the basic block.
		*/
		BNHighlightColor GetHighlight(BasicBlock* block);

		Ref<Architecture> GetArchitecture() const;
		Ref<Function> GetFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		/*! Gets the string representing the start of a comment.

		    \return The string representing the start of a comment.
		*/
		virtual std::string GetCommentStartString() const { return "// "; }

		/*! Gets the string representing the end of a comment.

		    \return The string representing the end of a comment.
		*/
		virtual std::string GetCommentEndString() const { return ""; }

		/*! Gets the string representing the start of an annotation.

		    \return The string representing the start of an annotation.
		*/
		virtual std::string GetAnnotationStartString() const { return "{"; }

		/*! Gets the string representing the end of an annotation.

		    \return The string representing the end of an annotation.
		*/
		virtual std::string GetAnnotationEndString() const { return "}"; }

	protected:
		/*! Override this method to initialize the options for the token emitter before it is used.

		    \param tokens The token emitter to initialize.
		*/
		virtual void InitTokenEmitter(HighLevelILTokenEmitter& tokens);

		/*! This method must be overridden by all language representation plugins.

		    This method is called to emit the tokens for a given High Level IL instruction.

		    \param instr The instruction to emit tokens for.
		    \param tokens The token emitter to use.
		    \param settings The disassembly settings to use (may be NULL).
		    \param precedence The current operator precedence level.
		    \param statement Whether the instruction is a statement or an expression.
		*/
		virtual void GetExprText(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens,
			DisassemblySettings* settings, BNOperatorPrecedence precedence = TopLevelOperatorPrecedence,
			bool statement = false) = 0;

		/*! This method can be overridden to emit tokens at the start of a function.

		    \param instr The root instruction of the function.
		    \param tokens The token emitter to use.
		*/
		virtual void BeginLines(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens);

		/*! This method can be overridden to emit tokens at the end of a function.

		    \param instr The root instruction of the function.
		    \param tokens The token emitter to use.
		*/
		virtual void EndLines(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens);

	private:
		static void FreeCallback(void* ctxt);
		static void InitTokenEmitterCallback(void* ctxt, BNHighLevelILTokenEmitter* tokens);
		static void GetExprTextCallback(void* ctxt, BNHighLevelILFunction* il, size_t exprIndex,
			BNHighLevelILTokenEmitter* tokens, BNDisassemblySettings* settings, bool asFullAst,
			BNOperatorPrecedence precedence, bool statement);
		static void BeginLinesCallback(
			void* ctxt, BNHighLevelILFunction* il, size_t exprIndex, BNHighLevelILTokenEmitter* tokens);
		static void EndLinesCallback(
			void* ctxt, BNHighLevelILFunction* il, size_t exprIndex, BNHighLevelILTokenEmitter* tokens);
		static char* GetCommentStartStringCallback(void* ctxt);
		static char* GetCommentEndStringCallback(void* ctxt);
		static char* GetAnnotationStartStringCallback(void* ctxt);
		static char* GetAnnotationEndStringCallback(void* ctxt);
	};

	/*!
	    \ingroup highlevelil
	*/
	class CoreLanguageRepresentationFunction : public LanguageRepresentationFunction
	{
	public:
		CoreLanguageRepresentationFunction(BNLanguageRepresentationFunction* func);
		std::string GetCommentStartString() const override;
		std::string GetCommentEndString() const override;
		std::string GetAnnotationStartString() const override;
		std::string GetAnnotationEndString() const override;

	protected:
		void GetExprText(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens,
			DisassemblySettings* settings, BNOperatorPrecedence precedence = TopLevelOperatorPrecedence,
			bool statement = false) override;
	};

	class TypePrinter;
	class TypeParser;

	/*!	LanguageRepresentationFunctionType represents a custom language representation function type.
	    This class provides methods to create LanguageRepresentationFunction instances for functions, as well
	    as manage the printing and parsing of types.

	    \ingroup highlevelil
	*/
	class LanguageRepresentationFunctionType : public StaticCoreRefCountObject<BNLanguageRepresentationFunctionType>
	{
		std::string m_nameForRegister;

	public:
		LanguageRepresentationFunctionType(const std::string& name);
		LanguageRepresentationFunctionType(BNLanguageRepresentationFunctionType* type);

		std::string GetName() const;

		/*! This method must be overridden. This creates the LanguageRepresentationFunction object for the
		    given architecture, owner function, and High Level IL function.

		    \param arch The architecture of the function.
		    \param owner The associated function.
		    \param highLevelIL The High Level IL for the function.
		    \return A LanguageRepresentationFunction instance for the given function.
		*/
		virtual Ref<LanguageRepresentationFunction> Create(
			Architecture* arch, Function* owner, HighLevelILFunction* highLevelIL) = 0;

		/*! Returns whether the language is valid for the given binary view.

		    \param view The binary view to check the validity for.
		    \return True if the language is valid for the given binary view, false otherwise.
		*/
		virtual bool IsValid(BinaryView* view);

		/*! Returns the type printer for displaying types in this language. If NULL is returned, the default type
		    printer will be used.

		    \return The optional type printer for displaying types in this language.
		*/
		virtual Ref<TypePrinter> GetTypePrinter() { return nullptr; }

		/*! Returns the type parser for parsing types in this language. If NULL is returned, the default type
		    parser will be used.

		    \return The optional type parser for parsing types in this language.
		*/
		virtual Ref<TypeParser> GetTypeParser() { return nullptr; }

		/*! Returns a list of lines representing a function prototype in this language. If no lines are returned, the
		    default C-style prototype will be used.

		    \param func The function to get the prototype lines for.
		    \param settings The disassembly settings to use (may be NULL).
		    \return An optional vector of lines representing the function prototype.
		*/
		virtual std::vector<DisassemblyTextLine> GetFunctionTypeTokens(
			Function* func, DisassemblySettings* settings = nullptr);

		/*! Registers the language representation function type.

		    \param type The language representation function type to register.
		*/
		static void Register(LanguageRepresentationFunctionType* type);

		static Ref<LanguageRepresentationFunctionType> GetByName(const std::string& name);
		static bool IsValidByName(const std::string& name, BinaryView* view);
		static std::vector<Ref<LanguageRepresentationFunctionType>> GetTypes();

	private:
		static BNLanguageRepresentationFunction* CreateCallback(
			void* ctxt, BNArchitecture* arch, BNFunction* owner, BNHighLevelILFunction* highLevelIL);
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static BNTypePrinter* GetTypePrinterCallback(void* ctxt);
		static BNTypeParser* GetTypeParserCallback(void* ctxt);
		static BNDisassemblyTextLine* GetFunctionTypeTokensCallback(
			void* ctxt, BNFunction* func, BNDisassemblySettings* settings, size_t* count);
		static void FreeLinesCallback(void* ctxt, BNDisassemblyTextLine* lines, size_t count);
	};

	class CoreLanguageRepresentationFunctionType : public LanguageRepresentationFunctionType
	{
	public:
		CoreLanguageRepresentationFunctionType(BNLanguageRepresentationFunctionType* type);
		Ref<LanguageRepresentationFunction> Create(
			Architecture* arch, Function* owner, HighLevelILFunction* highLevelIL) override;
		bool IsValid(BinaryView* view) override;
		Ref<TypePrinter> GetTypePrinter() override;
		Ref<TypeParser> GetTypeParser() override;
		std::vector<DisassemblyTextLine> GetFunctionTypeTokens(
			Function* func, DisassemblySettings* settings = nullptr) override;
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
		    const std::string& version, const std::function<bool(size_t progress, size_t total)>& progress);
		BNUpdateResult UpdateToLatestVersion();
		BNUpdateResult UpdateToLatestVersion(const std::function<bool(size_t progress, size_t total)>& progress);
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
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs, size_t len);

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
		\ingroup interaction
	*/
	struct FormInputField
	{
		BNFormInputFieldType type;
		std::string prompt;
		Ref<BinaryView> view;              // For AddressFormField
		uint64_t currentAddress;           // For AddressFormField
		std::vector<std::string> choices;  // For ChoiceFormField
		std::string ext;                   // For OpenFileNameFormField, SaveFileNameFormField
		std::string defaultName;           // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		std::string stringResult;
		size_t indexResult;
		bool hasDefault;
		int64_t intDefault;
		uint64_t addressDefault;
		std::string stringDefault;
		size_t indexDefault;

		static FormInputField Label(const std::string& text);
		static FormInputField Separator();
		static FormInputField TextLine(const std::string& prompt);
		static FormInputField MultilineText(const std::string& prompt);
		static FormInputField Integer(const std::string& prompt);
		static FormInputField Address(
		    const std::string& prompt, BinaryView* view = nullptr, uint64_t currentAddress = 0);
		static FormInputField Choice(const std::string& prompt, const std::vector<std::string>& choices);
		static FormInputField OpenFileName(const std::string& prompt, const std::string& ext);
		static FormInputField SaveFileName(
		    const std::string& prompt, const std::string& ext, const std::string& defaultName = "");
		static FormInputField DirectoryName(const std::string& prompt, const std::string& defaultName = "");
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

	/*!
		\ingroup interaction
	*/
	class InteractionHandler
	{
	  public:
		virtual void ShowPlainTextReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents) = 0;
		virtual void ShowMarkdownReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents, const std::string& plainText);
		virtual void ShowHTMLReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents, const std::string& plainText);
		virtual void ShowGraphReport(Ref<BinaryView> view, const std::string& title, Ref<FlowGraph> graph);
		virtual void ShowReportCollection(const std::string& title, Ref<ReportCollection> reports);

		virtual bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title) = 0;
		virtual bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
		virtual bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title,
		    Ref<BinaryView> view, uint64_t currentAddr);
		virtual bool GetChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
			const std::vector<std::string>& choices) = 0;
		virtual bool GetLargeChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
			const std::vector<std::string>& choices) = 0;
		virtual bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
		virtual bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
		    const std::string& defaultName = "");
		virtual bool GetDirectoryNameInput(
		    std::string& result, const std::string& prompt, const std::string& defaultName = "");
		virtual bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title) = 0;

		virtual BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
		    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon) = 0;
		virtual bool OpenUrl(const std::string& url) = 0;
		virtual bool RunProgressDialog(const std::string& title, bool canCancel, std::function<void(std::function<bool(size_t, size_t)> progress)> task) = 0;
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
		bool IsViewOnly() const;
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

	/*! \c Settings provides a way to define and access settings in a hierarchical fashion. The value of a setting can
		be defined for each hierarchical level, where each level overrides the preceding level. The backing-store for setting
		values at each level is also configurable. This allows for ephemeral or platform-independent persistent settings storage
		for components within Binary Ninja or consumers of the Binary Ninja API.

		Each \c Settings instance has an \c instanceId which identifies a schema. The schema defines the settings contents
		and the way in which settings are retrieved and manipulated. A new \c Settings instance defaults to using a value of <em><tt>default</tt></em>
		for the \c instanceId . The <em><tt>default</tt></em> settings schema defines all of the settings available for the active Binary Ninja components
		which include at a minimum, the settings defined by the Binary Ninja core. The <em><tt>default</tt></em> schema may additionally define settings
		for the UI and/or installed plugins. Extending existing schemas, or defining new ones is accomplished by calling \c RegisterGroup()
		and \c RegisterSetting() methods, or by deserializing an existing schema with \c DeserializeSchema() .

		\note All settings in the <em><tt>default</tt></em> settings schema are rendered with UI elements in the Settings View of Binary Ninja UI.

		Allowing setting overrides is an important feature and Binary Ninja accomplishes this by allowing one to override a setting at various
		levels. The levels and their associated storage are shown in the following table. Default setting values are optional, and if specified,
		saved in the schema itself.

			================= ========================== ============== ==============================================
			Setting Level     Settings Scope             Preference     Storage
			================= ========================== ============== ==============================================
			Default           SettingsDefaultScope       Lowest         Settings Schema
			User              SettingsUserScope          -              <User Directory>/settings.json
			Project           SettingsProjectScope       -              <Project Directory>/settings.json
			Resource          SettingsResourceScope      Highest        Raw BinaryView (Storage in BNDB)
			================= ========================== ============== ==============================================

		Settings are identified by a key, which is a string in the form of <b><tt><group>.<name></tt></b> or <b><tt><group>.<subGroup>.<name></tt></b> . Groups provide
		a simple way to categorize settings. Sub-groups are optional and multiple sub-groups are allowed. When defining a settings group, the
		\c RegisterGroup method allows for specifying a UI friendly title for use in the Binary Ninja UI. Defining a new setting requires a
		unique setting key and a JSON string of property, value pairs. The following table describes the available properties and values.

			==================   ======================================   ==================   ========   =======================================================================
			Property             JSON Data Type                           Prerequisite         Optional   {Allowed Values} and Notes
			==================   ======================================   ==================   ========   =======================================================================
			"title"              string                                   None                 No         Concise Setting Title
			"type"               string                                   None                 No         {"array", "boolean", "number", "string", "object"}
			"sorted"             boolean                                  "type" is "array"    Yes        Automatically sort list items (default is false)
			"isSerialized"       boolean                                  "type" is "string"   Yes        Treat the string as a serialized JSON object
			"enum"               array : {string}                         "type" is "array"    Yes        Enumeration definitions
			"enumDescriptions"   array : {string}                         "type" is "array"    Yes        Enumeration descriptions that match "enum" array
			"minValue"           number                                   "type" is "number"   Yes        Specify 0 to infer unsigned (default is signed)
			"maxValue"           number                                   "type" is "number"   Yes        Values less than or equal to INT_MAX result in a QSpinBox UI element
			"precision"          number                                   "type" is "number"   Yes        Specify precision for a QDoubleSpinBox
			"default"            {array, boolean, number, string, null}   None                 Yes        Specify optimal default value
			"aliases"            array : {string}                         None                 Yes        Array of deprecated setting key(s)
			"description"        string                                   None                 No         Detailed setting description
			"ignore"             array : {string}                         None                 Yes        {"SettingsUserScope", "SettingsProjectScope", "SettingsResourceScope"}
			"message"            string                                   None                 Yes        An optional message with additional emphasis
			"readOnly"           bool                                     None                 Yes        Only enforced by UI elements
			"optional"           bool                                     None                 Yes        Indicates setting can be null
			"hidden"             bool                                     "type" is "string"   Yes        Indicates the UI should conceal the content. The "ignore" property is required to specify the applicable storage scopes
			"requiresRestart     bool                                     None                 Yes        Enable restart notification in the UI upon change
			"uiSelectionAction"  string                                   "type" is "string"   Yes        {"file", "directory", <Registered UIAction Name>} Informs the UI to add a button to open a selection dialog or run a registered UIAction
			==================   ======================================   ==================   ========   =======================================================================

		\note In order to facilitate deterministic analysis results, settings from the <em><tt>default</tt></em> schema that impact analysis are serialized
		from Default, User, and Project scope into Resource scope during initial BinaryView analysis. This allows an analysis database to be opened
		at a later time with the same settings, regardless if Default, User, or Project settings have been modified.

		\note Settings that do not impact analysis (e.g. many UI settings) should use the \e "ignore" property to exclude
			\e "SettingsProjectScope" and \e "SettingsResourceScope" from the applicable scopes for the setting.

		<b>Example analysis plugin setting:</b>
	 	\code{.cpp}
		auto settings = Settings::Instance()

	 	settings->RegisterGroup("myPlugin", "My Plugin")

		settings->RegisterSetting("myPlugin.enablePreAnalysis",
			R"~({
			"title": "My Pre-Analysis Plugin",
			"type": "boolean",
			"default": false,
			"description": "Enable extra analysis before core analysis.",
			"ignore": ["SettingsProjectScope", "SettingsResourceScope"]
			})~");

		Metadata options = {{"myPlugin.enablePreAnalysis", Metadata(true)}};
		Ref<BinaryView> bv = Load("/bin/ls", true, {}, options);

		Settings::Instance()->Get<bool>("myPlugin.enablePreAnalysis"); // false
	    Settings::Instance()->Get<bool>("myPlugin.enablePreAnalysis", bv); // true
		\endcode

	 	<b>Getting a settings value:</b>
	 	\code{.cpp}
	    bool excludeUnreferencedStrings = Settings::Instance()->Get<bool>("ui.stringView.excludeUnreferencedStrings", bv);
	    \endcode

	    \ingroup settings
	*/
	class Settings : public CoreRefCountObject<BNSettings, BNNewSettingsReference, BNFreeSettings>
	{
		std::string m_instanceId;

		Settings() = delete;
		Settings(const std::string& m_instanceId);

	  public:
		Settings(BNSettings* settings);
		static Ref<Settings> Instance(const std::string& schemaId = "");
		virtual ~Settings() {}

		/*! Sets the file that this \c Settings instance uses when initially loading, and modifying \
			settings for the specified scope.

			\note At times it may be useful to make ephemeral changes to settings that are not saved to file. This can be accomplished \
			by calling \c LoadSettingsFile without specifying a filename. This action also resets settings to their default value.

			\param fileName the settings filename
			\param scope the BNSettingsScope
			\param view a BinaryView object
			\return True if the load is successful, False otherwise
		*/
		bool LoadSettingsFile(const std::string& fileName, BNSettingsScope scope = SettingsAutoScope, Ref<BinaryView> view = nullptr);

		/*! Sets the resource identifier for this \c Settings instance. When accessing setting values at the
			\c SettingsResourceScope level, the resource identifier is passed along through the backing store interface.

			\note Currently the only available backing store for \c SettingsResourceScope is a \c BinaryView object. In the context
			of a \c BinaryView the resource identifier is the \c BinaryViewType name. All settings for this type of backing store
			are saved in the \e 'Raw' \c BinaryViewType . This enables the configuration of setting values such that they are available
			during \c BinaryView creation and initialization.

			\param resourceId a unique identifier
		*/
		void SetResourceId(const std::string& resourceId = "");

		/*! Registers a group in the schema for this \c Settings instance

			\param group a unique identifier
			\param title a user friendly name appropriate for UI presentation
			\return True on success, False on failure
		*/
		bool RegisterGroup(const std::string& group, const std::string& title);

		/*! Registers a new setting with this \c Settings instance

			\param key a unique setting identifier in the form <b>'<group>.<name>'</b>
			\param properties a JSON string describes the setting schema
			\return True on success, False on failure.
		*/
		bool RegisterSetting(const std::string& key, const std::string& properties);

		/*! Determine if a setting identifier exists in the active settings schema

			\param key the setting identifier
			\return True if the identifier exists in this active settings schema, False otherwise
		*/
		bool Contains(const std::string& key);

		/*! Determine if the active settings schema is empty

			\return True if the active settings schema is empty, False otherwise
		*/
		bool IsEmpty();

		/*! Retrieve the list of setting identifiers in the active settings schema

			\return List of setting identifiers
		*/
		std::vector<std::string> Keys();

		template <typename T>
		T QueryProperty(const std::string& key, const std::string& property);

		bool UpdateProperty(const std::string& key, const std::string& property);
		bool UpdateProperty(const std::string& key, const std::string& property, bool value);
		bool UpdateProperty(const std::string& key, const std::string& property, double value);
		bool UpdateProperty(const std::string& key, const std::string& property, int value);
		bool UpdateProperty(const std::string& key, const std::string& property, int64_t value);
		bool UpdateProperty(const std::string& key, const std::string& property, uint64_t value);
		bool UpdateProperty(const std::string& key, const std::string& property, const char* value);
		bool UpdateProperty(const std::string& key, const std::string& property, const std::string& value);
		bool UpdateProperty(const std::string& key, const std::string& property, const std::vector<std::string>& value);

		bool DeserializeSchema(const std::string& schema, BNSettingsScope scope = SettingsAutoScope, bool merge = true);
		std::string SerializeSchema();
		bool DeserializeSettings(
		    const std::string& contents, Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);
		std::string SerializeSettings(Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);

		bool Reset(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);
		bool ResetAll(
		    Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope, bool schemaOnly = true);

		/*! Get the current setting value for a particular key

			\code{.cpp}
		 	bool excludeUnreferencedStrings = Settings::Instance()->Get<bool>("ui.stringView.excludeUnreferencedStrings", data);
			\endcode

			\tparam T type for the value you are retrieving
			\param key Key for the setting
			\param view BinaryView, for factoring in resource-scoped settings
			\param scope Scope for the settings
			\return Value for the setting, with type T
		*/
		template <typename T>
		T Get(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);

		/*! Get the current settings value for a particular key, as a JSON representation of its value.

			\code{.cpp}
		    string value = Settings::Instance()->GetJson("analysis.mode");
			// '"full"'
		 	\endcode

			\param key Key for the setting
			\param view BinaryView, for factoring in resource-scoped settings
			\param scope Scope for the settings
			\return JSON value for the setting, as a string
		*/
		std::string GetJson(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);

		bool Set(const std::string& key, bool value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, double value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int64_t value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, uint64_t value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const char* value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::string& value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::vector<std::string>& value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool SetJson(const std::string& key, const std::string& value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);

		// Function Settings
		bool DeserializeSettings(const std::string& contents, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		std::string SerializeSettings(Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);

		bool Reset(const std::string& key, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool ResetAll(Ref<Function> func, BNSettingsScope scope = SettingsAutoScope, bool schemaOnly = true);

		template <typename T>
		T Get(const std::string& key, Ref<Function> func, BNSettingsScope* scope = nullptr);

		std::string GetJson(const std::string& key, Ref<Function> func, BNSettingsScope* scope = nullptr);

		bool Set(const std::string& key, bool value, Ref<Function> func,  BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, double value, Ref<Function> func,  BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int64_t value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, uint64_t value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const char* value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::string& value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::vector<std::string>& value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
		bool SetJson(const std::string& key, const std::string& value, Ref<Function> func, BNSettingsScope scope = SettingsAutoScope);
	};

	// explicit specializations
	/*! \cond DOXYGEN_HIDE
		Prevent these from having docs autogenerated twice, due to an odd quirk with doxygen
	*/
	template <>
	std::string Settings::QueryProperty<std::string>(const std::string& key, const std::string& property);
	template <>
	std::vector<std::string> Settings::QueryProperty<std::vector<std::string>>(const std::string& key, const std::string& property);
	template <>
	bool Settings::Get<bool>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	double Settings::Get<double>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	int64_t Settings::Get<int64_t>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	uint64_t Settings::Get<uint64_t>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	std::string Settings::Get<std::string>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	std::vector<std::string> Settings::Get<std::vector<std::string>>(
	    const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	/*! \endcond*/

	template <>
	bool Settings::Get<bool>(const std::string& key, Ref<Function> func, BNSettingsScope* scope);
	template <>
	double Settings::Get<double>(const std::string& key, Ref<Function> func, BNSettingsScope* scope);
	template <>
	int64_t Settings::Get<int64_t>(const std::string& key, Ref<Function> func, BNSettingsScope* scope);
	template <>
	uint64_t Settings::Get<uint64_t>(const std::string& key, Ref<Function> func, BNSettingsScope* scope);
	template <>
	std::string Settings::Get<std::string>(const std::string& key, Ref<Function> func, BNSettingsScope* scope);
	template <>
	std::vector<std::string> Settings::Get<std::vector<std::string>>(const std::string& key, Ref<Function> func, BNSettingsScope* scope);

	typedef BNMetadataType MetadataType;

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
			BNTypeContext* typeCxt, size_t ctxCount, const char* language);
		static void FreeCallback(void* ctxt);
		static void FreeLinesCallback(void* ctxt, BNDisassemblyTextLine* lines, size_t count);

	  public:
		DataRenderer();
		DataRenderer(BNDataRenderer* renderer);
		virtual bool IsValidForData(
		    BinaryView* data, uint64_t addr, Type* type, std::vector<std::pair<Type*, size_t>>& context);
		virtual std::vector<DisassemblyTextLine> GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
		    const std::vector<InstructionTextToken>& prefix, size_t width,
			std::vector<std::pair<Type*, size_t>>& context, const std::string& language = std::string());
		std::vector<DisassemblyTextLine> RenderLinesForData(BinaryView* data, uint64_t addr, Type* type,
		    const std::vector<InstructionTextToken>& prefix, size_t width,
		    std::vector<std::pair<Type*, size_t>>& context, const std::string& language = std::string());

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
		static BNSymbolDisplayResult AddSymbolTokenStatic(
			std::vector<InstructionTextToken>& tokens, uint64_t addr, size_t size, size_t operand,
			BinaryView* data, size_t maxSymbolWidth, Function* func, uint8_t confidence = BN_FULL_CONFIDENCE,
			BNSymbolDisplayType symbolDisplay = DisplaySymbolOnly,
			BNOperatorPrecedence precedence = TopLevelOperatorPrecedence,
			uint64_t instrAddr = -1, uint64_t exprIndex = -1);
		void AddStackVariableReferenceTokens(
		    std::vector<InstructionTextToken>& tokens, const StackVariableReference& ref);

		static bool IsIntegerToken(BNInstructionTextTokenType type);
		void AddIntegerToken(std::vector<InstructionTextToken>& tokens, const InstructionTextToken& token,
		    Architecture* arch, uint64_t addr);

		void WrapComment(DisassemblyTextLine& line, std::vector<DisassemblyTextLine>& lines, const std::string& comment,
		    bool hasAutoAnnotations, const std::string& leadingSpaces = "  ", const std::string& indentSpaces = "");
		static std::string GetDisplayStringForInteger(Ref<BinaryView> binaryView, BNIntegerDisplayType type,
		    uint64_t value, size_t inputWidth, bool isSigned = true);
		static std::string GetStringLiteralPrefix(BNStringType type);
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
		static Ref<LinearViewObject> CreateLanguageRepresentation(BinaryView* view, DisassemblySettings* settings,
			const std::string& language = "Pseudo C");
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
		    Function* func, DisassemblySettings* settings, const std::string& language = "Pseudo C");
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
		FunctionViewType ilType;
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
		static bool ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view, BNBinaryView* debugFile, BNProgressFunction progress, void* progressCtxt);
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

	class TypeArchive;
	class TypeArchiveNotification
	{
		BNTypeArchiveNotification m_callbacks;

		static void OnTypeAddedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* definition);
		static void OnTypeUpdatedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* oldDefinition, BNType* newDefinition);
		static void OnTypeRenamedCallback(void* ctx, BNTypeArchive* archive, const char* id, const BNQualifiedName* oldName, const BNQualifiedName* newName);
		static void OnTypeDeletedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* definition);

	public:
		TypeArchiveNotification();
		virtual ~TypeArchiveNotification() = default;

		BNTypeArchiveNotification* GetCallbacks() { return &m_callbacks; }

		/*! Called when a type is added to the archive

		    \param archive
		    \param id Id of type added
		    \param definition Definition of type
		 */
		virtual void OnTypeAdded(Ref<TypeArchive> archive, const std::string& id, Ref<Type> definition)
		{
			(void)archive;
			(void)id;
		}

		/*! Called when a type in the archive is updated to a new definition

		    \param archive
		    \param id Id of type
		    \param oldDefinition Previous definition
		    \param newDefinition Current definition
		 */
		virtual void OnTypeUpdated(Ref<TypeArchive> archive, const std::string& id, Ref<Type> oldDefinition, Ref<Type> newDefinition)
		{
			(void)archive;
			(void)id;
			(void)oldDefinition;
			(void)newDefinition;
		}

		/*! Called when a type in the archive is renamed

		    \param archive
		    \param id Type id
		    \param oldName Previous name
		    \param newName Current name
		 */
		virtual void OnTypeRenamed(Ref<TypeArchive> archive, const std::string& id, const QualifiedName& oldName, const QualifiedName& newName)
		{
			(void)archive;
			(void)oldName;
			(void)newName;
		}

		/*! Called when a type in the archive is deleted from the archive

		    \param archive
		    \param id Id of type deleted
		    \param definition Definition of type deleted
		 */
		virtual void OnTypeDeleted(Ref<TypeArchive> archive, const std::string& id, Ref<Type> definition)
		{
			(void)archive;
			(void)id;
			(void)definition;
		}
	};

	/*! Type Archives are a collection of types which can be shared between different analysis
	    sessions and are backed by a database file on disk. Their types can be modified, and
	    a history of previous versions of types is stored in snapshots in the archive.

	    \ingroup binaryview
	 */
	class TypeArchive: public CoreRefCountObject<BNTypeArchive, BNNewTypeArchiveReference, BNFreeTypeArchiveReference>
	{
	public:
		TypeArchive(BNTypeArchive* archive);

		/*! Open the type archive at the given path, if it exists.

		    \param path Path to type archive file
		    \return Type archive, or nullptr if it could not be loaded.
		 */
		static Ref<TypeArchive> Open(const std::string& path);

		/*! Create a type archive at the given path.

		    \param path Path to type archive file
		    \param platform Relevant platform for types in the archive
		    \return Type archive, or nullptr if it could not be loaded.
		 */
		static Ref<TypeArchive> Create(const std::string& path, Ref<Platform> platform);

		/*! Create a type archive at the given path with a manually-specified id.

		    \note You probably want to use Create() and let BN handle picking an id for you.
		    \param path Path to type archive file
		    \param platform Relevant platform for types in the archive
		    \param id Assigned id for the type archive
		    \return Type archive, or nullptr if it could not be created.
		 */
		static Ref<TypeArchive> CreateWithId(const std::string& path, Ref<Platform> platform, const std::string& id);

		/*! Get a reference to the type archive with the known id, if one exists.

		    \param id Type archive id
		    \return Type archive, or nullptr if it could not be found.
		 */
		static Ref<TypeArchive> LookupById(const std::string& id);

		/*! Close a type archive, disconnecting it from any active views and closing any open file handles

		    \param archive Type Archive to close
		 */
		static void Close(Ref<TypeArchive> archive);

		/*! Determine if a file is a Type Archive

		    \param path File path
		    \return True if it's a type archive
		 */
		static bool IsTypeArchive(const std::string& path);

		/*! Get the unique id associated with this type archive

		    \return The id
		 */
		std::string GetId() const;

		/*! Get the path to the type archive

		    \return The path
		 */
		std::string GetPath() const;

		/*! Get the associated Platform for a Type Archive

		    \return Platform
		 */
		Ref<Platform> GetPlatform() const;

		/*! Get the id of the current snapshot in the type archive

		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Snapshot id
		 */
		std::string GetCurrentSnapshotId() const;

		/*! Revert the type archive's current snapshot to the given snapshot

		    \param id Snapshot id
		 */
		void SetCurrentSnapshot(const std::string& id);

		/*! Get a list of every snapshot's id

		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All ids (including the empty first snapshot)
		 */
		std::vector<std::string> GetAllSnapshotIds() const;

		/*! Get the ids of the parents to the given snapshot

		    \param id Child snapshot id
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Parent snapshot ids, or empty vector if the snapshot is a root
		 */
		std::vector<std::string> GetSnapshotParentIds(const std::string& id) const;

		/*! Get the ids of the children to the given snapshot

		    \param id Parent snapshot id
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Child snapshot ids, or empty vector if the snapshot is a leaf
		 */
		std::vector<std::string> GetSnapshotChildIds(const std::string& id) const;

		/*! Get the TypeContainer interface for this Type Archive, presenting types
		    at the current snapshot in the archive.

		    \return TypeContainer interface
		 */
		class TypeContainer GetTypeContainer() const;

		/*! Add named types to the type archive. Types must have all dependant named
		    types prior to being added, or this function will fail.
		    Types already existing with any added names will be overwritten.

		    \param name Name of new type
		    \param types Type definitions
		    \return True if the types were added
		 */
		bool AddTypes(const std::vector<QualifiedNameAndType>& types);

		/*! Change the name of an existing type in the type archive.

		    \param id Type id
		    \param newName New type name
		    \return True if successful
		 */
		bool RenameType(const std::string& id, const QualifiedName& newName);

		/*! Delete an existing type in the type archive.

		    \param id Type id
		    \return True if successful
		 */
		bool DeleteType(const std::string& id);

		/*! Retrieve a stored type in the archive by id

		    \param id Type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type, if it exists. Otherwise nullptr
		 */
		Ref<Type> GetTypeById(const std::string& id, std::string snapshot = "") const;

		/*! Retrieve a stored type in the archive

		    \param name Type name
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type, if it exists. Otherwise nullptr
		 */
		Ref<Type> GetTypeByName(const QualifiedName& name, std::string snapshot = "") const;

		/*! Retrieve a type's id by its name

		    \param name Type name
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type id, if it exists. Otherwise empty string
		 */
		std::string GetTypeId(const QualifiedName& name, std::string snapshot = "") const;

		/*! Retrieve a type's name by its id

		    \param id Type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type name, if it exists. Otherwise empty string
		 */
		QualifiedName GetTypeName(const std::string& id, std::string snapshot = "") const;

		/*! Retrieve all stored types in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All types
		 */
		std::unordered_map<std::string, QualifiedNameAndType> GetTypes(std::string snapshot = "") const;

		/*! Get a list of all types' ids currently in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All type ids
		 */
		std::vector<std::string> GetTypeIds(std::string snapshot = "") const;

		/*! Get a list of all types' names currently in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All type names
		 */
		std::vector<QualifiedName> GetTypeNames(std::string snapshot = "") const;

		/*! Get a list of all types' names and ids currently in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All type names and ids
		 */
		std::unordered_map<std::string, QualifiedName> GetTypeNamesAndIds(std::string snapshot = "") const;

		/*! Get all types a given type references directly

		    \param id Source type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Target type ids
		 */
		std::unordered_set<std::string> GetOutgoingDirectTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Get all types a given type references, and any types that the referenced types reference

		    \param id Source type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Target type ids
		 */
		std::unordered_set<std::string> GetOutgoingRecursiveTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Get all types that reference a given type

		    \param id Target type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Source type ids
		 */
		std::unordered_set<std::string> GetIncomingDirectTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Get all types that reference a given type, and all types that reference them, recursively

		    \param id Target type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Source type ids
		 */
		std::unordered_set<std::string> GetIncomingRecursiveTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Do some function in a transaction making a new snapshot whose id is passed to func. If func throws,
		    the transaction will be rolled back and the snapshot will not be created.

		    \param func Function to call
		    \param parents Parent snapshot ids
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Created snapshot id
		 */
		std::string NewSnapshotTransaction(std::function<void(const std::string& id)> func, const std::vector<std::string>& parents);

		/*! Register a notification listener

		    \param notification Object to receive notifications
		 */
		void RegisterNotification(TypeArchiveNotification* notification);

		/*! Unregister a notification listener

		    \param notification Object to no longer receive notifications
		 */
		void UnregisterNotification(TypeArchiveNotification* notification);

		/*! Store a key/value pair in the archive's metadata storage

		    \param key Metadata key
		    \param value Metadata value
		    \throws ExceptionWithStackTrace if an exception occurs
		 */
		void StoreMetadata(const std::string& key, Ref<Metadata> value);

		/*! Look up a metadata entry in the archive

		    \param key Metadata key
		    \return Metadata value, if it exists. Otherwise, nullptr
		 */
		Ref<Metadata> QueryMetadata(const std::string& key) const;

		/*! Delete a given metadata entry in the archive

		    \param key Metadata key
		    \throws ExceptionWithStackTrace if an exception occurs
		 */
		void RemoveMetadata(const std::string& key);

		/*! Turn a given snapshot into a data stream

		    \param snapshot Snapshot id
		    \return Buffer containing serialized snapshot data
		 */
		DataBuffer SerializeSnapshot(const std::string& snapshot) const;

		/*! Take a serialized snapshot data stream and create a new snapshot from it

		    \param data Snapshot data
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return String of created snapshot id
		 */
		std::string DeserializeSnapshot(const DataBuffer& data);

		/*! Merge two snapshots in the archive to produce a new snapshot

		    \param[in] baseSnapshot Common ancestor of snapshots
		    \param[in] firstSnapshot First snapshot to merge
		    \param[in] secondSnapshot Second snapshot to merge
		    \param[in] mergeConflictsIn Map of resolutions for all conflicting types, id <-> target snapshot
		    \param[out] mergeConflictsOut List of conflicting type ids
		    \param[in] progress Function to call for progress updates
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Snapshot id, if merge was successful. std::nullopt, otherwise
		 */
		std::optional<std::string> MergeSnapshots(
			const std::string& baseSnapshot,
			const std::string& firstSnapshot,
			const std::string& secondSnapshot,
			const std::unordered_map<std::string, std::string>& mergeConflictsIn,
			std::unordered_set<std::string>& mergeConflictsOut,
			std::function<bool(size_t, size_t)> progress
		);
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

	/*!
	    \ingroup binaryview
	*/
	class SymbolQueue
	{
		BNSymbolQueue* m_object;

		static void ResolveCallback(void* ctxt, BNSymbol** symbol, BNType** type);
		static void AddCallback(void* ctxt, BNSymbol* symbol, BNType* type);

	public:
		SymbolQueue();
		~SymbolQueue();
		void Append(const std::function<std::pair<Ref<Symbol>, Ref<Type>>()>& resolve,
			const std::function<void(Symbol*, Type*)>& add);
		void Process();
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


	/*!
		\ingroup firmwareninja
	*/
	struct FirmwareNinjaDevice
	{
		std::string name;
		uint64_t start;
		uint64_t end;
		std::string info;
	};

	/*!
		\ingroup firmwareninja
	*/
	struct FirmwareNinjaFunctionMemoryAccesses
	{
		uint64_t start;
		size_t count;
		std::vector<BNFirmwareNinjaMemoryAccess> accesses;
	};

	/*!
		\ingroup firmwareninja
	*/
	struct FirmwareNinjaDeviceAccesses
	{
		std::string name;
		size_t total;
		size_t unique;
	};

	/*! FirmwareNinja is a class containing features specific to embedded firmware analysis. This class is only
		available in the Ultimate Edition of Binary Ninja.

		\ingroup firmwareninja
	*/
	class FirmwareNinja
	{
		Ref<BinaryView> m_view;
		BNFirmwareNinja* m_object;

	public:
		FirmwareNinja(Ref<BinaryView> view);
		~FirmwareNinja();

		/*! Store a user-defined Firmware Ninja device to the binary view metadata

			\param device Hardware device information
			\return true on success, false otherwise
		 */
		bool StoreCustomDevice(FirmwareNinjaDevice& device);

		/*! Remove a user-defined Firmware Ninja device from the binary view metadata

			\param name Name of the device to remove
			\return true on success, false otherwise
		 */
		bool RemoveCustomDevice(const std::string& name);

		/*! Query all user-defined Firmware Ninja devices from the binary view metadata

			\return Vector of user-defined Firmware Ninja devices
		 */
		std::vector<FirmwareNinjaDevice> QueryCustomDevices();

		/*! Query names of all boards that are compatable with the current binary view and contain bundled device
			definitions

			\return Vector of board names
		 */
		std::vector<std::string> QueryBoardNames();

		/*! Query Firmware Ninja device definitions for the specified board

			\param board Name of the board to query devices for
			\return Vector of Firmware Ninja device definitions
		 */
		std::vector<FirmwareNinjaDevice> QueryDevicesForBoard(const std::string& board);

		/*! Find sections in the binary with Firmware Ninja heuristics and entropy analysis

			\param board highCodeEntropyThreshold High threshold for code entropy value range
			\param board lowCodeEntropyThreshold Low threshold for code entropy value range
			\param blockSize Size of blocks to analyze
			\param mode Analysis mode of operation
			\return Vector of Firmware Ninja section information
		 */
		std::vector<BNFirmwareNinjaSection> FindSections(float highCodeEntropyThreshold, float lowCodeEntropyThreshold,
			size_t blockSize, BNFirmwareNinjaSectionAnalysisMode mode);

		/*! Find functions that access memory-mapped I/O and other non-file backed memory regions

			\param progress Progress callback function
			\param progressContext Progress context
			\return Vector of Firmware Ninja function memory accesses information
		 */
		std::vector<FirmwareNinjaFunctionMemoryAccesses> GetFunctionMemoryAccesses(BNProgressFunction progress,
			void* progressContext);

		/*! Store Firmware Ninja function memory accesses information in the binary view metadata

			\param fma Vector of Firmware Ninja function memory accesses information
		 */
		void StoreFunctionMemoryAccesses(const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma);

		/*! Query cached Firmware Ninja function memory accesses information from the binary view metadata

			\return Vector of Firmware Ninja memory analyis information
		 */
		std::vector<FirmwareNinjaFunctionMemoryAccesses> QueryFunctionMemoryAccesses();

		/*! Compute number of accesses mad to memory-mapped hardware devices for each board that is compatible with the
			current architecture

			\param fma Vector of Firmware Ninja function memory accesses information
			\return Vector of Firmware Ninja device accesses information for each board
		 */
		std::vector<FirmwareNinjaDeviceAccesses> GetBoardDeviceAccesses(
			const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma);
	};


	/*!
		\ingroup demangler
	*/
	class Demangler: public StaticCoreRefCountObject<BNDemangler>
	{
		std::string m_nameForRegister;

	protected:
		explicit Demangler(const std::string& name);
		Demangler(BNDemangler* demangler);
		virtual ~Demangler() = default;

		static bool IsMangledStringCallback(void* ctxt, const char* name);
		static bool DemangleCallback(void* ctxt, BNArchitecture* arch, const char* name, BNType** outType,
			BNQualifiedName* outVarName, BNBinaryView* view);
		static void FreeVarNameCallback(void* ctxt, BNQualifiedName* name);

	public:
		/*! Register a custom Demangler. Newly registered demanglers will get priority over
			previously registered demanglers and built-in demanglers.
		 */
		static void Register(Demangler* demangler);

		/*! Get the list of currently registered demanglers, sorted by lowest to highest priority.

			\return List of demanglers
		 */
		static std::vector<Ref<Demangler>> GetList();
		static Ref<Demangler> GetByName(const std::string& name);

		/*! Promote a demangler to the highest-priority position.

			\param demangler Demangler to promote
		 */
		static void Promote(Ref<Demangler> demangler);

		std::string GetName() const;

		/*! Determine if a given name is mangled and this demangler can process it

			The most recently registered demangler that claims a name is a mangled string
			(returns true from this function), and then returns a value from Demangle will
			determine the result of a call to DemangleGeneric. Returning True from this
			does not require the demangler to succeed the call to Demangle, but simply
			implies that it may succeed.

			\param name Raw mangled name string
			\return True if the demangler thinks it can handle the name
		 */
		virtual bool IsMangledString(const std::string& name) = 0;

		/*! Demangle a raw name into a Type and QualifiedName.

			Any unresolved named types referenced by the resulting Type will be created as
			empty structures or void typedefs in the view, if the result is used on
			a data structure in the view. Given this, the call to Demangle should NOT
			cause any side-effects creating types in the view trying to resolve this
			and instead just return a type with unresolved named type references.

			The most recently registered demangler that claims a name is a mangled string
			(returns true from IsMangledString), and then returns a value from
			this function will determine the result of a call to DemangleGeneric.
			If this call returns None, the next most recently used demangler(s) will be tried instead.

			If the mangled name has no type information, but a name is still possible to extract,
			this function may return a successful result with outType=nullptr, which will be accepted.

			\param arch Architecture for context in which the name exists, eg for pointer sizes
			\param name Raw mangled name
			\param outType Resulting type, if one can be deduced, will be written here. Otherwise nullptr will be written
			\param outVarName Resulting variable name
			\param view (Optional) BinaryView context in which the name exists, eg for type lookup
			\return True if demangling was successful and results were stored into out-parameters
		 */
		virtual bool Demangle(Ref<Architecture> arch, const std::string& name, Ref<Type>& outType,
			QualifiedName& outVarName, Ref<BinaryView> view = nullptr) = 0;
	};

	/*!
		\ingroup demangler
	*/
	class CoreDemangler: public Demangler
	{
	public:
		CoreDemangler(BNDemangler* demangler);
		virtual ~CoreDemangler() = default;

		virtual bool IsMangledString(const std::string& name);
		virtual bool Demangle(Ref<Architecture> arch, const std::string& name, Ref<Type>& outType,
			QualifiedName& outVarName, Ref<BinaryView> view);
	};

	namespace Unicode
	{
		std::string UTF16ToUTF8(const uint8_t* utf16, const size_t len);
		std::string UTF32ToUTF8(const uint8_t* utf32);
		bool GetBlockRange(const std::string& name, std::pair<uint32_t, uint32_t>& range);
		std::vector<std::vector<std::pair<uint32_t, uint32_t>>> GetBlocksForNames(const std::vector<std::string>& names);
		std::vector<std::string> GetBlockNames();
		std::map<std::string, std::pair<uint32_t, uint32_t>> GetBlockRanges();
		std::string GetUTF8String(
			const std::vector<std::vector<std::pair<uint32_t, uint32_t>>>& unicodeBlocks,
			const uint8_t* data,
			const size_t offset,
			const size_t dataLen
		);
		std::string ToEscapedString(
			const std::vector<std::vector<std::pair<uint32_t, uint32_t>>>& unicodeBlocks,
			bool utf8Enabled,
			const void* data,
			const size_t dataLen
		);
	} // namespace Unicode

	/*! HighLevelILTokenEmitter contains methods for emitting text tokens for High Level IL instructions.
	    Methods are provided for typical patterns found in various high level languages.

	    This class cannot be instantiated directly. An instance of the class will be provided when the methods
	    in LanguageRepresentationFunction are called.

	    \ingroup highlevelil
	*/
	class HighLevelILTokenEmitter:
		public CoreRefCountObject<BNHighLevelILTokenEmitter, BNNewHighLevelILTokenEmitterReference, BNFreeHighLevelILTokenEmitter>
	{
	public:
		HighLevelILTokenEmitter(BNHighLevelILTokenEmitter* emitter);

		class CurrentExprGuard
		{
			HighLevelILTokenEmitter* m_parent;
			BNTokenEmitterExpr m_expr;

			CurrentExprGuard(const CurrentExprGuard&) = delete;
			CurrentExprGuard& operator=(const CurrentExprGuard&) = delete;

		public:
			CurrentExprGuard(HighLevelILTokenEmitter& parent, const BNTokenEmitterExpr& expr);
			~CurrentExprGuard();
		};

		/*! Appends a token to the output. */
		template <typename... Args>
		void Append(Args&&... args)
		{
			InstructionTextToken token(std::forward<Args>(args)...);
			BNInstructionTextToken converted;
			InstructionTextToken::ConvertInstructionTextToken(token, &converted);
			BNHighLevelILTokenEmitterAppend(m_object, &converted);
			InstructionTextToken::FreeInstructionTextToken(&converted);
		}

		void PrependCollapseIndicator();
		void PrependCollapseIndicator(Ref<Function> function, const HighLevelILInstruction& instr, uint64_t designator = 0);
		void PrependCollapseIndicator(BNInstructionTextTokenContext context, uint64_t hash);
		bool HasCollapsableRegions();
		void SetHasCollapsableRegions(bool state);

		/*! Starts a new line in the output. */
		void InitLine();

		/*! Starts a new line in the output. */
		void NewLine();

		/*! Increases the indentation level by one. */
		void IncreaseIndent();

		/*! Decreases the indentation level by one. */
		void DecreaseIndent();

		/*! Indicates that visual separation of scopes is desirable at the current position. By default,
		    this will insert a blank line, but this can be configured by the user.
		*/
		void ScopeSeparator();

		/*! Begins a new scope. Insertion of newlines and braces will be handled using the current settings.

		    \param scopeType Type of scope to be started.
		*/
		void BeginScope(BNScopeType scopeType);

		/*! Ends the current scope.

		    \param scopeType Type of scope passed to BeginScope.
		*/
		void EndScope(BNScopeType scopeType);

		/*! Continues the previous scope with a new associated scope. This is most commonly used for else statements.

		    \param forceSameLine If true, the continuation will always be placed on the same line as the previous scope.
		*/
		void ScopeContinuation(bool forceSameLine);

		/*! Finalizes the previous scope, indicating that there are no more associated scopes. */
		void FinalizeScope();

		/*! Forces there to be no indentation for the next line. */
		void NoIndentForThisLine();

		/*! Begins a region of tokens that always have zero confidence. */
		void BeginForceZeroConfidence();

		/*! Ends a region of tokens that always have zero confidence. */
		void EndForceZeroConfidence();

		/*! Sets the current expression. When the returned guard object goes out of scope, the previously set
		    expression becomes active again.

		    \param expr Expression to set as the current expression.
		    \return Guard object to manage the current expression.
		*/
		CurrentExprGuard SetCurrentExpr(const HighLevelILInstruction& expr);

		/*! Finalizes the outputted lines. */
		void Finalize();

		void AppendOpenParen();     // (
		void AppendCloseParen();    // )
		void AppendOpenBracket();   // [
		void AppendCloseBracket();  // ]
		void AppendOpenBrace();     // {
		void AppendCloseBrace();    // }
		void AppendSemicolon();

		/*! Returns the list of tokens on the current line */
		std::vector<InstructionTextToken> GetCurrentTokens() const;

		/*! Sets the requirement for insertion of braces around scopes in the output. */
		void SetBraceRequirement(BNBraceRequirement required);

		/*! Sets whether cases within switch statements should always have braces around them. */
		void SetBracesAroundSwitchCases(bool braces);

		/*! Sets whether braces should default to being on the same line as the statement that begins the scope.
		    If the user has explicitly set a preference, this setting will be ignored and the user's preference
		    will be used instead.
		*/
		void SetDefaultBracesOnSameLine(bool sameLine);

		/*! Sets whether omitting braces around single-line scopes is allowed. */
		void SetSimpleScopeAllowed(bool allowed);

		BNBraceRequirement GetBraceRequirement() const;
		bool HasBracesAroundSwitchCases() const;
		bool GetDefaultBracesOnSameLine() const;
		bool IsSimpleScopeAllowed() const;

		/*! Gets the list of lines in the output. */
		std::vector<DisassemblyTextLine> GetLines() const;

		/*! Appends a size token for the given size in the High Level IL syntax.

		    \param size Size in bytes.
		    \param type Token type to append.
		*/
		void AppendSizeToken(size_t size, BNInstructionTextTokenType type);

		/*! Appends a floating point size token for the given size in the High Level IL syntax.

		    \param size Size in bytes.
		    \param type Token type to append.
		*/
		void AppendFloatSizeToken(size_t size, BNInstructionTextTokenType type);

		/*! Appends tokens for access to a variable.

		    \param var Variable to access.
		    \param instr Instruction that accesses the variable.
		    \param size Size in bytes.
		*/
		void AppendVarTextToken(const Variable& var, const HighLevelILInstruction& instr, size_t size);

		/*! Appends tokens for a constant intenger value.

		    \param instr Instruction that references the value.
		    \param val Integer value.
		    \param size Size in bytes.
		*/
		void AppendIntegerTextToken(const HighLevelILInstruction& instr, int64_t val, size_t size);

		/*! Appends tokens for accessing an array by constant index.

		    \param instr Instruction that accesses the array.
		    \param val Index value.
		    \param size Size in bytes.
		    \param address Optional address override.
		*/
		void AppendArrayIndexToken(const HighLevelILInstruction& instr, int64_t val, size_t size, uint64_t address = 0);

		/*! Appends tokens for displaying a constant pointer value.

		    \param instr Instruction that references the pointer.
		    \param val Pointer value.
		    \param settings Settings for disassembly (may be NULL).
		    \param symbolDisplay Symbol display type.
		    \param precedence Current operator precedence level.
		    \param allowShortString If true, show as a string even if it is short.
		    \return Type of symbol resolved if any.
		*/
		BNSymbolDisplayResult AppendPointerTextToken(const HighLevelILInstruction& instr, int64_t val,
			DisassemblySettings* settings, BNSymbolDisplayType symbolDisplay, BNOperatorPrecedence precedence,
			bool allowShortString = false);

		/*! Appends tokens for a constant value.

		    \param instr Instruction that references the value.
		    \param val Constant value.
		    \param size Size in bytes.
		    \param settings Settings for disassembly (may be NULL).
		    \param precedence Current operator precedence level.
		*/
		void AppendConstantTextToken(const HighLevelILInstruction& instr, int64_t val, size_t size,
			DisassemblySettings* settings, BNOperatorPrecedence precedence);

		/*! Prepends the list of names for the outer structure members when accessing a structure member. This list
		    can be passed as the list of type names in tokens.

		    \param data Binary view associated with the type.
		    \param type Structure Type being accessed.
		    \param var Structure variable.
		    \param nameList Existing list of member names. This list will be updated with the outer structure member
		   names.
		*/
		static void AddNamesForOuterStructureMembers(
			BinaryView* data, Type* type, const HighLevelILInstruction& var, std::vector<std::string>& nameList);
	};
}  // namespace BinaryNinja


namespace BinaryNinja::Http
{
	struct Request;
	struct Response;
}

namespace BinaryNinja::Collaboration
{

	class AnalysisMergeConflict;
	class TypeArchiveMergeConflict;
	class CollabChangeset;

	struct DatabaseConflictHandlerContext
	{
		std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>)> callback;
	};

	struct TypeArchiveConflictHandlerContext
	{
		std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>)> callback;
	};

	struct NameChangesetContext
	{
		std::function<bool(Ref<CollabChangeset>)> callback;
	};

	bool DatabaseConflictHandlerCallback(void* ctxt, const char** keys, BNAnalysisMergeConflict** conflicts, size_t count);
	bool TypeArchiveConflictHandlerCallback(void* ctxt, BNTypeArchiveMergeConflict** conflicts, size_t count);
	bool NameChangesetCallback(void* ctxt, BNCollaborationChangeset* changeset);


	class Remote;
	class RemoteProject;

	struct SyncException : ExceptionWithStackTrace
	{
		SyncException(const std::string& desc) : ExceptionWithStackTrace(desc.c_str()) {}
	};

	/*!

		\ingroup collaboration
	*/
	struct RemoteException : std::runtime_error
	{
		RemoteException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

	/*!
		\ingroup collaboration
	*/
	class CollabUser : public CoreRefCountObject<BNCollaborationUser, BNNewCollaborationUserReference, BNFreeCollaborationUser>
	{
	public:
		CollabUser(BNCollaborationUser* collabUser);

		Ref<Remote> GetRemote();
		std::string GetUrl();
		std::string GetId();
		std::string GetUsername();
		std::string GetEmail();
		std::string GetLastLogin();
		bool IsActive();

		void SetUsername(const std::string& username);
		void SetEmail(const std::string& email);
		void SetIsActive(bool isActive);
	};

	/*!
		\ingroup collaboration
	*/
	class CollabGroup : public CoreRefCountObject<BNCollaborationGroup, BNNewCollaborationGroupReference, BNFreeCollaborationGroup>
	{
	public:
		CollabGroup(BNCollaborationGroup* group);

		uint64_t GetId();
		std::string GetName();
		void SetName(const std::string& name);
		void SetUsernames(const std::vector<std::string>& usernames);
		bool ContainsUser(const std::string& username);

	};

	/*!
		\ingroup collaboration
	*/
	class Remote : public CoreRefCountObject<BNRemote, BNNewRemoteReference, BNFreeRemote>
	{
	public:
		Remote(BNRemote* remote);

		std::string GetUniqueId();
		std::string GetName();
		std::string GetAddress();
		bool HasLoadedMetadata();
		bool IsConnected();
		std::string GetUsername();
		std::string GetToken();
		int GetServerVersion();
		std::string GetServerBuildId();
		std::vector<std::pair<std::string, std::string>> GetAuthBackends();
		bool HasPulledProjects();
		bool HasPulledUsers();
		bool HasPulledGroups();
		bool IsAdmin();

		/*!
			Determine if a remote is the same as the currently connected Enterprise Server
			On non-Enterprise clients, this always returns false.
			\return True if the remote is the same
		*/
		bool IsEnterprise();


		/*!
			Load remote metadata, including version, id, and auth backends
			\throws RemoteException If there is an error in any request, or if the remote version is not supported
		*/
		bool LoadMetadata();


		/*!
			Request an authentication token for a user given a username and password
			\param username CollabUser's username
			\param password CollabUser's password
			\return Authentication token
			\throws RemoteException If there is an error in any request
		*/
		std::string RequestAuthenticationToken(const std::string& username, const std::string& password);


		/*!
			Establish a connection to the remote, using a username and token
			\param username CollabUser's username
			\param token CollabUser's authentication token
			\throws RemoteException If there is an error in any request
		*/
		void Connect(const std::string& username, const std::string& token);


		/*!
			Disconnect from the remote
		*/
		void Disconnect();

		/*!
			Get all projects in the Remote
			\return All projects
			\throws RemoteException if projects have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<RemoteProject>> GetProjects();


		/*!
			Get a project in the remote by its id
			\param id Project's id
			\return Project, or null shared_ptr if not found
			\throws RemoteException If projects have not been pulled or if the remote is not connected
		*/
		Ref<RemoteProject> GetProjectById(const std::string& id);


		/*!
			Get a project in the remote by its name
			\param name Project's name
			\return Project, or null shared_ptr if not found
			\throws RemoteException If projects have not been pulled or if the remote is not connected
		*/
		Ref<RemoteProject> GetProjectByName(const std::string& name);


		/*!
			Pull list of projects from the remote. Necessary before calling GetProjects()
			\param progress Function to call on progress updates
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PullProjects(std::function<bool(size_t, size_t)> progress = {});


		/*!
			Create a new project on the remote (and pull it)
			\param name Project name
			\param description Project description
			\return Reference to the created project
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<RemoteProject> CreateProject(const std::string& name, const std::string& description);


		/*!
			Create a new project on the remote from a local project
			\param localProject The local project that should be copied to the server
			\param progress Function to call on progress updates
			\return Reference to the created project
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<RemoteProject> ImportLocalProject(Ref<Project> localProject, std::function<bool(size_t, size_t)> progress = {});


		/*!
			Push fields of a modified project to the remote
			\param project Updated project
			\param extraFields Extra post fields for the request
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PushProject(Ref<RemoteProject> project, const std::vector<std::pair<std::string, std::string>>& extraFields = {});


		/*!
			Delete a project from the remote
			\param project Pointer to project to delete (will invalidate pointer)
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void DeleteProject(const Ref<RemoteProject> project);

		/*!
			Get all groups in the Project
			\return All groups
			\throws RemoteException if groups have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<CollabGroup>> GetGroups();


		/*!
			Get a group in the project by its id
			\param id Group's id
			\return Group, or null shared_ptr if not found
			\throws RemoteException If groups have not been pulled or if the remote is not connected
		*/
		Ref<CollabGroup> GetGroupById(uint64_t id);


		/*!
			Get a group in the project by its name. Will check for both name and <project id>/name
			\param name Group's name
			\return Group, or null shared_ptr if not found
			\throws RemoteException If groups have not been pulled or if the remote is not connected
		*/
		Ref<CollabGroup> GetGroupByName(const std::string& name);


		/*!
			Search groups on the remote
			\param prefix Prefix to search for
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		std::vector<std::pair<uint64_t, std::string>> SearchGroups(const std::string& prefix);


		/*!
			Pull list of groups from the remote. Necessary before calling GetGroups()
			\param progress Function to call on progress updates
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PullGroups(std::function<bool(size_t, size_t)> progress = {});


		/*!
			Create a new group on the remote (and pull it)
			\param name Group name
			\return Reference to the created group
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<CollabGroup> CreateGroup(const std::string& name, const std::vector<std::string>& usernames);


		/*!
			Push fields of a modified group to the remote
			\param group Updated group
			\param extraFields Extra post fields for the request
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PushGroup(Ref<CollabGroup> group, const std::vector<std::pair<std::string, std::string>>& extraFields = {});


		/*!
			Delete a group from the remote
			\param group Pointer to group to delete (will invalidate pointer)
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void DeleteGroup(const Ref<CollabGroup> group);


		/*!
			Get all users in the Remote
			\return All users
			\throws RemoteException if users have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<CollabUser>> GetUsers();


		/*!
			Get a user in the remote by their id
			\param id CollabUser's id
			\return CollabUser, or null shared_ptr if not found
			\throws RemoteException If users have not been pulled or if the remote is not connected
		*/
		Ref<CollabUser> GetUserById(const std::string& id);


		/*!
			Get a user in the remote by their username
			\param username CollabUser's username
			\return CollabUser, or null shared_ptr if not found
			\throws RemoteException If users have not been pulled or if the remote is not connected
		*/
		Ref<CollabUser> GetUserByUsername(const std::string& username);


		/*!
			Get the currently logged-in user's CollabUser object
			\return The current user's CollabUser, or null shared_ptr if not found
			\throws RemoteException if users have not been pulled or if the remote is not connected
		*/
		Ref<CollabUser> GetCurrentUser();


		/*!
			Search users on the remote
			\param prefix Prefix to search for
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		std::vector<std::pair<std::string, std::string>> SearchUsers(const std::string& prefix);


		/*!
			Pull list of users from the remote. Necessary before calling GetUsers()
			\param progress Function to call on progress updates
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PullUsers(std::function<bool(size_t, size_t)> progress = {});


		/*!
			Create a new user on the remote (and pull it)
			\param name CollabUser name
			\param email CollabUser email
			\param is_active If the user should initially be active
			\param password CollabUser password
			\param groupIds List of group ids the user will be added to
			\param userPermissionIds List of permission ids the user will be granted
			\return Reference to the created user
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<CollabUser> CreateUser(const std::string& username, const std::string& email, bool is_active,
			const std::string& password, const std::vector<uint64_t>& groupIds,
			const std::vector<uint64_t>& userPermissionIds);

		/*!
			Push fields of a modified user to the remote
			\param user Updated user
			\param extraFields Extra post fields for the request (eg password)
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PushUser(Ref<CollabUser> user, const std::vector<std::pair<std::string, std::string>>& extraFields = {});

		/*!
			Perform an arbitrary HTTP request. An "Authorization: Token <token>" header will be added
			with the Remote's token for the current login session.
			\param request Request structure with headers and content.
			\param response Response structure with body
			\return Zero or greater on success
		*/
		int Request(Http::Request request, Http::Response& ret);
	};

	/*!
		\ingroup collaboration
	*/
	class RemoteFolder : public CoreRefCountObject<BNRemoteFolder, BNNewRemoteFolderReference, BNFreeRemoteFolder>
	{
	public:
		RemoteFolder(BNRemoteFolder* remoteFolder);

		Ref<ProjectFolder> GetCoreFolder();
		Ref<RemoteProject> GetProject();
		Ref<RemoteFolder> GetParent();
		Ref<Remote> GetRemote();
		std::string GetId();
		std::string GetUrl();
		std::string GetName();
		std::string GetDescription();
	};

	class RemoteFile;

	class CollabUndoEntry : public CoreRefCountObject<BNCollaborationUndoEntry, BNNewCollaborationUndoEntryReference, BNFreeCollaborationUndoEntry>
	{
	public:
		CollabUndoEntry(BNCollaborationUndoEntry* entry);

	};

	class CollabSnapshot : public CoreRefCountObject<BNCollaborationSnapshot, BNNewCollaborationSnapshotReference, BNFreeCollaborationSnapshot>
	{
	public:
		CollabSnapshot(BNCollaborationSnapshot* snapshot);

		Ref<RemoteFile> GetFile();
		Ref<RemoteProject> GetProject();
		Ref<Remote> GetRemote();
		std::string GetUrl();
		std::string GetId();
		std::string GetName();
		std::string GetAuthor();
		int64_t GetCreated();
		int64_t GetLastModified();
		std::string GetHash();
		std::string GetSnapshotFileHash();
		bool HasPulledUndoEntries();
		bool IsFinalized();
		std::vector<std::string> GetParentIds();
		std::vector<std::string> GetChildIds();
		uint64_t GetAnalysisCacheBuildId();

		/*!
		    Get the title of a snapshot: the first line of its name
		    \return CollabSnapshot title as described
		 */
		std::string GetTitle();

		/*!
		    Get the description of a snapshot: the lines of its name after the first line
		    \return CollabSnapshot description as described
		 */
		std::string GetDescription();

		/*!
		    Get the username of the author of a snapshot, if possible (vs GetAuthor() which is user id)
		    \return CollabSnapshot author username
		 */
		std::string GetAuthorUsername();

		/*!
		    Get all snapshots in this snapshot's file that are parents of this snapshot
		    \return List of parent snapshots
		    \throws RemoteException If a parent snapshot does not exist in the file or if the remote is not connected
		 */
		std::vector<Ref<CollabSnapshot>> GetParents();

		/*!
		    Get all snapshots in this snapshot's file that are children of this snapshot
		    \return List of child snapshots
		    \throws RemoteException If a child snapshot does not exist in the file or if the remote is not connected
		 */
		std::vector<Ref<CollabSnapshot>> GetChildren();

		/*!
		    Get all undo entries in the snapshot
		    \return All undo entries
		    \throws RemoteException if undo entries have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<CollabUndoEntry>> GetUndoEntries();

		/*!
		    Get a undo entry in the snapshot by its id
		    \param id Undo entry's id
		    \return Undo entry, or null shared_ptr if not found
		    \throws RemoteException If undo entries have not been pulled or if the remote is not connected
		 */
		Ref<CollabUndoEntry> GetUndoEntryById(uint64_t id);

		/*!
		    Pull list of undo entries from the remote. Necessary before calling GetUndoEntries()
		    \param progress Function to call on progress updates
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		void PullUndoEntries(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Create a new undo entry on the remote (and pull it)
		    \param parent Undo entry parent id (if exists)
		    \param data Undo entry data
		    \return Reference to the created undo entry
		    \throws RemoteException If there is an error in any request, or if the snapshot is finalized,
		                            or if the remote is not connected
		 */
		Ref<CollabUndoEntry> CreateUndoEntry(std::optional<uint64_t> parent, std::string data);

		/*!
		    Mark the snapshot as Finalized, preventing future modification and allowing child snapshots
		    This change is pushed instantly (calls the finalize endpoint)
		    \throws RemoteException if there is an error in any request or if the remote is not connected
		 */
		void Finalize();

		/*!
		    Download the contents of the file backing a snapshot
		    N.B. Multiple snapshots can be backed by the same file
		    \param progress Function to call on progress updates
		    \return Contents of the file at the point of the snapshot
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> DownloadSnapshotFile(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Download the contents of the snapshot
		    \param progress Function to call on progress updates
		    \return Contents of the snapshot
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> Download(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Download the contents of the analysis cache for this snapshot, returns an empty vector if there is no cache (eg: old snapshots)
		    \param progress Function to call on progress updates
		    \return Contents of the analysis cache
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> DownloadAnalysisCache(std::function<bool(size_t, size_t)> progress = {});
	};

	/*!
		\ingroup collaboration
	*/
	class RemoteFile : public CoreRefCountObject<BNRemoteFile, BNNewRemoteFileReference, BNFreeRemoteFile>
	{
	public:
		RemoteFile(BNRemoteFile* remoteFile);

		Ref<ProjectFile> GetCoreFile();
		Ref<RemoteProject> GetProject();
		Ref<RemoteFolder> GetFolder();
		Ref<Remote> GetRemote();
		std::string GetUrl();
		std::string GetChatLogUrl();
		std::string GetUserPositionsUrl();
		std::string GetId();
		BNRemoteFileType GetType();
		int64_t GetCreated();
		std::string GetCreatedBy();
		int64_t GetLastModified();
		int64_t GetLastSnapshot();
		std::string GetLastSnapshotBy();
		std::string GetLastSnapshotName();
		std::string GetHash();
		std::string GetName();
		std::string GetDescription();
		std::string GetMetadata();
		uint64_t GetSize();
		bool HasPulledSnapshots();

		void SetName(const std::string& name);
		void SetDescription(const std::string& description);
		void SetFolder(const Ref<RemoteFolder>& folder);
		void SetMetadata(const std::string& metadata);

		/*!
		    Get all snapshots in the file
		    \return All snapshops
		    \throws RemoteException if snapshots have not been pulled or if the remote is not connected
		 */
		std::vector<Ref<CollabSnapshot>> GetSnapshots();

		/*!
		    Get a snapshot in the file by its id
		    \param id CollabSnapshot's id
		    \return CollabSnapshot, or nullptr
		    \throws RemoteException If snapshots have not been pulled or if the remote is not connected
		 */
		Ref<CollabSnapshot> GetSnapshotById(const std::string& id);

		/*!
		    Pull list of snapshots from the remote. Necessary before calling GetSnapshots()
		    \param progress Function to call on progress updates
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		void PullSnapshots(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Create a new snapshot on the remote (and pull it)
		    \param name CollabSnapshot name
		    \param parentIds List of ids of parent snapshots (or empty if this is a root snapshot)
		    \param contents CollabSnapshot contents
		    \param analysisCacheContents Analysis cache contents
		    \param fileContents New file contents (if contents changed)
		    \param progress Function to call on progress updates
		    \return Reference to the created snapshot
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		Ref<CollabSnapshot> CreateSnapshot(
			std::string name,
			std::vector<uint8_t> contents,
			std::vector<uint8_t> analysisCacheContents,
			std::optional<std::vector<uint8_t>> fileContents,
			std::vector<std::string> parentIds,
			std::function<bool(size_t, size_t)> progress = {}
		);

		/*!
		    Delete a snapshot from the remote
		    \param snapshot Pointer to snapshot to delete (will invalidate pointer)
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		void DeleteSnapshot(const Ref<CollabSnapshot> snapshot);

		/*!
		    Download the contents of a remote file
		    \param progress Function to call on progress updates
		    \return Contents of the file
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> Download(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Get the current user positions for this file
		    \return User positions as json
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		Json::Value RequestUserPositions();

		/*!
		    Get the current chat log for this file
		    \return Chat log as json
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		Json::Value RequestChatLog();
	};

	/*!
		\ingroup collaboration
	*/
	class CollabPermission : public CoreRefCountObject<BNCollaborationPermission, BNNewCollaborationPermissionReference, BNFreeCollaborationPermission>
	{
	public:
		CollabPermission(BNCollaborationPermission* permission);

		Ref<RemoteProject> GetProject();
		Ref<Remote> GetRemote();
		std::string GetId();
		std::string GetUrl();
		uint64_t GetGroupId();
		std::string GetGroupName();
		std::string GetUserId();
		std::string GetUsername();
		BNCollaborationPermissionLevel GetLevel();
		void SetLevel(BNCollaborationPermissionLevel level);
		bool CanView();
		bool CanEdit();
		bool CanAdmin();
	};

	/*!
		\ingroup collaboration
	*/
	class RemoteProject : public CoreRefCountObject<BNRemoteProject, BNNewRemoteProjectReference, BNFreeRemoteProject>
	{
	public:
		RemoteProject(BNRemoteProject* remoteProject);

		Ref<Project> GetCoreProject();
		bool IsOpen();
		bool Open(std::function<bool(size_t, size_t)> progress = {});
		void Close();

		Ref<Remote> GetRemote();
		std::string GetUrl();
		int64_t GetCreated();
		int64_t GetLastModified();
		std::string GetId();
		std::string GetName();
		void SetName(const std::string& name);
		std::string GetDescription();
		void SetDescription(const std::string& description);
		uint64_t GetReceivedFileCount();
		uint64_t GetReceivedFolderCount();
		bool HasPulledFiles();
		bool HasPulledGroupPermissions();
		bool HasPulledUserPermissions();
		bool IsAdmin();

		std::vector<Ref<RemoteFile>> GetFiles();
		std::vector<Ref<RemoteFolder>> GetFolders();
		Ref<RemoteFile> GetFileById(const std::string& id);
		Ref<RemoteFile> GetFileByName(const std::string& name);
		void PullFiles(std::function<bool(size_t, size_t)> progress = {});
		void PullFolders(std::function<bool(size_t, size_t)> progress = {});
		Ref<RemoteFile> CreateFile(const std::string& filename, std::vector<uint8_t>& contents, const std::string& name, const std::string& description, Ref<RemoteFolder> folder, BNRemoteFileType type, std::function<bool(size_t, size_t)> progress = {}, Ref<ProjectFile> coreFile = nullptr);
		Ref<RemoteFolder> CreateFolder(const std::string& name, const std::string& description, Ref<RemoteFolder> parent, std::function<bool(size_t, size_t)> progress = {}, Ref<ProjectFolder> coreFolder = nullptr);
		void PushFile(Ref<RemoteFile> file, const std::vector<std::pair<std::string, std::string>>& extraFields = {});
		void PushFolder(Ref<RemoteFolder> folder, const std::vector<std::pair<std::string, std::string>>& extraFields = {});
		void DeleteFolder(const Ref<RemoteFolder> folder);
		void DeleteFile(const Ref<RemoteFile> file);
		Ref<RemoteFolder> GetFolderById(const std::string& id);
		std::vector<Ref<CollabPermission>> GetGroupPermissions();
		std::vector<Ref<CollabPermission>> GetUserPermissions();
		Ref<CollabPermission> GetPermissionById(const std::string& id);
		void PullGroupPermissions(std::function<bool(size_t, size_t)> progress = {});
		void PullUserPermissions(std::function<bool(size_t, size_t)> progress = {});
		Ref<CollabPermission> CreateGroupPermission(int groupId, BNCollaborationPermissionLevel level, std::function<bool(size_t, size_t)> progress = {});
		Ref<CollabPermission> CreateUserPermission(const std::string& userId, BNCollaborationPermissionLevel level, std::function<bool(size_t, size_t)> progress = {});
		void PushPermission(Ref<CollabPermission> permission, const std::vector<std::pair<std::string, std::string>>& extraFields = {});
		void DeletePermission(Ref<CollabPermission> permission);
		bool CanUserView(const std::string& username);
		bool CanUserEdit(const std::string& username);
		bool CanUserAdmin(const std::string& username);
	};

	class AnalysisMergeConflict : public CoreRefCountObject<BNAnalysisMergeConflict, BNNewAnalysisMergeConflictReference, BNFreeAnalysisMergeConflict>
	{
	public:
		AnalysisMergeConflict(BNAnalysisMergeConflict* conflict);

		std::string GetType();
		BNMergeConflictDataType GetDataType();
		std::optional<nlohmann::json> GetBase();
		std::optional<nlohmann::json> GetFirst();
		std::optional<nlohmann::json> GetSecond();

		Ref<FileMetadata> GetBaseFile();
		Ref<FileMetadata> GetFirstFile();
		Ref<FileMetadata> GetSecondFile();

		Ref<Snapshot> GetBaseSnapshot();
		Ref<Snapshot> GetFirstSnapshot();
		Ref<Snapshot> GetSecondSnapshot();

		template<typename T> T GetPathItem(const std::string& key);

		bool Success(std::nullopt_t value);
		bool Success(std::optional<const nlohmann::json*> value);
		bool Success(const std::optional<nlohmann::json>& value);
	};

	template<> std::any AnalysisMergeConflict::GetPathItem<std::any>(const std::string& path);
	template<> std::string AnalysisMergeConflict::GetPathItem<std::string>(const std::string& path);
	template<> uint64_t AnalysisMergeConflict::GetPathItem<uint64_t>(const std::string& path);
	template<> nlohmann::json AnalysisMergeConflict::GetPathItem<nlohmann::json>(const std::string& path);

	class TypeArchiveMergeConflict : public CoreRefCountObject<BNTypeArchiveMergeConflict, BNNewTypeArchiveMergeConflictReference, BNFreeTypeArchiveMergeConflict>
	{
	public:
		TypeArchiveMergeConflict(BNTypeArchiveMergeConflict* conflict);

		Ref<TypeArchive> GetTypeArchive();
		std::string GetTypeId();
		std::string GetBaseSnapshotId();
		std::string GetFirstSnapshotId();
		std::string GetSecondSnapshotId();

		bool Success(const std::string& value);
	};

	class CollabChangeset : public CoreRefCountObject<BNCollaborationChangeset, BNNewCollaborationChangesetReference, BNFreeCollaborationChangeset>
	{
	public:
		CollabChangeset(BNCollaborationChangeset* changeset);

		Ref<Database> GetDatabase();
		Ref<RemoteFile> GetFile();
		std::vector<int64_t> GetSnapshotIds();
		Ref<CollabUser> GetAuthor();
		std::string GetName();
		void SetName(const std::string& name);
	};

	typedef std::function<bool(Ref<CollabChangeset>)> NameChangesetFunction;
	typedef std::function<bool(size_t, size_t)> ProgressFunction;
	typedef std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>& conflicts)> AnalysisConflictHandler;
	typedef std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>& conflicts)> TypeArchiveConflictHandler;

	Ref<Remote> GetActiveRemote();
	void SetActiveRemote(Ref<Remote> remote);
	bool StoreDataInKeychain(const std::string& key, const std::map<std::string, std::string>& data);
	bool HasDataInKeychain(const std::string& key);
	std::optional<std::map<std::string, std::string>> GetDataFromKeychain(const std::string& key);
	bool DeleteDataFromKeychain(const std::string& key);

	void LoadRemotes();
	std::vector<Ref<Remote>> GetRemotes();
	Ref<Remote> GetRemoteById(const std::string& remoteId);
	Ref<Remote> GetRemoteByAddress(const std::string& remoteAddress);
	Ref<Remote> GetRemoteByName(const std::string& name);
	Ref<Remote> CreateRemote(const std::string& name, const std::string& address);
	void RemoveRemote(const Ref<Remote>& remote);

	/*!
	    Completely sync a database, pushing/pulling/merging/applying changes
	    \param database Database to sync
	    \param file Remote File to sync with
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \throws SyncException If there is an error syncing
	 */
	void SyncDatabase(Ref<Database> database, Ref<RemoteFile> file, AnalysisConflictHandler conflictHandler, std::function<bool(size_t, size_t)> progress = {}, NameChangesetFunction nameChangeset = [](Ref<CollabChangeset>){ return true; });

	/*!
	    Completely sync a type archive, pushing/pulling/merging/applying changes
	    \param archive Type archive
	    \param file Remote file
	    \param progress Function to call for progress updates
	 */
	void SyncTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, TypeArchiveConflictHandler conflictHandler, ProgressFunction progress = {});

	/*!
	    Merge a pair of snapshots and create a new snapshot with the result.
	    \param first First snapshot to merge
	    \param second Second snapshot to merge
	    \param conflictHandler Function to call when merge conflicts are encountered
	    \param progress Function to call for progress updates and cancelling
	    \throws SyncException If the snapshots have no common ancestor
	    \return Result snapshot
	 */
	Ref<Snapshot> MergeSnapshots(Ref<Snapshot> first, Ref<Snapshot> second, AnalysisConflictHandler conflictHandler, ProgressFunction progress);

	/*!
	    Get the default directory path for a remote Project. This is based off the Setting for
	    collaboration.directory, the project's id, and the project's remote's id.
	    \param project Remote Project
	    \return Default project path
	 */
	std::string DefaultProjectPath(Ref<RemoteProject> project);

	/*!
	    Get the default filepath for a remote File. This is based off the Setting for
	    collaboration.directory, the file's id, the file's project's id, and the file's
	    remote's id.
	    \param file Remote File
	    \return Default file path
	 */
	std::string DefaultFilePath(Ref<RemoteFile> file);

		/*!
	    Download a file from its remote, saving all snapshots to a database in the
	    specified location. Returns a FileContext for opening the file later.
	    \param file Remote File to download and open
	    \param dbPath File path for saved database
	    \param progress Function to call for progress updates
	    \return FileContext for opening
	    \throws SyncException If there was an error downloading
	 */
	Ref<FileMetadata> DownloadFile(Ref<RemoteFile> file, const std::string& dbPath, ProgressFunction progress = {});

	/*!
	    Add a snapshot to the id map in a database
	    \param localSnapshot Local snapshot, will use this snapshot's database
	    \param remoteSnapshot Remote snapshot
	 */
	void AssignSnapshotMap(Ref<Snapshot> localSnapshot, Ref<CollabSnapshot> remoteSnapshot);

	/*!
	    Upload a file, with database, to the remote under the given project
	    \param metadata Local file with database
	    \param project Remote project under which to place the new file
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \param folderId Id of folder that will contain the resulting file
	    \return Remote File created
	    \throws SyncException If there was an error uploading
	 */
	Ref<RemoteFile> UploadDatabase(Ref<FileMetadata> metadata, Ref<RemoteProject> project, Ref<RemoteFolder> folder, ProgressFunction progress, NameChangesetFunction nameChangeset = {});

	/*!
	    Get the remote author of a local snapshot
	    \param database Parent database
	    \param snapshot Snapshot to query
	 */
	std::optional<std::string> GetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot);

	/*!
	    Test if a database is valid for use in collaboration
	    \param database Database
	    \return True if database is valid
	 */
	bool IsCollaborationDatabase(Ref<Database> database);

	/*!
	    Get the Remote for a Database
	    \param database BN database, potentially with collaboration metadata
	    \return Remote from one of the connected remotes, or nullptr if not found
	 */
	Ref<Remote> GetRemoteForLocalDatabase(Ref<Database> database);

	/*!
	    Get the Remote Project for a Database
	    \param database BN database, potentially with collaboration metadata
	    \return Remote project from one of the connected remotes, or nullptr if not found
	            or if projects are not pulled
	 */
	Ref<RemoteProject> GetRemoteProjectForLocalDatabase(Ref<Database> database);

	/*!
	    Get the Remote File for a Database
	    \param database BN database, potentially with collaboration metadata
	    \return Remote file from one of the connected remotes, or nullptr if not found
	            or if files are not pulled
	 */
	Ref<RemoteFile> GetRemoteFileForLocalDatabase(Ref<Database> database);

	/*!
	    Pull updated snapshots from the remote. Merge local changes with remote changes and
	    potentially create a new snapshot for unsaved changes, named via nameChangeset.
	    \param database Database to pull
	    \param file Remote File to pull to
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \return Number of snapshots pulled
	    \throws SyncException If there is an error pulling
	 */
	size_t PullDatabase(Ref<Database> database, Ref<RemoteFile> file, AnalysisConflictHandler conflictHandler, ProgressFunction progress = {}, NameChangesetFunction nameChangeset = {});

	/*!
	    Merge all leaf snapshots in a database down to a single leaf snapshot.
	    \param database Database to merge
	    \param progress Function to call for progress updates
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \throws SyncException If there was an error merging
	 */
	void MergeDatabase(Ref<Database> database, AnalysisConflictHandler conflictHandler, ProgressFunction progress = {});

	/*!
	    Push locally added snapshots to the remote
	    \param database Database to push
	    \param file Remote File to push to
	    \param progress Function to call for progress updates
	    \return Number of snapshots pushed
	    \throws SyncException If there is an error pushing
	 */
	size_t PushDatabase(Ref<Database> database, Ref<RemoteFile> file, ProgressFunction progress = {});

	/*!
	    Print debug information about a database to stdout
	    \param database Database to dump
	 */
	void DumpDatabase(Ref<Database> database);

	/*!
	    Ignore a snapshot from database syncing operations
	    TODO: This is in place of deleting differential snapshots (which is unimplemented)
	    \param database Parent database
	    \param snapshot Snapshot to ignore
	 */
	void IgnoreSnapshot(Ref<Database> database, Ref<Snapshot> snapshot);

	/*!
	    Test if a snapshot is ignored from the database
	    TODO: This is in place of deleting differential snapshots (which is unimplemented)
	    \param database Parent database
	    \param snapshot Snapshot to test
	    \return True if snapshot should be ignored
	 */
	bool IsSnapshotIgnored(Ref<Database> database, Ref<Snapshot> snapshot);

	/*!
	    Get the remote snapshot associated with a local snapshot (if it exists)
	    \param snapshot Local snapshot
	    \return Remote snapshot if it exists, or nullptr if not
	 */
	Ref<CollabSnapshot> GetRemoteSnapshotFromLocal(Ref<Snapshot> snapshot);

	/*!
	    Get the local snapshot associated with a remote snapshot (if it exists)
	    \param snapshot Remote snapshot
	    \param database Local database to search
	    \return Snapshot reference if it exists, or nullptr reference if not
	 */
	Ref<Snapshot> GetLocalSnapshotFromRemote(Ref<CollabSnapshot> snapshot, Ref<Database> database);


	/*!
	    Test if a type archive is valid for use in collaboration
	    \param archive Type archive
	    \return True if archive is valid
	 */
	bool IsCollaborationTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the Remote for a Type Archive
	    \param archive Local Type Archive, potentially with collaboration metadata
	    \return Remote from one of the connected remotes, or nullptr if not found
	 */
	Ref<Remote> GetRemoteForLocalTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the Remote Project for a Type Archive
	    \param archive Local Type Archive, potentially with collaboration metadata
	    \return Remote project from one of the connected remotes, or nullptr if not found
	            or if projects are not pulled
	 */
	Ref<RemoteProject> GetRemoteProjectForLocalTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the Remote File for a Type Archive
	    \param archive Local Type Archive, potentially with collaboration metadata
	    \return Remote file from one of the connected remotes, or nullptr if not found
	            or if files are not pulled
	 */
	Ref<RemoteFile> GetRemoteFileForLocalTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the remote snapshot associated with a local snapshot (if it exists) in a Type Archive
	    \param archive Local Type Archive
	    \param snapshotId Local snapshot id
	    \return Remote snapshot if it exists, or nullptr if not
	 */
	Ref<CollabSnapshot> GetRemoteSnapshotFromLocalTypeArchive(Ref<TypeArchive> archive, const std::string& snapshotId);


	/*!
	    Get the local snapshot associated with a remote snapshot (if it exists) in a Type Archive
	    \param snapshot Remote snapshot
	    \param archive Local type archive to search
	    \return Snapshot id if it exists, or nullopt if not
	 */
	std::optional<std::string> GetLocalSnapshotFromRemoteTypeArchive(Ref<CollabSnapshot> snapshot, Ref<TypeArchive> archive);

	/*!
	    Test if a snapshot is ignored from the archive
	    \param archive Type archive
	    \param snapshot Snapshot to test
	    \return True if snapshot should be ignored
	 */
	bool IsTypeArchiveSnapshotIgnored(Ref<TypeArchive> archive, const std::string& snapshot);

	/*!
	    Download a type archive from its remote, saving all snapshots to an archive in the
	    specified location. Returns a Ref<TypeArchive> for using later.
	    \param file Remote Type Archive file to download and open
	    \param dbPath File path for saved archive
	    \param progress Function to call for progress updates
	    \return TypeArchive for using
	    \throws SyncException If there was an error downloading
	 */
	Ref<TypeArchive> DownloadTypeArchive(Ref<RemoteFile> file, const std::string& dbPath, ProgressFunction progress = {});

	/*!
	    Upload a type archive
	    \param archive Type archive
	    \param project Containing project
	    \param folder Containing folder
	    \param progress Function to call for progress updates
	    \param coreFile Core ProjectFile structure, if archive is in a project
	    \return Created file
	 */
	Ref<RemoteFile> UploadTypeArchive(Ref<TypeArchive> archive, Ref<RemoteProject> project, Ref<RemoteFolder> folder = nullptr, ProgressFunction progress = {}, Ref<ProjectFile> coreFile = nullptr);

	/*!
	    Push locally added snapshots to the remote
	    \param archive Type Archive to push
	    \param file Remote File to push to
	    \param progress Function to call for progress updates
	    \return Number of snapshots pushed
	    \throws SyncException If there is an error pushing
	 */
	size_t PushTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, ProgressFunction progress = {});

	/*!
	    Pull updated snapshots from the remote. Merge local changes with remote changes and
	    potentially create a new snapshot for unsaved changes, named via nameChangeset.
	    \param archive Type Archive to pull
	    \param file Remote File to pull to
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \return Number of snapshots pulled
	    \throws SyncException If there is an error pulling
	 */
	size_t PullTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>)> conflictHandler, ProgressFunction progress = {});

	void DownloadDatabaseForFile(Ref<RemoteFile> file, const std::string& dbPath, bool force, ProgressFunction progress = {});

	/*!
	    Set the remote author of a local snapshot (does not upload)
	    \param database Parent database
	    \param snapshot Snapshot to edit
	    \param author Target author
	 */
	void SetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot, const std::string& author);

} // namespace BinaryNinja::Collaboration


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
		if (it != end && *it != '}') report_error("invalid format");
		return it;
	}
};
