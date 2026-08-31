
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <type_traits>
#include "base/capi.h"
#include "binaryninjacore.h"

// FFI Helpers

namespace BinaryNinja
{
	//------------------------------------------------------------------------------------
	//region string <-> char*

	char BN_API_PTR* AllocApiString(std::string_view string);
	void AllocApiString(std::string_view string, char BN_API_PTR** output);

	char BN_API_PTR* BN_API_PTR* AllocApiStringList(const char* const* stringList, size_t count);
	void AllocApiStringList(const char* const* stringList, size_t count, char BN_API_PTR* BN_API_PTR** output);

	template <bn::base::capi::StringRange R>
	char BN_API_PTR* BN_API_PTR* AllocApiStringList(const R& strings, size_t* count)
	{
		return bn::base::capi::AllocStringList(strings, count,
			[](size_t n) { return new char*[n]; }, [](std::string_view sv) { return AllocApiString(sv); });
	}

	template <bn::base::capi::StringRange R>
	void AllocApiStringList(const R& strings, char BN_API_PTR* BN_API_PTR** output, size_t* count)
	{
		*output = AllocApiStringList(strings, count);
	}

	template <bn::base::capi::StringPairRange R>
	void AllocApiStringPairList(const R& pairs, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count)
	{
		*count = bn::base::capi::AllocStringPairList(pairs, outputKeys, outputValues,
			[](size_t n) { return new char*[n]; }, [](std::string_view sv) { return AllocApiString(sv); });
	}

	std::string ParseString(const char* string);
	std::vector<std::string> ParseStringList(const char* const* stringList, size_t count);
	std::set<std::string> ParseStringSet(const char* const* stringList, size_t count);
	std::unordered_set<std::string> ParseStringUnorderedSet(const char* const* stringList, size_t count);

	std::vector<std::pair<std::string, std::string>> ParseStringPairList(const char* const* keys, const char* const* values, size_t count);
	std::map<std::string, std::string> ParseStringMap(const char* const* keys, const char* const* values, size_t count);
	std::unordered_map<std::string, std::string> ParseStringUnorderedMap(const char* const* keys, const char* const* values, size_t count);

	void FreeApiString(char BN_API_PTR* string);
	void FreeApiStringList(char BN_API_PTR* BN_API_PTR* stringList, size_t count);
	void FreeApiStringPairList(char BN_API_PTR* BN_API_PTR* keys, char BN_API_PTR* BN_API_PTR* values, size_t count);

	void FreeCoreString(char BN_CORE_PTR* string);
	void FreeCoreStringList(char BN_CORE_PTR* BN_CORE_PTR* stringList, size_t count);
	void FreeCoreStringPairList(char BN_CORE_PTR* BN_CORE_PTR* keys, char BN_CORE_PTR* BN_CORE_PTR* values, size_t count);

	//endregion

	//region Generic API Structs

	using bn::base::capi::APIStruct;
	using bn::base::capi::APIStructType;
	using bn::base::capi::AllocAPIStruct;
	using bn::base::capi::ParseAPIStruct;

	template<APIStruct T>
	void AllocAPIStructList(const std::vector<T>& objects, APIStructType<T> BN_API_PTR** output, size_t* count)
	{
		bn::base::capi::AllocAPIStructList<T>(objects, output, count);
	}

	template<APIStruct T>
	APIStructType<T> BN_API_PTR* AllocAPIStructList(const std::vector<T>& objects, size_t* count)
	{
		return bn::base::capi::AllocAPIStructList<T>(objects, count);
	}

	template<APIStruct T>
	std::vector<T> ParseAPIStructList(const APIStructType<T>* objects, size_t count)
	{
		return bn::base::capi::ParseAPIStructList<T>(objects, count);
	}

	template<APIStruct T>
	void FreeAPIStructList(APIStructType<T> BN_API_PTR* objects, size_t count)
	{
		bn::base::capi::FreeAPIStructList<T>(objects, count);
	}

	//endregion

	//------------------------------------------------------------------------------------
	//region Try/Catch Helpers

	using bn::base::capi::WrapThrowable;

	// Forward declare this, so we don't have to depend on binaryninjaapi.h
	void LogErrorForException(const std::exception& e, const char*, ...);

	/*!
		Wrap a throwable block in a try/catch, passing through the return value on success.
		Specialized for pointers, where nullptr will be returned if an exception is thrown.
		\tparam T Return type
		\tparam F Throwable block
		\param func Throwable block to execute
		\return Either the func's result or nullptr
	 */
	template<typename T, typename F>
	T WrapThrowablePointer(F&& func, typename std::enable_if<std::is_pointer<T>::value, int>::type _ = 0)
	{
		try
		{
			return func();
		}
		catch (const std::exception& e)
		{
			// TODO: How to handle this?
			// g_lastExceptionMessage = e.what();
			LogErrorForException(e, "%s", e.what());
			return nullptr;
		}
		catch (...)
		{
			return nullptr;
		}
	}

	/*!
		Wrap a throwable block in a try/catch, passing through the return value on success.
		Specialized for bool and void functions, returning false if the function throws, or
		- if the function returns a bool, passing through that value.
		- if the function returns void, returning true on completion.
		\tparam F Throwable block
		\param func Throwable block to execute
		\return Bool as described above
	 */
	template<typename F>
	bool WrapThrowableBool(F&& func)
	{
		try
		{
			if constexpr (std::is_same<typename std::invoke_result<F>::type, bool>::value)
			{
				return func();
			}
			else
			{
				func();
				return true;
			}
		}
		catch (const std::exception& e)
		{
			// TODO: How to handle this?
			// g_lastExceptionMessage = e.what();
			LogErrorForException(e, "%s", e.what());
			return false;
		}
		catch (...)
		{
			return false;
		}
	}
	//endregion
}