
#pragma once

#include <optional>
#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <type_traits>
#include "binaryninjacore.h"

// FFI Helpers

/*! Pointer is allocated by the core */
#define BN_CORE_PTR __attribute__((annotate("bn_core_ptr")))
/*! Pointer is allocated by the api */
#define BN_API_PTR __attribute__((annotate("bn_api_ptr")))

namespace BinaryNinja
{
	//------------------------------------------------------------------------------------
	//region string <-> char*

	char BN_API_PTR* AllocApiString(const char* string);
	void AllocApiString(const char* string, char BN_API_PTR** output);
	char BN_API_PTR* AllocApiString(const std::string& string);
	void AllocApiString(const std::string& string, char BN_API_PTR** output);

	char BN_API_PTR* BN_API_PTR* AllocApiStringList(const char* const* stringList, size_t count);
	void AllocApiStringList(const char* const* stringList, size_t count, char BN_API_PTR* BN_API_PTR** output);
	char BN_API_PTR* BN_API_PTR* AllocApiStringList(const std::vector<std::string>& stringList, size_t* count);
	void AllocApiStringList(const std::vector<std::string>& stringList, char BN_API_PTR* BN_API_PTR** output, size_t* count);
	char BN_API_PTR* BN_API_PTR* AllocApiStringList(const std::set<std::string>& stringList, size_t* count);
	void AllocApiStringList(const std::set<std::string>& stringList, char BN_API_PTR* BN_API_PTR** output, size_t* count);
	char BN_API_PTR* BN_API_PTR* AllocApiStringList(const std::unordered_set<std::string>& stringList, size_t* count);
	void AllocApiStringList(const std::unordered_set<std::string>& stringList, char BN_API_PTR* BN_API_PTR** output, size_t* count);

	void AllocApiStringPairList(const std::vector<std::pair<std::string, std::string>>& stringPairList, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count);
	void AllocApiStringPairList(const std::map<std::string, std::string>& stringPairList, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count);
	void AllocApiStringPairList(const std::unordered_map<std::string, std::string>& stringPairList, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count);

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

	//------------------------------------------------------------------------------------
	//region Try/Catch Helpers

	// Forward declare this, so we don't have to depend on binaryninjaapi.h
	void LogError(const char*, ...);

	/*!
		Wrap a throwable block in a try/catch, passing through the return value on success, and
		calling a catch handler and passing through its return value on an exception
		\tparam T Return type
		\tparam F Throwable block
		\tparam C Catch handler
		\param func Throwable block to execute
		\param catcher Catch handler to execute if `func` throws
		\return Either the func's result or the handler's result
	 */
	template<typename T, typename F, typename C>
	T WrapThrowable(F&& func, C&& catcher)
	{
		try
		{
			return func();
		}
		catch (...)
		{
			if constexpr (std::is_invocable<C, std::exception_ptr>::value)
			{
				return catcher(std::current_exception());
			}
			else
			{
				return catcher();
			}
		}
	}

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
			LogError("%s", e.what());
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
			LogError("%s", e.what());
			return false;
		}
		catch (...)
		{
			return false;
		}
	}
	//endregion
}