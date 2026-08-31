// Copyright (c) 2026 Vector 35 Inc
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

#include <concepts>
#include <exception>
#include <ranges>
#include <stddef.h>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

// Helpers shared by the core and API sides of the C API boundary. Container flavored
// helpers are wrapped by each side's ffi.h with its preferred container and allocator
// choices.

#ifdef __clang__
/*! Pointer is allocated by the core */
#define BN_CORE_PTR __attribute__((annotate("bn_core_ptr")))
/*! Pointer is allocated by the api */
#define BN_API_PTR __attribute__((annotate("bn_api_ptr")))
#else
#define BN_CORE_PTR
#define BN_API_PTR
#endif

namespace bn::base::capi
{
// string ranges

template <typename R>
concept StringRange = std::ranges::sized_range<R>
	&& std::convertible_to<std::ranges::range_reference_t<R>, std::string_view>;

template <typename R>
concept StringPairRange = std::ranges::sized_range<R>
	&& requires(std::ranges::range_reference_t<R> p) {
		{ p.first }  -> std::convertible_to<std::string_view>;
		{ p.second } -> std::convertible_to<std::string_view>;
	};

// list building blocks

// Fill a preallocated output array from a range, converting each element.
template <std::ranges::sized_range R, typename Out, typename Convert>
void FillList(Out* output, const R& items, Convert&& convert)
{
	size_t i = 0;
	for (auto&& item : items)
	{
		output[i] = convert(item);
		i ++;
	}
}

// Fill a freshly allocated string array from a range. AllocArray allocates the char*
// array, AllocOne converts one element.
template <StringRange R, typename AllocArray, typename AllocOne>
char** AllocStringList(const R& strings, size_t* count, AllocArray&& allocArray, AllocOne&& allocOne)
{
	*count = std::ranges::size(strings);
	char** result = allocArray(*count);
	FillList(result, strings, allocOne);
	return result;
}

template <StringPairRange R, typename AllocArray, typename AllocOne>
size_t AllocStringPairList(const R& pairs, char*** outputKeys, char*** outputValues, AllocArray&& allocArray, AllocOne&& allocOne)
{
	size_t count = std::ranges::size(pairs);
	*outputKeys = allocArray(count);
	*outputValues = allocArray(count);
	size_t i = 0;
	for (const auto& p : pairs)
	{
		(*outputKeys)[i]   = allocOne(p.first);
		(*outputValues)[i] = allocOne(p.second);
		i++;
	}
	return count;
}

// Build a container from a C array, converting each element.
template <typename Container, typename In, typename Convert>
Container ParseList(const In* items, size_t count, Convert&& convert)
{
	Container result;
	if constexpr (requires { result.reserve(count); })
		result.reserve(count);

	for (size_t i = 0; i < count; i ++)
	{
		if constexpr (requires { result.push_back(convert(items[i])); })
			result.push_back(convert(items[i]));
		else
			result.insert(convert(items[i]));
	}
	return result;
}

template <typename Container, typename In>
Container ParseList(const In* items, size_t count)
{
	return ParseList<Container>(items, count, [](const In& item) -> const In& { return item; });
}

// Build a container of pairs from parallel C arrays, converting each element.
template <typename Container, typename K, typename V, typename ConvertKey, typename ConvertValue>
Container ParsePairList(const K* keys, const V* values, size_t count, ConvertKey&& convertKey, ConvertValue&& convertValue)
{
	Container result;
	if constexpr (requires { result.reserve(count); })
		result.reserve(count);

	for (size_t i = 0; i < count; i ++)
	{
		typename Container::value_type entry {convertKey(keys[i]), convertValue(values[i])};
		if constexpr (requires { result.push_back(std::move(entry)); })
			result.push_back(std::move(entry));
		else
			result.insert(std::move(entry));
	}
	return result;
}

template <typename Container, typename K, typename V>
Container ParsePairList(const K* keys, const V* values, size_t count)
{
	return ParsePairList<Container>(keys, values, count,
		[](const K& key) -> const K& { return key; },
		[](const V& value) -> const V& { return value; });
}

// API objects

/*! Helper class to determine if a type is "API-able" aka has the following interface:

		struct Foo
		{
			BNFoo GetAPIObject() const;
			static Foo FromAPIObject(const BNFoo* obj);
			static void FreeAPIObject(BNFoo* obj);
		};

	If you get weird compiler errors around here, make sure you've implemented
	the above interface correctly (with the `const`s too!).
 */
template<
	typename T,
	// Grab the type for TAPI from the return type of GetAPIObject()
	// Store into template argument for easier lookup
	typename TAPI_ = decltype(std::declval<T>().GetAPIObject())
>
// Subtype of bool_constant to allow std::enable_if usage
struct APIAble : std::bool_constant<
	// Make sure T::FromAPIObject(const TAPI*) actually works
	std::is_invocable_v<decltype(T::FromAPIObject), const TAPI_*>
	// Make sure T::FromAPIObject(const TAPI*) returns T
	&& std::is_same_v<T, decltype(T::FromAPIObject(std::declval<const TAPI_*>()))>
	// Make sure T::FreeAPIObject(TAPI*) actually works
	&& std::is_invocable_v<decltype(T::FreeAPIObject), TAPI_*>
>
{
	// For reference by users of APIAble
	typedef TAPI_ TAPI;
};

template<typename T, typename _ = std::enable_if_t<APIAble<T>::value, void>>
void AllocAPIObject(const T& object, typename APIAble<T>::TAPI* output)
{
	*output = object.GetAPIObject();
}

template<typename T, typename _ = std::enable_if_t<APIAble<T>::value, void>>
typename APIAble<T>::TAPI AllocAPIObject(const T& object)
{
	return object.GetAPIObject();
}

template<typename T, std::ranges::sized_range R, typename _ = std::enable_if_t<APIAble<T>::value, void>>
void AllocAPIObjectList(const R& objects, typename APIAble<T>::TAPI** output, size_t* count)
{
	*count = std::ranges::size(objects);
	*output = new typename APIAble<T>::TAPI[*count];
	FillList(*output, objects, [](const T& object) { return object.GetAPIObject(); });
}

template<typename T, std::ranges::sized_range R, typename _ = std::enable_if_t<APIAble<T>::value, void>>
typename APIAble<T>::TAPI* AllocAPIObjectList(const R& objects, size_t* count)
{
	typename APIAble<T>::TAPI* result;
	bn::base::capi::AllocAPIObjectList<T>(objects, &result, count);
	return result;
}

template<typename T, typename _ = std::enable_if_t<APIAble<T>::value, void>>
T ParseAPIObject(const typename APIAble<T>::TAPI& object)
{
	return T::FromAPIObject(&object);
}

template<typename T, typename _ = std::enable_if_t<APIAble<T>::value, void>>
T ParseAPIObject(const typename APIAble<T>::TAPI* object)
{
	return T::FromAPIObject(object);
}

template<typename T, typename List = std::vector<T>, typename _ = std::enable_if_t<APIAble<T>::value, void>>
List ParseAPIObjectList(const typename APIAble<T>::TAPI* objects, size_t count)
{
	return ParseList<List>(objects, count,
		[](const typename APIAble<T>::TAPI& object) { return T::FromAPIObject(&object); });
}

template<typename T, typename _ = std::enable_if_t<APIAble<T>::value, void>>
void FreeAPIObjectList(typename APIAble<T>::TAPI* objects, size_t count)
{
	for (size_t i = 0; i <  count; i ++)
	{
		T::FreeAPIObject(&objects[i]);
	}
	delete[] objects;
}

// enums

template<typename T, std::ranges::sized_range R>
void AllocEnumList(const R& enums, T** output, size_t* count)
{
	*count = std::ranges::size(enums);
	*output = new T[*count];
	FillList(*output, enums, [](T e) { return e; });
}

template<typename T, std::ranges::sized_range R>
T* AllocEnumList(const R& enums, size_t* count)
{
	T* result;
	bn::base::capi::AllocEnumList<T>(enums, &result, count);
	return result;
}

// try/catch wrappers

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

} // namespace bn::base::capi
