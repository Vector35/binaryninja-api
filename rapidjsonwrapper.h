#pragma once
#include <exception>
#include <stdexcept>

#if defined(__GNUC__) && __GNUC__ >= 8
// Disable warnings from rapidjson performance optimizations
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif

struct GenericException;
struct ParseException;

struct GenericException : public std::exception
{
	GenericException() : std::exception() {}
	virtual const char* what() const throw() { return "Exception while parsing json."; }
};

#define RAPIDJSON_HAS_STDSTRING      0
#define RAPIDJSON_HAS_CXX11_NOEXCEPT 0
#define RAPIDJSON_ASSERT(x) \
	do \
	{ \
		if (!(x)) \
			throw GenericException(); \
	} while (0);
#define RAPIDJSON_PARSE_ERROR_NORETURN(parseErrorCode, offset) \
	throw ParseException(parseErrorCode, #parseErrorCode, offset)

#include "rapidjson/error/error.h"
struct ParseException : public std::runtime_error, public rapidjson::ParseResult
{
	ParseException(rapidjson::ParseErrorCode code, const char* msg, size_t offset) :
	    std::runtime_error(msg), ParseResult(code, offset)
	{}
};

#include "rapidjson/error/en.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"



inline size_t combine(size_t seed, size_t h) noexcept
{
	seed ^= h + 0x9e3779b9 + (seed << 6U) + (seed >> 2U);
	return seed;
}


inline size_t HashBytes(const void* const ptr, const size_t len)
{
	// Taken from https://stackoverflow.com/questions/34597260/stdhash-value-on-char-value-and-not-on-memory-address
	const char* cdata = static_cast<const char *>(ptr);
	uint64_t acc = 0;
	for (rapidjson::SizeType i = 0; i < len; ++i)
	{
		const size_t next = cdata[i];
		acc = (acc ^ next) * 1099511628211;
	}
	return acc;
}


static inline uint64_t HashRapidValue(const rapidjson::Value& val)
{
	const auto type = static_cast<std::size_t>(val.GetType());
	switch (val.GetType())
	{
		case rapidjson::kNullType:
		case rapidjson::kFalseType:
		{
			return combine(type, 0);
		}
		case rapidjson::kObjectType:
		{
			auto seed = combine(type, val.MemberCount());
			for (const auto& element : val.GetObj())
			{
				const auto h = HashBytes(element.name.GetString(), element.name.GetStringLength());
				seed = combine(seed, h);
				seed = combine(seed, HashRapidValue(element.value));
			}
			return seed;
		}
		case rapidjson::kArrayType:
		{
			auto seed = combine(type, val.Size());
			for (const auto& element : val.GetArray())
			{
				seed = combine(seed, HashRapidValue(element));
			}
			return seed;
		}
		case rapidjson::kStringType:
		{
			return combine(type, HashBytes(val.GetString(), val.GetStringLength()));
		}
		case rapidjson::kTrueType:
		{
			return combine(type, 1);
		}
		case rapidjson::kNumberType:
		{
			size_t h;
			if (val.IsDouble())
			{
				const double dVal = val.GetDouble();
				h = HashBytes(&dVal, sizeof(dVal));
			}
			else if (val.IsInt())
			{
				h = static_cast<size_t>(val.GetInt());
			}
			else if (val.IsInt64())
			{
				h = static_cast<size_t>(val.GetUint64());
			}
			else if (val.IsUint())
			{
				h = static_cast<size_t>(val.GetUint());
			}
			else
			{
				h = val.GetUint64();
			}
			return combine(type, h);
		}

		default:
			RAPIDJSON_ASSERT(false);
			return 0;
	}
}


#if defined(__GNUC__) && __GNUC__ >= 8
	#pragma GCC diagnostic pop
#endif
