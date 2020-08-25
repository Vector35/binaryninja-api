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

struct GenericException: public std::exception
{
	GenericException() : std::exception() {}
	virtual const char* what() const throw()
	{
		return "Exception while parsing json.";
	}
};

#define RAPIDJSON_HAS_STDSTRING 0
#define RAPIDJSON_HAS_CXX11_NOEXCEPT 0
#define RAPIDJSON_ASSERT(x) do {if (!(x)) throw GenericException(); } while(0);
#define RAPIDJSON_PARSE_ERROR_NORETURN(parseErrorCode,offset) \
	throw ParseException(parseErrorCode, #parseErrorCode, offset)

#include "rapidjson/error/error.h"
struct ParseException: public std::runtime_error, rapidjson::ParseResult
{
	ParseException(rapidjson::ParseErrorCode code, const char* msg, size_t offset) : std::runtime_error(msg),
		ParseResult(code, offset) {}
};

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
