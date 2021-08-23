// Copyright (c) 2015-2021 Vector 35 Inc
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

#include <vector>
#include <string>
#include <optional>
#include <unordered_map>
#include <functional>
#include <utility>
#include <stdint.h>

#ifdef BINARYNINJACORE_LIBRARY
#include "downloadprovider.h"
#include "json/json.h"
#else
#include "binaryninjaapi.h"
#endif


#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore::Http
#else
namespace BinaryNinja::Http
#endif
{

#ifdef BINARYNINJACORE_LIBRARY
#define _STD_STRING string
#define _STD_VECTOR vector
#define _STD_UNORDERED_MAP unordered_map
#else
#define _STD_STRING std::string
#define _STD_VECTOR std::vector
#define _STD_UNORDERED_MAP std::unordered_map
#endif

	enum ResponseCode
	{
		Continue = 100,
		SwitchingProtocols = 101,
		OK = 200,
		Created = 201,
		Accepted = 202,
		NonAuthoritativeInformation = 203,
		NoContent = 204,
		ResetContent = 205,
		PartialContent = 206,
		MultipleChoices = 300,
		MovedPermanently = 301,
		Found = 302,
		SeeOther = 303,
		NotModified = 304,
		UseProxy = 305,
		TemporaryRedirect = 307,
		BadRequest = 400,
		Unauthorized = 401,
		PaymentRequired = 402,
		Forbidden = 403,
		NotFound = 404,
		MethodNotAllowed = 405,
		NotAcceptable = 406,
		ProxyAuthenticationRequired = 407,
		RequestTimeout = 408,
		Conflict = 409,
		Gone = 410,
		LengthRequired = 411,
		PreconditionFailed = 412,
		RequestEntityTooLarge = 413,
		RequestURITooLong = 414,
		UnsupportedMediaType = 415,
		RequestedRangeNotSatisfiable = 416,
		ExpectationFailed = 417,
		ImATeapot = 418,
		InternalServerError = 500,
		NotImplemented = 501,
		BadGateway = 502,
		ServiceUnavailable = 503,
		GatewayTimeout = 504,
		HTTPVersionNotSupported = 505,
	};


	/*!
	    Basic HTTP response structure
	 */
	struct Response
	{
		DownloadInstance::Response response;
		_STD_VECTOR<uint8_t> body;
		_STD_STRING error;

		/*!
		    Get response body as uint8_t vector
		    \return Response body bytes
		 */
		_STD_VECTOR<uint8_t> GetRaw() const noexcept;
		/*!
		    Get response body as text string
		    \return Response body string
		 */
		_STD_STRING GetString() const noexcept;
		/*!
		    Get response body as a json value
		    \return Response body json
		    \throws runtime_error On JSON parse error
		 */
		Json::Value GetJson() const;
		/*!
		    Get response body as a json value without throwing
		    \param value Output json value
		    \return True if successful
		 */
		bool GetJson(Json::Value& value) const noexcept;
	};


	/*!
	    Structure for multipart form fields
	 */
	struct MultipartField
	{
		_STD_STRING name;
		_STD_VECTOR<uint8_t> content;
		std::optional<_STD_STRING> filename;

		/*!
		    Construct a Multipart Field structure with a UTF-8 string encoded body
		    \param name Name of the field to be sent in a POST request
		    \param content Contents of the field
		 */
		MultipartField(_STD_STRING name, const _STD_STRING& content):
			name(std::move(name)), content({}), filename({})
		{
			std::copy(content.begin(), content.end(), std::back_inserter(this->content));
		}

		/*!
		    Construct a Multipart Field structure for a file with a UTF-8 string encoded body
		    \param name Name of the field to be sent in a POST request
		    \param content Contents of the field
		    \param filename Filename associated with the contents
		 */
		MultipartField(_STD_STRING name, const _STD_STRING& content, _STD_STRING filename):
			name(std::move(name)), content({}), filename(std::move(filename))
		{
			std::copy(content.begin(), content.end(), std::back_inserter(this->content));
		}

		/*!
		    Construct a Multipart Field structure with a binary blob body
		    \param name Name of the field to be sent in a POST request
		    \param content Contents of the field
		 */
		MultipartField(_STD_STRING name, _STD_VECTOR<uint8_t> content):
			name(std::move(name)), content(std::move(content)), filename({})
		{

		}

		/*!
		    Construct a Multipart Field structure for a file with a binary blob body
		    \param name Name of the field to be sent in a POST request
		    \param content Contents of the field
		    \param filename Filename associated with the contents
		 */
		MultipartField(_STD_STRING name, _STD_VECTOR<uint8_t> content, _STD_STRING filename):
			name(std::move(name)), content(std::move(content)), filename(std::move(filename))
		{

		}
	};


	/*!
	    Structure containing HTTP metadata for requests
	 */
	struct Request
	{
		_STD_STRING m_method;
		_STD_STRING m_url;
		_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> m_headers;
		_STD_VECTOR<uint8_t> m_body;

		std::function<bool(size_t, size_t)> m_downloadProgress;
		std::function<bool(size_t, size_t)> m_uploadProgress;

		/*!
		    Construct an arbitrary HTTP request with an empty body
		    \param method Request method eg GET
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		 */
		Request(_STD_STRING method, _STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers = {},
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params = {},
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an arbitrary HTTP request with a binary data body
		    \param method Request method eg GET
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param body Content body (binary data)
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		 */
		Request(_STD_STRING method, _STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params,
			_STD_VECTOR<uint8_t> body,
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an arbitrary HTTP request with url encoded form fields as the body
		    \param method Request method eg GET
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param formFields HTTP form fields, keys/values (both must be strings)
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		 */
		Request(_STD_STRING method, _STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> formFields,
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an arbitrary HTTP request with Multipart encoded form fields as the body
		    \param method Request method eg GET
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param formFields HTTP form fields, keys/values (values can be arbitrary data)
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		 */
		Request(_STD_STRING method, _STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params,
			_STD_VECTOR<MultipartField> formFields,
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an HTTP GET request
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		    \return Request structure with specified fields
		 */
		static Request Get(_STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers = {},
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params = {},
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an HTTP POST request with a binary data body
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param body Request body data
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		    \return Request structure with specified fields
		 */
		static Request Post(_STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers = {},
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params = {},
			_STD_VECTOR<uint8_t> body = {},
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an HTTP POST request with url encoded form fields as the body
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param formFields HTTP form fields, keys/values (both must be strings)
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		    \return Request structure with specified fields
		 */
		static Request Post(_STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> formFields,
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});


		/*!
		    Construct an HTTP POST request with Multipart encoded form fields as the body
		    \param url Target URL eg https://binary.ninja
		    \param headers Header keys/values
		    \param params Query parameters, keys/values
		    \param formFields HTTP form fields, keys/values (values can be arbitrary data)
		    \param downloadProgress Function to call for download progress updates
		    \param uploadProgress Function to call for upload progress updates
		    \return Request structure with specified fields
		 */
		static Request Post(_STD_STRING url,
			_STD_UNORDERED_MAP<_STD_STRING, _STD_STRING> headers,
			_STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>> params,
			_STD_VECTOR<MultipartField> formFields,
			std::function<bool(size_t, size_t)> downloadProgress = {},
			std::function<bool(size_t, size_t)> uploadProgress = {});
	};


	/*!
	    Convert a string to a URLEncoded form-field safe form
	    \param str Input string
	    \return URLEncoded string
	 */
	_STD_STRING UrlEncode(const _STD_STRING& str);


	/*!
	    Convert a list of key/value pair strings into a URLEncoded form body
	    \param fields Input key/value pairs
	    \return URLEncoded form body
	 */
	_STD_STRING UrlEncode(const _STD_VECTOR<std::pair<_STD_STRING, _STD_STRING>>& fields);


	/*!
	    Convert a list of form fields (potentially containing binary data) into a multipart encoded
	form body
	    \param fields Input fields
	    \param boundary Output boundary between fields in the body (for Content-Type header)
	    \return Multipart encoded form body
	 */
	_STD_VECTOR<uint8_t> MultipartEncode(const _STD_VECTOR<MultipartField>& fields, _STD_STRING& boundary);


	/*!
	    Perform an HTTP request as specified by a Request, storing results in a Response
	    \param instance DownloadInstance instance
	    \param request Input Request structure with fields
	    \param response Output Response structure with body
	    \return Zero or greater on success
	 */
	int Perform(const Ref<DownloadInstance>& instance, const Request& request, Response& response);

#undef _STD_VECTOR
#undef _STD_SET
#undef _STD_UNORDERED_MAP
#undef _STD_MAP
}