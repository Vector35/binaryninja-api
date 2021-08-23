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

#include <string.h>
#include <chrono>
#include <thread>
#include <math.h>
#include "http.h"

#ifdef BINARYNINJACORE_LIBRARY
#include "log.h"
#endif

#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#else
using namespace BinaryNinja;
using namespace std;
#endif

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore::Http
#else
namespace BinaryNinja::Http
#endif
{
	#define HTTP_MAX_RETRIES 3
	#define HTTP_BACKOFF_FACTOR 1

	struct RequestContext
	{
		size_t uploadOffset;
		size_t downloadLength;
		bool cancelled;
		const Request& request;
		Response& response;

		RequestContext(const Request& request, Response& response):
			uploadOffset(0), downloadLength(0), cancelled(false), request(request), response(response)
		{

		}
	};


	int64_t HttpReadCallback(uint8_t* data, uint64_t len, void* ctxt)
	{
		auto* request = reinterpret_cast<RequestContext*>(ctxt);
		uint64_t remain = request->request.m_body.size() - request->uploadOffset;
		if (len < remain)
		{
			memcpy(data, &request->request.m_body[request->uploadOffset], len);
			request->uploadOffset += len;
			if (request->request.m_uploadProgress)
			{
				if (!request->request.m_uploadProgress(request->uploadOffset, request->request.m_body.size()))
				{
					request->cancelled = true;
					return -1;
				}
			}
			return len;
		}
		else if (remain > 0)
		{
			memcpy(data, &request->request.m_body[request->uploadOffset], remain);
			request->uploadOffset += remain;
			if (request->request.m_uploadProgress)
			{
				if (!request->request.m_uploadProgress(request->uploadOffset, request->request.m_body.size()))
				{
					request->cancelled = true;
					return -1;
				}
			}
			return remain;
		}
		else
		{
			return 0;
		}
	}


	uint64_t HttpWriteCallback(uint8_t* data, uint64_t len, void* ctxt)
	{
		auto* request = reinterpret_cast<RequestContext*>(ctxt);
		// copy can totally take pointers, pretty cool
		copy(data, &data[len], back_inserter(request->response.body));

		// Detect content length if it has not been found yet
		if (request->downloadLength == 0)
		{
			const auto& headers = request->response.response.headers;
			auto found = headers.find("Content-Length");
			if (found != headers.end())
			{
				request->downloadLength = strtoll(found->second.c_str(), nullptr, 10);
				request->response.body.reserve(request->downloadLength);
			}
			else
			{
				request->downloadLength = -1;
			}
		}

		if (request->request.m_downloadProgress)
		{
			if (!request->request.m_downloadProgress(request->response.body.size(), request->downloadLength))
			{
				// Signal error by returning non-len
				request->cancelled = true;
				return 0;
			}
		}

		return len;
	}


	string UrlEncode(const string& str)
	{
		string outStr;
		outStr.reserve(str.size());
		for (auto& ch: str)
		{
			if (isalnum(ch))
			{
				outStr += ch;
			}
			else
			{
				char buf[8];
				snprintf(buf, 8, "%%%02hhx", ch);
				outStr += string(buf);
			}
		}
		return outStr;
	}


	string UrlEncode(const vector<pair<string, string>>& fields)
	{
		string outStr;

		bool first = true;
		for (auto& field: fields)
		{
			if (!first)
			{
				outStr += "&";
			}
			outStr += UrlEncode(field.first);
			outStr += "=";
			outStr += UrlEncode(field.second);
			first = false;
		}

		return outStr;
	}


	vector<uint8_t> MultipartEncode(const vector<MultipartField>& fields, string& boundary)
	{
		boundary = string(4, '-') + "MultipartFormBoundary" + (string)BNGetUniqueIdentifierString();

		vector<uint8_t> boundaryVec;
		boundaryVec.reserve(boundary.size());
		copy(boundary.begin(), boundary.end(), back_inserter(boundaryVec));

		vector<uint8_t> result;
		size_t expectedSize = boundaryVec.size() * fields.size();
		for (const auto& field: fields)
		{
			expectedSize += field.name.size() + field.content.size();
		}
		result.reserve(expectedSize);

		for (const auto& field: fields)
		{
			result.push_back('-');
			result.push_back('-');
			copy(boundaryVec.begin(), boundaryVec.end(), back_inserter(result));
			result.push_back('\r');
			result.push_back('\n');
			string disposition;
			if (field.filename)
			{
				disposition =
					string("Content-Disposition: form-data; name=\"") + field.name + "\"; filename=\"" +
						*field.filename + "\"";
				disposition += string("\r\nContent-Type: application/octet-stream");
			}
			else
			{
				disposition = string("Content-Disposition: form-data; name=\"") + field.name + "\"";
			}
			disposition += "\r\n\r\n";

			copy(disposition.begin(), disposition.end(), back_inserter(result));
			copy(field.content.begin(), field.content.end(), back_inserter(result));

			result.push_back('\r');
			result.push_back('\n');
		}
		result.push_back('-');
		result.push_back('-');
		copy(boundaryVec.begin(), boundaryVec.end(), back_inserter(result));
		result.push_back('-');
		result.push_back('-');
		result.push_back('\r');
		result.push_back('\n');

		return result;
	}


	Request::Request(string method, string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress):
		m_method(method), m_url(url), m_headers(headers),
		m_downloadProgress(downloadProgress), m_uploadProgress(uploadProgress)
	{
		if (!params.empty())
		{
			m_url += "?";
			m_url += UrlEncode(params);
		}

		if (m_headers.find("Content-Length") == m_headers.end())
		{
			m_headers.insert({"Content-Length", to_string(m_body.size())});
		}
		if (m_headers.find("Content-Type") == m_headers.end())
		{
			m_headers.insert({"Content-Type", "application/octet-stream"});
		}
	}


	Request::Request(string method, string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		vector<uint8_t> body,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress):
		m_method(method), m_url(url), m_headers(headers), m_body(body),
		m_downloadProgress(downloadProgress), m_uploadProgress(uploadProgress)
	{
		if (!params.empty())
		{
			m_url += "?";
			m_url += UrlEncode(params);
		}

		if (m_headers.find("Content-Length") == m_headers.end())
		{
			m_headers.insert({"Content-Length", to_string(m_body.size())});
		}
		if (m_headers.find("Content-Type") == m_headers.end())
		{
			m_headers.insert({"Content-Type", "application/octet-stream"});
		}
	}


	Request::Request(string method, string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		vector<pair<string, string>> formFields,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress):
		m_method(method), m_url(url), m_headers(headers),
		m_downloadProgress(downloadProgress), m_uploadProgress(uploadProgress)
	{
		if (!params.empty())
		{
			m_url += "?";
			m_url += UrlEncode(params);
		}

		string encoded = UrlEncode(formFields);
		copy(encoded.begin(), encoded.end(), back_inserter(m_body));
		m_headers.insert({"Content-Type", "application/x-www-form-urlencoded"});

		if (m_headers.find("Content-Length") == m_headers.end())
		{
			m_headers.insert({"Content-Length", to_string(m_body.size())});
		}
		if (m_headers.find("Content-Type") == m_headers.end())
		{
			m_headers.insert({"Content-Type", "application/octet-stream"});
		}
	}


	Request::Request(string method, string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		vector<MultipartField> formFields,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress):
		m_method(method), m_url(url), m_headers(headers),
		m_downloadProgress(downloadProgress), m_uploadProgress(uploadProgress)
	{
		if (!params.empty())
		{
			m_url += "?";
			m_url += UrlEncode(params);
		}

		string boundary;
		m_body = MultipartEncode(formFields, boundary);

		m_headers.insert({"Content-Type", string("multipart/form-data; boundary=\"") + boundary + "\""});

		if (m_headers.find("Content-Length") == m_headers.end())
		{
			m_headers.insert({"Content-Length", to_string(m_body.size())});
		}
		if (m_headers.find("Content-Type") == m_headers.end())
		{
			m_headers.insert({"Content-Type", "application/octet-stream"});
		}
	}


	Request Request::Get(string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress)
	{
		return Request("GET", url, headers, params, downloadProgress, uploadProgress);
	}


	Request Request::Post(string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		vector<uint8_t> body,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress)
	{
		return Request("POST", url, headers, params, body, downloadProgress, uploadProgress);
	}


	Request Request::Post(string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		vector<pair<string, string>> formFields,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress)
	{
		return Request("POST", url, headers, params, formFields, downloadProgress, uploadProgress);
	}


	Request Request::Post(string url,
		unordered_map<string, string> headers,
		vector<pair<string, string>> params,
		vector<MultipartField> formFields,
		std::function<bool(size_t, size_t)> downloadProgress,
		std::function<bool(size_t, size_t)> uploadProgress)
	{
		return Request("POST", url, headers, params, formFields, downloadProgress, uploadProgress);
	}


	int Perform(const Ref<DownloadInstance>& instance, const Request& request, Response& response)
	{
		int result = -1;
		int retry = 0;
		while (true)
		{
			response.response.statusCode = 0;
			response.response.headers.clear();
			response.body.clear();
			response.error.clear();

			RequestContext context{request, response};
			BNDownloadInstanceInputOutputCallbacks callbacks{};
			memset(&callbacks, 0, sizeof(BNDownloadInstanceInputOutputCallbacks));
			callbacks.readContext = &context;
			callbacks.readCallback = &HttpReadCallback;
			callbacks.writeContext = &context;
			callbacks.writeCallback = &HttpWriteCallback;
			result = instance->PerformCustomRequest(request.m_method, request.m_url, request.m_headers, response.response, &callbacks);
			if (result >= 0)
				break;

			// Request failed, grab its error and try again
			response.error = instance->GetError();
			if (retry == HTTP_MAX_RETRIES || context.cancelled)
				break;
			size_t backoff = 1000 * HTTP_BACKOFF_FACTOR * (2 * pow(2, retry - 1));
			retry += 1;
			LogWarn("Attempt %d to %s %s failed, trying again in %zums\n", retry, request.m_method.data(), request.m_url.data(), backoff);
			std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
		}
		return result;
	}

	vector<uint8_t> Response::GetRaw() const noexcept
	{
		return body;
	}


	string Response::GetString() const noexcept
	{
		string str;
		copy(body.begin(), body.end(), back_inserter(str));
		return str;
	}


	Json::Value Response::GetJson() const
	{
		string str = GetString();

		std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
		string errors;
		Json::Value value;
		if (!reader->parse(str.data(), str.data() + str.size(), &value, &errors))
		{
			throw std::runtime_error(std::string("Could not parse JSON: ") + errors.c_str());
		}
		return value;
	}


	bool Response::GetJson(Json::Value& value) const noexcept
	{
		string str = GetString();

		std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
		string errors;
		return reader->parse(str.data(), str.data() + str.size(), &value, &errors);
	}
}
