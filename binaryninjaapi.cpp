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

#include "binaryninjaapi.h"
#include <numeric>

using namespace BinaryNinja;
using namespace std;


struct WorkerThreadActionContext
{
	std::function<void()> action;
};


void BinaryNinja::DisablePlugins()
{
	BNDisablePlugins();
}


bool BinaryNinja::IsPluginsEnabled()
{
	return BNIsPluginsEnabled();
}


bool BinaryNinja::InitPlugins(bool allowUserPlugins)
{
	return BNInitPlugins(allowUserPlugins);
}


void BinaryNinja::InitCorePlugins()
{
	BNInitCorePlugins();
}


void BinaryNinja::InitUserPlugins()
{
	BNInitUserPlugins();
}


void BinaryNinja::InitRepoPlugins()
{
	BNInitRepoPlugins();
}


string BinaryNinja::GetBundledPluginDirectory()
{
	char* path = BNGetBundledPluginDirectory();
	if (!path)
		return string();
	string result = path;
	BNFreeString(path);
	return result;
}


void BinaryNinja::SetBundledPluginDirectory(const string& path)
{
	BNSetBundledPluginDirectory(path.c_str());
}


string BinaryNinja::GetUserDirectory(void)
{
	char* dir = BNGetUserDirectory();
	if (!dir)
		return string();
	string result(dir);
	BNFreeString(dir);
	return result;
}


string BinaryNinja::GetSettingsFileName()
{
	char* dir = BNGetSettingsFileName();
	if (!dir)
		return string();
	string result(dir);
	BNFreeString(dir);
	return result;
}


string BinaryNinja::GetRepositoriesDirectory()
{
	char* dir = BNGetRepositoriesDirectory();
	if (!dir)
		return string();
	string result(dir);
	BNFreeString(dir);
	return result;
}


string BinaryNinja::GetInstallDirectory()
{
	char* path = BNGetInstallDirectory();
	if (!path)
		return string();
	string result = path;
	BNFreeString(path);
	return result;
}


string BinaryNinja::GetUserPluginDirectory()
{
	char* path = BNGetUserPluginDirectory();
	if (!path)
		return string();
	string result = path;
	BNFreeString(path);
	return result;
}


string BinaryNinja::GetPathRelativeToBundledPluginDirectory(const string& rel)
{
	char* path = BNGetPathRelativeToBundledPluginDirectory(rel.c_str());
	if (!path)
		return rel;
	string result = path;
	BNFreeString(path);
	return result;
}


string BinaryNinja::GetPathRelativeToUserPluginDirectory(const string& rel)
{
	char* path = BNGetPathRelativeToUserPluginDirectory(rel.c_str());
	if (!path)
		return rel;
	string result = path;
	BNFreeString(path);
	return result;
}


string BinaryNinja::GetPathRelativeToUserDirectory(const string& rel)
{
	char* path = BNGetPathRelativeToUserDirectory(rel.c_str());
	if (!path)
		return rel;
	string result = path;
	BNFreeString(path);
	return result;
}


bool BinaryNinja::ExecuteWorkerProcess(const string& path, const vector<string>& args, const DataBuffer& input,
    string& output, string& errors, bool stdoutIsText, bool stderrIsText)
{
	const char** argArray = new const char*[args.size() + 1];
	for (size_t i = 0; i < args.size(); i++)
		argArray[i] = args[i].c_str();
	argArray[args.size()] = nullptr;

	char* outputStr;
	char* errorStr;
	bool result = BNExecuteWorkerProcess(
	    path.c_str(), argArray, input.GetBufferObject(), &outputStr, &errorStr, stdoutIsText, stderrIsText);

	output = outputStr;
	errors = errorStr;
	BNFreeString(outputStr);
	BNFreeString(errorStr);
	delete[] argArray;
	return result;
}


string BinaryNinja::GetVersionString()
{
	char* str = BNGetVersionString();
	string result = str;
	BNFreeString(str);
	return result;
}


string BinaryNinja::GetLicensedUserEmail()
{
	char* str = BNGetLicensedUserEmail();
	string result = str;
	BNFreeString(str);
	return result;
}


string BinaryNinja::GetProduct()
{
	char* str = BNGetProduct();
	string result = str;
	BNFreeString(str);
	return result;
}


string BinaryNinja::GetProductType()
{
	char* str = BNGetProductType();
	string result = str;
	BNFreeString(str);
	return result;
}


string BinaryNinja::GetSerialNumber()
{
	char* str = BNGetSerialNumber();
	string result = str;
	BNFreeString(str);
	return result;
}


int BinaryNinja::GetLicenseCount()
{
	return BNGetLicenseCount();
}


bool BinaryNinja::IsUIEnabled()
{
	return BNIsUIEnabled();
}


uint32_t BinaryNinja::GetBuildId()
{
	return BNGetBuildId();
}


void BinaryNinja::SetCurrentPluginLoadOrder(BNPluginLoadOrder order)
{
	BNSetCurrentPluginLoadOrder(order);
}


void BinaryNinja::AddRequiredPluginDependency(const string& name)
{
	BNAddRequiredPluginDependency(name.c_str());
}


void BinaryNinja::AddOptionalPluginDependency(const string& name)
{
	BNAddOptionalPluginDependency(name.c_str());
}


static void WorkerActionCallback(void* ctxt)
{
	WorkerThreadActionContext* action = (WorkerThreadActionContext*)ctxt;
	action->action();
	delete action;
}


void BinaryNinja::WorkerEnqueue(const function<void()>& action, const std::string& name)
{
	WorkerThreadActionContext* ctxt = new WorkerThreadActionContext;
	ctxt->action = action;
	BNWorkerEnqueueNamed(ctxt, WorkerActionCallback, name.c_str());
}


void BinaryNinja::WorkerEnqueue(RefCountObject* owner, const function<void()>& action, const std::string& name)
{
	struct
	{
		Ref<RefCountObject> owner;
		function<void()> func;
	} context;
	context.owner = owner;
	context.func = action;

	WorkerEnqueue([=]() { context.func(); }, name);
}


void BinaryNinja::WorkerPriorityEnqueue(const function<void()>& action, const std::string& name)
{
	WorkerThreadActionContext* ctxt = new WorkerThreadActionContext;
	ctxt->action = action;
	BNWorkerPriorityEnqueueNamed(ctxt, WorkerActionCallback, name.c_str());
}


void BinaryNinja::WorkerPriorityEnqueue(RefCountObject* owner, const function<void()>& action, const std::string& name)
{
	struct
	{
		Ref<RefCountObject> owner;
		function<void()> func;
	} context;
	context.owner = owner;
	context.func = action;

	WorkerPriorityEnqueue([=]() { context.func(); }, name);
}


void BinaryNinja::WorkerInteractiveEnqueue(const function<void()>& action, const std::string& name)
{
	WorkerThreadActionContext* ctxt = new WorkerThreadActionContext;
	ctxt->action = action;
	BNWorkerInteractiveEnqueueNamed(ctxt, WorkerActionCallback, name.c_str());
}


void BinaryNinja::WorkerInteractiveEnqueue(RefCountObject* owner, const function<void()>& action, const std::string& name)
{
	struct
	{
		Ref<RefCountObject> owner;
		function<void()> func;
	} context;
	context.owner = owner;
	context.func = action;

	WorkerInteractiveEnqueue([=]() { context.func(); }, name);
}


size_t BinaryNinja::GetWorkerThreadCount()
{
	return BNGetWorkerThreadCount();
}


void BinaryNinja::SetWorkerThreadCount(size_t count)
{
	BNSetWorkerThreadCount(count);
}


string BinaryNinja::GetUniqueIdentifierString()
{
	char* str = BNGetUniqueIdentifierString();
	string result = str;
	BNFreeString(str);
	return result;
}


map<string, uint64_t> BinaryNinja::GetMemoryUsageInfo()
{
	size_t count;
	BNMemoryUsageInfo* info = BNGetMemoryUsageInfo(&count);

	map<string, uint64_t> result;
	for (size_t i = 0; i < count; i++)
		result[info[i].name] = info[i].value;
	BNFreeMemoryUsageInfo(info, count);
	return result;
}


bool BinaryNinja::DefaultProgressFunction(size_t, size_t)
{
	return true;
}


BinaryNinja::ProgressFunction BinaryNinja::SplitProgress(
    BinaryNinja::ProgressFunction originalFn, size_t subpart, size_t subpartCount)
{
	return SplitProgress(originalFn, subpart, std::vector<double>(subpartCount, 1.0 / (double)subpartCount));
}


BinaryNinja::ProgressFunction BinaryNinja::SplitProgress(
    BinaryNinja::ProgressFunction originalFn, size_t subpart, std::vector<double> subpartWeights)
{
	if (!originalFn)
		return [](size_t, size_t) {
			return true;
		};

	// Normalize weights
	double weightSum = std::accumulate(subpartWeights.begin(), subpartWeights.end(), 0.0);
	if (weightSum < 0.0001f)
		return [](size_t, size_t) {
			return true;
		};
	// Keep a running count of weights for the start
	std::vector<double> subpartStarts;
	double start = 0.0;
	for (size_t i = 0; i < subpartWeights.size(); ++i)
	{
		subpartStarts.push_back(start);
		subpartWeights[i] /= weightSum;
		start += subpartWeights[i];
	}

	return [=](size_t current, size_t max) {
		// Just use a large number for easy divisibility
		size_t steps = 1000000;
		double subpartSize = steps * subpartWeights[subpart];
		double subpartProgress = ((double)current / (double)max) * subpartSize;
		return originalFn(subpartStarts[subpart] * steps + subpartProgress, steps);
	};
}


bool BinaryNinja::ProgressCallback(void* ctxt, size_t current, size_t total)
{
	ProgressContext* pctxt = reinterpret_cast<ProgressContext*>(ctxt);
	if (!pctxt->callback)
		return true;
	return pctxt->callback(current, total);
}


fmt::format_context::iterator fmtByteString(const std::vector<uint8_t>& string, fmt::format_context& ctx)
{
	*ctx.out()++ = 'b';
	*ctx.out()++ = '\"';
	for (uint8_t ch: string)
	{
		if (ch == '\n')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = 'n';
		}
		else if (ch == '\r')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = 'r';
		}
		else if (ch == '\t')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = 't';
		}
		else if (ch == '\"')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = '\"';
		}
		else if (ch == '\\')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = '\\';
		}
		else if (ch < 0x20 || ch >= 0x7f)
		{
			fmt::format_to(ctx.out(), "\\x{:02x}", ch);
		}
		else
		{
			*ctx.out()++ = ch;
		}
	}
	*ctx.out()++ = '\"';
	return ctx.out();
}


fmt::format_context::iterator fmtQuotedString(const std::string& string, fmt::format_context& ctx)
{
	*ctx.out()++ = '\"';
	for (char ch: string)
	{
		if (ch == '\n')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = 'n';
		}
		else if (ch == '\r')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = 'r';
		}
		else if (ch == '\t')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = 't';
		}
		else if (ch == '\"')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = '\"';
		}
		else if (ch == '\\')
		{
			*ctx.out()++ = '\\';
			*ctx.out()++ = '\\';
		}
		else if (ch < 0x20 || ch >= 0x7f)
		{
			fmt::format_to(ctx.out(), "\\x{:02x}", ch);
		}
		else
		{
			*ctx.out()++ = ch;
		}
	}
	*ctx.out()++ = '\"';
	return ctx.out();
}


fmt::format_context::iterator fmt::formatter<BinaryNinja::Metadata>::format(const BinaryNinja::Metadata& obj, format_context& ctx) const
{
	switch (obj.GetType())
	{
	default:
	case InvalidDataType:
		return fmt::format_to(ctx.out(), "(invalid)");
	case BooleanDataType:
		return fmt::format_to(ctx.out(), "{}", obj.GetBoolean());
	case StringDataType:
		return fmt::format_to(ctx.out(), "{}", obj.GetString());
	case UnsignedIntegerDataType:
		return fmt::format_to(ctx.out(), "{}", obj.GetUnsignedInteger());
	case SignedIntegerDataType:
		return fmt::format_to(ctx.out(), "{}", obj.GetSignedInteger());
	case DoubleDataType:
		return fmt::format_to(ctx.out(), "{}", obj.GetDouble());
	case RawDataType:
		return fmtByteString(obj.GetRaw(), ctx);
	case KeyValueDataType:
	{
		*ctx.out()++ = '{';
		bool first = true;
		for (auto& [name, value]: obj.GetKeyValueStore())
		{
			if (!first)
			{
				*ctx.out()++ = ',';
				*ctx.out()++ = ' ';
			}
			first = false;

			fmtQuotedString(name, ctx);
			*ctx.out()++ = ':';
			*ctx.out()++ = ' ';
			fmt::format_to(ctx.out(), "{}", value);
		}
		*ctx.out()++ = '}';
		return ctx.out();
	}
	case ArrayDataType:
		*ctx.out()++ = '[';
		bool first = true;
		for (auto& value: obj.GetArray())
		{
			if (!first)
			{
				*ctx.out()++ = ',';
				*ctx.out()++ = ' ';
			}
			first = false;
			fmt::format_to(ctx.out(), "{}", value);
		}
		*ctx.out()++ = ']';
		return ctx.out();
	}
}


fmt::format_context::iterator fmt::formatter<BinaryNinja::NameList>::format(const BinaryNinja::NameList& obj, format_context& ctx) const
{
	return fmt::format_to(ctx.out(), "{}", obj.GetString());
}


std::optional<size_t> BinaryNinja::FuzzyMatchSingle(const std::string& target, const std::string& query)
{
	size_t result = BNFuzzyMatchSingle(target.c_str(), query.c_str());
	if (result == 0)
	{
		return std::nullopt;
	}
	return result;
}


void BinaryNinja::SetThreadName(const std::string& name)
{
	BNSetThreadName(name.c_str());
}
