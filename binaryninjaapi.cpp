// Copyright (c) 2015-2019 Vector 35 Inc
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

using namespace BinaryNinja;
using namespace std;


struct WorkerThreadActionContext
{
	std::function<void()> action;
};


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
	bool result = BNExecuteWorkerProcess(path.c_str(), argArray, input.GetBufferObject(), &outputStr, &errorStr,
                                         stdoutIsText, stderrIsText);

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


void BinaryNinja::WorkerEnqueue(const function<void()>& action)
{
	WorkerThreadActionContext* ctxt = new WorkerThreadActionContext;
	ctxt->action = action;
	BNWorkerEnqueue(ctxt, WorkerActionCallback);
}


void BinaryNinja::WorkerEnqueue(RefCountObject* owner, const function<void()>& action)
{
	struct
	{
		Ref<RefCountObject> owner;
		function<void()> func;
	} context;
	context.owner = owner;
	context.func = action;

	WorkerEnqueue([=]() {
			context.func();
		});
}


void BinaryNinja::WorkerPriorityEnqueue(const function<void()>& action)
{
	WorkerThreadActionContext* ctxt = new WorkerThreadActionContext;
	ctxt->action = action;
	BNWorkerPriorityEnqueue(ctxt, WorkerActionCallback);
}


void BinaryNinja::WorkerPriorityEnqueue(RefCountObject* owner, const function<void()>& action)
{
	struct
	{
		Ref<RefCountObject> owner;
		function<void()> func;
	} context;
	context.owner = owner;
	context.func = action;

	WorkerPriorityEnqueue([=]() {
			context.func();
		});
}


void BinaryNinja::WorkerInteractiveEnqueue(const function<void()>& action)
{
	WorkerThreadActionContext* ctxt = new WorkerThreadActionContext;
	ctxt->action = action;
	BNWorkerInteractiveEnqueue(ctxt, WorkerActionCallback);
}


void BinaryNinja::WorkerInteractiveEnqueue(RefCountObject* owner, const function<void()>& action)
{
	struct
	{
		Ref<RefCountObject> owner;
		function<void()> func;
	} context;
	context.owner = owner;
	context.func = action;

	WorkerInteractiveEnqueue([=]() {
			context.func();
		});
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


vector<string> BinaryNinja::GetRegisteredPluginLoaders()
{
	size_t count = 0;
	char** loaders = BNGetRegisteredPluginLoaders(&count);
	vector<string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(loaders[i]);
	BNFreeRegisteredPluginLoadersList(loaders, count);
	return result;
}
