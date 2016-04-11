// Copyright (c) 2015-2016 Vector 35 LLC
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


void BinaryNinja::InitCorePlugins()
{
	BNInitCorePlugins();
}


void BinaryNinja::InitUserPlugins()
{
	BNInitUserPlugins();
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


bool BinaryNinja::ExecuteWorkerProcess(const string& path, const vector<string>& args, const DataBuffer& input,
                                       string& output, string& errors)
{
	const char** argArray = new const char*[args.size() + 1];
	for (size_t i = 0; i < args.size(); i++)
		argArray[i] = args[i].c_str();
	argArray[args.size()] = nullptr;

	char* outputStr;
	char* errorStr;
	bool result = BNExecuteWorkerProcess(path.c_str(), argArray, input.GetBufferObject(), &outputStr, &errorStr);

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
