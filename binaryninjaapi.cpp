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
