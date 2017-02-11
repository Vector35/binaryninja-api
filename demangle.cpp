#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

bool DemangleMS(Architecture* arch,
                const std::string& mangledName,
                Type** outType,
                QualifiedName& outVarName)
{
	BNType* localType = (*outType)->GetObject();
	char** localVarName = nullptr;
	size_t localSize = 0;
	if (!BNDemangleMS(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize))
		return false;
	for (size_t i = 0; i < localSize; i++)
	{
		outVarName.push_back(localVarName[i]);
		BNFreeString(localVarName[i]);
	}
	delete [] localVarName;
	return true;
}


bool DemangleGNU3(Architecture* arch,
                const std::string& mangledName,
                Type** outType,
                QualifiedName& outVarName)
{
	BNType* localType = (*outType)->GetObject();
	char** localVarName = nullptr;
	size_t localSize = 0;
	if (!BNDemangleGNU3(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize))
		return false;
	for (size_t i = 0; i < localSize; i++)
	{
		outVarName.push_back(localVarName[i]);
		BNFreeString(localVarName[i]);
	}
	delete [] localVarName;
	return true;
}
