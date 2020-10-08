#include "binaryninjaapi.h"

using namespace std;

namespace BinaryNinja
{
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType,
		QualifiedName& outVarName, const Ref<BinaryView>& view)
	{
		BNType* localType = nullptr;
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleMS(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize, view->GetObject()))
			return false;
		if (!localType)
			return false;
		*outType = new Type(localType);
		for (size_t i = 0; i < localSize; i++)
		{
			outVarName.push_back(localVarName[i]);
			BNFreeString(localVarName[i]);
		}
		delete [] localVarName;
		return true;
	}


	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType,
		QualifiedName& outVarName, const Ref<BinaryView>& view)
	{
		BNType* localType;
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleGNU3(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize, view->GetObject()))
			return false;
		if (!localType)
			return false;
		*outType = new Type(localType);
		for (size_t i = 0; i < localSize; i++)
		{
			outVarName.push_back(localVarName[i]);
			BNFreeString(localVarName[i]);
		}
		delete [] localVarName;
		return true;
	}
}
