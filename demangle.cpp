#include "binaryninjaapi.h"
#include <string>
using namespace std;

namespace BinaryNinja {
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
	    BinaryView* view)
	{
		const bool simplify = Settings::Instance()->Get<bool>("analysis.types.templateSimplifier", view);
		return DemangleMS(arch, mangledName, outType, outVarName, simplify);
	}

	bool DemangleMS(Architecture* arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
	    const bool simplify)
	{
		BNType* localType = nullptr;
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleMS(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize, simplify))
			return false;
		outType = localType ? new Type(localType) : nullptr;
		for (size_t i = 0; i < localSize; i++)
		{
			outVarName.push_back(localVarName[i]);
		}
		BNFreeDemangledName(&localVarName, localSize);
		return true;
	}

	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
	    BinaryView* view)
	{
		const bool simplify = Settings::Instance()->Get<bool>("analysis.types.templateSimplifier", view);
		return DemangleGNU3(arch, mangledName, outType, outVarName, simplify);
	}

	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Ref<Type>& outType, QualifiedName& outVarName,
	    const bool simplify)
	{
		BNType* localType;
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleGNU3(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize, simplify))
			return false;
		outType = localType ? new Type(localType) : nullptr;
		outVarName.clear();
		for (size_t i = 0; i < localSize; i++)
		{
			outVarName.push_back(localVarName[i]);
		}
		BNFreeDemangledName(&localVarName, localSize);
		return true;
	}


	bool IsGNU3MangledString(const std::string& mangledName)
	{
		return BNIsGNU3MangledString(mangledName.c_str());
	}


	string SimplifyToString(const string& input)
	{
		return BNRustSimplifyStrToStr(input.c_str());
	}


	string SimplifyToString(const QualifiedName& input)
	{
		return BNRustSimplifyStrToStr(input.GetString().c_str());
	}


	QualifiedName SimplifyToQualifiedName(const string& input, bool simplify)
	{
		BNQualifiedName name = BNRustSimplifyStrToFQN(input.c_str(), simplify);
		QualifiedName result = QualifiedName::FromAPIObject(&name);
		BNFreeQualifiedName(&name);
		return result;
	}


	QualifiedName SimplifyToQualifiedName(const QualifiedName& input)
	{
		BNQualifiedName name = BNRustSimplifyStrToFQN(input.GetString().c_str(), true);
		QualifiedName result = QualifiedName::FromAPIObject(&name);
		BNFreeQualifiedName(&name);
		return result;
	}
}  // namespace BinaryNinja
