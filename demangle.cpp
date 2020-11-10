#include "binaryninjaapi.h"
#include <string>
using namespace std;

namespace BinaryNinja
{
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType,
		QualifiedName& outVarName, const Ref<BinaryView>& view)
	{
		const bool simplify = Settings::Instance()->Get<bool>("analysis.types.TemplateSimplifier", view);
		return DemangleMS(arch, mangledName, outType, outVarName, simplify);
	}

	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType,
		QualifiedName& outVarName, const bool simplify)
	{
		BNType* localType = nullptr;
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleMS(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize, simplify))
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
		const bool simplify = Settings::Instance()->Get<bool>("analysis.types.TemplateSimplifier", view);
		return DemangleGNU3(arch, mangledName, outType, outVarName, simplify);
	}

	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType,
		QualifiedName& outVarName, const bool simplify)
	{
		BNType* localType;
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleGNU3(arch->GetObject(), mangledName.c_str(), &localType, &localVarName, &localSize, simplify))
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


	string SimplifyName::to_string(const string& input)
	{
		return (string)SimplifyName(input, SimplifierDest::str, true);
	}


	string SimplifyName::to_string(const QualifiedName& input)
	{
		return (string)SimplifyName(input.GetString(), SimplifierDest::str, true);
	}


	QualifiedName SimplifyName::to_qualified_name(const string& input, bool simplify)
	{
		return (QualifiedName)SimplifyName(input, SimplifierDest::fqn, simplify);
	}


	QualifiedName SimplifyName::to_qualified_name(const QualifiedName& input)
	{
		return (QualifiedName)SimplifyName(input.GetString(), SimplifierDest::fqn, true);
	}


	SimplifyName::SimplifyName(const string& input, const SimplifierDest dest, const bool simplify) :
			m_rust_string(nullptr), m_rust_array(nullptr), m_length(0)
	{
		if (dest == SimplifierDest::str)
			m_rust_string = BNRustSimplifyStrToStr(input.c_str());
		else
			m_rust_array = const_cast<const char**>(BNRustSimplifyStrToFQN(input.c_str(), simplify));
	}


	SimplifyName::~SimplifyName()
	{
		if (m_rust_string)
			BNRustFreeString(m_rust_string);
		if (m_rust_array)
		{
			if (m_length == 0)
			{
				// Should never reach here
				LogWarn("Deallocating SimplifyName without having been used; Likely misuse of API.\n");
				uint64_t index = 0;
				while (m_rust_array[index][0] != 0x0)
					++index;
				m_length = index + 1;
			}
			BNRustFreeStringArray(m_rust_array, m_length);
		}
	}


	SimplifyName::operator string() const
	{
		return string(m_rust_string);
	}


	SimplifyName::operator QualifiedName()
	{
		QualifiedName result;
		uint64_t      index = 0;
		while (m_rust_array[index][0] != 0x0)
		{
			result.push_back(string(m_rust_array[index++]));
		}
		m_length = index;
		return result;
	}
}
