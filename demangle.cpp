#include "binaryninjaapi.h"
#include <string>
using namespace std;
using namespace BinaryNinja;

namespace BinaryNinja {
	bool DemangleGeneric(Ref<Architecture> arch, const std::string& name, Ref<Type>& outType,
		QualifiedName& outVarName, Ref<BinaryView> view, bool simplify)
	{
		BNType* apiType;
		BNQualifiedName apiVarName;
		bool success = BNDemangleGeneric(
			arch->m_object, name.c_str(), &apiType, &apiVarName, view ? view->m_object : nullptr, simplify);

		if (!success)
			return false;

		if (apiType)
			outType = new Type(apiType);
		outVarName = QualifiedName::FromAPIObject(&apiVarName);
		BNFreeQualifiedName(&apiVarName);
		return true;
	}

	bool DemangleLLVM(const std::string& mangledName, QualifiedName& outVarName,
		BinaryView* view)
	{
		const bool simplify = Settings::Instance()->Get<bool>("analysis.types.templateSimplifier", view);
		return DemangleLLVM(mangledName, outVarName, simplify);
	}

	bool DemangleLLVM(const std::string& mangledName, QualifiedName& outVarName,
		const bool simplify)
	{
		char** localVarName = nullptr;
		size_t localSize = 0;
		if (!BNDemangleLLVM(mangledName.c_str(), &localVarName, &localSize, simplify))
			return false;
		for (size_t i = 0; i < localSize; i++)
		{
			outVarName.push_back(localVarName[i]);
		}
		BNFreeDemangledName(&localVarName, localSize);
		return true;
	}

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

	Demangler::Demangler(const std::string& name): m_nameForRegister(name)
	{
	}

	Demangler::Demangler(BNDemangler* demangler)
	{
		m_object = demangler;
	}

	bool Demangler::IsMangledStringCallback(void* ctxt, const char* name)
	{
		Demangler* demangler = (Demangler*)ctxt;
		return demangler->IsMangledString(name);
	}

	bool Demangler::DemangleCallback(void* ctxt, BNArchitecture* arch, const char* name, BNType** outType,
	                                 BNQualifiedName* outVarName, BNBinaryView* view)
	{
		Demangler* demangler = (Demangler*)ctxt;

		Ref<Architecture> apiArch = new CoreArchitecture(arch);
		Ref<BinaryView> apiView = view ? new BinaryView(BNNewViewReference(view)) : nullptr;

		Ref<Type> apiType;
		QualifiedName apiVarName;
		bool success = demangler->Demangle(apiArch, name, apiType, apiVarName, apiView);
		if (!success)
			return false;

		if (apiType)
		{
			*outType = BNNewTypeReference(apiType->m_object);
		}
		else
		{
			*outType = nullptr;
		}
		*outVarName = apiVarName.GetAPIObject();

		return true;
	}

	void Demangler::FreeVarNameCallback(void* ctxt, BNQualifiedName* name)
	{
		QualifiedName::FreeAPIObject(name);
	}

	void Demangler::Register(Demangler* demangler)
	{
		BNDemanglerCallbacks cb;
		cb.context = (void*)demangler;
		cb.isMangledString = IsMangledStringCallback;
		cb.demangle = DemangleCallback;
		cb.freeVarName = FreeVarNameCallback;
		demangler->m_object = BNRegisterDemangler(demangler->m_nameForRegister.c_str(), &cb);
	}

	std::vector<Ref<Demangler>> Demangler::GetList()
	{
		size_t count;
		BNDemangler** list = BNGetDemanglerList(&count);
		vector<Ref<Demangler>> result;
		for (size_t i = 0; i < count; i++)
			result.push_back(new CoreDemangler(list[i]));
		BNFreeDemanglerList(list);
		return result;
	}

	Ref<Demangler> Demangler::GetByName(const std::string& name)
	{
		BNDemangler* result = BNGetDemanglerByName(name.c_str());
		if (!result)
			return nullptr;
		return new CoreDemangler(result);
	}

	void Demangler::Promote(Ref<Demangler> demangler)
	{
		BNPromoteDemangler(demangler->m_object);
	}

	std::string Demangler::GetName() const
	{
		char* name = BNGetDemanglerName(m_object);
		std::string value = name;
		BNFreeString(name);
		return value;
	}

	CoreDemangler::CoreDemangler(BNDemangler* demangler): Demangler(demangler)
	{
	}

	bool CoreDemangler::IsMangledString(const std::string& name)
	{
		return BNIsDemanglerMangledName(m_object, name.c_str());
	}

	bool CoreDemangler::Demangle(Ref<Architecture> arch, const std::string& name, Ref<Type>& outType,
		QualifiedName& outVarName, Ref<BinaryView> view)
	{
		BNType* apiType;
		BNQualifiedName apiVarName;
		bool success = BNDemanglerDemangle(
			m_object, arch->m_object, name.c_str(), &apiType, &apiVarName, view ? view->m_object : nullptr);

		if (!success)
			return false;

		if (apiType)
			outType = new Type(apiType);
		outVarName = QualifiedName::FromAPIObject(&apiVarName);
		BNFreeQualifiedName(&apiVarName);
		return true;
	}
}  // namespace BinaryNinja
