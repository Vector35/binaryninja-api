#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


BNBinaryView* BinaryViewType::CreateCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Create(view);
	return BNNewViewReference(result->GetObject());
}


bool BinaryViewType::IsValidCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return type->IsTypeValidForData(view);
}


BinaryViewType::BinaryViewType(BNBinaryViewType* type)
{
	m_object = type;
}


BinaryViewType::BinaryViewType(const string& name, const string& longName):
	m_nameForRegister(name), m_longNameForRegister(longName)
{
	m_object = nullptr;
}


void BinaryViewType::Register(BinaryViewType* type)
{
	BNCustomBinaryViewType callbacks;
	callbacks.context = type;
	callbacks.create = CreateCallback;
	callbacks.isValidForData = IsValidCallback;

	type->AddRefForRegistration();
	type->m_object = BNRegisterBinaryViewType(type->m_nameForRegister.c_str(),
	                                          type->m_longNameForRegister.c_str(), &callbacks);
}


Ref<BinaryViewType> BinaryViewType::GetByName(const string& name)
{
	BNBinaryViewType* type = BNGetBinaryViewTypeByName(name.c_str());
	if (!type)
		return nullptr;
	return new CoreBinaryViewType(type);
}


vector<Ref<BinaryViewType>> BinaryViewType::GetViewTypes()
{
	BNBinaryViewType** types;
	size_t count;
	types = BNGetBinaryViewTypes(&count);

	vector<Ref<BinaryViewType>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreBinaryViewType(types[i]));

	BNFreeBinaryViewTypeList(types);
	return result;
}


vector<Ref<BinaryViewType>> BinaryViewType::GetViewTypesForData(BinaryView* data)
{
	BNBinaryViewType** types;
	size_t count;
	types = BNGetBinaryViewTypesForData(data->GetObject(), &count);

	vector<Ref<BinaryViewType>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreBinaryViewType(types[i]));

	BNFreeBinaryViewTypeList(types);
	return result;
}


void BinaryViewType::RegisterArchitecture(const string& name, uint32_t id, Architecture* arch)
{
	Ref<BinaryViewType> type = BinaryViewType::GetByName(name);
	if (!type)
		return;
	type->RegisterArchitecture(id, arch);
}


void BinaryViewType::RegisterArchitecture(uint32_t id, Architecture* arch)
{
	BNRegisterArchitectureForViewType(m_object, id, arch->GetObject());
}


Ref<Architecture> BinaryViewType::GetArchitecture(uint32_t id)
{
	BNArchitecture* arch = BNGetArchitectureForViewType(m_object, id);
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


void BinaryViewType::RegisterPlatform(const string& name, uint32_t id, Architecture* arch, Platform* platform)
{
	Ref<BinaryViewType> type = BinaryViewType::GetByName(name);
	if (!type)
		return;
	type->RegisterPlatform(id, arch, platform);
}


void BinaryViewType::RegisterDefaultPlatform(const string& name, Architecture* arch, Platform* platform)
{
	Ref<BinaryViewType> type = BinaryViewType::GetByName(name);
	if (!type)
		return;
	type->RegisterDefaultPlatform(arch, platform);
}


void BinaryViewType::RegisterPlatform(uint32_t id, Architecture* arch, Platform* platform)
{
	BNRegisterPlatformForViewType(m_object, id, arch->GetObject(), platform->GetObject());
}


void BinaryViewType::RegisterDefaultPlatform(Architecture* arch, Platform* platform)
{
	BNRegisterDefaultPlatformForViewType(m_object, arch->GetObject(), platform->GetObject());
}


Ref<Platform> BinaryViewType::GetPlatform(uint32_t id, Architecture* arch)
{
	BNPlatform* platform = BNGetPlatformForViewType(m_object, id, arch->GetObject());
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


string BinaryViewType::GetName()
{
	char* contents = BNGetBinaryViewTypeName(m_object);
	string result = contents;
	BNFreeString(contents);
	return result;
}


string BinaryViewType::GetLongName()
{
	char* contents = BNGetBinaryViewTypeLongName(m_object);
	string result = contents;
	BNFreeString(contents);
	return result;
}


CoreBinaryViewType::CoreBinaryViewType(BNBinaryViewType* type): BinaryViewType(type)
{
}


BinaryView* CoreBinaryViewType::Create(BinaryView* data)
{
	BNBinaryView* view = BNCreateBinaryViewOfType(m_object, data->GetObject());
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


bool CoreBinaryViewType::IsTypeValidForData(BinaryView* data)
{
	return BNIsBinaryViewTypeValidForData(m_object, data->GetObject());
}
