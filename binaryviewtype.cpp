#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


BNBinaryView* BinaryViewType::CreateCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Create(view);
	return BNNewViewReference(result->GetViewObject());
}


bool BinaryViewType::IsValidCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return type->IsTypeValidForData(view);
}


BinaryViewType::BinaryViewType(BNBinaryViewType* type): m_type(type)
{
}


BinaryViewType::BinaryViewType(const string& name, const string& longName):
	m_type(nullptr), m_nameForRegister(name), m_longNameForRegister(longName)
{
}


void BinaryViewType::Register(BinaryViewType* type)
{
	BNCustomBinaryViewType callbacks;
	callbacks.context = type;
	callbacks.create = CreateCallback;
	callbacks.isValidForData = IsValidCallback;

	type->m_type = BNRegisterBinaryViewType(type->m_nameForRegister.c_str(),
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
	types = BNGetBinaryViewTypesForData(data->GetViewObject(), &count);

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
	BNRegisterArchitectureForViewType(m_type, id, arch->GetArchitectureObject());
}


Ref<Architecture> BinaryViewType::GetArchitecture(uint32_t id)
{
	BNArchitecture* arch = BNGetArchitectureForViewType(m_type, id);
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


string BinaryViewType::GetName()
{
	char* contents = BNGetBinaryViewTypeName(m_type);
	string result = contents;
	BNFreeString(contents);
	return result;
}


string BinaryViewType::GetLongName()
{
	char* contents = BNGetBinaryViewTypeLongName(m_type);
	string result = contents;
	BNFreeString(contents);
	return result;
}


CoreBinaryViewType::CoreBinaryViewType(BNBinaryViewType* type): BinaryViewType(type)
{
}


BinaryView* CoreBinaryViewType::Create(BinaryView* data)
{
	BNBinaryView* view = BNCreateBinaryViewOfType(m_type, data->GetViewObject());
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


bool CoreBinaryViewType::IsTypeValidForData(BinaryView* data)
{
	return BNIsBinaryViewTypeValidForData(m_type, data->GetViewObject());
}
