#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


BNBinaryView* BinaryViewType::CreateCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Create(view);
	return BNNewViewReference(result->GetViewObject());
}


bool BinaryViewType::IsValidCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(data));
	return type->IsTypeValidForData(view);
}


BinaryViewType::BinaryViewType(BNBinaryViewType* type): m_type(type)
{
}


BinaryViewType::BinaryViewType(const string& name, const string& longName):
	m_type(nullptr), m_nameForRegister(name), m_longNameForRegister(longName)
{
}


BinaryViewType::~BinaryViewType()
{
	BNFreeBinaryViewType(m_type);
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


vector<Ref<BinaryViewType>> BinaryViewType::GetViewTypesForData(BinaryView* data)
{
	BNBinaryViewType** types;
	size_t count;
	types = BNGetBinaryViewTypesForData(data->GetViewObject(), &count);

	vector<Ref<BinaryViewType>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreBinaryViewType(BNNewViewTypeReference(types[i])));

	BNFreeBinaryViewTypeList(types, count);
	return result;
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
	return new CoreBinaryView(view);
}


bool CoreBinaryViewType::IsTypeValidForData(BinaryView* data)
{
	return BNIsBinaryViewTypeValidForData(m_type, data->GetViewObject());
}
