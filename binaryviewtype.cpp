// Copyright (c) 2015-2019 Vector 35 Inc
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


BNBinaryView* BinaryViewType::CreateCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Create(view);
	if (!result)
		return nullptr;
	return BNNewViewReference(result->GetObject());
}


bool BinaryViewType::IsValidCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return type->IsTypeValidForData(view);
}


char* BinaryViewType::GetSettingsCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return BNAllocString(type->GetLoadSettingsForData(view).c_str());
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
	callbacks.getLoadSettingsForData = GetSettingsCallback;

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
	result.reserve(count);
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreBinaryViewType(types[i]));

	BNFreeBinaryViewTypeList(types);
	return result;
}


void BinaryViewType::RegisterArchitecture(const string& name, uint32_t id, BNEndianness endian, Architecture* arch)
{
	Ref<BinaryViewType> type = BinaryViewType::GetByName(name);
	if (!type)
		return;
	type->RegisterArchitecture(id, endian, arch);
}


void BinaryViewType::RegisterArchitecture(uint32_t id, BNEndianness endian, Architecture* arch)
{
	BNRegisterArchitectureForViewType(m_object, id, endian, arch->GetObject());
}


Ref<Architecture> BinaryViewType::GetArchitecture(uint32_t id, BNEndianness endian)
{
	BNArchitecture* arch = BNGetArchitectureForViewType(m_object, id, endian);
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


string CoreBinaryViewType::GetLoadSettingsForData(BinaryView* data)
{
	char* settings = BNGetBinaryViewLoadSettingsForData(m_object, data->GetObject());
	string result = settings;
	BNFreeString(settings);
	return result;
}
