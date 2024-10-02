// Copyright (c) 2015-2024 Vector 35 Inc
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
	CallbackRef<BinaryViewType> type(ctxt);
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Create(view);
	if (!result)
		return nullptr;
	return BNNewViewReference(result->GetObject());
}


BNBinaryView* BinaryViewType::ParseCallback(void* ctxt, BNBinaryView* data)
{
	CallbackRef<BinaryViewType> type(ctxt);
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Parse(view);
	if (!result)
		return nullptr;
	return BNNewViewReference(result->GetObject());
}


bool BinaryViewType::IsValidCallback(void* ctxt, BNBinaryView* data)
{
	CallbackRef<BinaryViewType> type(ctxt);
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return type->IsTypeValidForData(view);
}


bool BinaryViewType::IsDeprecatedCallback(void* ctxt)
{
	CallbackRef<BinaryViewType> type(ctxt);
	return type->IsDeprecated();
}


bool BinaryViewType::IsForceLoadableCallback(void* ctxt)
{
	CallbackRef<BinaryViewType> type(ctxt);
	return type->IsForceLoadable();
}


BNSettings* BinaryViewType::GetSettingsCallback(void* ctxt, BNBinaryView* data)
{
	CallbackRef<BinaryViewType> type(ctxt);
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Settings> result = type->GetLoadSettingsForData(view);
	if (!result)
		return nullptr;
	return BNNewSettingsReference(result->GetObject());
}


BinaryViewType::BinaryViewType(BNBinaryViewType* type)
{
	m_object = type;
}


BinaryViewType::BinaryViewType(const string& name, const string& longName) :
    m_nameForRegister(name), m_longNameForRegister(longName)
{
	m_object = nullptr;
}


void BinaryViewType::Register(BinaryViewType* type)
{
	BNCustomBinaryViewType callbacks;
	callbacks.context = type;
	callbacks.create = CreateCallback;
	callbacks.parse = ParseCallback;
	callbacks.isValidForData = IsValidCallback;
	callbacks.isDeprecated = IsDeprecatedCallback;
	callbacks.isForceLoadable = IsForceLoadableCallback;
	callbacks.getLoadSettingsForData = GetSettingsCallback;

	type->AddRefForRegistration();
	type->m_object =
	    BNRegisterBinaryViewType(type->m_nameForRegister.c_str(), type->m_longNameForRegister.c_str(), &callbacks);
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


void BinaryViewType::RegisterPlatformRecognizer(uint64_t id, BNEndianness endian,
    const std::function<Ref<Platform>(BinaryView* view, Metadata* metadata)>& callback)
{
	PlatformRecognizerFunction* ctxt = new PlatformRecognizerFunction;
	ctxt->action = callback;
	BNRegisterPlatformRecognizerForViewType(m_object, id, endian, PlatformRecognizerCallback, ctxt);
}


Ref<Platform> BinaryViewType::RecognizePlatform(uint64_t id, BNEndianness endian, BinaryView* view, Metadata* metadata)
{
	BNPlatform* platform =
	    BNRecognizePlatformForViewType(m_object, id, endian, view->GetObject(), metadata->GetObject());
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

bool BinaryViewType::IsDeprecated()
{
	return false;
}


bool BinaryViewType::IsForceLoadable()
{
	return false;
}


void BinaryViewType::RegisterBinaryViewFinalizationEvent(const function<void(BinaryView* view)>& callback)
{
	BinaryViewEvent* event = new BinaryViewEvent;
	event->action = callback;
	BNRegisterBinaryViewEvent(BinaryViewFinalizationEvent, BinaryViewEventCallback, event);
}


void BinaryViewType::RegisterBinaryViewInitialAnalysisCompletionEvent(const function<void(BinaryView* view)>& callback)
{
	BinaryViewEvent* event = new BinaryViewEvent;
	event->action = callback;
	BNRegisterBinaryViewEvent(BinaryViewInitialAnalysisCompletionEvent, BinaryViewEventCallback, event);
}


void BinaryViewType::BinaryViewEventCallback(void* ctxt, BNBinaryView* view)
{
	BinaryViewEvent* event = (BinaryViewEvent*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	event->action(viewObject);
}


BNPlatform* BinaryViewType::PlatformRecognizerCallback(void* ctxt, BNBinaryView* view, BNMetadata* metadata)
{
	PlatformRecognizerFunction* callback = (PlatformRecognizerFunction*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<Metadata> metadataObject = new Metadata(BNNewMetadataReference(metadata));
	Ref<Platform> result = callback->action(viewObject, metadataObject);
	if (!result)
		return nullptr;
	return BNNewPlatformReference(result->GetObject());
}


Ref<BinaryView> BinaryViewType::Parse(BinaryView* data)
{
	Ref<BinaryView> viewRef;

	// Create ephemeral BinaryView to generate information for preview
	if (data && (GetName() != data->GetTypeName()))
	{
		viewRef = Create(data);
		if (!viewRef || !viewRef->Init())
			LogError("View type '%s' could not be created", GetName().c_str());
	}

	return viewRef;
}


Ref<Settings> BinaryViewType::GetLoadSettingsForData(BinaryView* data)
{
	return GetDefaultLoadSettingsForData(data);
}


Ref<Settings> BinaryViewType::GetDefaultLoadSettingsForData(BinaryView* data)
{
	BNSettings* settings = BNGetBinaryViewDefaultLoadSettingsForData(m_object, data->GetObject());
	if (!settings)
		return nullptr;
	return new Settings(settings);
}


CoreBinaryViewType::CoreBinaryViewType(BNBinaryViewType* type) : BinaryViewType(type) {}


Ref<BinaryView> CoreBinaryViewType::Create(BinaryView* data)
{
	BNBinaryView* view = BNCreateBinaryViewOfType(m_object, data->GetObject());
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


Ref<BinaryView> CoreBinaryViewType::Parse(BinaryView* data)
{
	BNBinaryView* view = BNParseBinaryViewOfType(m_object, data->GetObject());
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


bool CoreBinaryViewType::IsTypeValidForData(BinaryView* data)
{
	return BNIsBinaryViewTypeValidForData(m_object, data->GetObject());
}


bool CoreBinaryViewType::IsDeprecated()
{
	return BNIsBinaryViewTypeDeprecated(m_object);
}


bool CoreBinaryViewType::IsForceLoadable()
{
	return BNIsBinaryViewTypeForceLoadable(m_object);
}


Ref<Settings> CoreBinaryViewType::GetLoadSettingsForData(BinaryView* data)
{
	BNSettings* settings = BNGetBinaryViewLoadSettingsForData(m_object, data->GetObject());
	if (!settings)
		return nullptr;
	return new Settings(settings);
}
