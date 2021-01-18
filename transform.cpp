// Copyright (c) 2015-2021 Vector 35 Inc
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


Transform::Transform(BNTransform* xform)
{
	m_object = xform;
}


Transform::Transform(BNTransformType type, const string& name, const string& longName, const string& group):
	m_typeForRegister(type), m_nameForRegister(name), m_longNameForRegister(longName),
	m_groupForRegister(group)
{
	m_object = nullptr;
}


BNTransformParameterInfo* Transform::GetParametersCallback(void* ctxt, size_t* count)
{
	Transform* xform = (Transform*)ctxt;
	vector<TransformParameter> params = xform->GetParameters();
	*count = params.size();
	BNTransformParameterInfo* result = new BNTransformParameterInfo[params.size()];

	for (size_t i = 0; i < params.size(); i++)
	{
		result[i].name = BNAllocString(params[i].name.c_str());
		result[i].longName = BNAllocString(params[i].longName.c_str());
		result[i].fixedLength = params[i].fixedLength;
	}

	return result;
}


void Transform::FreeParametersCallback(BNTransformParameterInfo* params, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNFreeString(params[i].name);
		BNFreeString(params[i].longName);
	}
	delete[] params;
}


bool Transform::DecodeCallback(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount)
{
	map<string, DataBuffer> paramMap;
	for (size_t i = 0; i < paramCount; i++)
		paramMap[params[i].name] = DataBuffer(BNDuplicateDataBuffer(params[i].value));

	DataBuffer inputBuf(BNDuplicateDataBuffer(input));
	DataBuffer outputBuf;

	Transform* xform = (Transform*)ctxt;
	bool result = xform->Decode(inputBuf, outputBuf, paramMap);
	BNAssignDataBuffer(output, outputBuf.GetBufferObject());
	return result;
}


bool Transform::EncodeCallback(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount)
{
	map<string, DataBuffer> paramMap;
	for (size_t i = 0; i < paramCount; i++)
		paramMap[params[i].name] = DataBuffer(BNDuplicateDataBuffer(params[i].value));

	DataBuffer inputBuf(BNDuplicateDataBuffer(input));
	DataBuffer outputBuf;

	Transform* xform = (Transform*)ctxt;
	bool result = xform->Encode(inputBuf, outputBuf, paramMap);
	BNAssignDataBuffer(output, outputBuf.GetBufferObject());
	return result;
}


vector<TransformParameter> Transform::EncryptionKeyParameters(size_t fixedKeyLength)
{
	vector<TransformParameter> params;
	TransformParameter key;
	key.name = "key";
	key.longName = "Encryption key";
	key.fixedLength = fixedKeyLength;
	params.push_back(key);
	return params;
}


vector<TransformParameter> Transform::EncryptionKeyAndIVParameters(size_t fixedKeyLength, size_t fixedIVLength)
{
	vector<TransformParameter> params;
	TransformParameter key, iv;
	key.name = "key";
	key.longName = "Encryption key";
	key.fixedLength = fixedKeyLength;
	iv.name = "iv";
	iv.longName = "Initialization vector";
	iv.fixedLength = fixedIVLength;
	params.push_back(key);
	params.push_back(iv);
	return params;
}


void Transform::Register(Transform* xform)
{
	BNCustomTransform callbacks;
	callbacks.context = xform;
	callbacks.getParameters = GetParametersCallback;
	callbacks.freeParameters = FreeParametersCallback;
	callbacks.decode = DecodeCallback;
	callbacks.encode = EncodeCallback;
	xform->AddRefForRegistration();
	xform->m_object = BNRegisterTransformType(xform->m_typeForRegister, xform->m_nameForRegister.c_str(),
	                                          xform->m_longNameForRegister.c_str(), xform->m_groupForRegister.c_str(),
	                                          &callbacks);
}


Ref<Transform> Transform::GetByName(const string& name)
{
	BNTransform* result = BNGetTransformByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreTransform(result);
}


vector<Ref<Transform>> Transform::GetTransformTypes()
{
	size_t count;
	BNTransform** list = BNGetTransformTypeList(&count);

	vector<Ref<Transform>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreTransform(list[i]));

	BNFreeTransformTypeList(list);
	return result;
}


BNTransformType Transform::GetType() const
{
	return BNGetTransformType(m_object);
}


string Transform::GetName() const
{
	char* name = BNGetTransformName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string Transform::GetLongName() const
{
	char* name = BNGetTransformLongName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string Transform::GetGroup() const
{
	char* name = BNGetTransformGroup(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<TransformParameter> Transform::GetParameters() const
{
	return vector<TransformParameter>();
}


bool Transform::Decode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	if (GetType() == InvertingTransform)
		return Encode(input, output, params);
	return false;
}


bool Transform::Encode(const DataBuffer&, DataBuffer&, const map<string, DataBuffer>&)
{
	return false;
}


CoreTransform::CoreTransform(BNTransform* xform): Transform(xform)
{
}


vector<TransformParameter> CoreTransform::GetParameters() const
{
	size_t count;
	BNTransformParameterInfo* list = BNGetTransformParameterList(m_object, &count);

	vector<TransformParameter> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TransformParameter param;
		param.name = list[i].name;
		param.longName = list[i].longName;
		param.fixedLength = list[i].fixedLength;
		result.push_back(param);
	}

	BNFreeTransformParameterList(list, count);
	return result;
}


bool CoreTransform::Decode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	BNTransformParameter* list = new BNTransformParameter[params.size()];
	size_t idx = 0;
	for (auto& i : params)
	{
		list[idx].name = i.first.c_str();
		list[idx++].value = i.second.GetBufferObject();
	}

	bool result = BNDecode(m_object, input.GetBufferObject(), output.GetBufferObject(), list, idx);

	delete[] list;
	return result;
}


bool CoreTransform::Encode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	BNTransformParameter* list = new BNTransformParameter[params.size()];
	size_t idx = 0;
	for (auto& i : params)
	{
		list[idx].name = i.first.c_str();
		list[idx++].value = i.second.GetBufferObject();
	}

	bool result = BNEncode(m_object, input.GetBufferObject(), output.GetBufferObject(), list, idx);

	delete[] list;
	return result;
}
