#include "binaryninjaapi.h"
#include "ffi.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


BNDerivedString DerivedString::ToAPIStruct(bool owned) const
{
	BNDerivedString result;
	result.value = owned ? BNDuplicateStringRef(value.GetObject()) : value.GetObject();
	result.locationValid = location.has_value();
	if (location.has_value())
	{
		result.location.locationType = location->locationType;
		result.location.addr = location->addr;
		result.location.len = location->len;
	}
	else
	{
		result.location.locationType = DataBackedStringLocation;
		result.location.addr = 0;
		result.location.len = 0;
	}
	result.customType = customType ? customType->GetObject() : nullptr;
	return result;
}


DerivedString DerivedString::FromAPIStruct(BNDerivedString* str, bool owned)
{
	DerivedString result;
	result.value = StringRef(owned ? str->value : BNDuplicateStringRef(str->value));
	if (str->locationValid)
		result.location = {str->location.locationType, str->location.addr, str->location.len};
	result.customType = str->customType ? new CustomStringType(str->customType) : nullptr;
	return result;
}


CustomStringType::CustomStringType(BNCustomStringType* type)
{
	m_object = type;
}


string CustomStringType::GetName() const
{
	char* name = BNGetCustomStringTypeName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string CustomStringType::GetStringPrefix() const
{
	char* prefix = BNGetCustomStringTypePrefix(m_object);
	string result = prefix;
	BNFreeString(prefix);
	return result;
}


string CustomStringType::GetStringPostfix() const
{
	char* postfix = BNGetCustomStringTypePostfix(m_object);
	string result = postfix;
	BNFreeString(postfix);
	return result;
}


Ref<CustomStringType> CustomStringType::Register(
	const std::string& name, const std::string& stringPrefix, const std::string& stringPostfix)
{
	BNCustomStringTypeInfo info;
	info.name = (char*)name.c_str();
	info.stringPrefix = (char*)stringPrefix.c_str();
	info.stringPostfix = (char*)stringPostfix.c_str();
	BNCustomStringType* result = BNRegisterCustomStringType(&info);
	return new CustomStringType(result);
}


StringRecognizer::StringRecognizer(const std::string& name): m_nameForRegister(name)
{
	m_object = nullptr;
}


StringRecognizer::StringRecognizer(BNStringRecognizer* recognizer)
{
	m_object = recognizer;
}


string StringRecognizer::GetName() const
{
	char* name = BNGetStringRecognizerName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


bool StringRecognizer::IsValidForType(HighLevelILFunction*, Type*)
{
	return true;
}


std::optional<DerivedString> StringRecognizer::RecognizeConstant(const HighLevelILInstruction&, Type*, int64_t)
{
	return std::nullopt;
}


std::optional<DerivedString> StringRecognizer::RecognizeConstantPointer(const HighLevelILInstruction&, Type*, int64_t)
{
	return std::nullopt;
}


std::optional<DerivedString> StringRecognizer::RecognizeExternPointer(
	const HighLevelILInstruction&, Type*, int64_t, uint64_t)
{
	return std::nullopt;
}


std::optional<DerivedString> StringRecognizer::RecognizeImport(const HighLevelILInstruction&, Type*, int64_t)
{
	return std::nullopt;
}


std::optional<DerivedString> StringRecognizer::RecognizeConstantData(const HighLevelILInstruction&)
{
	return std::nullopt;
}


std::optional<DerivedString> StringRecognizer::RecognizeStructInit(
	const HighLevelILInstruction&, Type*, const std::map<uint64_t, int64_t>&)
{
	return std::nullopt;
}


void StringRecognizer::Register(StringRecognizer* recognizer)
{
	BNCustomStringRecognizer callbacks;
	callbacks.context = recognizer;
	callbacks.isValidForType = IsValidForTypeCallback;
	callbacks.recognizeConstant = RecognizeConstantCallback;
	callbacks.recognizeConstantPointer = RecognizeConstantPointerCallback;
	callbacks.recognizeExternPointer = RecognizeExternPointerCallback;
	callbacks.recognizeImport = RecognizeImportCallback;
	callbacks.recognizeConstantData = RecognizeConstantDataCallback;
	callbacks.recognizeStructInit = RecognizeStructInitCallback;

	recognizer->AddRefForRegistration();
	recognizer->m_object = BNRegisterStringRecognizer(recognizer->m_nameForRegister.c_str(), &callbacks);
}


bool StringRecognizer::IsValidForTypeCallback(void* ctxt, BNHighLevelILFunction* hlil, BNType* type)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	return recognizer->IsValidForType(hlilObj, typeObj);
}


bool StringRecognizer::RecognizeConstantCallback(
	void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNType* type, int64_t val, BNDerivedString* result)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	auto str = recognizer->RecognizeConstant(instr, typeObj, val);
	if (!str.has_value())
		return false;
	*result = str->ToAPIStruct(true);
	return true;
}


bool StringRecognizer::RecognizeConstantPointerCallback(
	void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNType* type, int64_t val, BNDerivedString* result)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	auto str = recognizer->RecognizeConstantPointer(instr, typeObj, val);
	if (!str.has_value())
		return false;
	*result = str->ToAPIStruct(true);
	return true;
}


bool StringRecognizer::RecognizeExternPointerCallback(void* ctxt, BNHighLevelILFunction* hlil, size_t expr,
	BNType* type, int64_t val, uint64_t offset, BNDerivedString* result)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	auto str = recognizer->RecognizeExternPointer(instr, typeObj, val, offset);
	if (!str.has_value())
		return false;
	*result = str->ToAPIStruct(true);
	return true;
}


bool StringRecognizer::RecognizeImportCallback(
	void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNType* type, int64_t val, BNDerivedString* result)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	auto str = recognizer->RecognizeImport(instr, typeObj, val);
	if (!str.has_value())
		return false;
	*result = str->ToAPIStruct(true);
	return true;
}


bool StringRecognizer::RecognizeConstantDataCallback(
	void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNDerivedString* result)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	auto str = recognizer->RecognizeConstantData(instr);
	if (!str.has_value())
		return false;
	*result = str->ToAPIStruct(true);
	return true;
}


bool StringRecognizer::RecognizeStructInitCallback(void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNType* type,
	const uint64_t* fieldOffsets, const int64_t* fieldValues, size_t fieldCount, BNDerivedString* result)
{
	StringRecognizer* recognizer = (StringRecognizer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	std::map<uint64_t, int64_t> values;
	for (size_t i = 0; i < fieldCount; i++)
		values.emplace(fieldOffsets[i], fieldValues[i]);
	auto str = recognizer->RecognizeStructInit(instr, typeObj, values);
	if (!str.has_value())
		return false;
	*result = str->ToAPIStruct(true);
	return true;
}


Ref<StringRecognizer> StringRecognizer::GetByName(const std::string& name)
{
	BNStringRecognizer* recognizer = BNGetStringRecognizerByName(name.c_str());
	if (!recognizer)
		return nullptr;
    return new CoreStringRecognizer(recognizer);
}


vector<Ref<StringRecognizer>> StringRecognizer::GetRecognizers()
{
	size_t count = 0;
    BNStringRecognizer** recognizers = BNGetStringRecognizerList(&count);

    vector<Ref<StringRecognizer>> result;
    result.reserve(count);
    for (size_t i = 0; i < count; i++)
        result.push_back(new CoreStringRecognizer(recognizers[i]));

    BNFreeStringRecognizerList(recognizers);
    return result;
}


CoreStringRecognizer::CoreStringRecognizer(BNStringRecognizer* recognizer):
    StringRecognizer(recognizer)
{
}


bool CoreStringRecognizer::IsValidForType(HighLevelILFunction* func, Type* type)
{
	return BNIsStringRecognizerValidForType(m_object, func->GetObject(), type->GetObject());
}


std::optional<DerivedString> CoreStringRecognizer::RecognizeConstant(
	const HighLevelILInstruction& instr, Type* type, int64_t val)
{
	BNDerivedString str;
	if (!BNStringRecognizerRecognizeConstant(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), val, &str))
		return std::nullopt;
	return DerivedString::FromAPIStruct(&str, true);
}


std::optional<DerivedString> CoreStringRecognizer::RecognizeConstantPointer(
	const HighLevelILInstruction& instr, Type* type, int64_t val)
{
	BNDerivedString str;
	if (!BNStringRecognizerRecognizeConstantPointer(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), val, &str))
		return std::nullopt;
	return DerivedString::FromAPIStruct(&str, true);
}


std::optional<DerivedString> CoreStringRecognizer::RecognizeExternPointer(
	const HighLevelILInstruction& instr, Type* type, int64_t val, uint64_t offset)
{
	BNDerivedString str;
	if (!BNStringRecognizerRecognizeExternPointer(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), val, offset, &str))
		return std::nullopt;
	return DerivedString::FromAPIStruct(&str, true);
}


std::optional<DerivedString> CoreStringRecognizer::RecognizeImport(
	const HighLevelILInstruction& instr, Type* type, int64_t val)
{
	BNDerivedString str;
	if (!BNStringRecognizerRecognizeImport(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), val, &str))
		return std::nullopt;
	return DerivedString::FromAPIStruct(&str, true);
}


std::optional<DerivedString> CoreStringRecognizer::RecognizeConstantData(
	const HighLevelILInstruction& instr)
{
	BNDerivedString str;
	if (!BNStringRecognizerRecognizeConstantData(m_object, instr.function->GetObject(), instr.exprIndex, &str))
		return std::nullopt;
	return DerivedString::FromAPIStruct(&str, true);
}


std::optional<DerivedString> CoreStringRecognizer::RecognizeStructInit(
	const HighLevelILInstruction& instr, Type* type, const std::map<uint64_t, int64_t>& values)
{
	std::vector<uint64_t> fieldOffsets;
	std::vector<int64_t> fieldValues;
	fieldOffsets.reserve(values.size());
	fieldValues.reserve(values.size());
	for (auto [offset, value] : values)
	{
		fieldOffsets.push_back(offset);
		fieldValues.push_back(value);
	}

	BNDerivedString str;
	if (!BNStringRecognizerRecognizeStructInit(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), fieldOffsets.data(), fieldValues.data(), values.size(), &str))
		return std::nullopt;
	return DerivedString::FromAPIStruct(&str, true);
}
