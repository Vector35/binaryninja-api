// Copyright (c) 2015-2022 Vector 35 Inc
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

#include "relocationhandler.hpp"
#include "getobject.hpp"
#include "architecture.hpp"
#include "lowlevelil.hpp"

using namespace std;
using namespace BinaryNinja;


RelocationHandler::RelocationHandler(BNRelocationHandler* handler)
{
	m_object = handler;
}


RelocationHandler::RelocationHandler()
{
	BNCustomRelocationHandler handler;
	handler.context = this;
	handler.freeObject = FreeCallback;
	handler.getRelocationInfo = GetRelocationInfoCallback;
	handler.applyRelocation = ApplyRelocationCallback;
	handler.getOperandForExternalRelocation = GetOperandForExternalRelocationCallback;

	AddRefForRegistration();
	m_object = BNCreateRelocationHandler(&handler);
}


void RelocationHandler::FreeCallback(void* ctxt)
{
	RelocationHandler* handler = (RelocationHandler*)ctxt;
	handler->ReleaseForRegistration();
}


bool RelocationHandler::GetRelocationInfoCallback(
    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* result, size_t resultCount)
{
	RelocationHandler* handler = (RelocationHandler*)ctxt;
	Ref<BinaryView> viewObj = CreateNewReferencedView(view);
	Ref<Architecture> archObj = new CoreArchitecture(arch);
	if (!result)
		return false;
	vector<BNRelocationInfo> resultVector(&result[0], &result[resultCount]);
	bool success = handler->GetRelocationInfo(viewObj, archObj, resultVector);
	for (size_t i = 0; i < resultCount; i++)
		result[i] = resultVector[i];
	return success;
}


bool RelocationHandler::ApplyRelocationCallback(
    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len)
{
	RelocationHandler* handler = (RelocationHandler*)ctxt;
	Ref<Architecture> archObj = new CoreArchitecture(arch);
	Ref<BinaryView> viewObj = CreateNewReferencedView(view);
	Ref<Relocation> relocObj = new Relocation(BNNewRelocationReference(reloc));
	return handler->ApplyRelocation(viewObj, archObj, relocObj, dest, len);
}


size_t RelocationHandler::GetOperandForExternalRelocationCallback(
    void* ctxt, const uint8_t* data, uint64_t addr, size_t length, BNLowLevelILFunction* il, BNRelocation* reloc)
{
	RelocationHandler* handler = (RelocationHandler*)ctxt;
	Ref<LowLevelILFunction> func(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)));
	Ref<Relocation> relocObj = new Relocation(BNNewRelocationReference(reloc));
	return handler->GetOperandForExternalRelocation(data, addr, length, func, relocObj);
}


bool RelocationHandler::GetRelocationInfo(
    Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result)
{
	(void)view;
	(void)arch;
	(void)result;
	return false;
}


bool RelocationHandler::ApplyRelocation(
    Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len)
{
	return BNRelocationHandlerDefaultApplyRelocation(
	    m_object, GetView(view), arch->GetObject(), BNNewRelocationReference(reloc->GetObject()), dest, len);
}


size_t RelocationHandler::GetOperandForExternalRelocation(
    const uint8_t* data, uint64_t addr, size_t length, Ref<LowLevelILFunction> il, Ref<Relocation> relocation)
{
	(void)data;
	(void)addr;
	(void)length;
	(void)il;
	(void)relocation;
	return BN_AUTOCOERCE_EXTERN_PTR;
}


CoreRelocationHandler::CoreRelocationHandler(BNRelocationHandler* handler) : RelocationHandler(handler) {}


bool CoreRelocationHandler::ApplyRelocation(
    Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len)
{
	return BNRelocationHandlerApplyRelocation(
	    m_object, GetView(view), arch->GetObject(), BNNewRelocationReference(reloc->GetObject()), dest, len);
}


bool CoreRelocationHandler::GetRelocationInfo(
    Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result)
{
	BNRelocationInfo* results = new BNRelocationInfo[result.size()];
	for (size_t i = 0; i < result.size(); i++)
		results[i] = result[i];
	bool status =
	    BNRelocationHandlerGetRelocationInfo(m_object, GetView(view), arch->GetObject(), results, result.size());
	for (size_t i = 0; i < result.size(); i++)
		result[i] = results[i];
	return status;
}


size_t CoreRelocationHandler::GetOperandForExternalRelocation(
    const uint8_t* data, uint64_t addr, size_t length, Ref<LowLevelILFunction> il, Ref<Relocation> relocation)
{
	return BNRelocationHandlerGetOperandForExternalRelocation(
	    m_object, data, addr, length, il->GetObject(), BNNewRelocationReference(relocation->GetObject()));
}
