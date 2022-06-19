// Copyright (c) 2020-2022 Vector 35 Inc
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

#include "core/basicblock.h"
#include "basicblock.hpp"
#include "core/linearviewobject.h"
#include "linearviewobject.hpp"
#include "tag.hpp"
#include "getobject.hpp"

using namespace std;
using namespace BinaryNinja;


LinearDisassemblyLine LinearDisassemblyLine::FromAPIObject(BNLinearDisassemblyLine* line)
{
	LinearDisassemblyLine result;
	result.type = line->type;
	result.function = CreateNewReferencedFunction(line->function);
	result.block = CreateNewReferencedBasicBlock(line->block);
	result.contents.addr = line->contents.addr;
	result.contents.instrIndex = line->contents.instrIndex;
	result.contents.highlight = line->contents.highlight;
	result.contents.tokens =
	    InstructionTextToken::ConvertInstructionTextTokenList(line->contents.tokens, line->contents.count);
	result.contents.tags = Tag::ConvertTagList(line->contents.tags, line->contents.tagCount);
	result.contents.typeInfo.hasTypeInfo = line->contents.typeInfo.hasTypeInfo;
	result.contents.typeInfo.fieldIndex = line->contents.typeInfo.fieldIndex;
	result.contents.typeInfo.parentType = CreateNewReferencedType(line->contents.typeInfo.parentType);
	result.contents.typeInfo.offset = line->contents.typeInfo.offset;
	return result;
}


LinearViewObjectIdentifier::LinearViewObjectIdentifier() : type(SingleLinearViewObject), start(0), end(0) {}


LinearViewObjectIdentifier::LinearViewObjectIdentifier(const string& _name) :
    name(_name), type(SingleLinearViewObject), start(0), end(0)
{}


LinearViewObjectIdentifier::LinearViewObjectIdentifier(const string& _name, uint64_t addr) :
    name(_name), type(AddressLinearViewObject), start(addr), end(addr)
{}


LinearViewObjectIdentifier::LinearViewObjectIdentifier(const string& _name, uint64_t _start, uint64_t _end) :
    name(_name), type(AddressRangeLinearViewObject), start(_start), end(_end)
{}


LinearViewObjectIdentifier::LinearViewObjectIdentifier(const LinearViewObjectIdentifier& other) :
    name(other.name), type(other.type), start(other.start), end(other.end)
{}


LinearViewObject::LinearViewObject(BNLinearViewObject* obj)
{
	m_object = obj;
}


Ref<LinearViewObject> LinearViewObject::GetFirstChild()
{
	BNLinearViewObject* result = BNGetFirstLinearViewObjectChild(m_object);
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


Ref<LinearViewObject> LinearViewObject::GetLastChild()
{
	BNLinearViewObject* result = BNGetLastLinearViewObjectChild(m_object);
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


Ref<LinearViewObject> LinearViewObject::GetPreviousChild(LinearViewObject* obj)
{
	BNLinearViewObject* result = BNGetPreviousLinearViewObjectChild(m_object, obj->GetObject());
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


Ref<LinearViewObject> LinearViewObject::GetNextChild(LinearViewObject* obj)
{
	BNLinearViewObject* result = BNGetNextLinearViewObjectChild(m_object, obj->GetObject());
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


Ref<LinearViewObject> LinearViewObject::GetChildForAddress(uint64_t addr)
{
	BNLinearViewObject* result = BNGetLinearViewObjectChildForAddress(m_object, addr);
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


Ref<LinearViewObject> LinearViewObject::GetChildForIdentifier(const LinearViewObjectIdentifier& id)
{
	BNLinearViewObjectIdentifier lvid;
	lvid.name = BNAllocString(id.name.c_str());
	lvid.type = id.type;
	lvid.start = id.start;
	lvid.end = id.end;
	BNLinearViewObject* result = BNGetLinearViewObjectChildForIdentifier(m_object, &lvid);
	BNFreeString(lvid.name);
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


int LinearViewObject::CompareChildren(LinearViewObject* a, LinearViewObject* b)
{
	return BNCompareLinearViewObjectChildren(m_object, a->GetObject(), b->GetObject());
}


vector<LinearDisassemblyLine> LinearViewObject::GetLines(LinearViewObject* prev, LinearViewObject* next)
{
	size_t count;
	BNLinearDisassemblyLine* lines = BNGetLinearViewObjectLines(
	    m_object, prev ? prev->GetObject() : nullptr, next ? next->GetObject() : nullptr, &count);

	vector<LinearDisassemblyLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(LinearDisassemblyLine::FromAPIObject(&lines[i]));

	BNFreeLinearDisassemblyLines(lines, count);
	return result;
}


uint64_t LinearViewObject::GetStart() const
{
	return BNGetLinearViewObjectStart(m_object);
}


uint64_t LinearViewObject::GetEnd() const
{
	return BNGetLinearViewObjectEnd(m_object);
}


LinearViewObjectIdentifier LinearViewObject::GetIdentifier() const
{
	BNLinearViewObjectIdentifier id = BNGetLinearViewObjectIdentifier(m_object);
	LinearViewObjectIdentifier result;
	result.name = id.name;
	result.type = id.type;
	result.start = id.start;
	result.end = id.end;
	BNFreeLinearViewObjectIdentifier(&id);
	return result;
}


uint64_t LinearViewObject::GetOrderingIndexTotal() const
{
	return BNGetLinearViewObjectOrderingIndexTotal(m_object);
}


uint64_t LinearViewObject::GetOrderingIndexForChild(LinearViewObject* obj) const
{
	return BNGetLinearViewObjectOrderingIndexForChild(m_object, obj->GetObject());
}


Ref<LinearViewObject> LinearViewObject::GetChildForOrderingIndex(uint64_t idx)
{
	BNLinearViewObject* result = BNGetLinearViewObjectChildForOrderingIndex(m_object, idx);
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


Ref<LinearViewObject> LinearViewObject::CreateDisassembly(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewDisassembly(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateLiftedIL(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewLiftedIL(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateLowLevelIL(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewLowLevelIL(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateLowLevelILSSAForm(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewLowLevelILSSAForm(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateMediumLevelIL(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewMediumLevelIL(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewMediumLevelILSSAForm(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateMappedMediumLevelIL(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewMappedMediumLevelIL(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateMappedMediumLevelILSSAForm(
    BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewMappedMediumLevelILSSAForm(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateHighLevelIL(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewHighLevelIL(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateHighLevelILSSAForm(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewHighLevelILSSAForm(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateLanguageRepresentation(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewLanguageRepresentation(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateDataOnly(BinaryView* view, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewDataOnly(BinaryNinja::GetObject(view), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionDisassembly(Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewSingleFunctionDisassembly(BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionLiftedIL(Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewSingleFunctionLiftedIL(BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionLowLevelIL(Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewSingleFunctionLowLevelIL(BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionLowLevelILSSAForm(
    Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(BNCreateLinearViewSingleFunctionLowLevelILSSAForm(
	    BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionMediumLevelIL(Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewSingleFunctionMediumLevelIL(BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionMediumLevelILSSAForm(
    Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(
	    BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionMappedMediumLevelIL(
    Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(BNCreateLinearViewSingleFunctionMappedMediumLevelIL(
	    BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionMappedMediumLevelILSSAForm(
    Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(BNCreateLinearViewSingleFunctionMappedMediumLevelILSSAForm(
	    BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionHighLevelIL(Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(
	    BNCreateLinearViewSingleFunctionHighLevelIL(BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionHighLevelILSSAForm(
    Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(BNCreateLinearViewSingleFunctionHighLevelILSSAForm(
	    BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}


Ref<LinearViewObject> LinearViewObject::CreateSingleFunctionLanguageRepresentation(
    Function* func, DisassemblySettings* settings)
{
	return new LinearViewObject(BNCreateLinearViewSingleFunctionLanguageRepresentation(
	    BinaryNinja::GetObject(func), BinaryNinja::GetObject(settings)));
}
