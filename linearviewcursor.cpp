// Copyright (c) 2020-2024 Vector 35 Inc
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

using namespace std;
using namespace BinaryNinja;


LinearViewCursor::LinearViewCursor(LinearViewObject* root)
{
	m_object = BNCreateLinearViewCursor(root->GetObject());
}


LinearViewCursor::LinearViewCursor(BNLinearViewCursor* cursor)
{
	m_object = cursor;
}


bool LinearViewCursor::IsBeforeBegin() const
{
	return BNIsLinearViewCursorBeforeBegin(m_object);
}


bool LinearViewCursor::IsAfterEnd() const
{
	return BNIsLinearViewCursorAfterEnd(m_object);
}


bool LinearViewCursor::IsValid() const
{
	return !(IsBeforeBegin() || IsAfterEnd());
}


Ref<LinearViewObject> LinearViewCursor::GetCurrentObject() const
{
	BNLinearViewObject* result = BNGetLinearViewCursorCurrentObject(m_object);
	if (result)
		return new LinearViewObject(result);
	return nullptr;
}


vector<LinearViewObjectIdentifier> LinearViewCursor::GetPath() const
{
	size_t count;
	BNLinearViewObjectIdentifier* path = BNGetLinearViewCursorPath(m_object, &count);
	vector<LinearViewObjectIdentifier> result;
	for (size_t i = 0; i < count; i++)
	{
		LinearViewObjectIdentifier id;
		id.name = path[i].name;
		id.type = path[i].type;
		id.start = path[i].start;
		id.end = path[i].end;
		result.push_back(id);
	}
	BNFreeLinearViewCursorPath(path, count);
	return result;
}


vector<Ref<LinearViewObject>> LinearViewCursor::GetPathObjects() const
{
	size_t count;
	BNLinearViewObject** path = BNGetLinearViewCursorPathObjects(m_object, &count);
	vector<Ref<LinearViewObject>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new LinearViewObject(BNNewLinearViewObjectReference(path[i])));
	BNFreeLinearViewCursorPathObjects(path, count);
	return result;
}


BNAddressRange LinearViewCursor::GetOrderingIndex() const
{
	return BNGetLinearViewCursorOrderingIndex(m_object);
}


uint64_t LinearViewCursor::GetOrderingIndexTotal() const
{
	return BNGetLinearViewCursorOrderingIndexTotal(m_object);
}


void LinearViewCursor::SeekToBegin()
{
	BNSeekLinearViewCursorToBegin(m_object);
}


void LinearViewCursor::SeekToEnd()
{
	BNSeekLinearViewCursorToEnd(m_object);
}


void LinearViewCursor::SeekToAddress(uint64_t addr)
{
	BNSeekLinearViewCursorToAddress(m_object, addr);
}


bool LinearViewCursor::SeekToPath(const vector<LinearViewObjectIdentifier>& path)
{
	BNLinearViewObjectIdentifier* ids = new BNLinearViewObjectIdentifier[path.size()];
	for (size_t i = 0; i < path.size(); i++)
	{
		ids[i].name = BNAllocString(path[i].name.c_str());
		ids[i].type = path[i].type;
		ids[i].start = path[i].start;
		ids[i].end = path[i].end;
	}
	bool result = BNSeekLinearViewCursorToPath(m_object, ids, path.size());
	for (size_t i = 0; i < path.size(); i++)
		BNFreeString(ids[i].name);
	delete[] ids;
	return result;
}


bool LinearViewCursor::SeekToPath(const vector<LinearViewObjectIdentifier>& path, uint64_t addr)
{
	BNLinearViewObjectIdentifier* ids = new BNLinearViewObjectIdentifier[path.size()];
	for (size_t i = 0; i < path.size(); i++)
	{
		ids[i].name = BNAllocString(path[i].name.c_str());
		ids[i].type = path[i].type;
		ids[i].start = path[i].start;
		ids[i].end = path[i].end;
	}
	bool result = BNSeekLinearViewCursorToPathAndAddress(m_object, ids, path.size(), addr);
	for (size_t i = 0; i < path.size(); i++)
		BNFreeString(ids[i].name);
	delete[] ids;
	return result;
}


bool LinearViewCursor::SeekToPath(LinearViewCursor* cursor)
{
	return BNSeekLinearViewCursorToCursorPath(m_object, cursor->GetObject());
}


bool LinearViewCursor::SeekToPath(LinearViewCursor* cursor, uint64_t addr)
{
	return BNSeekLinearViewCursorToCursorPathAndAddress(m_object, cursor->GetObject(), addr);
}


void LinearViewCursor::SeekToOrderingIndex(uint64_t idx)
{
	BNSeekLinearViewCursorToOrderingIndex(m_object, idx);
}


bool LinearViewCursor::Next()
{
	return BNLinearViewCursorNext(m_object);
}


bool LinearViewCursor::Previous()
{
	return BNLinearViewCursorPrevious(m_object);
}


vector<LinearDisassemblyLine> LinearViewCursor::GetLines()
{
	size_t count;
	BNLinearDisassemblyLine* lines = BNGetLinearViewCursorLines(m_object, &count);

	vector<LinearDisassemblyLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(LinearDisassemblyLine::FromAPIObject(&lines[i]));

	BNFreeLinearDisassemblyLines(lines, count);
	return result;
}


Ref<LinearViewCursor> LinearViewCursor::Duplicate()
{
	return new LinearViewCursor(BNDuplicateLinearViewCursor(m_object));
}


std::vector<RenderLayer*> LinearViewCursor::GetRenderLayers() const
{
	size_t count = 0;
	BNRenderLayer** layers = BNGetLinearViewCursorRenderLayers(m_object, &count);
	std::vector<RenderLayer*> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back(new CoreRenderLayer(layers[i]));
	}
	BNFreeRenderLayerList(layers);
	return result;
}


void LinearViewCursor::AddRenderLayer(RenderLayer* layer)
{
	BNAddLinearViewCursorRenderLayer(m_object, layer->GetObject());
}


void LinearViewCursor::RemoveRenderLayer(RenderLayer* layer)
{
	BNRemoveLinearViewCursorRenderLayer(m_object, layer->GetObject());
}


int LinearViewCursor::Compare(LinearViewCursor* a, LinearViewCursor* b)
{
	return BNCompareLinearViewCursors(a->GetObject(), b->GetObject());
}
