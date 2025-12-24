// Copyright (c) 2015-2025 Vector 35 Inc
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
#include "ffi.h"

using namespace BinaryNinja;
using namespace std;

DatabaseObject::DatabaseObject(BNDatabaseObject* object)
{
	m_object = object;
}


Ref<DatabaseObject> DatabaseObject::GetParent() const
{
	BNDatabaseObject* parent = BNGetDatabaseObjectParent(m_object);
	if (!parent)
	{
		return nullptr;
	}
	return new DatabaseObject(parent);
}


std::string DatabaseObject::GetDescription() const
{
	char* desc = BNGetDatabaseObjectDescription(m_object);
	std::string result = desc;
	BNFreeString(desc);
	return result;
}


Ref<Metadata> DatabaseObject::GetMetadata() const
{
	BNMetadata* metadata = BNGetDatabaseObjectMetadata(m_object);
	if (!metadata)
	{
		return nullptr;
	}
	return new Metadata(metadata);
}


int DatabaseObject::GetType() const
{
	return BNGetDatabaseObjectType(m_object);
}


std::unordered_map<std::string, Ref<DatabaseObject>> DatabaseObject::GetChildren()
{
	char** names;
	BNDatabaseObject** objects;
	size_t count = BNGetDatabaseObjectChildren(m_object, &names, &objects);

	// todo: do we want a cache?

	std::unordered_map<std::string, Ref<DatabaseObject>> result;
	for (size_t i = 0; i < count; i++)
	{
		result[names[i]] = new DatabaseObject(BNNewDatabaseObjectReference(objects[i]));
	}

	BNFreeStringList(names, count);
	BNFreeDatabaseObjectList(objects, count);
	return result;
}


std::vector<std::string> DatabaseObject::GetChildNames()
{
	size_t count = 0;
	char** names = BNGetDatabaseObjectChildNames(m_object, &count);
	std::vector<std::string> result = ParseStringList(names, count);
	BNFreeStringList(names, count);
	return result;
}


std::optional<Ref<DatabaseObject>> DatabaseObject::GetChild(const std::string& key)
{
	BNDatabaseObject* child = BNGetDatabaseObjectChild(m_object, key.c_str());
	if (child)
	{
		return new DatabaseObject(child);
	}
	return std::nullopt;
}


std::optional<Ref<DatabaseObject>> DatabaseObject::FindChild(const std::vector<std::string>& path)
{
	std::vector<const char*> pathCStrs;
	pathCStrs.reserve(path.size());
	for (const auto& item : path)
	{
		pathCStrs.push_back(item.c_str());
	}

	BNDatabaseObject* child = BNFindDatabaseObjectChild(m_object, pathCStrs.data(), pathCStrs.size());
	if (child)
	{
		return new DatabaseObject(child);
	}
	return std::nullopt;
}


std::vector<std::string> DatabaseObject::GetDependencies() const
{
	size_t count = 0;
	char** deps = BNGetDatabaseObjectDependencies(m_object, &count);
	std::vector<std::string> result = ParseStringList(deps, count);
	BNFreeStringList(deps, count);
	return result;
}


DiffState::DiffState(BNDiffState* state)
{
	m_object = state;
}


DiffState::DiffState(Ref<Logger> logger)
{
	m_object = BNCreateDiffState(logger->GetObject());
}


std::vector<std::string> DiffState::GetErrors() const
{
	size_t count = 0;
	char** errors = BNGetDiffStateErrors(m_object, &count);
	std::vector<std::string> result = ParseStringList(errors, count);
	BNFreeStringList(errors, count);
	return result;
}


void DiffState::ClearErrors()
{
	BNClearDiffStateErrors(m_object);
}


Ref<DiffObject> DiffState::GenerateDiff(
	Ref<DatabaseObject> base,
	Ref<DatabaseObject> left,
	Ref<DatabaseObject> right
)
{
	BNDiffObject* diff = BNDiffStateGenerateDiff(
		m_object,
		base ? base->GetObject() : nullptr,
		left ? left->GetObject() : nullptr,
		right ? right->GetObject() : nullptr
	);

	if (!diff)
	{
		return nullptr;
	}
	return new DiffObject(diff);
}


bool DiffState::ApplyDiff(
	Ref<DiffObject> diff,
	Ref<DatabaseObject> base,
	Ref<DatabaseObject> left,
	Ref<DatabaseObject> right,
	Ref<DatabaseObject> result
)
{
	return BNDiffStateApplyDiff(
		m_object,
		diff->GetObject(),
		base ? base->GetObject() : nullptr,
		left ? left->GetObject() : nullptr,
		right ? right->GetObject() : nullptr,
		result->GetObject()
	);
}


bool DiffState::IsDiffed(Ref<DatabaseObject> object) const
{
	return BNDiffStateIsDiffed(m_object, object->GetObject());
}


bool DiffState::IsApplied(Ref<DiffObject> object) const
{
	return BNDiffStateIsApplied(m_object, object->GetObject());
}


DiffObject::DiffObject(BNDiffObject* object)
{
	m_object = object;
}


std::optional<std::string> DiffObject::GetBase() const
{
	char* base = BNGetDiffObjectBase(m_object);
	if (!base)
	{
		return std::nullopt;
	}
	std::string result = base;
	BNFreeString(base);
	return result;
}


std::optional<std::string> DiffObject::GetLeft() const
{
	char* left = BNGetDiffObjectLeft(m_object);
	if (!left)
	{
		return std::nullopt;
	}
	std::string result = left;
	BNFreeString(left);
	return result;
}


std::optional<std::string> DiffObject::GetRight() const
{
	char* right = BNGetDiffObjectRight(m_object);
	if (!right)
	{
		return std::nullopt;
	}
	std::string result = right;
	BNFreeString(right);
	return result;
}


std::unordered_map<std::string, Ref<DiffObject>> DiffObject::GetChildren() const
{
	char** names;
	BNDiffObject** objects;
	size_t count = BNGetDiffObjectChildren(m_object, &names, &objects);

	// todo: do we want a cache?

	std::unordered_map<std::string, Ref<DiffObject>> result;
	for (size_t i = 0; i < count; i++)
	{
		result[names[i]] = new DiffObject(BNNewDiffObjectReference(objects[i]));
	}

	BNFreeStringList(names, count);
	BNFreeDiffObjectList(objects, count);
	return result;
}


BNMergeStrategy DiffObject::GetMergeStrategy() const
{
	return BNGetDiffObjectMergeStrategy(m_object);
}


void DiffObject::SetMergeStrategy(BNMergeStrategy strategy)
{
	BNSetDiffObjectMergeStrategy(m_object, strategy);
}
