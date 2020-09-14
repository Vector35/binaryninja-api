// Copyright (c) 2015-2020 Vector 35 Inc
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
#include <cstring>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace Json;
using namespace std;


KeyValueStore::KeyValueStore(BNKeyValueStore* store)
{
	m_object = store;
}


std::vector<std::string> KeyValueStore::GetKeys() const
{
	size_t count;
	char** keys = BNGetKeyValueStoreKeys(m_object, &count);

	std::vector<std::string> strings;
	strings.reserve(count);
	for (size_t i = 0; i < count; ++i)
	{
		strings.push_back(keys[i]);
	}

	BNFreeStringList(keys, count);
	return strings;
}


bool KeyValueStore::HasValue(const std::string& name) const
{
	return BNKeyValueStoreHasValue(m_object, name.c_str());
}


Json::Value KeyValueStore::GetValue(const std::string& name) const
{
	DataBuffer value = DataBuffer(BNGetKeyValueStoreBuffer(m_object, name.c_str()));
	Json::Value json;
	std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
	std::string errors;
	if (!reader->parse(static_cast<const char*>(value.GetData()),
	                   static_cast<const char*>(value.GetDataAt(value.GetLength())),
	                   &json, &errors))
	{
		throw Exception(errors);
	}
	return json;
}


DataBuffer KeyValueStore::GetBuffer(const std::string& name) const
{
	BNDataBuffer* buffer = BNGetKeyValueStoreBuffer(m_object, name.c_str());
	if (buffer == nullptr)
	{
		throw Exception("Unknown key");
	}
	return DataBuffer(buffer);
}


void KeyValueStore::SetValue(const std::string& name, const Json::Value& value)
{
	BNSetKeyValueStoreValue(m_object, name.c_str(), value.asCString());
}


void KeyValueStore::SetBuffer(const std::string& name, const DataBuffer& value)
{
	BNSetKeyValueStoreBuffer(m_object, name.c_str(), value.GetBufferObject());
}


DataBuffer KeyValueStore::GetSerializedData() const
{
	return DataBuffer(BNGetKeyValueStoreSerializedData(m_object));
}


void KeyValueStore::BeginNamespace(const std::string& name)
{
	BNBeginKeyValueStoreNamespace(m_object, name.c_str());
}


void KeyValueStore::EndNamespace()
{
	BNEndKeyValueStoreNamespace(m_object);
}


bool KeyValueStore::IsEmpty() const
{
	return BNIsKeyValueStoreEmpty(m_object);
}


size_t KeyValueStore::ValueSize() const
{
	return BNGetKeyValueStoreValueSize(m_object);
}


size_t KeyValueStore::DataSize() const
{
	return BNGetKeyValueStoreDataSize(m_object);
}


size_t KeyValueStore::ValueStorageSize() const
{
	return BNGetKeyValueStoreValueStorageSize(m_object);
}


size_t KeyValueStore::NamespaceSize() const
{
	return BNGetKeyValueStoreNamespaceSize(m_object);
}


Snapshot::Snapshot(BNSnapshot* snapshot)
{
	m_object = snapshot;
}


int64_t Snapshot::GetId()
{
	return BNGetSnapshotId(m_object);
}


std::string Snapshot::GetName()
{
	char* cstr = BNGetSnapshotName(m_object);
	std::string str{cstr};
	BNFreeString(cstr);
	return str;
}


bool Snapshot::IsAutoSave()
{
	return BNIsSnapshotAutoSave(m_object);
}


Ref<Snapshot> Snapshot::GetParent()
{
	BNSnapshot* snap = BNGetSnapshotParent(m_object);
	if (snap == nullptr)
		return nullptr;
	return new Snapshot(snap);
}


DataBuffer Snapshot::GetFileContents()
{
	return DataBuffer(BNGetSnapshotFileContents(m_object));
}


vector<UndoEntry> Snapshot::GetUndoEntries()
{
	size_t numEntries;
	BNUndoEntry* entries = BNGetSnapshotUndoEntries(m_object, &numEntries);

	vector<UndoEntry> result;
	result.reserve(numEntries);
	for (size_t i = 0; i < numEntries; i++)
	{
		UndoEntry temp;
		temp.timestamp = entries[i].timestamp;
		temp.hash = entries[i].hash;
		temp.user = new User(BNNewUserReference(entries[i].user));
		size_t actionCount = entries[i].actionCount;
		for (size_t actionIndex = 0; actionIndex < actionCount; actionIndex++)
		{
			temp.actions.emplace_back(entries[i].actions[actionIndex]);
		}
		result.push_back(temp);
	}

	BNFreeUndoEntries(entries, numEntries);
	return result;
}


Ref<KeyValueStore> Snapshot::ReadData()
{
	BNKeyValueStore* store = BNReadSnapshotData(m_object);
	return new KeyValueStore(store);
}


Database::Database(BNDatabase* database)
{
	m_object = database;
}


Ref<Snapshot> Database::GetSnapshot(int64_t id)
{
	BNSnapshot* snap = BNGetDatabaseSnapshot(m_object, id);
	if (snap == nullptr)
		return nullptr;
	return new Snapshot(snap);
}


Ref<Snapshot> Database::GetCurrentSnapshot()
{
	BNSnapshot* snap = BNGetDatabaseCurrentSnapshot(m_object);
	if (snap == nullptr)
		return nullptr;
	return new Snapshot(snap);
}
