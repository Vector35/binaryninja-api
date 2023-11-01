// Copyright (c) 2015-2023 Vector 35 Inc
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


void TypeArchiveNotification::OnTypeAddedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* definition)
{
	TypeArchiveNotification* notify = reinterpret_cast<TypeArchiveNotification*>(ctx);
	Ref<TypeArchive> cppArchive = new TypeArchive(BNNewTypeArchiveReference(archive));
	Ref<Type> cppDefinition = new Type(BNNewTypeReference(definition));
	notify->OnTypeAdded(cppArchive, id, cppDefinition);
}


void TypeArchiveNotification::OnTypeUpdatedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* oldDefinition, BNType* newDefinition)
{
	TypeArchiveNotification* notify = reinterpret_cast<TypeArchiveNotification*>(ctx);
	Ref<TypeArchive> cppArchive = new TypeArchive(BNNewTypeArchiveReference(archive));
	Ref<Type> cppOldDefinition = new Type(BNNewTypeReference(oldDefinition));
	Ref<Type> cppNewDefinition = new Type(BNNewTypeReference(newDefinition));
	notify->OnTypeUpdated(cppArchive, id, cppOldDefinition, cppNewDefinition);
}


void TypeArchiveNotification::OnTypeRenamedCallback(void* ctx, BNTypeArchive* archive, const char* id, const BNQualifiedName* oldName, const BNQualifiedName* newName)
{
	TypeArchiveNotification* notify = reinterpret_cast<TypeArchiveNotification*>(ctx);
	Ref<TypeArchive> cppArchive = new TypeArchive(BNNewTypeArchiveReference(archive));
	QualifiedName appOldName = QualifiedName::FromAPIObject(oldName);
	QualifiedName appNewName = QualifiedName::FromAPIObject(newName);
	notify->OnTypeRenamed(cppArchive, id, oldName, newName);
}


void TypeArchiveNotification::OnTypeDeletedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* definition)
{
	TypeArchiveNotification* notify = reinterpret_cast<TypeArchiveNotification*>(ctx);
	Ref<TypeArchive> cppArchive = new TypeArchive(BNNewTypeArchiveReference(archive));
	Ref<Type> cppDefinition = new Type(BNNewTypeReference(definition));
	notify->OnTypeDeleted(cppArchive, id, cppDefinition);
}


TypeArchiveNotification::TypeArchiveNotification()
{
	m_callbacks.context = this;
	m_callbacks.typeAdded = OnTypeAddedCallback;
	m_callbacks.typeUpdated = OnTypeUpdatedCallback;
	m_callbacks.typeRenamed = OnTypeRenamedCallback;
	m_callbacks.typeDeleted = OnTypeDeletedCallback;
}


TypeArchive::TypeArchive(BNTypeArchive* archive)
{
	m_object = archive;
}


Ref<TypeArchive> TypeArchive::Open(const std::string& path)
{
	BNTypeArchive* handle = BNOpenTypeArchive(path.c_str());
	if (!handle)
		return nullptr;
	return new TypeArchive(handle);
}


Ref<TypeArchive> TypeArchive::Create(const std::string& path, Ref<Platform> platform)
{
	BNTypeArchive* handle = BNCreateTypeArchive(path.c_str(), platform->GetObject());
	if (!handle)
		return nullptr;
	return new TypeArchive(handle);
}


Ref<TypeArchive> TypeArchive::CreateWithId(const std::string& path, Ref<Platform> platform, const std::string& id)
{
	BNTypeArchive* handle = BNCreateTypeArchiveWithId(path.c_str(), platform->GetObject(), id.c_str());
	if (!handle)
		return nullptr;
	return new TypeArchive(handle);
}


Ref<TypeArchive> TypeArchive::LookupById(const std::string& id)
{
	BNTypeArchive* handle = BNLookupTypeArchiveById(id.c_str());
	if (!handle)
		return nullptr;
	return new TypeArchive(handle);
}


void TypeArchive::Close(Ref<TypeArchive> archive)
{
	BNCloseTypeArchive(archive->GetObject());
}


bool TypeArchive::IsTypeArchive(const std::string& path)
{
	return BNIsTypeArchive(path.c_str());
}


std::string TypeArchive::GetId() const
{
	char* str = BNGetTypeArchiveId(m_object);
	std::string result(str);
	BNFreeString(str);
	return result;
}


std::string TypeArchive::GetPath() const
{
	char* str = BNGetTypeArchivePath(m_object);
	std::string result(str);
	BNFreeString(str);
	return result;
}


Ref<Platform> TypeArchive::GetPlatform() const
{
	BNPlatform* platform = BNGetTypeArchivePlatform(m_object);
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


std::string TypeArchive::GetCurrentSnapshotId() const
{
	char* str = BNGetTypeArchiveCurrentSnapshotId(m_object);
	if (!str)
		throw ExceptionWithStackTrace("BNGetTypeArchiveCurrentSnapshotId");
	std::string result(str);
	BNFreeString(str);
	return result;
}


void TypeArchive::SetCurrentSnapshot(const std::string& id)
{
	BNSetTypeArchiveCurrentSnapshot(m_object, id.c_str());
}


std::vector<std::string> TypeArchive::GetAllSnapshotIds() const
{
	size_t count = 0;
	char** ids = BNGetTypeArchiveAllSnapshotIds(m_object, &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveAllSnapshotIds");

	std::vector<std::string> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back(ids[i]);
	}

	BNFreeStringList(ids, count);
	return result;
}


std::vector<std::string> TypeArchive::GetSnapshotParentIds(const std::string& id) const
{
	size_t count = 0;
	char** ids = BNGetTypeArchiveSnapshotParentIds(m_object, id.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveSnapshotParentIds");

	std::vector<std::string> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back(ids[i]);
	}

	BNFreeStringList(ids, count);
	return result;
}


std::vector<std::string> TypeArchive::GetSnapshotChildIds(const std::string& id) const
{
	size_t count = 0;
	char** ids = BNGetTypeArchiveSnapshotChildIds(m_object, id.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveSnapshotChildIds");

	std::vector<std::string> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back(ids[i]);
	}

	BNFreeStringList(ids, count);
	return result;
}


TypeContainer TypeArchive::GetTypeContainer() const
{
	return TypeContainer(BNGetTypeArchiveTypeContainer(m_object));
}


bool TypeArchive::AddTypes(const std::vector<QualifiedNameAndType>& types)
{
	std::vector<BNQualifiedNameAndType> apiTypes;
	for (auto& type : types)
	{
		BNQualifiedNameAndType qnat;
		qnat.name = type.name.GetAPIObject();
		qnat.type = type.type->GetObject();
		apiTypes.push_back(qnat);
	}
	bool result = BNAddTypeArchiveTypes(m_object, apiTypes.data(), apiTypes.size());
	for (auto& type: apiTypes)
	{
		QualifiedName::FreeAPIObject(&type.name);
	}
	return result;
}


bool TypeArchive::RenameType(const std::string& id, const QualifiedName& newName)
{
	BNQualifiedName qname = newName.GetAPIObject();
	bool result = BNRenameTypeArchiveType(m_object, id.c_str(), &qname);
	QualifiedName::FreeAPIObject(&qname);
	return result;
}


bool TypeArchive::DeleteType(const std::string& id)
{
	return BNDeleteTypeArchiveType(m_object, id.c_str());
}


Ref<Type> TypeArchive::GetTypeById(const std::string& id, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	BNType* type = BNGetTypeArchiveTypeById(m_object, id.c_str(), snapshot.c_str());
	if (!type)
		return nullptr;
	return new Type(type);
}


Ref<Type> TypeArchive::GetTypeByName(const QualifiedName& name, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	BNQualifiedName qname = name.GetAPIObject();
	BNType* type = BNGetTypeArchiveTypeByName(m_object, &qname, snapshot.c_str());
	QualifiedName::FreeAPIObject(&qname);
	if (!type)
		return nullptr;
	return new Type(type);
}


std::string TypeArchive::GetTypeId(const QualifiedName& name, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	BNQualifiedName qname = name.GetAPIObject();
	char* id = BNGetTypeArchiveTypeId(m_object, &qname, snapshot.c_str());
	QualifiedName::FreeAPIObject(&qname);
	if (!id)
		return "";
	std::string result = id;
	BNFreeString(id);
	return result;

}


QualifiedName TypeArchive::GetTypeName(const std::string& id, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	BNQualifiedName qname = BNGetTypeArchiveTypeName(m_object, id.c_str(), snapshot.c_str());
	QualifiedName result = QualifiedName::FromAPIObject(&qname);
	BNFreeQualifiedName(&qname);
	return result;
}


std::unordered_map<std::string, QualifiedNameAndType> TypeArchive::GetTypes(std::string snapshot) const
{
	if (snapshot.empty())
	snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	BNQualifiedNameTypeAndId* types = BNGetTypeArchiveTypes(m_object, snapshot.c_str(), &count);
	if (!types)
		throw ExceptionWithStackTrace("BNGetTypeArchiveTypes");

	std::unordered_map<std::string, QualifiedNameAndType> result;
	for (size_t i = 0; i < count; ++i)
	{
		std::string id = types[i].id;
		QualifiedNameAndType qnat;
		qnat.name = QualifiedName::FromAPIObject(&types[i].name);
		qnat.type = new Type(BNNewTypeReference(types[i].type));
		result.emplace(id, qnat);
	}
	BNFreeTypeIdList(types, count);
	return result;
}


std::vector<std::string> TypeArchive::GetTypeIds(std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	char** ids = BNGetTypeArchiveTypeIds(m_object, snapshot.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveTypeIds");

	std::vector<std::string> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(ids[i]);
	}
	BNFreeStringList(ids, count);
	return result;
}


std::vector<QualifiedName> TypeArchive::GetTypeNames(std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	BNQualifiedName* names = BNGetTypeArchiveTypeNames(m_object, snapshot.c_str(), &count);
	if (!names)
		throw ExceptionWithStackTrace("BNGetTypeArchiveTypeNames");

	std::vector<QualifiedName> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(QualifiedName::FromAPIObject(&names[i]));
	}
	BNFreeTypeNameList(names, count);
	return result;
}


std::unordered_map<std::string, QualifiedName> TypeArchive::GetTypeNamesAndIds(std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	BNQualifiedName* names = nullptr;
	char** ids = nullptr;
	size_t count = 0;
	if (!BNGetTypeArchiveTypeNamesAndIds(m_object, snapshot.c_str(), &names, &ids, &count))
		throw ExceptionWithStackTrace("BNGetTypeArchiveTypeNamesAndIds");

	std::unordered_map<std::string, QualifiedName> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace(ids[i], QualifiedName::FromAPIObject(&names[i]));
	}
	BNFreeTypeNameList(names, count);
	BNFreeStringList(ids, count);
	return result;
}


std::unordered_set<std::string> TypeArchive::GetOutgoingDirectTypeReferences(const std::string& id, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	char** ids = BNGetTypeArchiveOutgoingDirectTypeReferences(m_object, id.c_str(), snapshot.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveOutgoingDirectTypeReferences");

	std::unordered_set<std::string> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.insert(ids[i]);
	}
	BNFreeStringList(ids, count);
	return result;
}


std::unordered_set<std::string> TypeArchive::GetOutgoingRecursiveTypeReferences(const std::string& id, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	char** ids = BNGetTypeArchiveOutgoingRecursiveTypeReferences(m_object, id.c_str(), snapshot.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveOutgoingRecursiveTypeReferences");

	std::unordered_set<std::string> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.insert(ids[i]);
	}
	BNFreeStringList(ids, count);
	return result;
}


std::unordered_set<std::string> TypeArchive::GetIncomingDirectTypeReferences(const std::string& id, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	char** ids = BNGetTypeArchiveIncomingDirectTypeReferences(m_object, id.c_str(), snapshot.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveIncomingDirectTypeReferences");

	std::unordered_set<std::string> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.insert(ids[i]);
	}
	BNFreeStringList(ids, count);
	return result;
}


std::unordered_set<std::string> TypeArchive::GetIncomingRecursiveTypeReferences(const std::string& id, std::string snapshot) const
{
	if (snapshot.empty())
		snapshot = GetCurrentSnapshotId();
	size_t count = 0;
	char** ids = BNGetTypeArchiveIncomingRecursiveTypeReferences(m_object, id.c_str(), snapshot.c_str(), &count);
	if (!ids)
		throw ExceptionWithStackTrace("BNGetTypeArchiveIncomingRecursiveTypeReferences");

	std::unordered_set<std::string> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.insert(ids[i]);
	}
	BNFreeStringList(ids, count);
	return result;
}


struct SnapshotContext
{
	std::function<void(const std::string& id)> func;
};


bool SnapshotContextCallback(void* context, const char* id)
{
	SnapshotContext* ctxt = (SnapshotContext*)context;
	try
	{
		ctxt->func(id);
		return true;
	}
	catch (...)
	{
		return false;
	}
}


std::string TypeArchive::NewSnapshotTransaction(std::function<void(const std::string& id)> func, const std::vector<std::string>& parents)
{
	SnapshotContext ctxt;
	ctxt.func = func;

	std::vector<const char*> apiParents;
	for (const auto& parent: parents)
	{
		apiParents.push_back(parent.c_str());
	}

	char* snapshotId = BNTypeArchiveNewSnapshotTransaction(m_object, SnapshotContextCallback, (void*)&ctxt, apiParents.data(), apiParents.size());
	if (!snapshotId)
	{
		throw ExceptionWithStackTrace("BNTypeArchiveNewSnapshotTransaction");
	}
	std::string result = snapshotId;
	BNFreeString(snapshotId);
	return result;
}


void TypeArchive::RegisterNotification(TypeArchiveNotification* notification)
{
	BNRegisterTypeArchiveNotification(m_object, notification->GetCallbacks());
}


void TypeArchive::UnregisterNotification(TypeArchiveNotification* notification)
{
	BNUnregisterTypeArchiveNotification(m_object, notification->GetCallbacks());
}


void TypeArchive::StoreMetadata(const std::string& key, Ref<Metadata> value)
{
	if (!BNTypeArchiveStoreMetadata(m_object, key.c_str(), value->GetObject()))
		throw ExceptionWithStackTrace("BNTypeArchiveStoreMetadata");
}


Ref<Metadata> TypeArchive::QueryMetadata(const std::string& key) const
{
	BNMetadata* metadata = BNTypeArchiveQueryMetadata(m_object, key.c_str());
	if (!metadata)
		return nullptr;
	return new Metadata(metadata);
}


void TypeArchive::RemoveMetadata(const std::string& key)
{
	if (!BNTypeArchiveRemoveMetadata(m_object, key.c_str()))
		throw ExceptionWithStackTrace("BNTypeArchiveRemoveMetadata");
}


DataBuffer TypeArchive::SerializeSnapshot(const std::string& snapshot) const
{
	BNDataBuffer* buffer = BNTypeArchiveSerializeSnapshot(m_object, snapshot.c_str());
	if (!buffer)
		throw ExceptionWithStackTrace("BNTypeArchiveSerializeSnapshot");
	return DataBuffer(buffer);
}


std::string TypeArchive::DeserializeSnapshot(const DataBuffer& data)
{
	char* id = BNTypeArchiveDeserializeSnapshot(m_object, data.GetBufferObject());
	if (!id)
		throw ExceptionWithStackTrace("BNTypeArchiveDeserializeSnapshot");
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::optional<std::string> TypeArchive::MergeSnapshots(
	const std::string& baseSnapshot,
	const std::string& firstSnapshot,
	const std::string& secondSnapshot,
	const std::unordered_map<std::string, std::string>& mergeConflictsIn,
	std::unordered_set<std::string>& mergeConflictsOut,
	std::function<bool(size_t, size_t)> progress
)
{
	std::vector<const char*> mergeConflictKeysIn;
	std::vector<const char*> mergeConflictValuesIn;
	for (auto& [key, value]: mergeConflictsIn)
	{
		mergeConflictKeysIn.push_back(key.data());
		mergeConflictValuesIn.push_back(value.data());
	}

	char** mergeConflictsOutApi;
	size_t mergeConflictCountOut;

	char* result;

	ProgressContext progressContext;
	progressContext.callback = progress;

	if (!BNTypeArchiveMergeSnapshots(
		m_object,
		baseSnapshot.c_str(),
		firstSnapshot.c_str(),
		secondSnapshot.c_str(),
		mergeConflictKeysIn.data(),
		mergeConflictValuesIn.data(),
		mergeConflictsIn.size(),
		&mergeConflictsOutApi,
		&mergeConflictCountOut,
		&result,
		ProgressCallback,
		&progressContext
	))
	{
		throw ExceptionWithStackTrace("BNTypeArchiveMergeSnapshots");
	}

	mergeConflictsOut.clear();
	for (size_t i = 0; i < mergeConflictCountOut; i ++)
	{
		mergeConflictsOut.insert(mergeConflictsOutApi[i]);
	}
	BNFreeStringList(mergeConflictsOutApi, mergeConflictCountOut);

	std::optional<std::string> resultCpp;
	if (result)
	{
		resultCpp = result;
		BNFreeString(result);
	}
	else
	{
		resultCpp = std::nullopt;
	}

	return resultCpp;
}