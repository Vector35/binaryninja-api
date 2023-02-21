#include "binaryninjaapi.h"

using namespace BinaryNinja;

TypeLibrary::TypeLibrary(BNTypeLibrary* handle)
{
	m_object = handle;
}


TypeLibrary::TypeLibrary(Ref<Architecture> arch, const std::string& name)
{
	m_object = BNNewTypeLibrary(arch->GetObject(), name.c_str());
}


bool TypeLibrary::DecompressToFile(const std::string& path, const std::string& output)
{
	return BNTypeLibraryDecompressToFile(path.c_str(), output.c_str());
}


Ref<TypeLibrary> TypeLibrary::LoadFromFile(const std::string& path)
{
	return new TypeLibrary(BNLoadTypeLibraryFromFile(path.c_str()));
}


Ref<TypeLibrary> TypeLibrary::LookupByName(Ref<Architecture> arch, const std::string& name)
{
	return new TypeLibrary(BNLookupTypeLibraryByName(arch->GetObject(), name.c_str()));
}


Ref<TypeLibrary> TypeLibrary::LookupByGuid(Ref<Architecture> arch, const std::string& guid)
{
	return new TypeLibrary(BNLookupTypeLibraryByGuid(arch->GetObject(), guid.c_str()));
}


void TypeLibrary::WriteToFile(const std::string& path)
{
	BNWriteTypeLibraryToFile(m_object, path.c_str());
}


Ref<Architecture> TypeLibrary::GetArchitecture()
{
	return new CoreArchitecture(BNGetTypeLibraryArchitecture(m_object));
}


std::string TypeLibrary::GetGuid()
{
	char* str = BNGetTypeLibraryGuid(m_object);
	std::string result = str;
	BNFreeString(str);
	return result;
}


std::string TypeLibrary::GetName()
{
	char* str = BNGetTypeLibraryName(m_object);
	std::string result = str;
	BNFreeString(str);
	return result;
}


std::set<std::string> TypeLibrary::GetAlternateNames()
{
	size_t count;
	char** strs = BNGetTypeLibraryAlternateNames(m_object, &count);
	std::set<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.insert(strs[i]);
	}
	BNFreeStringList(strs, count);
	return result;

}


std::string TypeLibrary::GetDependencyName()
{
	char* str = BNGetTypeLibraryDependencyName(m_object);
	std::string result = str;
	BNFreeString(str);
	return result;
}


std::set<std::string> TypeLibrary::GetPlatformNames()
{
	size_t count = 0;
	char** strs = BNGetTypeLibraryPlatforms(m_object, &count);
	std::set<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.insert(strs[i]);
	}
	BNFreeStringList(strs, count);
	return result;
}


Ref<Metadata> TypeLibrary::QueryMetadata(const std::string& key)
{
	BNMetadata* result = BNTypeLibraryQueryMetadata(m_object, key.c_str());
	if (!result)
		return nullptr;
	return new Metadata(result);
}


TypeContainer TypeLibrary::GetTypeContainer()
{
	return TypeContainer(BNGetTypeLibraryTypeContainer(m_object));
}


void TypeLibrary::SetGuid(const std::string& guid)
{
	BNSetTypeLibraryGuid(m_object, guid.c_str());
}


Ref<Type> TypeLibrary::GetNamedObject(const QualifiedName& name)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNType* result = BNGetTypeLibraryNamedObject(m_object, &qname);
	QualifiedName::FreeAPIObject(&qname);
	if (!result)
		return nullptr;
	return new Type(result);
}


Ref<Type> TypeLibrary::GetNamedType(const QualifiedName& name)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNType* result = BNGetTypeLibraryNamedType(m_object, &qname);
	QualifiedName::FreeAPIObject(&qname);
	if (!result)
		return nullptr;
	return new Type(result);
}


std::vector<QualifiedNameAndType> TypeLibrary::GetNamedObjects()
{
	size_t count = 0;
	BNQualifiedNameAndType* objects = BNGetTypeLibraryNamedObjects(m_object, &count);
	std::vector<QualifiedNameAndType> result;
	for (size_t i = 0; i < count; i ++)
	{
		QualifiedNameAndType qnat;
		qnat.name = QualifiedName::FromAPIObject(&objects[i].name);
		qnat.type = new Type(BNNewTypeReference(objects[i].type));
		result.push_back(std::move(qnat));
	}
	BNFreeQualifiedNameAndTypeArray(objects, count);
	return result;
}


std::vector<QualifiedNameAndType> TypeLibrary::GetNamedTypes()
{
	size_t count = 0;
	BNQualifiedNameAndType* types = BNGetTypeLibraryNamedTypes(m_object, &count);
	std::vector<QualifiedNameAndType> result;
	for (size_t i = 0; i < count; i ++)
	{
		QualifiedNameAndType qnat;
		qnat.name = QualifiedName::FromAPIObject(&types[i].name);
		qnat.type = new Type(BNNewTypeReference(types[i].type));
		result.push_back(std::move(qnat));
	}
	BNFreeQualifiedNameAndTypeArray(types, count);
	return result;
}


void TypeLibrary::SetName(const std::string& name)
{
	BNSetTypeLibraryName(m_object, name.c_str());
}


void TypeLibrary::AddAlternateName(const std::string& alternate)
{
	BNAddTypeLibraryAlternateName(m_object, alternate.c_str());
}


void TypeLibrary::SetDependencyName(const std::string& depName)
{
	BNSetTypeLibraryDependencyName(m_object, depName.c_str());
}


void TypeLibrary::ClearPlatforms()
{
	BNClearTypeLibraryPlatforms(m_object);
}


void TypeLibrary::AddPlatform(Ref<Platform> platform)
{
	BNAddTypeLibraryPlatform(m_object, platform->m_object);
}


void TypeLibrary::StoreMetadata(const std::string& key, Ref<Metadata> value)
{
	BNTypeLibraryStoreMetadata(m_object, key.c_str(), value->m_object);
}


void TypeLibrary::RemoveMetadata(const std::string& key)
{
	BNTypeLibraryRemoveMetadata(m_object, key.c_str());
}


void TypeLibrary::AddNamedObject(const QualifiedName& name, Ref<Type> type)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNAddTypeLibraryNamedObject(m_object, &qname, type->m_object);
	QualifiedName::FreeAPIObject(&qname);
}


void TypeLibrary::AddNamedType(const QualifiedName& name, Ref<Type> type)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNAddTypeLibraryNamedType(m_object, &qname, type->m_object);
	QualifiedName::FreeAPIObject(&qname);
}


void TypeLibrary::AddNamedTypeSource(const QualifiedName& name, const std::string& source)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNAddTypeLibraryNamedTypeSource(m_object, &qname, source.c_str());
	QualifiedName::FreeAPIObject(&qname);
}


void TypeLibrary::Finalize()
{
	BNFinalizeTypeLibrary(m_object);
}
