#include "binaryninjaapi.h"

using namespace BinaryNinja;

ImportLibrary::ImportLibrary(BNImportLibrary* handle)
{
	m_object = handle;
}


ImportLibrary::ImportLibrary(Ref<Architecture> arch, const std::string& name)
{
	m_object = BNNewImportLibrary(arch->GetObject(), name.c_str());
}


bool ImportLibrary::DecompressToFile(const std::string& path)
{
	return BNImportLibraryDecompressToFile(m_object, path.c_str());
}


Ref<ImportLibrary> ImportLibrary::LoadFromFile(const std::string& path)
{
	return new ImportLibrary(BNLoadImportLibraryFromFile(path.c_str()));
}


Ref<ImportLibrary> ImportLibrary::LookupByName(Ref<Architecture> arch, const std::string& name)
{
	return new ImportLibrary(BNLookupImportLibraryByName(arch->GetObject(), name.c_str()));
}


Ref<ImportLibrary> ImportLibrary::LookupByGuid(Ref<Architecture> arch, const std::string& guid)
{
	return new ImportLibrary(BNLookupImportLibraryByGuid(arch->GetObject(), guid.c_str()));
}


bool ImportLibrary::WriteToFile(const std::string& path)
{
	return BNWriteImportLibraryToFile(m_object, path.c_str());
}


Ref<Architecture> ImportLibrary::GetArchitecture()
{
	return new CoreArchitecture(BNGetImportLibraryArchitecture(m_object));
}


std::string ImportLibrary::GetGuid()
{
	char* str = BNGetImportLibraryGuid(m_object);
	std::string result = str;
	BNFreeString(str);
	return result;
}


std::string ImportLibrary::GetName()
{
	char* str = BNGetImportLibraryName(m_object);
	std::string result = str;
	BNFreeString(str);
	return result;
}


std::set<std::string> ImportLibrary::GetAlternateNames()
{
	size_t count;
	char** strs = BNGetImportLibraryAlternateNames(m_object, &count);
	std::set<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.insert(strs[i]);
	}
	BNFreeStringList(strs, count);
	return result;

}


std::string ImportLibrary::GetDependencyName()
{
	char* str = BNGetImportLibraryDependencyName(m_object);
	std::string result = str;
	BNFreeString(str);
	return result;
}


std::set<std::string> ImportLibrary::GetPlatformNames()
{
	size_t count = 0;
	char** strs = BNGetImportLibraryPlatforms(m_object, &count);
	std::set<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.insert(strs[i]);
	}
	BNFreeStringList(strs, count);
	return result;
}


Ref<Metadata> ImportLibrary::QueryMetadata(const std::string& key)
{
	BNMetadata* result = BNImportLibraryQueryMetadata(m_object, key.c_str());
	if (!result)
		return nullptr;
	return new Metadata(result);
}


TypeContainer ImportLibrary::GetTypeContainer()
{
	return TypeContainer(BNGetImportLibraryTypeContainer(m_object));
}


void ImportLibrary::SetGuid(const std::string& guid)
{
	BNSetImportLibraryGuid(m_object, guid.c_str());
}


Ref<Type> ImportLibrary::GetNamedObject(const QualifiedName& name)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNType* result = BNGetImportLibraryNamedObject(m_object, &qname);
	QualifiedName::FreeAPIObject(&qname);
	if (!result)
		return nullptr;
	return new Type(result);
}


Ref<Type> ImportLibrary::GetNamedType(const QualifiedName& name)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNType* result = BNGetImportLibraryNamedType(m_object, &qname);
	QualifiedName::FreeAPIObject(&qname);
	if (!result)
		return nullptr;
	return new Type(result);
}


std::vector<QualifiedNameAndType> ImportLibrary::GetNamedObjects()
{
	size_t count = 0;
	BNQualifiedNameAndType* objects = BNGetImportLibraryNamedObjects(m_object, &count);
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


std::vector<QualifiedNameAndType> ImportLibrary::GetNamedTypes()
{
	size_t count = 0;
	BNQualifiedNameAndType* types = BNGetImportLibraryNamedTypes(m_object, &count);
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


void ImportLibrary::SetName(const std::string& name)
{
	BNSetImportLibraryName(m_object, name.c_str());
}


void ImportLibrary::AddAlternateName(const std::string& alternate)
{
	BNAddImportLibraryAlternateName(m_object, alternate.c_str());
}


void ImportLibrary::RemoveAlternateName(const std::string& alternate)
{
	BNRemoveImportLibraryAlternateName(m_object, alternate.c_str());
}


void ImportLibrary::SetDependencyName(const std::string& depName)
{
	BNSetImportLibraryDependencyName(m_object, depName.c_str());
}


void ImportLibrary::ClearPlatforms()
{
	BNClearImportLibraryPlatforms(m_object);
}


void ImportLibrary::AddPlatform(Ref<Platform> platform)
{
	BNAddImportLibraryPlatform(m_object, platform->m_object);
}


void ImportLibrary::StoreMetadata(const std::string& key, Ref<Metadata> value)
{
	BNImportLibraryStoreMetadata(m_object, key.c_str(), value->m_object);
}


void ImportLibrary::RemoveMetadata(const std::string& key)
{
	BNImportLibraryRemoveMetadata(m_object, key.c_str());
}


Ref<Metadata> ImportLibrary::GetMetadata()
{
	return new Metadata(BNImportLibraryGetMetadata(m_object));
}


void ImportLibrary::AddNamedObject(const QualifiedName& name, Ref<Type> type)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNAddImportLibraryNamedObject(m_object, &qname, type->m_object);
	QualifiedName::FreeAPIObject(&qname);
}


void ImportLibrary::AddNamedType(const QualifiedName& name, Ref<Type> type)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNAddImportLibraryNamedType(m_object, &qname, type->m_object);
	QualifiedName::FreeAPIObject(&qname);
}


void ImportLibrary::AddNamedTypeSource(const QualifiedName& name, const std::string& source)
{
	BNQualifiedName qname = name.GetAPIObject();
	BNAddImportLibraryNamedTypeSource(m_object, &qname, source.c_str());
	QualifiedName::FreeAPIObject(&qname);
}


void ImportLibrary::Finalize()
{
	BNFinalizeImportLibrary(m_object);
}


void ImportLibrary::Register()
{
	BNRegisterImportLibrary(m_object);
}
