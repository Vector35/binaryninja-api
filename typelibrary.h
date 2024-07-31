#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <set>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class Architecture;
	class Metadata;
	class Platform;
	class QualifiedName;
	struct QualifiedNameAndType;
	class Type;
	class TypeContainer;

	class TypeLibrary: public CoreRefCountObject<BNTypeLibrary, BNNewTypeLibraryReference, BNFreeTypeLibrary>
	{
	public:
		TypeLibrary(BNTypeLibrary* handle);

		/*! Creates an empty type library object with a random GUID and the provided name.

			\param arch
			\param name
		*/
		TypeLibrary(Ref<Architecture> arch, const std::string& name);

		/*! Decompresses a type library from a file

			\param path
			\return The string contents of the decompressed type library
		*/
		std::string Decompress(const std::string& path);

		/*! Decompresses a type library from a file

			\param path
			\param output
			\return True if the type library was successfully decompressed
		*/
		static bool DecompressToFile(const std::string& path, const std::string& output);

		/*! Loads a finalized type library instance from file

			\param path
			\return True if the type library was successfully loaded
		*/
		static Ref<TypeLibrary> LoadFromFile(const std::string& path);

		/*! Looks up the first type library found with a matching name. Keep in mind that names are
			not necessarily unique.

			\param arch
			\param name
			\return
		*/
		static Ref<TypeLibrary> LookupByName(Ref<Architecture> arch, const std::string& name);

		/*! Attempts to grab a type library associated with the provided Architecture and GUID pair

			\param arch
			\param guid
			\return
		*/
		static Ref<TypeLibrary> LookupByGuid(Ref<Architecture> arch, const std::string& guid);

		/*! Saves a finalized type library instance to file

			\param path
		*/
		bool WriteToFile(const std::string& path);

		/*! The Architecture this type library is associated with

			\return
		*/
		Ref<Architecture> GetArchitecture();

		/*! Returns the GUID associated with the type library

			\return
		*/
		std::string GetGuid();

		/*! The primary name associated with this type library

			\return
		*/
		std::string GetName();

		/*! A list of extra names that will be considered a match by ``Platform::GetTypeLibrariesByName``

			\return
		*/
		std::set<std::string> GetAlternateNames();

		/*! The dependency name of a library is the name used to record dependencies across
			type libraries. This allows, for example, a library with the name "musl_libc" to have
			dependencies on it recorded as "libc_generic", allowing a type library to be used across
			multiple platforms where each has a specific libc that also provides the name "libc_generic"
			as an `alternate_name`.

			\return
		*/
		std::string GetDependencyName();

		/*! Returns a list of all platform names that this type library will register with during platform
			type registration.

			This returns strings, not Platform objects, as type libraries can be distributed with support for
			Platforms that may not be present.

			\return
		*/
		std::set<std::string> GetPlatformNames();

		/*! Retrieves a metadata associated with the given key stored in the type library

			\param key Key to query
			\return Metadata associated with the key
		*/
		Ref<Metadata> QueryMetadata(const std::string& key);

		/*! Sets the GUID of a type library instance that has not been finalized

			\param guid
		*/
		void SetGuid(const std::string& guid);

		/*! Type Container for all TYPES within the Type Library. Objects are not included.
			The Type Container's Platform will be the first platform associated with the Type Library.
			\return Type Library Type Container
		 */
		TypeContainer GetTypeContainer();

		/*! Direct extracts a reference to a contained object -- when attempting to extract types from a library
			into a BinaryView, consider using BinaryView::ImportTypeLibraryObject instead.

			\param name
			\return
		*/
		Ref<Type> GetNamedObject(const QualifiedName& name);

		/*! Direct extracts a reference to a contained type -- when attempting to extract types from a library
			into a BinaryView, consider using BinaryView.ImportTypeLibraryType>` instead.

			\param name
			\return
		*/
		Ref<Type> GetNamedType(const QualifiedName& name);

		/*! A list containing all named objects (functions, exported variables) provided by a type library

			\return
		*/
		std::vector<QualifiedNameAndType> GetNamedObjects();

		/*! A list containing all named types provided by a type library

			\return
		*/
		std::vector<QualifiedNameAndType> GetNamedTypes();

		/*! Sets the name of a type library instance that has not been finalized

			\param name
		*/
		void SetName(const std::string& name);

		/*! Adds an extra name to this type library used during library lookups and dependency resolution

			\param alternate
		*/
		void AddAlternateName(const std::string& alternate);

		/*! Sets the dependency name of a type library instance that has not been finalized

			\param depName
		*/
		void SetDependencyName(const std::string& depName);

		/*! Clears the list of platforms associated with a type library instance that has not been finalized

		*/
		void ClearPlatforms();

		/*! Associate a platform with a type library instance that has not been finalized.

			This will cause the library to be searchable by Platform::GetTypeLibrariesByName when loaded.

			This does not have side affects until finalization of the type library.

			\param platform
		*/
		void AddPlatform(Ref<Platform> platform);

		/*! Stores an object for the given key in the current type library. Objects stored using StoreMetadata can be
			retrieved from any reference to the library.

			This is primarily intended as a way to store Platform specific information relevant to BinaryView implementations;
			for example the PE BinaryViewType uses type library metadata to retrieve ordinal information, when available.

			\param key Key value to associate the Metadata object with
			\param value Object to store.
		*/
		void StoreMetadata(const std::string& key, Ref<Metadata> value);

		/*! Removes the metadata associated with key from the current type library.

			\param key Key associated with metadata
		*/
		void RemoveMetadata(const std::string& key);

		/*! Returns a base Metadata object associated with the current type library.

			\return Metadata object associated with the type library
		*/
		Ref<Metadata> GetMetadata();

		/*! Directly inserts a named object into the type library's object store.
			This is not done recursively, so care should be taken that types referring to other types
			through NamedTypeReferences are already appropriately prepared.

			To add types and objects from an existing BinaryView, it is recommended to use
			BinaryView::ExportObjectToLibrary, which will automatically pull in all referenced types and record
			additional dependencies as needed.

			\param name
			\param type
		*/
		void AddNamedObject(const QualifiedName& name, Ref<Type> type);

		/*! Directly inserts a named object into the type library's object store.
			This is not done recursively, so care should be taken that types referring to other types
			through NamedTypeReferences are already appropriately prepared.

			To add types and objects from an existing BinaryView, it is recommended to use
			BinaryView::ExportTypeToLibrary, which will automatically pull in all referenced types and record
			additional dependencies as needed.

			\param name
			\param type
		*/
		void AddNamedType(const QualifiedName& name, Ref<Type> type);

		/*! Manually flag NamedTypeReferences to the given QualifiedName as originating from another source
			TypeLibrary with the given dependency name.

			\warning Use this api with extreme caution.

			\param name
			\param source
		*/
		void AddNamedTypeSource(const QualifiedName& name, const std::string& source);

		/*! Flags a newly created type library instance as finalized and makes it available for Platform and Architecture
			type library searches

		*/
		void Finalize();
	};

}
