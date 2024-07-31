#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace BinaryNinja
{

	class BinaryView;
	class Platform;
	class QualifiedName;
	struct QualifiedNameAndType;
	class Type;
	class TypeArchive;
	class TypeLibrary;
	struct TypeParserError;
	struct TypeParserResult;

	/*! A TypeContainer is a generic interface to access various Binary Ninja models
		that contain types. Types are stored with both a unique id and a unique name.

		\ingroup types
	 */
	class TypeContainer
	{
		BNTypeContainer* m_object;

	public:
		explicit TypeContainer(BNTypeContainer* container);

		/*! Get the Type Container for a given BinaryView

			\param data BinaryView source
		 */
		TypeContainer(Ref<BinaryView> data);

		/*! Get the Type Container for a Type Library

			\note The Platform for the Type Container will be the first Platform
			      associated with the Type Library
			\param library TypeLibrary source
		 */
		TypeContainer(Ref<TypeLibrary> library);


		/*! Get the Type Container for a Type Archive

			\param archive TypeArchive source
		 */
		TypeContainer(Ref<TypeArchive> archive);

		/*! Get the Type Container for a Platform

			\param platform Platform source
		 */
		TypeContainer(Ref<Platform> platform);

		~TypeContainer();
		TypeContainer(const TypeContainer& other);
		TypeContainer(TypeContainer&& other);
		TypeContainer& operator=(const TypeContainer& other);
		TypeContainer& operator=(TypeContainer&& other);
		bool operator==(const TypeContainer& other) const { return GetId() == other.GetId(); }
		bool operator!=(const TypeContainer& other) const { return !operator==(other); }

		BNTypeContainer* GetObject() const { return m_object; }

		/*! Get an id string for the Type Container. This will be unique within a given
			analysis session, but may not be globally unique.

			\return Identifier string
		 */
		std::string GetId() const;

		/*! Get a user-friendly name for the Type Container.

			\return Display name
		 */
		std::string GetName() const;

		/*! Get the type of underlying model the Type Container is accessing.

			\return Container type enum
		 */
		BNTypeContainerType GetType() const;

		/*! Test if the Type Container supports mutable operations (add, rename, delete)

			\return True if mutable
		 */
		bool IsMutable() const;

		/*! Get the Platform object associated with this Type Container. All Type Containers
			have exactly one associated Platform (as opposed to, e.g. Type Libraries).

			\return Associated Platform object
		 */
		Ref<Platform> GetPlatform() const;


		/*! Add or update a single type in the Type Container. If the Type Container already contains
			a type with the same name as a type being added, the existing type will be
			replaced with the definition given to this function, and references will be
			updated in the source model.

			\param name Name of type to add
			\param type Definition of type to add
			\return String of added type's id, if successful, std::nullopt otherwise
		 */
		std::optional<std::string> AddType(QualifiedName name, Ref<Type> type);

		/*! Add or update types to a Type Container. If the Type Container already contains
			a type with the same name as a type being added, the existing type will be
			replaced with the definition given to this function, and references will be
			updated in the source model.

			An optional progress callback is included because adding many types can be a slow operation.

			\param types List of (name, definition) pairs of new types to add
			\param progress Optional function to call for progress updates
			\return Map of name -> id of type in Type Container for all added types if successful,
			        std::nullopt otherwise.
		 */
		std::optional<std::unordered_map<QualifiedName, std::string>> AddTypes(
			const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
			std::function<bool(size_t, size_t)> progress = {});

		/*! Rename a type in the Type Container. All references to this type will be updated
			(by id) to use the new name.

			\param typeId Id of type to update
			\param newName New name for the type
			\return True if successful
		 */
		bool RenameType(const std::string& typeId, const QualifiedName& newName);

		/*! Delete a type in the Type Container. Behavior of references to this type is
			not specified and you may end up with broken references if any still exist.

			\param typeId Id of type to delete
			\return True if successful
		 */
		bool DeleteType(const std::string& typeId);


		/*! Get the unique id of the type in the Type Container with the given name.
			If no type with that name exists, returns std::nullopt.

			\param typeName Name of type
			\return Type id, if exists, else, std::nullopt
		 */
		std::optional<std::string> GetTypeId(const QualifiedName& typeName) const;

		/*! Get the unique name of the type in the Type Container with the given id.
			If no type with that id exists, returns std::nullopt.

			\param typeId Id of type
			\return Type name, if exists, else, std::nullopt
		 */
		std::optional<QualifiedName> GetTypeName(const std::string& typeId) const;

		/*! Get the definition of the type in the Type Container with the given id.
			If no type with that id exists, returns std::nullopt.

			\param typeId Id of type
			\return Type object, if exists, else, std::nullopt
		 */
		std::optional<Ref<Type>> GetTypeById(const std::string& typeId) const;

		/*! Get a mapping of all types in a Type Container.

			\return All types in a map of type id -> (type name, type definition)
		 */
		std::optional<std::unordered_map<std::string, std::pair<QualifiedName, Ref<Type>>>> GetTypes() const;


		/*! Get the definition of the type in the Type Container with the given name.
			If no type with that name exists, returns None.

			\param typeName Name of type
			\return Type object, if exists, else, None
		 */
		std::optional<Ref<Type>> GetTypeByName(const QualifiedName& typeName) const;

		/*! Get all type ids in a Type Container.

			\return List of all type ids
		 */
		std::optional<std::unordered_set<std::string>> GetTypeIds() const;

		/*! Get all type names in a Type Container.

			\return List of all type names
		 */
		std::optional<std::unordered_set<QualifiedName>> GetTypeNames() const;

		/*! Get a mapping of all type ids and type names in a Type Container.

			\return Map of type id -> type name
		 */
		std::optional<std::unordered_map<std::string, QualifiedName>> GetTypeNamesAndIds() const;

		/*! Parse a single type and name from a string containing their definition,
			with knowledge of the types in the Type Container.

			\param source Source code to parse
			\param importDependencies If Type Library / Type Archive types should be imported during parsing
			\param result Reference into which the resulting type and name will be written
			\param errors Reference to a list into which any parse errors will be written
			\return True if parsing was successful
		 */
		bool ParseTypeString(
			const std::string& source,
			bool importDependencies,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		);

		/*!
			\deprecated Use `ParseTypeString` with the extra `importDependencies` param
		 */
		bool ParseTypeString(
			const std::string& source,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		);

		/*! Parse an entire block of source into types, variables, and functions, with
			knowledge of the types in the Type Container.

			\param text Source code to parse
			\param fileName Name of the file containing the source (optional: exists on disk)
			\param options Optional string arguments to pass as options, e.g. command line arguments
			\param includeDirs Optional list of directories to include in the header search path
			\param autoTypeSource Optional source of types if used for automatically generated types
			\param importDependencies If Type Library / Type Archive types should be imported during parsing
			\param result Reference to structure into which the results will be written
			\param errors Reference to a list into which any parse errors will be written
			\return True if successful
		 */
		bool ParseTypesFromSource(
			const std::string& text,
			const std::string& fileName,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			bool importDependencies,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		);

		/*!
			\deprecated Use `ParseTypesFromSource` with the extra `importDependencies` param
		 */
		bool ParseTypesFromSource(
			const std::string& text,
			const std::string& fileName,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		);
	};
}
