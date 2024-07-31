#pragma once


#include "binaryninjacore.h"
#include "refcount.h"
#include <string>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;
	class DataVariable;
	class Function;
	class Type;

	/*! Components are objects that can contain Functions, DataVariables, and other Components.

		\note Components should not be instantiated directly. Instead use BinaryView::CreateComponent()

		They can be queried for information about the functions contained within them.

	 	Components have a Guid, which persistent across saves and loads of the database, and should be
	 	used for retrieving components when such is required and a reference to the Component cannot be held.

	 	\ingroup coreapi

	*/
	class Component : public CoreRefCountObject<BNComponent, BNNewComponentReference, BNFreeComponent>
	{
	public:
		Component(BNComponent* type);

		/*! Get the unique identifier for this component.

			\return Component GUID
		*/
		std::string GetGuid();

		bool operator==(const Component& other) const;
		bool operator!=(const Component& other) const;

		Ref<BinaryView> GetView();

		/*! The displayed name for the component

		 	@threadunsafe

			This can differ from the GetOriginalName() value if the parent
		 	component also contains other components with the same name.

		 	Subsequent duplicates will return the original name with " (1)", " (2)" and so on appended.

		 	This name can change whenever a different duplicate is removed.

		 	\note For looking up Components, utilizing Guid is highly recommended, as it will *always* map to this component,
		 	and as Guid lookups are faster by nature.

			\return Component name
		*/
		std::string GetDisplayName();

		/*! The original name for the component

		 	@threadunsafe

			This may differ from Component::GetName() whenever the parent contains Components with the same original name.

		 	This function will always return the value originally set for this Component.

			\return Component name
		*/
		std::string GetName();

		/*! Set the name for the component

		 	@threadunsafe

			\see GetName(), GetOriginalName()

		    \param name New component name.
		*/
		void SetName(const std::string &name);

		/*! Get the parent component. If it's a top level component, it will return the "root" Component.

		 	@threadsafe

			\return Parent Component
		*/
		Ref<Component> GetParent();

		/*! Add a function to this component

		 	@threadsafe

			\param func Function to add.
			\return True if the function was successfully added.
		*/
		bool AddFunction(Ref<Function> func);

		/*! Move a component to this component.

		 	@threadsafe

			\param component Component to add.
			\return True if the component was successfully added.
		*/
		bool AddComponent(Ref<Component> component);

		bool AddDataVariable(DataVariable dataVariable);

		/*! Remove a Component from this Component, moving it to the root component.

		 	@threadsafe

			This will not remove a component from the tree entirely.

			\see BinaryView::GetRootComponent(), BinaryView::RemoveComponent()

			\param component Component to remove
			\return True if the component was successfully removed
		*/
		bool RemoveComponent(Ref<Component> component);

		/*! Remove a function

		 	@threadsafe

			\param func Function to remove
			\return True if the function was successfully removed.
		*/
		bool RemoveFunction(Ref<Function> func);

		bool RemoveDataVariable(DataVariable dataVariable);

		/*! Get a list of types referenced by the functions in this Component.

		 	@threadsafe

			\return vector of Type objects
		*/
		std::vector<Ref<Type>> GetReferencedTypes();

		/*! Get a list of components contained by this component.

		 	@threadsafe

			\return vector of Component objects
		*/
		std::vector<Ref<Component>> GetContainedComponents();

		/*! Get a list of functions contained within this Component.

		 	@threadsafe

			\return vector of Function objects
		*/
		std::vector<Ref<Function>> GetContainedFunctions();

		/*! Get a list of datavariables added to this component

		 	@threadsafe

			\return list of DataVariables
		*/
		std::vector<DataVariable> GetContainedDataVariables();

		/*! Get a list of DataVariables referenced by the functions in this Component.

		 	@threadsafe

			\return vector of DataVariable objects
		*/
		std::vector<DataVariable> GetReferencedDataVariables();
	};

}
