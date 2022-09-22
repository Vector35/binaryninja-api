
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

bool Component::operator==(const Component& other) const
{
	return BNComponentsEqual(m_object, other.m_object);
}


bool Component::operator!=(const Component& other) const
{
	return BNComponentsNotEqual(m_object, other.m_object);
}



Component::Component(BNComponent* component)
{
	m_object = component;
}


std::string Component::GetDisplayName()
{
	return BNComponentGetDisplayName(m_object);
}


std::string Component::GetName()
{
	return BNComponentGetOriginalName(m_object);
}


Ref<BinaryView> Component::GetView()
{
	return new BinaryView(BNComponentGetView(m_object));
}


void Component::SetName(const std::string &name)
{
	BNComponentSetName(m_object, name.c_str());
}


Ref<Component> Component::GetParent()
{
	return new Component(BNComponentGetParent(m_object));
}


std::string Component::GetGuid()
{
	return string(BNComponentGetGuid(m_object));
}


bool Component::AddFunction(Ref<Function> func)
{
	return BNComponentAddFunctionReference(m_object, func->GetObject());
}


bool Component::AddComponent(Ref<Component> component)
{
	return BNComponentAddComponent(m_object, component->m_object);
}


bool Component::RemoveComponent(Ref<Component> component)
{
	return BNComponentRemoveComponent(component->m_object);
}


bool Component::RemoveFunction(Ref<Function> func)
{
	return BNComponentRemoveFunctionReference(m_object, func->GetObject());
}


std::vector<Ref<Component>> Component::GetContainedComponents()
{
	std::vector<Ref<Component>> components;

	size_t count;
	BNComponent** list = BNComponentGetContainedComponents(m_object, &count);

	components.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		Ref<Component> component = new Component(BNNewComponentReference(list[i]));
		components.push_back(component);
	}

	BNFreeComponents(list, count);

	return components;
}


std::vector<Ref<Function>> Component::GetContainedFunctions()
{
	std::vector<Ref<Function>> functions;

	size_t count;
	BNFunction** list = BNComponentGetContainedFunctions(m_object, &count);

	functions.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		Ref<Function> function = new Function(BNNewFunctionReference(list[i]));
		functions.push_back(function);
	}

	BNFreeFunctionList(list, count);

	return functions;
}


std::vector<Ref<Type>> Component::GetReferencedTypes()
{
	std::vector<Ref<Type>> types;

	size_t count;
	BNType** list = BNComponentGetReferencedTypes(m_object, &count);

	types.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		Ref<Type> type = new Type(BNNewTypeReference(list[i]));
		types.push_back(type);
	}

	BNComponentFreeReferencedTypes(list, count);

	return types;
}


std::vector<DataVariable> Component::GetReferencedDataVariables()
{
	vector<DataVariable> result;

	size_t count;
	BNDataVariable* variables = BNComponentGetReferencedDataVariables(m_object, &count);

	result.reserve(count);
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(variables[i].address,
			Confidence(new Type(BNNewTypeReference(variables[i].type)), variables[i].typeConfidence),
			variables[i].autoDiscovered);
	}

	BNFreeDataVariables(variables, count);
	return result;
}
