
import ctypes
import inspect
from typing import Generator, Optional, List, Tuple, Union, Mapping, Any, Dict, Iterator
from dataclasses import dataclass

from . import binaryview

from . import function
from . import _binaryninjacore as core
from . import types


class Component:
    """
    Components are objects that can contain Functions and other Components.

    They can be queried for information about the functions contained within them.

    Components have a Guid, which persistent across saves and loads of the database, and should be
    used for retrieving components when such is required and a reference to the Component cannot be held.

    """
    def __init__(self, handle=None):

        assert handle is not None, "Cannot create component directly, run `bv.create_component?`"

        self.handle = handle

        self.guid = core.BNComponentGetGuid(self.handle)

    def __eq__(self, other):
        if not isinstance(other, Component):
            return NotImplemented
        return core.BNComponentsEqual(self.handle, other.handle)

    def __ne__(self, other):
        if not isinstance(other, Component):
            return NotImplemented
        return core.BNComponentsNotEqual(self.handle, other.handle)

    def __repr__(self):
        return f'<Component "{self.display_name}" "({self.guid[:8]}...")>'

    def __del__(self):
        if (hasattr(self, 'handle')):
            core.BNFreeComponent(self.handle)

    def __str__(self):
        return self._sprawl_component(self)

    def _sprawl_component(self, c, depth=1, out=None):
        """
        Recursive quick function to print out the component's tree of items

        :param c: Current cycle's component. On initial call, pass `self`
        :param depth: Current tree depth.
        :param out: Current text
        :return:
        """
        _out = ([repr(c)] if not out else out.split('\n')) + [('  ' * depth + repr(f)) for f in c.functions]
        _out += ['  ' * (depth+1) + repr(i) for i in (c.get_referenced_data_variables() + c.get_referenced_types())]
        for i in c.components:
            _out.append('  ' * depth + repr(i))
            _out = self._sprawl_component(i, depth+1, '\n'.join(_out)).split('\n')
        return '\n'.join(_out)

    def add_function(self, func: 'function.Function') -> bool:
        """
        Add function to this component.

        :param func: Function to add
        :return: True if function was successfully added.
        """
        return core.BNComponentAddFunctionReference(self.handle, func.handle)

    def contains_function(self, func: 'function.Function') -> bool:
        """
        Check whether this component contains a function.

        :param func: Function to check
        :return: True if this component contains the function.
        """
        return core.BNComponentContainsFunction(self.handle, func.handle)

    def remove_function(self, func: 'function.Function') -> bool:
        """
        Remove function from this component.

        :param func: Function to remove
        :return: True if function was successfully removed.
        """
        return core.BNComponentRemoveFunctionReference(self.handle, func.handle)

    def add_component(self, component: 'Component') -> bool:
        """
        Move component to this component. This will remove it from the old parent.

        :param component: Component to add to this component.
        :return: True if the component was successfully moved to this component
        """
        return core.BNComponentAddComponent(self.handle, component.handle)

    def contains_component(self, component: 'Component') -> bool:
        """
        Check whether this component contains a component.

        :param component: Component to check
        :return: True if this component contains the component.
        """
        return core.BNComponentContainsComponent(self.handle, component.handle)

    def remove_component(self, component: 'Component') -> bool:
        """
        Remove a component from the current component, moving it to the root.

        This function has no effect when used from the root component.
        Use `BinaryView.remove_component` to Remove a component from the tree entirely.

        :param component: Component to remove
        :return:
        """

        return self.view.root_component.add_component(component)

    def add_data_variable(self, data_variable):
        return core.BNComponentAddDataVariable(self.handle, data_variable.address)

    def contains_data_variable(self, data_variable):
        return core.BNComponentContainsDataVariable(self.handle, data_variable.address)

    def remove_data_variable(self, data_variable):
        return core.BNComponentRemoveDataVariable(self.handle, data_variable.address)

    @property
    def display_name(self) -> str:
        """Original Name of the component (read-only)"""
        return core.BNComponentGetDisplayName(self.handle)

    @property
    def name(self) -> str:
        """Original name set for this component

        :note: The `.display_name` property should be used for `bv.get_component_by_path()` lookups.

        This can differ from the .display_name property if one of its sibling components has the same .original_name; In that
        case, .name will be an automatically generated unique name (e.g. "MyComponentName (1)") while .original_name will
        remain what was originally set (e.g. "MyComponentName")

        If this component has a duplicate name and is moved to a component where none of its siblings share its name,
        the .name property will return the original "MyComponentName"
        """
        return core.BNComponentGetOriginalName(self.handle)

    @name.setter
    def name(self, _name):
        core.BNComponentSetName(self.handle, _name)

    @property
    def parent(self) -> Optional['Component']:
        """
        The component that contains this component, if it exists.
        """
        bn_component = core.BNComponentGetParent(self.handle)
        if bn_component is not None:
            return Component(bn_component)
        return None

    @property
    def view(self):
        bn_binaryview = core.BNComponentGetView(self.handle)
        if bn_binaryview is not None:
            return binaryview.BinaryView(handle=bn_binaryview)
        return None

    @property
    def components(self) -> List['Component']:
        """
		``components`` is an iterator for all Components contained within this Component

		:return: A list of components
		:Example:

			>>> for subcomp in component.components:
			...  print(repr(component))
        """

        count = ctypes.c_ulonglong(0)
        bn_components = core.BNComponentGetContainedComponents(self.handle, count)
        components = []
        try:
            for i in range(count.value):
                components.append(Component(core.BNNewComponentReference(bn_components[i])))
        finally:
            core.BNFreeComponents(bn_components, count.value)

        return components

    @property
    def function_list(self) -> List['function.Function']:
        """
		``function_list`` List of all Functions contained within this Component

		:warning: .functions Should be used instead of this in any performance sensitive context.

		:return: A list of functions
		:Example:

			>>> for func in component.functions:
			...  print(func.name)
        """

        count = ctypes.c_ulonglong(0)
        bn_functions = core.BNComponentGetContainedFunctions(self.handle, count)
        funcs = []
        try:
            for i in range(count.value):
                bn_function = core.BNNewFunctionReference(bn_functions[i])
                funcs.append(function.Function(self.view, bn_function))
        finally:
            core.BNFreeFunctionList(bn_functions, count.value)

        return funcs

    @property
    def functions(self) -> Iterator['function.Function']:
        """
		``functions`` is an iterator for all Functions contained within this Component
		:return: An iterator containing Components
		:rtype: ComponentIterator
		:Example:
			>>> for func in component.functions:
			...  print(func.name)
        """
        @dataclass
        class FunctionIterator:
            view: 'binaryview.BinaryView'
            comp: Component

            def __iter__(self):
                count = ctypes.c_ulonglong(0)
                bn_functions = core.BNComponentGetContainedFunctions(self.comp.handle, count)
                try:
                    for i in range(count.value):
                        bn_function = core.BNNewFunctionReference(bn_functions[i])
                        yield function.Function(self.view, bn_function)
                finally:
                    core.BNFreeFunctionList(bn_functions, count.value)

        return iter(FunctionIterator(self.view, self))

    @property
    def data_variable_list(self):
        data_vars = []

        count = ctypes.c_ulonglong(0)
        bn_data_vars = core.BNComponentGetContainedDataVariables(self.handle, count)
        try:
            for i in range(count.value):
                bn_data_var = bn_data_vars[i]
                data_var = binaryview.DataVariable.from_core_struct(bn_data_var, self.view)
                data_vars.append(data_var)
        finally:
            core.BNFreeDataVariables(bn_data_vars, count.value)

        return data_vars

    @property
    def data_variables(self):
        @dataclass
        class DataVariableIterator:
            view: 'binaryview.BinaryView'
            comp: Component

            def __iter__(self):
                count = ctypes.c_ulonglong(0)
                bn_data_vars = core.BNComponentGetContainedDataVariables(self.comp.handle, count)
                try:
                    for i in range(count.value):
                        bn_data_var = bn_data_vars[i]
                        yield binaryview.DataVariable.from_core_struct(bn_data_var, self.view)
                finally:
                    core.BNFreeDataVariables(bn_data_vars, count.value)

        return iter(DataVariableIterator(self.view, self))


    def get_referenced_data_variables(self, recursive=False):
        """
        Get data variables referenced by this component

        :param recursive: Optional; Get all DataVariables referenced by this component and subcomponents.
        :return: List of DataVariables
        """
        data_vars = []
        count = ctypes.c_ulonglong(0)
        if recursive:
            bn_data_vars = core.BNComponentGetReferencedDataVariablesRecursive(self.handle, count)
        else:
            bn_data_vars = core.BNComponentGetReferencedDataVariables(self.handle, count)
        try:
            for i in range(count.value):
                bn_data_var = bn_data_vars[i]
                data_var = binaryview.DataVariable.from_core_struct(bn_data_var, self.view)
                data_vars.append(data_var)
        finally:
            core.BNFreeDataVariables(bn_data_vars, count.value)
        return data_vars

    def get_referenced_types(self, recursive=False):
        """
        Get Types referenced by this component

        :param recursive: Optional; Get all Types referenced by this component and subcomponents.
        :return: List of Types
        """
        _types = []
        count = ctypes.c_ulonglong(0)

        if recursive:
            bn_types = core.BNComponentGetReferencedTypesRecursive(self.handle, count)
        else:
            bn_types = core.BNComponentGetReferencedTypes(self.handle, count)

        try:
            for i in range(count.value):
                _types.append(types.Type(core.BNNewTypeReference(bn_types[i])))
        finally:
            core.BNComponentFreeReferencedTypes(bn_types, count.value)

        return _types
