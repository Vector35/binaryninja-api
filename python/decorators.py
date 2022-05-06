def passive(cls):
	passive_note = '''

	.. note:: This object is a "passive" object. Any changes you make to it will not be reflected in the core and vice-versa. If you wish to update a core version of this object you should use the appropriate API.
'''

	if hasattr(cls, "__doc__") and cls.__doc__:
		cls.__doc__ += passive_note
	else:
		cls.__doc__ = passive_note

	return cls


def deprecated(cls):
	deprecated_note = '''
	.. warning:: This object is deprecated.  Please migrate code away from using this class or method.

'''

	if hasattr(cls, "__doc__") and cls.__doc__:
		cls.__doc__ = deprecated_note + cls.__doc__
	else:
		cls.__doc__ = deprecated_note

	return cls