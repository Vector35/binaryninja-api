def passive(cls):
	passive_note = '''

	.. note:: This object is a "passive" object. Any changes you make to it will not be reflected in the core and vice-versa. If you wish to update a core version of this object you should use the appropriate API.
'''

	if hasattr(cls, "__doc__") and cls.__doc__:
		cls.__doc__ += passive_note
	else:
		cls.__doc__ = passive_note

	return cls


def enterprise(cls):
	enterprise_note = '''
	.. note: This object is only available in the Ultimate edition of Binary Ninja.
'''

	if hasattr(cls, "__doc__") and cls.__doc__:
		cls.__doc__ = enterprise_note + cls.__doc__
	else:
		cls.__doc__ = enterprise_note

	return cls
