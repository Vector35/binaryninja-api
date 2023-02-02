class RelocationWriteException(Exception):
	""" Exception raised when a relocation fails to apply """
	pass

class ILException(Exception):
	""" Exception raised when IL operations fail """
	pass

class ProjectException(Exception):
	""" Exception raised when project operations fail """
	pass
