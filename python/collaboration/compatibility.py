import warnings

from .file import RemoteFile
from .folder import RemoteFolder
from .project import RemoteProject


class File(RemoteFile):
	def __init__(self, handle):
		warnings.warn('Legacy class "File" will be removed in a future version. Please migrate to "binaryninja.collaboration.file.RemoteFile".')
		super().__init__(handle)

class Folder(RemoteFolder):
	def __init__(self, handle):
		warnings.warn('Legacy class "Folder" will be removed in a future version. Please migrate to "binaryninja.collaboration.folder.RemoteFolder".')
		super().__init__(handle)

class Project(RemoteProject):
	def __init__(self, handle):
		warnings.warn('Legacy class "Project" will be removed in a future version. Please migrate to "binaryninja.collaboration.project.RemoteProject".')
		super().__init__(handle)
