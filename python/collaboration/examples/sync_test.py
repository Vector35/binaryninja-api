# coding=utf-8
# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import shutil
from pathlib import Path

import binaryninja
import binaryninja.enterprise as enterprise
import binaryninja.collaboration as collaboration


def main():
	with enterprise.LicenseCheckout():
		# Connect to remote from Enterprise
		remote = collaboration.enterprise_remote()
		if not remote:
			return
		if not remote.is_connected:
			# Will pull default credentials from Enterprise
			remote.connect()

		# Create test project
		project = remote.create_project("Test Project", "Test project for test purposes")
		file = None
		project_dir = None
		try:
			print(f'Created project {project.name}')
			file = project.upload_new_file('/bin/ls')
			print(f'Created file {project.name}/{file.name}')

			project_dir = Path(file.default_bndb_path).parent

			print(f'Snapshots: {[snapshot.id for snapshot in file.snapshots]}')
			bv = binaryninja.load(file.default_bndb_path)
			view_type = bv.view_type
			assert collaboration.RemoteFile.get_for_bv(bv) == file

			print(f'Setting entry function at 0x{bv.entry_function.start:08x} name to \'entry_function\'')
			bv.entry_function.name = 'entry_function'
			bv.file.save_auto_snapshot()

			file.sync(bv, lambda conflicts: False)
			print(f'Snapshots: {[snapshot.id for snapshot in file.snapshots]}')

			# Try deleting the bndb, redownload and see if the function name is preserved
			bv.file.close()
			Path(file.default_bndb_path).unlink()

			print(f'Redownloading {project.name}/{file.name}...')
			metadata = file.download_to_bndb()
			bv = metadata.get_view_of_type(view_type)
			print(f'Entry function name: {bv.entry_function.name}')
			assert bv.entry_function.name == 'entry_function'

		finally:
			# Clean up
			if file is not None:
				project.delete_file(file)
			remote.delete_project(project)
			if project_dir is not None:
				shutil.rmtree(project_dir)


if __name__ == '__main__':
	main()

