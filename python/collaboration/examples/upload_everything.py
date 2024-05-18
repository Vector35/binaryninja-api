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
import hashlib
import os
import traceback
import sys
from pathlib import Path
from typing import Optional

from tqdm import tqdm

import binaryninja
import binaryninja.enterprise as enterprise
import binaryninja.collaboration as collaboration


def main():
	with enterprise.LicenseCheckout():
		if len(sys.argv) < 2:
			print(f"Usage: {sys.argv[0]} <remote name> <project name>")
			print("")
			print("Here is a list of remotes available to you:")
			for remote in sorted(collaboration.known_remotes(), key=lambda remote: remote.name):
				print(f"{remote.name}")
			sys.exit(1)

		# Connect to remote as specified
		remote = collaboration.get_remote_by_name(sys.argv[1])
		if not remote:
			return
		if not remote.is_connected:
			# Will pull default credentials from either Enterprise or Keychain
			remote.connect()

		if len(sys.argv) < 3:
			print(f"Usage: {sys.argv[0]} <remote name> <project name>")
			print("")
			print("Here is a list of projects available to you:")
			for project in sorted(remote.projects, key=lambda project: project.name):
				print(f"{project.name}")
			sys.exit(1)

		# Create test project
		project = remote.get_project_by_name(sys.argv[2])
		if project is None:
			print(f"Creating new project '{sys.argv[2]}'")
			project = remote.create_project(sys.argv[2], "")

		known_hashes = set()
		project.pull_folders()
		for file in project.files:
			known_hashes.add(file.hash.lower())

		# Find all the files in the current directory and upload them
		for file in tqdm(list(sorted(Path(os.curdir).rglob("*"))), desc="Files"):
			if not file.is_file():
				continue
			if file.name == ".DS_Store":
				continue
			try:
				# Check sha256
				with open(file, 'rb') as f:
					hash = hashlib.sha256(f.read()).hexdigest()
				if hash.lower() in known_hashes:
					continue

				# Create parents
				base = Path(os.curdir)
				parents = []
				parent = file.parent
				while parent != base and parent is not None:
					parents.insert(0, parent.name)
					parent = parent.parent

				def get_folder_by_name(name: str, parent: Optional[collaboration.RemoteFolder]) -> Optional[collaboration.RemoteFolder]:
					for folder in project.folders:
						if folder.name == name and folder.parent == parent:
							return folder
					return None

				folder = None
				for p in parents:
					next_folder = get_folder_by_name(p, folder)
					if next_folder is None:
						next_folder = project.create_folder(p, "", folder)
					folder = next_folder

				tqdm.write(f"Uploading {file}...")
				with TqdmProgress(desc="", leave=False) as t:
					with binaryninja.load(file, update_analysis=False, progress_func=lambda cur, max: t.progress(cur, max)) as bv:
						project.upload_new_file(bv.file, folder, progress=lambda cur, max: t.progress(cur, max))
			except:
				tqdm.write(traceback.format_exc())


class TqdmProgress(tqdm):
	def __init__(self, *args, **kwargs):
		kwargs['total'] = 100
		super(TqdmProgress, self).__init__(*args, **kwargs)

	def progress(self, cur, max):
		new_n = cur / max * self.total
		self.update(new_n - self.n)
		return True


if __name__ == '__main__':
	main()

