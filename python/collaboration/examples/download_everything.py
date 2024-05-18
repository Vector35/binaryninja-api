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

from pathlib import Path
import sys

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

		# Pull every file from every project
		for project in remote.projects:
			for file in project.files:
				bndb_path = file.default_bndb_path
				print(f"{project.name}/{file.name} BNDB at {bndb_path}")

				try:
					metadata: binaryninja.FileMetadata = file.download_to_bndb(bndb_path)

					for v in metadata.existing_views:
						if v == 'Raw':
							continue
						bv = metadata.get_view_of_type(v)
						# Show the entry point to demonstrate we have pulled the analyzed file
						print(f"{project.name}/{file.name} {v} Entrypoint @ 0x{bv.entry_point:08x}")
				except InterruptedError as e:
					# In case of ^C
					raise e

				except Exception as e:
					# In case download or open fails
					print(f"{project.name}/{file.name} Load failed: {e}", file=sys.stderr)


if __name__ == '__main__':
	main()

