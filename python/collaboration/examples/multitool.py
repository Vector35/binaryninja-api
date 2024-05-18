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

import argparse
import os
import sys

import binaryninja.enterprise as enterprise
import binaryninja.collaboration as collaboration
from binaryninja.collaboration import Remote, RemoteProject, RemoteFile


def print_remote_info(remote: Remote, extended=False):
	try:
		if not remote.is_connected:
			remote.connect()
	except:
		pass
	if extended:
		print(f"Name: {remote.name}\n"
		      f"Address: {remote.address}"
		      )
		if remote.is_connected:
			print(f"Id: {remote.unique_id}\n"
			      f"Is Enterprise: {remote.is_enterprise}\n"
			      f"Connected username: {remote.username}\n"
			      f"Is administrator: {remote.is_admin}\n"
			      f"Server version: {remote.server_version}\n"
			      f"Server build id: {remote.server_build_id}\n"
			      f"Project count: {len(remote.projects)}")
		if remote.is_admin:
			print(f"Group count: {len(remote.groups)}\n"
			      f"User count: {len(remote.users)}")
	else:
		if remote.is_connected:
			print(f"{remote.name} @ {remote.address} (id: {remote.unique_id})")
		else:
			print(f"{remote.name} @ {remote.address} (id: ???)")

def print_project_info(project: RemoteProject, extended=False):
	if extended:
		print(f"Name: {project.name}\n"
		      f"Description: {project.description}\n"
		      f"Id: {project.id}\n"
		      f"Url: {project.url}\n"
		      f"Created date: {project.created}\n"
		      f"Last modified date: {project.last_modified}\n"
		      f"Default path on disk: {project.default_path}\n"
		      f"Is admin: {project.is_admin}\n"
		      f"File count: {len(project.files)}")
	else:
		print(f"{project.remote.name}/{project.name} @ {project.url} (id: {project.id})")

def print_file_info(file: RemoteFile, extended=False):
	if extended:
		print(f"Name: {file.name}\n"
		      f"Description: {file.description}\n"
		      f"Id: {file.id}\n"
		      f"Url: {file.url}\n"
		      f"Created date: {file.created}\n"
		      f"Last modified date: {file.last_modified}\n"
		      f"Last snapshot date: {file.last_snapshot}\n"
		      f"Contents hash: {file.hash}\n"
		      f"Contents size: {file.size}\n"
		      f"Default path on disk: {file.default_bndb_path}\n"
		      f"Snapshot count: {len(file.snapshots)}")
	else:
		print(f"{file.remote.name}/{file.project.name}/{file.name} @ {file.url} (id: {file.id})")


def main():
	parser = argparse.ArgumentParser(prog=sys.argv[0])
	subparsers = parser.add_subparsers(dest='command', help="Commands", required=True)

	remote_parser = subparsers.add_parser("remote", help="Remote-specific commands")
	remote_subparsers = remote_parser.add_subparsers(dest='remote_command', help="Remote-specific commands", required=True)

	remote_add_parser = remote_subparsers.add_parser("add", help="Add new Remote")
	remote_add_parser.add_argument("name", type=str)
	remote_add_parser.add_argument("address", type=str)

	remote_remove_parser = remote_subparsers.add_parser("remove", help="Remove existing Remote")
	remote_remove_parser.add_argument("name", type=str)

	remote_list_parser = remote_subparsers.add_parser("list", help="List existing Remotes")

	remote_info_parser = remote_subparsers.add_parser("info", help="Lookup remote information")
	remote_info_parser.add_argument("name", type=str)

	project_parser = subparsers.add_parser("project", help="Project-specific commands")
	project_subparsers = project_parser.add_subparsers(dest='project_command', help="Project-specific commands", required=True)

	project_create_parser = project_subparsers.add_parser("create", help="Create new Project")
	project_create_parser.add_argument("remote", type=str)
	project_create_parser.add_argument("name", type=str)
	project_create_parser.add_argument("description", type=str)

	project_delete_parser = project_subparsers.add_parser("delete", help="Delete existing Project")
	project_delete_parser.add_argument("remote", type=str)
	project_delete_parser.add_argument("name", type=str)

	project_list_parser = project_subparsers.add_parser("list", help="List Projects in Remote")
	project_list_parser.add_argument("remote", type=str)

	project_info_parser = project_subparsers.add_parser("info", help="Lookup Project information")
	project_info_parser.add_argument("remote", type=str)
	project_info_parser.add_argument("name", type=str)

	file_parser = subparsers.add_parser("file", help="File-specific commands")
	file_subparsers = file_parser.add_subparsers(dest='file_command', help="File-specific commands", required=True)

	file_upload_parser = file_subparsers.add_parser("upload", help="Upload new File")
	file_upload_parser.add_argument("remote", type=str)
	file_upload_parser.add_argument("project", type=str)
	file_upload_parser.add_argument("filepath", type=str)
	file_upload_parser.add_argument("description", type=str)

	file_download_parser = file_subparsers.add_parser("download", help="Download existing File")
	file_download_parser.add_argument("remote", type=str)
	file_download_parser.add_argument("project", type=str)
	file_download_parser.add_argument("name", type=str)

	file_delete_parser = file_subparsers.add_parser("delete", help="Delete existing File")
	file_delete_parser.add_argument("remote", type=str)
	file_delete_parser.add_argument("project", type=str)
	file_delete_parser.add_argument("name", type=str)

	file_list_parser = file_subparsers.add_parser("list", help="List Files in Project")
	file_list_parser.add_argument("remote", type=str)
	file_list_parser.add_argument("project", type=str)

	file_info_parser = file_subparsers.add_parser("info", help="Lookup File information")
	file_info_parser.add_argument("remote", type=str)
	file_info_parser.add_argument("project", type=str)
	file_info_parser.add_argument("name", type=str)

	args = parser.parse_args(sys.argv[1:])
	if args.command == "remote":
		if args.remote_command == "add":
			remote = Remote(args.name, args.address)
			collaboration.add_known_remote(remote)
			collaboration.save_remotes()
			print_remote_info(remote)
		elif args.remote_command == "remove":
			remote = collaboration.get_remote_by_name(args.name)
			if remote is None:
				print(f"Unknown Remote: {args.name}")
				sys.exit(1)
			collaboration.remove_known_remote(remote)
			collaboration.save_remotes()
			print_remote_info(remote)
		elif args.remote_command == "list":
			for remote in collaboration.known_remotes():
				print_remote_info(remote)
		elif args.remote_command == "info":
			remote = collaboration.get_remote_by_name(args.name)
			if remote is None:
				print(f"Unknown Remote: {args.name}")
				sys.exit(1)
			print_remote_info(remote, extended=True)
	elif args.command == "project":
		# Connect to remote
		remote = collaboration.get_remote_by_name(args.remote)
		if remote is None:
			print(f"Unknown Remote: {args.remote}")
			sys.exit(1)

		try:
			remote.connect()
		except RuntimeError as e:
			print(f"Could not connect to Remote {args.remote}: {e}")
			sys.exit(1)

		if args.project_command == "create":
			project = remote.create_project(args.name, args.description)
			print_project_info(project)
		elif args.project_command == "delete":
			project = remote.get_project_by_name(args.name)
			if project is None:
				print(f"Unknown Project: {args.name}")
				sys.exit(1)
			remote.delete_project(project)
			print_project_info(project)
		elif args.project_command == "list":
			for project in remote.projects:
				print_project_info(project)
		elif args.project_command == "info":
			project = remote.get_project_by_name(args.name)
			if project is None:
				print(f"Unknown Project: {args.name}")
				sys.exit(1)
			print_project_info(project, extended=True)
	elif args.command == "file":
		# Connect to remote
		remote = collaboration.get_remote_by_name(args.remote)
		if remote is None:
			print(f"Unknown Remote: {args.remote}")
			sys.exit(1)

		try:
			remote.connect()
		except RuntimeError as e:
			print(f"Could not connect to Remote {args.remote}: {e}")
			sys.exit(1)

		project = remote.get_project_by_name(args.project)
		if project is None:
			print(f"Unknown Project: {args.project}")
			sys.exit(1)

		if args.file_command == "upload":
			with TqdmProgress(desc="", leave=False) as t:
				file = project.upload_new_file(args.filepath, progress=lambda cur, max: t.progress(cur, max))
			file.description = args.description
			print_file_info(file)
		elif args.file_command == "download":
			file = project.get_file_by_name(args.name)
			if file is None:
				print(f"Unknown File: {args.name}")
				sys.exit(1)
			with TqdmProgress(desc="", leave=False) as t:
				file.download(lambda cur, max: t.progress(cur, max))
			print_file_info(file)
		elif args.file_command == "delete":
			file = project.get_file_by_name(args.name)
			if file is None:
				print(f"Unknown File: {args.name}")
				sys.exit(1)
			print_file_info(file)
			project.delete_file(file)
		elif args.file_command == "list":
			for file in project.files:
				print_file_info(file)
		elif args.file_command == "info":
			file = project.get_file_by_name(args.name)
			if file is None:
				print(f"Unknown File: {args.name}")
				sys.exit(1)
			print_file_info(file, extended=True)
	else:
		pass


try:
	from tqdm import tqdm

	class TqdmProgress(tqdm):
		def __init__(self, *args, **kwargs):
			kwargs['total'] = 100
			super(TqdmProgress, self).__init__(*args, **kwargs)

		def progress(self, cur, max):
			new_n = cur / max * self.total
			self.update(new_n - self.n)
			return True

except ImportError:
	# Stub class
	class TqdmProgress:
		def __init__(self, *args, **kwargs):
			pass

		def __enter__(self):
			return TqdmProgress()

		def __exit__(self, exc_type, exc_val, exc_tb):
			pass

		def progress(self, cur, max):
			pass


if __name__ == '__main__':
	os.environ["BN_DISABLE_USER_PLUGINS"] = "True"

	# Short checkout and don't release, in case you want to run this many times in a row
	with enterprise.LicenseCheckout(duration=120, release=False):
		main()

