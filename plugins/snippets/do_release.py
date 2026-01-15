#!/usr/bin/env python3
#Little utility to automatically do a new release.
from git import Repo
from json import load, dump
from github_release import gh_release_create
from sys import exit
from os import path
from argparse import ArgumentParser
from subprocess import run
'''WARNING: IF YOU DO NOT UPDATE YOUR README.md USING generate_plugininfo.py 
THIS PLUGIN WILL OVERWRITE IT!'''

parser = ArgumentParser()
parser.add_argument("-d", "--description", help="Description for the new release", action="store", dest="description", default="")
parser.add_argument("-v", "--version", help="New version string", action="store", dest="new_version", default="")
parser.add_argument("--force", help="Override the repository dirty check", action="store_true", dest="dirtyoverride", default=False)
args = parser.parse_args()
#TODO

repo = Repo(".")
reponame = list(repo.remotes.origin.urls)[0].split(':')[1].split('.')[0]
if repo.is_dirty() and not args.dirtyoverride:
	print("Cowardly refusing to do anything as the plugin repository is currently dirty.")
	exit(-1)

if not path.isfile("./generate_plugininfo.py"):
	print("Missing ./generate_plugininfo.py.")
	exit(-1)

with open('plugin.json') as plugin:
	data = load(plugin)

def update_version(data):
	print(f"Updating plugin with new version {data['version']}")
	with open('plugin.json', 'w') as plugin:
		dump(data, plugin)
	run(["./generate_plugininfo.py", "-r", "-f"], check=True)
	repo.index.add('plugin.json')
	repo.index.add('README.md')
	if args.description == "":
		repo.index.commit(f"Updating to {data['version']}")
	else:
		repo.index.commit(args.description)
	repo.git.push('origin')

for tag in repo.tags:
	if tag.name == data['version']:
		if args.new_version == "":
			print(f"Current plugin version {data['version']} is already a tag. Shall I increment it for you?")
			yn = input("[y/n]: ")
			if yn == "Y" or yn == "y":
				digits = data['version'].split('.')
				newlast = str(int(digits[-1])+1)
				digits[-1] = newlast
				inc_version = '.'.join(digits)
				data['version'] = inc_version
				update_version(data)
			else:
				print("Stopping...")
				exit(-1)
		else:
			data['version'] = args.new_version
			update_version(data)

# Create new tag
new_tag = repo.create_tag(data['version'])
# Push
repo.remotes.origin.push(data['version'])
# Create release
gh_release_create(reponame, data['version'], publish=True, name="%s v%s" % (data['name'], data['version']))
