import argparse
import glob
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

import argparse

parser = argparse.ArgumentParser(
    description='Test building the API repo and plugins out-of-tree (for CI checking of end-user workflow)'
)
parser.add_argument('--headless', default=False, action='store_true', help='Only include headless plugins')
parser.add_argument('-j', '--parallel', default=4, help='Number of parallel jobs to tell cmake to run.')
args = parser.parse_args()

try:
	# Make sure we have clang!
	subprocess.check_call(['clang', '-v'])
except subprocess.SubprocessError as e:
	print("Clang not found! Please install clang and add it to PATH")
	sys.exit(1)

if not args.headless:
	try:
		# Also Qt
		subprocess.check_call(['qmake', '--version'])
	except subprocess.SubprocessError as e:
		print("qmake not found! Please install Qt and add it to PATH")
		sys.exit(1)

api_base = Path(__file__).parent.parent.absolute()

configure_args = []
build_args = []
configure_env = os.environ.copy()

if platform.system() == "Windows":
	configure_env['CXXFLAGS'] = f'/MP{args.parallel}'
	configure_env['CFLAGS'] = f'/MP{args.parallel}'
else:
	build_args.extend(['-j', str(args.parallel)])

if args.headless:
	configure_args.extend(['-DHEADLESS=1'])
else:
	configure_args.extend(['-DQT6=1', ])

# Copy api out of the source tree and build it externally
with tempfile.TemporaryDirectory() as tempdir:
	temp_api_base = Path(tempdir) / 'binaryninjaapi'
	print(f'Copy {api_base} => {temp_api_base}')
	shutil.copytree(api_base, temp_api_base)

	# Clean up dirty repo
	if (temp_api_base / 'build').exists():
		shutil.rmtree(temp_api_base / 'build')

	# Now try to build
	try:
		subprocess.check_call(['cmake', '-B', 'build'] + configure_args, cwd=temp_api_base, env=configure_env)
		subprocess.check_call(['cmake', '--build', 'build'] + build_args, cwd=temp_api_base)
	finally:
		if (temp_api_base / 'build').exists():
			shutil.rmtree(temp_api_base / 'build')

	# Now try to build examples (in-tree)
	try:
		subprocess.check_call(['cmake', '-B', 'build', '-DBN_API_BUILD_EXAMPLES=1'] + configure_args, cwd=temp_api_base,
		                      env=configure_env)
		subprocess.check_call(['cmake', '--build', 'build'] + build_args, cwd=temp_api_base)
	finally:
		if (temp_api_base / 'build').exists():
			shutil.rmtree(temp_api_base / 'build')

	# Now try to build examples (out-of-tree)
	for f in glob.glob(str(api_base / 'examples' / '**' / 'CMakeLists.txt'), recursive=True):
		example_base = Path(f).parent
		if example_base == api_base / 'examples':
			continue

		# Check for headless
		if args.headless:
			with open(f, 'r') as cmake_file:
				# Assume any ui plugin has 'binaryninjaui' in its contents
				if 'binaryninjaui' in cmake_file.read():
					continue

		with tempfile.TemporaryDirectory() as tempexdir:
			temp_example_base = Path(tempexdir) / example_base.name
			print(f'Copy {example_base} => {temp_example_base}')
			shutil.copytree(example_base, temp_example_base)

			if (temp_example_base / 'build').exists():
				shutil.rmtree(temp_example_base / 'build')

			try:
				subprocess.check_call(['cmake', '-B', 'build', f'-DBN_API_PATH={temp_api_base}'] + configure_args,
				                      cwd=temp_example_base, env=configure_env)
				subprocess.check_call(['cmake', '--build', 'build'] + build_args, cwd=temp_example_base)
			finally:
				if (temp_example_base / 'build').exists():
					shutil.rmtree(temp_example_base / 'build')
