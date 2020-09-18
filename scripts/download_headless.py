#!/usr/bin/env python3
'''Note that this script will only function for headless licenses at this time.'''
import json
import os
import requests
import sys
import urllib

from pathlib import Path

class DownloadException(Exception):
    pass

url='https://master.binary.ninja/headless-download'
env_lic = 'HEADLESS_LICENSE'
min_download = 8192

def get_system_license_path() -> Path:
	"""Returns the default path to the Binary Ninja license.dat on the current platform

	:return: Path object to the license.dat file.
	:rtype: Path
	"""
	if sys.platform == "darwin":
		return Path.home() / 'Library' / 'Application Support' / 'Binary Ninja' / 'license.dat'
	elif sys.platform.startswith("linux"):
		return Path.home() / '.binaryninja' / 'license.dat'
	else:
		return Path.home() / 'AppData' / 'Roaming' / 'Binary Ninja' / 'license.dat'


def get_serial_from_license(path: str) -> str:
	"""Extracts the serial number from the license specified in path

	:param path: path to license file
	:type path: str
	:raises ValueError: When no headless license is found in the provided license.dat
	:return: returns the serial number of the headless license
	:rtype: str
	"""
	with open(path) as f:
		for license in [l for l in json.load(f) if 'Headless' in l['product']]:
			return license['serial']
		raise ValueError(f'No "computer" license in {path}')


def get_serial_from_environment(env: str='HEADLESS_LICENSE') -> str:
	"""Extracts the serial number from the license file referenced by the env

	:param env: environment variable containing headless license path, defaults to 'HEADLESS_LICENSE'
	:type env: str, optional
	:raises ValueError: When provided envronment variable doesn't exist or license doesn't contain a headless license.
	:return: the serial number
	:rtype: str
	"""
	if env not in os.environ:
		raise ValueError(f'Please add an environment variable {env} pointing to your headless Binary Ninja license')

	return get_serial_from_license(os.environ[env])


def download_headless(serial: str, output_path: str=None, dev: bool=False) -> str:
	"""Downloads the headless Binary Ninja installation binaries.

	:param serial: Serial number for verification
	:type serial: str
	:param output_path: path to write the binaries to, defaults to None
	:type output_path: str, optional
	:param dev: set to True if you wish to download 'dev' branch, defaults to False
	:type dev: bool, optional
	:raises DownloadException: On failure to download the requested binaries.
	"""
	r = requests.get(url, {'serial': serial, 'dev': str(dev).lower()})
	results = json.loads(r.text)
	if not results['ok']:
		raise DownloadException('Download failed.')

	req_url = results['url']
	content = requests.get(req_url, allow_redirects=True)
	if len(content.content) < min_download:
		raise DownloadException(f'Error downloading from {req_url}')

	if output_path is None:
		output_path = os.path.basename(urllib.parse.urlparse(req_url).path)
	with open(output_path, 'wb') as f:
		f.write(content.content)
	return output_path

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Download a Binary Ninja installer given a headless license')
	parser.add_argument('--serial', default=None, help='serial number')
	parser.add_argument('--env', default=False, action='store_true', help='will extract serial from enviroment variable "HEADLESS_LICENSE" if not specfied')
	parser.add_argument('--dev', default=False, action='store_true', help='download the development branch')
	parser.add_argument('--output', default=None, help='path to write the file to (defaults to current directory)')
	parser.add_argument('-q', '--quiet', default=False, action='store_true', help='Don\'t show any output')
	args = parser.parse_args()

	try:
		if args.serial is None:
			if args.env:
				args.serial = get_serial_from_environment()
			else:
				args.serial = get_serial_from_license(get_system_license_path())

		download_path = download_headless(args.serial, args.output, args.dev)
		if not args.quiet:
			print(f"Successfully downloaded to: {download_path}")
		sys.exit(0)
	except Exception as e:
		if not args.quiet:
			print(e)
		sys.exit(1)
