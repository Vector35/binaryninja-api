#!/usr/bin/env python3
'''Note that this script will only function for headless licenses at this time.'''
import json
import os
import requests
import sys
import urllib
import zipfile
import logging
from pathlib import Path


class DownloadException(Exception):
	pass


url = 'https://master.binary.ninja/headless-download'
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
		raise ValueError(f'No "Headless" license in {path}')


def download_headless(serial: str, output_path: str = None, dev: bool = False) -> str:
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
		message = results.get('message', 'No additional information available.')
		raise DownloadException('Download failed: {}'.format(message))

	req_url = results['url']
	content = requests.get(req_url, allow_redirects=True)
	if len(content.content) < min_download:
		raise DownloadException(f'Error downloading from {req_url}')

	if output_path is None:
		output_path = os.path.basename(urllib.parse.urlparse(req_url).path)
	with open(output_path, 'wb') as f:
		f.write(content.content)
	return output_path


def install_zip(zippath: str, installpath: str, clean: bool):
	with zipfile.ZipFile(zippath, 'r') as zip_ref:
		zip_ref.extractall(installpath)
	if clean:
		os.unlink(zippath)


def download_and_install(
  serial: str = None, downloaddir: str = None, dev: bool = False, clean: bool = False, install: bool = False,
  installdir: str = '/usr/local/bin'
):
	env_lic = 'BN_HEADLESS_LICENSE'
	if serial is None:
		if env_lic in os.environ:
			license_path = os.environ[env_lic]
		else:
			license_path = get_system_license_path()
		serial = get_serial_from_license(license_path)

	download_path = download_headless(serial, downloaddir, dev)
	logging.info(f"Successfully downloaded to: {download_path}")
	if install is True:
		install_zip(download_path, installdir, clean)
		logging.info(f"Successfully installed to {installdir}")


if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Download a Binary Ninja installer given a headless license')
	parser.add_argument('--serial', default=None, help='serial number')
	parser.add_argument('--dev', default=False, action='store_true', help='download the development branch')
	parser.add_argument('--output', default=None, help='path to write the file to (defaults to current directory)')
	parser.add_argument('-q', '--quiet', default=False, action='store_true', help='Don\'t show any output')
	parser.add_argument('-i', '--install', default=False, action='store_true', help='Install after downloading')
	parser.add_argument(
	  '-d', '--dir', default='/usr/local/bin', help='Install into provided directory used only when \'-i\' is specified'
	)
	parser.add_argument('-c', '--clean', default=False, action='store_true', help='Delete zip file after installation.')
	args = parser.parse_args()

	logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
	if args.quiet:
		logging.disable()
	try:
		download_and_install(args.serial, args.output, args.dev, args.clean, args.install, args.dir)
	except Exception as e:
		logging.critical(e)
		sys.exit(1)
