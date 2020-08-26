#!/usr/bin/env python3
'''Note that this script will only function for headless licenses at this time.'''
import argparse
import json
import os
import requests
import sys
import urllib

from pathlib import Path

url='https://master.binary.ninja/headless-download'

if sys.platform == "darwin":
	userpath = Path.home() / 'Library' / 'Application Support' / 'Binary Ninja'
elif sys.platform.startswith("linux"):
	userpath = Path.home() / '.binaryninja'
else:
	userpath = Path.home() / 'AppData' / 'Roaming' / 'Binary Ninja'

serial = ''
parser = argparse.ArgumentParser(description='Download a Binary Ninja installer with a headless license')
parser.add_argument("--serial", help="serial number")
parser.add_argument('--dev', dest='dev', default=False, action='store_true')
args = parser.parse_args()

if args.serial:
	serial = args.serial
elif userpath.is_dir():
	if (userpath / 'license.dat').is_file():
		with open(userpath / 'license.dat') as f:
			licenses = json.load(f)
			for license in licenses:
				if 'headless' in license['product']:
					serial = license['serial']

if serial == '':
	parser.print_help()
	sys.exit(-1)

params = {'serial': serial, 'dev': str(args.dev).lower()}

r = requests.get(url, params)
results = json.loads(r.text)
if results['ok']:
	url = results['url']
	r = requests.get(url, allow_redirects=True)
	filename = os.path.basename(urllib.parse.urlparse(url).path)
	if len(r.content) < 2**13:
		print(f'Error downloading from {url}')
	else:
		open(filename, 'wb').write(r.content)
else:
	print('Download failed.')
