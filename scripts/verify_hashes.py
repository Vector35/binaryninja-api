#!/usr/bin/env python3
'''Simple script to verify SHA256 hashes and rename downloaded versions with their version number'''
import json
import requests
import hashlib
from pathlib import Path


class DownloadException(Exception):
	pass

def sha256(path):
    with open(filename,"rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

url = 'https://binary.ninja/js/hashes.json'
r = requests.get(url)
results = json.loads(r.text)
if not results['version']:
    raise DownloadException('Hash file does not exist or is incomplete.')

version = results["version"]
for filename in results["hashes"]:
    hash = results["hashes"][filename]
    binfile = Path(filename)
    if binfile.is_file():
        if sha256(binfile) == hash:
            newname = f"{filename[0:-4]}-{version}{filename[-4:]}"
            print(f"SHA256 matches for {filename}, renaming to {newname}")
            binfile.rename(newname)
        else:
            print(f"HASH FAILED for {filename}")
    else:
        print(f"No {filename} found")
