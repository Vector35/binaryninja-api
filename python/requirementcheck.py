# Copyright (c) 2015-2026 Vector 35 Inc
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


import json
import re
from typing import Dict, Iterable, List, Optional


def pip_requirements_from_dependency_metadata(dependencies: bytes) -> List[str]:
	raw_text = dependencies.decode("utf-8")
	try:
		# Dependencies might be specified in JSON format, which we need to translate to text.
		dependencies_json = json.loads(raw_text)
		pip_dependencies = dependencies_json.get("pip", "") if isinstance(dependencies_json, dict) else ""
	except json.JSONDecodeError:
		# If we can't parse input as JSON, it's probably already in text format.
		pip_dependencies = raw_text

	if isinstance(pip_dependencies, list):
		lines = [
			line
			for requirement in pip_dependencies if isinstance(requirement, str)
			for line in requirement.split('\n')
		]
	elif isinstance(pip_dependencies, str):
		lines = pip_dependencies.split('\n')
	else:
		return []

	result = []
	for line in lines:
		line = line.strip()
		if not line or line.startswith('#'):
			continue
		comment = re.search(r'\s+#', line)
		if comment:
			line = line[:comment.start()].rstrip()
		if line:
			result.append(line)
	return result


def pip_requirements_satisfied(requirements: Iterable[str], installed_versions: Optional[Dict[str, str]] = None) -> bool:
	try:
		from importlib import metadata as importlib_metadata
		from packaging.requirements import Requirement
		from packaging.utils import canonicalize_name
	except Exception:
		from importlib import metadata as importlib_metadata
		from pip._vendor.packaging.requirements import Requirement
		from pip._vendor.packaging.utils import canonicalize_name

	if installed_versions is None:
		installed_versions = {}
		for dist in importlib_metadata.distributions():
			name = dist.metadata.get("Name")
			if name:
				installed_versions[canonicalize_name(name)] = dist.version
	else:
		installed_versions = {canonicalize_name(name): version for name, version in installed_versions.items()}

	for requirement_text in requirements:
		requirement = Requirement(requirement_text)
		if requirement.marker is not None and not requirement.marker.evaluate():
			continue

		version = installed_versions.get(canonicalize_name(requirement.name))
		if version is None:
			return False
		if requirement.specifier and not requirement.specifier.contains(version, prereleases=True):
			return False

	return True
