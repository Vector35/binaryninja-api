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
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence


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


@dataclass(frozen=True)
class DependencyRequirement:
	plugin_name: str
	requirement: str


@dataclass(frozen=True)
class DependencyConflict:
	status: str
	package_name: str
	candidate_requirements: Sequence[DependencyRequirement]
	installed_requirements: Sequence[DependencyRequirement]


def _requirement_parts(requirement_text: str):
	# Parse only the active dependency and version specifier forms we can
	# compare safely. See the following specifications for more information:
	# https://packaging.python.org/en/latest/specifications/dependency-specifiers/#dependency-specifiers
	# https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers
	try:
		from packaging.requirements import Requirement
		from packaging.specifiers import Specifier
		from packaging.utils import canonicalize_name
		from packaging.version import Version, InvalidVersion
	except Exception:
		from pip._vendor.packaging.requirements import Requirement
		from pip._vendor.packaging.specifiers import Specifier
		from pip._vendor.packaging.utils import canonicalize_name
		from pip._vendor.packaging.version import Version, InvalidVersion

	try:
		requirement = Requirement(requirement_text)
		if requirement.marker is not None and not requirement.marker.evaluate():
			return None
		if requirement.url is not None:
			return (canonicalize_name(requirement.name), None, None)
		bounds = []
		for specifier in requirement.specifier:
			if specifier.operator not in {"<", "<=", ">", ">=", "=="} or "*" in specifier.version:
				return (canonicalize_name(requirement.name), None, None)
			try:
				bounds.append((specifier.operator, Version(specifier.version)))
			except InvalidVersion:
				return (canonicalize_name(requirement.name), None, None)
		return (canonicalize_name(requirement.name), bounds, Specifier)
	except Exception:
		return ("<unknown>", None, None)


def _constraint_status(bounds, specifier_type) -> str:
	lower = None
	upper = None
	exacts = []
	specifiers = [specifier_type(f"{operator}{version}") for operator, version in bounds]
	for operator, version in bounds:
		if operator == "==":
			exacts.append(version)
		elif operator in {">", ">="}:
			candidate = (version, operator == ">=")
			if lower is None or candidate[0] > lower[0] or (candidate[0] == lower[0] and not candidate[1]):
				lower = candidate
		else:
			candidate = (version, operator == "<=")
			if upper is None or candidate[0] < upper[0] or (candidate[0] == upper[0] and not candidate[1]):
				upper = candidate
	if exacts:
		return "compatible" if any(all(specifier.contains(version, prereleases=True)
			for specifier in specifiers) for version in exacts) else "conflict"
	if lower is None or upper is None:
		return "compatible"
	if lower[0] > upper[0] or (lower[0] == upper[0] and not (lower[1] and upper[1])):
		return "conflict"
	if lower[0] == upper[0]:
		return "compatible"
	if not lower[1] or not upper[1]:
		# Strict bounds have special pre- and post-release exclusions under the
		# version-specifier rules. We need to check the actual specifiers to
		# prove compatibility. Otherwise, just conservatively say we don't know.
		version_type = type(lower[0])
		candidates = [lower[0], upper[0]]
		for boundary in (lower[0], upper[0]):
			release = list(boundary.release)
			candidates.append(version_type(".".join(map(str, release[:-1] + [release[-1] + 1]))))
			for depth in range(1, 4):
				candidates.append(version_type(".".join(map(str, release + ([0] * depth) + [1]))))
		if any(all(specifier.contains(version, prereleases=True) for specifier in specifiers)
			for version in candidates):
			return "compatible"
		return "unknown_compatibility"
	return "compatible"


def pip_dependency_conflicts(candidate_name: str, candidate_dependencies: bytes,
		installed_plugins: Iterable[tuple[str, bytes]]) -> List[DependencyConflict]:
	"""Compare active requirements for a candidate plugin.

	See the following for more on dependency and version specifiers:

	- https://packaging.python.org/en/latest/specifications/dependency-specifiers/#dependency-specifiers
	- https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers

	Markers that do not apply are ignored. Only a subset of the possible operators are
	handled and the result we hand back is conservative if we can't prove a conflict.
	"""
	def requirements(plugin_name: str, dependencies: bytes):
		try:
			return [(DependencyRequirement(plugin_name, text), _requirement_parts(text))
				for text in pip_requirements_from_dependency_metadata(dependencies)]
		except Exception:
			return [(DependencyRequirement(plugin_name, dependencies.decode("utf-8", errors="replace")),
				("<unknown>", None, None))]

	candidate = requirements(candidate_name, candidate_dependencies)
	installed_groups = [requirements(name, dependencies) for name, dependencies in installed_plugins]
	installed = [requirement for group in installed_groups for requirement in group]
	result = []
	package_names = dict.fromkeys(parts[0] for _, parts in candidate if parts is not None)
	for package_name in package_names:
		candidate_same_package = [(requirement, parts) for requirement, parts in candidate
			if parts is not None and parts[0] == package_name]
		matching = [(requirement, parts) for requirement, parts in installed
			if parts is not None and parts[0] == package_name]
		candidate_unknown = any(parts[1] is None for _, parts in candidate_same_package)
		candidate_bounds = [bound for _, parts in candidate_same_package if parts[1] is not None for bound in parts[1]]
		specifier_type = next((parts[2] for _, parts in candidate_same_package + matching if parts[2] is not None), None)
		candidate_status = _constraint_status(candidate_bounds, specifier_type)
		if candidate_status == "conflict":
			result.append(DependencyConflict("proven_conflict", package_name,
				[requirement for requirement, _ in candidate_same_package], []))
			continue
		proven = []
		unknown = []
		for installed_group in installed_groups:
			installed_same_plugin = [(requirement, parts) for requirement, parts in installed_group
				if parts is not None and parts[0] == package_name]
			if not installed_same_plugin:
				continue
			installed_bounds = [bound for _, parts in installed_same_plugin if parts[1] is not None for bound in parts[1]]
			installed_unknown = any(parts[1] is None for _, parts in installed_same_plugin)
			installed_status = _constraint_status(installed_bounds, specifier_type)
			combined_status = _constraint_status(candidate_bounds + installed_bounds, specifier_type)
			if installed_status != "conflict" and combined_status == "conflict":
				proven.extend(requirement for requirement, _ in installed_same_plugin)
			elif installed_unknown or combined_status == "unknown_compatibility":
				unknown.extend(requirement for requirement, _ in installed_same_plugin)
		if proven:
			result.append(DependencyConflict("proven_conflict", package_name,
				[requirement for requirement, _ in candidate_same_package],
				proven))
			continue
		if candidate_unknown or candidate_status == "unknown_compatibility" or unknown:
			result.append(DependencyConflict("unknown_compatibility", package_name,
				[requirement for requirement, _ in candidate_same_package],
				unknown))
	return result
