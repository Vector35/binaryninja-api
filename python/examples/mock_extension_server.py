#!/usr/bin/env python3
"""
Mock Binary Ninja Extension Manager API server

Usage:
    python mock_extension_server.py [--name NAME] [--host HOST] [--port PORT] plugin.json [plugin.json ...]
"""

import argparse
import hashlib
import http.server
import io
import json
import logging
import re
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

log = logging.getLogger(__name__)

PLATFORMS = [
    "darwin-x64",
    "darwin-arm64",
    "linux-x64",
    "linux-arm64",
    "win-x64",
    "win-arm64",
]

# Module-level state populated at startup via CLI args (read at request time by route handlers)
plugin_files: list[Path] = []
manifest_name: str = "Mock Manifest"
manifest_uuid: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000001")
manifest_slug: str = "mock-manifest"


# --- ID helpers ---


def _str_uuid(s: str) -> uuid.UUID:
    """Deterministic UUID from an arbitrary string via MD5."""
    return uuid.UUID(hashlib.md5(s.encode()).hexdigest())


def _ext_id(plugin: dict) -> uuid.UUID:
    return _str_uuid(f"extension:{plugin['name']}")


def _ver_id(ext_id: uuid.UUID, version: str) -> uuid.UUID:
    return _str_uuid(f"version:{ext_id}:{version}")


def _pv_id(ver_id: uuid.UUID, platform: str) -> uuid.UUID:
    return _str_uuid(f"platform_version:{ver_id}:{platform}")


def _category_id(name: str) -> int:
    return int(hashlib.md5(name.encode()).hexdigest()[:8], 16) % 9999 + 1


# --- Data helpers ---


def _name_to_path(name: str) -> str:
    path = re.sub(r"[^a-zA-Z0-9]", "_", name.lower())
    return re.sub(r"_+", "_", path).strip("_")


def _normalize_dependencies(raw_dependencies) -> dict:
    if not isinstance(raw_dependencies, dict):
        return {}

    dependencies = {}
    for name, values in raw_dependencies.items():
        if isinstance(values, list):
            normalized = [
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            ]
        elif isinstance(values, str):
            normalized = [
                value.strip() for value in values.splitlines() if value.strip()
            ]
        else:
            normalized = []
        if normalized:
            dependencies[name] = normalized
    return dependencies


def _minimum_client_build(value) -> int:
    if isinstance(value, dict):
        builds = [_minimum_client_build(item) for item in value.values()]
        return max(builds, default=0)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        components = re.findall(r"\d+", value)
        return int(components[-1]) if components else 0
    return 0


def _normalize_platforms(value) -> list[str]:
    if value is None:
        return list(PLATFORMS)
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []

    aliases = {
        "darwin": ["darwin-x64", "darwin-arm64"],
        "macos": ["darwin-x64", "darwin-arm64"],
        "linux": ["linux-x64", "linux-arm64"],
        "windows": ["win-x64", "win-arm64"],
        "win": ["win-x64", "win-arm64"],
    }
    selected = set()
    for item in value:
        if not isinstance(item, str):
            continue
        platform = item.lower()
        if platform in PLATFORMS:
            selected.add(platform)
        else:
            selected.update(aliases.get(platform, []))
    return [platform for platform in PLATFORMS if platform in selected]


def _normalize_plugin(data: dict) -> dict:
    if "plugin" in data and isinstance(data["plugin"], dict):
        data = data["plugin"]

    plugin = dict(data)
    raw_version = data.get("version", "1.0.0")
    version = (
        dict(raw_version)
        if isinstance(raw_version, dict)
        else {"version_string": str(raw_version)}
    )
    version.setdefault("version_string", "1.0.0")
    version.setdefault("long_description", data.get("longdescription", ""))
    version.setdefault("changelog", data.get("changelog", ""))
    version.setdefault("subdir", data.get("subdir", ""))
    version.setdefault("created", data.get("created", ""))
    minimum_client_version = (
        version.get("minimum_client_version")
        or data.get("minimum_client_version")
        or data.get("minimumbinaryninjaversion")
        or data.get("minimumBinaryNinjaVersion")
        or 0
    )
    version["minimum_client_version"] = _minimum_client_build(
        minimum_client_version
    )
    version["dependencies"] = _normalize_dependencies(
        version.get("dependencies", data.get("dependencies", {}))
    )
    version["platforms"] = _normalize_platforms(
        version.get("platforms", data.get("platforms"))
    )

    categories = data.get("categories", data.get("type", []))
    if isinstance(categories, str):
        categories = [categories]
    plugin["categories"] = [
        {"id": _category_id(category), "name": category}
        if isinstance(category, str)
        else category
        for category in categories
        if isinstance(category, (str, dict))
    ]
    plugin["short_description"] = data.get(
        "short_description", data.get("description", "")
    )
    plugin["author_name"] = data.get("author_name", data.get("author", ""))
    plugin["homepage"] = data.get("homepage", data.get("projectUrl", ""))
    plugin["path"] = data.get("path") or _name_to_path(data["name"])
    using_apis = data.get("using_apis", data.get("api", []))
    plugin["using_apis"] = (
        [using_apis] if isinstance(using_apis, str) else using_apis
    )

    license_data = data.get("license", "")
    if isinstance(license_data, dict):
        plugin["license_name"] = data.get(
            "license_name", license_data.get("name", "")
        )
        plugin["license"] = license_data.get("text", "")
    else:
        plugin["license_name"] = data.get("license_name", "")
        plugin["license"] = str(license_data)
    plugin["version"] = version
    return plugin


def _load_plugin(path: Path) -> dict:
    return _normalize_plugin(json.loads(path.read_text()))


# --- URL helpers ---


def _url(base: str, path: str) -> str:
    return f"{base}{path}"


def _paginate_url(request_url: str, page: int) -> str:
    parsed = urlparse(request_url)
    qs = parse_qs(parsed.query)
    qs["page"] = [str(page)]
    return parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})).geturl()


# --- Response builders ---


def _manifest_response(base_url: str) -> dict:
    mid = str(manifest_uuid)
    return {
        "id": mid,
        "name": manifest_name,
        "extensions_url": _url(base_url, f"/v2/manifests/{mid}/extensions"),
    }


def _extension_response(plugin: dict, base_url: str) -> dict:
    ext_id = _ext_id(plugin)
    mid = str(manifest_uuid)
    ext_pk = str(ext_id)
    version_string = str(plugin["version"]["version_string"])
    ver_id = _ver_id(ext_id, version_string)

    return {
        "id": ext_pk,
        "name": plugin["name"],
        "type": 0,
        "short_description": plugin.get("short_description", ""),
        "author_name": plugin.get("author_name", ""),
        "categories": plugin.get("categories", []),
        "homepage": plugin.get("homepage", ""),
        "path": plugin["path"],
        "using_apis": plugin.get("using_apis", []),
        "state": 0,
        "versions_url": _url(
            base_url, f"/v2/manifests/{mid}/extensions/{ext_pk}/versions"
        ),
        "official": False,
        "is_paid": False,
        "latest_version_id": str(ver_id),
        "view_only": False,
        "license_name": plugin.get("license_name", ""),
        "license": plugin.get("license", ""),
    }


def _version_response(plugin: dict, base_url: str, path: Path) -> dict:
    ext_id = _ext_id(plugin)
    mid = str(manifest_uuid)
    ext_pk = str(ext_id)
    version = plugin["version"]
    version_string = str(version["version_string"])
    ver_id = _ver_id(ext_id, version_string)
    ver_pk = str(ver_id)

    platform_versions = []
    for platform in version.get("platforms", PLATFORMS):
        pv_pk = str(_pv_id(ver_id, platform))
        dl_url = _url(
            base_url,
            f"/v2/manifests/{mid}/extensions/{ext_pk}/versions/{ver_pk}/platforms/{pv_pk}/download",
        )
        platform_versions.append(
            {
                "platform": {"name": platform},
                "download_url": dl_url,
                "untracked_download_url": dl_url + "?notrack=1",
            }
        )

    return {
        "id": ver_pk,
        "version_string": version_string,
        "long_description": version.get("long_description", ""),
        "changelog": version.get("changelog", ""),
        "dependencies": _normalize_dependencies(version.get("dependencies", {})),
        "minimum_client_version": int(version.get("minimum_client_version", 0)),
        "created": version.get("created") or datetime.fromtimestamp(
            path.stat().st_mtime, tz=timezone.utc).isoformat(),
        "platform_versions": platform_versions,
        "subdir": version.get("subdir", ""),
    }


def _paginate(items: list, page: int, request_url: str) -> dict:
    page_size = 100
    p = max(1, page)
    start = (p - 1) * page_size
    end = start + page_size
    return {
        "count": len(items),
        "next": _paginate_url(request_url, p + 1) if end < len(items) else None,
        "previous": _paginate_url(request_url, p - 1) if p > 1 else None,
        "results": items[start:end],
    }


# --- HTTP handler ---

ROUTES = [
    (re.compile(r"^/v2/manifests/?$"), "list_manifests"),
    (
        re.compile(r"^/v2/manifests/(?P<manifest_pk>[^/]+)/extensions/?$"),
        "list_extensions",
    ),
    (
        re.compile(
            r"^/v2/manifests/(?P<manifest_pk>[^/]+)/extensions/(?P<extension_pk>[^/]+)/versions/?$"
        ),
        "list_versions",
    ),
    (
        re.compile(
            r"^/v2/manifests/(?P<manifest_pk>[^/]+)/extensions/(?P<extension_pk>[^/]+)/versions/(?P<version_pk>[^/]+)/platforms/(?P<pk>[^/]+)/download/?$"
        ),
        "download",
    ),
]


class _HTTPError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log.info(f"{self.address_string()} - {format % args}")

    @property
    def base_url(self) -> str:
        addr: tuple[str, int] = self.server.server_address  # type: ignore[assignment]
        host = self.headers.get("Host") or f"{addr[0]}:{addr[1]}"
        return f"http://{host}"

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        page = int(qs.get("page", ["1"])[0])
        request_url = self.base_url + self.path

        for pattern, handler_name in ROUTES:
            m = pattern.match(parsed.path)
            if m:
                try:
                    getattr(self, f"_handle_{handler_name}")(
                        m.groupdict(), page, request_url
                    )
                except _HTTPError as e:
                    self._send_json(e.status, {"detail": e.detail})
                return

        self._send_json(404, {"detail": "Not found"})

    def _resolve_manifest(self, manifest_pk: str) -> None:
        if manifest_pk not in (str(manifest_uuid), manifest_slug, manifest_name):
            raise _HTTPError(404, "Manifest not found")

    def _handle_list_manifests(self, *_) -> None:
        self._send_json(200, [_manifest_response(self.base_url)])

    def _handle_list_extensions(
        self, kwargs: dict, page: int, request_url: str
    ) -> None:
        self._resolve_manifest(kwargs["manifest_pk"])
        extensions = []
        for path in plugin_files:
            try:
                extensions.append(
                    _extension_response(_load_plugin(path), self.base_url)
                )
            except Exception as e:
                log.warning("Failed to load %s: %s", path, e)
        self._send_json(
            200,
            _paginate(sorted(extensions, key=lambda e: e["name"]), page, request_url),
        )

    def _handle_list_versions(self, kwargs: dict, page: int, request_url: str) -> None:
        self._resolve_manifest(kwargs["manifest_pk"])
        for path in plugin_files:
            try:
                plugin = _load_plugin(path)
                if str(_ext_id(plugin)) == kwargs["extension_pk"]:
                    self._send_json(
                        200,
                        _paginate(
                            [_version_response(plugin, self.base_url, path)],
                            page,
                            request_url,
                        ),
                    )
                    return
            except Exception as e:
                log.warning("Failed to load %s: %s", path, e)
        raise _HTTPError(404, "Extension not found")

    def _handle_download(self, kwargs: dict, *_) -> None:
        for path in plugin_files:
            try:
                plugin = _load_plugin(path)
                if str(_ext_id(plugin)) != kwargs["extension_pk"]:
                    continue
                plugin_dir = path.parent
                folder_name = plugin_dir.name
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for file_path in sorted(plugin_dir.rglob("*")):
                        if (
                            file_path.is_file()
                            and file_path.relative_to(plugin_dir).parts[0] != ".git"
                        ):
                            zf.write(
                                file_path,
                                Path(folder_name) / file_path.relative_to(plugin_dir),
                            )
                body = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{folder_name}.zip"'
                )
                self.end_headers()
                self.wfile.write(body)
                return
            except Exception as e:
                log.warning("Failed to load %s: %s", path, e)
        raise _HTTPError(404, "Extension not found")

    def _send_json(self, status: int, data) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mock Binary Ninja Extension Manager API"
    )
    parser.add_argument(
        "--name",
        default="Mock Manifest",
        help="Manifest name (default: 'Mock Manifest')",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port to listen on (default: 8000)"
    )
    parser.add_argument(
        "plugin_files",
        nargs="+",
        metavar="plugin.json",
        help="v1 or v2 plugin metadata files to serve over the v2 API",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    plugin_files[:] = [Path(f) for f in args.plugin_files]
    manifest_name = args.name
    manifest_uuid = _str_uuid(f"manifest:{args.name}")
    manifest_slug = re.sub(
        r"-+", "-", re.sub(r"[^a-z0-9]", "-", args.name.lower())
    ).strip("-")

    log.info(f"Manifest:  {manifest_name}")
    log.info(f"UUID:      {manifest_uuid}")
    log.info(f"Slug:      {manifest_slug}")
    log.info(f"Plugins:   {len(plugin_files)}")
    log.info(f"Serving on http://{args.host}:{args.port}")

    http.server.HTTPServer((args.host, args.port), Handler).serve_forever()
