"""Validate the static catalog; optionally verify published ZIPs without running code."""

import argparse
import hashlib
import io
import json
import re
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

MAX_PACKAGE = 256 * 1024 * 1024
RESERVED = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{i}" for prefix in ("com", "lpt") for i in range(1, 10)
}
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def https_url(value):
    parsed = urllib.parse.urlsplit(value)
    require(
        parsed.scheme == "https" and parsed.hostname and not parsed.username
        and not parsed.password and not parsed.fragment,
        f"Invalid HTTPS URL: {value}",
    )
    return value


def safe_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 512, "Invalid archive path")
    require("\\" not in value and ":" not in value, f"Unsafe archive path: {value}")
    for part in value.split("/"):
        require(
            part and part not in (".", "..") and not part.endswith((".", " "))
            and part.split(".")[0].lower() not in RESERVED
            and all(ord(c) >= 32 for c in part),
            f"Unsafe archive path: {value}",
        )


def validate_catalog(data):
    require(data.get("schemaVersion") == 1, "Unsupported schemaVersion")
    require(isinstance(data.get("name"), str) and 0 < len(data["name"].strip()) <= 120, "Invalid catalog name")
    plugins = data.get("plugins", [])
    require(isinstance(plugins, list) and len(plugins) <= 1000, "Invalid plugin list")
    seen = set()
    for p in plugins:
        identity = (p["kind"], p["id"])
        require(identity not in seen, "Duplicate kind:id")
        seen.add(identity)
        require(p["kind"] in ("provider", "lyrics"), "Invalid kind")
        require(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", p["id"]), "Invalid plugin id")
        require(".." not in p["id"] and not p["id"].endswith(".") and p["id"].split(".")[0] not in RESERVED, "Unsafe plugin id")
        require(isinstance(p["name"], str) and 0 < len(p["name"].strip()) <= 120, "Invalid plugin name")
        match = SEMVER.fullmatch(p["version"])
        require(match is not None, "Invalid SemVer")
        pre = match.group(4)
        require(not pre or not any(x.isdigit() and len(x) > 1 and x[0] == "0" for x in pre.split(".")), "Leading-zero prerelease")
        require(type(p.get("apiVersion", 1)) is int and p.get("apiVersion", 1) > 0, "Invalid apiVersion")
        require(type(p.get("minHostApiVersion", 1)) is int and p.get("minHostApiVersion", 1) > 0, "Invalid minHostApiVersion")
        require(len(p.get("description", "")) <= 8192 and len(p.get("changelog", "")) <= 16384, "Text too long")
        if p["kind"] == "lyrics":
            require(type(p.get("versionCode")) is int and p["versionCode"] > 0, "Missing lyrics versionCode")
        artifacts = p["artifacts"]
        require(isinstance(artifacts, list) and 1 <= len(artifacts) <= 32, "Invalid artifacts")
        targets = set()
        for a in artifacts:
            platform, arch = a["platform"], a.get("arch", "any")
            require(platform in ("any", "windows", "linux", "macos", "android"), "Invalid platform")
            require(arch in ("any", "x64", "arm64", "armv7"), "Invalid arch")
            require((platform, arch) not in targets, "Duplicate target artifact")
            targets.add((platform, arch))
            runtimes = ("http", "jni", "binary") if p["kind"] == "provider" else ("rhino-js",)
            require(a["runtime"] in runtimes, "Invalid runtime")
            if a["runtime"] in ("jni", "binary"):
                require(platform != "any" and arch != "any", "Native artifact needs an exact target")
            require(not (platform == "android" and a["runtime"] == "binary"), "Android binary not supported")
            https_url(a["url"])
            require(re.fullmatch(r"[0-9a-f]{64}", a["sha256"]), "Invalid SHA-256")
            require(type(a["bytes"]) is int and 1 <= a["bytes"] <= MAX_PACKAGE, "Invalid package length")
    return plugins


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(artifact):
    opener = urllib.request.build_opener(HttpsRedirect())
    request = urllib.request.Request(https_url(artifact["url"]), headers={"User-Agent": "CPPlayer-Catalog-Validator/1"})
    with opener.open(request, timeout=60) as response:
        require(response.status == 200, f"HTTP {response.status}")
        payload = response.read(artifact["bytes"] + 1)
    require(len(payload) == artifact["bytes"], "Package length mismatch")
    require(hashlib.sha256(payload).hexdigest() == artifact["sha256"], "SHA-256 mismatch")
    return payload


def verify_archive(plugin, artifact, payload):
    require(len(payload) == artifact["bytes"], "Package length mismatch")
    require(hashlib.sha256(payload).hexdigest() == artifact["sha256"], "SHA-256 mismatch")
    lyrics = plugin["kind"] == "lyrics"
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        require(len(entries) <= (512 if lyrics else 4096), "Too many archive entries")
        seen, total = set(), 0
        for entry in entries:
            name = entry.filename.rstrip("/")
            safe_path(name)
            require(name.lower() not in seen, "Case-insensitive duplicate archive path")
            seen.add(name.lower())
            require(name == "manifest.json" or not name.lower().endswith("/manifest.json"), "Nested manifest")
            if entry.is_dir():
                continue
            size = 0
            with archive.open(entry) as stream:
                while chunk := stream.read(65536):
                    size += len(chunk)
                    total += len(chunk)
                    require(size <= (16 * 1024 * 1024 if lyrics else MAX_PACKAGE), "Entry too large")
                    require(total <= (64 * 1024 * 1024 if lyrics else 512 * 1024 * 1024), "Archive expands too far")
            if name == "manifest.json":
                require(size <= 256 * 1024, "Manifest too large")
        m = json.loads(archive.read("manifest.json").decode("utf-8"))
        require(m["id"] == plugin["id"], "Manifest ID mismatch")
        require(m["versionName" if lyrics else "version"] == plugin["version"], "Manifest version mismatch")
        require(m.get("apiVersion", 1) == plugin.get("apiVersion", 1), "Manifest API mismatch")
        require(m.get("minHostApiVersion", 1) == plugin.get("minHostApiVersion", 1), "Manifest minimum host API mismatch")
        if lyrics:
            require(m.get("versionCode", 1) == plugin["versionCode"], "Manifest versionCode mismatch")
            safe_path(m.get("entry", "source.js"))
            require(m.get("entry", "source.js") in archive.namelist(), "Missing lyric entry")
            for path in m.get("includeDirs", []):
                safe_path(path)
        else:
            require(m["type"] == artifact["runtime"], "Manifest runtime mismatch")
            if m["type"] == "http":
                url = urllib.parse.urlsplit(m["entryPoint"])
                require(url.scheme in ("http", "https") and url.hostname and not url.username, "Invalid HTTP entry")
            else:
                safe_path(m["entryPoint"])
                abi = {"x64": "x86_64", "arm64": "arm64-v8a", "armv7": "armeabi-v7a"}[artifact["arch"]]
                paths = (m["entryPoint"], f"lib/{abi}/{m['entryPoint']}")
                require(any(path in archive.namelist() and not archive.getinfo(path).is_dir() for path in paths), "Missing native entry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", nargs="?", type=Path, default=Path(__file__).resolve().parents[1] / "index.json")
    parser.add_argument("--verify-packages", action="store_true")
    args = parser.parse_args()
    payload = args.catalog.read_bytes()
    require(len(payload) <= 5 * 1024 * 1024, "Catalog too large")
    plugins = validate_catalog(json.loads(payload.decode("utf-8")))
    downloaded = {}
    for plugin in plugins:
        for artifact in plugin["artifacts"]:
            if args.verify_packages:
                key = (artifact["url"], artifact["sha256"], artifact["bytes"])
                if key not in downloaded:
                    downloaded[key] = fetch(artifact)
                verify_archive(plugin, artifact, downloaded[key])
    print(f"Validated {len(plugins)} plugin(s); package checks: {args.verify_packages}")


if __name__ == "__main__":
    main()
