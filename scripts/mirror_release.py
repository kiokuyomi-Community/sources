#!/usr/bin/env python3
"""Mirror published ciphertext, never decrypt/re-encrypt it or change upstream.

TLS plus bounded schema/hash checks protect transport and consistency. The App
remains responsible for cryptographic signature verification and decryption.
No encryption keys or signing private keys are accepted by this program.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

UPSTREAM = "https://sources.kiokuyomi.com"
REPOSITORY = "kiokuyomi-Community/sources"
MAX_MANIFEST = 512 * 1024
MAX_BUNDLE = 32 * 1024 * 1024
MAX_PACKAGE = 1 * 1024 * 1024
SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PROHIBITED_KEYS = {"dev-1", "fixture-aes-1", "fixture-rule-sign-1", "catalog-test-1"}
COLLECTION_REQUIRED = {"kind", "schemaVersion", "name", "catalogSequence", "releaseId", "count", "rules", "bundle"}
COLLECTION_OPTIONAL = {"minimumRuleEngineVersion"}
ENTRY_REQUIRED = {"id", "name", "url", "packageBytes", "packageSha256", "contentRating"}
ENTRY_OPTIONAL = {"minimumRuleEngineVersion"}


class MirrorError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MirrorError(message)


def exact_fields(value: object, required: set[str], optional: set[str] = frozenset()) -> None:
    require(isinstance(value, dict), "expected a JSON object")
    require(required <= value.keys() <= required | optional, "unexpected or missing JSON fields")


def integer(value: object, low: int, high: int, label: str) -> None:
    require(type(value) is int and low <= value <= high, f"invalid {label}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json(data: bytes, maximum: int) -> dict:
    require(0 < len(data) <= maximum, "JSON exceeds byte limit or is empty")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MirrorError("invalid UTF-8 JSON") from error
    require(isinstance(value, dict), "expected a JSON object")
    return value


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def https_url(url: object) -> None:
    require(isinstance(url, str) and not any(c.isspace() for c in url), "invalid URL")
    parts = urlsplit(url)
    require(parts.scheme == "https" and parts.hostname and not parts.username and not parts.password
            and not parts.query and not parts.fragment and parts.port in (None, 443), "URL must be credential-free HTTPS")


def validate_collection(collection: dict, channel: str, upstream: bool = True) -> None:
    require(channel in {"all", "general"}, "unknown collection channel")
    exact_fields(collection, COLLECTION_REQUIRED, COLLECTION_OPTIONAL)
    require(collection["kind"] == "kiokuyomiRuleCollection" and type(collection["schemaVersion"]) is int and collection["schemaVersion"] == 1,
            "unsupported collection schema")
    require(isinstance(collection["name"], str) and 0 < len(collection["name"]) <= 256, "invalid collection name")
    release = collection["releaseId"]
    require(isinstance(release, str) and SEGMENT.fullmatch(release), "invalid release ID")
    integer(collection["catalogSequence"], 0, 2**53 - 1, "catalog sequence")
    integer(collection["count"], 1, 512, "rule count")
    if "minimumRuleEngineVersion" in collection:
        integer(collection["minimumRuleEngineVersion"], 1, 2**31 - 1, "engine version")
    rules = collection["rules"]
    require(isinstance(rules, list) and len(rules) == collection["count"], "collection count mismatch")
    seen = set()
    for rule in rules:
        exact_fields(rule, ENTRY_REQUIRED, ENTRY_OPTIONAL)
        rule_id = rule["id"]
        require(isinstance(rule_id, str) and SEGMENT.fullmatch(rule_id) and rule_id not in seen, "invalid or duplicate rule ID")
        seen.add(rule_id)
        require(isinstance(rule["name"], str) and 0 < len(rule["name"]) <= 256, "invalid rule name")
        require(rule["contentRating"] in {"safe", "teen", "mature", "adult"}, "invalid content rating")
        if channel == "general":
            require(rule["contentRating"] != "adult", "general collection contains adult content")
        integer(rule["packageBytes"], 1, MAX_PACKAGE, "package size")
        require(isinstance(rule["packageSha256"], str) and SHA256.fullmatch(rule["packageSha256"]), "invalid package hash")
        if "minimumRuleEngineVersion" in rule:
            integer(rule["minimumRuleEngineVersion"], 1, 2**31 - 1, "rule engine version")
        https_url(rule["url"])
        expected = (f"{UPSTREAM}/v1/rule-packages/{release}/{rule_id}.kyyrule" if upstream else
                    f"https://github.com/{REPOSITORY}/releases/download/{release}/{rule_id}.kyyrule")
        require(rule["url"] == expected, "package URL outside approved immutable release")
    bundle = collection["bundle"]
    exact_fields(bundle, {"url", "bytes", "sha256"})
    integer(bundle["bytes"], 1, MAX_BUNDLE, "bundle size")
    require(isinstance(bundle["sha256"], str) and SHA256.fullmatch(bundle["sha256"]), "invalid bundle hash")
    https_url(bundle["url"])
    expected = (f"{UPSTREAM}/v1/rule-bundles/{release}/{channel}.kyybundle" if upstream else
                f"https://github.com/{REPOSITORY}/releases/download/{release}/{channel}.kyybundle")
    require(bundle["url"] == expected, "bundle URL outside approved immutable release")


def check_pair(all_collection: dict, general: dict) -> None:
    validate_collection(all_collection, "all")
    validate_collection(general, "general")
    require((all_collection["releaseId"], all_collection["catalogSequence"]) ==
            (general["releaseId"], general["catalogSequence"]), "upstream changed between collection requests")
    expected = [rule for rule in all_collection["rules"] if rule["contentRating"] != "adult"]
    require(general["rules"] == expected, "general collection is not the exact non-adult subset")


def check_hash(data: bytes, size: int, sha256: str) -> None:
    require(len(data) == size and digest(data) == sha256, "byte count or SHA-256 mismatch")


def decode_base64url(value: object) -> bytes:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value), "invalid base64url")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise MirrorError("invalid base64url") from error


def check_encrypted_package(data: bytes) -> None:
    envelope = parse_json(data, MAX_PACKAGE)
    exact_fields(envelope, {"encrypted", "signature"})
    require(isinstance(envelope["encrypted"], str) and isinstance(envelope["signature"], str), "invalid encrypted envelope")
    encrypted = envelope["encrypted"].split(":")
    signature = envelope["signature"].split(":")
    require(len(encrypted) == 3 and encrypted[0] == "kyy1" and KEY_ID.fullmatch(encrypted[1])
            and encrypted[1] not in PROHIBITED_KEYS, "package must contain production ciphertext")
    require(len(decode_base64url(encrypted[2])) >= 28, "ciphertext is too short")
    require(len(signature) == 3 and signature[0] == "ed25519" and KEY_ID.fullmatch(signature[1])
            and signature[1] not in PROHIBITED_KEYS and len(decode_base64url(signature[2])) == 64,
            "package must contain an Ed25519 signature envelope")
    # Structural validation is deliberately not described as signature verification.
    # Existing App code verifies signatures and decrypts with its installed keyring.


def unpack_bundle(data: bytes, collection: dict) -> dict[str, bytes]:
    metadata = collection["bundle"]
    check_hash(data, metadata["bytes"], metadata["sha256"])
    bundle = parse_json(data, MAX_BUNDLE)
    exact_fields(bundle, {"kind", "schemaVersion", "releaseId", "catalogSequence", "count", "packages"})
    require(bundle["kind"] == "kiokuyomiRuleBundle" and type(bundle["schemaVersion"]) is int and bundle["schemaVersion"] == 1, "unsupported bundle schema")
    require((bundle["releaseId"], bundle["catalogSequence"], bundle["count"]) ==
            (collection["releaseId"], collection["catalogSequence"], collection["count"]), "bundle revision mismatch")
    require(isinstance(bundle["packages"], list) and len(bundle["packages"]) == bundle["count"], "bundle count mismatch")
    entries = {entry["id"]: entry for entry in collection["rules"]}
    result = {}
    for package in bundle["packages"]:
        exact_fields(package, {"id", "payload"})
        rule_id = package["id"]
        require(isinstance(rule_id, str) and rule_id in entries and rule_id not in result, "unexpected or duplicate bundle package")
        require(isinstance(package["payload"], str), "package payload must be ciphertext text")
        raw = package["payload"].encode("utf-8")
        entry = entries[rule_id]
        check_hash(raw, entry["packageBytes"], entry["packageSha256"])
        check_encrypted_package(raw)
        result[rule_id] = raw
    require(result.keys() == entries.keys(), "missing bundle package")
    return result


def fetch(url: str, maximum: int) -> bytes:
    https_url(url)
    with tempfile.TemporaryDirectory(prefix="kyy-ciphertext-") as temporary:
        path = Path(temporary) / "download"
        command = ["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
                   "--proto-redir", "=https", "--tlsv1.2", "--max-redirs", "5", "--retry", "3",
                   "--connect-timeout", "15", "--max-time", "120", "--max-filesize", str(maximum),
                   url, "--output", str(path)]
        run(command)
        require(0 < path.stat().st_size <= maximum, "download exceeds byte limit")
        return path.read_bytes()


def run(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, timeout=600)
    if result.returncode:
        # Commands never contain credentials; GH_TOKEN is read by gh itself.
        raise MirrorError(f"{command[0]} failed: {result.stderr.strip()}")
    return result.stdout


def find_release(tag: str) -> dict | None:
    result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases/tags/{tag}"],
                            text=True, capture_output=True, timeout=60)
    if result.returncode:
        if "HTTP 404" not in result.stderr:
            raise MirrorError("unable to read release: " + result.stderr.strip())
        # A draft does not create its Git tag until publication, so GitHub's
        # /releases/tags endpoint returns 404 even to its owner. Look through
        # the authenticated releases list before creating another draft.
        pages = json.loads(run(["gh", "api", f"repos/{REPOSITORY}/releases?per_page=100",
                               "--paginate", "--slurp"]))
        matches = [release for page in pages for release in page if release["tag_name"] == tag]
        require(len(matches) <= 1, "multiple releases have the same tag")
        return matches[0] if matches else None
    return json.loads(result.stdout)


def prepare(output: Path, fetcher: Callable[[str, int], bytes] = fetch) -> dict:
    require(not output.exists() or not any(output.iterdir()), "output directory must be empty")
    collections = {}
    original = {}
    for channel in ("all", "general"):
        data = fetcher(f"{UPSTREAM}/{channel}.json", MAX_MANIFEST)
        original[channel] = digest(data)
        collections[channel] = parse_json(data, MAX_MANIFEST)
    check_pair(collections["all"], collections["general"])
    bundle_bytes, packages = {}, {}
    for channel, collection in collections.items():
        data = fetcher(collection["bundle"]["url"], collection["bundle"]["bytes"])
        bundle_bytes[channel] = data
        packages[channel] = unpack_bundle(data, collection)
    require(all(packages["all"][key] == value for key, value in packages["general"].items()),
            "general and all ciphertext differ")
    # Re-read mutable channels to fail safely during an upstream release transition.
    for channel in ("all", "general"):
        require(digest(fetcher(f"{UPSTREAM}/{channel}.json", MAX_MANIFEST)) == original[channel],
                "upstream changed while preparing release; retry next run")
    release = collections["all"]["releaseId"]
    output.mkdir(parents=True, exist_ok=True)
    for channel, collection in collections.items():
        mirrored = copy.deepcopy(collection)
        mirrored["bundle"]["url"] = f"https://github.com/{REPOSITORY}/releases/download/{release}/{channel}.kyybundle"
        for rule in mirrored["rules"]:
            rule["url"] = f"https://github.com/{REPOSITORY}/releases/download/{release}/{rule['id']}.kyyrule"
        validate_collection(mirrored, channel, upstream=False)
        write_json(output / f"{channel}.json", mirrored)
        (output / f"{channel}.kyybundle").write_bytes(bundle_bytes[channel])
    # New repository alias only. The older discovery-format sources.json is untouched.
    (output / "sources.json").write_bytes((output / "all.json").read_bytes())
    for rule_id, data in packages["all"].items():
        (output / f"{rule_id}.kyyrule").write_bytes(data)
    report = {
        "schemaVersion": 1, "releaseId": release,
        "catalogSequence": collections["all"]["catalogSequence"],
        "count": collections["all"]["count"], "generalCount": collections["general"]["count"],
        "upstream": UPSTREAM, "upstreamManifestSha256": original,
        "assets": {path.name: {"bytes": path.stat().st_size, "sha256": digest(path.read_bytes())}
                   for path in sorted(output.iterdir()) if path.is_file()},
    }
    write_json(output / "checksums.json", report)
    # Pointer committed only after publication; not a release asset.
    write_json(output / "publication.json", {key: value for key, value in report.items() if key != "assets"})
    return report


def expected_assets(output: Path) -> dict[str, dict]:
    report = parse_json((output / "checksums.json").read_bytes(), MAX_MANIFEST)
    assets = copy.deepcopy(report["assets"])
    raw = (output / "checksums.json").read_bytes()
    assets["checksums.json"] = {"bytes": len(raw), "sha256": digest(raw)}
    return assets


def list_assets(release_id: int) -> list[dict]:
    # gh concatenates paginated JSON arrays; --slurp gives one valid outer array.
    pages = json.loads(run(["gh", "api", f"repos/{REPOSITORY}/releases/{release_id}/assets?per_page=100",
                           "--paginate", "--slurp"]))
    return [asset for page in pages for asset in page]


def check_remote_assets(release: dict, expected: dict[str, dict]) -> None:
    assets = list_assets(release["id"])
    require(len(assets) == len(expected) and {asset["name"] for asset in assets} == expected.keys(),
            "release has missing, duplicate, or unexpected assets")
    for asset in assets:
        metadata = expected[asset["name"]]
        require(asset["state"] == "uploaded" and asset["size"] == metadata["bytes"], "incomplete uploaded asset")
        # GitHub stores SHA-256 on uploaded release assets. Refuse publication if
        # the backend cannot prove every encrypted package arrived unchanged.
        require(asset.get("digest") == "sha256:" + metadata["sha256"], "uploaded asset digest mismatch or unavailable")


def publish(output: Path, report: dict, pointer: Path) -> None:
    if pointer.exists():
        previous = parse_json(pointer.read_bytes(), MAX_MANIFEST)
        require(report["catalogSequence"] >= previous["catalogSequence"], "refusing catalog rollback")
        if report["catalogSequence"] == previous["catalogSequence"]:
            require(report["releaseId"] == previous["releaseId"] and
                    report["upstreamManifestSha256"] == previous["upstreamManifestSha256"],
                    "same sequence cannot identify different catalog contents")
    tag = report["releaseId"]
    expected = expected_assets(output)
    existing = find_release(tag)
    if existing and not existing["draft"]:
        require(not existing["prerelease"], "unexpected prerelease")
        check_remote_assets(existing, expected)
        print(f"Already published and verified: {tag}")
        return
    if not existing:
        notes = (f"Mirror of existing published release `{tag}`.\n\n"
                 f"- Full collection: {report['count']} rules\n"
                 f"- General collection (no adult sources): {report['generalCount']} rules\n"
                 "- Ciphertext, signatures, sizes, and SHA-256 are unchanged.\n"
                 "- Existing subscription URLs remain supported; switching is optional.\n"
                 "- Import is opt-in; inspect the App's import preview before accepting.\n")
        run(["gh", "release", "create", tag, "--repo", REPOSITORY, "--draft", "--target", "main",
             "--title", f"Rules {report['catalogSequence']} ({tag})", "--notes", notes])
        existing = find_release(tag)
    require(existing and existing["draft"], "release must be a draft before upload")
    # --clobber is used ONLY on unpublished drafts for safe retry after a failure.
    for offset in range(0, len(expected), 40):
        names = list(expected)[offset:offset + 40]
        run(["gh", "release", "upload", tag, "--repo", REPOSITORY, "--clobber",
             *[str(output / name) for name in names]])
    check_remote_assets(existing, expected)
    # Promoting a newer draft switches /latest only after all assets are verified.
    latest_result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases/latest"],
                                   capture_output=True, text=True, timeout=60)
    if latest_result.returncode == 0:
        latest = json.loads(latest_result.stdout)
        if latest["tag_name"] != tag:
            with tempfile.TemporaryDirectory(prefix="kyy-latest-") as temp:
                run(["gh", "release", "download", latest["tag_name"], "--repo", REPOSITORY,
                     "--pattern", "checksums.json", "--dir", temp])
                latest_report = parse_json((Path(temp) / "checksums.json").read_bytes(), MAX_MANIFEST)
                require(report["catalogSequence"] > latest_report["catalogSequence"], "refusing to replace latest with an older release")
    elif "HTTP 404" not in latest_result.stderr:
        raise MirrorError("unable to verify current latest release")
    run(["gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest"])
    published = find_release(tag)
    require(published and not published["draft"], "release was not published")
    check_remote_assets(published, expected)
    print(f"Published and verified {len(expected)} assets: {tag}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--publish", action="store_true", help="publish verified ciphertext to this repository only")
    parser.add_argument("--pointer", type=Path, default=Path("publication.json"))
    options = parser.parse_args()
    report = prepare(options.output)
    print(f"Prepared {report['count']} ciphertext packages; general: {report['generalCount']}; sequence: {report['catalogSequence']}")
    if options.publish:
        publish(options.output, report, options.pointer)


if __name__ == "__main__":
    try:
        main()
    except (MirrorError, OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
