import base64
import copy
import importlib.util
import json
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("mirror", Path(__file__).parents[1] / "scripts/mirror_release.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def encoded(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def raw_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def package(seed):
    return raw_json({"encrypted": "kyy1:prod-aes-1:" + encoded(bytes([seed]) * 40),
                     "signature": "ed25519:prod-sign-1:" + encoded(bytes([seed]) * 64)})


def fixtures(sequence=39):
    release = f"rules-test-{sequence}"
    raw_packages = {"sample": package(1), "restricted": package(2)}
    rules = [{"id": key, "name": key, "url": f"{m.UPSTREAM}/v1/rule-packages/{release}/{key}.kyyrule",
              "packageBytes": len(data), "packageSha256": m.digest(data),
              "contentRating": "adult" if key == "restricted" else "safe", "minimumRuleEngineVersion": 1}
             for key, data in raw_packages.items()]
    result = {}
    for channel in ("all", "general"):
        entries = copy.deepcopy(rules if channel == "all" else rules[:1])
        bundle = {"kind": "kiokuyomiRuleBundle", "schemaVersion": 1, "releaseId": release,
                  "catalogSequence": sequence, "count": len(entries),
                  "packages": [{"id": entry["id"], "payload": raw_packages[entry["id"]].decode()} for entry in entries]}
        data = raw_json(bundle)
        collection = {"kind": "kiokuyomiRuleCollection", "schemaVersion": 1, "name": channel,
                      "releaseId": release, "catalogSequence": sequence, "minimumRuleEngineVersion": 1,
                      "count": len(entries), "rules": entries,
                      "bundle": {"url": f"{m.UPSTREAM}/v1/rule-bundles/{release}/{channel}.kyybundle",
                                 "bytes": len(data), "sha256": m.digest(data)}}
        result[f"{m.UPSTREAM}/{channel}.json"] = raw_json(collection)
        result[collection["bundle"]["url"]] = data
    return result, raw_packages


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.files, self.packages = fixtures()
        self.all = json.loads(self.files[m.UPSTREAM + "/all.json"])
        self.general = json.loads(self.files[m.UPSTREAM + "/general.json"])

    def test_valid_pair(self):
        m.check_pair(self.all, self.general)

    def test_collection_rejects_sensitive_or_unknown_fields(self):
        for target in (self.all, self.all["rules"][0], self.all["bundle"]):
            for key in ("token", "privateKey", "encryptionKeys", "javascript", "unexpected"):
                bad = copy.deepcopy(self.all)
                selected = bad if target is self.all else bad["bundle"] if target is self.all["bundle"] else bad["rules"][0]
                selected[key] = "must-not-leak"
                with self.subTest(field=key), self.assertRaises(m.MirrorError):
                    m.validate_collection(bad, "all")

    def test_rejects_duplicate_or_traversal_id(self):
        for rule_id in ("sample", "../escape", "/absolute", ".", "bad id"):
            bad = copy.deepcopy(self.all)
            bad["rules"][1]["id"] = rule_id
            with self.subTest(id=rule_id), self.assertRaises(m.MirrorError):
                m.validate_collection(bad, "all")

    def test_rejects_bad_url(self):
        for url in ("http://sources.kiokuyomi.com/a", "https://evil.invalid/sample.kyyrule",
                    self.all["rules"][0]["url"] + "?token=value",
                    self.all["rules"][0]["url"] + "#fragment",
                    "https://user:password@sources.kiokuyomi.com/a",
                    "https://sources.kiokuyomi.com/v1/rule-packages/other/sample.kyyrule"):
            bad = copy.deepcopy(self.all)
            bad["rules"][0]["url"] = url
            with self.subTest(url=url), self.assertRaises(m.MirrorError):
                m.validate_collection(bad, "all")

    def test_rejects_bad_sizes_counts_schema(self):
        for key, value in (("count", 0), ("count", 513), ("count", True), ("count", 1),
                           ("catalogSequence", -1), ("catalogSequence", True),
                           ("schemaVersion", 2), ("schemaVersion", True), ("schemaVersion", 1.0),
                           ("releaseId", "../x"), ("minimumRuleEngineVersion", 0)):
            bad = copy.deepcopy(self.all)
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(m.MirrorError):
                m.validate_collection(bad, "all")
        for key, value in (("packageBytes", 0), ("packageBytes", m.MAX_PACKAGE + 1), ("packageSha256", "invalid")):
            bad = copy.deepcopy(self.all)
            bad["rules"][0][key] = value
            with self.assertRaises(m.MirrorError):
                m.validate_collection(bad, "all")

    def test_rejects_changed_upstream_version(self):
        for key, value in (("releaseId", "another"), ("catalogSequence", 40)):
            bad = copy.deepcopy(self.general)
            bad[key] = value
            with self.assertRaises(m.MirrorError):
                m.check_pair(self.all, bad)

    def test_general_exact_subset_required(self):
        bad = copy.deepcopy(self.general)
        bad["rules"][0]["name"] = "changed"
        with self.assertRaises(m.MirrorError):
            m.check_pair(self.all, bad)
        bad["rules"][0]["contentRating"] = "adult"
        with self.assertRaises(m.MirrorError):
            m.validate_collection(bad, "general")

    def test_parser_rejects_duplicate_fields_and_invalid_utf8(self):
        for raw in (b'{"key":1,"key":2}', b'[]', b'\xff', b'', b'null'):
            with self.assertRaises(m.MirrorError):
                m.parse_json(raw, 512)
        with self.assertRaises(m.MirrorError):
            m.parse_json(b'{"key":1}', 2)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.files, self.packages = fixtures()
        self.collection = json.loads(self.files[m.UPSTREAM + "/all.json"])
        self.raw = self.files[self.collection["bundle"]["url"]]

    def test_ciphertext_export_is_exact_bytes(self):
        self.assertEqual(m.unpack_bundle(self.raw, self.collection), self.packages)

    def test_rejects_hash_or_size_mismatch(self):
        for raw in (self.raw + b" ", self.raw[:-1], self.raw.replace(b"sample", b"tamper", 1)):
            with self.assertRaises(m.MirrorError):
                m.unpack_bundle(raw, self.collection)

    def test_rejects_bundle_tampering_even_with_new_outer_hash(self):
        original = json.loads(self.raw)
        for field, value in (("releaseId", "another"), ("catalogSequence", 40), ("count", 1),
                             ("schemaVersion", 2), ("privateKey", "must-not-leak")):
            bad = copy.deepcopy(original)
            bad[field] = value
            raw = raw_json(bad)
            collection = copy.deepcopy(self.collection)
            collection["bundle"].update(bytes=len(raw), sha256=m.digest(raw))
            with self.subTest(field=field), self.assertRaises(m.MirrorError):
                m.unpack_bundle(raw, collection)

    def test_rejects_duplicate_package(self):
        bad = json.loads(self.raw)
        bad["packages"][1] = bad["packages"][0]
        raw = raw_json(bad)
        self.collection["bundle"].update(bytes=len(raw), sha256=m.digest(raw))
        with self.assertRaises(m.MirrorError):
            m.unpack_bundle(raw, self.collection)

    def test_rejects_plaintext_unsigned_dev_and_unknown_envelopes(self):
        valid = json.loads(self.packages["sample"])
        variants = [{"id": "sample", "chapters": {}}, {"encrypted": valid["encrypted"]},
                    {**valid, "privateKey": "must-not-leak"},
                    {**valid, "encrypted": valid["encrypted"].replace("prod-aes-1", "dev-1")},
                    {**valid, "signature": valid["signature"].replace("prod-sign-1", "fixture-rule-sign-1")},
                    {**valid, "signature": "ed25519:prod-sign-1:AAAA"},
                    {**valid, "encrypted": "kyy1:prod-aes-1:AAAA"}]
        for envelope in variants:
            with self.subTest(envelope=list(envelope)), self.assertRaises(m.MirrorError):
                m.check_encrypted_package(raw_json(envelope))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.files, self.packages = fixtures()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "dist"
        self.report = m.prepare(self.output, lambda url, limit: self.files[url])

    def tearDown(self):
        self.temp.cleanup()

    def test_prepare_preserves_ciphertext_and_engine_requirements(self):
        for rule_id, raw in self.packages.items():
            self.assertEqual((self.output / (rule_id + ".kyyrule")).read_bytes(), raw)
        for channel in ("all", "general"):
            source = json.loads(self.files[f"{m.UPSTREAM}/{channel}.json"])
            mirrored = json.loads((self.output / (channel + ".json")).read_bytes())
            m.validate_collection(mirrored, channel, upstream=False)
            self.assertEqual(mirrored["minimumRuleEngineVersion"], source["minimumRuleEngineVersion"])
            self.assertEqual(mirrored["catalogSequence"], 39)
            self.assertNotIn("/latest/", mirrored["bundle"]["url"])
            self.assertEqual((self.output / (channel + ".kyybundle")).read_bytes(), self.files[source["bundle"]["url"]])
        self.assertEqual((self.output / "sources.json").read_bytes(), (self.output / "all.json").read_bytes())

    def test_output_must_be_empty(self):
        with self.assertRaises(m.MirrorError):
            m.prepare(self.output, lambda url, limit: self.files[url])

    def test_racing_upstream_does_not_write_any_output(self):
        counts = {}
        changed, _ = fixtures(40)
        def fetch(url, limit):
            counts[url] = counts.get(url, 0) + 1
            return changed.get(url, self.files[url]) if counts[url] > 1 else self.files[url]
        output = self.root / "race"
        with self.assertRaises(m.MirrorError):
            m.prepare(output, fetch)
        self.assertFalse(output.exists())

    def test_expected_assets_excludes_internal_pointer(self):
        assets = m.expected_assets(self.output)
        self.assertIn("checksums.json", assets)
        self.assertNotIn("publication.json", assets)
        self.assertEqual(len(assets), 8)

    def test_remote_asset_digest_and_completeness_required(self):
        expected = m.expected_assets(self.output)
        valid = [{"name": name, "state": "uploaded", "size": entry["bytes"], "digest": "sha256:" + entry["sha256"]}
                 for name, entry in expected.items()]
        with patch.object(m, "list_assets", return_value=valid):
            m.check_remote_assets({"id": 1}, expected)
        for index, field, value in ((0, "digest", None), (0, "digest", "sha256:" + "0" * 64),
                                    (0, "state", "starter"), (0, "size", 0)):
            bad = copy.deepcopy(valid)
            bad[index][field] = value
            with patch.object(m, "list_assets", return_value=bad), self.assertRaises(m.MirrorError):
                m.check_remote_assets({"id": 1}, expected)
        for bad in (valid[:-1], valid + [valid[0]], valid[:-1] + [valid[0]]):
            with patch.object(m, "list_assets", return_value=bad), self.assertRaises(m.MirrorError):
                m.check_remote_assets({"id": 1}, expected)

    def test_rollback_and_same_sequence_change_rejected_before_remote_write(self):
        pointer = self.root / "pointer.json"
        previous = {"catalogSequence": 40, "releaseId": "newer", "upstreamManifestSha256": {}}
        m.write_json(pointer, previous)
        with patch.object(m, "run") as run, self.assertRaises(m.MirrorError):
            m.publish(self.output, self.report, pointer)
        run.assert_not_called()
        previous["catalogSequence"] = 39
        m.write_json(pointer, previous)
        with self.assertRaises(m.MirrorError):
            m.publish(self.output, self.report, pointer)

    def test_published_release_is_read_only_and_idempotent(self):
        existing = {"id": 1, "draft": False, "prerelease": False}
        with patch.object(m, "find_release", return_value=existing), patch.object(m, "check_remote_assets") as check, \
                patch.object(m, "run") as run:
            m.publish(self.output, self.report, self.root / "absent-pointer")
        check.assert_called_once()
        run.assert_not_called()

    def test_draft_digest_failure_never_promotes(self):
        existing = {"id": 1, "draft": True}
        with patch.object(m, "find_release", return_value=existing), \
                patch.object(m, "check_remote_assets", side_effect=m.MirrorError("digest mismatch")), \
                patch.object(m, "run", return_value="") as run, self.assertRaises(m.MirrorError):
            m.publish(self.output, self.report, self.root / "absent-pointer")
        calls = [call.args[0] for call in run.call_args_list]
        self.assertTrue(all(command[:3] == ["gh", "release", "upload"] for command in calls))

    def test_find_release_falls_back_to_authenticated_draft_list(self):
        tag = "rules-test-39"
        draft = {"id": 1, "draft": True, "tag_name": tag}
        response = subprocess.CompletedProcess([], 1, stdout="", stderr="gh: Not Found (HTTP 404)")
        with patch.object(m.subprocess, "run", return_value=response), \
                patch.object(m, "run", return_value=json.dumps([[draft]])) as run:
            self.assertEqual(m.find_release(tag), draft)
        self.assertIn("--paginate", run.call_args.args[0])

    def test_find_release_returns_none_only_after_checking_drafts(self):
        response = subprocess.CompletedProcess([], 1, stdout="", stderr="gh: Not Found (HTTP 404)")
        with patch.object(m.subprocess, "run", return_value=response), \
                patch.object(m, "run", return_value="[[]]") as run:
            self.assertIsNone(m.find_release("absent"))
        run.assert_called_once()

    def test_find_release_authentication_failure_is_not_treated_as_absence(self):
        response = subprocess.CompletedProcess([], 1, stdout="", stderr="gh: Bad credentials (HTTP 401)")
        with patch.object(m.subprocess, "run", return_value=response), \
                patch.object(m, "run") as run, self.assertRaises(m.MirrorError):
            m.find_release("rules-test-39")
        run.assert_not_called()

    def test_url_policy_rejects_http_credentials_query_fragment(self):
        for url in ("http://github.com/a", "https://u:p@github.com/a", "https://github.com/a?token=x",
                    "https://github.com/a#x", "https://github.com:444/a", "https://github.com/a b"):
            with self.assertRaises(m.MirrorError):
                m.https_url(url)


if __name__ == "__main__":
    unittest.main()
