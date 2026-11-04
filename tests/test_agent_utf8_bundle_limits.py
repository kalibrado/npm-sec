"""Validate agent bundle size using UTF-8 bytes, not Unicode code points."""
import importlib.util
import unittest
from pathlib import Path

AGENT_FILE = Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
spec = importlib.util.spec_from_file_location("nsd_agent_utf8_limits", AGENT_FILE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def job_with_payload(payload):
    files = {
        "http-security.conf": 'log_format detailed_visitor escape=json' +
                              "\ninclude /data/nginx/custom/npm-security/npm-blocklist.conf;\n" + payload,
        "server-security.conf": "include /data/nginx/custom/npm-security/npm-server-guard.conf;\n",
        "npm-blocklist.conf": "# blocklist\n",
        "npm-server-guard.conf": "if ($npm_security_deny) { return 403; }\n",
    }
    return {"id": 1, "files": files, "bundle_sha256": agent.hash_bundle(files)}


class UTF8BundleLimitTests(unittest.TestCase):
    def test_accepts_small_multibyte_content(self):
        self.assertEqual(agent.validate_job(job_with_payload("# é\n")), 1)

    def test_rejects_file_over_one_megabyte_in_utf8_bytes(self):
        job = job_with_payload("# " + "é" * 524_280)
        self.assertLess(len(job["files"]["http-security.conf"]), 1024 * 1024)
        self.assertGreater(len(job["files"]["http-security.conf"].encode("utf-8")), 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "trop grand"):
            agent.validate_job(job)

    def test_rejects_total_over_two_megabytes_in_utf8_bytes(self):
        job = job_with_payload("# " + "é" * 500_000)
        job["files"]["npm-blocklist.conf"] = "# " + "é" * 500_000
        job["files"]["npm-server-guard.conf"] += "# " + "é" * 100_000
        job["bundle_sha256"] = agent.hash_bundle(job["files"])
        self.assertTrue(all(len(value.encode("utf-8")) < 1024 * 1024 for value in job["files"].values()))
        self.assertGreater(sum(len(value.encode("utf-8")) for value in job["files"].values()), 2 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "Bundle trop volumineux"):
            agent.validate_job(job)


if __name__ == "__main__":
    unittest.main()
