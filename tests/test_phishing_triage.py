import unittest
import os
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from tempfile import NamedTemporaryFile
from unittest.mock import patch
from email import policy
from email.parser import BytesParser
from pathlib import Path

import phishing_triage as triage


ROOT = Path(__file__).resolve().parents[1]


class ParsingTests(unittest.TestCase):
    def test_email_input_limit_is_enforced(self):
        with NamedTemporaryFile(dir=ROOT / "tests", suffix=".eml", delete=False) as scratch:
            scratch.write(b"x" * 33)
            path = Path(scratch.name)
        self.addCleanup(path.unlink, missing_ok=True)
        original_open = Path.open
        requested_sizes = []

        class TrackingReader:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args):
                return self.wrapped.__exit__(*args)

            def read(self, size=-1):
                requested_sizes.append(size)
                return self.wrapped.read(size)

        def tracking_open(file_path, *args, **kwargs):
            return TrackingReader(original_open(file_path, *args, **kwargs))

        with patch.object(triage, "MAX_EMAIL_BYTES", 32), \
             patch.object(Path, "open", tracking_open):
            with self.assertRaisesRegex(ValueError, "input limit"):
                triage.parse_email(path)
        self.assertEqual(requested_sizes, [33])

    def test_received_spf_status_is_parsed_without_spf_equals_token(self):
        for status in ("fail", "pass"):
            with self.subTest(status=status):
                raw = (
                    "Received-SPF: " + status + " (sender SPF authorized) "
                    "identity=mailfrom; client-ip=192.0.2.1\n\n"
                ).encode()
                message = BytesParser(policy=policy.default).parsebytes(raw)
                self.assertEqual(triage.parse_authentication(message)["spf"], status)

    def test_conflicting_received_spf_failure_is_not_hidden_by_pass_claim(self):
        raw = (
            "Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.org\n"
            "Received-SPF: fail (sender SPF unauthorized) identity=mailfrom; "
            "client-ip=192.0.2.1\n\n"
        ).encode()
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(triage.parse_authentication(message)["spf"], "fail")

    def test_pass_cannot_erase_failures_in_either_header_order(self):
        fail = "mx.example; spf=fail; dkim=fail; dmarc=fail"
        passed = "forged.example; spf=pass; dkim=pass; dmarc=pass"
        for values in ((fail, passed), (passed, fail)):
            with self.subTest(values=values):
                raw = "".join(f"Authentication-Results: {value}\n" for value in values).encode() + b"\n"
                message = BytesParser(policy=policy.default).parsebytes(raw)
                self.assertEqual(triage.parse_authentication(message),
                                 {"spf": "fail", "dkim": "fail", "dmarc": "fail"})

    def test_repeated_clauses_and_received_spf_are_conservative(self):
        raw = (b"Authentication-Results: mx.example; DKIM=pass; dkim=fail; dkim=pass;\n"
               b" DMARC=fail; dmarc=pass\nReceived-SPF: pass\nReceived-SPF: fail\n\n")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(triage.parse_authentication(message),
                         {"spf": "fail", "dkim": "fail", "dmarc": "fail"})

    def test_versioned_methods_cannot_be_hidden_by_unversioned_pass(self):
        raw = (b"Authentication-Results: mx.example; spf/1=fail; dkim/1=fail; dmarc/1=fail\n"
               b"Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass\n\n")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(triage.parse_authentication(message),
                         {"spf": "fail", "dkim": "fail", "dmarc": "fail"})

    def test_comments_and_quoted_properties_do_not_inject_claims(self):
        raw = (b'Authentication-Results: mx.example (nested (dkim=fail; dmarc=fail));\n'
               b' dkim=pass reason="text; dkim=fail; dmarc=fail";\n'
               b' dmarc=pass (text; dmarc=fail)\n\n')
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(triage.parse_authentication(message),
                         {"spf": "unknown", "dkim": "pass", "dmarc": "pass"})

    def test_missing_or_unknown_claims_stay_unknown(self):
        for raw in (b"\n", b"Authentication-Results: mx.example; dkim=unrecognized\n\n",
                    b"Authentication-Results: dkim=fail\n\n"):
            with self.subTest(raw=raw):
                message = BytesParser(policy=policy.default).parsebytes(raw)
                self.assertEqual(triage.parse_authentication(message),
                                 {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"})

    def test_extracts_headers_authentication_and_urls(self):
        report = triage.parse_email(ROOT / "samples/emails/credential-harvest.eml")
        self.assertEqual(report.authentication, {"spf": "fail", "dkim": "fail", "dmarc": "fail"})
        self.assertEqual(report.message["reply_to"], "Help Desk <reset@account-security.example>")
        self.assertIn("http://198.51.100.42/login?tenant=example", report.urls)
        self.assertIn("account-security.example", report.domains)

    def test_html_and_plain_duplicates_are_deduplicated(self):
        raw = b"""From: A <a@example.org>\nContent-Type: multipart/alternative; boundary=x\n\n--x\nContent-Type: text/plain\n\nhttps://example.org/a\n--x\nContent-Type: text/html\n\n<a href=\"https://example.org/a\">A</a>\n--x--\n"""
        message = BytesParser(policy=policy.default).parsebytes(raw)
        plain, html_parts = triage.extract_body_parts(message)
        self.assertEqual(triage.extract_urls(plain, html_parts), ["https://example.org/a"])

    def test_attachments_are_not_scanned_as_message_body(self):
        raw = b"""From: A <a@example.org>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nHello\n--x\nContent-Type: text/plain\nContent-Disposition: attachment; filename=note.txt\n\nhttps://evil.example/a\n--x--\n"""
        message = BytesParser(policy=policy.default).parsebytes(raw)
        plain, html_parts = triage.extract_body_parts(message)
        self.assertEqual(triage.extract_urls(plain, html_parts), [])


class AnalysisTests(unittest.TestCase):
    def test_forged_pass_header_cannot_lower_authentication_failure_score(self):
        report = triage.parse_email(ROOT / "samples/emails/benign-newsletter.eml")
        raw = (b"Authentication-Results: receiver.example; spf=fail; dkim=fail; dmarc=fail\n"
               b"Authentication-Results: forged.example; dkim=pass; dmarc=pass\n\n")
        report.authentication = triage.parse_authentication(BytesParser(policy=policy.default).parsebytes(raw))
        triage.analyze(report)
        self.assertEqual(report.score, 35)
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.to_dict()["authentication_provenance"], "unverified_header_claims")
        self.assertIn("header claims (unverified)", triage.markdown_report(report))

    def load(self, name):
        report = triage.parse_email(ROOT / f"samples/emails/{name}.eml")
        triage.enrich(report, triage.FixtureClient(ROOT / "samples/demo-intel.json"), "both")
        triage.analyze(report)
        return report

    def test_malicious_sample(self):
        report = self.load("credential-harvest")
        self.assertEqual(report.verdict, "malicious")
        self.assertEqual(report.score, 100)

    def test_suspicious_sample(self):
        report = self.load("invoice-lure")
        self.assertEqual(report.verdict, "suspicious")
        self.assertGreaterEqual(report.score, 25)

    def test_benign_sample(self):
        report = self.load("benign-newsletter")
        self.assertEqual(report.verdict, "likely_benign")
        self.assertEqual(report.score, 0)

    def test_cli_json_and_markdown_label_unverified_authentication(self):
        sample = str(ROOT / "samples/emails/benign-newsletter.eml")
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(triage.main([sample, "--format", "json"]), 0)
        self.assertEqual(json.loads(out.getvalue())["authentication_provenance"], "unverified_header_claims")
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(triage.main([sample]), 0)
        self.assertIn("Confirm with trusted receiver evidence", out.getvalue())

    def test_markdown_defangs_indicators(self):
        rendered = triage.markdown_report(self.load("credential-harvest"))
        self.assertIn(r"hxxp://198\[\.\]51\[\.\]100\[\.\]42", rendered)
        self.assertNotIn("http://198.51.100.42", rendered)

    def test_untrusted_headers_and_source_are_inert_markdown(self):
        report = self.load("credential-harvest")
        hostile_subject = "**bold** _em_ \\\\ [click](https://evil.example) | `code` <tag>\x01\u0085\n## forged\u202e"
        report.message["subject"] = hostile_subject
        report.source_file = "[click](https://evil.example)\nnew.md"
        report.authentication["spf"] = "**pass**\u202e"
        report.findings.append(triage.Finding("high", 1, "**forged finding**\u202e"))
        rendered = triage.markdown_report(report)
        self.assertNotIn("[click](https://evil.example)", rendered)
        self.assertNotIn("\n## forged", rendered)
        self.assertNotIn("<tag>", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("\u0085", rendered)
        self.assertNotIn("\x01", rendered)
        self.assertIn(r"\*\*bold\*\*", rendered)
        self.assertIn(r"\_em\_", rendered)
        self.assertIn(r"\*\*PASS\*\*", rendered)
        self.assertIn(r"\*\*forged finding\*\*", rendered)
        self.assertIn(r"\[click\]\(hxxps://evil\[\.\]example\)", rendered)
        encoded = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(encoded["message"]["subject"], hostile_subject)

    def test_untrusted_fixture_indicator_markup_is_inert(self):
        report = self.load("credential-harvest")
        report.intelligence[0].indicator = "[click](https://evil.example)\n| forged"
        rendered = triage.markdown_report(report)
        self.assertNotIn("[click](https://evil.example)", rendered)
        self.assertNotIn("\n| forged", rendered)

    def test_api_key_does_not_enable_external_requests_by_default(self):
        with patch.dict(os.environ, {"VT_API_KEY": "placeholder"}), \
             patch.object(triage, "VirusTotalClient") as client, \
             redirect_stdout(StringIO()):
            self.assertEqual(triage.main([str(ROOT / "samples/emails/credential-harvest.eml")]), 0)
        client.assert_not_called()

    def test_local_fixture_takes_precedence_even_with_online_url_lookup_requested(self):
        with patch.dict(os.environ, {"VT_API_KEY": "placeholder"}), \
             patch.object(triage, "VirusTotalClient") as client, \
             redirect_stdout(StringIO()):
            self.assertEqual(triage.main([
                str(ROOT / "samples/emails/credential-harvest.eml"),
                "--intel-file", str(ROOT / "samples/demo-intel.json"),
                "--online-enrichment", "--lookup", "urls",
            ]), 0)
        client.assert_not_called()

    def test_explicit_online_enrichment_uses_domain_only_default(self):
        with patch.dict(os.environ, {"VT_API_KEY": "placeholder"}), \
             patch.object(triage, "VirusTotalClient") as client, \
             patch.object(triage, "enrich") as enrich, \
             redirect_stdout(StringIO()):
            self.assertEqual(triage.main([str(ROOT / "samples/emails/credential-harvest.eml"),
                                          "--online-enrichment"]), 0)
        client.assert_called_once_with("placeholder", delay=0.0, allow_url_disclosure=False)
        self.assertEqual(enrich.call_args.args[2], "domains")

    def test_online_url_lookup_requires_per_run_disclosure_approval(self):
        with patch.object(triage, "VirusTotalClient") as client, \
             patch.object(triage, "enrich") as enrich, \
             redirect_stderr(StringIO()):
            self.assertEqual(triage.main([
                str(ROOT / "samples/emails/credential-harvest.eml"),
                "--online-enrichment", "--api-key", "placeholder", "--lookup", "urls",
            ]), 1)
        client.assert_not_called()
        enrich.assert_not_called()

    def test_online_enrichment_requires_an_api_key(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(triage, "VirusTotalClient") as client, \
             patch.object(triage, "enrich") as enrich, \
             redirect_stderr(StringIO()):
            self.assertEqual(triage.main([
                str(ROOT / "samples/emails/credential-harvest.eml"), "--online-enrichment",
            ]), 1)
        client.assert_not_called()
        enrich.assert_not_called()

    def test_client_refuses_url_lookup_without_disclosure_approval(self):
        client = triage.VirusTotalClient("placeholder")
        with self.assertRaisesRegex(ValueError, "not approved"):
            client.lookup_url("https://example.org/private?token=placeholder")


if __name__ == "__main__":
    unittest.main()
