import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

import phishing_triage as triage


ROOT = Path(__file__).resolve().parents[1]


class ParsingTests(unittest.TestCase):
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

    def test_markdown_defangs_indicators(self):
        rendered = triage.markdown_report(self.load("credential-harvest"))
        self.assertIn("hxxp://198[.]51[.]100[.]42", rendered)
        self.assertNotIn("http://198.51.100.42", rendered)


if __name__ == "__main__":
    unittest.main()
