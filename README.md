# Automated Phishing Triage Toolkit

A dependency-free Python CLI that turns a raw email (`.eml`) into an analyst-friendly phishing triage summary. It parses identity and authentication headers, extracts links without visiting them, enriches URL/domain indicators with VirusTotal, applies transparent scoring rules, and exports Markdown or JSON.

> This is a portfolio and analyst-assistance tool, not an autonomous email security gateway. An analyst should validate every verdict in context.

## What it demonstrates

- RFC 5322 and MIME parsing with Python's standard library
- Header analysis: `From`, `Reply-To`, `Return-Path`, `Authentication-Results`, and `Received-SPF`
- URL extraction from plain text and HTML links while ignoring attachments
- VirusTotal API v3 enrichment for domain and URL reports
- Explainable risk scoring and response recommendations
- Safe Markdown output with defanged indicators
- Deterministic offline demonstrations and automated tests

## Quick start

Python 3.10+ is required. No third-party packages are needed.

```bash
git clone https://github.com/YOUR-USERNAME/automated-phishing-triage-toolkit.git
cd automated-phishing-triage-toolkit

# Parse and score locally (no network requests)
python phishing_triage.py samples/emails/credential-harvest.eml

# Reproduce the sanitized demo with fixture intelligence
python phishing_triage.py samples/emails/credential-harvest.eml \
  --intel-file samples/demo-intel.json

# Generate JSON for a SIEM/SOAR pipeline
python phishing_triage.py message.eml --format json --output report.json
```

## VirusTotal enrichment

Create a VirusTotal API key, store it in an environment variable, and run the tool. Never commit the key.

PowerShell:

```powershell
$env:VT_API_KEY = "your-api-key"
python phishing_triage.py .\message.eml --lookup both --request-delay 16 --output .\triage.md
```

Bash:

```bash
export VT_API_KEY="your-api-key"
python phishing_triage.py message.eml --lookup both --request-delay 16 --output triage.md
```

The client uses VirusTotal API v3's domain endpoint and the URL endpoint with an unpadded URL-safe Base64 identifier. `--request-delay` is configurable because quota and rate limits vary by account. A 404 becomes `not_found`; other API/network failures are recorded as `error` and do not crash the entire investigation.

The tool only requests existing reports. It does **not** submit unknown URLs for scanning, because submission may disclose sensitive tokens, internal hostnames, or victim-specific data to a third party. Review your organization's data-handling policy before enriching real messages.

## Verdict model

The score is capped at 100. Every point is shown as a finding in the report.

| Signal | Points |
|---|---:|
| Reply-To domain differs from From | 15 |
| Return-Path domain differs from From | 10 |
| SPF or DKIM fail/softfail/permerror | 10 each |
| DMARC fail/softfail/permerror | 15 |
| Raw IP address in a URL | 20 |
| Punycode domain in a URL | 15 |
| User-info (`user@host`) in a URL | 20 |
| Unencrypted HTTP URL | 3 |
| VirusTotal: 1+ malicious or 2+ suspicious engines | 35 |
| VirusTotal: 3+ malicious engines | 60 |

| Score | Verdict | Default response |
|---:|---|---|
| 0–24 | Likely benign | Validate and close/release |
| 25–59 | Suspicious | Hold and investigate |
| 60–100 | Malicious | Quarantine, scope, contain, and preserve |

These thresholds are intentionally readable and conservative, but they are example policy. Tune them to your mail environment and risk appetite. Authentication alignment and message context can be more nuanced than simple domain equality.

## Sample evidence

- [`samples/reports/credential-harvest.md`](samples/reports/credential-harvest.md) — malicious credential-harvest scenario
- [`samples/reports/invoice-lure.md`](samples/reports/invoice-lure.md) — suspicious vendor/payment scenario
- [`samples/reports/benign-newsletter.json`](samples/reports/benign-newsletter.json) — likely-benign JSON output
- [`PLAYBOOK.md`](PLAYBOOK.md) — analyst decision tree and escalation checklist

All samples use reserved or documentation-only namespaces/addresses (`.example`, `example.org`, and `198.51.100.0/24`). The intelligence in `samples/demo-intel.json` is fictional and exists only to make the demo reproducible.

## CLI reference

```text
python phishing_triage.py EMAIL
  [--format markdown|json]
  [--output PATH]
  [--api-key KEY]
  [--intel-file PATH]
  [--lookup domains|urls|both]
  [--request-delay SECONDS]
```

Prefer `VT_API_KEY` over `--api-key`, since command-line arguments may be captured in shell history or process listings. `--intel-file` takes precedence over the API key and is intended for demonstrations and tests.

## Test

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the suite on Python 3.10 and 3.13.

## Limitations and next steps

- It does not open links, detonate attachments, resolve redirect chains, or submit indicators.
- It extracts only `http` and `https` URLs and does not recursively decode QR codes or nested archives.
- Domain comparison is exact rather than organizational-domain/PSL aware, avoiding an extra dependency but producing some legitimate third-party-sender findings.
- A production deployment should add secure evidence storage, organizational allowlists, case-management integration, and monitoring around API quotas.

## References

- [VirusTotal: Get a domain report](https://docs.virustotal.com/reference/domain-info)
- [VirusTotal: Get a URL report](https://docs.virustotal.com/reference/url-info)
- [Python `email` package documentation](https://docs.python.org/3/library/email.html)

## License

MIT — see [`LICENSE`](LICENSE).
