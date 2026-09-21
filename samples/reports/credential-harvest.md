# Phishing Triage Summary

- **Verdict:** MALICIOUS
- **Risk score:** 100/100
- **Source:** `credential-harvest.eml`
- **Generated (UTC):** 2026-09-21T23:47:10+00:00

## Message overview

| Field | Value |
|---|---|
| From | Microsoft 365 Support <support@microsoft.example> |
| Reply To | Help Desk <reset@account-security.example> |
| Return Path | <bounce@mailer-example.net> |
| To | analyst@example.org |
| Subject | Urgent: Password expires today |
| Date | Mon, 21 Sep 2026 09:12:00 -0400 |
| Message Id | <demo-malicious-001@example.org> |

## Authentication

| Control | Result |
|---|---|
| SPF | FAIL |
| DKIM | FAIL |
| DMARC | FAIL |

## Indicators

| Type | Indicator (defanged) | Status | Malicious | Suspicious |
|---|---|---:|---:|---:|
| domain | `account-security[.]example` | found | 9 | 2 |
| domain | `mailer-example[.]net` | found | 4 | 1 |
| domain | `microsoft[.]example` | not_found | 0 | 0 |
| url | `hxxp://198[.]51[.]100[.]42/login?tenant=example` | found | 14 | 3 |

## Findings

- **MEDIUM (+15):** Reply-To domain differs from the From domain.
- **MEDIUM (+10):** Return-Path domain differs from the From domain.
- **MEDIUM (+10):** SPF authentication result is fail.
- **MEDIUM (+10):** DKIM authentication result is fail.
- **HIGH (+15):** DMARC authentication result is fail.
- **MEDIUM (+20):** A URL uses a raw IP address instead of a domain.
- **LOW (+3):** A URL uses unencrypted HTTP.
- **CRITICAL (+60):** VirusTotal marks a domain malicious by 9 engines.
- **CRITICAL (+60):** VirusTotal marks a domain malicious by 4 engines.
- **CRITICAL (+60):** VirusTotal marks a url malicious by 14 engines.

## Recommended actions

- Quarantine the message and search for matching indicators across mail and endpoint telemetry.
- Block confirmed malicious indicators after validating business impact.
- Identify recipients who clicked or submitted credentials; reset credentials and revoke sessions as needed.
- Preserve the original message and investigation notes for incident response.

> Analyst note: Reputation and heuristic results are decision support, not a substitute for contextual review.
