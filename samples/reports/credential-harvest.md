# Phishing Triage Summary

- **Verdict:** MALICIOUS
- **Risk score:** 100/100
- **Source:** credential\-harvest\[\.\]eml
- **Generated (UTC):** 2026-10-28T01:46:50+00:00

## Message overview

| Field | Value |
|---|---|
| From | Microsoft 365 Support &lt;support@microsoft\[\.\]example&gt; |
| Reply To | Help Desk &lt;reset@account\-security\[\.\]example&gt; |
| Return Path | &lt;bounce@mailer\-example\[\.\]net&gt; |
| To | analyst@example\[\.\]org |
| Subject | Urgent: Password expires today |
| Date | Mon, 21 Sep 2026 09:12:00 \-0400 |
| Message Id | &lt;demo\-malicious\-001@example\[\.\]org&gt; |

## Authentication header claims (unverified)

Imported headers do not verify SPF, DKIM, or DMARC. Confirm with trusted receiver evidence.

| Control | Claimed result |
|---|---|
| SPF | FAIL |
| DKIM | FAIL |
| DMARC | FAIL |

## Indicators

| Type | Indicator (defanged) | Status | Malicious | Suspicious |
|---|---|---:|---:|---:|
| domain | account\-security\[\.\]example | found | 9 | 2 |
| domain | mailer\-example\[\.\]net | found | 4 | 1 |
| domain | microsoft\[\.\]example | not\_found | 0 | 0 |

## Findings

- **MEDIUM (+15):** Reply\-To domain differs from the From domain\[\.\]
- **MEDIUM (+10):** Return\-Path domain differs from the From domain\[\.\]
- **MEDIUM (+10):** SPF header claims fail \(unverified\)\[\.\]
- **MEDIUM (+10):** DKIM header claims fail \(unverified\)\[\.\]
- **HIGH (+15):** DMARC header claims fail \(unverified\)\[\.\]
- **MEDIUM (+20):** A URL uses a raw IP address instead of a domain\[\.\]
- **LOW (+3):** A URL uses unencrypted HTTP\[\.\]
- **CRITICAL (+60):** VirusTotal marks a domain malicious by 9 engines\[\.\]
- **CRITICAL (+60):** VirusTotal marks a domain malicious by 4 engines\[\.\]

## Recommended actions

- Quarantine the message and search for matching indicators across mail and endpoint telemetry\[\.\]
- Block confirmed malicious indicators after validating business impact\[\.\]
- Identify recipients who clicked or submitted credentials; reset credentials and revoke sessions as needed\[\.\]
- Preserve the original message and investigation notes for incident response\[\.\]

> Analyst note: Reputation and heuristic results are decision support, not a substitute for contextual review.
