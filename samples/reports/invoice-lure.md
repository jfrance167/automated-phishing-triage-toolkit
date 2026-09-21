# Phishing Triage Summary

- **Verdict:** SUSPICIOUS
- **Risk score:** 25/100
- **Source:** `invoice-lure.eml`
- **Generated (UTC):** 2026-09-21T23:47:11+00:00

## Message overview

| Field | Value |
|---|---|
| From | Accounts Payable <invoices@trusted-vendor.example> |
| Reply To | Payment Desk <billing@vendor-payments.example> |
| Return Path | <billing@vendor-payments.example> |
| To | analyst@example.org |
| Subject | Updated invoice requires approval |
| Date | Mon, 21 Sep 2026 10:20:00 -0400 |
| Message Id | <demo-suspicious-002@example.org> |

## Authentication

| Control | Result |
|---|---|
| SPF | PASS |
| DKIM | PASS |
| DMARC | PASS |

## Indicators

| Type | Indicator (defanged) | Status | Malicious | Suspicious |
|---|---|---:|---:|---:|
| domain | `invoice-review[.]example` | found | 0 | 0 |
| domain | `trusted-vendor[.]example` | found | 0 | 0 |
| domain | `vendor-payments[.]example` | found | 0 | 1 |
| url | `hxxps://invoice-review[.]example/document/48321` | found | 0 | 1 |

## Findings

- **MEDIUM (+15):** Reply-To domain differs from the From domain.
- **MEDIUM (+10):** Return-Path domain differs from the From domain.

## Recommended actions

- Hold or quarantine the message pending analyst review.
- Validate sender identity through a trusted out-of-band channel.
- Review URL reputation and authentication evidence before release.

> Analyst note: Reputation and heuristic results are decision support, not a substitute for contextual review.
