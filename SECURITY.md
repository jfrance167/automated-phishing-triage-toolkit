# Security Policy

## Safe handling

Treat every submitted email and extracted indicator as untrusted. The parser does not render HTML, fetch message URLs, execute attachments, or submit unknown URLs for analysis. Email input is capped at 25 MiB. Markdown reports normalize control/format characters, escape Markdown syntax in untrusted fields, and defang web addresses. JSON retains raw normalized values for automation; open JSON only in tools that do not auto-link or fetch content.

VirusTotal lookups disclose indicators to a third party. Live requests require `--online-enrichment` even if an API key is configured; URL lookups additionally require the per-run `--allow-url-disclosure` confirmation. Domain-only lookup is the default. `--intel-file` uses local fixtures and takes precedence over live-enrichment settings. Do not disclose sensitive, internal, victim-specific, or token-bearing URLs unless organizational policy allows it. Use environment variables for API keys and never commit `.env` files or raw production messages.

## Reporting a vulnerability

Open a private security advisory in the GitHub repository. Include the affected version, reproduction steps, impact, and a suggested mitigation if available. Do not include real malicious payloads or personal data in a public issue.
