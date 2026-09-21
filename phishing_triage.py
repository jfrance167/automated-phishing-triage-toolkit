#!/usr/bin/env python3
"""Parse an RFC 5322 email and produce a defensible phishing triage summary."""

from __future__ import annotations

import argparse
import base64
import html
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"
VERDICTS = ("likely_benign", "suspicious", "malicious")


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "area"}:
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)


@dataclass
class IntelResult:
    indicator: str
    kind: str
    status: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    last_analysis_date: str | None = None
    error: str | None = None


@dataclass
class Finding:
    severity: str
    points: int
    description: str


@dataclass
class TriageReport:
    source_file: str
    generated_at: str
    message: dict[str, Any]
    authentication: dict[str, str]
    urls: list[str]
    domains: list[str]
    intelligence: list[IntelResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "likely_benign"
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def decode_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeDecodeError):
        return value


def address_domain(value: str) -> str | None:
    addresses = getaddresses([value])
    if not addresses or "@" not in addresses[0][1]:
        return None
    candidate = addresses[0][1].rsplit("@", 1)[1].strip().rstrip(".").lower()
    return normalize_domain(candidate)


def normalize_domain(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or "." not in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9-]+", label)
           or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    return value


def extract_body_parts(message: Any) -> tuple[list[str], list[str]]:
    plain: list[str] = []
    html_parts: list[str] = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain.append(str(content))
    return plain, html_parts


def normalize_url(candidate: str) -> str | None:
    candidate = html.unescape(candidate).strip().rstrip(TRAILING_URL_PUNCTUATION)
    try:
        parsed = urllib.parse.urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        # Accessing .port validates malformed ports before the URL reaches any API.
        _ = parsed.port
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if any(char.isspace() for char in host):
            return None
        userinfo = ""
        if parsed.username is not None:
            userinfo = urllib.parse.quote(parsed.username, safe="")
            if parsed.password is not None:
                userinfo += ":" + urllib.parse.quote(parsed.password, safe="")
            userinfo += "@"
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"{userinfo}{host}{port}"
        path = parsed.path or "/"
        return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    except (UnicodeError, ValueError):
        return None


def extract_urls(plain_parts: Iterable[str], html_parts: Iterable[str]) -> list[str]:
    candidates: list[str] = []
    for text in [*plain_parts, *html_parts]:
        candidates.extend(URL_RE.findall(text))
    for markup in html_parts:
        parser = LinkParser()
        try:
            parser.feed(markup)
        except Exception:
            pass
        candidates.extend(parser.links)
    urls = {url for candidate in candidates if (url := normalize_url(candidate))}
    return sorted(urls)


def parse_authentication(message: Any) -> dict[str, str]:
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    values = message.get_all("Authentication-Results", []) + message.get_all(
        "Received-SPF", []
    )
    joined = " ".join(str(value) for value in values)
    for mechanism, outcome in AUTH_RE.findall(joined):
        results[mechanism.lower()] = outcome.lower()
    return results


def parse_email(path: Path) -> TriageReport:
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    plain, html_parts = extract_body_parts(message)
    urls = extract_urls(plain, html_parts)
    header_values = {
        "from": decode_value(message.get("From")),
        "reply_to": decode_value(message.get("Reply-To")),
        "return_path": decode_value(message.get("Return-Path")),
        "to": decode_value(message.get("To")),
        "subject": decode_value(message.get("Subject")),
        "date": decode_value(message.get("Date")),
        "message_id": decode_value(message.get("Message-ID")),
    }
    domains = {
        domain
        for value in (header_values["from"], header_values["reply_to"], header_values["return_path"])
        if (domain := address_domain(value))
    }
    for url in urls:
        host = urllib.parse.urlsplit(url).hostname
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if domain := normalize_domain(host):
                    domains.add(domain)
    return TriageReport(
        source_file=path.name,
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        message=header_values,
        authentication=parse_authentication(message),
        urls=urls,
        domains=sorted(domains),
    )


class VirusTotalClient:
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, timeout: float = 15.0, delay: float = 0.0) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.delay = delay

    def _get(self, endpoint: str, indicator: str, kind: str) -> IntelResult:
        request = urllib.request.Request(
            f"{self.base_url}/{endpoint}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            timestamp = attrs.get("last_analysis_date")
            analyzed = (
                datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
                if isinstance(timestamp, (int, float))
                else None
            )
            return IntelResult(
                indicator=indicator,
                kind=kind,
                status="found",
                malicious=int(stats.get("malicious", 0)),
                suspicious=int(stats.get("suspicious", 0)),
                harmless=int(stats.get("harmless", 0)),
                undetected=int(stats.get("undetected", 0)),
                reputation=attrs.get("reputation"),
                last_analysis_date=analyzed,
            )
        except urllib.error.HTTPError as exc:
            status = "not_found" if exc.code == 404 else "error"
            return IntelResult(indicator, kind, status, error=f"VirusTotal HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return IntelResult(indicator, kind, "error", error=f"VirusTotal request failed: {exc}")
        finally:
            if self.delay:
                time.sleep(self.delay)

    def lookup_domain(self, domain: str) -> IntelResult:
        encoded = urllib.parse.quote(domain, safe="")
        return self._get(f"domains/{encoded}", domain, "domain")

    def lookup_url(self, url: str) -> IntelResult:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._get(f"urls/{url_id}", url, "url")


class FixtureClient:
    def __init__(self, path: Path) -> None:
        self.data = json.loads(path.read_text(encoding="utf-8"))

    def _lookup(self, indicator: str, kind: str) -> IntelResult:
        record = self.data.get(kind + "s", {}).get(indicator)
        if not record:
            return IntelResult(indicator, kind, "not_found")
        allowed = {key: value for key, value in record.items() if key in IntelResult.__dataclass_fields__}
        return IntelResult(indicator=indicator, kind=kind, **allowed)

    def lookup_domain(self, domain: str) -> IntelResult:
        return self._lookup(domain, "domain")

    def lookup_url(self, url: str) -> IntelResult:
        return self._lookup(url, "url")


def enrich(report: TriageReport, client: Any | None, lookup: str) -> None:
    if client is None:
        for domain in report.domains:
            report.intelligence.append(IntelResult(domain, "domain", "not_checked"))
        for url in report.urls:
            report.intelligence.append(IntelResult(url, "url", "not_checked"))
        return
    if lookup in {"domains", "both"}:
        report.intelligence.extend(client.lookup_domain(domain) for domain in report.domains)
    if lookup in {"urls", "both"}:
        report.intelligence.extend(client.lookup_url(url) for url in report.urls)


def add_finding(report: TriageReport, severity: str, points: int, description: str) -> None:
    report.findings.append(Finding(severity, points, description))


def analyze(report: TriageReport) -> None:
    from_domain = address_domain(report.message["from"])
    reply_domain = address_domain(report.message["reply_to"])
    return_domain = address_domain(report.message["return_path"])
    if from_domain and reply_domain and from_domain != reply_domain:
        add_finding(report, "medium", 15, "Reply-To domain differs from the From domain.")
    if from_domain and return_domain and from_domain != return_domain:
        add_finding(report, "medium", 10, "Return-Path domain differs from the From domain.")

    for mechanism, outcome in report.authentication.items():
        if outcome in {"fail", "softfail", "permerror"}:
            points = 15 if mechanism == "dmarc" else 10
            add_finding(report, "high" if mechanism == "dmarc" else "medium", points,
                        f"{mechanism.upper()} authentication result is {outcome}.")

    for url in report.urls:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        try:
            ipaddress.ip_address(host)
            add_finding(report, "medium", 20, "A URL uses a raw IP address instead of a domain.")
        except ValueError:
            pass
        if host.startswith("xn--") or ".xn--" in host:
            add_finding(report, "medium", 15, "A URL contains an internationalized (Punycode) domain.")
        if parsed.username is not None:
            add_finding(report, "high", 20, "A URL contains user-info that can obscure its true host.")
        if parsed.scheme == "http":
            add_finding(report, "low", 3, "A URL uses unencrypted HTTP.")

    for result in report.intelligence:
        if result.status != "found":
            continue
        if result.malicious >= 3:
            add_finding(report, "critical", 60,
                        f"VirusTotal marks a {result.kind} malicious by {result.malicious} engines.")
        elif result.malicious >= 1 or result.suspicious >= 2:
            add_finding(report, "high", 35,
                        f"VirusTotal flags a {result.kind} ({result.malicious} malicious, "
                        f"{result.suspicious} suspicious engines).")

    report.score = min(100, sum(finding.points for finding in report.findings))
    if report.score >= 60:
        report.verdict = "malicious"
        report.recommended_actions = [
            "Quarantine the message and search for matching indicators across mail and endpoint telemetry.",
            "Block confirmed malicious indicators after validating business impact.",
            "Identify recipients who clicked or submitted credentials; reset credentials and revoke sessions as needed.",
            "Preserve the original message and investigation notes for incident response.",
        ]
    elif report.score >= 25:
        report.verdict = "suspicious"
        report.recommended_actions = [
            "Hold or quarantine the message pending analyst review.",
            "Validate sender identity through a trusted out-of-band channel.",
            "Review URL reputation and authentication evidence before release.",
        ]
    else:
        report.verdict = "likely_benign"
        report.recommended_actions = [
            "No automated containment recommended; close or release after normal analyst validation.",
            "Do not treat a clean or unavailable reputation result as proof of safety.",
        ]


def defang(value: str) -> str:
    return value.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def markdown_report(report: TriageReport) -> str:
    verdict = report.verdict.replace("_", " ").upper()
    lines = [
        "# Phishing Triage Summary",
        "",
        f"- **Verdict:** {verdict}",
        f"- **Risk score:** {report.score}/100",
        f"- **Source:** `{report.source_file}`",
        f"- **Generated (UTC):** {report.generated_at}",
        "",
        "## Message overview",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for key in ("from", "reply_to", "return_path", "to", "subject", "date", "message_id"):
        value = str(report.message.get(key) or "Not present").replace("|", "\\|")
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    lines.extend(["", "## Authentication", "", "| Control | Result |", "|---|---|"])
    for mechanism, result in report.authentication.items():
        lines.append(f"| {mechanism.upper()} | {result.upper()} |")
    lines.extend(["", "## Indicators", ""])
    if not report.intelligence:
        lines.append("No URL or domain indicators were extracted.")
    else:
        lines.extend(["| Type | Indicator (defanged) | Status | Malicious | Suspicious |",
                      "|---|---|---:|---:|---:|"])
        for item in report.intelligence:
            lines.append(
                f"| {item.kind} | `{defang(item.indicator)}` | {item.status} | "
                f"{item.malicious} | {item.suspicious} |"
            )
    lines.extend(["", "## Findings", ""])
    if report.findings:
        for finding in report.findings:
            lines.append(f"- **{finding.severity.upper()} (+{finding.points}):** {finding.description}")
    else:
        lines.append("- No rule-based risk findings.")
    lines.extend(["", "## Recommended actions", ""])
    lines.extend(f"- {action}" for action in report.recommended_actions)
    lines.extend([
        "",
        "> Analyst note: Reputation and heuristic results are decision support, not a substitute for contextual review.",
        "",
    ])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email", type=Path, help="Path to a raw RFC 5322 .eml file")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, help="Write the report to this path (stdout by default)")
    parser.add_argument("--api-key", help="VirusTotal API key (prefer VT_API_KEY environment variable)")
    parser.add_argument("--intel-file", type=Path, help="Offline JSON intelligence fixture for demos/tests")
    parser.add_argument("--lookup", choices=("domains", "urls", "both"), default="both")
    parser.add_argument("--request-delay", type=float, default=0.0,
                        help="Seconds between VirusTotal requests (useful for rate limits)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.email.is_file():
        print(f"error: email file not found: {args.email}", file=sys.stderr)
        return 2
    if args.intel_file and not args.intel_file.is_file():
        print(f"error: intelligence fixture not found: {args.intel_file}", file=sys.stderr)
        return 2
    try:
        report = parse_email(args.email)
        if args.intel_file:
            client: Any | None = FixtureClient(args.intel_file)
        elif api_key := (args.api_key or os.getenv("VT_API_KEY")):
            client = VirusTotalClient(api_key, delay=max(0.0, args.request_delay))
        else:
            client = None
        enrich(report, client, args.lookup)
        analyze(report)
        rendered = (
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
            if args.format == "json"
            else markdown_report(report)
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
