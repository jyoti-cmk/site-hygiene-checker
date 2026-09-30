"""
Site Hygiene Checker
--------------------
Passive (read-only) review of a single URL for common web hygiene issues:

- HTTPS / redirect / HSTS
- Recommended security headers
- Cookie flags (Secure, HttpOnly, SameSite)
- Mixed content (http:// subresources on an https:// page)
- HTML form inventory (no form submission, no attack payloads)

This tool only issues a GET request to the URL you pass. It does not crawl
the site, does not log in, and does not inject test payloads.

Usage:
    python site_hygiene_checker.py --url https://example.com
    python site_hygiene_checker.py --url https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

TIMEOUT = 15
HEADERS = {"User-Agent": "SiteHygieneChecker-Educational/1.0"}

# Headers commonly recommended for browser-facing apps (presence check only).
EXPECTED_HEADERS = [
    ("Content-Security-Policy", "Restricts where scripts, styles, and other resources may load from."),
    ("X-Content-Type-Options", "Reduces MIME-sniffing (expect nosniff)."),
    ("X-Frame-Options", "Helps limit clickjacking via framing (or use CSP frame-ancestors)."),
    ("Referrer-Policy", "Controls how much referrer data is sent on navigation."),
    ("Permissions-Policy", "Limits browser features (camera, geolocation, etc.)."),
]

MIXED_CONTENT_TAGS = {
    "img": ("src", "srcset"),
    "script": ("src",),
    "link": ("href",),
    "iframe": ("src",),
    "audio": ("src",),
    "video": ("src", "poster"),
    "source": ("src", "srcset"),
    "embed": ("src",),
    "object": ("data",),
    "form": ("action",),
}

TOKEN_NAME_HINTS = (
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "anti-forgery",
    "__requestverificationtoken",
)


def header_value(headers, name):
    """Return the first matching header value, case-insensitive, or None."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def set_cookie_headers(response):
    """Collect all Set-Cookie header values from the raw response."""
    raw = getattr(response.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        values = raw.getlist("Set-Cookie")
        if values:
            return values
    single = header_value(response.headers, "Set-Cookie")
    if not single:
        return []
    return [single]


def parse_set_cookie(raw):
    """
    Parse a Set-Cookie header into name plus flag attributes.
    Does not evaluate cookie values beyond the name=value pair.
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return None
    name_value = parts[0]
    if "=" not in name_value:
        return None
    name, _value = name_value.split("=", 1)
    flags = {}
    for attr in parts[1:]:
        if "=" in attr:
            key, val = attr.split("=", 1)
            flags[key.strip().lower()] = val.strip()
        else:
            flags[attr.lower()] = True
    return {
        "name": name.strip(),
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": flags.get("samesite"),
    }


def cookie_looks_session_like(name):
    lowered = name.lower()
    return any(
        token in lowered
        for token in ("session", "sess", "auth", "token", "sid", "jwt", "login")
    )


def looks_like_csrf_field(name):
    lowered = (name or "").lower()
    return any(hint in lowered for hint in TOKEN_NAME_HINTS)


def is_http_url(url):
    if not url or url.startswith("#") or url.lower().startswith("javascript:"):
        return False
    parsed = urlparse(urljoin("https://placeholder.invalid/", url))
    return parsed.scheme == "http"


def fetch(url):
    session = requests.Session()
    session.max_redirects = 5
    response = session.get(
        url,
        headers=HEADERS,
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    history = [r.url for r in response.history] + [response.url]
    return response, history


def check_https(request_url, response, history):
    findings = []
    start = urlparse(request_url)
    final = urlparse(response.url)

    if start.scheme == "http":
        findings.append(
            {
                "severity": "fail",
                "category": "HTTPS",
                "title": "Target URL uses HTTP",
                "detail": "The requested URL is not HTTPS. Traffic and cookies can be intercepted on the network.",
            }
        )
        if final.scheme == "https":
            findings.append(
                {
                    "severity": "info",
                    "category": "HTTPS",
                    "title": "HTTP request redirected to HTTPS",
                    "detail": f"Final URL after redirects: {response.url}",
                }
            )
        else:
            findings.append(
                {
                    "severity": "fail",
                    "category": "HTTPS",
                    "title": "Did not land on HTTPS",
                    "detail": f"Final URL is still HTTP: {response.url}",
                }
            )
    elif start.scheme == "https":
        findings.append(
            {
                "severity": "info",
                "category": "HTTPS",
                "title": "Target URL uses HTTPS",
                "detail": f"Fetched {response.url} (HTTP {response.status_code}).",
            }
        )
    else:
        findings.append(
            {
                "severity": "fail",
                "category": "HTTPS",
                "title": "Unsupported URL scheme",
                "detail": f"Expected http or https, got '{start.scheme}'.",
            }
        )

    if len(history) > 1:
        findings.append(
            {
                "severity": "info",
                "category": "HTTPS",
                "title": "Redirect chain",
                "detail": " -> ".join(history),
            }
        )

    hsts = header_value(response.headers, "Strict-Transport-Security")
    if final.scheme == "https" and not hsts:
        findings.append(
            {
                "severity": "warn",
                "category": "HTTPS",
                "title": "Missing Strict-Transport-Security",
                "detail": "Browsers are not instructed to always use HTTPS on future visits.",
            }
        )
    elif hsts:
        findings.append(
            {
                "severity": "info",
                "category": "HTTPS",
                "title": "HSTS is present",
                "detail": hsts,
            }
        )

    return findings


def check_security_headers(response):
    findings = []
    csp = header_value(response.headers, "Content-Security-Policy")
    xfo = header_value(response.headers, "X-Frame-Options")

    for name, why in EXPECTED_HEADERS:
        value = header_value(response.headers, name)
        if value:
            findings.append(
                {
                    "severity": "info",
                    "category": "Headers",
                    "title": f"{name} is present",
                    "detail": value,
                }
            )
            continue
        if name == "X-Frame-Options" and csp and "frame-ancestors" in csp.lower():
            findings.append(
                {
                    "severity": "info",
                    "category": "Headers",
                    "title": "X-Frame-Options missing, CSP frame-ancestors present",
                    "detail": "Clickjacking controls can be provided by CSP instead of X-Frame-Options.",
                }
            )
            continue
        findings.append(
            {
                "severity": "warn",
                "category": "Headers",
                "title": f"Missing {name}",
                "detail": why,
            }
        )

    xcto = header_value(response.headers, "X-Content-Type-Options")
    if xcto and xcto.lower().replace(" ", "") != "nosniff":
        findings.append(
            {
                "severity": "warn",
                "category": "Headers",
                "title": "X-Content-Type-Options is not nosniff",
                "detail": f"Got: {xcto}",
            }
        )

    return findings


def check_cookies(response, page_is_https):
    findings = []
    raw_cookies = set_cookie_headers(response)
    if not raw_cookies:
        findings.append(
            {
                "severity": "info",
                "category": "Cookies",
                "title": "No Set-Cookie headers on this response",
                "detail": "This page did not set cookies. Other responses on the site still might.",
            }
        )
        return findings

    for raw in raw_cookies:
        parsed = parse_set_cookie(raw)
        if not parsed:
            continue
        name = parsed["name"]
        session_like = cookie_looks_session_like(name)

        if page_is_https and not parsed["secure"]:
            findings.append(
                {
                    "severity": "fail" if session_like else "warn",
                    "category": "Cookies",
                    "title": f"Cookie '{name}' missing Secure",
                    "detail": "Without Secure, the cookie may be sent over HTTP.",
                }
            )
        if not parsed["httponly"]:
            findings.append(
                {
                    "severity": "warn",
                    "category": "Cookies",
                    "title": f"Cookie '{name}' missing HttpOnly",
                    "detail": "Without HttpOnly, page scripts can read the cookie if XSS is present.",
                }
            )
        if not parsed["samesite"]:
            findings.append(
                {
                    "severity": "warn",
                    "category": "Cookies",
                    "title": f"Cookie '{name}' missing SameSite",
                    "detail": "SameSite=Lax or Strict reduces cross-site cookie sending.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "info",
                    "category": "Cookies",
                    "title": f"Cookie '{name}' SameSite={parsed['samesite']}",
                    "detail": "Secure=%s HttpOnly=%s"
                    % (parsed["secure"], parsed["httponly"]),
                }
            )

    return findings


def check_mixed_content(page_url, html):
    findings = []
    page = urlparse(page_url)
    if page.scheme != "https":
        findings.append(
            {
                "severity": "info",
                "category": "Mixed content",
                "title": "Skipped mixed-content check",
                "detail": "Mixed content only applies when the page itself is HTTPS.",
            }
        )
        return findings

    soup = BeautifulSoup(html, "html.parser")
    seen = set()

    for tag_name, attrs in MIXED_CONTENT_TAGS.items():
        for tag in soup.find_all(tag_name):
            for attr in attrs:
                raw = tag.get(attr)
                if not raw:
                    continue
                candidates = [raw]
                if attr == "srcset":
                    candidates = [part.strip().split(" ")[0] for part in raw.split(",") if part.strip()]
                for candidate in candidates:
                    absolute = urljoin(page_url, candidate)
                    if not is_http_url(absolute):
                        continue
                    key = (tag_name, attr, absolute)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        {
                            "severity": "fail",
                            "category": "Mixed content",
                            "title": f"HTTP {tag_name}[{attr}]",
                            "detail": absolute,
                        }
                    )

    for match in re.findall(r"url\(\s*['\"]?(http://[^)'\"]+)", html, flags=re.IGNORECASE):
        if match not in seen:
            seen.add(match)
            findings.append(
                {
                    "severity": "fail",
                    "category": "Mixed content",
                    "title": "HTTP url() in page HTML/CSS",
                    "detail": match,
                }
            )

    if not any(f["severity"] == "fail" for f in findings):
        findings.append(
            {
                "severity": "info",
                "category": "Mixed content",
                "title": "No http:// subresources found on this page",
                "detail": "Only this HTML document was inspected (no crawl).",
            }
        )
    return findings


def inventory_forms(page_url, html):
    findings = []
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    page_https = urlparse(page_url).scheme == "https"

    findings.append(
        {
            "severity": "info",
            "category": "Forms",
            "title": f"Found {len(forms)} form(s) on this page",
            "detail": "Forms are listed only. Nothing is submitted.",
        }
    )

    for index, form in enumerate(forms, 1):
        action = form.get("action", "")
        method = (form.get("method") or "get").upper()
        enctype = form.get("enctype") or ""
        absolute_action = urljoin(page_url, action) if action else page_url

        fields = []
        has_password = False
        has_file = False
        has_csrf_hint = False
        password_autocomplete = []

        for control in form.find_all(["input", "textarea", "select"]):
            name = control.get("name") or control.get("id") or "(unnamed)"
            control_type = (control.get("type") or control.name).lower()
            fields.append(f"{name}:{control_type}")
            if control_type == "password":
                has_password = True
                password_autocomplete.append(control.get("autocomplete", ""))
            if control_type == "file":
                has_file = True
            if control_type == "hidden" and looks_like_csrf_field(name):
                has_csrf_hint = True

        findings.append(
            {
                "severity": "info",
                "category": "Forms",
                "title": f"Form {index}: {method} {absolute_action}",
                "detail": "Fields: "
                + (", ".join(fields) if fields else "(no named fields)")
                + (f"; enctype={enctype}" if enctype else ""),
            }
        )

        if page_https and is_http_url(absolute_action):
            findings.append(
                {
                    "severity": "fail",
                    "category": "Forms",
                    "title": f"Form {index} submits to HTTP",
                    "detail": absolute_action,
                }
            )

        if method == "POST" and not has_csrf_hint:
            findings.append(
                {
                    "severity": "warn",
                    "category": "Forms",
                    "title": f"Form {index} POST has no obvious CSRF token field",
                    "detail": "Looked only for common hidden field names (csrf, _token, etc.). "
                    "A token might still be set via cookie or header — this is a hygiene hint, not a proof of vulnerability.",
                }
            )

        if has_password:
            if not page_https:
                findings.append(
                    {
                        "severity": "fail",
                        "category": "Forms",
                        "title": f"Form {index} collects a password over HTTP",
                        "detail": "Password fields should only appear on HTTPS pages.",
                    }
                )
            if any(val.lower() == "off" for val in password_autocomplete if val):
                findings.append(
                    {
                        "severity": "info",
                        "category": "Forms",
                        "title": f"Form {index} password autocomplete=off",
                        "detail": "Disabling password manager autocomplete can weaken account security.",
                    }
                )

        if has_file and "multipart/form-data" not in enctype.lower():
            findings.append(
                {
                    "severity": "warn",
                    "category": "Forms",
                    "title": f"Form {index} has a file input without multipart/form-data",
                    "detail": "File uploads typically need enctype=\"multipart/form-data\".",
                }
            )

    return findings


def scan(url):
    response, history = fetch(url)
    page_url = response.url
    page_is_https = urlparse(page_url).scheme == "https"
    html = response.text if "html" in (response.headers.get("Content-Type") or "").lower() else response.text

    findings = []
    findings.extend(check_https(url, response, history))
    findings.extend(check_security_headers(response))
    findings.extend(check_cookies(response, page_is_https))
    findings.extend(check_mixed_content(page_url, html))
    findings.extend(inventory_forms(page_url, html))
    return {
        "requested_url": url,
        "final_url": page_url,
        "status_code": response.status_code,
        "findings": findings,
    }


def print_report(result):
    findings = result["findings"]
    fails = sum(1 for f in findings if f["severity"] == "fail")
    warns = sum(1 for f in findings if f["severity"] == "warn")

    print("=" * 64)
    print("SITE HYGIENE REPORT")
    print("=" * 64)
    print(f"Requested : {result['requested_url']}")
    print(f"Final URL : {result['final_url']}")
    print(f"HTTP      : {result['status_code']}")
    print(f"Findings  : {fails} fail, {warns} warn")
    print("-" * 64)

    current = None
    for item in findings:
        if item["category"] != current:
            current = item["category"]
            print(f"\n[{current}]")
        marker = {"fail": "FAIL", "warn": "WARN", "info": "INFO"}[item["severity"]]
        print(f"  [{marker}] {item['title']}")
        print(f"         {item['detail']}")

    print("\n" + "=" * 64)
    print("Passive check of one URL only. Missing findings does not mean the site is secure.")
    print("=" * 64)


def main():
    parser = argparse.ArgumentParser(
        description="Passive site hygiene checker (headers, HTTPS, cookies, mixed content, forms)."
    )
    parser.add_argument("--url", required=True, help="Page URL to inspect (GET only).")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a text report.")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("[ERROR] Please pass a full http:// or https:// URL.")
        sys.exit(1)

    try:
        result = scan(args.url)
    except requests.RequestException as exc:
        print(f"[ERROR] Could not fetch '{args.url}': {exc}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    if any(f["severity"] == "fail" for f in result["findings"]):
        sys.exit(2)
    if any(f["severity"] == "warn" for f in result["findings"]):
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
