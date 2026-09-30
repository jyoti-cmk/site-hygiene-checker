# Site Hygiene Checker

Python CLI that performs a **passive** review of one web page: HTTPS, security headers, cookie flags, mixed content, and a form inventory.

It uses `requests` and BeautifulSoup. It **only sends a GET** to the URL you provide. It does not crawl, log in, submit forms, or send attack payloads.

## Requirements

- Python 3.8+

```bash
pip install -r requirements.txt
```

## Usage

```bash
python site_hygiene_checker.py --url https://example.com
python site_hygiene_checker.py --url https://example.com --json
```

## What it checks

| Area | What you get |
| --- | --- |
| HTTPS | Scheme, redirect chain, HSTS presence |
| Security headers | CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options` (or CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy` |
| Cookies | `Secure`, `HttpOnly`, `SameSite` on `Set-Cookie` from this response |
| Mixed content | `http://` images, scripts, styles, iframes, and similar on an HTTPS page |
| Forms | Method, action, field names/types; password-over-HTTP; POST without an obvious CSRF field name |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No fail or warn findings |
| `1` | Could not fetch the URL, or the URL was invalid |
| `2` | At least one **fail** finding |
| `3` | At least one **warn** finding (and no fails) |

## Notes

- Absence of findings does **not** mean the application is secure. This is hygiene on a single response, not a vulnerability assessment.
- CSRF field names are a hint only. Tokens may be delivered in cookies or headers.
- Only inspect sites you are allowed to request.

## Tests

```bash
python -m unittest discover -s tests
```
