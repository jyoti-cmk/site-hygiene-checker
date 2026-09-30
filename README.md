# Task 3: Penetration Testing Toolkit

A Python-based, modular toolkit with two pentesting modules sharing one CLI.

## ⚠️ Ethical use
Only run this against systems you **own** or have **explicit written
authorization** to test. Unauthorized scanning or credential brute-forcing
is illegal in most jurisdictions.

## Structure
```
pentest_toolkit.py          # main CLI dispatcher
modules/
  port_scanner.py           # TCP connect port scanner
  brute_forcer.py           # HTTP Basic Auth credential brute-forcer
auth_test_app.py            # local Flask app for safely testing bruteforce
example_usernames.txt       # sample wordlist
example_passwords.txt       # sample wordlist
```

## Module 1: Port Scanner
Scans a host for open TCP ports using multithreaded TCP connect scans
(no raw sockets / root privileges required).

```bash
python pentest_toolkit.py portscan --host 127.0.0.1 --ports 1-1024
python pentest_toolkit.py portscan --host scanme.example.com --ports 22,80,443
```

**Verified:** tested against localhost with a known open port (9999) — the
scanner correctly identified it as open and all others in range as closed.

## Module 2: Brute-Forcer (HTTP Basic Auth)
Tries username/password combinations from wordlists against an HTTP Basic
Auth-protected URL, using concurrent requests.

```bash
python pentest_toolkit.py bruteforce \
  --url http://127.0.0.1:5056/secret \
  --usernames example_usernames.txt \
  --passwords example_passwords.txt
```

**Verified:** tested against `auth_test_app.py`, a local Flask app with
Basic Auth credentials `admin:letmein123`. The brute-forcer found the
correct pair on the first pass through the wordlists.

To try it yourself:
```bash
pip install flask requests
python auth_test_app.py            # runs on http://127.0.0.1:5056
# in another terminal:
python pentest_toolkit.py bruteforce --url http://127.0.0.1:5056/secret \
  --usernames example_usernames.txt --passwords example_passwords.txt
```

## Design notes (for your documentation)
- Both modules are plain Python files under `modules/`, imported by the
  main CLI — this is the "modular" structure the task asks for. You can
  add more modules (e.g. a subdomain finder, a directory brute-forcer)
  the same way: drop a new file in `modules/`, add a subcommand in
  `pentest_toolkit.py`.
- Threading (`ThreadPoolExecutor`) is used in both modules since each
  operation (a socket connect, an HTTP request) is I/O-bound and benefits
  from concurrency.
- The brute-forcer stops at the first successful login by default
  (`--no-stop` to keep going and find all valid combos).

## For your GitHub submission
Put this whole folder in `task3-pentest-toolkit/` with this README as
the documentation the task explicitly asks for.
