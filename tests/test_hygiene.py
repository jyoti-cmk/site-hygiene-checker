import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from site_hygiene_checker import (
    check_mixed_content,
    inventory_forms,
    parse_set_cookie,
)


class ParseCookieTests(unittest.TestCase):
    def test_flags(self):
        parsed = parse_set_cookie("sid=abc; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(parsed["name"], "sid")
        self.assertTrue(parsed["secure"])
        self.assertTrue(parsed["httponly"])
        self.assertEqual(parsed["samesite"], "Lax")

    def test_missing_flags(self):
        parsed = parse_set_cookie("theme=dark")
        self.assertFalse(parsed["secure"])
        self.assertFalse(parsed["httponly"])
        self.assertIsNone(parsed["samesite"])


class MixedContentTests(unittest.TestCase):
    def test_detects_http_script(self):
        html = '<script src="http://cdn.example/x.js"></script>'
        findings = check_mixed_content("https://example.com/app", html)
        fails = [f for f in findings if f["severity"] == "fail"]
        self.assertTrue(any("http://cdn.example/x.js" in f["detail"] for f in fails))

    def test_skips_on_http_page(self):
        findings = check_mixed_content("http://example.com/", "<img src='http://x/y.png'>")
        self.assertTrue(any("Skipped" in f["title"] for f in findings))


class FormInventoryTests(unittest.TestCase):
    def test_lists_fields_without_submitting(self):
        html = """
        <form method="post" action="/login">
          <input type="hidden" name="csrf_token" value="demo">
          <input type="text" name="user">
          <input type="password" name="pass">
        </form>
        """
        findings = inventory_forms("https://example.com/login", html)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("Found 1 form" in t for t in titles))
        self.assertTrue(any("POST" in t and "login" in t for t in titles))
        self.assertFalse(any("no obvious CSRF" in t for t in titles))

    def test_password_on_http_is_fail(self):
        html = '<form><input type="password" name="p"></form>'
        findings = inventory_forms("http://example.com/", html)
        fails = [f for f in findings if f["severity"] == "fail"]
        self.assertTrue(any("password over HTTP" in f["title"] for f in fails))


if __name__ == "__main__":
    unittest.main()
