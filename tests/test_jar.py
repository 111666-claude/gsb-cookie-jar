import unittest

from cookiejar.jar import CookieError, CookieJar, parse_set_cookie


class ParseTest(unittest.TestCase):
    def test_name_and_value(self):
        cookie = parse_set_cookie("a=1", "http://example.com/x")
        self.assertEqual(cookie.name, "a")
        self.assertEqual(cookie.value, "1")
        self.assertEqual(cookie.domain, "example.com")

    def test_explicit_path_is_kept(self):
        cookie = parse_set_cookie("a=1; Path=/foo", "http://example.com/bar")
        self.assertEqual(cookie.path, "/foo")

    def test_explicit_domain_is_lowercased(self):
        cookie = parse_set_cookie("a=1; Domain=Example.COM", "http://example.com/")
        self.assertEqual(cookie.domain, "example.com")

    def test_flags(self):
        cookie = parse_set_cookie("a=1; Secure; HttpOnly", "https://example.com/")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)

    def test_missing_equals(self):
        with self.assertRaises(CookieError):
            parse_set_cookie("justtext", "http://example.com/")

    def test_empty_name(self):
        with self.assertRaises(CookieError):
            parse_set_cookie("=1", "http://example.com/")


class JarTest(unittest.TestCase):
    def test_header_contains_value(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        self.assertIn("a=1", jar.header_for("http://example.com/"))

    def test_same_cookie_is_overwritten(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        jar.store("a=2; Path=/", "http://example.com/")
        self.assertEqual(len(jar.cookies), 1)
        self.assertEqual(jar.get("a").value, "2")

    def test_creation_time_is_kept_on_overwrite(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/", now=5)
        jar.store("a=2; Path=/", "http://example.com/", now=9)
        self.assertEqual(jar.get("a").creation, 5)

    def test_other_domain_is_not_sent(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Domain=example.com", "http://example.com/")
        self.assertEqual(jar.header_for("http://other.test/"), "")

    def test_http_only_can_be_excluded(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; HttpOnly", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/", include_http_only=False), "")


if __name__ == "__main__":
    unittest.main()
