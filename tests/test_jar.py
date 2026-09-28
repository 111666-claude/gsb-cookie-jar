import unittest

import time

from cookiejar.jar import CookieError, CookieJar, default_path, parse_set_cookie


class ParseTest(unittest.TestCase):
    def test_name_and_value(self):
        cookie = parse_set_cookie("a=1", "http://example.com/x")
        self.assertEqual(cookie.name, "a")
        self.assertEqual(cookie.value, "1")
        self.assertEqual(cookie.domain, "example.com")

    def test_explicit_path_is_kept(self):
        cookie = parse_set_cookie("a=1; Path=/foo", "http://example.com/bar")
        self.assertEqual(cookie.path, "/foo")

    def test_default_path_is_parent_directory(self):
        cookie = parse_set_cookie("a=1", "http://example.com/foo/bar")
        self.assertEqual(cookie.path, "/foo")
        cookie = parse_set_cookie("a=1", "http://example.com/foo")
        self.assertEqual(cookie.path, "/")
        cookie = parse_set_cookie("a=1", "http://example.com/")
        self.assertEqual(cookie.path, "/")
        cookie = parse_set_cookie("a=1", "http://example.com")
        self.assertEqual(cookie.path, "/")

    def test_default_path_helper(self):
        self.assertEqual(default_path("/foo/bar"), "/foo")
        self.assertEqual(default_path("/foo/bar/baz"), "/foo/bar")
        self.assertEqual(default_path("/foo"), "/")
        self.assertEqual(default_path("/"), "/")
        self.assertEqual(default_path("foo"), "/")
        self.assertEqual(default_path(""), "/")

    def test_explicit_domain_is_lowercased(self):
        cookie = parse_set_cookie("a=1; Domain=Example.COM", "http://example.com/")
        self.assertEqual(cookie.domain, "example.com")

    def test_supercookie_domain_is_rejected(self):
        with self.assertRaises(CookieError) as context:
            parse_set_cookie("a=1; Domain=.com", "http://example.com/")
        self.assertIn("Domain", str(context.exception))
        with self.assertRaises(CookieError):
            parse_set_cookie("a=1; Domain=localhost", "http://localhost/")

    def test_host_only_cookie_is_marked(self):
        cookie = parse_set_cookie("a=1", "http://www.example.com/")
        self.assertTrue(cookie.host_only)
        cookie = parse_set_cookie("a=1; Domain=example.com", "http://www.example.com/")
        self.assertFalse(cookie.host_only)

    def test_flags(self):
        cookie = parse_set_cookie("a=1; Secure; HttpOnly", "https://example.com/")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)

    def test_max_age_zero_is_expired(self):
        cookie = parse_set_cookie("a=1; Max-Age=0", "http://example.com/", now=100)
        self.assertEqual(cookie.expires, 100)

    def test_negative_max_age_is_expired(self):
        cookie = parse_set_cookie("a=1; Max-Age=-5", "http://example.com/", now=100)
        self.assertEqual(cookie.expires, 100)

    def test_max_age_takes_precedence_over_expires(self):
        cookie = parse_set_cookie(
            "a=1; Max-Age=10; Expires=Mon, 01 Jan 1900 00:00:00 GMT",
            "http://example.com/", now=100)
        self.assertEqual(cookie.expires, 110)

    def test_bad_max_age_names_attribute(self):
        with self.assertRaises(CookieError) as context:
            parse_set_cookie("a=1; Max-Age=soon", "http://example.com/")
        self.assertIn("Max-Age", str(context.exception))

    def test_bad_expires_names_attribute(self):
        with self.assertRaises(CookieError) as context:
            parse_set_cookie("a=1; Expires=not-a-date", "http://example.com/")
        self.assertIn("Expires", str(context.exception))

    def test_session_cookie_has_no_expires(self):
        cookie = parse_set_cookie("a=1", "http://example.com/", now=100)
        self.assertIsNone(cookie.expires)

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

    def test_domain_match_is_label_aware(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Domain=example.com", "http://example.com/")
        self.assertIn("a=1", jar.header_for("http://www.example.com/"))
        self.assertEqual(jar.header_for("http://evil-example.com/x"), "")

    def test_host_only_cookie_is_not_sent_to_subdomain(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://www.example.com/")
        self.assertIn("a=1", jar.header_for("http://www.example.com/"))
        self.assertEqual(jar.header_for("http://example.com/"), "")
        self.assertEqual(jar.header_for("http://sub.www.example.com/"), "")

    def test_supercookie_is_rejected_on_store(self):
        jar = CookieJar()
        with self.assertRaises(CookieError):
            jar.store("a=1; Domain=.com", "http://example.com/")

    def test_header_is_sorted_by_path_length_desc(self):
        jar = CookieJar()
        jar.store("x=1; Path=/", "http://example.com/foo/bar", now=1)
        jar.store("y=1; Path=/foo", "http://example.com/foo/bar", now=2)
        self.assertEqual(jar.header_for("http://example.com/foo/bar"), "y=1; x=1")

    def test_header_creation_time_breaks_ties(self):
        jar = CookieJar()
        jar.store("a=1; Path=/foo", "http://example.com/foo/bar", now=2)
        jar.store("b=2; Path=/foo", "http://example.com/foo/bar", now=1)
        self.assertEqual(jar.header_for("http://example.com/foo/bar"), "b=2; a=1")

    def test_path_prefix_is_required_both_ways(self):
        jar = CookieJar()
        jar.store("a=1; Path=/foo", "http://example.com/foo/x")
        self.assertIn("a=1", jar.header_for("http://example.com/foo/bar"))
        self.assertIn("a=1", jar.header_for("http://example.com/foo"))
        self.assertEqual(jar.header_for("http://example.com/baz"), "")

    def test_secure_only_sent_over_https(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Secure", "https://example.com/")
        self.assertIn("a=1", jar.header_for("https://example.com/"))
        self.assertEqual(jar.header_for("http://example.com/"), "")

    def test_http_only_can_be_excluded(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; HttpOnly", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/", include_http_only=False), "")

    def test_max_age_zero_deletes_cookie(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Max-Age=100", "http://example.com/", now=0)
        jar.store("a=1; Path=/; Max-Age=0", "http://example.com/", now=50)
        self.assertEqual(len(jar.cookies), 0)
        self.assertEqual(jar.header_for("http://example.com/", now=50), "")

    def test_expired_cookie_is_not_sent(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
                  "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/"), "")

    def test_same_name_different_paths_coexist(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        jar.store("a=2; Path=/foo", "http://example.com/")
        self.assertEqual(len(jar.cookies), 2)

    def test_header_has_each_name_once(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        jar.store("a=2; Path=/foo", "http://example.com/")
        header = jar.header_for("http://example.com/foo/bar")
        self.assertEqual(header, "a=2")

    def test_overwrite_then_expire_keeps_no_cookie(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/", now=5)
        jar.store("a=2; Path=/; Max-Age=0", "http://example.com/", now=9)
        self.assertEqual(jar.get("a"), None)

    def test_repeated_operations_are_deterministic(self):
        def run():
            jar = CookieJar()
            jar.store("x=1; Path=/", "http://example.com/", now=1)
            jar.store("y=1; Path=/foo", "http://example.com/", now=2)
            return jar.header_for("http://example.com/foo/bar", now=3)
        self.assertEqual(run(), run())

    def test_scale_100k_cookies_and_queries(self):
        jar = CookieJar()
        total = 100000
        for index in range(total):
            jar.store("n%d=1; Path=/" % index, "http://h%d.test/" % index, now=0)
        start = time.perf_counter()
        for index in range(total):
            jar.header_for("http://h%d.test/" % index, now=1000)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0, "10 万次查询耗时 %.3fs" % elapsed)


if __name__ == "__main__":
    unittest.main()
