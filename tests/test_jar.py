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


class DefaultPathTest(unittest.TestCase):
    def test_nested_path_uses_parent_directory(self):
        cookie = parse_set_cookie("a=1", "http://example.com/foo/bar")
        self.assertEqual(cookie.path, "/foo")

    def test_single_segment_uses_root(self):
        cookie = parse_set_cookie("a=1", "http://example.com/foo")
        self.assertEqual(cookie.path, "/")

    def test_root_uses_root(self):
        cookie = parse_set_cookie("a=1", "http://example.com/")
        self.assertEqual(cookie.path, "/")

    def test_trailing_slash_uses_parent(self):
        cookie = parse_set_cookie("a=1", "http://example.com/foo/")
        self.assertEqual(cookie.path, "/foo")

    def test_empty_path_uses_root(self):
        cookie = parse_set_cookie("a=1", "http://example.com")
        self.assertEqual(cookie.path, "/")


class DomainMatchTest(unittest.TestCase):
    def _jar(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Domain=example.com", "http://example.com/")
        return jar

    def test_same_host_matches(self):
        self.assertEqual(self._jar().header_for("http://example.com/x"), "a=1")

    def test_subdomain_matches(self):
        self.assertEqual(self._jar().header_for("http://www.example.com/x"), "a=1")

    def test_label_suffix_required(self):
        self.assertEqual(self._jar().header_for("http://evil-example.com/x"), "")

    def test_parent_domain_does_not_match(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Domain=www.example.com", "http://www.example.com/")
        self.assertEqual(jar.header_for("http://example.com/x"), "")

    def test_supercookie_is_rejected(self):
        jar = CookieJar()
        with self.assertRaises(CookieError) as ctx:
            jar.store("a=1; Domain=.com", "http://example.com/")
        self.assertEqual(ctx.exception.attribute, "domain")

    def test_unrelated_domain_is_rejected(self):
        jar = CookieJar()
        with self.assertRaises(CookieError) as ctx:
            jar.store("a=1; Domain=other.com", "http://example.com/")
        self.assertEqual(ctx.exception.attribute, "domain")


class OrderingTest(unittest.TestCase):
    def test_longer_path_comes_first(self):
        jar = CookieJar()
        jar.store("x=1; Path=/", "http://example.com/")
        jar.store("y=1; Path=/foo", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/foo/bar"), "y=1; x=1")

    def test_same_path_length_uses_creation_time(self):
        jar = CookieJar()
        jar.store("z=1; Path=/a", "http://example.com/", now=2)
        jar.store("y=1; Path=/b", "http://example.com/", now=1)
        self.assertEqual(jar.header_for("http://example.com/"), "y=1; z=1")

    def test_overwrite_keeps_original_sort_position(self):
        jar = CookieJar()
        jar.store("y=1; Path=/b", "http://example.com/", now=1)
        jar.store("z=1; Path=/a", "http://example.com/", now=2)
        jar.store("z=2; Path=/a", "http://example.com/", now=3)
        self.assertEqual(jar.header_for("http://example.com/"), "y=1; z=2")

    def test_same_name_appears_once(self):
        jar = CookieJar()
        jar.store("a=root; Path=/", "http://example.com/")
        jar.store("a=deep; Path=/foo", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/foo/bar"), "a=deep")
        self.assertEqual(len(jar.cookies), 2)

    def test_repeat_runs_are_identical(self):
        def run():
            jar = CookieJar()
            jar.store("x=1; Path=/", "http://example.com/")
            jar.store("y=1; Path=/foo", "http://example.com/")
            jar.store("x=2; Path=/", "http://example.com/")
            return jar.header_for("http://example.com/foo")
        self.assertEqual(run(), run())


class MaxAgeTest(unittest.TestCase):
    def test_max_age_zero_deletes_immediately(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        jar.store("a=1; Path=/; Max-Age=0", "http://example.com/")
        self.assertEqual(len(jar.cookies), 0)
        self.assertEqual(jar.header_for("http://example.com/"), "")

    def test_negative_max_age_deletes(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        jar.store("a=1; Path=/; Max-Age=-5", "http://example.com/")
        self.assertEqual(len(jar.cookies), 0)

    def test_max_age_expiry_uses_now(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Max-Age=10", "http://example.com/", now=100)
        self.assertEqual(jar.header_for("http://example.com/", now=105), "a=1")
        self.assertEqual(jar.header_for("http://example.com/", now=110), "")

    def test_max_age_wins_over_expires(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Max-Age=0; Expires=Wed, 01 Jan 2098 00:00:00 GMT",
                  "http://example.com/")
        self.assertEqual(len(jar.cookies), 0)

    def test_expires_used_without_max_age(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                  "http://example.com/", now=0)
        self.assertEqual(len(jar.cookies), 0)

    def test_session_cookie_without_expiry(self):
        cookie = parse_set_cookie("a=1", "http://example.com/")
        self.assertIsNone(cookie.expires)

    def test_bad_max_age_reports_attribute(self):
        with self.assertRaises(CookieError) as ctx:
            parse_set_cookie("a=1; Max-Age=soon", "http://example.com/")
        self.assertEqual(ctx.exception.attribute, "max-age")

    def test_bad_expires_reports_attribute(self):
        with self.assertRaises(CookieError) as ctx:
            parse_set_cookie("a=1; Expires=not-a-date", "http://example.com/")
        self.assertEqual(ctx.exception.attribute, "expires")


class SendConditionsTest(unittest.TestCase):
    def test_secure_only_over_https(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Secure", "https://example.com/")
        self.assertEqual(jar.header_for("http://example.com/"), "")
        self.assertEqual(jar.header_for("https://example.com/"), "a=1")

    def test_path_must_share_prefix(self):
        jar = CookieJar()
        jar.store("a=1; Path=/foo", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/foo/bar"), "a=1")
        self.assertEqual(jar.header_for("http://example.com/fo"), "a=1")
        self.assertEqual(jar.header_for("http://example.com/bar"), "")

    def test_request_path_is_prefix_of_cookie_path(self):
        jar = CookieJar()
        jar.store("a=1; Path=/foo/bar", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/foo"), "a=1")


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

    def test_same_name_different_path_coexists(self):
        jar = CookieJar()
        jar.store("a=1; Path=/", "http://example.com/")
        jar.store("a=2; Path=/foo", "http://example.com/")
        self.assertEqual(len(jar.cookies), 2)

    def test_other_domain_is_not_sent(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; Domain=example.com", "http://example.com/")
        self.assertEqual(jar.header_for("http://other.test/"), "")

    def test_http_only_can_be_excluded(self):
        jar = CookieJar()
        jar.store("a=1; Path=/; HttpOnly", "http://example.com/")
        self.assertEqual(jar.header_for("http://example.com/", include_http_only=False), "")
        self.assertEqual(jar.header_for("http://example.com/"), "a=1")


if __name__ == "__main__":
    unittest.main()
