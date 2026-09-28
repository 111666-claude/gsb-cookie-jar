"""HTTP cookie 的解析与匹配（RFC 6265 子集），只用标准库。

口径见 README：默认 Path 取请求路径的上一级目录、域匹配按标签、
Cookie 头按 Path 长度降序再按创建时间升序、Max-Age 优先于 Expires。
"""

from bisect import bisect_left, bisect_right
from datetime import timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit


class CookieError(ValueError):
    """Set-Cookie 不合法；attribute 指出是哪个属性出错。"""

    def __init__(self, message, attribute=None):
        super().__init__(message)
        self.message = message
        self.attribute = attribute


class Cookie:
    """一条 cookie。expires 是绝对时间戳，None 表示会话 cookie。"""

    __slots__ = ("name", "value", "domain", "path", "secure", "http_only",
                 "expires", "creation")

    def __init__(self, name, value, domain, path, secure=False, http_only=False,
                 expires=None, creation=0):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.secure = secure
        self.http_only = http_only
        self.expires = expires
        self.creation = creation


def _default_path(url_path):
    """默认 Path：请求路径的上一级目录；不以 / 开头则为 /。"""
    if not url_path.startswith("/"):
        return "/"
    if url_path.count("/") <= 1:
        return "/"
    return url_path[:url_path.rfind("/")]


def _domain_match(host, domain):
    """按标签匹配：host 等于 domain，或以「.domain」结尾。"""
    return host == domain or host.endswith("." + domain)


def _parse_expires(raw):
    try:
        moment = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        raise CookieError("Expires 属性无法解析: %r" % raw, attribute="expires")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def parse_set_cookie(header, request_url, now=0):
    """解析 Set-Cookie；过期时间折算成时间戳，查询时不再解析字符串。"""
    parts = [part.strip() for part in header.split(";")]
    if not parts or "=" not in parts[0]:
        raise CookieError("缺少 name=value", attribute="name")
    name, _, value = parts[0].partition("=")
    name = name.strip()
    if not name:
        raise CookieError("cookie 名字为空", attribute="name")
    url = urlsplit(request_url)
    host = (url.hostname or "").lower()
    path = _default_path(url.path)
    attributes = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, raw = part.partition("=")
        attributes.setdefault(key.strip().lower(), raw.strip())
    domain = host
    if "domain" in attributes:
        domain = attributes["domain"].lstrip(".").lower()
        if not domain:
            raise CookieError("Domain 属性为空", attribute="domain")
        if not _domain_match(host, domain):
            raise CookieError(
                "Domain=%s 与请求主机 %s 不匹配" % (domain, host), attribute="domain")
        if domain != host and "." not in domain:
            raise CookieError("拒绝 supercookie Domain=%s" % domain, attribute="domain")
    if "path" in attributes and attributes["path"].startswith("/"):
        path = attributes["path"]
    expires = None
    if "max-age" in attributes:
        raw = attributes["max-age"]
        try:
            delta = int(raw)
        except ValueError:
            raise CookieError("Max-Age 属性不是整数: %r" % raw, attribute="max-age")
        expires = now + delta
    elif "expires" in attributes:
        expires = _parse_expires(attributes["expires"])
    return Cookie(name=name, value=value, domain=domain, path=path,
                  secure="secure" in attributes, http_only="httponly" in attributes,
                  expires=expires, creation=now)


class _Bucket:
    """单个域下的 cookie：按 (name, path) 去重，按 path 建查询索引。"""

    __slots__ = ("cookies", "by_path", "sorted_paths", "dirty")

    def __init__(self):
        self.cookies = {}    # (name, path) -> Cookie
        self.by_path = {}    # path -> [Cookie]
        self.sorted_paths = []
        self.dirty = False

    def add(self, cookie):
        key = (cookie.name, cookie.path)
        existing = self.cookies.get(key)
        if existing is not None:
            cookie.creation = existing.creation
            self.cookies[key] = cookie
            siblings = self.by_path[cookie.path]
            siblings[siblings.index(existing)] = cookie
        else:
            self.cookies[key] = cookie
            self.by_path.setdefault(cookie.path, []).append(cookie)
            self.dirty = True

    def remove(self, name, path):
        existing = self.cookies.pop((name, path), None)
        if existing is None:
            return
        siblings = self.by_path[path]
        siblings.remove(existing)
        if not siblings:
            del self.by_path[path]
            self.dirty = True

    def matching(self, request_path):
        """返回 Path 与 request_path 互为前缀的 cookie。"""
        by_path = self.by_path
        out = []
        for end in range(1, len(request_path) + 1):
            siblings = by_path.get(request_path[:end])
            if siblings:
                out.extend(siblings)
        if self.dirty:
            self.sorted_paths = sorted(by_path)
            self.dirty = False
        paths = self.sorted_paths
        low = bisect_left(paths, request_path + "\x00")
        high = bisect_right(paths, request_path + "\U0010ffff")
        for index in range(low, high):
            out.extend(by_path[paths[index]])
        return out


class CookieJar:
    """cookie 存储：按域分桶，同 name+domain+path 覆盖并保留最初创建时间。"""

    def __init__(self):
        self._by_domain = {}

    @property
    def cookies(self):
        out = []
        for bucket in self._by_domain.values():
            out.extend(bucket.cookies.values())
        return out

    def store(self, header, request_url, now=0):
        """存一条 cookie；已过期（含 Max-Age<=0）则删除同 key 的旧 cookie。"""
        cookie = parse_set_cookie(header, request_url, now)
        bucket = self._by_domain.get(cookie.domain)
        if cookie.expires is not None and cookie.expires <= now:
            if bucket is not None:
                bucket.remove(cookie.name, cookie.path)
                if not bucket.cookies:
                    del self._by_domain[cookie.domain]
            return None
        if bucket is None:
            bucket = self._by_domain[cookie.domain] = _Bucket()
        bucket.add(cookie)
        return cookie

    def get(self, name):
        for bucket in self._by_domain.values():
            for cookie in bucket.cookies.values():
                if cookie.name == name:
                    return cookie
        return None

    def header_for(self, url, include_http_only=True, now=0):
        """拼 Cookie 头：按 Path 长度降序、创建时间升序，每个 name 只出现一次。"""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        request_path = parts.path or "/"
        is_https = parts.scheme == "https"
        labels = host.split(".")
        candidates = []
        for index in range(len(labels)):
            bucket = self._by_domain.get(".".join(labels[index:]))
            if bucket is None:
                continue
            for cookie in bucket.matching(request_path):
                if cookie.secure and not is_https:
                    continue
                if cookie.http_only and not include_http_only:
                    continue
                if cookie.expires is not None and cookie.expires <= now:
                    continue
                candidates.append(cookie)
        candidates.sort(key=lambda item: (-len(item.path), item.creation))
        seen = set()
        out = []
        for cookie in candidates:
            if cookie.name in seen:
                continue
            seen.add(cookie.name)
            out.append("%s=%s" % (cookie.name, cookie.value))
        return "; ".join(out)
