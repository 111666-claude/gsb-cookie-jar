"""HTTP cookie 的解析与匹配（RFC 6265 子集），只用标准库。

口径（见 README）：
- 默认 Path 取请求路径的上一级目录。
- 域匹配按标签，host 等于 Domain 或以 .Domain 结尾；单标签 Domain 拒绝。
- 发送要求路径互为前缀；Secure 只在 https 下发送；HttpOnly 可排除。
- Cookie 头按 Path 长度降序、创建时间升序，同名只出现一次。
- Max-Age 优先于 Expires；Max-Age <= 0 立刻删除；过期按传入 now 判断。
"""

import re
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit


class CookieError(ValueError):
    """Set-Cookie 不合法，message 指出出错的属性。"""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class Cookie:
    """一条 cookie。

    expires 为到期时刻（与传入的 now 同一时间轴）；None 表示会话 cookie。
    host_only=True 时只有 host 精确等于 domain 才发送。
    """

    def __init__(self, name, value, domain, path, secure=False, http_only=False,
                 host_only=False, expires=None, creation=0, seq=0):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.secure = secure
        self.http_only = http_only
        self.host_only = host_only
        self.expires = expires
        self.creation = creation
        self.seq = seq


_MAX_AGE_RE = re.compile(r"-?\d+$")


def default_path(request_path):
    """默认 Path：请求路径的上一级目录。

    /foo/bar -> /foo，/foo -> /，不以 / 开头或在根上 -> /。
    """
    if not request_path or not request_path.startswith("/"):
        return "/"
    slash = request_path.rfind("/")
    if slash <= 0:
        return "/"
    return request_path[:slash]


def _normalize_domain(raw_domain):
    """规范化 Domain 属性，并拒绝不含点的域（如 .com 这种 supercookie）。"""
    domain = raw_domain.strip().lstrip(".").lower()
    if not domain:
        raise CookieError("Domain 属性非法：域名为空")
    if "." not in domain:
        raise CookieError("Domain 属性非法：%s 是不含点的 public suffix" % domain)
    return domain


def _parse_expiry(attributes, now):
    """返回到期时刻；Max-Age 优先于 Expires；都没有则 None（会话 cookie）。"""
    if "max-age" in attributes:
        raw = attributes["max-age"]
        if not _MAX_AGE_RE.match(raw):
            raise CookieError("Max-Age 属性非法：%r 不是整数" % raw)
        delta = int(raw)
        if delta <= 0:
            return now
        return now + delta
    if "expires" in attributes:
        raw = attributes["expires"]
        if not raw:
            raise CookieError("Expires 属性非法：日期为空")
        try:
            return parsedate_to_datetime(raw).timestamp()
        except (TypeError, ValueError, IndexError):
            raise CookieError("Expires 属性非法：无法解析 %r" % raw)
    return None


def parse_set_cookie(header, request_url, now=0):
    """解析 Set-Cookie；Max-Age<=0 等落库删除由 CookieJar.store 处理。"""
    parts = header.split(";")
    first = parts[0].strip()
    if "=" not in first:
        raise CookieError("缺少 name=value")
    name, _, value = first.partition("=")
    name = name.strip()
    if not name:
        raise CookieError("cookie 名字为空")

    attributes = {}
    for part in parts[1:]:
        key, _, raw = part.partition("=")
        attributes[key.strip().lower()] = raw.strip()

    url = urlsplit(request_url)
    host = (url.hostname or "").lower()
    path = default_path(url.path)

    host_only = "domain" not in attributes
    if host_only:
        domain = host
    else:
        domain = _normalize_domain(attributes["domain"])

    if "path" in attributes and attributes["path"].startswith("/"):
        path = attributes["path"]

    expires = _parse_expiry(attributes, now)

    return Cookie(
        name=name, value=value, domain=domain, path=path,
        secure="secure" in attributes,
        http_only="httponly" in attributes,
        host_only=host_only, expires=expires, creation=now)


def _domain_match(host, cookie):
    """host 等于 Domain，或（非 host-only 时）host 以 .Domain 结尾（按标签）。"""
    if host == cookie.domain:
        return True
    if cookie.host_only:
        return False
    return host.endswith("." + cookie.domain)


def _path_match(request_path, cookie_path):
    """cookie 的 Path 与请求路径互为前缀（README 口径）。"""
    return request_path.startswith(cookie_path) or cookie_path.startswith(request_path)


class CookieJar:
    """cookie 存储。

    _by_key：(name, domain, path) -> Cookie，负责覆盖与 O(1) 删除。
    _by_domain：domain -> {(name, domain, path)}，查询时只扫命中的域。
    """

    def __init__(self):
        self._by_key = {}
        self._by_domain = {}
        self._counter = 0

    @property
    def cookies(self):
        return list(self._by_key.values())

    def store(self, header, request_url, now=None):
        """存一条 cookie。

        同 name+domain+path 覆盖并沿用最早的创建时间；Max-Age<=0 或已过期
        则删除同名 cookie；不同 Path 的同名 cookie 共存。
        """
        if now is None:
            now = time.time()
        cookie = parse_set_cookie(header, request_url, now)
        key = (cookie.name, cookie.domain, cookie.path)
        existing = self._by_key.get(key)
        if existing is not None:
            cookie.creation = existing.creation
            cookie.seq = existing.seq
        else:
            cookie.seq = self._counter
            self._counter += 1

        if cookie.expires is not None and cookie.expires <= now:
            self._delete(key, cookie.domain)
            return cookie

        self._by_key[key] = cookie
        self._by_domain.setdefault(cookie.domain, set()).add(key)
        return cookie

    def _delete(self, key, domain):
        self._by_key.pop(key, None)
        bucket = self._by_domain.get(domain)
        if bucket is not None:
            bucket.discard(key)
            if not bucket:
                del self._by_domain[domain]

    def get(self, name):
        for cookie in self._by_key.values():
            if cookie.name == name:
                return cookie
        return None

    def header_for(self, url, include_http_only=True, now=None):
        """拼 Cookie 头。

        按 Path 长度降序、创建时间（及稳定的入库序号）升序；同名只保留首个。
        """
        if now is None:
            now = time.time()
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        request_path = parts.path or "/"
        is_https = parts.scheme.lower() == "https"

        matched = []
        current = host
        while current:
            bucket = self._by_domain.get(current)
            if bucket:
                for key in bucket:
                    cookie = self._by_key.get(key)
                    if cookie is None:
                        continue
                    if cookie.expires is not None and cookie.expires <= now:
                        continue
                    if not _domain_match(host, cookie):
                        continue
                    if not _path_match(request_path, cookie.path):
                        continue
                    if cookie.secure and not is_https:
                        continue
                    if cookie.http_only and not include_http_only:
                        continue
                    matched.append(cookie)
            dot = current.find(".")
            if dot < 0:
                break
            current = current[dot + 1:]

        matched.sort(key=lambda item: (-len(item.path), item.creation, item.seq))
        out = []
        seen_names = set()
        for cookie in matched:
            if cookie.name in seen_names:
                continue
            seen_names.add(cookie.name)
            out.append("%s=%s" % (cookie.name, cookie.value))
        return "; ".join(out)
