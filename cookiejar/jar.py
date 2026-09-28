"""HTTP cookie 的解析与匹配（RFC 6265 子集），只用标准库。

缺陷：默认 Path 用整条请求路径、域匹配用裸后缀、Cookie 头只按插入顺序、
Max-Age 被忽略、也不看 Secure 与路径前缀。
"""

from urllib.parse import urlsplit


class CookieError(ValueError):
    """Set-Cookie 不合法。缺陷：不带出错字段。"""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class Cookie:
    """一条 cookie。"""

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


def parse_set_cookie(header, request_url, now=0):
    """解析 Set-Cookie。缺陷：默认 Path 取整条请求路径，Max-Age 直接丢掉。"""
    parts = [part.strip() for part in header.split(";")]
    if not parts or "=" not in parts[0]:
        raise CookieError("缺少 name=value")
    name, _, value = parts[0].partition("=")
    name = name.strip()
    if not name:
        raise CookieError("cookie 名字为空")
    url = urlsplit(request_url)
    host = (url.hostname or "").lower()
    path = url.path  # 缺陷：没有退到最后一个 / 之前
    attributes = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, raw = part.partition("=")
        attributes[key.strip().lower()] = raw.strip()
    domain = host
    if "domain" in attributes:
        domain = attributes["domain"].lstrip(".").lower()  # 缺陷：不校验 supercookie
    if "path" in attributes and attributes["path"].startswith("/"):
        path = attributes["path"]
    expires = None
    if "max-age" in attributes:
        pass  # 缺陷：Max-Age 被忽略
    elif "expires" in attributes:
        expires = attributes["expires"]
    return Cookie(name=name, value=value, domain=domain, path=path,
                  secure="secure" in attributes, http_only="httponly" in attributes,
                  expires=expires, creation=now)


def _domain_match(host, domain):
    """缺陷：裸后缀匹配，evil-example.com 也会命中 example.com。"""
    if not domain:
        return True
    return host == domain or host.endswith(domain)


class CookieJar:
    """cookie 存储。"""

    def __init__(self):
        self.cookies = []

    def store(self, header, request_url, now=0):
        """存一条 cookie；同 name+domain+path 覆盖并保留最初的创建时间。"""
        cookie = parse_set_cookie(header, request_url, now)
        for index, existing in enumerate(self.cookies):
            if (existing.name == cookie.name and existing.domain == cookie.domain
                    and existing.path == cookie.path):
                cookie.creation = existing.creation
                self.cookies[index] = cookie
                return cookie
        self.cookies.append(cookie)
        return cookie

    def get(self, name):
        for cookie in self.cookies:
            if cookie.name == name:
                return cookie
        return None

    def header_for(self, url, include_http_only=True):
        """拼 Cookie 头。缺陷：只按插入顺序，也不看 Secure 与路径前缀。"""
        host = (urlsplit(url).hostname or "").lower()
        out = []
        for cookie in self.cookies:
            if not _domain_match(host, cookie.domain):
                continue
            if cookie.http_only and not include_http_only:
                continue
            out.append("%s=%s" % (cookie.name, cookie.value))
        return "; ".join(out)
