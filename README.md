# cookie-jar

HTTP cookie 的解析与匹配（RFC 6265 子集），只用 Python 标准库。

```
python3 -m cookiejar.cli --set 'a=1' --set-url http://example.com/foo/bar --request http://example.com/foo/bar
python3 -m cookiejar.cli --set 'a=1; Domain=example.com' --request http://evil-example.com/x
python3 -m unittest discover -s tests -v
```

## 口径（README 为准）

- **默认 Path 是请求路径的上一级目录**：`--set 'a=1' --set-url http://example.com/foo/bar` 按口径 `path=/foo`，
  现在直接照抄整条路径，给 `path=/foo/bar`。
- **域匹配必须按标签**：`--set 'a=1; Domain=example.com'` 之后向 `http://evil-example.com/x` 发请求，
  按口径不该带 cookie（现在裸后缀匹配，会带上）；`Domain=.com` 这种 supercookie 要拒绝。
- **Cookie 头按 Path 长度降序、再按创建时间升序**：
  `--set 'x=1; Path=/' --set 'y=1; Path=/foo'` 之后请求 `/foo/bar`，按口径是 `header=y=1; x=1`，
  现在按插入顺序给 `header=x=1; y=1`。
- **Max-Age 优先于 Expires**：`Max-Age=0` 或负数要立刻删除该 cookie（现在完全忽略 Max-Age）。
- 其它：只有 Path 是请求路径前缀（或请求路径是 cookie Path 的前缀）时才发送；`Secure` 只在 https 下发送；
  `HttpOnly` 在 `include_http_only=False` 时排除；同 name+domain+path 覆盖并保留最初的创建时间。
- 不变量：同一批操作重复执行结果相同；`header_for` 里同名 cookie 只出现一次。
- 规模：10 万条 cookie、10 万次查询要在 1 秒内完成，内存 O(cookie 数)；不许每次查询都重新解析。

## 现在的行为

- `parse_set_cookie` 的 `path = url.path`：默认 Path 就是整条请求路径。
- `_domain_match` 用 `host.endswith(domain)`：`evil-example.com` 能命中 `example.com`。
- `header_for` 按插入顺序输出，不看 Path 长度，也不检查路径前缀与 Secure。
- `max-age` 分支是空的：`Max-Age=0` 的 cookie 仍然会发出去。

## 计划新增的能力

```
--set 头           Set-Cookie 头，可重复
--set-url URL      存 cookie 时用的请求 URL
--request URL      读取 Cookie 头时用的 URL
```

## 输出

```
header=y=1; x=1
stored=2
path=x:/ domain=example.com
path=y:/foo domain=example.com
```

## 目录

```
cookiejar/jar.py   解析、存储与匹配
cookiejar/cli.py   命令行入口
tests/             unittest 用例
```
