"""命令行入口：存 cookie 并打印 Cookie 头。"""

import argparse
import sys

from .jar import CookieError, CookieJar


def build_parser():
    parser = argparse.ArgumentParser(prog="cookie-jar", description="cookie 解析与匹配")
    parser.add_argument("--set", action="append", default=[], help="Set-Cookie 头，可重复")
    parser.add_argument("--set-url", default="http://example.com/", help="存这些 cookie 时用的 URL")
    parser.add_argument("--request", default="", help="读取 Cookie 头时用的 URL")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    jar = CookieJar()
    try:
        for header in args.set:
            jar.store(header, args.set_url)
        if args.request:
            print("header=%s" % jar.header_for(args.request))
    except CookieError as error:
        print("错误：%s" % error, file=sys.stderr)
        return 1
    print("stored=%d" % len(jar.cookies))
    for cookie in sorted(jar.cookies, key=lambda item: item.name):
        print("path=%s:%s domain=%s" % (cookie.name, cookie.path, cookie.domain))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
