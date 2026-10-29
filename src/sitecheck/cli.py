# -*- coding: utf-8 -*-
"""命令行入口。

用法（保持 v1.0 的调用方式兼容）：
    sitecheck github.com
    sitecheck github.com --ip 1.2.3.4 --report out.md
    sitecheck github.com --apply-hosts
    sitecheck check github.com --json out.json --html out.html
    sitecheck hosts --list | --audit | --backups | --restore [n]
    sitecheck dns-bench [--json out.json]
    sitecheck --version
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, dnsbench, orchestrator
from . import audit as auditmod
from . import hosts as hostsmod
from . import render as rendermod

KNOWN_COMMANDS = {"check", "hosts", "dns-bench", "version", "help"}


# ---------------------------------------------------------------- 控制台

def _enable_ansi() -> bool:
    """Windows 控制台默认不解析 ANSI，需要显式打开 VT 处理。"""
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel = ctypes.windll.kernel32
        handle = kernel.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class Style:
    def __init__(self, enabled: bool):
        self.on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return "\033[%sm%s\033[0m" % (code, text) if self.on else text

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def blue(self, text: str) -> str:
        return self._wrap("36", text)


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def _make_progress(style: Style, quiet: bool):
    state = {"stage": ""}

    def progress(stage: str, message: str, done: int, total: int) -> None:
        if quiet:
            return
        if stage != state["stage"]:
            state["stage"] = stage
            sys.stderr.write("\n%s\n" % style.blue("▸ " + stage))
        if total:
            sys.stderr.write("  %s %s\n" % (style.dim("[%d/%d]" % (done, total)), message))
        else:
            sys.stderr.write("  %s\n" % message)
        sys.stderr.flush()

    return progress


# ---------------------------------------------------------------- check

def cmd_check(args: argparse.Namespace) -> int:
    style = Style(_enable_ansi())
    progress = _make_progress(style, args.quiet)

    if not args.domain:
        print(style.red("缺少域名。用法：sitecheck <域名>"))
        return 2

    domain = orchestrator.normalize_domain(args.domain)
    if not domain or "." not in domain:
        print(style.red("域名格式不正确：%r" % args.domain))
        return 2

    if not args.quiet:
        print(style.bold("\n检测 %s ..." % domain))

    report = orchestrator.analyze(domain, args.ip, progress,
                                  timeout=args.timeout, version=__version__,
                                  total_timeout=args.deadline)
    if not args.quiet:
        print()

    text = rendermod.render_markdown(report)
    print(text)

    # 导出
    _write_outputs(report, args, style)

    if args.apply_hosts:
        return _apply_hosts_flow(report, args, style)

    return 0 if report.verdict and report.verdict.layer.value == "SUCCESS" else 1


def _write_outputs(report, args: argparse.Namespace, style: Style) -> None:
    if args.report:
        _write_file(args.report, rendermod.render_markdown(report),
                    "Markdown 报告", style)
    if args.json:
        _write_file(args.json, rendermod.render_json(report), "JSON 报告", style)
    if args.html:
        html = ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
                "<title>sitecheck - %s</title></head><body style='margin:24px;"
                "background:#ffffff;'>%s</body></html>"
                % (report.domain, rendermod.render_html(report)))
        _write_file(args.html, html, "HTML 报告", style)


def _write_file(path: str, content: str, label: str, style: Style) -> None:
    try:
        Path(path).write_text(content, encoding="utf-8")
        print(style.dim("\n%s已写入 %s" % (label, Path(path).resolve())))
    except OSError as exc:
        print(style.red("\n%s写入失败：%s" % (label, exc)))


def _apply_hosts_flow(report, args: argparse.Namespace, style: Style) -> int:
    verdict = report.verdict
    if not verdict:
        print(style.red("\n没有可用结论，已中止，hosts 未改动。"))
        return 1

    ips = args.ip or verdict.hosts_entry_ips or report.real_ips
    if not ips:
        print(style.red("\n没有可用于写入的真实 IP（候选均未通过证书校验）。"
                        "已中止，hosts 未改动。"))
        return 1

    domain = report.domain
    try:
        ips = hostsmod.validate_ips(list(ips))
    except hostsmod.HostsError as exc:
        print(style.red("\n%s" % exc))
        return 1

    removed, added = hostsmod.plan(domain, ips)
    print(style.bold("\n将对 %s 做如下改动：" % hostsmod.HOSTS_PATH))
    for line_no, text in removed:
        print("  替换第 %-4d 行  %s" % (line_no, text))
    for line in added:
        print("  新增            %s" % line)
    print()

    try:
        message, backup = hostsmod.apply(domain, ips)
    except hostsmod.HostsError as exc:
        if str(exc) == "NEED_ADMIN":
            print(style.yellow("写入 hosts 需要管理员权限。"))
            print("请右键以管理员身份运行终端后重试，例如：")
            print("  %s" % style.dim("sitecheck %s --apply-hosts" % domain))
            return 1
        print(style.red("写入失败：%s" % exc))
        return 1

    ok, detail = hostsmod.flush_dns()
    print(style.green("写入成功：%s" % message))
    print("DNS 缓存刷新：%s" % ("成功" if ok else "失败 -> %s" % detail))
    if backup:
        print("备份文件：%s" % backup)
    print(style.dim("\n提示：建议重新检测一次确认效果；如需回滚：sitecheck hosts --restore"))
    return 0


# ---------------------------------------------------------------- hosts 写入

def _hosts_write(domain: str, ips: list[str], style: Style) -> int:
    """写入 hosts。供 CLI 与 GUI 提权后调用。"""
    domain = orchestrator.normalize_domain(domain)
    if not domain:
        print(style.red("域名无效"))
        return 2
    try:
        ips = hostsmod.validate_ips(list(ips))
    except hostsmod.HostsError as exc:
        print(style.red(str(exc)))
        return 1

    removed, added = hostsmod.plan(domain, ips)
    print(style.bold("将对 %s 做如下改动：" % hostsmod.HOSTS_PATH))
    for line_no, text in removed:
        print("  替换第 %-4d 行  %s" % (line_no, text))
    for line in added:
        print("  新增            %s" % line)

    try:
        message, backup = hostsmod.apply(domain, ips)
    except hostsmod.HostsError as exc:
        if str(exc) == "NEED_ADMIN":
            print(style.yellow("写入 hosts 需要管理员权限，请以管理员身份重新执行。"))
            return 1
        print(style.red("写入失败：%s" % exc))
        return 1

    ok, detail = hostsmod.flush_dns()
    print(style.green("写入成功：%s" % message))
    print("DNS 缓存刷新：%s" % ("成功" if ok else "失败 -> %s" % detail))
    if backup:
        print("备份文件：%s" % backup)
    return 0


# ---------------------------------------------------------------- hosts

def cmd_hosts(args: argparse.Namespace) -> int:
    style = Style(_enable_ansi())

    if args.write:
        return _hosts_write(args.write, args.ip, style)

    if args.restore is not None:
        backups = hostsmod.list_backups()
        if not backups:
            print(style.yellow("没有可用的备份。"))
            return 1
        index = args.restore
        if index >= len(backups):
            print(style.red("备份序号超出范围（共 %d 个）。" % len(backups)))
            return 2
        target = backups[index]
        try:
            message = hostsmod.restore(target)
        except hostsmod.HostsError as exc:
            if str(exc) == "NEED_ADMIN":
                print(style.yellow("还原 hosts 需要管理员权限，请以管理员身份重试。"))
                return 1
            print(style.red(str(exc)))
            return 1
        print(style.green(message))
        return 0

    if args.backups:
        backups = hostsmod.list_backups()
        if not backups:
            print("没有备份。")
            return 0
        print("可用备份（序号从 0 开始，越靠前越新）：")
        for index, path in enumerate(backups):
            print("  [%d] %s" % (index, path))
        print("\n还原：sitecheck hosts --restore 0")
        return 0

    if args.audit:
        progress = _make_progress(style, quiet=False)
        rows = auditmod.run(timeout=args.timeout, progress=progress)
        print()
        print(auditmod.render(rows))
        return 0

    # 默认：列出条目
    entries = hostsmod.parse_entries()
    if not entries:
        print("hosts 文件里没有任何映射条目。")
        return 0
    hosts_count = len({e["host"] for e in entries})
    print("hosts 共 %d 条映射 / %d 个域名\n" % (len(entries), hosts_count))
    print("%-6s %-17s %s" % ("行", "IP", "域名"))
    print("-" * 70)
    for entry in entries:
        print("%-6d %-17s %s" % (entry["line"], entry["ip"], entry["host"]))
    return 0


# ---------------------------------------------------------------- dns-bench

def cmd_dns_bench(args: argparse.Namespace) -> int:
    style = Style(_enable_ansi())
    print("开始 DNS 基准测试（约需 20~40 秒）...\n")
    rows = dnsbench.run(timeout=args.timeout)
    print(dnsbench.render(rows))
    if args.json:
        try:
            Path(args.json).write_text(dnsbench.to_json(rows), encoding="utf-8")
            print(style.dim("\nJSON 已写入 %s" % Path(args.json).resolve()))
        except OSError as exc:
            print(style.red("\nJSON 写入失败：%s" % exc))
            return 1
    return 0


# ---------------------------------------------------------------- 解析

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sitecheck",
        description="网站直连检测工具：逐层定位为什么打不开，"
                    "只在 hosts 真能解决时才建议改 hosts。",
        epilog="不带子命令时等价于 sitecheck check <域名>。",
    )
    parser.add_argument("--version", action="version",
                        version="sitecheck %s" % __version__)

    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="检测单个域名（默认行为）")
    check.add_argument("domain", nargs="?", help="要检测的域名")
    check.add_argument("--ip", action="append", default=[],
                       help="手动指定候选 IP，可重复")
    check.add_argument("--report", help="输出 Markdown 报告到指定路径")
    check.add_argument("--json", help="输出 JSON 报告到指定路径")
    check.add_argument("--html", help="输出 HTML 报告到指定路径")
    check.add_argument("--apply-hosts", action="store_true",
                       help="把确认可用的真实 IP 写入 hosts 并刷新缓存（需管理员）")
    check.add_argument("--timeout", type=float, default=8.0,
                       help="单层探测超时秒数（默认 8）")
    check.add_argument("--deadline", type=float,
                       default=orchestrator.DEFAULT_TOTAL_TIMEOUT,
                       help="整体超时秒数（默认 45，0 表示不限）")
    check.add_argument("--quiet", action="store_true", help="不输出进度信息")
    check.set_defaults(func=cmd_check)

    hosts_cmd = sub.add_parser("hosts", help="hosts 文件体检与备份管理")
    hosts_cmd.add_argument("--audit", action="store_true",
                           help="逐条探测 hosts 里的映射是否可用")
    hosts_cmd.add_argument("--write", metavar="DOMAIN",
                           help="把指定 IP 写入 hosts（需管理员权限）")
    hosts_cmd.add_argument("--ip", action="append", default=[],
                           help="配合 --write 使用的 IP，可重复")
    hosts_cmd.add_argument("--backups", action="store_true", help="列出备份")
    hosts_cmd.add_argument("--restore", type=int, nargs="?", const=0,
                           metavar="N", help="还原第 N 个备份（默认 0，即最新）")
    hosts_cmd.add_argument("--timeout", type=float, default=6.0)
    hosts_cmd.set_defaults(func=cmd_hosts)

    bench = sub.add_parser("dns-bench", help="公共 DNS 延迟与防污染基准测试")
    bench.add_argument("--json", help="输出 JSON 到指定路径")
    bench.add_argument("--timeout", type=float, default=3.0)
    bench.set_defaults(func=cmd_dns_bench)

    version_cmd = sub.add_parser("version", help="显示版本")
    version_cmd.set_defaults(func=lambda _a: (print("sitecheck %s" % __version__), 0)[1])

    return parser


def main(argv: list[str] | None = None) -> int:
    _reconfigure_streams()
    argv = list(sys.argv[1:] if argv is None else argv)

    # 兼容 v1.0 的用法：第一个参数是域名时按 check 处理
    if argv and argv[0] not in KNOWN_COMMANDS and not argv[0].startswith("-"):
        argv = ["check"] + argv
    elif not argv:
        argv = ["check"]

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
