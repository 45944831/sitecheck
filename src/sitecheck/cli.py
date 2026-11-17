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
from . import family as familymod
from . import familycheck as familycheckmod
from . import hosts as hostsmod
from . import profile as profilemod
from . import render as rendermod
from . import watch as watchmod
from .exitcodes import EXIT_HELP, EXIT_IO, exit_code_for_report

KNOWN_COMMANDS = {"check", "hosts", "dns-bench", "version", "help", "family"}
# 顶层直接写 check 专属选项时（如 `sitecheck --profile github`），
# argparse 会把它当成未知命令。这里显式转发到 check 子命令。
CHECK_ONLY_FLAGS = {
    "--profile", "--watch", "--interval", "--count", "--confirm",
    "--watch-json", "--ip", "--report", "--json", "--html",
    "--apply-hosts", "--timeout", "--deadline", "--quiet",
}


# ---------------------------------------------------------------- 控制台

def _stream(name: str):
    """安全取标准流。

    windowed 打包（GUI 提权重启的 CLI 进程）里 sys.stdout/stderr 可能是
    None —— 没有控制台可挂时 _attach_console 会失败。print() 对 None 是
    安全的，但显式的 .isatty()/.write()/flush() 会抛 AttributeError。
    """
    return getattr(sys, name, None)


def _enable_ansi() -> bool:
    """Windows 控制台默认不解析 ANSI，需要显式打开 VT 处理。"""
    stdout = _stream("stdout")
    if stdout is None or not hasattr(stdout, "isatty") or not stdout.isatty():
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
    for name in ("stdout", "stderr"):
        stream = _stream(name)
        if stream is None:
            continue
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def _make_progress(style: Style, quiet: bool):
    state = {"stage": ""}

    def progress(stage: str, message: str, done: int, total: int) -> None:
        if quiet:
            return
        err = _stream("stderr")
        if err is None or not hasattr(err, "write"):
            return
        if stage != state["stage"]:
            state["stage"] = stage
            err.write("\n%s\n" % style.blue("▸ " + stage))
        if total:
            err.write("  %s %s\n" % (style.dim("[%d/%d]" % (done, total)), message))
        else:
            err.write("  %s\n" % message)
        try:
            err.flush()
        except Exception:
            pass

    return progress


# ---------------------------------------------------------------- family

def cmd_family(args: argparse.Namespace) -> int:
    """核验一个服务的整族域名，可选批量把可用 IP 写入 hosts。"""
    style = Style(_enable_ansi())
    name = (args.family or "github").lower()
    domains = familymod.domains_for(name)
    if not domains:
        print(style.red("未知服务：%s（可用：%s）"
                        % (name, "、".join(familymod.available_families()))))
        return 2

    def progress(domain: str, done: int, total: int) -> None:
        if not args.quiet:
            print(style.dim("  [%d/%d] %s" % (done, total, domain)))

    if not args.quiet:
        print(style.bold("核验 %s 的 %d 个关联域名 ..."
                         % (familymod.BUILTIN_FAMILIES.get(name, name), len(domains))))
    report = familycheckmod.run(
        name, domains, version=__version__, timeout=args.timeout,
        progress=progress)

    print()
    print(familycheckmod.render_text(report))
    _write_family_outputs(report, args, style)

    if not args.apply_hosts:
        return 0
    return _apply_family_hosts(report, args, style)


def _write_family_outputs(report, args: argparse.Namespace, style: Style) -> None:
    if getattr(args, "json", ""):
        _write_file(args.json, familycheckmod.render_json(report),
                    "JSON 报告", style)
    if getattr(args, "report", ""):
        _write_file(args.report, familycheckmod.render_text(report),
                    "Markdown 报告", style)
    if getattr(args, "html", ""):
        html = ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
                "<title>sitecheck family - %s</title></head>"
                "<body style='margin:24px;background:#ffffff;'>%s</body></html>"
                % (report.name, familycheckmod.render_html(report)))
        _write_file(args.html, html, "HTML 报告", style)


def _apply_family_hosts(report, args: argparse.Namespace, style: Style) -> int:
    """把检测到可修复的域名批量写入 hosts。先展示完整计划再执行。"""
    targets = [c for c in report.fixable if c.working_ips]
    if not targets:
        print(style.yellow("\n没有需要修复且已验证可用 IP 的域名，hosts 未改动。"))
        return 0

    # 每个域名只取第一个可用 IP（延迟最低的在前）
    plan = [(c.domain, c.working_ips[0]) for c in targets]
    try:
        plan = [(d, hostsmod.validate_ips([ip])[0]) for d, ip in plan]
    except hostsmod.HostsError as exc:
        print(style.red("\nIP 校验失败：%s" % exc))
        return 1

    print(style.bold("\n将对 %s 批量写入 %d 个域名：" % (hostsmod.HOSTS_PATH, len(plan))))
    for domain, ip in plan:
        removed, added = hostsmod.plan(domain, [ip])
        for line_no, text in removed:
            print("  %-45s 替换第 %d 行 %s" % (domain, line_no, text))
        for line in added:
            print("  %-45s 新增 %s" % (domain, line))
    print(style.dim("\n  每个域名写入前都会单独备份；写入后统一刷新 DNS 缓存。"))
    print(style.dim("  第三方 CDN 域名已自动排除，不会被写入。"))

    if not args.yes and not _confirm(style):
        print(style.yellow("已取消，hosts 未改动。"))
        return 0

    written, failed = 0, 0
    for domain, ip in plan:
        try:
            _msg, _bak = hostsmod.apply(domain, [ip])
            written += 1
            print(style.green("  ✓ %s → %s" % (domain, ip)))
        except hostsmod.HostsError as exc:
            failed += 1
            if str(exc) == "NEED_ADMIN":
                print(style.red("  写入 hosts 需要管理员权限，请以管理员身份重试。"))
                print(style.dim("  " + hostsmod.admin_hint("")))
                break
            print(style.red("  ✗ %s：%s" % (domain, exc)))

    if written:
        ok, detail = hostsmod.flush_dns()
        print("\n已写入 %d 个域名，失败 %d 个；DNS 缓存刷新：%s"
              % (written, failed, "成功" if ok else "失败 -> %s" % detail))
    return 0 if failed == 0 else 1


def _confirm(style: Style) -> bool:
    """tty 下逐次确认；无控制台（windowed 提权重启）时默认执行。"""
    stdin = getattr(sys, "stdin", None)
    if stdin is None or not hasattr(stdin, "readline"):
        return True                      # 已在调用前展示过完整计划
    try:
        return input("\n确认写入？[y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, OSError):
        return False


# ---------------------------------------------------------------- check

def cmd_check(args: argparse.Namespace) -> int:
    style = Style(_enable_ansi())

    if getattr(args, "profile", ""):
        return _profile_flow(args, style)

    progress = _make_progress(style, args.quiet)

    if not args.domain:
        print(style.red("缺少域名。用法：sitecheck <域名>"))
        return 2

    domain = orchestrator.normalize_domain(args.domain)
    if not domain or "." not in domain:
        print(style.red("域名格式不正确：%r" % args.domain))
        return 2

    def analyze_once():
        return orchestrator.analyze(domain, args.ip, progress,
                                    timeout=args.timeout, version=__version__,
                                    total_timeout=args.deadline)

    if args.watch:
        if args.apply_hosts:
            print(style.red("--watch 不支持 --apply-hosts：监控模式不会自动改动 hosts。"))
            return 2
        if not args.quiet:
            print(style.bold("\n持续检测 %s（每 %g 秒一次，Ctrl+C 停止）..."
                             % (domain, args.interval)))
        return watchmod.run(domain, analyze_once, interval=args.interval,
                            count=args.count, confirm=args.confirm,
                            json_path=args.watch_json, quiet=args.quiet)

    if not args.quiet:
        print(style.bold("\n检测 %s ..." % domain))

    report = analyze_once()
    if not args.quiet:
        print()

    text = rendermod.render_markdown(report)
    print(text)

    # 导出
    outputs_ok = _write_outputs(report, args, style)

    if args.apply_hosts:
        return _apply_hosts_flow(report, args, style)

    code = exit_code_for_report(report)
    return EXIT_IO if code == 0 and not outputs_ok else code


def _profile_flow(args: argparse.Namespace, style: Style) -> int:
    """--profile NAME：并发检测一个服务的多条链路。"""
    name = args.profile
    available = profilemod.available_profiles()
    if name not in available:
        print(style.red("未知画像：%s（可用：%s）"
                        % (name, "、".join(available))))
        return 2
    if args.apply_hosts:
        print(style.red("--profile 不支持 --apply-hosts：请对具体域名单独执行。"))
        return 2

    def analyze(domain: str):
        return orchestrator.analyze(domain, args.ip, lambda *_a, **_k: None,
                                    timeout=args.timeout, version=__version__,
                                    total_timeout=args.deadline)

    try:
        result = profilemod.run(name, analyze, version=__version__)
    except ValueError as exc:
        print(style.red(str(exc)))
        return 2

    text = profilemod.render_text(result)
    print(text)
    ok = True
    if args.report:
        ok = _write_file(args.report, text, "Markdown 报告", style) and ok
    if args.json:
        ok = _write_file(args.json, profilemod.render_json(result),
                         "JSON 报告", style) and ok
    if args.html:
        page = ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
                "<title>sitecheck - %s</title></head><body style='margin:24px;"
                "background:#ffffff;'>%s</body></html>"
                % (result.name, profilemod.render_html(result)))
        ok = _write_file(args.html, page, "HTML 报告", style) and ok

    code = profilemod.exit_code_for_profile(result)
    return EXIT_IO if code == 0 and not ok else code


def _write_outputs(report, args: argparse.Namespace, style: Style) -> bool:
    ok = True
    if args.report:
        ok = _write_file(args.report, rendermod.render_markdown(report),
                         "Markdown 报告", style) and ok
    if args.json:
        ok = _write_file(args.json, rendermod.render_json(report),
                         "JSON 报告", style) and ok
    if args.html:
        html = ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
                "<title>sitecheck - %s</title></head><body style='margin:24px;"
                "background:#ffffff;'>%s</body></html>"
                % (report.domain, rendermod.render_html(report)))
        ok = _write_file(args.html, html, "HTML 报告", style) and ok
    return ok


def _write_file(path: str, content: str, label: str, style: Style) -> bool:
    try:
        Path(path).write_text(content, encoding="utf-8")
        print(style.dim("\n%s已写入 %s" % (label, Path(path).resolve())))
        return True
    except OSError as exc:
        print(style.red("\n%s写入失败：%s" % (label, exc)))
        return False


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
            print(style.dim(hostsmod.admin_hint("%s --apply-hosts" % domain)))
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
            print(style.yellow("写入 hosts 需要管理员权限。%s"
                               % hostsmod.admin_hint("%s --write --ip <IP>" % domain)))
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
                print(style.yellow("还原 hosts 需要管理员权限。%s"
                                   % hostsmod.admin_hint("hosts --restore 0")))
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
        epilog="不带子命令时等价于 sitecheck check <域名>。\n" + EXIT_HELP,
    )
    parser.add_argument("--version", action="version",
                        version="sitecheck %s" % __version__)

    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="检测单个域名（默认行为）")
    check.add_argument("domain", nargs="?", help="要检测的域名")
    check.add_argument("--profile", metavar="NAME",
                       help="服务画像：一次检查多个域名（如 github）")
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
    check.add_argument("--watch", action="store_true",
                       help="持续检测并记录状态变化时间线（不自动改 hosts）")
    check.add_argument("--interval", type=float, default=watchmod.DEFAULT_INTERVAL,
                       help="--watch 的检测间隔秒数（默认 60）")
    check.add_argument("--count", type=int, default=0,
                       help="--watch 的检测次数，0 表示不限（默认 0）")
    check.add_argument("--confirm", type=int, default=watchmod.DEFAULT_CONFIRM,
                       help="--watch 连续几次同状态才确认变化，过滤抖动（默认 2）")
    check.add_argument("--watch-json", default="", metavar="PATH",
                       help="--watch 结束时把事件时间线写入 JSON")
    check.add_argument("--quiet", action="store_true", help="不输出进度信息")
    check.set_defaults(func=cmd_check)

    fam = sub.add_parser("family", help="核验一个服务的整族关联域名（GitHub 图片/下载/API 等）")
    fam.add_argument("family", nargs="?", default="github",
                     help="服务名，默认 github")
    fam.add_argument("--apply-hosts", action="store_true",
                     help="把检测到可修复的域名批量写入 hosts（需管理员）")
    fam.add_argument("--yes", action="store_true", help="跳过写入前的交互确认")
    fam.add_argument("--json", help="输出 JSON 报告到指定路径")
    fam.add_argument("--report", help="输出 Markdown 报告到指定路径")
    fam.add_argument("--html", help="输出 HTML 报告到指定路径")
    fam.add_argument("--timeout", type=float, default=4.0,
                     help="单域名探测超时秒数（默认 4）")
    fam.add_argument("--quiet", action="store_true", help="不输出进度信息")
    fam.set_defaults(func=cmd_family)

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
    if argv and argv[0] in CHECK_ONLY_FLAGS:
        argv = ["check"] + argv
    elif argv and argv[0] not in KNOWN_COMMANDS and not argv[0].startswith("-"):
        argv = ["check"] + argv
    elif not argv:
        argv = ["check"]

    # 顶层 --family 别名：`sitecheck --family github` → `sitecheck family github`
    if argv and argv[0] == "--family":
        argv = ["family"] + argv[1:]

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
