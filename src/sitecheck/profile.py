# -*- coding: utf-8 -*-
"""服务画像：一次检查一个服务的多条链路。

单站检测回答不了"为什么 git clone 能通但 raw 挂了"—— GitHub 的
主站 / API / Raw / 下载走的是不同域名，解析路径也不同。这里把一个
服务拆成若干目标并发检测，再给出聚合结论。

判定沿用各目标自己的 verdict，不引入新的 Layer —— 聚合状态是
ProfileReport.summary，不污染单站判定树。
"""
from __future__ import annotations

import dataclasses
import html
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .exitcodes import EXIT_INCONCLUSIVE, EXIT_OK, EXIT_PARTIAL, exit_code_for_report
from .models import Layer, Report

# (显示名, 域名)
BUILTIN_PROFILES: dict[str, list[tuple[str, str]]] = {
    "github": [
        ("主站", "github.com"),
        ("API", "api.github.com"),
        ("Raw", "raw.githubusercontent.com"),
        ("下载", "codeload.github.com"),
    ],
}


@dataclasses.dataclass
class ProfileTarget:
    label: str
    domain: str
    layer: str
    headline: str
    code: int
    real_ips: list[str] = dataclasses.field(default_factory=list)
    evidence: str = ""
    incomplete: str = ""


@dataclasses.dataclass
class ProfileReport:
    name: str
    time: str
    version: str
    summary: str                  # all_ok / partial / all_failed / inconclusive
    headline: str
    targets: list[ProfileTarget] = dataclasses.field(default_factory=list)
    advice: str = ""


def available_profiles() -> list[str]:
    return sorted(BUILTIN_PROFILES)


def run(name: str,
        analyze_fn: Callable[[str], Report],
        version: str = "") -> ProfileReport:
    """并发检测画像内所有目标。analyze_fn 接收域名返回 Report。"""
    targets_def = BUILTIN_PROFILES.get(name.lower())
    if not targets_def:
        raise ValueError("未知画像：%s（可用：%s）"
                         % (name, "、".join(available_profiles())))

    collected: dict[str, ProfileTarget] = {}
    with ThreadPoolExecutor(max_workers=len(targets_def)) as pool:
        futures = {
            pool.submit(analyze_fn, domain): (label, domain)
            for label, domain in targets_def
        }
        for future in as_completed(futures):
            label, domain = futures[future]
            try:
                report = future.result()
            except Exception as exc:                      # noqa: BLE001
                collected[domain] = ProfileTarget(
                    label=label, domain=domain, layer=Layer.INCONCLUSIVE.value,
                    headline="检测异常：%s" % str(exc)[:60],
                    code=EXIT_INCONCLUSIVE)
                continue
            layer = (report.verdict.layer if report.verdict
                     else Layer.INCONCLUSIVE)
            collected[domain] = ProfileTarget(
                label=label, domain=domain, layer=layer.value,
                headline=(report.verdict.headline if report.verdict else "无结论"),
                code=exit_code_for_report(report),
                real_ips=list(report.real_ips),
                evidence=(report.verdict.evidence if report.verdict else ""),
                incomplete=report.incomplete)

    ordered = [collected[domain] for _label, domain in targets_def]
    return aggregate(name, ordered, version)


def aggregate(name: str, targets: list[ProfileTarget],
              version: str = "") -> ProfileReport:
    """纯函数：把多条目标结论聚合成画像结论。可离线测试。"""
    ok_idx = {i for i, t in enumerate(targets)
              if t.layer == Layer.SUCCESS.value}
    inc_idx = {i for i, t in enumerate(targets)
               if t.layer == Layer.INCONCLUSIVE.value or t.incomplete}
    ok = [t for i, t in enumerate(targets) if i in ok_idx]
    inconclusive = [t for i, t in enumerate(targets) if i in inc_idx]
    failed = [t for i, t in enumerate(targets)
              if i not in ok_idx and i not in inc_idx]

    if not targets:
        summary, headline = "inconclusive", "无法判定：没有检测任何链路"
        advice = "请检查本机出网后重试（sitecheck --profile %s）。" % name
    elif inconclusive:
        labels = "、".join(t.label for t in inconclusive)
        summary = "inconclusive"
        headline = "%s 存在无法判定的链路（%s）" % (name, labels)
        advice = ("有链路证据不足，整体不下可用 / 不可用结论。"
                  "请对上面标注的域名单独执行 sitecheck <域名> 看细节。")
    elif len(ok) == len(targets):
        summary, headline = "all_ok", "%s 的全部 %d 条链路均可直连" % (name, len(targets))
        advice = "无需调整，当前 DNS / hosts 配置对全部链路有效。"
    elif ok:
        broken = "、".join(t.label for t in failed)
        summary = "partial"
        headline = "%s 部分可用：%s 异常" % (name, broken)
        advice = ("只有部分域名受影响，不要全局改 hosts。"
                  "逐条查看下方结论，只对确实需要的一条做处理。")
    else:
        summary, headline = "all_failed", "%s 的 %d 条链路均未连通" % (name, len(targets))
        advice = ("全部链路异常。先看单机单站结论与控制组，"
                  "确认不是本机出网问题后再决定是否调整 hosts。")

    return ProfileReport(name=name, time=datetime.now().strftime("%Y-%m-%d %H:%M"),
                         version=version, summary=summary, headline=headline,
                         targets=targets, advice=advice)


def exit_code_for_profile(profile: ProfileReport) -> int:
    if profile.summary == "all_ok":
        return EXIT_OK
    if profile.summary == "partial":
        return EXIT_PARTIAL
    if profile.summary == "inconclusive":
        return EXIT_INCONCLUSIVE
    failed = [t for t in profile.targets if t.code != EXIT_OK]
    return min((t.code for t in failed), default=EXIT_INCONCLUSIVE)


def render_text(profile: ProfileReport) -> str:
    lines = [
        "# 服务画像：%s" % profile.name,
        "",
        "**%s**" % profile.headline,
        "",
        "| 链路 | 域名 | 结论 | 阻断点 | 退出码 | 真实 IP |",
        "|---|---|---|---|---|---|",
    ]
    for target in profile.targets:
        lines.append("| %s | %s | %s | `%s` | %d | %s |" % (
            target.label, target.domain, target.headline, target.layer,
            target.code, "、".join(target.real_ips[:3]) or "-"))
    lines += ["", "**建议**：%s" % profile.advice, "",
              "检测时间：%s　|　工具版本 v%s"
              % (profile.time, profile.version or "-")]
    return "\n".join(lines)


def render_json(profile: ProfileReport, indent: int = 2) -> str:
    return json.dumps(dataclasses.asdict(profile), ensure_ascii=False,
                      indent=indent)


def render_html(profile: ProfileReport) -> str:
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td>"
        "<td>%d</td><td>%s</td></tr>" % (
            html.escape(t.label), html.escape(t.domain),
            html.escape(t.headline), html.escape(t.layer), t.code,
            html.escape("、".join(t.real_ips[:3]) or "-"))
        for t in profile.targets
    )
    return (
        "<div style='font-family:\"Microsoft YaHei UI\",sans-serif;"
        "font-size:10pt;color:#1a1d21;'>"
        "<h2 style='font-size:14pt;'>服务画像：%s</h2>"
        "<p><b>%s</b></p>"
        "<table cellspacing='0' cellpadding='5' width='100%%' "
        "style='border-collapse:collapse;font-size:9pt;'>"
        "<tr style='background:#f0f2f5;'><th align='left'>链路</th>"
        "<th align='left'>域名</th><th align='left'>结论</th>"
        "<th align='left'>阻断点</th><th align='left'>码</th>"
        "<th align='left'>真实 IP</th></tr>%s</table>"
        "<p><b>建议：</b>%s</p>"
        "<p style='color:#9aa2ac;font-size:8pt;'>%s | v%s</p></div>"
        % (html.escape(profile.name), html.escape(profile.headline), rows,
           html.escape(profile.advice), html.escape(profile.time),
           html.escape(profile.version or "-"))
    )
