# -*- coding: utf-8 -*-
"""服务域名族：一次发现并检测一个服务的所有关联域名。

跟 profile.py 的区别：
    profile 是"几条已知链路逐个完整 analyze"，域名少、每条都跑完整判定树；
    family 是"一个服务的一整族域名轻量核验"，域名多、只验证候选 IP 的真身，
    避免 31 个域名各跑 9 次 DNS + 控制组把网络打爆。

清单来源（2026-11-17 核对，双重证据）：
    1. GitHub520 hosts 源 https://raw.hellogithub.com/hosts —— 社区维护的
       github 关联域名全集（40 条），是"有哪些关联域名"的事实来源；
    2. GitHub 官方 meta API https://api.github.com/meta 的 web/api/git/pages
       段 —— 用 ipaddress 反查每个域名当前 IP，判断它是否落在 GitHub
       自有段。落在自有段的才适合固定 hosts；第三方 CDN（S3/Fastly/
       Azure）的域名写 hosts 反而容易失效或变慢，只检测不写入。

注意：meta API 明确说明它不是穷举清单，且 IP 会变。所以这里不把候选 IP
写死进代码，只固化"域名 + 用途分组 + 是否适合固定"，IP 一律运行时从远程
情报源现取并做证书校验。
"""
from __future__ import annotations

import dataclasses

# (域名, 中文标签, 用途分组, 是否适合写入 hosts)
# fixable=False 的都是第三方 CDN，仅检测展示，不参与批量写入。
_GITHUB_DOMAINS: list[tuple[str, str, str, bool]] = [
    # --- 核心：git / 网页主链路 ---
    ("github.com", "主站", "核心", True),
    ("api.github.com", "API", "核心", True),
    ("codeload.github.com", "代码下载", "核心", True),
    ("gist.github.com", "Gist", "核心", True),
    # --- 代码与资源拉取 ---
    ("raw.githubusercontent.com", "Raw 文件", "拉取", True),
    ("objects.githubusercontent.com", "Git 对象", "拉取", True),
    ("camo.githubusercontent.com", "图片代理", "拉取", True),
    ("media.githubusercontent.com", "媒体资源", "拉取", True),
    ("cloud.githubusercontent.com", "云资源", "拉取", True),
    ("desktop.githubusercontent.com", "桌面端资源", "拉取", True),
    # --- 图片 / 静态资源 ---
    ("github.githubassets.com", "静态资源", "图片", True),
    ("avatars.githubusercontent.com", "头像", "图片", True),
    ("avatars0.githubusercontent.com", "头像 0", "图片", True),
    ("avatars1.githubusercontent.com", "头像 1", "图片", True),
    ("avatars2.githubusercontent.com", "头像 2", "图片", True),
    ("avatars3.githubusercontent.com", "头像 3", "图片", True),
    ("avatars4.githubusercontent.com", "头像 4", "图片", True),
    ("avatars5.githubusercontent.com", "头像 5", "图片", True),
    ("user-images.githubusercontent.com", "用户图片", "图片", True),
    ("private-user-images.githubusercontent.com", "私有图片", "图片", True),
    ("favicons.githubusercontent.com", "站点图标", "图片", True),
    # --- 辅助站点 ---
    ("alive.github.com", "存活检测", "辅助", True),
    ("live.github.com", "实时", "辅助", True),
    ("central.github.com", "中心", "辅助", True),
    ("collector.github.com", "遥测", "辅助", True),
    ("education.github.com", "教育", "辅助", True),
    ("github.community", "社区", "辅助", True),
    ("githubstatus.com", "状态页", "辅助", True),
    ("github.io", "Pages", "辅助", True),
    ("api.individual.githubcopilot.com", "Copilot", "辅助", True),
    # --- 第三方 CDN：只检测，不写 hosts ---
    ("github.blog", "官方博客", "CDN", False),
    ("github.global.ssl.fastly.net", "Fastly", "CDN", False),
    ("github.map.fastly.net", "Fastly 映射", "CDN", False),
    ("pipelines.actions.githubusercontent.com", "Actions", "CDN", False),
    ("github-cloud.s3.amazonaws.com", "云存储 S3", "CDN", False),
    ("github-com.s3.amazonaws.com", "S3", "CDN", False),
    ("github-production-release-asset-2e65be.s3.amazonaws.com", "发布资产 S3", "CDN", False),
    ("github-production-repository-file-5c1aeb.s3.amazonaws.com", "仓库文件 S3", "CDN", False),
    ("github-production-user-asset-6210df.s3.amazonaws.com", "用户资产 S3", "CDN", False),
    ("vscode.dev", "VS Code Web", "CDN", False),
]

BUILTIN_FAMILIES: dict[str, str] = {"github": "GitHub 全家桶"}


@dataclasses.dataclass(frozen=True)
class FamilyDomain:
    domain: str
    label: str
    group: str
    fixable: bool


def domains_for(name: str) -> list[FamilyDomain]:
    """取某个服务的域名族。未知名返回空列表。"""
    if name.lower() != "github":
        return []
    return [FamilyDomain(d, label, group, fixable)
            for d, label, group, fixable in _GITHUB_DOMAINS]


def available_families() -> list[str]:
    return sorted(BUILTIN_FAMILIES)


def groups_of(name: str) -> list[str]:
    """按清单出现顺序返回分组名（供报告分组展示）。"""
    seen: list[str] = []
    for d in domains_for(name):
        if d.group not in seen:
            seen.append(d.group)
    return seen
