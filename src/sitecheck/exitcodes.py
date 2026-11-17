# -*- coding: utf-8 -*-
"""语义化退出码。

v2.0.x 只有 0=成功、1=一切失败、2=参数错误，脚本无法区分
"DNS 污染"和"代理配置问题"这类处置方式完全不同的结论。

    0        SUCCESS（可直连）
    2        用法 / 参数错误
    3        INCONCLUSIVE（证据不足，不做负面推断）
    10..19   按阻断点分层的失败
    4        IO / 写文件失败

兼容性：只判断 rc == 0 或 rc != 0 的旧脚本行为不变；
硬编码 rc == 1 的脚本需要改用分层码。
"""
from __future__ import annotations

from .models import Layer, Report

EXIT_OK = 0
EXIT_IO = 4
EXIT_USAGE = 2
EXIT_INCONCLUSIVE = 3
EXIT_PARTIAL = 20
EXIT_UNKNOWN = 19

LAYER_EXIT: dict[Layer, int] = {
    Layer.SUCCESS: EXIT_OK,
    Layer.HTTP_REJECT: 10,
    Layer.PROXY_REQUIRED: 11,
    Layer.HTTP_NO_RESPONSE: 12,
    Layer.DNS_POISONED: 13,
    Layer.TLS_BLOCKED: 14,
    Layer.TCP_BLOCKED: 15,
    Layer.DNS_FAIL: 16,
    Layer.INCONCLUSIVE: EXIT_INCONCLUSIVE,
    Layer.UNKNOWN: EXIT_UNKNOWN,
}

EXIT_HELP = (
    "退出码：0 可直连 | 2 参数错误 | 3 无法判定 | 4 输出失败 | "
    "10 服务端拒绝 | 11 需代理 | 12 应用层无响应 | 13 DNS 污染 | "
    "14 TLS/SNI 阻断 | 15 TCP 不通 | 16 解析失败 | 19 未知 | 20 部分可用"
)


def exit_code_for_layer(layer: Layer) -> int:
    return LAYER_EXIT.get(layer, EXIT_UNKNOWN)


def exit_code_for_report(report: Report) -> int:
    """按最终结论给出退出码。无结论一律视为无法判定。"""
    if not report.verdict:
        return EXIT_INCONCLUSIVE
    if report.incomplete and report.verdict.layer is not Layer.SUCCESS:
        return EXIT_INCONCLUSIVE
    return exit_code_for_layer(report.verdict.layer)
