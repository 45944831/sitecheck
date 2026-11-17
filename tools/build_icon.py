# -*- coding: utf-8 -*-
"""从 SVG 源生成多尺寸 sitecheck.ico。

每个尺寸都用矢量源单独渲染，而不是缩放同一张大图 —— 16/24px 下的
笔画只有独立渲染才不会糊成一团。小尺寸另有一套加粗简化的源图
（icon-small.svg），因为细笔画缩到 16px 会直接消失。

用法：
    python tools/build_icon.py              # 生成 ico
    python tools/build_icon.py --preview    # 同时导出 PNG 预览，便于肉眼检查
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "src" / "sitecheck_gui" / "assets"
SVG_LARGE = ASSETS / "icon.svg"
SVG_SMALL = ASSETS / "icon-small.svg"
ICO_PATH = ASSETS / "sitecheck.ico"

# 小尺寸用加粗版，避免细节糊掉；阈值取 32
SMALL_MAX = 32
SIZES = (16, 24, 32, 48, 64, 128, 256)


def source_for(size: int) -> Path:
    return SVG_SMALL if size <= SMALL_MAX and SVG_SMALL.exists() else SVG_LARGE


def render_png(size: int, svg: Path) -> bytes:
    """用 Qt 把 SVG 渲染成指定边长的 PNG 字节。"""
    from PyQt5.QtCore import QBuffer, QByteArray, QIODevice
    from PyQt5.QtGui import QImage, QPainter
    from PyQt5.QtSvg import QSvgRenderer

    renderer = QSvgRenderer(str(svg))
    if not renderer.isValid():
        raise SystemExit("SVG 无效：%s" % svg)

    image = QImage(size, size, QImage.Format_ARGB32)
    image.fill(0)

    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    renderer.render(painter)
    painter.end()

    # QByteArray 必须单独持有引用：传给 QBuffer 的临时对象会被回收，随后写入即崩溃
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    buffer.close()
    return bytes(data)


def write_ico(payloads: dict[int, bytes], path: Path) -> None:
    """按 ICO 规范拼装（PNG 压缩条目，Vista 以后系统都认）。"""
    sizes = sorted(payloads)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)

    entries = b""
    body = b""
    for size in sizes:
        data = payloads[size]
        side = 0 if size >= 256 else size          # 256 在目录项里记作 0
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        body += data

    path.write_bytes(header + entries + body)


def main() -> int:
    if not SVG_LARGE.exists():
        print("找不到矢量源：%s" % SVG_LARGE)
        return 1

    # 注意：这里刻意不创建 QGuiApplication。QSvgRenderer + QImage 不需要它，
    # 而本机在 offscreen 平台下实例化 QGuiApplication 会直接段错误。
    payloads = {size: render_png(size, source_for(size)) for size in SIZES}
    write_ico(payloads, ICO_PATH)

    print("已生成 %s" % ICO_PATH.relative_to(ROOT))
    print("  尺寸：%s" % ", ".join(str(s) for s in SIZES))
    print("  体积：%.1f KB" % (ICO_PATH.stat().st_size / 1024))

    if "--preview" in sys.argv:
        # 写到 build/ 下：预览只是给人眼看的中间产物，不该进版本库
        out_dir = ROOT / "build" / "icon-preview"
        out_dir.mkdir(parents=True, exist_ok=True)
        for size, data in payloads.items():
            (out_dir / ("icon-%d.png" % size)).write_bytes(data)
        print("  预览：%s" % out_dir.relative_to(ROOT))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
