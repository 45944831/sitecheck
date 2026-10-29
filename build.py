# -*- coding: utf-8 -*-
"""sitecheck 打包脚本。

用法：
    python build.py              -> onedir 模式（默认，启动约 0.5~1 秒）
    python build.py onefile      -> 单文件模式（每次启动要解压约 98MB，实测 23~35 秒）

为什么默认 onedir：
    onefile 每次启动都要把全部依赖解压到临时目录再加载，Qt 依赖体积大且要被
    杀毒软件逐文件扫描，实测冷启动 23~35 秒。onedir 不解压，实测 0.5~1 秒。

为什么用 --windowed：
    windowed 子系统不创建控制台，双击无黑框闪现。
    命令行模式由 sitecheck_gui.app._attach_console() 挂回父控制台。

已知限制（windowed 的固有问题）：
    cmd 不会等待 windowed 进程结束就返回提示符，所以
    `sitecheck.exe github.com > out.txt` 的重定向会丢内容。
    需要重定向时请用 `python -m sitecheck.cli`。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
ENTRY = os.path.join(SRC, "sitecheck_gui", "app.py")

# 用不到的 Qt 模块，剔除后体积更小、加载更快
EXCLUDE = [
    "PyQt5.QtWebEngineWidgets", "PyQt5.QtWebEngineCore", "PyQt5.QtWebEngine",
    "PyQt5.QtQml", "PyQt5.QtQuick", "PyQt5.QtQuickWidgets",
    "PyQt5.QtMultimedia", "PyQt5.QtMultimediaWidgets",
    "PyQt5.QtBluetooth", "PyQt5.QtNfc", "PyQt5.QtPositioning",
    "PyQt5.QtSerialPort", "PyQt5.QtSql", "PyQt5.QtTest",
    "PyQt5.QtDesigner", "PyQt5.QtHelp", "PyQt5.QtSvg",
    "tkinter",
]


def find_pyinstaller() -> list[str] | None:
    """返回可执行的 PyInstaller 命令前缀。

    首选 `当前解释器 -m PyInstaller`：打包环境必须与依赖环境一致，
    否则会出现"打包成功但运行时报 No module named PyQt5"——
    PATH 上可能存在另一个 Python 的 pyinstaller.exe，它看不到本环境的依赖。

    回退顺序：
      1. 环境变量 PYINSTALLER（显式指定）
      2. PATH 上的 pyinstaller
      3. 当前 Python 同目录的 Scripts/
    """
    try:
        probe = subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                               capture_output=True, timeout=90)
        if probe.returncode == 0:
            return [sys.executable, "-m", "PyInstaller"]
    except (OSError, subprocess.SubprocessError):
        pass

    env = os.environ.get("PYINSTALLER")
    if env and os.path.exists(env):
        return [env]

    which = shutil.which("pyinstaller") or shutil.which("pyinstaller.exe")
    if which:
        return [which]

    scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
    for name in ("pyinstaller.exe", "pyinstaller"):
        candidate = os.path.join(scripts, name)
        if os.path.exists(candidate):
            return [candidate]
    return None


def read_version() -> str:
    """从 pyproject.toml 读版本，避免版本号散落在多个文件里。"""
    try:
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
            for line in handle:
                if line.strip().startswith("version"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return "0.0.0"


def prepare_dist(target: str) -> None:
    """打包前把旧产物挪走，而不是让 PyInstaller 去删。

    PyInstaller 在 COLLECT 阶段会 `Removing dir <输出目录>`。在启用了
    批量删除保护的环境里（例如带安全策略的沙箱、部分企业终端），
    这一步会被拦下来，打包直接失败。重命名不涉及删除，可以完全避开。
    """
    if not os.path.exists(target):
        return
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = os.path.join(ROOT, "build",
                          "prev-%s-%s" % (os.path.basename(target), stamp))
    os.makedirs(os.path.dirname(backup), exist_ok=True)
    try:
        os.rename(target, backup)
        print("       旧产物已移至 %s" % os.path.relpath(backup, ROOT))
    except OSError as exc:
        print("       [警告] 旧产物无法移走（%s），将交由 PyInstaller 处理" % exc)


def main() -> int:
    mode = "onefile" if len(sys.argv) > 1 and sys.argv[1].lower() == "onefile" else "onedir"

    pyinstaller = find_pyinstaller()
    if not pyinstaller:
        print("[错误] 找不到 pyinstaller。三种解决办法：")
        print("  1) 激活装了 pyinstaller 的环境后重跑（推荐）")
        print("  2) 设置环境变量 PYINSTALLER 指向 pyinstaller.exe")
        print("  3) pip install pyinstaller 到当前 Python")
        return 1

    version = read_version()
    print("python     ：%s" % sys.executable)
    print("pyinstaller：%s" % " ".join(pyinstaller))
    print("打包模式：%s" % mode)
    print("版本    ：%s" % version)
    print("子系统  ：windowed (无控制台黑框)")
    print()

    cmd = pyinstaller + [
        "--" + mode,
        "--windowed",
        "--name", "sitecheck",
        "--noconfirm",
        "--paths", SRC,
        "--collect-submodules", "sitecheck",
        "--collect-submodules", "sitecheck_gui",
        "--distpath", os.path.join(ROOT, "dist"),
        "--workpath", os.path.join(ROOT, "build"),
        "--specpath", os.path.join(ROOT, "build"),
    ]
    for module in EXCLUDE:
        cmd += ["--exclude-module", module]
    cmd.append(ENTRY)

    prepare_dist(os.path.join(ROOT, "dist", "sitecheck"))
    rc = subprocess.call(cmd, cwd=ROOT)
    if rc != 0:
        print()
        print("[失败] 打包出错，返回码 %d" % rc)
        return rc

    print()
    if mode == "onedir":
        _copy_docs(os.path.join(ROOT, "dist", "sitecheck"))
        print("[完成] 输出在 dist\\sitecheck\\ 目录")
        print("       运行：dist\\sitecheck\\sitecheck.exe")
        print("       分发：整个 dist\\sitecheck 文件夹一起拷贝，可压成 zip")
    else:
        _copy_docs(os.path.join(ROOT, "dist"))
        print("[完成] 输出在 dist\\sitecheck.exe")
    return 0


def _copy_docs(target_dir: str) -> None:
    """把使用说明放进产物目录，方便分发给最终用户。"""
    source = os.path.join(ROOT, "docs", "使用说明.txt")
    if not os.path.exists(source) or not os.path.isdir(target_dir):
        return
    try:
        shutil.copy2(source, os.path.join(target_dir, "使用说明.txt"))
        print("       已附带：使用说明.txt")
    except OSError as exc:
        print("       [提示] 使用说明复制失败：%s" % exc)


if __name__ == "__main__":
    sys.exit(main())
