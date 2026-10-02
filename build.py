# -*- coding: utf-8 -*-
"""
sitecheck 打包脚本

用法：
    python build.py              -> onedir 模式（默认，推荐，启动约 0.5-1 秒）
    python build.py onefile      -> 单文件模式（每次启动需解压 ~98MB，实测 23-35 秒）

为什么默认 onedir：
    onefile 每次启动都要把全部依赖解压到临时目录再加载，
    Qt 依赖体积大且要被杀毒软件逐文件扫描，实测冷启动 23~35 秒。
    onedir 不解压，实测 0.5~1 秒。

为什么用 --windowed：
    windowed 子系统不创建控制台，双击无黑框闪现。
    命令行模式由 sitecheck_gui.py 里的 AttachConsole(-1) 挂回父控制台，
    在 cmd 里带参数运行仍可正常输出。

注：原先的 build.bat 有 chcp 65001 导致 cmd 按 UTF-8 重新解析后续行、
    把命令行截断的问题（中文注释吃掉相邻 ASCII 字符）。改用 Python 驱动，无此问题。
"""
import os
import sys
import shutil
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))


def find_pyinstaller():
    """
    定位 pyinstaller.exe，按优先级：
      1. 环境变量 PYINSTALLER（显式指定优先）
      2. PATH 上能找到（推荐：装 pyinstaller 的那个 venv 激活后直接用）
      3. 当前 Python 同目录的 Scripts/ 下（venv 的常见布局）
    不硬编码任何用户目录——公开仓库里不该出现本机用户名。
    """
    env = os.environ.get("PYINSTALLER")
    if env and os.path.exists(env):
        return env

    which = shutil.which("pyinstaller") or shutil.which("pyinstaller.exe")
    if which:
        return which

    scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
    for name in ("pyinstaller.exe", "pyinstaller"):
        p = os.path.join(scripts, name)
        if os.path.exists(p):
            return p
    return None

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


def main():
    mode = "onefile" if len(sys.argv) > 1 and sys.argv[1].lower() == "onefile" else "onedir"

    pyinstaller = find_pyinstaller()
    if not pyinstaller:
        print("[错误] 找不到 pyinstaller。三种解决办法：")
        print("  1) 激活装了 pyinstaller 的环境后重跑（推荐）")
        print("  2) 设置环境变量 PYINSTALLER 指向 pyinstaller.exe")
        print("  3) pip install pyinstaller 到当前 Python")
        return 1

    print("pyinstaller：%s" % pyinstaller)
    print("打包模式：%s" % mode)
    print("子系统  ：windowed (无控制台黑框)")
    print()

    cmd = [
        pyinstaller,
        "--" + mode,
        "--windowed",
        "--name", "sitecheck",
        "--clean",
        "--noconfirm",
        "--hidden-import", "sitecheck",
        "--distpath", os.path.join(ROOT, "dist"),
        "--workpath", os.path.join(ROOT, "build"),
        "--specpath", os.path.join(ROOT, "build"),
    ]
    for m in EXCLUDE:
        cmd += ["--exclude-module", m]
    cmd.append(os.path.join(ROOT, "sitecheck_gui.py"))

    rc = subprocess.call(cmd, cwd=ROOT)
    if rc != 0:
        print()
        print("[失败] 打包出错，返回码 %d" % rc)
        return rc

    print()
    if mode == "onedir":
        print("[完成] 输出在 dist\\sitecheck\\ 目录")
        print("       运行：dist\\sitecheck\\sitecheck.exe")
        print("       分发：整个 dist\\sitecheck 文件夹一起拷贝，可压成 zip")
    else:
        print("[完成] 输出在 dist\\sitecheck.exe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
