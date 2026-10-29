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
    "PyQt5.QtNetwork", "PyQt5.QtDBus", "PyQt5.QtWebSockets",
    "tkinter",
]

# PyInstaller 的 PyQt5 hook 会把 Qt5/bin 里的 Quick / Qml / 软件 OpenGL 整套复制，
# 即使 --exclude-module 排除了对应绑定。纯 QWidget + 栅格绘制用不到这些，
# 打包后统一剔掉：安装体积 92MB -> 约 50MB，zip 38MB -> 约 20MB。
PRUNE_QT_BIN = [
    "opengl32sw.dll",        # 软件 OpenGL，仅 QtQuick / QOpenGLWidget 需要
    "d3dcompiler_47.dll",    # ANGLE 的着色器编译器
    "libEGL.dll",
    "libGLESv2.dll",
    "Qt5Quick.dll",
    "Qt5Qml.dll",
    "Qt5QmlModels.dll",
    "Qt5DBus.dll",
    "Qt5Network.dll",
    "Qt5WebSockets.dll",
    "Qt5Svg.dll",
]
PRUNE_QT_PLUGINS = [
    "platforms/qminimal.dll",       # 仅离屏 / 无窗口测试用
    "platforms/qoffscreen.dll",
    "platforms/qwebgl.dll",
    "platformthemes/qxdgdesktopportal.dll",   # Linux 桌面门户
    "generic/qtuiotouchplugin.dll",
    "imageformats/qsvg.dll",
    "iconengines/qsvgicon.dll",
    "imageformats/qwebp.dll",
    "imageformats/qtiff.dll",
    "imageformats/qtga.dll",
    "imageformats/qwbmp.dll",
    "imageformats/qicns.dll",
]
# 应用从未安装 QTranslator，Qt 自带的 .qm 一律用不到
PRUNE_QT_DIRS = ["translations"]


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


def _configure_stdio() -> None:
    """管道 / CI 里 stdout 可能是 cp1252，中文 print 会直接抛 UnicodeEncodeError。

    统一改成 UTF-8；个别字符编不出来时替换而不是中断构建。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def main() -> int:
    _configure_stdio()
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
    child_env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    rc = subprocess.call(cmd, cwd=ROOT, env=child_env)
    if rc != 0:
        print()
        print("[失败] 打包出错，返回码 %d" % rc)
        return rc

    print()
    if mode == "onedir":
        target = os.path.join(ROOT, "dist", "sitecheck")
        _prune_payload(target)
        _copy_docs(target)
        print("[完成] 输出在 dist\\sitecheck\\ 目录")
        print("       运行：dist\\sitecheck\\sitecheck.exe")
        print("       分发：整个 dist\\sitecheck 文件夹一起拷贝，可压成 zip")
    else:
        _copy_docs(os.path.join(ROOT, "dist"))
        print("[完成] 输出在 dist\\sitecheck.exe")
    return 0


def _dir_size(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def _prune_payload(target_dir: str) -> None:
    """剔除 PyInstaller 多带的 Qt 组件。

    个别文件被安全软件占用时只提示、不中断构建 —— 这里的目标是瘦身，
    不是必须成功的步骤。
    """
    qt_dir = os.path.join(target_dir, "_internal", "PyQt5", "Qt5")
    if not os.path.isdir(qt_dir):
        return

    before = _dir_size(target_dir)
    targets = [os.path.join(qt_dir, "bin", name) for name in PRUNE_QT_BIN]
    targets += [os.path.join(qt_dir, "plugins", name)
                for name in PRUNE_QT_PLUGINS]
    for path in targets:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print("       [提示] 无法删除 %s（%s）"
                  % (os.path.relpath(path, target_dir), exc))
    for name in PRUNE_QT_DIRS:
        path = os.path.join(qt_dir, name)
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
            except OSError as exc:
                print("       [提示] 无法删除 %s（%s）" % (name, exc))

    after = _dir_size(target_dir)
    print("       已精简未使用的 Qt 组件：%.1f MB -> %.1f MB（-%.1f MB）"
          % (before / 1048576, after / 1048576,
             (before - after) / 1048576))


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
