# -*- coding: utf-8 -*-
"""
sitecheck GUI —— 网站直连检测工具（图形界面，PyQt5）

运行规则：
    双击 / 无参数运行  → 打开图形界面
    带参数运行         → 走命令行模式（与 sitecheck.exe 一致）

网络探测在 QThread 里跑，通过信号回传进度，界面不会卡死。
"""
import sys, os, re, traceback

import sitecheck


def _attach_console():
    """
    打包为 windowed 子系统时进程没有控制台，命令行模式要把输出挂回父进程控制台。
    若已是 console 子系统（sys.stdout 存在）则直接跳过。
    """
    if getattr(sys, "stdout", None) is not None:
        return
    try:
        import ctypes, msvcrt
        k = ctypes.windll.kernel32
        if not k.AttachConsole(-1):          # ATTACH_PARENT_PROCESS
            return
        for name, std_handle, mode in (("stdin", -10, os.O_RDONLY),
                                       ("stdout", -11, os.O_WRONLY),
                                       ("stderr", -12, os.O_WRONLY)):
            h = k.GetStdHandle(std_handle)
            if not h or h in (0, -1):
                continue
            try:
                f = os.fdopen(msvcrt.open_osfhandle(h, mode),
                              "r" if mode == os.O_RDONLY else "w",
                              errors="replace")
                setattr(sys, name, f)
            except Exception:
                pass
    except Exception:
        pass


def _msgbox(title, text, ok=True):
    """不依赖 Qt 的原生弹窗，供提权后那个没有控制台的进程回显结果"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text[:1800], title, 0x40 if ok else 0x10)
        return True
    except Exception:
        return False


# 带参数运行 → 命令行模式，此时不需要任何 GUI 依赖
if len(sys.argv) > 1:
    _attach_console()
    import io
    buf = None
    if getattr(sys, "stdout", None) is None:
        # windowed 且没挂上控制台（例如被 UAC 提权启动）：先攒着，结束用弹窗回显
        buf = io.StringIO()
        sys.stdout = sys.stderr = buf
    code = 0
    try:
        sitecheck.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 0
    for s in (sys.stdout, sys.stderr):
        try:
            s.flush()
        except Exception:
            pass
    if buf is not None:
        if not _msgbox("sitecheck（%s）" % ("成功" if code == 0 else "失败"), buf.getvalue(), code == 0):
            try:
                with open("sitecheck-cli-output.txt", "w", encoding="utf-8") as f:
                    f.write(buf.getvalue())
            except Exception:
                pass
    raise SystemExit(code)

# 无参数 → 图形界面，下面才加载 Qt
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QFileDialog, QMessageBox, QGroupBox, QFormLayout,
                             QSizePolicy)

UI_FONT = "Microsoft YaHei UI"
MONO = "Consolas"
APP_VERSION = sitecheck.VERSION   # launch() 时会用 next_version() 刷新

CSS_OK = "background:#1d9e75;color:white;border-radius:4px;padding:9px;"
CSS_BAD = "background:#c0392b;color:white;border-radius:4px;padding:9px;"
CSS_WARN = "background:#b26a00;color:white;border-radius:4px;padding:9px;"
CSS_IDLE = "background:#e8e8e8;color:#555;border-radius:4px;padding:9px;"
CSS_BUSY = "background:#2b6cb0;color:white;border-radius:4px;padding:9px;"


class Worker(QThread):
    msg = pyqtSignal(str)
    done = pyqtSignal(object, str)
    failed = pyqtSignal(str)

    def __init__(self, domain, ips, parent=None):
        super().__init__(parent)
        self.domain, self.ips = domain, ips

    def run(self):
        try:
            R = sitecheck.analyze(self.domain, self.ips, progress=self.msg.emit)
            sitecheck.verdict(R)
            self.done.emit(R, sitecheck.render(R))
        except Exception as e:
            self.failed.emit("%s\n\n%s" % (e, traceback.format_exc(limit=4)))


class Win(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.result = None
        self.text = ""
        self._build()

    def _build(self):
        self.setWindowTitle("网站直连检测工具 sitecheck  v%s" % APP_VERSION)
        self.setFixedSize(920, 700)   # 固定尺寸：不随结果长度拉伸，内容长了靠滚动
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(8)

        hrow = QHBoxLayout()
        vleft = QVBoxLayout()
        vleft.setSpacing(0)
        title = QLabel("网站直连检测")
        title.setFont(QFont(UI_FONT, 15, QFont.Bold))
        sub = QLabel("DNS / TCP / TLS-SNI 逐层定位；只在 hosts 真能解决时才建议改 hosts")
        sub.setFont(QFont(UI_FONT, 9))
        sub.setStyleSheet("color:#777;")
        vleft.addWidget(title)
        vleft.addWidget(sub)
        hrow.addLayout(vleft)
        hrow.addStretch()
        self.ver_label = QLabel("v%s" % APP_VERSION)
        self.ver_label.setFont(QFont(UI_FONT, 11, QFont.Bold))
        self.ver_label.setStyleSheet("color:#2b6cb0;")
        hrow.addWidget(self.ver_label)
        root.addLayout(hrow)

        box = QGroupBox("检测参数")
        form = QFormLayout(box)
        form.setLabelAlignment(Qt.AlignRight)
        self.e_domain = QLineEdit()
        self.e_domain.setFont(QFont(UI_FONT, 11))
        self.e_domain.setPlaceholderText("例如 github.com")
        self.e_domain.returnPressed.connect(self.start)
        form.addRow("域名", self.e_domain)

        self.e_ip = QLineEdit()
        self.e_ip.setFont(QFont(UI_FONT, 11))
        self.e_ip.setPlaceholderText("可选，多个用逗号分隔")
        self.e_ip.returnPressed.connect(self.start)
        form.addRow("指定 IP", self.e_ip)

        hint = QLabel("DNS 被污染时解析结果全是假的，必须手动填真实 IP 才能判断 hosts 有没有用")
        hint.setFont(QFont(UI_FONT, 8))
        hint.setStyleSheet("color:#888;")
        hint.setWordWrap(True)
        form.addRow("", hint)

        brow = QHBoxLayout()
        self.b_run = QPushButton("开始检测")
        self.b_run.setFont(QFont(UI_FONT, 10, QFont.Bold))
        self.b_run.setCursor(Qt.PointingHandCursor)
        self.b_run.setStyleSheet("background:#2b6cb0;color:white;border:none;padding:8px 16px;border-radius:4px;")
        self.b_run.clicked.connect(self.start)
        self.b_save = QPushButton("保存报告")
        self.b_save.setFont(QFont(UI_FONT, 10))
        self.b_save.setCursor(Qt.PointingHandCursor)
        self.b_save.clicked.connect(self.save)
        self.b_hosts = QPushButton("写入 hosts")
        self.b_hosts.setFont(QFont(UI_FONT, 10))
        self.b_hosts.setCursor(Qt.PointingHandCursor)
        self.b_hosts.setToolTip("把确认可用的真实 IP 写入系统 hosts，并自动刷新 DNS 缓存")
        self.b_hosts.setEnabled(False)
        self.b_hosts.clicked.connect(self.write_hosts)
        self.b_clear = QPushButton("清空")
        self.b_clear.setFont(QFont(UI_FONT, 10))
        self.b_clear.setCursor(Qt.PointingHandCursor)
        self.b_clear.clicked.connect(self.clear)
        for b in (self.b_run, self.b_hosts, self.b_save, self.b_clear):
            b.setMinimumHeight(34)
            brow.addWidget(b)
        brow.addStretch()
        form.addRow("", self._wrap(brow))
        root.addWidget(box)

        # 真实 IP 单独一行放在最上面，检测完立刻可见；右侧 + 按钮可一键填入下面的指定 IP 栏
        ipbox = QHBoxLayout()
        ipbox.setSpacing(6)
        self.ip_row = QLabel("真实 IP：待检测")
        self.ip_row.setFont(QFont(UI_FONT, 10, QFont.Bold))
        self.ip_row.setStyleSheet("background:#eef2f7;color:#1e4e8c;border-radius:4px;padding:6px;")
        self.ip_row.setWordWrap(True)
        self.ip_row.setFixedHeight(34)
        ipbox.addWidget(self.ip_row, 1)
        self.b_add = QPushButton("+")
        self.b_add.setFixedSize(34, 34)
        self.b_add.setFont(QFont(UI_FONT, 12, QFont.Bold))
        self.b_add.setCursor(Qt.PointingHandCursor)
        self.b_add.setToolTip("把真实 IP 填入下方「指定 IP」栏（多个用逗号分隔）")
        self.b_add.setStyleSheet("background:#2b6cb0;color:white;border:none;border-radius:4px;")
        self.b_add.setEnabled(False)
        self.b_add.clicked.connect(self.fill_ip)
        ipbox.addWidget(self.b_add)
        root.addWidget(self._wrap(ipbox))

        self.banner = QLabel("等待检测")
        self.banner.setFont(QFont(UI_FONT, 11, QFont.Bold))
        self.banner.setStyleSheet(CSS_IDLE)
        self.banner.setWordWrap(True)          # 换行，避免长判定文本把窗口撑宽
        self.banner.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.banner.setFixedHeight(54)         # 高度固定，完整说明放在下方结果区
        root.addWidget(self.banner)

        self.status = QLabel("就绪")
        self.status.setFont(QFont(UI_FONT, 9))
        self.status.setStyleSheet("color:#666;")
        root.addWidget(self.status)

        self.pbar = QProgressBar()
        self.pbar.setRange(0, 0)          # 不确定进度
        self.pbar.setFixedHeight(6)
        self.pbar.setTextVisible(False)
        self.pbar.hide()
        root.addWidget(self.pbar)

        self.out = QTextEdit()
        self.out.setReadOnly(True)
        # Expanding 策略：吃掉剩余空间，而不是用自己的 sizeHint 去驱动布局变大
        self.out.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.out.setMinimumHeight(160)
        # 表格由布局引擎排版，正文字体可以选好看的，不必硬用等宽
        self.out.setFont(QFont(UI_FONT, 10))
        self.out.setStyleSheet("background:white;border:1px solid #ccc;")
        root.addWidget(self.out, 1)

        self._welcome()
        # 不让布局用子控件的 sizeHint 反推窗口尺寸
        self.layout().setSizeConstraint(QVBoxLayout.SetNoConstraint)

    def _wrap(self, layout):
        w = QWidget()
        w.setLayout(layout)
        return w

    def _welcome(self):
        self.out.setPlainText(
            "输入域名后点“开始检测”。\n\n"
            "工具会依次检查：\n"
            "  1. 多家 DNS + 加密 DNS 解析，判断是否被污染\n"
            "  2. 逐 IP 做 TCP / TLS / HTTP 探测，用证书主体判定真身\n"
            "  3. 定位阻断点：DNS / TCP / TLS-SNI / DNS 污染\n"
            "  4. 能连给优化建议，不能连给原因\n"
            "  5. 只有在 hosts 真能解决时才给出可粘贴的条目\n\n"
            "提示：结果开头有“控制组”一栏，若控制组也不通，说明当前网络出网受限，\n"
            "此时“TCP 不通”的结论不可信，请换网络环境再测。")

    @staticmethod
    def _short(v, n=44):
        """横幅只放结论摘要，完整说明留给下方结果区，避免撑宽窗口"""
        for sep in ("——", "。"):
            if sep in v:
                v = v.split(sep)[0]
        v = v.strip()
        return v if len(v) <= n else v[:n] + " …"

    # ---------- 动作 ----------
    def start(self):
        if self.worker and self.worker.isRunning():
            return
        d = self.e_domain.text().strip()
        if not d:
            QMessageBox.warning(self, "缺少域名", "请先输入要检测的域名，例如 github.com")
            return
        d = re.sub(r"^https?://", "", d).strip().strip("/").split("/")[0].split("?")[0]
        ips = [x.strip() for x in self.e_ip.text().replace("，", ",").split(",") if x.strip()]

        self.result, self.text = None, ""
        self.b_run.setEnabled(False)
        self.b_run.setText("检测中...")
        self.b_add.setEnabled(False)
        self.b_hosts.setEnabled(False)
        self.banner.setText("检测中 ...")
        self.banner.setStyleSheet(CSS_BUSY)
        self.pbar.show()
        self.out.setPlainText("检测 %s\n\n" % d + ("附带验证 IP：%s\n" % ", ".join(ips) if ips else ""))

        self.worker = Worker(d, ips, self)
        self.worker.msg.connect(self.on_msg)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_err)
        self.worker.start()

    def on_msg(self, s):
        self.status.setText(s)
        self.out.append(s)

    def fill_ip(self):
        """把已确认的真实 IP 追加进「指定 IP」栏，去重、不覆盖已有内容"""
        real = (self.result or {}).get("real_ips") or []
        if not real:
            return
        cur = self.e_ip.text().strip()
        have = [x.strip() for x in cur.replace("，", ",").split(",") if x.strip()]
        for ip in real:
            if ip not in have:
                have.append(ip)
        self.e_ip.setText(", ".join(have))
        self.status.setText("已填入指定 IP 栏：%s" % ", ".join(real))

    def on_done(self, R, text):
        self.result, self.text = R, text
        self.pbar.hide()
        self.b_run.setEnabled(True)
        self.b_run.setText("开始检测")
        real = R.get("real_ips") or []
        if real:
            self.ip_row.setText("真实 IP：%s　（已通过 TLS 证书校验，确认归属该站）"
                                % "、".join(real))
            self.ip_row.setStyleSheet("background:#eef2f7;color:#1e4e8c;border-radius:4px;padding:6px;")
        else:
            self.ip_row.setText("真实 IP：未能确认　（候选 IP 均未通过证书校验，解析结果可能是伪造的）")
            self.ip_row.setStyleSheet("background:#fdecea;color:#a32d2d;border-radius:4px;padding:6px;")
        self.b_add.setEnabled(bool(real))   # 没确认出真实 IP 就不给填
        need = bool(R.get("hosts_write_needed"))
        self.b_hosts.setEnabled(need)
        self.b_hosts.setToolTip(
            "把确认可用的真实 IP 写入系统 hosts，并自动刷新 DNS 缓存"
            if need else
            "仅在「DNS 解析不可用、但已找到可直连 IP」时才需要写入 hosts")
        css = CSS_OK if R["layer"] == "SUCCESS" else (CSS_BAD if R["layer"] == "TLS/SNI" else CSS_WARN)
        self.banner.setText("%s　|　阻断点：%s" % (self._short(R["verdict"]), R["layer"]))
        self.banner.setStyleSheet(css)
        # 用 HTML 渲染：表格交给布局引擎排，中英文混排也能对齐
        self.out.setHtml(sitecheck.render_html(R))
        self.out.moveCursor(self.out.textCursor().Start)
        self.status.setText("检测完成，可点“保存报告”导出 Markdown")

    def on_err(self, msg):
        self.pbar.hide()
        self.b_run.setEnabled(True)
        self.b_run.setText("开始检测")
        self.banner.setText("检测出错")
        self.banner.setStyleSheet(CSS_BAD)
        self.status.setText("出错")
        QMessageBox.critical(self, "检测失败", msg[:800])

    def write_hosts(self):
        """写入系统 hosts：先展示改动预演并征求确认，写入前备份，写后刷新 DNS 缓存"""
        R = self.result
        if not R or not R.get("hosts_write_needed"):
            return
        ips = R.get("hosts_entry_ips") or []
        if not ips:
            return
        d = R["domain"]
        removed, added = sitecheck.hosts_plan(d, ips)

        lines = ["将对系统 hosts 文件做如下改动：", "",
                 "文件：" + sitecheck.HOSTS_PATH, ""]
        if removed:
            lines.append("替换掉 %d 条该域名的旧条目：" % len(removed))
            for ln, txt in removed:
                lines.append("   第 %d 行    %s" % (ln, txt))
            lines.append("")
        lines.append("新增 %d 条：" % len(added))
        for l in added:
            lines.append("   %s" % l)
        lines += ["",
                  "· 修改前会自动备份 hosts",
                  "· 写入后自动执行 ipconfig /flushdns",
                  "· 需要管理员权限，可能会弹出 UAC 确认",
                  "", "确定继续吗？"]
        if QMessageBox.question(self, "写入 hosts", "\n".join(lines),
                                QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return

        ok, msg, bak = sitecheck.apply_hosts(d, ips)
        if ok:
            fok, fmsg = sitecheck.flush_dns()
            QMessageBox.information(
                self, "完成",
                "已写入 %s\n\n%s\nDNS 缓存刷新：%s\n\n备份文件：\n%s"
                % (d, msg, "成功" if fok else "失败：%s" % fmsg, bak))
            self.status.setText("hosts 已更新并刷新缓存，建议重新检测一次确认")
            return

        if msg == "NEED_ADMIN":
            if QMessageBox.question(
                    self, "需要管理员权限",
                    "写入 hosts 需要管理员权限。\n\n是否以管理员身份重新执行？"
                    "（会弹出 UAC 确认窗口，完成后自动刷新 DNS 缓存）",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) == QMessageBox.Yes:
                if sitecheck.relaunch_as_admin(["--apply-hosts", d] + ips):
                    QMessageBox.information(
                        self, "已请求提权",
                        "请在弹出的 UAC 窗口中确认。\n完成后可点「开始检测」验证结果。")
                else:
                    QMessageBox.warning(
                        self, "提权失败",
                        "无法发起提权请求。请右键以管理员身份运行本程序后重试。")
            return

        QMessageBox.critical(self, "写入失败", msg)

    def save(self):
        if not self.text:
            QMessageBox.information(self, "无内容", "还没有检测结果可保存")
            return
        dom = (self.result or {}).get("domain", "site")
        path, _ = QFileDialog.getSaveFileName(
            self, "保存报告", "检测结果-%s.md" % dom, "Markdown (*.md);;文本 (*.txt);;所有文件 (*.*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.text)
            QMessageBox.information(self, "已保存", path)
        except Exception as e:
            QMessageBox.critical(self, "保存失败", str(e))

    def clear(self):
        self.e_domain.clear()
        self.e_ip.clear()
        self.result, self.text = None, ""
        self.ip_row.setText("真实 IP：待检测")
        self.ip_row.setStyleSheet("background:#eef2f7;color:#1e4e8c;border-radius:4px;padding:6px;")
        self.b_add.setEnabled(False)
        self.b_hosts.setEnabled(False)
        self.banner.setText("等待检测")
        self.banner.setStyleSheet(CSS_IDLE)
        self.status.setText("就绪")
        self._welcome()


def launch():
    global APP_VERSION
    APP_VERSION = sitecheck.next_version()   # 每次启动 +0.1，逢 10 进 1
    # windowed 子系统打包时不会创建控制台，双击启动也就没有黑框
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = Win()
    w.show()
    sys.exit(app.exec_())


def main():
    launch()   # 走到这里说明没有命令行参数


if __name__ == "__main__":
    main()
