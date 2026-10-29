# -*- coding: utf-8 -*-
"""sitecheck 图形界面（PyQt5）。

相对 v1.0 的改动：
    1. 窗口可缩放 / 可最大化（v1.0 固定 920×700，高 DPI 下内容被裁）
    2. 确定进度条（v1.0 是不确定进度，用户不知道要等多久）
    3. 进度日志与结果分离，检测完不会把日志冲掉
    4. 新增批量检测：一次输入多个域名，表格展示，可排序
    5. 导出 Markdown / JSON / HTML
    6. 结论区展示"为什么这么判"（evidence）

无参数启动 -> GUI；带参数启动 -> 转发给命令行，行为与 v1.0 一致。
"""
from __future__ import annotations

import os
import sys
import traceback

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

import sitecheck
from sitecheck import hosts as hostsmod
from sitecheck import render as rendermod
from sitecheck.models import HttpStatus, Layer
from sitecheck.orchestrator import DEFAULT_TOTAL_TIMEOUT, normalize_domain

UI_FONT = "Microsoft YaHei UI"
MONO = "Consolas"
APP_VERSION = sitecheck.__version__

CSS_OK = "background:#1d9e75;color:white;border-radius:5px;padding:10px;"
CSS_BAD = "background:#c0392b;color:white;border-radius:5px;padding:10px;"
CSS_WARN = "background:#b26a00;color:white;border-radius:5px;padding:10px;"
CSS_INFO = "background:#6b4fa8;color:white;border-radius:5px;padding:10px;"
CSS_IDLE = "background:#eef1f5;color:#5a6472;border-radius:5px;padding:10px;"
CSS_BUSY = "background:#2b6cb0;color:white;border-radius:5px;padding:10px;"

LAYER_CSS = {
    Layer.SUCCESS: CSS_OK,
    Layer.HTTP_REJECT: CSS_WARN,
    Layer.HTTP_NO_RESPONSE: CSS_WARN,
    Layer.PROXY_REQUIRED: CSS_INFO,
    Layer.TLS_BLOCKED: CSS_BAD,
    Layer.DNS_POISONED: CSS_BAD,
    Layer.TCP_BLOCKED: CSS_BAD,
    Layer.DNS_FAIL: CSS_BAD,
    Layer.INCONCLUSIVE: CSS_INFO,
    Layer.UNKNOWN: CSS_WARN,
}

LAYER_TEXT = {
    Layer.SUCCESS: "可直连",
    Layer.HTTP_REJECT: "服务端拒绝",
    Layer.HTTP_NO_RESPONSE: "应用层无响应",
    Layer.PROXY_REQUIRED: "需要代理",
    Layer.TLS_BLOCKED: "TLS/SNI 被切断",
    Layer.DNS_POISONED: "DNS 污染",
    Layer.TCP_BLOCKED: "TCP 不通",
    Layer.DNS_FAIL: "解析失败",
    Layer.INCONCLUSIVE: "无法判定",
    Layer.UNKNOWN: "未知",
}


# ---------------------------------------------------------------- 线程

class AnalyzeWorker(QThread):
    progress = pyqtSignal(str, str, int, int)
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, domain: str, ips: list[str], timeout: float,
                 total_timeout: float = DEFAULT_TOTAL_TIMEOUT, parent=None):
        super().__init__(parent)
        self.domain = domain
        self.ips = ips
        self.timeout = timeout
        self.total_timeout = total_timeout
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            report = sitecheck.analyze(self.domain, self.ips,
                                       progress=self.progress.emit,
                                       timeout=self.timeout,
                                       version=APP_VERSION,
                                       total_timeout=self.total_timeout,
                                       should_stop=lambda: self._stop)
            self.done.emit(report)
        except Exception as exc:                       # noqa: BLE001
            self.failed.emit("%s\n\n%s" % (exc, traceback.format_exc(limit=5)))


class BatchWorker(QThread):
    item_done = pyqtSignal(object)
    progress = pyqtSignal(str, int, int)
    finished_all = pyqtSignal()

    def __init__(self, domains: list[str], timeout: float, parent=None):
        super().__init__(parent)
        self.domains = domains
        self.timeout = timeout
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        import time
        total = len(self.domains)
        for index, domain in enumerate(self.domains, 1):
            if self._stop:
                break
            self.progress.emit(domain, index, total)
            started = time.perf_counter()
            try:
                report = sitecheck.analyze(domain, [], timeout=self.timeout,
                                           version=APP_VERSION,
                                           should_stop=lambda: self._stop)
            except Exception as exc:                   # noqa: BLE001
                self.item_done.emit(("error", domain, str(exc)[:80], 0.0))
                continue
            self.item_done.emit(("ok", domain, report,
                                 time.perf_counter() - started))
        self.finished_all.emit()


# ---------------------------------------------------------------- 主窗口

class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.worker: AnalyzeWorker | None = None
        self.batch_worker: BatchWorker | None = None
        self.report = None
        self.batch_reports: list = []
        self._build()

    # ---------- 构建 ----------
    def _build(self) -> None:
        self.setWindowTitle("网站直连检测工具 sitecheck  v%s" % APP_VERSION)
        self.setMinimumSize(960, 680)          # 可缩放，不再 setFixedSize
        self.resize(1080, 760)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # 标题
        head = QHBoxLayout()
        left = QVBoxLayout()
        left.setSpacing(0)
        title = QLabel("网站直连检测")
        title.setFont(QFont(UI_FONT, 16, QFont.Bold))
        subtitle = QLabel("DNS / TCP / TLS-SNI / 代理 逐层定位；"
                          "只在 hosts 真能解决时才建议改 hosts")
        subtitle.setFont(QFont(UI_FONT, 9))
        subtitle.setStyleSheet("color:#7c848e;")
        left.addWidget(title)
        left.addWidget(subtitle)
        head.addLayout(left)
        head.addStretch()
        version = QLabel("v%s" % APP_VERSION)
        version.setFont(QFont(UI_FONT, 11, QFont.Bold))
        version.setStyleSheet("color:#2b6cb0;")
        head.addWidget(version)
        root.addLayout(head)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_single_tab(), "单站检测")
        self.tabs.addTab(self._build_batch_tab(), "批量检测")
        root.addWidget(self.tabs, 1)

        self.status = QLabel("就绪")
        self.status.setFont(QFont(UI_FONT, 9))
        self.status.setStyleSheet("color:#5a6472;")
        root.addWidget(self.status)

    def _build_single_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 10, 4, 4)
        layout.setSpacing(8)

        # 参数
        box = QGroupBox("检测参数")
        form = QFormLayout(box)
        form.setLabelAlignment(Qt.AlignRight)

        self.e_domain = QLineEdit()
        self.e_domain.setFont(QFont(UI_FONT, 11))
        self.e_domain.setPlaceholderText("例如 github.com　（多个域名请用「批量检测」标签页）")
        self.e_domain.returnPressed.connect(self.start)
        form.addRow("域名", self.e_domain)

        self.e_ip = QLineEdit()
        self.e_ip.setFont(QFont(UI_FONT, 11))
        self.e_ip.setPlaceholderText("可选，多个用逗号分隔")
        self.e_ip.returnPressed.connect(self.start)
        form.addRow("指定 IP", self.e_ip)

        hint = QLabel("DNS 被污染时解析结果全是假的，手动填入真实 IP 才能判断 hosts 有没有用")
        hint.setFont(QFont(UI_FONT, 8))
        hint.setStyleSheet("color:#8b939d;")
        hint.setWordWrap(True)
        form.addRow("", hint)

        buttons = QHBoxLayout()
        self.b_run = QPushButton("开始检测")
        self.b_run.setFont(QFont(UI_FONT, 10, QFont.Bold))
        self.b_run.setCursor(Qt.PointingHandCursor)
        self.b_run.setStyleSheet("background:#2b6cb0;color:white;border:none;"
                                 "padding:8px 18px;border-radius:4px;")
        self.b_run.clicked.connect(self.start)

        self.b_cancel = QPushButton("取消")
        self.b_cancel.setCursor(Qt.PointingHandCursor)
        self.b_cancel.setEnabled(False)
        self.b_cancel.setToolTip("中断当前检测；已完成的层保留，未探测的部分只给「无法判定」")
        self.b_cancel.clicked.connect(self.cancel)

        self.b_hosts = QPushButton("写入 hosts")
        self.b_hosts.setCursor(Qt.PointingHandCursor)
        self.b_hosts.setEnabled(False)
        self.b_hosts.setToolTip("仅在「DNS 不可用但已找到可直连 IP」时才需要写入")
        self.b_hosts.clicked.connect(self.write_hosts)

        self.b_export = QPushButton("导出报告")
        self.b_export.setCursor(Qt.PointingHandCursor)
        self.b_export.setEnabled(False)
        self.b_export.clicked.connect(self.export_report)

        self.b_clear = QPushButton("清空")
        self.b_clear.setCursor(Qt.PointingHandCursor)
        self.b_clear.clicked.connect(self.clear)

        for button in (self.b_run, self.b_cancel, self.b_hosts,
                       self.b_export, self.b_clear):
            button.setMinimumHeight(34)
            button.setFont(QFont(UI_FONT, 10))
            buttons.addWidget(button)
        buttons.addStretch()
        form.addRow("", self._wrap(buttons))
        layout.addWidget(box)

        # 真实 IP 行
        ip_row = QHBoxLayout()
        ip_row.setSpacing(6)
        self.ip_label = QLabel("真实 IP：待检测")
        self.ip_label.setFont(QFont(UI_FONT, 10, QFont.Bold))
        self.ip_label.setStyleSheet("background:#eef2f7;color:#1e4e8c;"
                                    "border-radius:4px;padding:7px;")
        self.ip_label.setWordWrap(True)
        ip_row.addWidget(self.ip_label, 1)
        self.b_add = QPushButton("+")
        self.b_add.setFixedSize(34, 34)
        self.b_add.setFont(QFont(UI_FONT, 13, QFont.Bold))
        self.b_add.setCursor(Qt.PointingHandCursor)
        self.b_add.setToolTip("把真实 IP 填入「指定 IP」栏")
        self.b_add.setStyleSheet("background:#2b6cb0;color:white;border:none;"
                                 "border-radius:4px;")
        self.b_add.setEnabled(False)
        self.b_add.clicked.connect(self.fill_ip)
        ip_row.addWidget(self.b_add)
        layout.addWidget(self._wrap(ip_row))

        # 结论横幅
        self.banner = QLabel("等待检测")
        self.banner.setFont(QFont(UI_FONT, 11, QFont.Bold))
        self.banner.setStyleSheet(CSS_IDLE)
        self.banner.setWordWrap(True)
        self.banner.setMinimumHeight(48)
        layout.addWidget(self.banner)

        # 进度
        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.pbar.setFixedHeight(8)
        self.pbar.setTextVisible(False)
        layout.addWidget(self.pbar)

        # 日志 | 结果
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        log_box = QWidget()
        log_layout = QVBoxLayout(log_box)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(4)
        log_title = QLabel("检测日志")
        log_title.setFont(QFont(UI_FONT, 9, QFont.Bold))
        log_title.setStyleSheet("color:#5a6472;")
        log_layout.addWidget(log_title)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont(MONO, 9))
        self.log.setStyleSheet("background:#fbfcfd;border:1px solid #e3e7ec;")
        log_layout.addWidget(self.log, 1)
        splitter.addWidget(log_box)

        result_box = QWidget()
        result_layout = QVBoxLayout(result_box)
        result_layout.setContentsMargins(0, 0, 0, 0)
        result_layout.setSpacing(4)
        result_title = QLabel("检测结果")
        result_title.setFont(QFont(UI_FONT, 9, QFont.Bold))
        result_title.setStyleSheet("color:#5a6472;")
        result_layout.addWidget(result_title)
        self.result_view = QTextBrowser()
        self.result_view.setOpenExternalLinks(True)
        self.result_view.setStyleSheet("background:#ffffff;border:1px solid #e3e7ec;")
        result_layout.addWidget(self.result_view, 1)
        splitter.addWidget(result_box)

        splitter.setSizes([300, 680])
        layout.addWidget(splitter, 1)

        self._welcome()
        return page

    def _build_batch_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 10, 4, 4)
        layout.setSpacing(8)

        box = QGroupBox("批量检测")
        form = QFormLayout(box)
        self.batch_input = QPlainTextEdit()
        self.batch_input.setFont(QFont(MONO, 10))
        self.batch_input.setPlaceholderText(
            "每行一个域名，或用逗号 / 空格分隔，例如：\n"
            "github.com\nwww.google.com\nexample.com")
        self.batch_input.setFixedHeight(96)
        form.addRow("域名列表", self.batch_input)

        row = QHBoxLayout()
        self.b_batch_run = QPushButton("开始批量检测")
        self.b_batch_run.setFont(QFont(UI_FONT, 10, QFont.Bold))
        self.b_batch_run.setCursor(Qt.PointingHandCursor)
        self.b_batch_run.setStyleSheet("background:#2b6cb0;color:white;border:none;"
                                       "padding:8px 18px;border-radius:4px;")
        self.b_batch_run.clicked.connect(self.start_batch)

        self.b_batch_stop = QPushButton("停止")
        self.b_batch_stop.setCursor(Qt.PointingHandCursor)
        self.b_batch_stop.setEnabled(False)
        self.b_batch_stop.clicked.connect(self.stop_batch)

        self.b_batch_export = QPushButton("导出 CSV")
        self.b_batch_export.setCursor(Qt.PointingHandCursor)
        self.b_batch_export.setEnabled(False)
        self.b_batch_export.clicked.connect(self.export_batch)

        for button in (self.b_batch_run, self.b_batch_stop, self.b_batch_export):
            button.setMinimumHeight(34)
            button.setFont(QFont(UI_FONT, 10))
            row.addWidget(button)
        row.addStretch()
        form.addRow("", self._wrap(row))
        layout.addWidget(box)

        self.batch_bar = QProgressBar()
        self.batch_bar.setRange(0, 100)
        self.batch_bar.setValue(0)
        self.batch_bar.setFixedHeight(8)
        self.batch_bar.setTextVisible(False)
        layout.addWidget(self.batch_bar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["域名", "结论", "阻断点", "真实 IP", "HTTP", "耗时"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column in range(1, 6):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        self.table.setStyleSheet("QTableWidget{background:#ffffff;"
                                 "alternate-background-color:#fbfcfd;"
                                 "border:1px solid #e3e7ec;}"
                                 "QHeaderView::section{background:#f0f2f5;"
                                 "border:none;border-bottom:1px solid #e3e7ec;"
                                 "padding:6px;font-weight:bold;}")
        layout.addWidget(self.table, 1)
        return page

    def _wrap(self, layout) -> QWidget:
        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _welcome(self) -> None:
        self.result_view.setHtml(
            "<div style='font-family:\"Microsoft YaHei UI\";font-size:10pt;"
            "color:#4a5058;line-height:1.7;'>"
            "<p style='font-size:12pt;font-weight:bold;color:#1a1d21;'>"
            "输入域名后点「开始检测」</p>"
            "<p>工具会依次检查：</p>"
            "<ol>"
            "<li>6 家 DNS + 3 个加密 DNS 并发解析，判断是否被污染</li>"
            "<li>并发逐 IP 做 TCP / TLS / HTTP 探测，用证书 SAN 判定 IP 真身</li>"
            "<li>定位阻断点：DNS / TCP / TLS-SNI / 应用层 / 本机代理</li>"
            "<li>能连给优化建议，不能连给原因和可执行的处理方式</li>"
            "<li>只有在 hosts 真能解决时才给出可粘贴的条目</li>"
            "</ol>"
            "<p style='color:#7c848e;'>提示：结论区会说明「为什么这么判」。"
            "如果控制组全部不通，说明本机出网受限，此时「连不上」的结论不可信。</p>"
            "</div>")

    # ---------- 单站检测 ----------
    def start(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        raw = self.e_domain.text().strip()
        if not raw:
            QMessageBox.warning(self, "缺少域名", "请先输入要检测的域名，例如 github.com")
            return
        domain = normalize_domain(raw)
        if not domain or "." not in domain:
            QMessageBox.warning(self, "域名格式不正确", "请检查输入的域名：%s" % raw)
            return

        ips = [part.strip() for part in
               self.e_ip.text().replace("，", ",").split(",") if part.strip()]

        self.report = None
        self.b_run.setEnabled(False)
        self.b_run.setText("检测中...")
        self.b_cancel.setEnabled(True)
        self.b_add.setEnabled(False)
        self.b_hosts.setEnabled(False)
        self.b_export.setEnabled(False)
        self.banner.setText("检测中 ...")
        self.banner.setStyleSheet(CSS_BUSY)
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.log.clear()
        self.log.appendPlainText("开始检测 %s%s" % (
            domain, ("　附带 IP：%s" % ", ".join(ips)) if ips else ""))
        self.result_view.setHtml("<div style='padding:16px;color:#7c848e;"
                                 "font-family:\"Microsoft YaHei UI\";'>检测中，请稍候…</div>")
        self.status.setText("正在检测 %s ..." % domain)

        self.worker = AnalyzeWorker(domain, ips, timeout=8.0, parent=self)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_error)
        self.worker.start()

    def on_progress(self, stage: str, message: str, done: int, total: int) -> None:
        text = f"[{done}/{total}] {message}" if total > 0 else message
        self.status.setText("%s · %s" % (stage, text))
        self.log.appendPlainText("[%s] %s" % (stage, text))
        if total > 0:
            self.pbar.setValue(int(done * 100 / total))

    def cancel(self) -> None:
        if not (self.worker and self.worker.isRunning()):
            return
        self.worker.stop()
        self.b_cancel.setEnabled(False)
        self.banner.setText("正在中断 ...")
        self.banner.setStyleSheet(CSS_BUSY)
        self.status.setText("已请求中断，当前阶段结束后停止")
        self.log.appendPlainText("[取消] 已请求中断，当前阶段结束后停止")

    def on_done(self, report) -> None:
        self.report = report
        self.b_run.setEnabled(True)
        self.b_run.setText("开始检测")
        self.b_cancel.setEnabled(False)
        if not report.incomplete:
            self.pbar.setValue(100)

        if report.real_ips:
            self.ip_label.setText("真实 IP：%s　（已通过 TLS 证书校验）"
                                  % "、".join(report.real_ips))
            self.ip_label.setStyleSheet("background:#eef2f7;color:#1e4e8c;"
                                        "border-radius:4px;padding:7px;")
        else:
            self.ip_label.setText("真实 IP：未能确认　（候选 IP 均未通过证书校验）")
            self.ip_label.setStyleSheet("background:#fdeeec;color:#a32d2d;"
                                        "border-radius:4px;padding:7px;")
        self.b_add.setEnabled(bool(report.real_ips))

        verdict = report.verdict
        layer = verdict.layer if verdict else Layer.UNKNOWN
        self.banner.setText("%s　|　阻断点：%s" % (
            verdict.headline if verdict else "未完成",
            LAYER_TEXT.get(layer, layer.value)))
        self.banner.setStyleSheet(LAYER_CSS.get(layer, CSS_WARN))

        self.b_hosts.setEnabled(bool(verdict and verdict.hosts_write_needed))
        self.b_export.setEnabled(True)

        self.result_view.setHtml(rendermod.render_html(report))
        self.result_view.verticalScrollBar().setValue(0)
        self.log.appendPlainText("")
        if report.incomplete:
            self.log.appendPlainText(
                "检测中断：%s（只探测了 %d 个 IP，未探测部分不参与判定）"
                % (report.incomplete, len(report.probes)))
            self.status.setText("已中断（%s）　|　结论不可作为「连不上」的依据"
                                % report.incomplete)
        else:
            self.log.appendPlainText("检测完成。判定：%s"
                                     % (verdict.headline if verdict else "-"))
            self.status.setText("检测完成　|　%d 个候选 IP　|　耗时见日志"
                                % len(report.probes))

    def on_error(self, message: str) -> None:
        self.b_run.setEnabled(True)
        self.b_run.setText("开始检测")
        self.b_cancel.setEnabled(False)
        self.pbar.setValue(0)
        self.banner.setText("检测出错")
        self.banner.setStyleSheet(CSS_BAD)
        self.status.setText("出错")
        self.log.appendPlainText("错误：%s" % message)
        QMessageBox.critical(self, "检测失败", message[:900])

    def fill_ip(self) -> None:
        if not self.report or not self.report.real_ips:
            return
        current = [part.strip() for part in
                   self.e_ip.text().replace("，", ",").split(",") if part.strip()]
        for ip in self.report.real_ips:
            if ip not in current:
                current.append(ip)
        self.e_ip.setText(", ".join(current))
        self.status.setText("已填入指定 IP：%s" % ", ".join(self.report.real_ips))

    # ---------- hosts ----------
    def write_hosts(self) -> None:
        report = self.report
        if not report or not report.verdict or not report.verdict.hosts_write_needed:
            return
        ips = report.verdict.hosts_entry_ips or report.real_ips
        if not ips:
            return
        domain = report.domain

        try:
            ips = hostsmod.validate_ips(ips)
        except hostsmod.HostsError as exc:
            QMessageBox.critical(self, "IP 无效", str(exc))
            return

        removed, added = hostsmod.plan(domain, ips)
        lines = ["将对系统 hosts 文件做如下改动：", "",
                 "文件：%s" % hostsmod.HOSTS_PATH, ""]
        if removed:
            lines.append("替换掉 %d 条该域名的旧条目：" % len(removed))
            for line_no, text in removed:
                lines.append("   第 %d 行    %s" % (line_no, text))
            lines.append("")
        lines.append("新增 %d 条：" % len(added))
        for line in added:
            lines.append("   %s" % line)
        lines += ["", "· 修改前自动备份到 %s" % hostsmod.backup_dir(),
                  "· 写入后自动执行 ipconfig /flushdns",
                  "· 需要管理员权限，可能会弹出 UAC 确认",
                  "", "确定继续吗？"]

        if QMessageBox.question(self, "写入 hosts", "\n".join(lines),
                                QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return

        try:
            message, backup = hostsmod.apply(domain, ips)
        except hostsmod.HostsError as exc:
            if str(exc) == "NEED_ADMIN":
                self._request_admin(domain, ips)
                return
            QMessageBox.critical(self, "写入失败", str(exc))
            return

        ok, detail = hostsmod.flush_dns()
        QMessageBox.information(
            self, "完成",
            "已写入 %s\n\n%s\nDNS 缓存刷新：%s\n\n备份文件：\n%s"
            % (domain, message, "成功" if ok else "失败：%s" % detail, backup))
        self.status.setText("hosts 已更新，建议重新检测一次确认")

    def _request_admin(self, domain: str, ips: list[str]) -> None:
        answer = QMessageBox.question(
            self, "需要管理员权限",
            "写入 hosts 需要管理员权限。\n\n是否以管理员身份重新执行？\n"
            "（会弹出 UAC 确认窗口）",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer != QMessageBox.Yes:
            return
        args = ["hosts", "--write", domain]
        for ip in ips:
            args += ["--ip", ip]
        if hostsmod.relaunch_as_admin(args):
            QMessageBox.information(
                self, "已请求提权",
                "请在弹出的 UAC 窗口中确认。\n完成后可点「开始检测」验证结果。")
        else:
            QMessageBox.warning(self, "提权失败",
                                "无法发起提权请求。请右键以管理员身份运行本程序后重试。")

    # ---------- 导出 ----------
    def export_report(self) -> None:
        if not self.report:
            QMessageBox.information(self, "无内容", "还没有检测结果可导出")
            return
        domain = self.report.domain
        path, selected = QFileDialog.getSaveFileName(
            self, "导出报告", "检测结果-%s.md" % domain,
            "Markdown (*.md);;JSON (*.json);;HTML (*.html);;所有文件 (*.*)")
        if not path:
            return
        try:
            if path.lower().endswith(".json") or "JSON" in selected:
                content = rendermod.render_json(self.report)
            elif path.lower().endswith(".html") or "HTML" in selected:
                content = ("<!DOCTYPE html><html lang='zh-CN'><head>"
                           "<meta charset='utf-8'><title>sitecheck - %s</title>"
                           "</head><body style='margin:28px;background:#fff;'>%s"
                           "</body></html>"
                           % (domain, rendermod.render_html(self.report)))
            else:
                content = rendermod.render_markdown(self.report)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            QMessageBox.information(self, "已导出", path)
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    # ---------- 批量 ----------
    def start_batch(self) -> None:
        if self.batch_worker and self.batch_worker.isRunning():
            return
        raw = self.batch_input.toPlainText().replace("，", ",").replace(",", "\n")
        domains: list[str] = []
        for token in raw.split():
            domain = normalize_domain(token)
            if domain and "." in domain and domain not in domains:
                domains.append(domain)
        if not domains:
            QMessageBox.warning(self, "没有域名", "请先输入至少一个域名")
            return

        self.table.setRowCount(0)
        self.batch_reports = []
        self.b_batch_run.setEnabled(False)
        self.b_batch_stop.setEnabled(True)
        self.b_batch_export.setEnabled(False)
        self.batch_bar.setValue(0)
        self.status.setText("批量检测 %d 个域名 ..." % len(domains))

        self.batch_worker = BatchWorker(domains, timeout=8.0, parent=self)
        self.batch_worker.progress.connect(self.on_batch_progress)
        self.batch_worker.item_done.connect(self.on_batch_item)
        self.batch_worker.finished_all.connect(self.on_batch_done)
        self.batch_worker.start()

    def on_batch_progress(self, domain: str, index: int, total: int) -> None:
        self.status.setText("批量检测 %d/%d：%s" % (index, total, domain))
        self.batch_bar.setValue(int((index - 1) * 100 / total))

    def on_batch_item(self, payload) -> None:
        kind, domain, data, elapsed = payload
        row = self.table.rowCount()
        self.table.insertRow(row)

        if kind == "error":
            cells = [domain, "检测失败", "-", "-", "-", "-"]
        else:
            report = data
            self.batch_reports.append(report)
            verdict = report.verdict
            layer = verdict.layer if verdict else Layer.UNKNOWN
            http_code = "-"
            for probe in report.probes:
                if probe.http and probe.http.status is HttpStatus.OK:
                    http_code = str(probe.http.code)
                    break
            cells = [
                domain,
                (verdict.headline if verdict else "未完成"),
                LAYER_TEXT.get(layer, layer.value),
                ("、".join(report.real_ips[:2]) if report.real_ips else "未确认"),
                http_code,
                "%.1f s" % elapsed,
            ]

        for column, text in enumerate(cells):
            item = QTableWidgetItem(str(text))
            if column == 1:
                layer = Layer.UNKNOWN
                if kind == "ok" and data.verdict:
                    layer = data.verdict.layer
                color = {Layer.SUCCESS: "#1d9e75",
                         Layer.HTTP_REJECT: "#b26a00",
                         Layer.HTTP_NO_RESPONSE: "#b26a00",
                         Layer.PROXY_REQUIRED: "#6b4fa8",
                         Layer.INCONCLUSIVE: "#6b4fa8"}.get(layer, "#c0392b")
                item.setForeground(QColor(color))
            self.table.setItem(row, column, item)

    def on_batch_done(self) -> None:
        self.b_batch_run.setEnabled(True)
        self.b_batch_stop.setEnabled(False)
        self.b_batch_export.setEnabled(bool(self.batch_reports))
        self.batch_bar.setValue(100)
        self.status.setText("批量检测完成：%d 个域名" % self.table.rowCount())

    def stop_batch(self) -> None:
        if self.batch_worker and self.batch_worker.isRunning():
            self.batch_worker.stop()
            self.status.setText("正在停止 ...")

    def export_batch(self) -> None:
        if not self.batch_reports:
            QMessageBox.information(self, "无内容", "还没有可导出的结果")
            return
        path, _selected = QFileDialog.getSaveFileName(
            self, "导出 CSV", "批量检测结果.csv", "CSV (*.csv);;所有文件 (*.*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write("域名,结论,阻断点,真实IP,HTTP状态\n")
                for report in self.batch_reports:
                    verdict = report.verdict
                    http_code = ""
                    for probe in report.probes:
                        if probe.http and probe.http.status is HttpStatus.OK:
                            http_code = str(probe.http.code)
                            break
                    handle.write('"%s","%s","%s","%s","%s"\n' % (
                        report.domain,
                        (verdict.headline if verdict else "").replace('"', "'"),
                        verdict.layer.value if verdict else "",
                        " ".join(report.real_ips),
                        http_code))
            QMessageBox.information(self, "已导出", path)
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    # ---------- 清空 ----------
    def clear(self) -> None:
        self.e_domain.clear()
        self.e_ip.clear()
        self.report = None
        self.ip_label.setText("真实 IP：待检测")
        self.ip_label.setStyleSheet("background:#eef2f7;color:#1e4e8c;"
                                    "border-radius:4px;padding:7px;")
        self.b_add.setEnabled(False)
        self.b_hosts.setEnabled(False)
        self.b_export.setEnabled(False)
        self.banner.setText("等待检测")
        self.banner.setStyleSheet(CSS_IDLE)
        self.pbar.setValue(0)
        self.log.clear()
        self.status.setText("就绪")
        self._welcome()


# ---------------------------------------------------------------- 入口

def _target_encoding(fd: int | None) -> str:
    """决定往这个流里写中文该用什么编码。

    单看 GetConsoleOutputCP() 不够：Git Bash(mintty)、Windows Terminal
    期望 UTF-8，但控制台代码页可能仍是 936(GBK)，中文就成乱码。
    优先级：
        1. Git Bash / Windows Terminal -> UTF-8（最可靠的信号）
        2. 输出是管道或普通文件（含被 shell 重定向）-> UTF-8（现代工具惯例）
        3. 真正的控制台字符设备 -> 跟随控制台代码页

    参数是 CRT 文件描述符；传 None 表示拿不到 fd，按现代终端处理。
    """
    import stat

    if os.environ.get("MSYSTEM") or os.environ.get("WT_SESSION"):
        return "utf-8"
    if fd is None:
        return "utf-8"
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):      # 管道或普通文件
            return "utf-8"
    except OSError:
        return "utf-8"                                   # 判断不了就按现代终端处理

    try:
        import ctypes
        codepage = ctypes.windll.kernel32.GetConsoleOutputCP()
    except Exception:
        codepage = 0
    return {65001: "utf-8", 936: "gbk", 950: "big5", 437: "cp437"}.get(codepage, "mbcs")


def _attach_console() -> None:
    """windowed 进程完全没有标准流时，把输出挂回父进程控制台。"""
    try:
        import ctypes
        import msvcrt
        kernel = ctypes.windll.kernel32
        if not kernel.AttachConsole(-1):          # ATTACH_PARENT_PROCESS
            return

        for name, std_handle, mode in (("stdin", -10, os.O_RDONLY),
                                       ("stdout", -11, os.O_WRONLY),
                                       ("stderr", -12, os.O_WRONLY)):
            handle = kernel.GetStdHandle(std_handle)
            if not handle or handle in (0, -1):
                continue
            try:
                fd = msvcrt.open_osfhandle(handle, mode)
                if mode == os.O_RDONLY:
                    stream = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
                else:
                    stream = os.fdopen(fd, "w",
                                       encoding=_target_encoding(fd),
                                       errors="replace")
                setattr(sys, name, stream)
            except OSError:
                pass
    except Exception:
        pass


def _prepare_console() -> None:
    """让命令行模式的中文输出在各类终端都不乱码。

    两种情况都要管：
      A. 完全没有标准流（双击 exe 时带参数）—— 先 AttachConsole 拿到句柄。
      B. 句柄已经存在（被 shell 重定向到管道/文件）—— 这时 sys.stdout 并不是
         None，但 CPython 按 ANSI 代码页（中文 Windows 是 cp936）初始化它，
         直接写出去就是 GBK 字节，在 UTF-8 终端里全是乱码。必须重新配置编码。
    """
    if getattr(sys, "stdout", None) is None:
        _attach_console()

    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            fd = stream.fileno()
        except Exception:
            fd = None
        wanted = _target_encoding(fd)
        current = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if current == wanted.lower().replace("-", ""):
            continue
        try:
            stream.reconfigure(encoding=wanted, errors="replace")
        except Exception:
            pass


def run() -> int:
    # 带参数 -> 命令行模式，不加载任何 Qt 窗口
    if len(sys.argv) > 1:
        _prepare_console()
        from sitecheck.cli import main as cli_main
        return cli_main(sys.argv[1:])

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("sitecheck")
    app.setApplicationVersion(APP_VERSION)
    window = MainWindow()
    window.show()
    return app.exec_()


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
