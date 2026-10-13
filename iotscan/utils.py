# -*- coding: utf-8 -*-
"""通用工具: 颜色输出、本机网络信息探测、命令执行、主机名解析。"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

IS_WINDOWS = platform.system().lower().startswith("win")
if IS_WINDOWS:
    os.system("")  # 让 Windows 终端支持 ANSI 颜色

C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m",
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_STYLE = {
    "critical": ("red", True), "high": ("red", False),
    "medium": ("yellow", False), "low": ("blue", False),
    "info": ("gray", False),
}
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危",
          "low": "低危", "info": "提示"}

# 漏洞类别中文名
CATEGORY_CN = {
    "服务暴露": "服务暴露", "访问控制": "访问控制", "传输安全": "传输安全",
    "视频监控": "视频监控", "物联网协议": "物联网协议", "已知漏洞": "已知漏洞",
    "攻击面": "攻击面", "凭证安全": "凭证安全", "信息泄露": "信息泄露",
    "僵尸网络": "僵尸网络", "日志与配置": "日志与配置",
}

# 每个环节的说明文案
SCAN_PHASES = [
    ("discover", "主机发现"),
    ("portscan", "端口扫描"),
    ("fingerprint", "指纹识别"),
    ("probes", "深度探测"),
    ("vulncheck", "漏洞分析"),
    ("reporting", "生成报告"),
]


def color(text: str, key: str, bold: bool = False) -> str:
    if not key or not sys.stdout.isatty():
        return text
    code = C.get(key, "")
    return f"{C['bold'] if bold else ''}{code}{text}{C['reset']}"


def sev_badge(sev: str) -> str:
    key, bold = SEV_STYLE.get(sev, ("gray", False))
    return color(f"[{SEV_CN.get(sev, sev)}]", key, bold)


def sev_cn(sev: str) -> str:
    return SEV_CN.get(sev, sev)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def fmt_dur(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} 毫秒"
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    m, s = divmod(seconds, 60)
    return f"{int(m)} 分 {s:.1f} 秒"


def run(cmd: list[str], timeout: float = 15) -> tuple[int, str, str]:
    """运行外部命令, 返回 (返回码, stdout, stderr)。异常安全。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           text=True, errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception:
        return -1, "", ""


def default_route_ip() -> str | None:
    """通过 UDP connect 技巧获取本机默认出口 IP (不产生真实流量)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip if ip and not ip.startswith("127.") else None
    except OSError:
        return None
    finally:
        s.close()


def detect_network() -> ipaddress.IPv4Network:
    """探测本机所在网段 (CIDR)。优先使用平台命令获取真实掩码, 失败回退 /24。"""
    ip = default_route_ip()
    if not ip:
        raise RuntimeError("无法确定本机 IP, 请使用 --target 指定扫描目标")
    prefix: int | None = None
    if IS_WINDOWS:
        rc, out, _ = run([
            "powershell", "-NoProfile", "-Command",
            f"(Get-NetIPAddress -AddressFamily IPv4 | "
            f"Where-Object {{$_.IPAddress -eq '{ip}'}}).PrefixLength",
        ], timeout=20)
        m = re.search(r"\b(\d{1,2})\b", out or "")
        if m:
            prefix = int(m.group(1))
    else:
        rc, out, _ = run(["ip", "-4", "-o", "addr", "show"], timeout=5)
        for line in out.splitlines():
            m = re.search(r"inet\s+%s/(\d+)" % re.escape(ip), line)
            if m:
                prefix = int(m.group(1))
                break
        if prefix is None:
            rc, out, _ = run(["ip", "route", "show", "default"], timeout=5)
            m = re.search(r"default via \S+ dev (\S+)", out or "")
            if m:
                dev = m.group(1)
                rc, out, _ = run(["ip", "-4", "-o", "addr", "show", "dev", dev], 5)
                m = re.search(r"inet\s+\S+/(\d+)", out or "")
                if m:
                    prefix = int(m.group(1))
    if prefix is None or not (8 <= prefix <= 32):
        prefix = 24
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def ping(ip: str, timeout: float = 1.0) -> bool:
    """ICMP Ping 单个主机。"""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    rc, out, _ = run(cmd, timeout=timeout + 3)
    if rc == 0:
        return True
    # 部分系统 rc 非 0 但实际有回应
    return bool(re.search(r"(TTL|ttl)=\d+", out or ""))


def arp_table() -> dict[str, str]:
    """解析 ARP 表, 返回 {ip: mac}。兼容 Windows / Linux(net-tools)。"""
    table: dict[str, str] = {}
    rc, out, _ = run(["arp", "-a"], timeout=8)
    if out:
        for line in out.splitlines():
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+.*?(([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})",
                line)
            if m:
                mac = m.group(2).replace("-", ":").lower()
                table[m.group(1)] = mac
    if not IS_WINDOWS and not table:
        rc, out, _ = run(["ip", "neigh"], timeout=8)
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+"
                          r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
            if m:
                table[m.group(1)] = m.group(2).lower()
    return table


def resolve_hostname(ip: str, timeout: float = 2.0) -> str | None:
    """尽力解析主机名 (阻塞 DNS/NBNS 查询, 失败返回 None)。"""
    def _job():
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None
        finally:
            socket.setdefaulttimeout(old)

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(_job).result(timeout=timeout + 1.5)
    except Exception:
        return None


def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def disp_width(s: str) -> int:
    """字符串显示宽度 (中文/全角算 2 列)。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1
               for ch in str(s))


def pad(s: str, width: int) -> str:
    """按显示宽度右填充空格 (中文对齐用)。"""
    return str(s) + " " * max(0, width - disp_width(s))
