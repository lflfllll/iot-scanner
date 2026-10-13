# -*- coding: utf-8 -*-
"""默认凭据检测 (opt-in, 需 --creds 开启)。

仅对自有网络设备测试常见出厂默认口令, 帮助用户发现
"路由器还在用 admin/admin" 这类最高危问题。
"""
from __future__ import annotations

import re
import socket
import urllib.request
from urllib.error import HTTPError, URLError

# 物联网设备常见出厂默认口令 (user, pass)
DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"), ("admin", "123456"), ("admin", ""), ("admin", "password"),
    ("root", "root"), ("root", "123456"), ("root", "xc3511"), ("root", "12345"),
    ("root", ""), ("root", "vizxv"), ("root", "888888"), ("support", "support"),
    ("default", "default"), ("666666", "666666"), ("888888", "888888"),
    ("guest", "guest"), ("service", "service"), ("admin", "1234"),
    ("admin", "1111"), ("user", "user"), ("ubnt", "ubnt"), ("admin", "smcadmin"),
]

TELNET_PROMPT = re.compile(r"(login|user\s*name|用户名|password|密码)",
                           re.IGNORECASE)
FAIL_MARKERS = ("incorrect", "invalid", "failed", "denied", "error",
                "拒绝", "错误", "失败", "login incorrect")
SUCCESS_MARKERS = ("#", "$", ">", "busybox", "welcome", "登录成功", "shell")


def test_telnet(ip: str, port: int, user: str, password: str,
                timeout: float = 4.0) -> bool:
    """最小化 Telnet 登录测试。返回是否登录成功。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(1024)
            if not TELNET_PROMPT.search(data):
                # 服务端可能等待输入
                s.sendall(b"\r\n")
                data = s.recv(1024)
            s.sendall(user.encode() + b"\r\n")
            data = s.recv(1024)
            if b"assword" not in data and "密码" not in \
                    data.decode("utf-8", errors="replace"):
                return False
            s.sendall(password.encode() + b"\r\n")
            data = s.recv(1024)
            text = data.decode("utf-8", errors="replace").lower()
            if any(m in text for m in FAIL_MARKERS):
                return False
            if any(m in text for m in SUCCESS_MARKERS):
                return True
            # 再探测一次 shell 提示符
            s.sendall(b"\r\n")
            follow = s.recv(512).decode("utf-8", errors="replace")
            return any(m in follow for m in SUCCESS_MARKERS)
    except OSError:
        return False


def test_http_basic(ip: str, port: int, path: str, user: str, password: str,
                    timeout: float = 4.0) -> bool:
    """HTTP Basic 认证测试。200 即成功。"""
    import base64
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    url = f"http://{ip}:{port}{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Authorization": f"Basic {token}",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except HTTPError:
        return False
    except (URLError, OSError, ValueError):
        return False


def test_ftp(ip: str, port: int, user: str, password: str,
             timeout: float = 4.0) -> bool:
    """FTP 登录测试。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if not s.recv(128).startswith(b"220"):
                return False
            s.sendall(f"USER {user}\r\n".encode())
            resp = s.recv(128)
            if not (resp.startswith(b"331") or resp.startswith(b"230")):
                return False
            s.sendall(f"PASS {password}\r\n".encode())
            data = s.recv(128)
            return data.startswith(b"230")
    except OSError:
        return False


def test_device(device: dict, creds: list[tuple[str, str]] | None = None,
                stop_on_first: bool = True,
                progress=None) -> list[dict]:
    """对单设备尝试默认凭据 (Telnet / HTTP Basic / FTP)。"""
    creds = creds or DEFAULT_CREDS
    results: list[dict] = []
    ports = device.get("open_ports") or []
    services = device.get("services") or {}

    for port in ports:
        svc = services.get(port) or services.get(str(port)) or {}
        http_info = (device.get("probes", {}).get("http") or {}).get(str(port))
        # --- Telnet
        if port in (23, 2323, 26):
            for user, pw in creds:
                if progress:
                    progress(f"凭据测试 {device['ip']}:{port} "
                              f"{user}/{'*' * len(pw) or '(空)'}")
                if test_telnet(device["ip"], port, user, pw):
                    results.append({"protocol": "Telnet", "port": port,
                                    "username": user, "password": pw,
                                    "success": True})
                    if stop_on_first:
                        break
            else:
                results.append({"protocol": "Telnet", "port": port,
                                "username": "-", "password": "-",
                                "success": False})
        # --- HTTP Basic (仅对返回 401 或登录页的端口)
        if port in (80, 8080, 8000, 8008, 8009, 8888, 8081, 81) and (
                (http_info or {}).get("www_authenticate") or
                ((http_info or {}).get("title") and
                 re.search(r"(?i)login|sign in|登录|管理",
                           (http_info or {}).get("title") or ""))):
            for user, pw in creds:
                if progress:
                    progress(f"凭据测试 {device['ip']}:{port}(HTTP) "
                              f"{user}/{'*' * len(pw) or '(空)'}")
                if test_http_basic(device["ip"], port, "/", user, pw):
                    results.append({"protocol": "HTTP Basic", "port": port,
                                    "username": user, "password": pw,
                                    "success": True})
                    if stop_on_first:
                        break
            else:
                results.append({"protocol": "HTTP Basic", "port": port,
                                "username": "-", "password": "-",
                                "success": False})
        # --- FTP
        if port == 21:
            for user, pw in creds:
                if test_ftp(device["ip"], port, user, pw):
                    results.append({"protocol": "FTP", "port": port,
                                    "username": user, "password": pw,
                                    "success": True})
                    if stop_on_first:
                        break
            else:
                results.append({"protocol": "FTP", "port": port,
                                "username": "-", "password": "-",
                                "success": False})
    return results


def creds_findings(creds_results: list[dict]) -> list[dict]:
    """把凭据测试结果转成 finding (仅成功项, 这是最高危的问题)。"""
    findings = []
    for r in creds_results:
        if not r.get("success"):
            continue
        protocol, port = r["protocol"], r["port"]
        pw_display = r["password"] or "(空密码)"
        findings.append({
            "rule_id": "DEFAULT-CREDS",
            "title": f"设备仍在使用默认凭据 ({protocol}:{port})",
            "severity": "critical",
            "category": "凭证安全",
            "cwe": "CWE-521",
            "cvss": 9.8,
            "description": (
                f"设备 {protocol} 服务（端口 {port}）可使用默认凭据 "
                f"{r['username']}/{pw_display} 直接登录。这是 Mirai、"
                f"Mozi 等僵尸网络最常用的入侵方式，也意味着内网任何人都"
                f"能接管该设备。"),
            "recommendation": (
                "立即登录设备修改为 12 位以上强密码（大小写+数字+符号）；"
                "检查路由器是否已将设备暴露到公网；无法修改口令的设备"
                "应更换或升级固件。"),
            "refs": ["CWE-521", "Mirai", "CISA 默认口令清单"],
            "credential": {"username": r["username"], "password": r["password"],
                           "protocol": protocol, "port": port},
        })
    return findings
