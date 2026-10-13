# -*- coding: utf-8 -*-
"""深度服务探测: HTTP/MQTT/RTSP/FTP/Redis/SNMP/HTTPS 证书等。

每个探测都带超时与异常保护, 失败时返回 None (不阻断扫描)。
"""
from __future__ import annotations

import base64
import re
import socket
import ssl
import struct
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .portscan import HTTP_LIKE_PORTS

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) IoT-Security-Scanner/1.0"


# ---------------------------------------------------------------- HTTP
def http_probe(ip: str, port: int, timeout: float = 2.5) -> dict | None:
    """HTTP 服务探测: 状态码/Server/标题/重定向/OPTIONS 危险方法/目录列表。"""
    url = f"http://{ip}:{port}/"
    body = ""
    headers: dict[str, str] = {}
    status = None
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT,
                                    "Connection": "close"})
        with urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
            body = resp.read(16384).decode("utf-8", errors="replace")
    except HTTPError as e:
        status = e.code
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            body = (e.read(16384) or b"").decode("utf-8", errors="replace")
        except Exception:
            body = ""
    except (URLError, OSError, ValueError):
        return None

    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    result = {
        "url": url,
        "status": status,
        "server": headers.get("server"),
        "title": title,
        "www_authenticate": headers.get("www-authenticate"),
        "redirect": headers.get("location"),
        "content_type": headers.get("content-type"),
        "powered_by": headers.get("x-powered-by"),
        "dirlist": bool(re.search(r"directory listing|index of\s*/?",
                                  body, re.I)),
        "dangerous_methods": [],
        "truncated": "",
    }
    if body:
        result["truncated"] = re.sub(r"\s+", " ", body)[:300]

    # OPTIONS 探测危险方法
    try:
        req = Request(url, method="OPTIONS",
                      headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=min(timeout, 1.5)) as resp:
            allow = (resp.headers.get("Allow") or "").upper()
        if re.search(r"\b(PUT|DELETE|MOVE|PROPPATCH)\b", allow):
            result["dangerous_methods"] = re.findall(
                r"\b(PUT|DELETE|MOVE|PROPPATCH)\b", allow)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------- MQTT
def mqtt_anonymous(ip: str, port: int = 1883,
                   timeout: float = 3.0) -> bool | None:
    """尝试无用户名/密码的 MQTT CONNECT; CONNACK rc=0 即允许匿名接入。"""
    try:
        # CONNECT: protoName=MQTT, level=4, flags=0x02(clean), keepalive=60
        pkt = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(pkt)
            data = s.recv(8)
        if len(data) >= 4 and data[0] == 0x20:
            return data[3] == 0x00  # CONNACK return code
        return None
    except OSError:
        return None


# ---------------------------------------------------------------- RTSP
def rtsp_open(ip: str, port: int = 554, timeout: float = 2.5) -> bool | None:
    """对 RTSP 发送 DESCRIBE; 200 OK => 未授权即可观看视频流。"""
    try:
        req = (f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
               f"CSeq: 1\r\nUser-Agent: IoT-Security-Scanner\r\n"
               f"Accept: application/sdp\r\n\r\n")
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req.encode("ascii", "ignore"))
            data = s.recv(512)
        if b"200 OK" in data:
            return True
        if b"401" in data or b"Unauthorized" in data:
            return False
        return None
    except OSError:
        return None


# ---------------------------------------------------------------- FTP
def ftp_anonymous(ip: str, port: int = 21, timeout: float = 4.0) -> bool | None:
    """FTP 匿名登录检测 (USER anonymous / PASS anon@)。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256)
            if not banner.startswith(b"220"):
                return False
            s.sendall(b"USER anonymous\r\n")
            resp = s.recv(256)
            if not (resp.startswith(b"331") or resp.startswith(b"230")):
                return False
            s.sendall(b"PASS anon@example.com\r\n")
            resp = s.recv(256)
            return resp.startswith(b"230")
    except OSError:
        return None


# ---------------------------------------------------------------- Redis
def redis_unauth(ip: str, port: int = 6379, timeout: float = 2.0) -> bool | None:
    """Redis 未授权访问检测: INFO 命令直接返回数据或 NOAUTH。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"INFO\r\n")
            data = s.recv(1024)
        if b"redis_version" in data:
            return True
        if b"NOAUTH" in data or b"protected" in data:
            return True  # 无 AUTH 配置 (受保护模式仅限制外部 IP)
        return None
    except OSError:
        return None


# ---------------------------------------------------------------- SNMP
def _snmp_get_public() -> bytes:
    """构造 SNMPv1 GetRequest (community=public, OID=sysDescr.0)。"""
    def _tlv(tag: int, payload: bytes) -> bytes:
        if len(payload) > 127:  # 简化的长格式编码, 足够小报文使用
            ln = struct.pack(">B", 0x80 | 2) + struct.pack(">H", len(payload))
        else:
            ln = struct.pack(">B", len(payload))
        return bytes([tag]) + ln + payload

    oid = _tlv(0x06, struct.pack(">BBBBBBBB", 0x2B, 6, 1, 2, 1, 1, 1, 0))
    varbind = _tlv(0x30, oid + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01")            # request-id
               + _tlv(0x02, b"\x00")                 # error-status
               + _tlv(0x02, b"\x00")                 # error-index
               + varbind)
    msg = _tlv(0x30, _tlv(0x02, b"\x00")            # version = 0 (SNMPv1)
               + _tlv(0x04, b"public") + pdu)
    return msg


def snmp_public(ip: str, port: int = 161, timeout: float = 2.0) -> bool | None:
    """SNMP public community 探测 (UDP); 收到 GetResponse 即存在默认社区字符串。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_snmp_get_public(), (ip, port))
            data, _ = s.recvfrom(2048)
        # 忽略 OID 不同但响应即说明 community 有效
        return bool(data) and data[:1] == b"\x30"
    except OSError:
        return None


# ---------------------------------------------------------------- HTTPS
def https_cert_info(ip: str, port: int = 443,
                    timeout: float = 3.0) -> dict | None:
    """提取 HTTPS 证书信息 (自签名/过期检测)。"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            with ctx.wrap_socket(s, server_hostname=ip) as ss:
                cert = ss.getpeercert(binary_form=False)
                der = ss.getpeercert(binary_form=True)
        if not cert and not der:
            return None
        subject = dict(x[0] for x in (cert or {}).get("subject", ())) \
            if cert else {}
        issuer = dict(x[0] for x in (cert or {}).get("issuer", ())) \
            if cert else {}
        return {
            "subject_cn": subject.get("commonName"),
            "issuer_cn": issuer.get("commonName"),
            "self_signed": bool(subject) and str(subject) == str(issuer),
            "not_after": (cert or {}).get("notAfter"),
        }
    except Exception:
        return None


# ---------------------------------------------------------------- 汇总
def probe_device(ip: str, open_ports: list[int],
                 timeout: float = 2.0) -> dict:
    """对单台设备执行所有适用的深度探测。返回探测结果 dict。"""
    res: dict = {"http": {}, "checks": {}}
    for port in open_ports:
        if port in HTTP_LIKE_PORTS and port not in res["http"]:
            try:
                res["http"][str(port)] = http_probe(ip, port, timeout)
            except Exception:
                pass
    if 1883 in open_ports:
        res["checks"]["mqtt_anonymous"] = mqtt_anonymous(ip, 1883, timeout)
    if any(p in open_ports for p in (554, 8554)):
        port = 554 if 554 in open_ports else 8554
        res["checks"]["rtsp_open"] = rtsp_open(ip, port, timeout)
    if 21 in open_ports:
        res["checks"]["ftp_anonymous"] = ftp_anonymous(ip, 21, timeout)
    if 6379 in open_ports:
        res["checks"]["redis_unauth"] = redis_unauth(ip, 6379, timeout)
    res["checks"]["snmp_public"] = snmp_public(ip, timeout=timeout)
    if 443 in open_ports or 8443 in open_ports:
        port = 443 if 443 in open_ports else 8443
        info = https_cert_info(ip, port, timeout)
        if info:
            res["checks"]["https_cert"] = info
    return res


def basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"
