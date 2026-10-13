# -*- coding: utf-8 -*-
"""端口扫描: 多线程 TCP 连接扫描 + 服务 Banner 抓取。"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

# IoT / 智能家居设备常见端口清单 (48 项, 覆盖路由器/摄像头/音箱/打印机/NAS/工控等)
TOP_IOT_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 515: "LPD", 548: "AFP", 554: "RTSP",
    587: "SMTP-TLS", 631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1883: "MQTT", 1900: "UPnP", 2000: "MikroTik-BW",
    2323: "Telnet-alt", 3128: "HTTP-Proxy", 3289: "DICOM?", 3306: "MySQL",
    3389: "RDP", 4444: "?", 48101: "?", 5000: "UPnP-alt", 5001: "HTTPS-alt",
    5060: "SIP", 5228: "GCM", 5432: "PostgreSQL", 5555: "ADB", 5683: "CoAP",
    5900: "VNC", 5901: "VNC", 6379: "Redis", 6667: "IRC", 7547: "TR-069",
    8000: "HTTP-alt", 8008: "HTTP-alt", 8080: "HTTP-Proxy", 8081: "HTTP-alt",
    8443: "HTTPS-alt", 8554: "RTSP-alt", 8883: "MQTT-TLS", 8888: "HTTP-alt",
    9000: "HTTP-alt", 9001: "HTTP-alt", 9100: "JetDirect", 27017: "MongoDB",
    37777: "Dahua-DVR", 34567: "DVR-alt", 49152: "UPnP-dyn", 49153: "UPnP-dyn",
    62078: "iPhone-Sync", 8291: "MikroTik-Winbox", 8728: "MikroTik-API",
    8729: "MikroTik-API-SSL", 11211: "Memcached", 9300: "Elasticsearch",
    502: "Modbus", 102: "S7", 2375: "Docker-API", 9200: "Elastic-REST",
    44818: "EtherNet/IP", 20000: "DNP3", 5353: "mDNS", 7547: "TR-069",
}
TOP_IOT_PORTS = dict(sorted(TOP_IOT_PORTS.items()))

# 全端口模式时的范围
FULL_RANGE = (1, 1024)

HTTP_LIKE_PORTS = {80, 81, 443, 591, 3000, 3128, 5000, 5001, 8000, 8008, 8009,
                   8080, 8081, 8082, 8443, 8444, 8800, 8888, 9000, 9001, 9002}


def resolve_ports(spec: str | None, full: bool = False) -> list[int]:
    """解析 --ports 参数: 'top'(默认) / 'full' / '1-1024' / '80,443,8080'。"""
    if full:
        ports = list(range(FULL_RANGE[0], FULL_RANGE[1] + 1))
        ports += list(TOP_IOT_PORTS)
        return sorted(set(ports))
    if not spec or spec == "top":
        return sorted(TOP_IOT_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def _connect(ip: str, port: int, timeout: float) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port))
    finally:
        s.close()


def scan_host(ip: str, ports: list[int] | None = None, timeout: float = 0.5,
              threads: int = 128) -> list[int]:
    """对单主机执行 TCP 连接扫描, 返回开放端口列表。"""
    ports = ports if ports is not None else sorted(TOP_IOT_PORTS)
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=min(threads, 256)) as ex:
        futs = {ex.submit(_connect, ip, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            if fut.result() == 0:
                open_ports.append(futs[fut])
    return sorted(open_ports)


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """抓取服务 Banner。HTTP 类端口主动发送 GET, 其余等待服务端主动横幅。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_LIKE_PORTS:
                req = (f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                       f"User-Agent: Mozilla/5.0 (compatible; IoTScanner/1.0)\r\n"
                       f"Accept: */*\r\nConnection: close\r\n\r\n")
                s.sendall(req.encode("ascii", "ignore"))
            elif port in (22, 2222):
                pass  # SSH/FTP/Telnet/SMTP 等服务会主动发送横幅
            else:
                s.sendall(b"\r\n")  # 某些服务需要客户端先发送数据
            chunks: list[bytes] = []
            total = 0
            while total < 4096:
                try:
                    data = s.recv(1024)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if b"\r\n\r\n" in b"".join(chunks) and port in HTTP_LIKE_PORTS:
                    break
            return _clean(b"".join(chunks))
    except OSError:
        return ""


def _clean(raw: bytes) -> str:
    """清理 Banner: 去控制字符/非可打印字符, 压缩空行, 截断超长内容。"""
    text = raw.decode("utf-8", errors="replace")
    lines = []
    for line in text.splitlines():
        line = "".join(ch for ch in line if ch == "\t" or 32 <= ord(ch) < 127)
        line = line.strip()
        if line:
            lines.append(line)
    out = "\n".join(lines)
    return out[:600]


def service_name(port: int) -> str:
    return TOP_IOT_PORTS.get(port, "unknown")
