# -*- coding: utf-8 -*-
"""主机发现: ICMP Ping 扫荡 + ARP 表合并 + 主机名解析。

多策略融合:
  1. Ping 扫荡整个子网;
  2. 对 ping 不通的主机尝试 TCP 连接通用端口 (触发 ARP、探测 ping 禁用的设备);
  3. 合并本机 ARP 表中的存活条目;
  4. 尽力解析主机名 (mDNS/NBNS/DNS)。
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .utils import arp_table, is_ipv4, ping, resolve_hostname

# ping 失败时尝试连接的端口, 用于触发 ARP 并发现禁 ping 的设备
PROBE_PORTS = (80, 443, 22, 445, 8080)


def _tcp_alive(ip: str, ports: tuple[int, ...] = PROBE_PORTS,
               timeout: float = 0.4) -> bool:
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def discover(cidr: str | None = None, timeout: float = 1.2,
             threads: int = 128,
             progress: Callable[[str, str], None] | None = None,
             network: ipaddress.IPv4Network | None = None) -> list[dict]:
    """发现子网内存活主机, 返回 [{ip, mac, hostname, discovery}, ...]"""
    net = network or (ipaddress.ip_network(cidr, strict=False)
                      if cidr else None)
    if net is None:
        from .utils import detect_network
        net = detect_network()

    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 8192:
        if progress:
            progress("discover", f"警告: 目标网段过大 ({net}), 仅扫描有效主机 "
                                f"{len(hosts)} 个, 可能需要较长时间")

    # 扫描前先读一次 ARP 表, 扫描后再读一次并合并
    arp_before = arp_table()
    alive: dict[str, str] = {}  # ip -> method

    def _probe(ip: str) -> tuple[str, str] | None:
        if ping(ip, timeout):
            return ip, "icmp"
        if _tcp_alive(ip):
            return ip, "tcp"
        if ip in arp_before:
            return ip, "arp"
        return None

    done = 0
    with ThreadPoolExecutor(max_workers=min(threads, max(4, len(hosts)))) as ex:
        futs = [ex.submit(_probe, ip) for ip in hosts]
        for fut in as_completed(futs):
            done += 1
            res = fut.result()
            if res:
                alive[res[0]] = res[1]
            if progress and (done % 64 == 0 or done == len(futs)):
                progress("discover",
                         f"扫描进度 {done}/{len(futs)} ... 已发现 {len(alive)} 台")

    arp_after = arp_table()
    arp_all = {**arp_before, **arp_after}
    for ip in hosts:
        if ip not in alive and ip in arp_all:
            alive[ip] = "arp"

    # 主机名解析 (尽力而为, 线程池并行)
    hostnames: dict[str, str | None] = {}
    ips = list(alive)
    with ThreadPoolExecutor(max_workers=32) as ex:
        futmap = {ex.submit(resolve_hostname, ip): ip for ip in ips}
        for fut in as_completed(futmap):
            ip = futmap[fut]
            try:
                hostnames[ip] = fut.result()
            except Exception:
                hostnames[ip] = None

    devices = []
    for ip in ips:
        devices.append({
            "ip": ip,
            "mac": arp_all.get(ip),
            "hostname": hostnames.get(ip),
            "discovery": alive.get(ip, "arp"),
        })
    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices


def discover_single(ip: str) -> list[dict]:
    """单主机快速探测 (--target 指定单个 IP 时使用)。"""
    if not is_ipv4(ip):
        return []
    ok = ping(ip) or _tcp_alive(ip)
    if not ok:
        return []
    return [{
        "ip": ip,
        "mac": arp_table().get(ip),
        "hostname": resolve_hostname(ip, timeout=1.5),
        "discovery": "direct",
    }]
