# -*- coding: utf-8 -*-
"""扫描编排: discovery -> portscan -> fingerprint -> probes -> vulns -> scoring -> report。

同时提供 demo_result(): 一套贴近真实家庭网络的设备画像,
用于离线演示报告生成流程 (规则引擎真实执行)。
"""
from __future__ import annotations

import time
import ipaddress

from . import creds as creds_mod
from . import discovery, fingerprint, portscan, probes, vulns
from .scoring import device_score, network_summary
from .utils import detect_network, is_ipv4, now_str


class Progress:
    """扫描进度回调 (phase, message)。"""

    def __init__(self, quiet: bool = False, stream=None):
        self.quiet = quiet
        self.stream = stream

    def __call__(self, phase: str, message: str) -> None:
        if self.quiet:
            return
        from .utils import C, color
        phase_cn = dict(host_discovery="主机发现", port_scan="端口扫描",
                        fingerprinting="指纹识别", deep_probing="深度探测",
                        rule_check="规则引擎", report="生成报告")
        tag = phase_cn.get(phase, phase)
        line = f"  {color('[' + tag + ']', 'cyan')} {message}"
        print(line, file=self.stream, flush=True)


def _build_device(base: dict) -> dict:
    """填充指纹/探测结构化字段, 返回完整设备 dict。"""
    d = dict(base)
    d.setdefault("discovery", "icmp")
    # services: 保持 {port: {"name","banner","http"}} 结构
    for p in d.get("open_ports", []):
        svc = d["_services"].get(p, {})
        d.setdefault("services", {})[p] = {
            "name": portscan.service_name(p),
            "banner": svc.get("banner", ""),
            "http": (d.get("probes", {}).get("http", {}) or {}).get(str(p)),
        }
    d.pop("_services", None)
    fingerprint.classify(d)
    return d


def run_scan(target: str | None = None, ports_spec: str | None = None,
             full: bool = False, timeout: float = 0.6,
             threads: int = 128, creds: bool = False,
             progress: Progress | None = None) -> dict:
    """完整扫描流程, 返回 result dict (供 report/json/html 消费)。"""
    progress = progress or Progress()
    t0 = time.time()
    meta = {"start_time": now_str(), "target": target or "auto",
            "mode": "live"}

    # 1. 主机发现
    if target and is_ipv4(target):
        devices = discovery.discover_single(target)
        meta["target"] = target
        progress("host_discovery", f"单主机探测 {target}: "
                                  f"{'在线' if devices else '不在线'}")
    else:
        net = None
        if target:
            net = ipaddress.ip_network(target, strict=False)
        else:
            net = detect_network()
        n_hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
        if n_hosts > 20000:
            raise RuntimeError(
                f"目标网段 {net} 含 {n_hosts} 台主机, 扫描时间过长。"
                f"请用 --target 指定更小的网段 (如 {net.network_address}/24)")
        if n_hosts > 4096:
            est_min = n_hosts * max(timeout, 1.0) / threads / 60
            progress("host_discovery",
                     f"警告: {net} 含 {n_hosts} 台主机, 预计耗时约 {est_min:.0f} 分钟")
        devices = discovery.discover(progress=progress, threads=threads,
                                     timeout=max(timeout, 1.0), network=net)
        meta["target"] = str(net)
        progress("host_discovery", f"发现 {len(devices)} 台在线主机")

    ports = portscan.resolve_ports(ports_spec, full)
    progress("port_scan", f"端口清单: {len(ports)} 个端口/主机, "
                          f"连接超时 {timeout}s")

    # 逐设备: 端口扫描 -> 指纹 -> 深度探测 -> 规则评估
    from concurrent.futures import ThreadPoolExecutor
    results: list[dict] = []

    def _scan_one(dev: dict) -> dict:
        open_ports = portscan.scan_host(dev["ip"], ports, timeout=timeout,
                                        threads=min(threads, 256))
        d = dict(dev)
        d["open_ports"] = open_ports
        # banner
        services: dict[int, dict] = {}
        for p in open_ports:
            services[p] = {"name": portscan.service_name(p),
                           "banner": portscan.grab_banner(dev["ip"], p,
                                                          timeout=max(timeout, 1.2))}
        # 深度探测
        probe_res = probes.probe_device(dev["ip"], open_ports,
                                        timeout=max(timeout, 1.5))
        d["probes"] = probe_res
        for p in open_ports:
            services[p]["http"] = (probe_res.get("http", {}) or {}).get(str(p))
        d["services"] = services
        fingerprint.classify(d)
        d["findings"] = vulns.evaluate(d)
        if creds:
            cr = creds_mod.test_device(d, progress=progress)
            d["creds_results"] = cr
            d["findings"] = vulns.evaluate(d) + creds_mod.creds_findings(cr)
        d["score"] = device_score(d["findings"])
        return d

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(devices)))) as ex:
        for i, d in enumerate(ex.map(_scan_one, devices), 1):
            results.append(d)
            progress("deep_probing",
                     f"({i}/{len(devices)}) {d['ip']}: "
                     f"{len(d['open_ports'])} 个开放端口, "
                     f"{len(d['findings'])} 项风险")

    # 3. 汇总
    results.sort(key=lambda x: x["score"]["score"])
    summary = network_summary(results)
    meta["duration"] = round(time.time() - t0, 2)
    meta["ports_scanned"] = len(ports)
    meta["rules_loaded"] = len(vulns.RULES)
    meta["creds_tested"] = bool(creds)
    return {"meta": meta, "summary": summary, "devices": results}


# ================================================================ DEMO 数据
def demo_result() -> dict:
    """构造一套典型家庭网络设备画像, 走真实规则引擎生成报告。

    模拟设备含: 路由器/摄像头/音箱/打印机/NAS/电视/恒温器/开发板等,
    覆盖全部严重级漏洞, 便于无网络环境下预览报告效果。
    """
    devices = [
        # ---------------- 路由器 ----------------
        dict(ip="192.168.1.1", mac="50:C7:BF:2A:91:34",
             hostname="Router.lan", discovery="icmp",
             open_ports=[53, 80, 443, 1900],
             _services={
                 53: {"banner": "dnsmasq 2.80"},
                 80: {"banner": "HTTP/1.1 200 OK\r\nServer: Boa/0.94.14rc21\r\n"
                                "Content-Type: text/html"},
                 443: {"banner": "TLSv1.2 - APACHE mini"},
                 1900: {"banner": "HTTP/1.1 200 OK - SSDP Linux UPnP/1.0 TP-Link"},
             },
             probes={
                 "http": {"80": {"status": 200, "server": "Boa/0.94.14rc21",
                                 "title": "TP-Link Router TL-WR886N - Firmware "
                                          "1.0.6 Build 180119 Rel.58504",
                                 "dirlist": False, "dangerous_methods": [],
                                 "www_authenticate": None}},
                 "checks": {"snmp_public": None},
             }),
        # ---------------- 海康威视摄像头 (默认凭据 + 无认证 RTSP) ----------------
        dict(ip="192.168.1.101", mac="44:19:B6:0C:4D:22",
             hostname="hik-cam-frontdoor", discovery="icmp",
             open_ports=[23, 80, 554, 8000],
             _services={
                 23: {"banner": "Welcome to HiLinux\r\n(none) login: "},
                 80: {"banner": "HTTP/1.1 200 OK\r\nServer: App-webs/\r\n"
                                "WWW-Authenticate: Basic realm=\"DS-2CD2T47\""},
                 554: {"banner": "RTSP/1.0 200 OK"},
                 8000: {"banner": "HTTP/1.1 200 OK - DNVRS-Webs"},
             },
             probes={
                 "http": {"80": {"status": 401, "server": "App-webs/",
                                 "title": "login",
                                 "www_authenticate": "Basic realm=\"DS-2CD2T47\"",
                                 "dirlist": False, "dangerous_methods": []}},
                 "checks": {"rtsp_open": True, "snmp_public": None},
             },
             creds_results=[{"protocol": "Telnet", "port": 23, "username": "root",
                             "password": "12345", "success": True}]),
        # ---------------- 亚马逊智能音箱 ----------------
        dict(ip="192.168.1.102", mac="44:65:0D:88:2E:11",
             hostname="echo-living-room", discovery="icmp",
             open_ports=[4070, 8008, 8888],
             _services={
                 4070: {"banner": "Amazon Dash Setup"},
                 8008: {"banner": "Cast HTTP"},
                 8888: {"banner": "HTTP/1.1 200 OK - alexa local hub"},
             },
             probes={"http": {"8888": {"status": 200, "server": "",
                                       "title": "Amazon Echo", "dirlist": False,
                                       "dangerous_methods": []}},
                     "checks": {"snmp_public": None}}),
        # ---------------- HP 打印机 ----------------
        dict(ip="192.168.1.103", mac="3C:D9:2B:71:0F:5C",
             hostname="HP-LaserJet-Pro", discovery="icmp",
             open_ports=[515, 631, 9100],
             _services={
                 515: {"banner": "LPD spooler"},
                 631: {"banner": "IPP LaserJet Pro MFP M428fdn"},
                 9100: {"banner": "HP JetDirect - ready"},
             },
             probes={"http": {"631": {"status": 200, "server": "LightHTTPD",
                                      "title": "HP LaserJet Pro MFP M428fdn - Ready",
                                      "dirlist": False, "dangerous_methods": []}},
                     "checks": {"snmp_public": None}}),
        # ---------------- 群晖 NAS (旧版 OpenSSH + SMB) ----------------
        dict(ip="192.168.1.104", mac="00:11:32:4E:6A:8B",
             hostname="NAS-DS220", discovery="icmp",
             open_ports=[22, 80, 443, 445, 5000, 5001],
             _services={
                 22: {"banner": "SSH-2.0-OpenSSH_7.4"},
                 80: {"banner": "HTTP/1.1 200 OK\r\nServer: nginx"},
                 443: {"banner": "TLSv1.2 - nginx"},
                 445: {"banner": "SMB 3.1.1 (Samba 3.6.9 unix)"},
                 5000: {"banner": "Synology DSM"},
             },
             probes={
                 "http": {"80": {"status": 200, "server": "nginx",
                                 "title": "Synology DiskStation | DSM 6.2.4-25556",
                                 "dirlist": False, "dangerous_methods": []}},
                 "checks": {"snmp_public": None}},
             https={"subject_cn": "NAS-DS220", "self_signed": True}),
        # ---------------- 乐鑫智能插座 ----------------
        dict(ip="192.168.1.105", mac="24:0A:C4:11:9F:02",
             hostname=None, discovery="arp",
             open_ports=[80],
             _services={
                 80: {"banner": "HTTP/1.1 200 OK - Tasmota 12.3.1(sonoff)"},
             },
             probes={"http": {"80": {"status": 200, "server": "Tasmota",
                                     "title": "Tasmota 智能插座 - 固件 12.3.1",
                                     "dirlist": False, "dangerous_methods": []}},
                     "checks": {"snmp_public": None}}),
        # ---------------- 大华 DVR ----------------
        dict(ip="192.168.1.106", mac="90:02:A9:3B:C1:77",
             hostname="dvr-garage", discovery="icmp",
             open_ports=[23, 80, 554, 37777, 34567],
             _services={
                 23: {"banner": "Dahua DVR telnet - login:"},
                 80: {"banner": "HTTP/1.1 200 OK\r\nServer: GoAhead-Webs\r\n"
                                "Content-Type: text/html"},
                 554: {"banner": "RTSP/1.0 200 OK"},
                 37777: {"banner": "Dahua P2P protocol"},
             },
             probes={
                 "http": {"80": {"status": 200, "server": "GoAhead-Webs",
                                 "title": "Dahua 网络硬盘录像机 DH-NVR4108",
                                 "dirlist": False, "dangerous_methods": []}},
                 "checks": {"rtsp_open": True, "snmp_public": None}},
             creds_results=[{"protocol": "HTTP Basic", "port": 80,
                             "username": "admin", "password": "admin",
                             "success": True}]),
        # ---------------- 小米电视 (ADB 开放) ----------------
        dict(ip="192.168.1.107", mac="64:09:80:5A:32:B6",
             hostname="Xiaomi-TV", discovery="icmp",
             open_ports=[5555, 8008, 8009],
             _services={
                 5555: {"banner": "Android Debug Bridge daemon"},
                 8008: {"banner": "Google Cast"},
             },
             probes={"http": {}, "checks": {"snmp_public": None}}),
        # ---------------- Honeywell 恒温器 (健康设备) ----------------
        dict(ip="192.168.1.108", mac="00:20:3D:D1:44:9A",
             hostname="thermostat-hall", discovery="icmp",
             open_ports=[8883, 443],
             _services={
                 8883: {"banner": "TLS - Honeywell Home Weave"},
                 443: {"banner": "TLSv1.2 - Honeywell Cloud"},
             },
             probes={"http": {}, "checks": {"snmp_public": None}}),
        # ---------------- 旧树莓派 (Redis 未授权 + 旧 OpenSSH) ----------------
        dict(ip="192.168.1.109", mac="D8:3A:DD:45:71:F3",
             hostname="raspberrypi", discovery="arp",
             open_ports=[22, 6379, 8080],
             _services={
                 22: {"banner": "SSH-2.0-OpenSSH_7.6p1 Debian-4"},
                 6379: {"banner": "Redis 5.0.7 - ready"},
                 8080: {"banner": "HTTP/1.1 200 OK - Tornado/6.0.4"},
             },
             probes={
                 "http": {"8080": {"status": 200, "server": "Tornado/6.0.4",
                                   "title": "Home Assistant - 固件版本 2021.3.4",
                                   "dirlist": True, "dangerous_methods": []}},
                 "checks": {"redis_unauth": True, "snmp_public": None}}),
        # ---------------- Windows 笔记本 ----------------
        dict(ip="192.168.1.112", mac="8C:16:45:0E:5C:1D",
             hostname="LAPTOP-MAIN", discovery="icmp",
             open_ports=[135, 139, 445],
             _services={
                 135: {"banner": "MS-RPC endpoint mapper"},
                 445: {"banner": "SMB 3.1.1 - Windows 11"},
             },
             probes={"http": {}, "checks": {"snmp_public": None}}),
        # ---------------- ESP32 开发板 (默认凭据) ----------------
        dict(ip="192.168.1.150", mac="7C:9E:BD:03:5A:41",
             hostname=None, discovery="arp",
             open_ports=[23, 80, 8080],
             _services={
                 23: {"banner": "ESP32 Telnet - login:"},
                 80: {"banner": "HTTP/1.1 200 OK - ESP WebServer"},
                 8080: {"banner": "HTTP/1.1 200 OK - MicroPython WebREPL"},
             },
             probes={"http": {"80": {"status": 200, "server": "ESP WebServer",
                                      "title": "ESP32 智能家居控制器",
                                      "dirlist": False, "dangerous_methods": []},
                             "8080": {"status": 401, "server": "",
                                      "title": "login", "www_authenticate":
                                      "Basic realm=\"Config\"",
                                      "dirlist": False,
                                      "dangerous_methods": ["PUT", "DELETE"]}},
                     "checks": {"mqtt_anonymous": True, "snmp_public": None}},
             creds_results=[{"protocol": "Telnet", "port": 23,
                             "username": "root", "password": "root",
                             "success": True}]),
    ]

    built = []
    for dev in devices:
        d = _build_device(dev)
        cr = d.pop("creds_results", None)
        d["findings"] = vulns.evaluate(d)
        if cr:
            d["creds_results"] = cr
            d["findings"] += creds_mod.creds_findings(cr)
        d["score"] = device_score(d["findings"])
        built.append(d)
    built.sort(key=lambda x: x["score"]["score"])
    summary = network_summary(built)
    return {
        "meta": {"start_time": now_str(), "target": "192.168.1.0/24 (演示数据)",
                 "duration": 0.8, "mode": "demo", "ports_scanned": len(portscan.TOP_IOT_PORTS),
                 "rules_loaded": len(vulns.RULES), "creds_tested": True},
        "summary": summary, "devices": built,
    }
