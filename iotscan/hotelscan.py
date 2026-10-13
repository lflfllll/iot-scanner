# -*- coding: utf-8 -*-
"""酒店隐私模式: 针对"我住的房间里可能有偷拍摄像头"这一场景的扫描。

与家用漏洞扫描的区别:
  - 目标不是"设备有没有漏洞", 而是"网络里有没有摄像头正在看我";
  - 手段: ONVIF/SSDP 组播主动发现 + 端口/厂商指纹 + 未知设备画像;
  - 输出: 可疑设备证据链 + 人工/物理排查清单。

注意: 仅扫描你本人接入的网络(自己的房间/民宿), 用于保护自身隐私。
存本地卡(不入网)的摄像头网络扫描发现不了, 必须配合物理排查,
报告中的"物理排查清单"就是为此准备的。
"""
from __future__ import annotations

import ipaddress
import re
import time

from . import discovery, fingerprint, portscan, probes
from .fingerprint import is_random_mac
from .utils import is_ipv4, now_str

# 摄像头强特征端口
CAMERA_STRONG_PORTS = {554, 8554, 37777, 34567, 5000, 5001}
# 摄像头中特征端口 (管理面)
CAMERA_WEAK_PORTS = {80, 8080, 8000, 8008, 8009, 8888, 8081, 81, 443, 8443}
# 常见消费电子端口 (排除误报: 手机/笔记本/电视/游戏机/音箱)
CIVILIAN_PORTS = {
    62078,           # iPhone 同步
    7000, 8008, 8009, 32768,  # Chromecast/投屏
    8612, 8615,      # 智能电视/盒子
    4070,            # Dash
    5540, 5541, 5542,
    49152, 49153, 49154,
    3689,            # DAAP
    5353,            # mDNS
    9001, 9002, 9000,
    9100, 631, 515,  # 打印机
    8291, 8728, 8729, 2000,  # MikroTik
}

# 摄像头厂商关键词 (命中 OUI / Banner)
CAMERA_VENDOR_RE = (
    r"hikvision|dahua|ezviz|reolink|amcrest|uniview|tiandy|axis|foscam|"
    r"wanscam|vstarcam|ipc|network camera|网络摄像头|录像机|nvr|dvr|"
    r"onvif|camera|chnipt|h264|netcam|escam|sricam| rovio|tenvis|"
    r"mobotix|vivotek|hanwha|wisenet|samsung techwin"
)

SUSPICION_LEVELS = ["高度可疑", "可疑", "常规"]


def camera_suspicion(device: dict) -> dict:
    """单设备摄像头可疑度评估。

    返回 {level, score, evidence: [文字证据...], is_camera_like: bool}
    """
    evidence: list[str] = []
    score = 0
    ports = set(device.get("open_ports") or [])
    services = device.get("services") or {}
    vendor = (device.get("vendor") or "")
    blob_parts = [vendor]
    for svc in services.values():
        blob_parts.append(svc.get("banner") or "")
    for entry in (device.get("probes", {}).get("http") or {}).values():
        if not entry:
            continue
        blob_parts.append(str(entry.get("server") or ""))
        blob_parts.append(str(entry.get("title") or ""))
    blob = " ".join(blob_parts).lower()

    probes_res = device.get("probes", {}) or {}
    checks = probes_res.get("checks") or {}

    # ---- 强证据 ----
    if device.get("onvif"):
        score += 45
        xaddrs = device["onvif"].get("xaddrs") or "?"
        evidence.append(f"ONVIF 设备发现应答 (服务地址: {xaddrs[:60]})")
    if ports & CAMERA_STRONG_PORTS:
        hit = sorted(ports & CAMERA_STRONG_PORTS)
        score += 30
        evidence.append(f"开放视频/录像机端口: {hit}")
    if checks.get("rtsp_open") is True:
        score += 35
        evidence.append("RTSP 无需认证即可播放视频流")
    elif ports & {554, 8554} and checks.get("rtsp_open") is False:
        score += 15
        evidence.append("开放 RTSP 端口(有认证)")
    if 23 in ports or 2323 in ports:
        score += 10
        evidence.append("开放 Telnet(廉价摄像头固件常见配置)")

    # ---- 厂商指纹 ----
    if re.search(CAMERA_VENDOR_RE, blob, re.I):
        score += 20
        evidence.append(f"厂商/服务指纹命中了摄像头特征")

    # ---- 未知设备 + Web 管理口 (廉价针孔摄像头典型画像) ----
    unknown_vendor = vendor in ("", "未知厂商")
    has_web = bool(ports & CAMERA_WEAK_PORTS)
    has_deep_probe = bool(probes_res.get("http"))
    if unknown_vendor and has_web:
        score += 18
        evidence.append("无法识别厂商 + 开放 Web 管理端口")
    if unknown_vendor and is_random_mac(device.get("mac")):
        score += 12
        evidence.append("随机 MAC(本地管理地址), 设备刻意隐藏身份")
    if unknown_vendor and ports and not (ports & CIVILIAN_PORTS):
        score += 8
        evidence.append("端口画像与常见手机/电视/音箱均不匹配")

    # ---- 消费电子排除项 (降低误报) ----
    civilian_hits = sorted(ports & CIVILIAN_PORTS)
    if civilian_hits and not (ports & CAMERA_STRONG_PORTS):
        score = max(0, score - 25)
        evidence.append(f"命中常见消费电子端口 {civilian_hits}, 初步判为普通设备")
    if device.get("hostname"):
        hn = str(device["hostname"]).lower()
        if re.search(r"iphone|android|macbook|laptop|desktop|pc|tv|"
                     r"pad|phone|watch", hn):
            score = max(0, score - 40)
            evidence.append(f"主机名提示为个人终端: {device['hostname']}")

    # 归一化
    score = min(100, score)
    if score >= 60:
        level = "高度可疑"
    elif score >= 30:
        level = "可疑"
    else:
        level = "常规"
    return {"level": level, "score": score, "evidence": evidence,
            "is_camera_like": level != "常规"}


# 物理排查清单 (存本地卡的摄像头网络扫描发现不了, 必须人工检查)
PHYSICAL_CHECKLIST = [
    ("网络扫描", "入住后连上酒店 WiFi, 立即运行本工具扫描; 换房间/换楼层的"
                " AP 后重扫一次; 偷拍摄像头多为独立小设备, 只要入网就能发现。"),
    ("红光测试", "关灯、拉窗帘, 用手机手电筒照射可疑位置(烟雾报警器、插座、"
                "电视机顶盒、空调出风口、装饰品、正对床/浴室的摆件), "
                "肉眼或手机摄像头观察是否有微弱红/蓝光点——红外补光灯的痕迹。"),
    ("镜头反光", "打开手机相机仔细扫视房间, 缓慢移动寻找微小反光点; "
                 "针孔镜头在强光下会有特征性反光, 肉眼难辨但镜头可辨。"),
    ("双面镜", "指尖贴在镜面上, 若指尖与镜像指尖之间有明显缝隙=普通镜子; "
               "若指尖相触无缝隙=可能是双面镜(后面有人), 立即检查另一侧。"),
    ("小孔排查", "检查墙面上不该有的直径 <2mm 的小孔, 尤其对准床/浴室的位置; "
                 "可用手机电筒侧照, 观察孔内是否有镜片反光。"),
    ("电源异常", "检查烟雾报警器、插座、路由器、音箱、闹钟等是否多出线缆、"
                 "指示灯异常、摆放位置别扭(对床/对浴室)。"),
    ("信号检测", "如有手持 RF 探测器, 可在关掉房间内所有已知无线设备后, "
                 "扫描 1.2GHz/2.4GHz/5.8GHz 频段的异常发射源。"),
    ("其他渠道", "发现可疑设备后不要拆除/触碰(保留证据), 联系酒店方、"
                 "必要时报警; 贵重物品和隐私物品远离可疑摆件。"),
]


def run_hotel_scan(target: str | None = None, timeout: float = 0.6,
                   threads: int = 128, progress=None) -> dict:
    """酒店隐私模式完整流程: 组播发现 -> 主机发现 -> 端口扫描 -> 摄像头评估。"""
    t0 = time.time()

    def prog(phase, msg):
        if progress:
            progress(phase, msg)

    # 1. 组播主动发现 (ONVIF + SSDP), 不必等主机发现就能抓到摄像头
    prog("multicast", "ONVIF/SSDP 组播探测 (239.255.255.250:3702/1900) ...")
    onvif = probes.onvif_discover(timeout=3.0)
    ssdp = probes.ssdp_search(timeout=2.0)
    prog("multicast", f"ONVIF 应答 {len(onvif)} 台, SSDP 应答 {len(ssdp)} 条")

    # 2. 常规主机发现
    if target and is_ipv4(target):
        devices = discovery.discover_single(target)
        target_desc = target
    else:
        from .utils import detect_network
        net = None
        if target:
            net = ipaddress.ip_network(target, strict=False)
        devices = discovery.discover(progress=progress, threads=threads,
                                     timeout=max(timeout, 1.0), network=net)
        target_desc = str(net) if net else "auto"
    prog("host_discovery", f"发现 {len(devices)} 台在线主机")

    # 3. 组播结果合并: ONVIF/SSDP 应答但 ping 不通的设备也要纳入
    known_ips = {d["ip"] for d in devices}
    for item in onvif:
        if item["ip"] not in known_ips:
            devices.append({"ip": item["ip"], "mac": None, "hostname": None,
                            "discovery": "onvif"})
            known_ips.add(item["ip"])
    for item in ssdp:
        if item["ip"] not in known_ips and item["ip"].startswith(("192.", "10.", "172.")):
            devices.append({"ip": item["ip"], "mac": None, "hostname": None,
                            "discovery": "ssdp"})
            known_ips.add(item["ip"])

    # 4. 端口扫描 + 摄像头评估
    from concurrent.futures import ThreadPoolExecutor
    ports = portscan.TOP_IOT_PORTS

    def _scan_one(dev: dict) -> dict:
        open_ports = portscan.scan_host(dev["ip"], sorted(ports),
                                        timeout=timeout,
                                        threads=min(threads, 256))
        d = dict(dev)
        d["open_ports"] = open_ports
        services = {}
        for p in open_ports:
            services[p] = {"name": portscan.service_name(p),
                           "banner": portscan.grab_banner(dev["ip"], p,
                                                          timeout=max(timeout, 1.2))}
        probe_res = probes.probe_device(dev["ip"], open_ports,
                                        timeout=max(timeout, 1.5))
        d["probes"] = probe_res
        for p in open_ports:
            services[p]["http"] = (probe_res.get("http", {}) or {}).get(str(p))
        d["services"] = services
        # 组播证据
        if dev["ip"] in {o["ip"] for o in onvif}:
            d["onvif"] = next(o for o in onvif if o["ip"] == dev["ip"])
        else:
            d["onvif"] = None
        d["ssdp"] = [s for s in ssdp if s["ip"] == dev["ip"]] or None
        fingerprint.classify(d)
        d["suspicion"] = camera_suspicion(d)
        return d

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(devices)))) as ex:
        results = list(ex.map(_scan_one, devices))

    # 5. 排序: 可疑度高的在前
    order = {"高度可疑": 0, "可疑": 1, "常规": 2}
    results.sort(key=lambda d: (order[d["suspicion"]["level"]],
                                -d["suspicion"]["score"]))
    dur = round(time.time() - t0, 2)
    suspicious = [d for d in results if d["suspicion"]["is_camera_like"]]
    summary = {
        "total_devices": len(results),
        "onvif_found": len(onvif),
        "ssdp_found": len(ssdp),
        "suspicious_count": len(suspicious),
        "high_suspicious": sum(1 for d in suspicious
                               if d["suspicion"]["level"] == "高度可疑"),
        "total_open_ports": sum(len(d.get("open_ports") or []) for d in results),
    }
    return {
        "meta": {"start_time": now_str(),
                 "target": target_desc, "duration": dur, "mode": "hotel"},
        "summary": summary, "devices": results,
        "onvif": onvif, "ssdp": ssdp,
    }
