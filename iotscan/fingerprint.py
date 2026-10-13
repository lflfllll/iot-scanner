# -*- coding: utf-8 -*-
"""设备指纹: MAC OUI 厂商识别 + Banner/端口特征分析 + 设备类型推断。"""
from __future__ import annotations

import json
import re
from pathlib import Path

OUI_FILE = Path(__file__).resolve().parent.parent / "data" / "oui.json"

_OUI_CACHE: dict[str, str] | None = None


def load_oui() -> dict[str, str]:
    global _OUI_CACHE
    if _OUI_CACHE is None:
        try:
            _OUI_CACHE = json.loads(OUI_FILE.read_text(encoding="utf-8"))
        except Exception:
            _OUI_CACHE = {}
    return _OUI_CACHE


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    return m if len(m) >= 6 else None


def mac_vendor(mac: str | None) -> str | None:
    """通过 OUI 查询厂商, 并标准化厂名 (去掉公司后缀噪音)。"""
    m = normalize_mac(mac)
    if not m:
        return None
    org = load_oui().get(m[:6])
    if not org:
        return None
    return _tidy_vendor(org)


def _tidy_vendor(org: str) -> str:
    # 统一常见厂名, 便于中文市场认知
    fixes = [
        (r"TP-LINK TECHNOLOGIES.*", "TP-Link"),
        (r"XIAOMI Electronics.*|XIAOMI Communications.*", "小米 Xiaomi"),
        (r"Hangzhou Hikvision.*|Hikvision.*", "海康威视 Hikvision"),
        (r"Zhejiang Dahua.*|Dahua.*", "大华 Dahua"),
        (r"Espressif Inc\..*", "乐鑫 Espressif"),
        (r"Raspberry Pi.*", "Raspberry Pi"),
        (r"Amazon Technologies.*|Amazon\.com.*", "Amazon"),
        (r"Google, Inc\..*|Google LLC.*", "Google"),
        (r"Nest Labs.*", "Google Nest"),
        (r"Routerboard\.com.*|MikroTik.*", "MikroTik"),
        (r"NETGEAR.*", "Netgear"),
        (r"D-Link.*", "D-Link"),
        (r"ASUSTek.*", "ASUS"),
        (r"HUAWEI.*", "华为 Huawei"),
        (r"ZTE.*", "中兴 ZTE"),
        (r"Synology.*", "群晖 Synology"),
        (r"SAMSUNG.*", "三星 Samsung"),
        (r"Apple, Inc\..*", "Apple"),
        (r"Hewlett Packard.*|HP Inc\..*", "HP"),
        (r"Ubiquiti.*", "Ubiquiti"),
        (r"Espressif.*", "乐鑫 Espressif"),
        (r"Honeywell.*", "Honeywell"),
        (r"Tuya.*", "涂鸦 Tuya"),
        (r"Iton Technology.*|Sonoff.*", "Sonoff"),
        (r"Zhejiang Reolink.*|Reolink.*", "Reolink"),
        (r"EZVIZ.*", "萤石 EZVIZ"),
        (r"Sonos.*", "Sonos"),
        (r"Ecobee.*", "Ecobee"),
    ]
    for pat, name in fixes:
        if re.match(pat, org, re.IGNORECASE):
            return name
    # 去掉年营收后缀, 保留主名
    name = re.sub(r",?\s*(Co\.|Corporation|Inc\.?|Ltd\.?|LLC|GmbH|S\.A\.|"
                  r"AB|PLC|AG)\b.*$", "", org, flags=re.IGNORECASE).strip(" ,.")
    return name[:60] if name else org[:60]


# 端口 -> 图标语义 (供报告使用)
PORT_ICONS = {
    23: "⚠", 22: "🔑", 80: "🌐", 443: "🔒", 554: "📹", 8554: "📹",
    445: "💾", 3389: "🖥", 5900: "🖥", 5901: "🖥", 1883: "📡", 8883: "📡",
    631: "🖨", 9100: "🖨", 6379: "🛢", 3306: "🛢", 5432: "🛢", 1433: "🛢",
    1900: "🔄", 53: "🧭", 8291: "🔀", 8728: "🔀", 5555: "🐞",
}

# Banner / HTTP 特征 -> (厂商提示, 设备类型, 系统提示)
BANNER_HINTS: list[tuple[str, str | None, str | None, str | None]] = [
    (r"hikvision|ivms|ds-\d{4}|app-webs", "海康威视", "IP 摄像头", None),
    (r"dahua|dh-ipc|dh-[a-z]{1,3}\d{3}|dhnvr|recorder", "大华", "DVR/NVR 录像机", None),
    (r"reolink", "Reolink", "IP 摄像头", None),
    (r"ezviz", "萤石", "IP 摄像头", None),
    (r"axis|m1011|p33\d\d", "Axis", "IP 摄像头", None),
    (r"boa", None, "嵌入式 Web 设备", "Boa Web Server"),
    (r"mini_httpd|thttpd", None, "嵌入式 Web 设备", None),
    (r"goahead", "Embedthis", "嵌入式 Web 设备", "GoAhead"),
    (r"lighttpd", None, "嵌入式 Web 设备", None),
    (r"dropbear", None, "嵌入式 Linux 设备", "Dropbear SSH"),
    (r"busybox", None, "嵌入式 Linux 设备", "BusyBox"),
    (r"uclinux|openwrt", None, "OpenWrt 路由器", "OpenWrt"),
    (r"routeros", "MikroTik", "路由器", "RouterOS"),
    (r"winbox", "MikroTik", "路由器", None),
    (r"synology|diskstation|dsm", "群晖", "NAS 网络存储", "DSM"),
    (r"qnap|qts", "威联通", "NAS 网络存储", "QTS"),
    (r"tp-link|tl-[a-z]{2,3}\d{3}|archer", "TP-Link", "路由器", None),
    (r"tenda|tplink", "Tenda", "路由器", None),
    (r"mikrotik", "MikroTik", "路由器", "RouterOS"),
    (r"hnap", None, "路由器", None),
    (r"dnvrs|net-surveillance|dvr", None, "DVR/NVR 录像机", None),
    (r"printer|laserjet|deskjet|officejet|ipp", None, "打印机", None),
    (r"canon|epson|brother|kyocera|xerox", None, "打印机", None),
    (r"chromecast|google cast", "Google", "智能音箱/投屏设备", None),
    (r"amazon|echo|alexa", "Amazon", "智能音箱", None),
    (r"sonos", "Sonos", "智能音箱", None),
    (r"tuya|smartlife", "涂鸦", "智能家居设备", None),
    (r"sonoff|ewelink", "Sonoff", "智能家居设备", None),
    (r"homekit|hkipc|aeotec", None, "智能家居设备", None),
    (r"foscam|wanscam|ipcamera", None, "IP 摄像头", None),
    (r"espressif|esp8266|esp32", "乐鑫", "IoT 模组/开发板", None),
    (r"thermostat|nest weave|honeywell|tado|ecobee|weave", None,
     "智能温控器", None),
    (r"firmware|webui", None, None, None),
    (r"linux|debian|ubuntu|centos", None, None, "Linux"),
    (r"windows|iis|microsoft", "Microsoft", "Windows 主机", "Windows"),
]

# 设备类型推断规则 (按优先级排序, 第一个命中生效)
_TYPE_RULES: list[tuple[str, list | dict]] = [
    # (设备类型, {"ports_any": [...], "ports_all": [...], "banner": regex, "vendor": regex})
    ("DVR/NVR 录像机", {"ports_any": [37777, 34567]}),
    ("IP 摄像头", {"ports_any": [554, 8554]}),
    ("打印机", {"ports_any": [631, 9100, 515]}),
    ("NAS 网络存储", {"ports_any": [5000, 5001]}),
    ("MikroTik 路由器", {"ports_any": [8291, 8728, 8729]}),
    ("智能音箱/投屏设备", {"ports_any": [8008, 8009]}),
    ("路由器", {"banner": r"routeros|winbox|openwrt|boa|hnap|router"}),
    ("IoT 模组/开发板", {"banner": r"esp8266|esp32|espressif|arduino"}),
    ("智能家居设备", {"banner": r"tuya|sonoff|ewelink|smartlife|homekit"}),
    ("智能音箱", {"banner": r"echo|alexa|sonos|chromecast"}),
    ("NAS 网络存储", {"banner": r"synology|diskstation|qnap"}),
    ("打印机", {"banner": r"printer|laserjet|deskjet|officejet"}),
    ("IP 摄像头", {"banner": r"hikvision|dahua|dvr|ipc|foscam|reolink"}),
    ("Windows 主机", {"banner": r"windows|microsoft-iis"}),
    ("嵌入式 Linux 设备", {"banner": r"busybox|dropbear|uclinux|linux"}),
    ("Windows 主机", {"ports_all": [135, 139, 445]}),
    ("网络设备", {"ports_any": [23, 22, 80, 443]}),
]


def classify(device: dict) -> dict:
    """推断设备类型/厂商/系统。回写 device['device_type'] 等字段。"""
    mac = device.get("mac")
    ports = set(device.get("open_ports") or [])
    services = device.get("services") or {}
    banners = " ".join(
        (svc.get("banner") or "") for svc in services.values()).lower()
    title = (services.get(80, {}).get("http", {}) or {}).get("title") or ""
    title = str(title).lower()
    blob = f"{banners} {title}"

    vendor = mac_vendor(mac)
    os_guess = None
    dev_type = None

    # 1) Banner 特征
    for pat, ven, typ, osg in BANNER_HINTS:
        if re.search(pat, blob, re.IGNORECASE):
            vendor = vendor or ven
            dev_type = dev_type or typ
            os_guess = os_guess or osg
            if dev_type and vendor:
                break

    # 2) 设备类型推断
    for typ, cond in _TYPE_RULES:
        if "ports_any" in cond and ports & set(cond["ports_any"]):
            dev_type = dev_type or typ
            break
        if "ports_all" in cond and ports and set(cond["ports_all"]) <= ports:
            dev_type = dev_type or typ
            break
        if "banner" in cond and re.search(cond["banner"], blob, re.IGNORECASE):
            dev_type = dev_type or typ
            break

    # 3) 厂商修正设备类型
    if vendor:
        vl = vendor.lower()
        if "hikvision" in vl or "dahua" in vl or "ezviz" in vl or "reolink" in vl:
            dev_type = dev_type or "IP 摄像头"
        elif "tp-link" in vl or "d-link" in vl or "netgear" in vl or "tenda" in vl:
            dev_type = dev_type or "路由器"
        elif "synology" in vl:
            dev_type = dev_type or "NAS 网络存储"
        elif "espressif" in vl or "xiaomi" in vl or "tuya" in vl:
            dev_type = dev_type or "智能家居设备"

    device["vendor"] = vendor or "未知厂商"
    device["device_type"] = dev_type or infer_type_by_ports(ports)
    device["os_guess"] = os_guess
    return device


def infer_type_by_ports(ports: set[int]) -> str:
    """无 banner 时按端口组合兜底推断。"""
    if not ports:
        return "未知设备"
    if {80, 443} <= ports:
        return "网络设备"
    if ports & {53}:
        return "路由器/网关"
    if ports & {135, 139}:
        return "Windows 主机"
    if ports & {62078}:
        return "移动终端"
    return "未知设备"


def is_random_mac(mac: str | None) -> bool:
    """MAC 第二低位为 1 时表示本地管理地址 (随机 MAC / 虚拟网卡)。"""
    m = normalize_mac(mac)
    if not m:
        return False
    return bool(int(m[1], 16) & 0b0010)
