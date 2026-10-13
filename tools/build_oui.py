# -*- coding: utf-8 -*-
"""从 IEEE MA-L 注册表生成 IoT 相关厂商 OUI 数据库。

用法:
    python tools/build_oui.py <oui.csv 路径> [输出 json 路径]

若无网络, 请从 https://standards-oui.ieee.org/oui/oui.csv 手动下载后传入。
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

# 与 IoT / 智能家居 / 网络设备相关的厂商关键词(大小写不敏感)
KEYWORDS = [
    # 安防摄像头 / 录像机
    "camera", "hikvision", "dahua", "ezviz", "reolink", "amcrest", "axis communications",
    "vivotek", "uniview", "tiandy", "dvr", "nvr", "hanwha", "wisenet", "lorex",
    # 消费电子 / 智能家居
    "xiaomi", "amazon", "google", "nest", "sonos", "ring", "wyze", "arlo",
    "ecobee", "philips", "signify", "belkin", "tp-link", "tplink", "tenda",
    "totolink", "netis", "mercury", "mercutio", "ruijie", "h3c",
    # 网络设备
    "netgear", "d-link", "dlink", "asus", "asustek", "ubiquiti", "mikrotik",
    "huawei", "zte", "zyxel", "sagemcom", "technicolor", "sercomm", "arris",
    "commscope", "cisco", "juniper", "linksys", "ruckus", "ruckus wireless",
    # NAS / 存储
    "synology", "qnap", "western digital", "wd ", "seagate", "lacie",
    "buffalo", "asustor", "terramaster",
    # 嵌入式 / 芯片 / 模组
    "espressif", "tuya", "sonoff", "itead", "shelly", "broadlink", "orvibo",
    "rockchip", "realtek", "mediatek", "broadcom", "qualcomm", "nordic",
    "raspberry", "esp", "silicon labs", "texas instruments",
    # 打印 / 办公
    "hewlett", "hp inc", "epson", "canon", "brother", "xerox", "ricoh",
    "kyocera", "toshiba", "konica", "lexmark", "samsung electronics",
    # 家电 / 影音
    "samsung", "lg electronics", "lg innotek", "sony", "panasonic", "sharp",
    "philips lighting", "gree", "haier", "midea", "hisense", "vizio", "tcl",
    # 工控 / 楼宇
    "honeywell", "schneider", "siemens", "bosch", "johnson controls", "abb ",
    "emerson", "yokogawa", "omron", "mitsubishi electric", "legrand",
    # 平台厂商
    "apple", "microsoft", "intel", "dell", "lenovo", "hon hai", "foxconn",
    "lite-on", "delta", "wistron", "compal", "quanta",
]


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/oui.csv")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else
               Path(__file__).resolve().parent.parent / "data" / "oui.json")

    if not src.exists():
        print(f"[!] 找不到 {src}, 请先下载 oui.csv")
        return 1

    out: dict[str, str] = {}
    with src.open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            org = (row.get("Organization Name") or "").strip()
            if not org:
                continue
            low = org.lower()
            if not any(k in low for k in KEYWORDS):
                continue
            asn = (row.get("Assignment") or "").strip().upper()
            if len(asn) == 6 and all(c in "0123456789ABCDEF" for c in asn):
                # 同名厂商保留最长描述(信息更全的)
                out[asn] = org

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=0, sort_keys=True),
                   encoding="utf-8")
    print(f"[+] 已生成 {dst}: {len(out)} 条 OUI 记录")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
