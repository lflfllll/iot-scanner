#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IoT Security Scanner - 物联网设备安全扫描器 (命令行入口)

示例:
    python iotscan.py --demo                       # 离线演示(内置模拟家庭网络)
    python iotscan.py                              # 扫描本机所在网段
    python iotscan.py -t 192.168.1.0/24            # 指定网段
    python iotscan.py -t 192.168.1.50              # 单台设备
    python iotscan.py -t 192.168.1.0/24 --creds -v # 含默认凭据测试与详情
    python iotscan.py --ports 1-1024               # 自定义端口范围
    python iotscan.py --list-rules                 # 查看全部检测规则
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iotscan import __version__           # noqa: E402
from iotscan.core import Progress, demo_result, run_scan  # noqa: E402
from iotscan.report import (console_report, save_html,  # noqa: E402
                            save_json)
from iotscan.utils import (C, color, fmt_ts)  # noqa: E402

BANNER = rf"""
{C['cyan']}  ___    _____   _____    ___                            ___   ___   ___
 |_ _|  |_   _| |_   _|  / __|  ___  _ __   __ _   ___  ___  / __| / __| / __|
  | |    | |     | |   \__ \ / _ \| '_ \ / _` | / __|/ __| \__ \| (__  \__ \
 |___|   |_|     |_|   |___/ \___/| .__/ \__,_| \___|\___| |___/ \___| |___/
                                  |_|        IoT Security Scanner v{__version__}
{C['reset']}"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iotscan",
        description="IoT 设备安全扫描器: 发现局域网物联网设备、识别端口/服务/"
                    "已知漏洞/默认凭据, 并给出加固建议, 生成 HTML/JSON 报告。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python iotscan.py --demo\n"
               "  python iotscan.py -t 192.168.1.0/24 --creds -v\n"
               "  python iotscan.py -t 192.168.1.50 --ports 80,443,8080\n")
    p.add_argument("-t", "--target", metavar="CIDR|IP",
                   help="扫描目标: 网段(192.168.1.0/24)、IP 范围(192.168.1.1-50) "
                        "或单 IP; 缺省自动探测本机网段")
    p.add_argument("--ports", metavar="SPEC", default="top",
                   help="端口清单: top(默认,85 个 IoT 常用端口) / "
                        "1-1024 / 逗号列表, 如 80,443,554")
    p.add_argument("--full", action="store_true",
                   help="扫描所有 1024 低位常用端口 + IoT 端口清单")
    p.add_argument("--timeout", type=float, default=0.6,
                   help="单端口连接超时(秒), 默认 0.6")
    p.add_argument("--threads", type=int, default=128, help="并发线程数, 默认 128")
    p.add_argument("--creds", action="store_true",
                   help="测试常见出厂默认凭据 (Telnet/HTTP Basic/FTP, "
                        "建议仅对自有设备使用)")
    p.add_argument("--demo", action="store_true",
                   help="演示模式: 使用内置模拟家庭网络数据生成报告")
    p.add_argument("--hotel", action="store_true",
                   help="酒店隐私模式: 排查所住房间网络中的针孔摄像头/偷拍设备"
                        " (ONVIF/SSDP 组播发现 + 摄像头指纹 + 物理排查清单)")
    p.add_argument("--hotel-demo", action="store_true",
                   help="酒店隐私模式演示: 内置模拟酒店房间网络数据")
    p.add_argument("--html", metavar="PATH", help="HTML 报告输出路径")
    p.add_argument("--json", metavar="PATH", help="JSON 报告输出路径")
    p.add_argument("-o", "--outdir", default="reports",
                   help="报告输出目录(缺省 reports/)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="输出每台设备的漏洞详情与修复建议")
    p.add_argument("-q", "--quiet", action="store_true", help="静默模式")
    p.add_argument("--list-rules", action="store_true", help="列出全部检测规则")
    p.add_argument("--version", action="version",
                   version=f"IoT Security Scanner v{__version__}")
    return p


def print_rules() -> None:
    from iotscan import vulns
    from iotscan.utils import SEV_CN, sev_badge
    print(f"\n共 {len(vulns.RULES)} 条检测规则:\n")
    for r in vulns.RULES:
        conds = ", ".join(f"{k}={v}" for k, v in (r.get("when") or {}).items())
        print(f" {sev_badge(r['severity'])} {r['id']:<24} {r['title']}")
        print(f"     条件: {conds or 'N/A'}")
    print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        print_rules()
        return 0

    if not args.quiet:
        print(BANNER)

    if args.demo:
        from iotscan.core import demo_result as _demo
        progress = Progress(quiet=args.quiet)
        progress("report", "演示模式: 载入内置模拟家庭网络数据 ...")
        result = _demo()
        progress("deep_probing", f"对 {result['summary']['total_devices']} 台 "
                                  f"模拟设备执行规则引擎 ...")
        hotel_mode = False
    elif args.hotel_demo:
        from iotscan.core import hotel_demo_result
        result = hotel_demo_result()
        hotel_mode = True
    elif args.hotel:
        hotel_mode = True
        try:
            from iotscan.hotelscan import run_hotel_scan
            result = run_hotel_scan(target=args.target, timeout=args.timeout,
                                    threads=args.threads,
                                    progress=Progress(quiet=args.quiet))
        except KeyboardInterrupt:
            print(color("\n[!] 用户中断扫描", "yellow"))
            return 130
        except Exception as exc:  # noqa: BLE001
            print(color(f"\n[!] 扫描出错: {exc}", "red"))
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    else:
        hotel_mode = False
        try:
            result = run_scan(target=args.target, ports_spec=args.ports,
                              full=args.full, timeout=args.timeout,
                              threads=args.threads, creds=args.creds,
                              progress=Progress(quiet=args.quiet))
        except KeyboardInterrupt:
            print(color("\n[!] 用户中断扫描", "yellow"))
            return 130
        except Exception as exc:  # noqa: BLE001
            print(color(f"\n[!] 扫描出错: {exc}", "red"))
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    # ---- 报告输出
    os.makedirs(args.outdir, exist_ok=True)
    stamp = fmt_ts()
    if hotel_mode:
        from iotscan.report import console_hotel_report, save_hotel_html
        hpath = args.html or os.path.join(args.outdir,
                                          f"hotel-scan-{stamp}.html")
        save_hotel_html(result, hpath)
        if not args.quiet:
            console_hotel_report(result)
            print(color("报告已生成:", "green", True))
            print(f"  HTML : {hpath}")
        return 0

    html_path = args.html or os.path.join(args.outdir, f"iot-scan-{stamp}.html")
    json_path = args.json or os.path.join(args.outdir, f"iot-scan-{stamp}.json")
    save_html(result, html_path)
    save_json(result, json_path)

    if not args.quiet:
        console_report(result, verbose=args.verbose)
        print(color("报告已生成:", "green", True))
        print(f"  HTML : {html_path}")
        print(f"  JSON : {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
