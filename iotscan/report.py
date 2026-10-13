# -*- coding: utf-8 -*-
"""报告输出: 彩色控制台 / JSON / HTML(带 SVG 图表)。"""
from __future__ import annotations

import html as html_mod
import json
import os
import sys
from datetime import datetime

from .utils import (C, SEV_CN, SEV_ORDER, color, fmt_dur, now_str,
                    sev_badge, sev_cn)

SEV_COLOR_HEX = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#2563eb", "info": "#6b7280",
}
SEV_BG_HEX = {
    "critical": "#fef2f2", "high": "#fff7ed", "medium": "#fefce8",
    "low": "#eff6ff", "info": "#f3f4f6",
}
GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04",
               "D": "#ea580c", "E": "#dc2626", "F": "#991b1b"}


# ================================================================ 控制台
def console_report(result: dict, out=sys.stdout, verbose: bool = False) -> None:
    devices = result["devices"]
    meta = result["meta"]
    summary = result["summary"]

    def w(line: str = "") -> None:
        print(line, file=out)

    from .utils import pad
    w()
    w(color("╔" + "═" * 56 + "╗", "cyan"))
    w(color("║", "cyan") + color(pad("        IoT Security Scanner v"
                                  + __import__("iotscan").__version__, 56),
                                  "cyan", True) + color("║", "cyan"))
    w(color("║", "cyan") + color(pad("        物联网设备安全扫描报告", 56),
                                  "cyan") + color("║", "cyan"))
    w(color("╚" + "═" * 56 + "╝", "cyan"))
    w(f" 扫描目标 : {meta['target']}")
    w(f" 开始时间 : {meta['start_time']}    耗时: {fmt_dur(meta['duration'])}")
    w(f" 发现设备 : {summary['total_devices']} 台    开放端口: "
      f"{summary['total_open_ports']} 个")
    w()

    if not devices:
        w(color("未发现任何在线设备。", "yellow"))
        return

    # ---- 摘要
    w(color("═" * 60, "cyan"))
    w(color(f" 全网安全评分: {summary['network_score']}/100 "
            f"({summary['network_grade']} 级)", "bold", True))
    bs = summary["by_severity"]
    w(f" 发现风险: {summary['total_findings']} 项  "
      f"{color('严重 ' + str(bs['critical']), 'red', True)} / "
      f"{color('高危 ' + str(bs['high']), 'red')} / "
      f"{color('中危 ' + str(bs['medium']), 'yellow')} / "
      f"{color('低危 ' + str(bs['low']), 'blue')} / "
      f"{color('提示 ' + str(bs['info']), 'gray')}")
    w(color("═" * 60, "cyan"))
    w()

    # ---- 设备风险排名
    from .utils import pad
    w(color("── 设备风险排名 (风险从高到低) ──", "bold", True))
    w(f" {pad('IP', 16)}{pad('设备类型', 16)}{pad('厂商', 26)}"
      f"{pad('评分', 4)} {'等级':<4}风险项")
    w(" " + "-" * 76)
    ranked = sorted(devices, key=lambda d: d["score"]["score"])
    for d in ranked:
        sc = d["score"]
        level_color = ("green" if sc["score"] >= 85 else
                       "yellow" if sc["score"] >= 60 else
                       "red")
        score_cell = color(pad(sc["score"], 4), level_color, True)
        w(f" {pad(_trunc(d['ip'], 16), 16)}"
          f"{pad(_trunc(d.get('device_type') or '-', 16), 16)}"
          f"{pad(_trunc(d.get('vendor') or '-', 24), 24)}"
          f"{score_cell} {sc['grade']:<5} {len(d.get('findings', []))} 项")
    w()

    # ---- 优先修复建议
    w(color("── 优先修复建议 (Top 10) ──", "bold", True))
    for i, issue in enumerate(summary["top_issues"][:10], 1):
        devs = ", ".join(issue["devices"][:3])
        if len(issue["devices"]) > 3:
            devs += f" 等 {len(issue['devices'])} 台"
        w(f" {i:>2}. {sev_badge(issue['severity'])} {issue['title']}"
          f"  {color('[' + devs + ']', 'dim')}")
        if verbose:
            w(f"     修复: {issue['recommendation']}")
    w()

    # ---- 设备明细
    if verbose:
        for d in ranked:
            _print_device_detail(w, d)
        # 规则目录外的收尾
    else:
        w(color("提示: 使用 -v/--verbose 查看每台设备的漏洞详情与修复建议。",
                "dim"))
    w()


def _print_device_detail(w, d: dict) -> None:
    w(color("─" * 78, "gray"))
    sc = d["score"]
    header = f"▸ {d['ip']}  {d.get('device_type') or '未知设备'}"
    if d.get("vendor"):
        header += f"  ({d['vendor']})"
    w(color(header, "bold", True) + f"   评分 {sc['score']}/100 ({sc['grade']})")
    meta_bits = [f"MAC: {d.get('mac') or '未知'}"]
    if d.get("hostname"):
        meta_bits.append(f"主机名: {d['hostname']}")
    if d.get("os_guess"):
        meta_bits.append(f"系统: {d['os_guess']}")
    meta_bits.append(f"发现方式: {d.get('discovery', '-')}")
    w("   " + "  |  ".join(meta_bits))
    if d.get("open_ports"):
        from .fingerprint import PORT_ICONS
        from .portscan import TOP_IOT_PORTS
        chips = []
        for p in d["open_ports"]:
            name = TOP_IOT_PORTS.get(p, "unknown")
            chips.append(f"{PORT_ICONS.get(p, '')}{p}/{name}")
        w("   开放端口: " + ", ".join(chips))
    for f in d.get("findings", []):
        w(f"   {sev_badge(f['severity'])} {f['title']}  "
          f"{color(f.get('cwe') or '', 'dim')}")
        w(f"       说明: {f['description']}")
        w(f"       建议: {color(f['recommendation'], 'green')}")
        if f.get("credential"):
            c = f["credential"]
            w(f"       凭据: {color(c['username'] + '/' + c['password'], 'red', True)}"
              f"  ({c['protocol']}:{c['port']})")
    w()


# ================================================================ JSON
def json_report(result: dict) -> dict:
    """输出可序列化的 JSON 结构 (finding 内凭证字段已脱敏由调用方控制)。"""
    return result


def save_json(result: dict, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return path


# ================================================================ HTML
def _esc(s) -> str:
    return html_mod.escape(str(s)) if s is not None else ""


def _sev_badge(sev: str) -> str:
    return (f'<span class="badge" style="color:{SEV_COLOR_HEX[sev]};'
            f'background:{SEV_BG_HEX[sev]}">{SEV_CN[sev]}</span>')


def _trunc(s: str, width: int) -> str:
    """按显示宽度截断 (用于控制台表格中文列)。"""
    from .utils import disp_width
    s = str(s)
    if disp_width(s) <= width:
        return s
    out, w = "", 0
    for ch in s:
        cw = 2 if disp_width(ch) == 2 else 1
        if w + cw > width - 1:
            return out + "…"
        out += ch
        w += cw
    return out


def _gauge_svg(score: int, grade: str) -> str:
    """半圆形仪表盘。"""
    radius, cx, cy = 78, 100, 100
    circumference = 3.14159 * radius  # 半圆
    pct = max(0.0, min(1.0, score / 100.0))
    dash = circumference * pct
    color_hex = GRADE_COLOR.get(grade, "#6b7280")
    return f'''
<svg viewBox="0 0 200 120" class="gauge" role="img" aria-label="安全评分 {score}">
  <path d="M {cx - radius} {cy} A {radius} {radius} 0 0 1 {cx + radius} {cy}"
        fill="none" stroke="#e5e7eb" stroke-width="18" stroke-linecap="round"/>
  <path d="M {cx - radius} {cy} A {radius} {radius} 0 0 1 {cx + radius} {cy}"
        fill="none" stroke="{color_hex}" stroke-width="18" stroke-linecap="round"
        stroke-dasharray="{dash:.1f} {circumference:.1f}"/>
  <text x="{cx}" y="{cy - 12}" text-anchor="middle" font-size="40"
        font-weight="700" fill="#111827">{score}</text>
  <text x="{cx}" y="{cy + 8}" text-anchor="middle" font-size="12"
        fill="#6b7280">/ 100 · {grade} 级</text>
</svg>'''


def _donut_svg(by_sev: dict) -> str:
    """漏洞分布环形图。"""
    total = sum(by_sev.values()) or 1
    r, cx, cy, circ = 60, 100, 100, 2 * 3.14159 * 60
    offset = 25.0  # 从顶部开始
    parts = []
    for sev in SEV_ORDER:
        n = by_sev.get(sev, 0)
        if not n:
            continue
        frac = n / total
        length = circ * frac
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{SEV_COLOR_HEX[sev]}" stroke-width="26" '
            f'stroke-dasharray="{length:.2f} {circ - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>')
        offset -= length
    legend = "".join(
        f'<div class="lg"><i style="background:{SEV_COLOR_HEX[s]}"></i>'
        f'{SEV_CN[s]} <b>{by_sev.get(s, 0)}</b></div>'
        for s in SEV_ORDER if by_sev.get(s))
    return (f'<svg viewBox="0 0 200 200" class="donut" role="img" '
            f'aria-label="漏洞分布">{"".join(parts)}'
            f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="34" '
            f'font-weight="700" fill="#111827">{total}</text>'
            f'<text x="{cx}" y="{cy + 18}" text-anchor="middle" font-size="12" '
            f'fill="#6b7280">项风险</text></svg>'
            f'<div class="legend">{legend}</div>')


CSS = '''
:root{--ink:#111827;--sub:#6b7280;--line:#e5e7eb;--bg:#f4f6fa;--card:#fff;
--brand:#2563eb;--crit:#dc2626;--high:#ea580c;--med:#ca8a04;--low:#2563eb;--info:#6b7280}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
background:var(--bg);color:var(--ink);line-height:1.6}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
header.hero{background:linear-gradient(135deg,#1e3a8a,#2563eb);color:#fff;padding:34px 0 30px}
header.hero h1{font-size:26px;letter-spacing:.5px}
header.hero .sub{opacity:.85;margin-top:10px;font-size:13px;flex-wrap:wrap}
header.hero .sub span{margin-right:18px;white-space:nowrap}
main{padding:26px 0 60px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:-46px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:18px;box-shadow:0 6px 18px rgba(15,23,42,.06)}
.card h3{font-size:13px;color:var(--sub);font-weight:600;margin-bottom:6px}
.kpi{display:flex;align-items:baseline;gap:8px}
.kpi b{font-size:30px}
.kpi small{color:var(--sub)}
.gauge-box{grid-row:span 1}
.gauge{width:100%;height:auto;max-width:260px;display:block;margin:0 auto}
.grid2{display:grid;grid-template-columns:1fr 1.4fr;gap:14px;margin-top:16px}
.donut-wrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.donut{width:170px;height:170px}
.legend div{font-size:13px;margin:3px 0;color:var(--ink)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;
margin-right:7px;vertical-align:middle}
table.rank{width:100%;border-collapse:collapse;font-size:13px}
table.rank th{color:var(--sub);font-weight:600;text-align:left;padding:8px 6px;
border-bottom:1px solid var(--line)}
table.rank td{padding:8px 6px;border-bottom:1px solid #f1f3f7}
.bar{height:8px;border-radius:4px;background:#eef1f6;overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;border-radius:4px}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;
font-weight:600;line-height:1.7}
.meta{display:flex;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--sub);
margin:10px 0 12px}
.meta b{color:var(--ink);font-weight:600}
.ports{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.port{font-size:12px;background:#f1f5f9;border:1px solid var(--line);
border-radius:8px;padding:2px 9px;color:#334155}
.port.warn{background:#fff7ed;border-color:#fdba74;color:#9a3412}
.port.danger{background:#fef2f2;border-color:#fca5a5;color:#991b1b}
.finding{border:1px solid var(--line);border-left-width:4px;border-radius:10px;
padding:12px 14px;margin:10px 0;background:#fff}
.finding h4{font-size:14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.finding h4 .rid{font-size:11px;color:var(--sub);font-weight:500}
.finding p{font-size:13px;color:#374151;margin:7px 0}
.finding .fix{color:#166534;background:#f0fdf4;border:1px solid #bbf7d0;
border-radius:8px;padding:8px 11px;font-size:13px;margin-top:6px}
.finding .fix b{color:#14532d}
.finding .refs{font-size:11px;color:var(--sub);margin-top:6px}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.dev-card{margin-top:18px}
.dev-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.dev-head h2{font-size:18px}
.dev-head .grade{width:34px;height:34px;border-radius:9px;color:#fff;
display:flex;align-items:center;justify-content:center;font-weight:700;font-size:16px}
.type-chip{background:#eef2ff;color:#3730a3;border-radius:999px;
padding:2px 12px;font-size:12px;font-weight:600}
.vendor{font-size:13px;color:var(--sub)}
.fix-list{counter-reset:fx}
.fix-item{display:flex;gap:12px;padding:11px 0;border-bottom:1px dashed var(--line);
font-size:13.5px}
.fix-item:last-child{border-bottom:none}
.fix-item .no{counter-increment:fx;min-width:26px;height:26px;border-radius:8px;
color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;
font-size:13px}
.fix-item .t b{font-size:13.5px}
.fix-item .t div{color:var(--sub);font-size:12.5px}
.fix-item .devs{color:var(--sub);font-size:12px;white-space:nowrap}
footer{padding:22px 0 30px;color:var(--sub);font-size:12px;text-align:center}
@media(max-width:860px){.cards{grid-template-columns:repeat(2,1fr)}
.grid2{grid-template-columns:1fr}}
'''


def _device_card(d: dict) -> str:
    sc = d["score"]
    grade = sc["grade"]
    ports_html = []
    from .portscan import TOP_IOT_PORTS
    danger = {23, 2323, 2323, 26, 21, 69, 2375, 5555, 5900, 5901, 3389, 445,
              6379, 11211, 9200, 9300}
    warn = {80, 8080, 8081, 8000, 8008, 8009, 8888, 1883, 1900, 502, 44818,
            161, 7547, 53, 445, 554, 8554, 37777, 34567, 135}
    for p in d.get("open_ports", []):
        cls = "danger" if p in danger else ("warn" if p in warn else "")
        name = TOP_IOT_PORTS.get(p, "unknown")
        ports_html.append(f'<span class="port {cls}">{p} · {_esc(name)}</span>')
    if not ports_html:
        ports_html.append('<span class="port">未发现开放端口</span>')

    findings_html = []
    for f in d.get("findings", []):
        refs = " · ".join(f.get("refs", []))
        cred = ""
        if f.get("credential"):
            c = f["credential"]
            cred = (f'<p style="color:#991b1b"><b>测试到的凭据：</b>'
                    f'{_esc(c["username"])} / {_esc(c["password"])} '
                    f'({_esc(c["protocol"])}:{c["port"]})</p>')
        findings_html.append(f'''
<div class="finding {f['severity']}">
  <h4>{_sev_badge(f['severity'])} {_esc(f['title'])}
      <span class="rid">{_esc(f['rule_id'])} · CWE {_esc(f.get('cwe') or '-')}
      · CVSS {_esc(f.get('cvss') or '-')}</span></h4>
  <p>{_esc(f['description'])}</p>
  {cred}
  <div class="fix"><b>修复建议：</b>{_esc(f['recommendation'])}</div>
  <div class="refs">参考: {_esc(refs) if refs else '-'}</div>
</div>''')

    gcolor = GRADE_COLOR.get(grade, "#6b7280")
    mac_line = (f"MAC <b>{_esc(d.get('mac'))}</b>" if d.get("mac")
                else "MAC <b>未知</b>")
    host_line = (f"主机名 <b>{_esc(d['hostname'])}</b>" if d.get("hostname") else "")
    os_line = f"系统 <b>{_esc(d['os_guess'])}</b>" if d.get("os_guess") else ""
    return f'''
<section class="card dev-card">
  <div class="dev-head">
    <div class="grade" style="background:{gcolor}">{grade}</div>
    <h2>{_esc(d['ip'])}</h2>
    <span class="type-chip">{_esc(d.get('device_type') or '未知设备')}</span>
    <span class="vendor">{_esc(d.get('vendor') or '')}</span>
    <span style="margin-left:auto" class="vendor">评分 <b>{sc['score']}</b>/100
      · {_esc(sc['risk_level'])}</span>
  </div>
  <div class="meta">{mac_line} · {host_line} · {os_line} ·
    发现方式: {_esc(d.get('discovery', '-'))} · 开放端口 {len(d.get('open_ports') or [])}</div>
  <div class="ports">{''.join(ports_html)}</div>
  {''.join(findings_html) if findings_html else '<div class="finding info"><h4>未发现安全问题 — 该设备本次扫描通过全部规则</h4></div>'}
</section>'''


def html_report(result: dict) -> str:
    devices = sorted(result["devices"], key=lambda d: d["score"]["score"])
    meta, summary = result["meta"], result["summary"]
    bs = summary["by_severity"]

    # 设备风险排名表
    rank_rows = []
    max_risk = max((100 - d["score"]["score"] for d in devices), default=1) or 1
    for d in devices:
        risk = 100 - d["score"]["score"]
        pct = max(4, min(100, round(risk / max(max_risk, 1) * 100)))
        bw = GRADE_COLOR.get(d["score"]["grade"], "#6b7280")
        rank_rows.append(f'''
<tr><td><b>{_esc(d['ip'])}</b></td>
<td>{_esc(d.get('device_type') or '-')}</td>
<td>{_esc(d.get('vendor') or '-')}</td>
<td><div class="bar"><i style="width:{pct}%;background:{bw}"></i></div></td>
<td><b>{d['score']['score']}</b> ({d['score']['grade']})</td>
<td>{len(d.get('findings', []))}</td></tr>''')

    fix_items = []
    for i, issue in enumerate(summary["top_issues"][:12], 1):
        col = SEV_COLOR_HEX[issue["severity"]]
        devs = ", ".join(issue["devices"][:4]) + \
            (f" 等 {len(issue['devices'])} 台" if len(issue["devices"]) > 4 else "")
        fix_items.append(f'''
<div class="fix-item">
  <div class="no" style="background:{col}">{i}</div>
  <div class="t"><b>{_sev_badge(issue['severity'])} {_esc(issue['title'])}</b>
    <div>{_esc(issue['recommendation'][:110])}</div></div>
  <div class="devs">影响 {_esc(devs)}</div>
</div>''')

    cards = "".join(_device_card(d) for d in devices)
    total_crit = bs["critical"] + bs["high"]
    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IoT 设备安全扫描报告 · {_esc(meta['start_time'])}</title>
<style>{CSS}</style>
</head>
<body>
<header class="hero"><div class="wrap">
  <h1>IoT 设备安全扫描报告</h1>
  <div class="sub">
    <span>扫描目标：{_esc(meta['target'])}</span>
    <span>开始时间：{_esc(meta['start_time'])}</span>
    <span>耗时：{_esc(fmt_dur(meta['duration']))}</span>
    <span>模式：{_esc(meta.get('mode', 'live'))}</span>
  </div>
</div></header>
<main class="wrap">
  <div class="cards">
    <div class="card gauge-box"><h3>全网安全评分</h3>{_gauge_svg(summary['network_score'], summary['network_grade'])}</div>
    <div class="card"><h3>设备资产</h3>
      <div class="kpi"><b>{summary['total_devices']}</b><small>台在线设备</small></div>
      <div class="kpi" style="margin-top:8px"><b>{summary['total_open_ports']}</b><small>个开放端口</small></div>
      <div class="kpi" style="margin-top:8px"><b>{summary['avg_device_score']}</b><small>设备平均分</small></div>
    </div>
    <div class="card"><h3>风险发现</h3>
      <div class="kpi"><b>{summary['total_findings']}</b><small>项风险</small></div>
      <div class="kpi" style="margin-top:8px"><b style="color:var(--crit)">{bs['critical']}</b><small>严重</small></div>
      <div class="kpi" style="margin-top:8px"><b style="color:var(--high)">{bs['high']}</b><small>高危</small></div>
    </div>
    <div class="card"><h3>处置优先级</h3>
      <div class="kpi"><b style="color:var(--crit)">{total_crit}</b><small>项需立即处理（严重+高危）</small></div>
      <div style="margin-top:10px;font-size:12.5px;color:var(--sub)">
        按设备评分排序，优先修复评分最低设备上的问题。
      </div>
    </div>
  </div>

  <div class="grid2">
    <div class="card"><h3>漏洞严重级分布</h3>
      <div class="donut-wrap">{_donut_svg(bs)}</div>
    </div>
    <div class="card"><h3>设备风险排名（分数越低越危险）</h3>
      <table class="rank">
        <tr><th>IP</th><th>设备类型</th><th>厂商</th><th>风险</th><th>评分</th><th>风险项</th></tr>
        {''.join(rank_rows)}
      </table>
    </div>
  </div>

  <div class="card" style="margin-top:16px"><h3>优先修复清单（按严重级与影响面排序）</h3>
    <div class="fix-list">{''.join(fix_items)}</div>
  </div>

  <h2 style="margin:26px 0 4px;font-size:19px">设备详情</h2>
  {cards}
</main>
<footer>
  <div class="wrap">
    由 IoT Security Scanner v1.0.0 生成 · {_esc(now_str())}<br>
    共扫描 {summary['total_devices']} 台设备 · 命中规则 {summary['total_findings']} 项
  </div>
</footer>
</body>
</html>'''


def save_html(result: dict, path: str) -> str:
    html = html_report(result)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path

