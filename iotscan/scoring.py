# -*- coding: utf-8 -*-
"""风险评分: 单设备风险分 + 全网安全分。"""
from __future__ import annotations

from .utils import SEV_ORDER

# 各严重级权重 (扣分制)
SEV_WEIGHT = {"critical": 30, "high": 16, "medium": 8, "low": 3, "info": 0.5}


def device_score(findings: list[dict]) -> dict:
    """设备安全评分: 100 分扣减法, 返回 {score, grade, risk_level}。"""
    risk = sum(SEV_WEIGHT.get(f["severity"], 0) for f in findings)
    score = max(0, round(100 - risk))
    grade = "A"
    if score < 90:
        grade = "B"
    if score < 75:
        grade = "C"
    if score < 60:
        grade = "D"
    if score < 40:
        grade = "E"
    if score < 20:
        grade = "F"
    if score >= 85:
        level = "安全"
    elif score >= 60:
        level = "低风险"
    elif score >= 35:
        level = "中风险"
    else:
        level = "高风险"
    return {"score": score, "grade": grade, "risk_level": level,
            "risk_points": round(risk, 1)}


def network_summary(devices: list[dict]) -> dict:
    """全网汇总统计。"""
    total_findings = 0
    by_sev = {s: 0 for s in SEV_ORDER}
    by_category: dict[str, int] = {}
    top_issues: dict[str, dict] = {}
    for dev in devices:
        for f in dev.get("findings", []):
            total_findings += 1
            by_sev[f["severity"]] += 1
            by_category[f["category"]] = by_category.get(f["category"], 0) + 1
            rid = f["rule_id"]
            if rid not in top_issues:
                top_issues[rid] = {
                    "rule_id": rid, "title": f["title"],
                    "severity": f["severity"], "count": 0,
                    "recommendation": f.get("recommendation", ""),
                    "devices": [],
                }
            top_issues[rid]["count"] += 1
            top_issues[rid]["devices"].append(dev["ip"])

    scores = [d["score"]["score"] for d in devices if d.get("score")]
    avg = round(sum(scores) / len(scores)) if scores else 0
    # 全网分 = 平均分 - 严重/高危未处置惩罚
    penalty = min(40, by_sev["critical"] * 3 + by_sev["high"])
    net_score = max(0, min(100, avg - penalty))
    grade = "A"
    if net_score < 90:
        grade = "B"
    if net_score < 75:
        grade = "C"
    if net_score < 60:
        grade = "D"
    if net_score < 40:
        grade = "E"
    if net_score < 20:
        grade = "F"

    return {
        "total_devices": len(devices),
        "total_open_ports": sum(len(d.get("open_ports") or [])
                                for d in devices),
        "total_findings": total_findings,
        "by_severity": by_sev,
        "by_category": dict(sorted(by_category.items(),
                                   key=lambda kv: -kv[1])),
        "avg_device_score": avg,
        "network_score": net_score,
        "network_grade": grade,
        "top_issues": sorted(top_issues.values(),
                             key=lambda i: (SEV_ORDER.index(i["severity"]),
                                            -i["count"])),
    }
