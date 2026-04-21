from __future__ import annotations

from typing import Any


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _is_true_flag(value: Any) -> bool:
    return _to_int(value, default=0) == 1


def generate_mitigations(data: dict) -> list[dict]:
    payload = data if isinstance(data, dict) else {}
    recommendations: list[dict] = []
    seen_titles: set[str] = set()

    def add_recommendation(
        title: str,
        recommendation: str,
        severity: str,
        priority: str,
        reason: str,
    ) -> None:
        if title in seen_titles:
            return
        seen_titles.add(title)
        recommendations.append(
            {
                "title": title,
                "recommendation": recommendation,
                "severity": severity,
                "priority": priority,
                "reason": reason,
            }
        )

    high_risk_flag_count = 0

    internet_exposed = _is_true_flag(payload.get("internet_exposed"))
    if internet_exposed:
        high_risk_flag_count += 1
        add_recommendation(
            title="Restrict Internet Exposure",
            recommendation="Restrict inbound traffic and remove unnecessary public network exposure.",
            severity="HIGH",
            priority="P1",
            reason="Asset is internet-exposed, increasing direct attack surface.",
        )

    public_access = _is_true_flag(payload.get("public_access"))
    if public_access:
        high_risk_flag_count += 1
        add_recommendation(
            title="Remove Public Access",
            recommendation="Remove public access paths and tighten access policies to trusted principals only.",
            severity="HIGH",
            priority="P1",
            reason="Public access allows broader unauthorized reachability.",
        )

    weak_iam = _is_true_flag(payload.get("weak_iam"))
    if weak_iam:
        high_risk_flag_count += 1
        add_recommendation(
            title="Strengthen IAM Controls",
            recommendation="Apply least-privilege policies, audit roles, and enforce MFA for privileged access.",
            severity="HIGH",
            priority="P1",
            reason="Weak IAM controls increase the likelihood of account abuse.",
        )

    privilege_escalation_possible = _is_true_flag(payload.get("privilege_escalation_possible"))
    if privilege_escalation_possible:
        high_risk_flag_count += 1
        add_recommendation(
            title="Block Privilege Escalation Paths",
            recommendation="Audit permission boundaries and remove escalation paths across identities and roles.",
            severity="HIGH",
            priority="P1",
            reason="Privilege escalation paths can enable full environment compromise.",
        )

    critical_vulnerability_count = max(_to_int(payload.get("critical_vulnerability_count"), default=0), 0)
    if critical_vulnerability_count > 0:
        high_risk_flag_count += 1
        add_recommendation(
            title="Patch Critical Vulnerabilities",
            recommendation="Prioritize and patch critical vulnerabilities immediately using emergency remediation timelines.",
            severity="HIGH",
            priority="P1",
            reason="Critical vulnerabilities present immediate exploit risk.",
        )

    vulnerability_count = max(_to_int(payload.get("vulnerability_count"), default=0), 0)
    if vulnerability_count >= 5 and critical_vulnerability_count == 0:
        add_recommendation(
            title="Review Vulnerability Management",
            recommendation="Run a focused vulnerability management cycle to reduce high-volume findings and recurrence.",
            severity="MEDIUM",
            priority="P2",
            reason="Elevated vulnerability count indicates sustained hygiene gaps.",
        )

    misconfiguration_count = max(_to_int(payload.get("misconfiguration_count"), default=0), 0)
    if misconfiguration_count > 0:
        add_recommendation(
            title="Harden Security Configuration",
            recommendation="Apply baseline hardening standards and remediate known configuration drift.",
            severity="MEDIUM",
            priority="P2",
            reason="Detected misconfigurations can expose exploitable control weaknesses.",
        )

    lateral_movement_possible = _is_true_flag(payload.get("lateral_movement_possible"))
    if lateral_movement_possible:
        high_risk_flag_count += 1
        add_recommendation(
            title="Limit Lateral Movement",
            recommendation="Implement network segmentation and stricter east-west access controls between assets.",
            severity="HIGH",
            priority="P1",
            reason="Lateral movement paths enable attackers to pivot deeper into the environment.",
        )

    has_critical_data = _is_true_flag(payload.get("has_critical_data"))
    if has_critical_data:
        high_risk_flag_count += 1
        add_recommendation(
            title="Protect Critical Data",
            recommendation="Enforce encryption, strict data access controls, and continuous monitoring for sensitive assets.",
            severity="HIGH",
            priority="P1",
            reason="Critical data exposure can result in severe business and compliance impact.",
        )

    if high_risk_flag_count >= 2:
        add_recommendation(
            title="Immediate Containment and Security Review",
            recommendation="Prioritize immediate containment actions and perform a full security review across related assets.",
            severity="HIGH",
            priority="P1",
            reason="Multiple high-risk indicators were detected simultaneously.",
        )

    return recommendations