from typing import Any, List

SEVERITY_PENALTY = {
    "critical": 40,
    "high":     25,
    "medium":   10,
    "low":       5,
    "info":      0,
}


def calculate_score(vulnerabilities: List[Any]) -> int:
    penalty = sum(SEVERITY_PENALTY.get(v.get("severity", ""), 0) for v in vulnerabilities)
    return max(0, 100 - penalty)


def get_risk_level(score: int) -> str:
    if score >= 80:
        return "Safe"
    if score >= 60:
        return "Low Risk"
    if score >= 40:
        return "Medium Risk"
    if score >= 20:
        return "High Risk"
    return "Critical Risk"


def calculate_weighted_score(vulnerabilities: List[Any]) -> int:
    total = 100.0
    for v in vulnerabilities:
        base = SEVERITY_PENALTY.get(v.get("severity", ""), 0)
        exploit_score = v.get("exploitability_score", 50)
        total -= base * (exploit_score / 100)
    return max(0, round(total))
