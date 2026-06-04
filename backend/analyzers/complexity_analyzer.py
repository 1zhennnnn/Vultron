import re
from typing import Any, Dict


def analyze_complexity(code: str, slither_result: dict) -> Dict[str, Any]:
    """
    Evaluate contract complexity using static analysis only — no AI required.
    """
    function_count = len(re.findall(r'\bfunction\s+\w+', code))

    public_function_count = len(re.findall(
        r'\bfunction\s+\w+[^)]*\)\s+(?:public|external)', code
    ))

    state_var_count = len(re.findall(
        r'^\s+(?:uint|int|address|bool|bytes|string|mapping)\w*\s+'
        r'(?:public\s+)?(?:private\s+)?(?:internal\s+)?\w+',
        code, re.MULTILINE,
    ))

    inheritance_count = len(re.findall(
        r'\bcontract\s+\w+\s+is\s+([^{]+)', code
    ))

    external_call_count = len(re.findall(
        r'\.(call|transfer|send|delegatecall|staticcall)\b', code
    ))

    modifier_count = len(re.findall(r'\bmodifier\s+\w+', code))
    event_count    = len(re.findall(r'\bevent\s+\w+', code))

    lines = [l for l in code.split('\n') if l.strip() and not l.strip().startswith('//')]
    loc = len(lines)

    complexity_score = (
        function_count * 2
        + public_function_count * 3
        + external_call_count * 5
        + inheritance_count * 2
        + state_var_count
    )

    if complexity_score >= 50:
        complexity_level = "HIGH"
        complexity_note  = "Complex contract — thorough review recommended"
    elif complexity_score >= 20:
        complexity_level = "MEDIUM"
        complexity_note  = "Moderate complexity"
    else:
        complexity_level = "LOW"
        complexity_note  = "Simple contract structure"

    return {
        "complexity_score": complexity_score,
        "complexity_level": complexity_level,
        "complexity_note":  complexity_note,
        "metrics": {
            "loc":                   loc,
            "function_count":        function_count,
            "public_function_count": public_function_count,
            "state_variable_count":  state_var_count,
            "external_call_count":   external_call_count,
            "modifier_count":        modifier_count,
            "event_count":           event_count,
            "inheritance_depth":     inheritance_count,
        },
    }
