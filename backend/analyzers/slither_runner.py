import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SOLC_PATH = os.getenv("SOLC_PATH", "C:/Users/zhenn/solc.exe")


def detect_solidity_version(code: str) -> Optional[str]:
    patterns = [
        r'pragma solidity\s+[^;]*?(0\.\d+\.\d+)',
        r'pragma solidity\s+[\^~>=<]*\s*(0\.\d+\.\d+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return match.group(1)
    return None


def get_solc_for_version(version: Optional[str]) -> str:
    solc_path = SOLC_PATH
    if not version:
        return solc_path
    try:
        import solcx  # type: ignore
        installed = [str(v) for v in solcx.get_installed_solc_versions()]
        if version not in installed:
            try:
                solcx.install_solc(version, show_progress=False)
            except Exception:
                pass
        if version in [str(v) for v in solcx.get_installed_solc_versions()]:
            return str(solcx.get_solc_binary_path(version))
    except ImportError:
        pass
    return solc_path


def normalize_vuln_type(raw_type: str) -> str:
    normalized = raw_type.lower().strip().replace(' ', '-')
    mapping = {
        'reentrancy':               'reentrancy',
        'reentrancy-eth':           'reentrancy',
        'reentrancy-no-eth':        'reentrancy',
        'reentrancy-benign':        'reentrancy',
        'reentrancy-events':        'reentrancy',
        'tx-origin':                'tx-origin',
        'tx.origin':                'tx-origin',
        'txorigin':                 'tx-origin',
        'suicidal':                 'unprotected-selfdestruct',
        'unprotected-selfdestruct': 'unprotected-selfdestruct',
        'unchecked-transfer':       'unchecked-call',
        'unchecked-lowlevel':       'unchecked-call',
        'unchecked-send':           'unchecked-call',
        'unchecked-call':           'unchecked-call',
        'access-control':           'access-control',
        'events-access':            'access-control',
        'missing-zero-check':       'access-control',
        'unprotected-upgrade':      'access-control',
        'protected-vars':           'access-control',
        'arbitrary-send-eth':       'arbitrary-send',
        'arbitrary-send-erc20':     'arbitrary-send',
        'integer-overflow':         'integer-overflow',
        'incorrect-exp':            'integer-overflow',
        'tautology':                'integer-overflow',
        'controlled-delegatecall':  'unsafe-delegatecall',
        'delegatecall-loop':        'unsafe-delegatecall',
        'unsafe-delegatecall':      'unsafe-delegatecall',
        'weak-prng':                'timestamp-dependence',
        'timestamp':                'timestamp-dependence',
        'block-timestamp':          'timestamp-dependence',
        'timestamp-dependence':     'timestamp-dependence',
        'msg-value-loop':           'denial-of-service',
        'calls-loop':               'denial-of-service',
        'gas-griefing':             'denial-of-service',
        'denial-of-service':        'denial-of-service',
        'flash-loan-attack':        'flash-loan-attack',
        'front-running':            'front-running',
        'shadowing-state':          'shadowing',
        'uninitialized-local':      'uninitialized',
        'locked-ether':             'locked-ether',
    }
    return mapping.get(normalized, normalized)


CHECK_TYPE_MAP: Dict[str, str] = {
    "reentrancy-eth":          "reentrancy",
    "reentrancy-no-eth":       "reentrancy",
    "reentrancy-benign":       "reentrancy",
    "reentrancy-events":       "reentrancy",
    "tx-origin":               "tx-origin",
    "suicidal":                "unprotected-selfdestruct",
    "controlled-delegatecall": "unsafe-delegatecall",
    "delegatecall-loop":       "unsafe-delegatecall",
    "unchecked-lowlevel":      "unchecked-call",
    "unchecked-send":          "unchecked-call",
    "unchecked-transfer":      "unchecked-call",
    "integer-overflow":        "integer-overflow",
    "incorrect-exp":           "integer-overflow",
    "tautology":               "integer-overflow",
    "missing-zero-check":      "access-control",
    "unprotected-upgrade":     "access-control",
    "protected-vars":          "access-control",
    "arbitrary-send-eth":      "arbitrary-send",
    "arbitrary-send-erc20":    "arbitrary-send",
    "weak-prng":               "timestamp-dependence",
    "timestamp":               "timestamp-dependence",
    "block-timestamp":         "timestamp-dependence",
    "msg-value-loop":          "denial-of-service",
    "calls-loop":              "denial-of-service",
    "gas-griefing":            "denial-of-service",
    "shadowing-state":         "shadowing",
    "uninitialized-local":     "uninitialized",
    "locked-ether":            "locked-ether",
}

IMPACT_MAP: Dict[str, str] = {
    "High":          "critical",
    "Medium":        "high",
    "Low":           "medium",
    "Informational": "info",
    "Optimization":  "info",
}

# Issue #5: Per-check severity overrides — certain Slither check families produce
# inflated severity when the global IMPACT_MAP maps too aggressively.
# These caps reflect actual exploitability, not worst-case assumptions.
SEVERITY_OVERRIDE: Dict[str, str] = {
    "unchecked-send":      "medium",  # silent ETH failure ≠ theft
    "unchecked-lowlevel":  "medium",  # same reasoning as above
    "missing-zero-check":  "low",     # input validation gap, not an access breach
    "weak-prng":           "medium",  # miner window is ≤15 s, rarely decisive
    "shadowing-state":     "low",     # code-quality issue, rarely directly exploitable
    "locked-ether":        "medium",  # bad UX but not an external attack vector
}

# P2-7: SWC mapping
SWC_MAP: Dict[str, Dict[str, str]] = {
    "reentrancy":               {"swc_id": "SWC-107", "swc_title": "Reentrancy"},
    "tx-origin":                {"swc_id": "SWC-115", "swc_title": "Authorization through tx.origin"},
    "unprotected-selfdestruct": {"swc_id": "SWC-106", "swc_title": "Unprotected SELFDESTRUCT Instruction"},
    "unsafe-delegatecall":      {"swc_id": "SWC-112", "swc_title": "Delegatecall to Untrusted Callee"},
    "integer-overflow":         {"swc_id": "SWC-101", "swc_title": "Integer Overflow and Underflow"},
    "access-control":           {"swc_id": "SWC-105", "swc_title": "Unprotected Ether Withdrawal"},
    "unchecked-call":           {"swc_id": "SWC-104", "swc_title": "Unchecked Call Return Value"},
    "arbitrary-send":           {"swc_id": "SWC-105", "swc_title": "Unprotected Ether Withdrawal"},
    "timestamp-dependence":     {"swc_id": "SWC-116", "swc_title": "Block values as a proxy for time"},
    "denial-of-service":        {"swc_id": "SWC-113", "swc_title": "DoS with Failed Call"},
    "flash-loan-attack":        {"swc_id": "SWC-100", "swc_title": "Function Default Visibility"},
    "front-running":            {"swc_id": "SWC-114", "swc_title": "Transaction Order Dependence"},
}

# Issue #8: CWE mapping (complements SWC IDs with the broader MITRE taxonomy)
CWE_MAP: Dict[str, str] = {
    "reentrancy":               "CWE-1265",  # Unintended Reentrance
    "tx-origin":                "CWE-284",   # Improper Access Control
    "unprotected-selfdestruct": "CWE-284",
    "unsafe-delegatecall":      "CWE-829",   # Untrusted Control Sphere
    "integer-overflow":         "CWE-190",   # Integer Overflow
    "access-control":           "CWE-862",   # Missing Authorization
    "unchecked-call":           "CWE-252",   # Unchecked Return Value
    "timestamp-dependence":     "CWE-330",   # Insufficient Randomness
    "denial-of-service":        "CWE-400",   # Uncontrolled Resource Consumption
    "flash-loan-attack":        "CWE-841",
    "front-running":            "CWE-362",   # Race Condition
}

# Issue #6: Patterns indicating a vulnerability is already mitigated
SAFE_PATTERNS: Dict[str, List[str]] = {
    "reentrancy": [
        r"\bnonReentrant\b",
        r"\bReentrancyGuard\b",
    ],
    "integer-overflow": [
        r"pragma solidity\s+[\^>=]*\s*0\.[89]\.\d+",
        r"\bSafeMath\b",
    ],
    "unchecked-call": [
        r"\bAddress\.sendValue\b",
        r"\bSafeERC20\b",
    ],
    "timestamp-dependence": [
        r"\bChainlink\b",
        r"\bAggregatorV3Interface\b",
    ],
}

# Issue #1/#7: Recognized authorization mechanisms used in Issue #1 FP suppression
_AUTH_PATTERNS: List[str] = [
    r"\bonlyOwner\b",
    r"\bonlyRole\b",
    r"\bhasRole\b",
    r"\bAccessControl\b",
    r"\bOwnable\b",
    r"require\s*\(\s*msg\.sender\s*==\s*(?:owner|_owner|admin)\b",
    r"require\s*\(\s*hasRole\(",
    r"if\s*\(\s*msg\.sender\s*!=\s*(?:owner|admin)\s*\)\s*revert",
]


def _detect_auth_mechanisms(contract_code: str) -> bool:
    """Return True if the contract has recognizable access-control mechanisms."""
    return any(re.search(p, contract_code) for p in _AUTH_PATTERNS)


# Issue #1/#7: access-control sub-checks that are informational/style issues
# rather than true vulnerabilities when the contract already has auth mechanisms.
# - missing-zero-check: input validation gap (not an auth breach)
# - events-access: "no event on ownership change" — fires ON guarded functions
_AC_INFORMATIONAL_CHECKS = {"missing-zero-check", "events-access", "protected-vars"}


def suppress_false_positives(vulns: List[Dict[str, Any]], contract_code: str) -> List[Dict[str, Any]]:
    if not contract_code:
        return vulns

    has_auth = _detect_auth_mechanisms(contract_code)
    kept = []
    for v in vulns:
        source_check = v.get("source_check", "")
        vuln_type    = v.get("type", "")

        # Issue #1/#7: informational access-control sub-checks fired on functions
        # that already have proper authorization guards → suppress as FP.
        if vuln_type == "access-control" and source_check in _AC_INFORMATIONAL_CHECKS and has_auth:
            logger.info(f"FP suppressed: {v['id']} ({source_check}) — auth mechanisms present")
            continue

        # Issue #6: standard pattern-based suppression (nonReentrant, SafeMath, etc.)
        patterns = SAFE_PATTERNS.get(vuln_type, [])
        if patterns and any(re.search(p, contract_code) for p in patterns):
            logger.info(f"FP suppressed: {v['id']} ({vuln_type}) — safe pattern detected")
        else:
            kept.append(v)

    return kept


# Issue #2: Slither checkers whose access-control findings are downstream symptoms
# of tx-origin (the root auth issue).  When tx-origin is present, suppress these.
_TXORIGIN_REDUNDANT_CHECKS = {"arbitrary-send-eth", "arbitrary-send-erc20", "missing-zero-check"}


def deduplicate_vulns(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    types = {v["type"] for v in vulns}
    if "tx-origin" not in types:
        return vulns
    result = []
    for v in vulns:
        if v["type"] == "access-control" and v.get("source_check") in _TXORIGIN_REDUNDANT_CHECKS:
            logger.info(f"Dedup suppressed: {v['id']} ({v.get('source_check')}) — redundant with tx-origin")
            continue
        result.append(v)
    return result


def _run_slither_sync(sol_file: str) -> Dict[str, Any]:
    try:
        with open(sol_file, "r", encoding="utf-8") as _f:
            _contract_code = _f.read()
        detected_version = detect_solidity_version(_contract_code)
        solc_to_use = get_solc_for_version(detected_version)
        logger.info(f"Solidity version detected: {detected_version}, solc: {solc_to_use}")

        try:
            from slither import Slither  # type: ignore
            from slither.detectors.abstract_detector import AbstractDetector  # type: ignore
            import slither.detectors.all_detectors as _all_det  # type: ignore
            import inspect as _inspect
        finally:
            pass

        oz_path = str(Path(__file__).parent.parent / "node_modules" / "@openzeppelin" / "contracts")

        work_dir = os.path.dirname(sol_file)
        filename  = os.path.basename(sol_file)
        old_cwd   = os.getcwd()
        try:
            os.chdir(work_dir)
            sl = Slither(
                filename,
                solc=solc_to_use,
                solc_remaps=[f"@openzeppelin/={oz_path}/"],
                disallow_partial=False,
            )
        finally:
            os.chdir(old_cwd)

        for _name in dir(_all_det):
            _cls = getattr(_all_det, _name)
            if _inspect.isclass(_cls) and issubclass(_cls, AbstractDetector) and _cls is not AbstractDetector:
                try:
                    sl.register_detector(_cls)
                except Exception:
                    pass

        nested = sl.run_detectors()
        all_findings: List[Dict[str, Any]] = []
        for sublist in nested:
            for finding in sublist:
                entry = dict(finding)
                impact = entry.get("impact", "")
                if isinstance(impact, str) and impact.isupper():
                    entry["impact"] = impact.title()
                all_findings.append(entry)

        filtered = [
            r for r in all_findings
            if r.get("impact") not in {"Informational", "Optimization", "informational", "optimization"}
        ]
        logger.info(f"Slither: {len(filtered)} findings ({len(all_findings) - len(filtered)} informational/optimization filtered)")
        return {
            "success": True,
            "detectors": filtered,
            "solidity_version": detected_version or "unknown",
            "solc_used": solc_to_use,
        }

    except Exception as e:
        logger.error(f"Slither execution error: {e}")
        return {"success": False, "detectors": [], "error": str(e),
                "solidity_version": "unknown", "solc_used": SOLC_PATH}


async def run_slither(solidity_code: str) -> Dict[str, Any]:
    import tempfile
    fd, temp_file = tempfile.mkstemp(suffix=".sol", prefix="vultron_")
    os.close(fd)
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(solidity_code)
        result = await asyncio.to_thread(_run_slither_sync, temp_file)
        return result
    finally:
        try:
            os.unlink(temp_file)
        except Exception:
            pass


def map_slither_to_vulnerabilities(detectors: List[Dict[str, Any]], contract_code: str = "") -> List[Dict[str, Any]]:
    result = []
    for i, d in enumerate(detectors):
        impact_lower = d.get("impact", "").lower()
        if impact_lower in {"informational", "optimization"}:
            continue

        elements: List[Any] = d.get("elements", [])
        fn_el = next((e for e in elements if e.get("type") == "function"), None)
        first_el = elements[0] if elements else {}
        affected_function = (fn_el or first_el).get("name", "unknown")
        source_mapping = first_el.get("source_mapping", {}) if first_el else {}
        lines: List[int] = source_mapping.get("lines", [])

        raw_check  = d.get("check", "unknown")
        vuln_type  = normalize_vuln_type(CHECK_TYPE_MAP.get(raw_check, raw_check))
        swc_info   = SWC_MAP.get(vuln_type, {})
        cwe_id     = CWE_MAP.get(vuln_type)

        # Issue #5: apply per-check severity override before the global IMPACT_MAP
        if raw_check in SEVERITY_OVERRIDE:
            severity = SEVERITY_OVERRIDE[raw_check]
        else:
            severity = IMPACT_MAP.get(d.get("impact", ""), "info")

        result.append({
            "id":          f"SL-{str(i).zfill(3)}",
            "type":        vuln_type,
            "source_check": raw_check,
            "function":    affected_function,
            "severity":    severity,
            "description": " ".join(d.get("description", "").replace("\n", " ").split()),
            "lineNumber":  lines[0] if lines else None,
            "swc_id":      swc_info.get("swc_id"),
            "swc_title":   swc_info.get("swc_title"),
            "cwe_id":      cwe_id,
        })

    deduped = deduplicate_vulns(result)
    return suppress_false_positives(deduped, contract_code)
