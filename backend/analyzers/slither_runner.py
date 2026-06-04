import asyncio
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Solc binary — override via SOLC_PATH env var if needed
SOLC_PATH = os.getenv("SOLC_PATH", "C:/Users/zhenn/solc.exe")


def detect_solidity_version(code: str) -> Optional[str]:
    """
    Parse Solidity version from pragma directive.
    Supports: ^0.8.0, >=0.7.0 <0.9.0, 0.8.19
    """
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
    """
    Return the solc binary path for the given version.
    Falls back to SOLC_PATH if solcx is unavailable or install fails.
    """
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
    normalized = raw_type.lower().strip()
    normalized = normalized.replace(' ', '-')

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
        'arbitrary-send-eth':       'access-control',
        'arbitrary-send-erc20':     'access-control',
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
    # Reentrancy
    "reentrancy-eth":          "reentrancy",
    "reentrancy-no-eth":       "reentrancy",
    "reentrancy-benign":       "reentrancy",
    "reentrancy-events":       "reentrancy",
    # Authentication
    "tx-origin":               "tx-origin",
    # Selfdestruct
    "suicidal":                "unprotected-selfdestruct",
    # Delegatecall
    "controlled-delegatecall": "unsafe-delegatecall",
    "delegatecall-loop":       "unsafe-delegatecall",
    # Unchecked calls
    "unchecked-lowlevel":      "unchecked-call",
    "unchecked-send":          "unchecked-call",
    "unchecked-transfer":      "unchecked-call",
    # Integer issues
    "integer-overflow":        "integer-overflow",
    "incorrect-exp":           "integer-overflow",
    "tautology":               "integer-overflow",
    # Access control
    "missing-zero-check":      "access-control",
    "unprotected-upgrade":     "access-control",
    "protected-vars":          "access-control",
    "arbitrary-send-eth":      "access-control",
    "arbitrary-send-erc20":    "access-control",
    # Timestamp / randomness
    "weak-prng":               "timestamp-dependence",
    "timestamp":               "timestamp-dependence",
    "block-timestamp":         "timestamp-dependence",
    # Denial of service
    "msg-value-loop":          "denial-of-service",
    "calls-loop":              "denial-of-service",
    "gas-griefing":            "denial-of-service",
    # Misc
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


def _run_slither_sync(sol_file: str) -> Dict[str, Any]:
    try:
        # Read contract code for version detection
        with open(sol_file, "r", encoding="utf-8") as _f:
            _contract_code = _f.read()
        detected_version = detect_solidity_version(_contract_code)
        solc_to_use = get_solc_for_version(detected_version)
        logger.info(f"Solidity version detected: {detected_version}, solc: {solc_to_use}")

        # VIRTUAL_ENV pointing to C:\Program Files\Python311 causes solc-select
        # to try creating dirs there (no write permission). Pop it temporarily.
        _venv = os.environ.pop("VIRTUAL_ENV", None)
        try:
            from slither import Slither  # type: ignore
            from slither.detectors.abstract_detector import AbstractDetector  # type: ignore
            import slither.detectors.all_detectors as _all_det  # type: ignore
            import inspect as _inspect
        finally:
            if _venv is not None:
                os.environ["VIRTUAL_ENV"] = _venv

        oz_path = str(Path(__file__).parent.parent / "node_modules" / "@openzeppelin" / "contracts")

        # crytic-compile mis-parses drive letters in absolute paths on Windows.
        # cd into the temp dir and pass only the filename to avoid this.
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

        # Slither 0.11.5: detectors are NOT auto-registered — must be added manually.
        for _name in dir(_all_det):
            _cls = getattr(_all_det, _name)
            if _inspect.isclass(_cls) and issubclass(_cls, AbstractDetector) and _cls is not AbstractDetector:
                try:
                    sl.register_detector(_cls)
                except Exception:
                    pass

        # run_detectors() returns List[List[OrderedDict]] — one sublist per detector.
        # Flatten to List[Dict] and normalise impact casing.
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
    os.makedirs("C:/Temp", exist_ok=True)
    temp_file = f"C:/Temp/vultron_{uuid.uuid4().hex}.sol"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(solidity_code)
        # Run synchronous Slither in a thread so we don't block the event loop
        result = await asyncio.to_thread(_run_slither_sync, temp_file)
        return result
    finally:
        try:
            os.unlink(temp_file)
        except Exception:
            pass


def map_slither_to_vulnerabilities(detectors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

        result.append({
            "id": f"SL-{str(i).zfill(3)}",
            "type": normalize_vuln_type(CHECK_TYPE_MAP.get(d.get("check", ""), d.get("check", "unknown"))),
            "function": affected_function,
            "severity": IMPACT_MAP.get(d.get("impact", ""), "info"),
            "description": " ".join(d.get("description", "").replace("\n", " ").split()),
            "lineNumber": lines[0] if lines else None,
        })

    return result
