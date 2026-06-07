import json
import logging
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional

from pydantic import BaseModel, Field, validator

from groq_client import ask_groq

logger = logging.getLogger(__name__)

SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}

# Issue #4: Evidence conditions — 5 binary checks × 20 pts each = 0-100 scale.
# Each entry represents one observable code artefact that raises confidence the
# vulnerability is genuinely exploitable.
# INVARIANT: weights per vuln_type MUST sum to 100.
# calculate_evidence_score() normalises by total_weight, so any sum works
# mathematically, but keeping 100 makes the per-condition contribution
# immediately readable (each weight == percentage points).
EVIDENCE_CONDITIONS: Dict[str, List[Dict[str, Any]]] = {
    "reentrancy": [
        {"pattern": r"\.call\{value:",              "weight": 20, "label": "External ETH Call"},
        {"pattern": r"balances\[|_balances\[",       "weight": 20, "label": "Balance Mapping"},
        {"pattern": r"\bwithdraw\b|\bdeposit\b",    "weight": 20, "label": "Withdraw/Deposit Function"},
        {"pattern": r"receive\(\)|fallback\(\)",    "weight": 20, "label": "Fallback Entry Point"},
        {"pattern": r"msg\.sender\.call|address\(msg\.sender\)\.call", "weight": 20, "label": "Sender Call"},
    ],
    "tx-origin": [
        {"pattern": r"tx\.origin\s*==",             "weight": 40, "label": "tx.origin Comparison"},
        {"pattern": r"require\s*\(\s*tx\.origin",   "weight": 40, "label": "tx.origin Require"},
        {"pattern": r"msg\.sender",                 "weight": 10, "label": "msg.sender Present"},
        {"pattern": r"\btransfer\b|\bsend\b|\bcall\b", "weight": 10, "label": "Value Transfer"},
    ],
    "unprotected-selfdestruct": [
        {"pattern": r"\bselfdestruct\b|\bsuicide\b", "weight": 40, "label": "Selfdestruct Present"},
        {"pattern": r"payable\(msg\.sender\)",        "weight": 20, "label": "Payable Sender"},
        {"pattern": r"(?:public|external)\s+(?!.*\bonlyOwner\b)", "weight": 20, "label": "Public Function"},
        {"pattern": r"address\s+\w+\s*=\s*msg\.sender", "weight": 20, "label": "User Controlled Address"},
    ],
    "integer-overflow": [
        {"pattern": r"pragma solidity\s+[\^>=]*\s*0\.[0-7]\.", "weight": 40, "label": "Pre-0.8 Pragma"},
        {"pattern": r"\+=|-=|\*=",                             "weight": 20, "label": "Arithmetic Assignment"},
        {"pattern": r"uint\d*\s+\w+\s*=\s*\w+\s*[+\-\*]",   "weight": 20, "label": "Uint Arithmetic"},
        {"pattern": r"(?<!SafeMath\.)(?:add|sub|mul)\b",       "weight": 20, "label": "No SafeMath"},
    ],
    "access-control": [
        {"pattern": r"\.transfer\(|\.send\(|\.call\{value:",  "weight": 20, "label": "Value Transfer"},
        {"pattern": r"\bpublic\b|\bexternal\b",               "weight": 20, "label": "Public Function"},
        {"pattern": r"owner\s*=\s*|transferOwnership",        "weight": 20, "label": "Ownership Assignment"},
        {"pattern": r"msg\.sender",                           "weight": 20, "label": "User Input"},
        {"pattern": r"(?!.*\bonlyOwner\b)(?!.*\bonlyRole\b)(?!.*\bhasRole\b)", "weight": 20, "label": "No Auth Guard"},
    ],
    "unsafe-delegatecall": [
        {"pattern": r"\.delegatecall\(",              "weight": 40, "label": "Delegatecall Present"},
        {"pattern": r"address\s+\w+\s*=\s*\w+\[",   "weight": 20, "label": "Dynamic Address"},
        {"pattern": r"owner|admin",                   "weight": 20, "label": "Admin Variable"},
        {"pattern": r"slot0|assembly",                "weight": 20, "label": "Storage Manipulation"},
    ],
    "unchecked-call": [
        {"pattern": r"\.call\b(?!\{value:)",          "weight": 20, "label": "Raw Call"},
        {"pattern": r"\.send\(",                      "weight": 20, "label": "Send Call"},
        {"pattern": r"bool\s+\w+\s*=\s*.*\.call|bool\s+success", "weight": 20, "label": "Return Capture"},
        {"pattern": r"require\s*\(.*success|if\s*\(.*success", "weight": 20, "label": "Return Check"},
        {"pattern": r"(?:payable|transfer)\s*\(",     "weight": 20, "label": "ETH Involved"},
    ],
    "timestamp-dependence": [
        {"pattern": r"block\.timestamp",                          "weight": 40, "label": "Timestamp Used"},
        {"pattern": r"block\.timestamp\s*%|keccak256.*block\.",   "weight": 40, "label": "Timestamp Randomness"},
        {"pattern": r"now\b",                                     "weight": 20, "label": "Deprecated now"},
    ],
    "denial-of-service": [
        {"pattern": r"for\s*\([^)]*\.length",         "weight": 40, "label": "Unbounded Loop"},
        {"pattern": r"\.transfer\(|\.send\(",         "weight": 20, "label": "Loop with Transfer"},
        {"pattern": r"push\s*\(",                     "weight": 20, "label": "Array Growth"},
        {"pattern": r"mapping\s*\(.*=>\s*\w+\[\]",   "weight": 20, "label": "Mapping of Arrays"},
    ],
}


def calculate_evidence_score(vuln_type: str, contract_code: str) -> Dict[str, Any]:
    conditions = EVIDENCE_CONDITIONS.get(vuln_type, [])
    if not conditions or not contract_code:
        return {"evidence_score": 50, "evidence_confidence": "MEDIUM"}

    total_weight   = sum(c["weight"] for c in conditions)
    matched_weight = sum(c["weight"] for c in conditions if re.search(c["pattern"], contract_code))
    score = int((matched_weight / total_weight) * 100) if total_weight > 0 else 50

    # Issue #4: thresholds aligned with the 5-point system
    if score >= 80:
        confidence = "HIGH"
    elif score >= 40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {"evidence_score": score, "evidence_confidence": confidence}


# ── Issue #3: Speculative claim → required code evidence ──────────────────────
# If a narrative step makes a claim, at least one of its patterns must match the
# contract code.  Missing evidence → the step is replaced with a safe fallback.
_SPECULATIVE_CLAIMS: List[Dict[str, Any]] = [
    {
        "keywords": ["reassigns ownership", "reassign ownership", "transfer ownership"],
        "patterns": [r"\bowner\s*=\b", r"\btransferOwnership\b", r"\b_transferOwnership\b"],
        "fallback": "Attacker modifies unprotected state variable to gain elevated privileges",
    },
    {
        "keywords": ["contract takeover", "fully controlled by attacker", "now controls the contract"],
        "patterns": [r"\bowner\s*=\b", r"\btransferOwnership\b", r"\bselfdestruct\b"],
        "fallback": "Attacker executes privileged function without authorization",
    },
    {
        "keywords": ["selfdestruct", "bytecode permanently deleted", "contract destroyed"],
        "patterns": [r"\bselfdestruct\b", r"\bsuicide\b"],
        "fallback": "Attacker corrupts contract state — recovery may be impossible",
    },
    {
        "keywords": ["upgrade control", "upgrade the contract", "proxy upgrade"],
        "patterns": [r"\bupgradeTo\b", r"\bdelegatecall\b", r"\bproxy\b"],
        "fallback": "Attacker tampers with implementation logic",
    },
    {
        "keywords": ["admin privilege escalation", "privilege escalation"],
        "patterns": [r"\bowner\s*=\b", r"\badmin\s*=\b", r"\brole\b", r"\bACCESS_CONTROL\b"],
        "fallback": "Attacker bypasses authorization check",
    },
]


def _filter_speculative_steps(steps: List[str], contract_code: str) -> List[str]:
    """Remove or replace attack steps not supported by code evidence."""
    if not contract_code:
        return steps

    filtered: List[str] = []
    for step in steps:
        step_lower = step.lower()
        replaced = False
        for claim in _SPECULATIVE_CLAIMS:
            if any(kw in step_lower for kw in claim["keywords"]):
                if not any(re.search(p, contract_code) for p in claim["patterns"]):
                    logger.debug(f"Speculative step replaced: '{step[:60]}...'")
                    # Only add the fallback once per claim type
                    if claim["fallback"] not in filtered:
                        filtered.append(claim["fallback"])
                    replaced = True
                    break
        if not replaced:
            filtered.append(step)

    # Always keep at least 2 steps so the path is meaningful
    return filtered if len(filtered) >= 2 else steps[:2]


# ── Evidence-conditional narrative step builders ───────────────────────────────

def _ac_steps(vuln: Dict, code: str = "") -> List[str]:
    """Access-control steps conditioned on what the contract actually contains."""
    base = [
        f"Privileged function {vuln['function']}() lacks onlyOwner or role-based guard",
        "Any external address directly invokes the unprotected admin function",
    ]
    if code:
        if re.search(r"\bowner\s*=\b|\btransferOwnership\b", code):
            base += [
                "Attacker reassigns contract ownership to their address",
                "New owner drains funds or executes destructive admin operations",
            ]
        elif re.search(r"\bselfdestruct\b|\bsuicide\b", code):
            base += [
                "Attacker triggers selfdestruct — all ETH transferred and code deleted",
                "Contract permanently destroyed — all user funds irretrievably lost",
            ]
        elif re.search(r"\.transfer\(|\.send\(|\.call\{value:", code):
            base += [
                "Attacker drains ETH balance via unguarded value-transfer call",
                "ETH irreversibly moved to attacker-controlled address",
            ]
        else:
            base += [
                "Attacker modifies critical contract parameters via unprotected call",
                "Contract integrity compromised — state permanently altered",
            ]
    else:
        base += [
            "Attacker modifies critical state or drains assets",
            "Protocol integrity permanently compromised",
        ]
    return base


# ── Causal rules ───────────────────────────────────────────────────────────────
CAUSAL_RULES = [
    {
        "trigger": "tx-origin",
        "enables": "unprotected-selfdestruct",
        "mechanism": "tx.origin auth bypass allows unauthorized selfdestruct call",
        "edge": "enables",
    },
    {
        "trigger": "tx-origin",
        "enables": "arbitrary-send",
        "mechanism": "tx.origin auth bypass grants unauthorized fund transfer access",
        "edge": "enables",
    },
    {
        "trigger": "unsafe-delegatecall",
        "enables": "arbitrary-send",
        "mechanism": "delegatecall storage corruption overwrites owner → enables theft",
        "edge": "enables",
    },
    {
        "trigger": "reentrancy",
        "enables": "integer-overflow",
        "mechanism": "repeated reentrant calls can amplify overflow conditions",
        "edge": "amplifies",
    },
]

COMPOUND_RULES = [
    {
        "typeA": "integer-overflow",
        "typeB": "unchecked-call",
        "title": "Silent Overflow + Transfer Chain",
        "mechanism": "integer-overflow corrupts balance value, unchecked-call silently transfers inflated amount without revert",
        "edge": "amplifies",
    },
    {
        "typeA": "access-control",
        "typeB": "unprotected-selfdestruct",
        "title": "Privilege Escalation → Contract Destruction",
        "mechanism": "missing access control lets attacker invoke selfdestruct enabling fund theft and permanent contract deletion",
        "edge": "enables",
    },
    {
        "typeA": "flash-loan-attack",
        "typeB": "reentrancy",
        "title": "Flash Loan Reentrancy Combo",
        "mechanism": "flash loan provides capital to trigger reentrancy, amplifying drain amount within a single atomic transaction",
        "edge": "amplifies",
    },
]

# ── Narrative templates ────────────────────────────────────────────────────────
# Steps signature: (vuln, code="") so evidence-conditional builders can check the code.
# Non-speculative templates use a simple lambda with a default code="" arg.
NARRATIVE_TEMPLATES = [
    {
        "type": "reentrancy",
        "title": "Reentrancy → Drain ETH Balance",
        "steps": lambda vuln, code="": [
            "Attacker deploys malicious contract with reentrant fallback/receive function",
            "Attacker calls deposit() to establish valid balance",
            f"Attacker calls {vuln['function']}() — ETH sent before state update",
            "Malicious fallback re-enters before balance is decremented",
            "Loop repeats until contract ETH balance is zero",
        ],
    },
    {
        "type": "tx-origin",
        "title": "tx.origin Auth Bypass → Phishing Takeover",
        "steps": lambda vuln, code="": [
            "Attacker deploys phishing contract disguised as legitimate service",
            "Victim (owner) interacts with the phishing contract",
            "Phishing contract calls privileged target function — tx.origin == owner passes",
            "Attacker gains owner-level access and executes malicious action",
        ],
    },
    {
        "type": "unprotected-selfdestruct",
        "title": "Unprotected Selfdestruct → Permanent Fund Loss",
        "steps": lambda vuln, code="": [
            f"Attacker calls {vuln['function']}() which contains an unguarded selfdestruct",
            "selfdestruct transfers all contract ETH to attacker address",
            "Contract bytecode permanently deleted from blockchain state",
            "All user funds permanently lost — no recovery mechanism exists",
        ],
    },
    {
        "type": "unsafe-delegatecall",
        "title": "Unsafe Delegatecall → Storage Hijack",
        "steps": lambda vuln, code="": [
            "Attacker provides malicious implementation contract address",
            "delegatecall executes attacker code in victim contract's storage context",
            "Attacker overwrites storage slot 0 (owner variable) with their address",
            "Attacker is now owner — drains all funds via privileged functions",
        ],
    },
    {
        "type": "integer-overflow",
        "title": "Integer Overflow → Inflated Balance Withdrawal",
        "steps": lambda vuln, code="": [
            "Attacker crafts input value near uint256 maximum boundary",
            f"Arithmetic in {vuln['function']}() wraps from MAX back to 0 or attacker-controlled value",
            "Balance or counter holds incorrect inflated value due to overflow",
            "Attacker withdraws far more than originally deposited",
        ],
    },
    {
        "type": "access-control",
        "title": "Access Control → Unauthorized Admin Action",
        # Evidence-conditional: _ac_steps checks what is actually in the code
        "steps": _ac_steps,
    },
    {
        "type": "flash-loan-attack",
        "title": "Flash Loan → Oracle Manipulation → Reserve Drain",
        "steps": lambda vuln, code="": [
            "Attacker identifies protocol reads price from manipulable on-chain AMM spot",
            "Attacker borrows large capital amount via flash loan in single transaction",
            "Attacker executes large swap to artificially move oracle price",
            "Protocol calculates collateral or exchange rate using manipulated price",
            "Attacker extracts protocol reserves then repays flash loan atomically",
        ],
    },
    {
        "type": "front-running",
        "title": "Front-Running → MEV Profit Extraction",
        "steps": lambda vuln, code="": [
            "Attacker monitors mempool for high-value pending transactions",
            f"Attacker detects profitable pending call to {vuln['function']}()",
            "Attacker submits identical or interfering transaction with higher gas price",
            "Miner prioritizes attacker transaction — it executes first",
            "Victim receives worse price, loses opportunity, or transaction fails",
        ],
    },
    {
        "type": "timestamp-dependence",
        "title": "Timestamp Manipulation → Miner-Controlled Outcome",
        "steps": lambda vuln, code="": [
            f"{vuln['function']}() uses block.timestamp for time-sensitive or randomness logic",
            "Miner identifies 15-second timestamp manipulation window",
            "Miner adjusts block timestamp to trigger the desired contract condition",
            "Time-locked or randomness-dependent function executes ahead of schedule",
            "Attacker wins lottery, auction, or time-gated reward unfairly",
        ],
    },
    {
        "type": "denial-of-service",
        "title": "Denial of Service → Function Permanently Bricked",
        "steps": lambda vuln, code="": [
            f"{vuln['function']}() iterates over user-controlled or unbounded array",
            "Attacker repeatedly adds entries to inflate array size and gas cost",
            "Array grows until single iteration exceeds block gas limit",
            "Every subsequent call to the function reverts due to out-of-gas",
            "Critical function permanently uncallable — contract funds locked forever",
        ],
    },
]


_EDGE_RELATIONS = ["enables", "triggers", "causes", "results in", "leads to"]

_STEP_COUNT_TO_TYPES: Dict[int, List[str]] = {
    1: ["final-impact"],
    2: ["root-cause", "final-impact"],
    3: ["root-cause", "exploit-action", "final-impact"],
    4: ["root-cause", "trigger", "exploit-action", "final-impact"],
}


def _steps_to_nodes_edges(steps: List[str]) -> tuple:
    n = len(steps)
    if n in _STEP_COUNT_TO_TYPES:
        types = _STEP_COUNT_TO_TYPES[n]
    else:
        types = ["root-cause", "trigger", "exploit-action"] + ["cascade-effect"] * (n - 4) + ["final-impact"]

    nodes = []
    for i, (step, node_type) in enumerate(zip(steps, types)):
        words = step.split()
        label = " ".join(words[:6]) + ("..." if len(words) > 6 else "")
        nodes.append({"id": f"n{i}", "type": node_type, "label": label, "description": step})

    edges = []
    for i in range(len(nodes) - 1):
        edges.append({"from": f"n{i}", "to": f"n{i + 1}", "relation": _EDGE_RELATIONS[i] if i < len(_EDGE_RELATIONS) else "→"})

    return nodes, edges


def _build_path_from_template(template: Dict, match: Dict, contract_code: str = "") -> Dict:
    # Issue #3: pass contract_code to evidence-conditional step builders
    try:
        steps = template["steps"](match, contract_code)
    except TypeError:
        steps = template["steps"](match)

    # Issue #3: filter out speculative steps not supported by code evidence
    steps = _filter_speculative_steps(steps, contract_code)

    nodes, edges = _steps_to_nodes_edges(steps)
    if nodes and match.get("lineNumber"):
        nodes[0]["lineNumber"] = match["lineNumber"]

    path = {
        "id":       f"path_{template['type']}",
        "from":     "attacker",
        "to":       match["type"],
        "mechanism": steps[0],
        "edge":     "exploits",
        "title":    template["title"],
        "severity": match.get("severity"),
        "summary":  " ".join(steps[-2:]) if len(steps) >= 2 else steps[0],
        "nodes":    nodes,
        "edges":    edges,
    }
    logger.debug(f"path object title: {path['title']}")
    return path


def build_causal_paths(vulnerabilities: List[Dict], contract_code: str = "") -> Dict:
    actionable = [v for v in vulnerabilities if v.get("severity") != "info"]
    logger.debug(f"causalEngine input: {[v['type'] for v in actionable]}")

    if not actionable:
        logger.debug("build_causal_paths: no actionable vulns — skipping path generation")
        return {"paths": [], "criticalPathId": None}

    types = {v["type"] for v in actionable}
    paths: List[Dict] = []

    # Per-vulnerability template paths
    for template in NARRATIVE_TEMPLATES:
        match = next((v for v in actionable if v["type"] == template["type"]), None)
        logger.debug(f"checking template: {template['type']} → match: {bool(match)}")
        if match:
            path = _build_path_from_template(template, match, contract_code)
            if contract_code:
                path.update(calculate_evidence_score(match["type"], contract_code))
            paths.append(path)
            logger.debug(f"pushed path: {path['title']} | total paths: {len(paths)}")

    # Single-vuln causal rules
    for rule in CAUSAL_RULES:
        trigger_found = rule["trigger"] in types
        enables_found = rule["enables"] in types
        if trigger_found and enables_found:
            rule_steps = [
                f"{rule['trigger']} vulnerability present — auth bypass becomes possible",
                rule["mechanism"],
                f"{rule['enables']} exploited via chained {rule['trigger']} attack",
            ]
            rule_steps = _filter_speculative_steps(rule_steps, contract_code)
            rule_nodes, rule_edges = _steps_to_nodes_edges(rule_steps)
            rule_path: Dict[str, Any] = {
                "id":       f"rule_{rule['trigger']}_to_{rule['enables']}",
                "from":     rule["trigger"],
                "to":       rule["enables"],
                "mechanism": rule["mechanism"],
                "edge":     rule["edge"],
                "title":    f"{rule['trigger'].replace('-', ' ').title()} → {rule['enables'].replace('-', ' ').title()}",
                "summary":  rule["mechanism"],
                "nodes":    rule_nodes,
                "edges":    rule_edges,
            }
            if contract_code:
                rule_path.update(calculate_evidence_score(rule["enables"], contract_code))
            paths.append(rule_path)

    # Compound rules
    for rule in COMPOUND_RULES:
        a_found = rule["typeA"] in types
        b_found = rule["typeB"] in types
        if a_found and b_found:
            compound_steps = [
                f"{rule['typeA'].replace('-', ' ')} vulnerability corrupts contract state",
                rule["mechanism"],
                f"{rule['typeB'].replace('-', ' ')} exploited via compound {rule['typeA'].replace('-', ' ')} chain",
                f"Compound attack complete — {rule['title']}",
            ]
            compound_steps = _filter_speculative_steps(compound_steps, contract_code)
            compound_nodes, compound_edges = _steps_to_nodes_edges(compound_steps)
            compound_path: Dict[str, Any] = {
                "id":       f"compound_{rule['typeA']}_{rule['typeB']}",
                "from":     rule["typeA"],
                "to":       rule["typeB"],
                "mechanism": rule["mechanism"],
                "edge":     rule["edge"],
                "compound": True,
                "title":    rule["title"],
                "summary":  rule["mechanism"],
                "nodes":    compound_nodes,
                "edges":    compound_edges,
            }
            if contract_code:
                compound_path.update(calculate_evidence_score(rule["typeA"], contract_code))
            paths.append(compound_path)

    critical_path = max(
        (p for p in paths),
        key=lambda p: SEVERITY_RANK.get(p.get("severity") or "", 0),
        default=None,
    )

    logger.debug(f"causalEngine RETURNING paths count: {len(paths)}")
    return {
        "paths": paths,
        "criticalPathId": critical_path["id"] if critical_path else None,
    }


def build_attack_narrative(
    vulnerabilities: List[Dict],
    prebuilt_paths: Optional[Any] = None,
) -> List[str]:
    priority = ["critical", "high", "medium", "low", "info"]
    sorted_vulns = sorted(
        [v for v in vulnerabilities if v.get("severity") != "info"],
        key=lambda v: priority.index(v.get("severity", "info")),
    )

    if not sorted_vulns:
        return [
            "No exploitable vulnerabilities detected",
            "Contract follows secure coding patterns",
            "Recommend formal audit for business logic edge cases",
        ]

    if prebuilt_paths is None:
        raw = build_causal_paths(vulnerabilities)
        causal_paths: List[Dict] = raw["paths"]
    elif isinstance(prebuilt_paths, list):
        causal_paths = prebuilt_paths
    else:
        causal_paths = prebuilt_paths.get("paths", [])

    steps: List[str] = []
    primary = sorted_vulns[0]

    steps.append(
        f"Attacker identifies {primary['type'].replace('-', ' ')} in {primary['function']}() via on-chain analysis"
    )

    for path in (p for p in causal_paths if p.get("compound")):
        steps.append(f"Compound attack chain detected: {path.get('title', '')}")
        steps.append(path["mechanism"])

    for path in (p for p in causal_paths if not p.get("compound")):
        steps.append(path["mechanism"])

    template = next((t for t in NARRATIVE_TEMPLATES if t["type"] == primary["type"]), None)
    if template:
        try:
            steps.extend(template["steps"](primary, ""))
        except TypeError:
            steps.extend(template["steps"](primary))
    else:
        steps.append(f"Attacker crafts transaction targeting {primary['function']}()")
        steps.append("Vulnerability exploited to bypass security checks")
        steps.append("Attacker extracts value or corrupts contract state")
        steps.append("Protocol damage complete")

    terminal_words = ("permanently", "zero", "atomically", "forever")
    if not any(word in s for s in steps for word in terminal_words):
        steps.append("Attacker withdraws stolen funds to external wallet")

    return steps


# ── Pydantic schemas for AI causal path validation ────────────────────────────
class CausalNodeSchema(BaseModel):
    id: str
    type: str
    label: str
    description: str
    lineNumber: Optional[int] = None

    @validator('type')
    def validate_type(cls, v):
        allowed = {'root-cause', 'trigger', 'exploit-action', 'cascade-effect', 'final-impact'}
        if v not in allowed:
            raise ValueError(f'Invalid node type: {v}')
        return v

    @validator('lineNumber', pre=True)
    def coerce_line_number(cls, v):
        if v is None or v == '' or v == 'unknown':
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None


class CausalEdgeSchema(BaseModel):
    from_node: str = Field(alias='from')
    to: str
    relation: Optional[str] = ""

    class Config:
        populate_by_name = True


class CausalPathSchema(BaseModel):
    id: str
    title: str
    severity: str
    summary: str
    from_field: str = Field(alias='from')
    to: str
    mechanism: str
    nodes: List[CausalNodeSchema]
    edges: List[CausalEdgeSchema]

    class Config:
        populate_by_name = True


class CausalOutputSchema(BaseModel):
    paths: List[CausalPathSchema]
    criticalPathId: Optional[str] = None


# ── AI-powered causal path generation (with static fallback) ──────────────────
async def generate_ai_causal_paths(
    vulnerabilities: List[Dict],
    call_groq: Callable[[str], Awaitable[str]],
    language: str = "en",
    contract_code: str = "",
) -> Dict:
    actionable = [v for v in vulnerabilities if v.get("severity") != "info"]
    logger.debug(
        f"non-info vulns: {[{'type': v['type'], 'severity': v['severity']} for v in actionable]}"
    )

    if not actionable:
        logger.debug(
            f"generateAICausalPaths: no actionable vulns — total input length: {len(vulnerabilities)}"
        )
        return {"paths": [], "criticalPathId": None}

    def _enrich_with_evidence(paths: List[Dict]) -> List[Dict]:
        if not contract_code:
            return paths
        for p in paths:
            vuln_type = p.get("to", p.get("from", ""))
            p.update(calculate_evidence_score(vuln_type, contract_code))
        return paths

    def _apply_evidence_filter(paths: List[Dict]) -> List[Dict]:
        """Post-process AI paths to remove speculative steps not grounded in code."""
        if not contract_code:
            return paths
        for p in paths:
            nodes = p.get("nodes", [])
            filtered_nodes = []
            for node in nodes:
                desc = node.get("description", "")
                desc_lower = desc.lower()
                speculative = False
                for claim in _SPECULATIVE_CLAIMS:
                    if any(kw in desc_lower for kw in claim["keywords"]):
                        if not any(re.search(pat, contract_code) for pat in claim["patterns"]):
                            short_label = claim["fallback"].split("—")[0].strip()[:30]
                            node = {**node, "description": claim["fallback"], "label": short_label}
                            speculative = True
                            logger.debug(f"AI node claim replaced: '{desc[:60]}'")
                            break
                filtered_nodes.append(node)
            p["nodes"] = filtered_nodes
        return paths

    vuln_summary = "\n".join(
        f"- {v['type']} ({v['severity']}) in {v['function']}() at line {v.get('lineNumber', '?')}"
        for v in actionable
    )

    function_names = json.dumps([v.get('function', 'unknown') for v in actionable])

    # Issue #3: inject contract snippet evidence into the prompt to ground AI output
    code_snippet = ""
    if contract_code:
        lines = contract_code.split('\n')
        focal_lines = [v.get("lineNumber") for v in actionable if v.get("lineNumber")]
        if focal_lines:
            center = min(focal_lines)
            start = max(0, center - 20)
            end = min(len(lines), center + 40)
        else:
            start, end = 0, 60
        snippet_lines = lines[start:end]
        line_offset = start + 1
        code_snippet = f"""
CONTRACT CODE lines {line_offset}–{line_offset + len(snippet_lines) - 1} (use this as the ONLY evidence for your attack steps):
```solidity
{chr(10).join(snippet_lines)}
```

EVIDENCE-BASED RULES — ANTI-HALLUCINATION:
- Do NOT claim ownership reassignment unless `owner =` or `transferOwnership` appears in the code above.
- Do NOT claim admin privilege escalation unless an admin/owner assignment appears in the code above.
- Do NOT claim upgrade/proxy attack unless `delegatecall` or `upgradeTo` appears in the code above.
- Do NOT claim contract destruction unless `selfdestruct` appears in the code above.
- Every attack step must be directly inferrable from the code snippet above.
"""

    prompt = f"""You are a smart contract security expert.
Given these vulnerabilities detected by Slither static analysis:
{vuln_summary}
{code_snippet}
STRICT RULES — VIOLATIONS WILL CAUSE SYSTEM FAILURE:
1. You MUST ONLY generate paths for vulnerabilities in the list above.
2. You MUST ONLY reference function names that appear in the list above.
3. Do NOT invent new vulnerability types not present in the list.
4. Do NOT add extra paths beyond the listed vulnerabilities.
5. If a field value is unknown, use the string "unknown" — never guess.
6. Every node's description MUST reference one of these function names: {function_names}

GENERATE EXACTLY {len(actionable)} PATH(S) — ONE PER VULNERABILITY.

Generate a JSON causal attack path analysis. Return ONLY valid JSON, no markdown.

{{
  "paths": [
    {{
      "id": "path_0",
      "title": "Short attack title",
      "severity": "critical|high|medium|low",
      "summary": "2-3 sentence explanation of how attacker exploits this",
      "from": "attacker",
      "to": "vulnerability-type",
      "mechanism": "one sentence causal link",
      "nodes": [
        {{ "id": "n0", "type": "root-cause", "label": "short label", "description": "detail", "lineNumber": 16 }},
        {{ "id": "n1", "type": "trigger", "label": "short label", "description": "detail", "lineNumber": 18 }}
      ],
      "edges": [
        {{ "from": "n0", "to": "n1", "relation": "enables" }},
        {{ "from": "n1", "to": "n2", "relation": "triggers" }},
        {{ "from": "n2", "to": "n3", "relation": "causes" }},
        {{ "from": "n3", "to": "n4", "relation": "results in" }}
      ]
    }}
  ],
  "criticalPathId": "path_0"
}}

Rules:
- Generate 1 path per unique high/critical vulnerability
- If multiple vulnerabilities chain together, add 1 compound path
- Maximum 4 paths total
- Node types must be: root-cause, trigger, exploit-action, cascade-effect, final-impact
- severity must match the vulnerability severity
- Keep labels under 6 words, descriptions under 20 words
- Provide "lineNumber" for nodes mapping to specific code (use the numbers provided above)
- Omit "lineNumber" for abstract impact or trigger nodes that don't map to a specific line
{"" if language != "zh" else "- title、summary、mechanism、label、description 必須用繁體中文"}

{"[SYSTEM: 請完全用繁體中文回覆。JSON 字串值也必須是繁體中文。]" if language == "zh" else "[SYSTEM: You must respond in English only. Never use Chinese, Traditional Chinese, or any non-English language. English-only responses are mandatory.]"}"""

    try:
        raw = await ask_groq(prompt, max_tokens=2000, temperature=0.05)

        clean = raw
        json_match = re.search(r"\{[\s\S]*\}", raw)
        if json_match:
            clean = json_match.group(0)

        clean = re.sub(r"```json\s*", "", clean)
        clean = re.sub(r"```\s*", "", clean)
        clean = clean.strip()
        clean = re.sub(r"//[^\n]*", "", clean)
        clean = re.sub(r"/\*[\s\S]*?\*/", "", clean)
        clean = re.sub(r"(['\"])?([a-zA-Z0-9_\-]+)(['\"])?\s*:", r'"\2":', clean)
        clean = re.sub(r",\s*([}\]])", r"\1", clean)

        try:
            parsed = json.loads(clean)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse failed. First 500 chars of cleaned response: {clean[:500]}")
            raise e

        if not isinstance(parsed.get("paths"), list) or len(parsed["paths"]) == 0:
            raise ValueError("AI returned empty paths array")

        try:
            validated = CausalOutputSchema(**parsed)
            validated_data = validated.dict(by_alias=True)
            logger.info(f"AI causal paths generated: {len(validated_data['paths'])}")
            result_paths = _enrich_with_evidence(validated_data["paths"])
            result_paths = _apply_evidence_filter(result_paths)
            return {
                "paths": result_paths,
                "criticalPathId": validated_data.get("criticalPathId"),
            }
        except Exception as e:
            logger.warning(f"AI causal output validation failed: {e}")
            fallback_result = build_causal_paths(vulnerabilities, contract_code)
            return {
                "paths": _enrich_with_evidence(fallback_result["paths"]),
                "criticalPathId": fallback_result.get("criticalPathId"),
            }

    except Exception as err:
        logger.warning(f"AI causal path generation failed, falling back to static: {err}")
        fallback_result = build_causal_paths(vulnerabilities, contract_code)
        return {
            "paths": _enrich_with_evidence(fallback_result["paths"]),
            "criticalPathId": fallback_result.get("criticalPathId"),
        }
