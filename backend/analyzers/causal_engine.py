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

# ── Single-vulnerability causal rules ──────────────────────────────────────
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

# ── Compound path rules (two vulnerabilities merge into one chain) ─────────
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
        "mechanism": "missing access control lets attacker claim ownership, enabling immediate selfdestruct and fund theft",
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

# ── Narrative templates — one entry per vulnerability type ─────────────────
# Each template["steps"] is a callable (vuln) -> List[str].
# All 10 templates from the original causalEngine.ts are preserved verbatim.
NARRATIVE_TEMPLATES = [
    {
        "type": "reentrancy",
        "title": "Reentrancy → Drain ETH Balance",
        "steps": lambda vuln: [
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
        "steps": lambda vuln: [
            "Attacker deploys phishing contract disguised as legitimate service",
            "Victim (owner) interacts with phishing contract",
            "Phishing contract calls privileged target function — tx.origin == owner passes",
            "Attacker gains owner-level access and executes malicious action",
        ],
    },
    {
        "type": "unprotected-selfdestruct",
        "title": "Unprotected Selfdestruct → Permanent Fund Loss",
        "steps": lambda vuln: [
            f"Attacker calls {vuln['function']}() containing selfdestruct",
            "selfdestruct transfers all ETH to attacker address",
            "Contract bytecode permanently deleted from blockchain",
            "All user funds permanently lost — no recovery possible",
        ],
    },
    {
        "type": "unsafe-delegatecall",
        "title": "Unsafe Delegatecall → Storage Hijack",
        "steps": lambda vuln: [
            "Attacker provides malicious implementation contract address",
            "delegatecall executes attacker code in victim contract storage context",
            "Attacker overwrites storage slot 0 (owner variable) with their address",
            "Attacker is now owner — drains all funds via privileged functions",
        ],
    },
    {
        "type": "integer-overflow",
        "title": "Integer Overflow → Inflated Balance Withdrawal",
        "steps": lambda vuln: [
            "Attacker crafts input value near uint256 maximum boundary",
            f"Arithmetic in {vuln['function']}() wraps from MAX back to 0 or attacker-controlled value",
            "Balance or counter holds incorrect inflated value due to overflow",
            "Attacker withdraws far more than originally deposited",
        ],
    },
    {
        "type": "access-control",
        "title": "Access Control → Contract Takeover",
        "steps": lambda vuln: [
            f"Privileged function {vuln['function']}() lacks onlyOwner or role check",
            "Any external address calls the unprotected admin function directly",
            "Attacker reassigns ownership or modifies critical contract parameters",
            "Contract now fully controlled by attacker — funds drained or contract destroyed",
        ],
    },
    {
        "type": "flash-loan-attack",
        "title": "Flash Loan → Oracle Manipulation → Reserve Drain",
        "steps": lambda vuln: [
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
        "steps": lambda vuln: [
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
        "steps": lambda vuln: [
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
        "steps": lambda vuln: [
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


def _build_path_from_template(template: Dict, match: Dict) -> Dict:
    steps = template["steps"](match)
    nodes, edges = _steps_to_nodes_edges(steps)
    # Root-cause node gets the vulnerability's actual line number so the editor can scroll to it
    if nodes and match.get("lineNumber"):
        nodes[0]["lineNumber"] = match["lineNumber"]
    path = {
        "id": f"path_{template['type']}",
        "from": "attacker",
        "to": match["type"],
        "mechanism": steps[0],
        "edge": "exploits",
        "title": template["title"],
        "severity": match.get("severity"),
        "summary": " ".join(steps[-2:]) if len(steps) >= 2 else steps[0],
        "nodes": nodes,
        "edges": edges,
    }
    logger.debug(f"path object title: {path['title']}")
    return path


def build_causal_paths(vulnerabilities: List[Dict]) -> Dict:
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
            path = _build_path_from_template(template, match)
            paths.append(path)
            logger.debug(f"pushed path: {path['title']} | total paths: {len(paths)}")

    # Single-vuln causal rules
    for rule in CAUSAL_RULES:
        trigger_found = rule["trigger"] in types
        enables_found = rule["enables"] in types
        logger.debug(f"checking rule: {rule['trigger']} → {rule['enables']} | trigger: {trigger_found}, enables: {enables_found}")
        if trigger_found and enables_found:
            rule_steps = [
                f"{rule['trigger']} vulnerability present — auth bypass becomes possible",
                rule["mechanism"],
                f"{rule['enables']} exploited via chained {rule['trigger']} attack",
            ]
            rule_nodes, rule_edges = _steps_to_nodes_edges(rule_steps)
            paths.append({
                "id": f"rule_{rule['trigger']}_to_{rule['enables']}",
                "from": rule["trigger"],
                "to": rule["enables"],
                "mechanism": rule["mechanism"],
                "edge": rule["edge"],
                "title": f"{rule['trigger'].replace('-', ' ').title()} → {rule['enables'].replace('-', ' ').title()}",
                "summary": rule["mechanism"],
                "nodes": rule_nodes,
                "edges": rule_edges,
            })

    # Compound rules
    for rule in COMPOUND_RULES:
        a_found = rule["typeA"] in types
        b_found = rule["typeB"] in types
        logger.debug(f"checking compound: {rule['typeA']} + {rule['typeB']} | A: {a_found}, B: {b_found}")
        if a_found and b_found:
            compound_steps = [
                f"{rule['typeA'].replace('-', ' ')} vulnerability corrupts contract state",
                rule["mechanism"],
                f"{rule['typeB'].replace('-', ' ')} exploited via compound {rule['typeA'].replace('-', ' ')} chain",
                f"Compound attack complete — {rule['title']}",
            ]
            compound_nodes, compound_edges = _steps_to_nodes_edges(compound_steps)
            paths.append({
                "id": f"compound_{rule['typeA']}_{rule['typeB']}",
                "from": rule["typeA"],
                "to": rule["typeB"],
                "mechanism": rule["mechanism"],
                "edge": rule["edge"],
                "compound": True,
                "title": rule["title"],
                "summary": rule["mechanism"],
                "nodes": compound_nodes,
                "edges": compound_edges,
            })

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

    # Reuse pre-built paths to avoid a second build_causal_paths call
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
    logger.debug(f"checking template: {primary['type']} → match: {bool(template)}")
    if template:
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


# ── Pydantic schemas for AI causal path validation ────────────────────────
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


# ── AI-powered causal path generation (with static fallback) ───────────────
async def generate_ai_causal_paths(
    vulnerabilities: List[Dict],
    call_groq: Callable[[str], Awaitable[str]],
    language: str = "en",
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

    vuln_summary = "\n".join(
        f"- {v['type']} ({v['severity']}) in {v['function']}() at line {v.get('lineNumber', '?')}"
        for v in actionable
    )

    function_names = json.dumps([v.get('function', 'unknown') for v in actionable])
    prompt = f"""You are a smart contract security expert.
Given these vulnerabilities detected by Slither static analysis:
{vuln_summary}

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

        # Step 1: Extract outermost JSON object
        clean = raw
        json_match = re.search(r"\{[\s\S]*\}", raw)
        if json_match:
            clean = json_match.group(0)

        # Step 2: Remove markdown fences
        clean = re.sub(r"```json\s*", "", clean)
        clean = re.sub(r"```\s*", "", clean)
        clean = clean.strip()

        # Step 3: Remove JS-style comments
        clean = re.sub(r"//[^\n]*", "", clean)
        clean = re.sub(r"/\*[\s\S]*?\*/", "", clean)

        # Step 4: Normalize unquoted / single-quoted property names
        clean = re.sub(r"(['\"])?([a-zA-Z0-9_\-]+)(['\"])?\s*:", r'"\2":', clean)

        # Step 5: Remove trailing commas before } or ]
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
            return {
                "paths": validated_data["paths"],
                "criticalPathId": validated_data.get("criticalPathId"),
            }
        except Exception as e:
            logger.warning(f"AI causal output validation failed: {e}")
            fallback_result = build_causal_paths(vulnerabilities)
            return {
                "paths": fallback_result["paths"],
                "criticalPathId": fallback_result.get("criticalPathId"),
            }

    except Exception as err:
        logger.warning(f"AI causal path generation failed, falling back to static: {err}")
        fallback_result = build_causal_paths(vulnerabilities)
        return {
            "paths": fallback_result["paths"],
            "criticalPathId": fallback_result.get("criticalPathId"),
        }
