import asyncio
import json
import logging
import os
from typing import Any, List

import httpx

logger = logging.getLogger(__name__)

GROQ_MODEL = "llama-3.1-8b-instant"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Limit concurrent Groq requests to avoid 429 rate-limit errors
_groq_semaphore = asyncio.Semaphore(3)


async def ask_groq(prompt: str, max_tokens: int = 800, temperature: float = 0.2) -> str:
    async with _groq_semaphore:
        return await _ask_groq_inner(prompt, max_tokens, temperature)


async def _ask_groq_inner(prompt: str, max_tokens: int, temperature: float) -> str:
    max_retries = 3
    last_error: Exception = RuntimeError("Max retries reached for Groq API")
    api_key = os.getenv("GROQ_API_KEY", "")

    async with httpx.AsyncClient(timeout=30.0) as client:
        for attempt in range(max_retries):
            try:
                res = await client.post(
                    GROQ_API_URL,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                    json={
                        "model": GROQ_MODEL,
                        "max_tokens": max_tokens,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": temperature,
                    },
                )

                if res.status_code == 429:
                    wait_ms = (2 ** attempt) * 1000  # 1000ms base for rate limit
                    logger.warning(
                        f"Groq Rate Limit (429). Retrying in {wait_ms}ms... "
                        f"(Attempt {attempt + 1}/{max_retries})"
                    )
                    await asyncio.sleep(wait_ms / 1000)
                    continue

                if res.status_code != 200:
                    err_text = res.text
                    logger.warning(
                        f"Groq API error {res.status_code}: {err_text}. "
                        "Falling back to mock response."
                    )
                    raise RuntimeError(f"API_ERROR_{res.status_code}")

                data = res.json()
                return data["choices"][0]["message"]["content"]

            except RuntimeError as e:
                if "API_ERROR" in str(e):
                    raise
                last_error = e
                wait_ms = (2 ** attempt) * 500  # 500ms base for network errors
                await asyncio.sleep(wait_ms / 1000)
            except Exception as e:
                last_error = e
                wait_ms = (2 ** attempt) * 500
                await asyncio.sleep(wait_ms / 1000)

    raise last_error


def _parse_json(raw: str, fallback: Any) -> Any:
    try:
        clean = raw.replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
    except Exception:
        return fallback


from analyzers.slither_runner import normalize_vuln_type


def _lang_system(language: str) -> str:
    """Return a SYSTEM instruction that enforces the target language."""
    if language == "zh":
        return (
            "[SYSTEM: 請完全用繁體中文（Traditional Chinese）回覆。"
            "所有 JSON 字串值也必須是繁體中文。嚴禁使用英文或其他語言。]"
        )
    return (
        "[SYSTEM: You must respond in English only. "
        "Never use Chinese, Traditional Chinese, or any non-English language. "
        "English-only responses are mandatory.]"
    )


async def analyze_contract_with_ai(code: str, language: str = "en") -> List[Any]:
    try:
        raw = await ask_groq(
            f"""{_lang_system(language)}

You are a smart contract security auditor. Analyze the following Solidity code and identify vulnerabilities (Reentrancy, tx.origin, Unprotected Selfdestruct, Access Control, Overflow, etc.).
Return ONLY a JSON array with no explanation text.
Format:
[
  {{
    "id": "AI-001",
    "type": "vulnerability-type",
    "function": "functionName",
    "severity": "critical|high|medium|low",
    "description": "concise vulnerability description",
    "lineNumber": 10
  }}
]

Contract code:
```solidity
{code[:3000]}
```""",
            1000,
        )
        vulns = _parse_json(raw, [])
        for v in vulns:
            if isinstance(v, dict) and 'type' in v:
                v['type'] = normalize_vuln_type(v['type'])
        return vulns
    except Exception:
        return []


async def generate_security_summary(code: str, vulnerabilities: List[Any], language: str = "en") -> str:
    try:
        if len(vulnerabilities) == 0:
            return await ask_groq(
                f"""{_lang_system(language)}

You are a smart contract security expert. This Solidity contract passed automated analysis with no vulnerabilities detected. Write a concise 2-3 sentence security summary for the developer. Be positive but note that automated tools cannot guarantee complete coverage.

Contract code:
```solidity
{code[:1000]}
```""",
                300,
            )

        vuln_list = "\n".join(
            f"- [{v['severity'].upper()}] {v['type']} in {v['function']}(): {v['description'][:100]}"
            for v in vulnerabilities
        )
        return await ask_groq(
            f"{_lang_system(language)}\n\nYou are a smart contract security expert. Analyze the following vulnerabilities and write a 2-3 sentence summary. Focus on the most severe risks.\n  {vuln_list}",
            300,
        )
    except Exception:
        if language == "zh":
            return "分析完成。偵測到多個漏洞，請檢閱下方漏洞清單與攻擊路徑。優先修復 Critical 和 High 級別的問題。"
        return "Analysis complete. Multiple vulnerabilities detected — review the findings list and attack paths below. Prioritize Critical and High severity fixes."


async def generate_attack_strategy(vulnerabilities: List[Any], language: str = "en") -> dict:
    if language == "zh":
        fallback = {
            "exploitType": "自動化安全風險",
            "riskLevel": "High",
            "steps": [
                "攻擊者識別合約中的邏輯缺陷",
                "攻擊者構造惡意交易資料",
                "透過外部呼叫或權限繞過執行攻擊",
                "合約資金被提取或狀態遭破壞",
            ],
        }
        no_vuln = {"exploitType": "安全", "riskLevel": "Safe", "steps": ["未偵測到漏洞。"]}
    else:
        fallback = {
            "exploitType": "Automated Security Risk",
            "riskLevel": "High",
            "steps": [
                "Attacker identifies logic flaw in the contract",
                "Attacker crafts malicious transaction data",
                "Attack executes via external call or permission bypass",
                "Contract funds drained or state corrupted",
            ],
        }
        no_vuln = {"exploitType": "Secure", "riskLevel": "Safe", "steps": ["No vulnerabilities detected."]}

    if len(vulnerabilities) == 0:
        return no_vuln

    try:
        priority = ["critical", "high", "medium", "low", "info"]
        primary = sorted(vulnerabilities, key=lambda v: priority.index(v.get("severity", "info")))[0]

        raw = await ask_groq(
            f"""{_lang_system(language)}

Generate a JSON attack strategy for the following vulnerability:
  Type: {primary['type']}
  Function: {primary['function']}()

  {{"exploitType": "...", "riskLevel": "Critical", "steps": ["step 1", "step 2", "step 3"]}}""",
            400,
        )
        return _parse_json(raw, fallback)
    except Exception:
        return fallback


_DEFENSE_FALLBACK_EN = {
    "reentrancy": (
        "External call is made before state update, enabling reentrancy drain.",
        "Apply Checks-Effects-Interactions: update balances before the external call. Add nonReentrant modifier from OpenZeppelin ReentrancyGuard.",
        'balances[msg.sender] -= amount;\n(bool ok,) = msg.sender.call{value: amount}("");\nrequire(ok);',
    ),
    "tx-origin": (
        "tx.origin is used for authentication, allowing phishing bypass.",
        "Replace tx.origin with msg.sender for all auth checks. Inherit OpenZeppelin Ownable and use the onlyOwner modifier.",
        'require(msg.sender == owner, "Not authorized");',
    ),
    "unprotected-selfdestruct": (
        "selfdestruct is callable by any address, risking permanent fund loss.",
        "Add onlyOwner modifier to restrict destruction. Consider removing selfdestruct entirely (deprecated by EIP-6049).",
        "function kill() external onlyOwner { selfdestruct(payable(owner())); }",
    ),
    "unsafe-delegatecall": (
        "delegatecall target is user-supplied, enabling storage hijack.",
        "Never delegatecall to arbitrary addresses. Maintain an explicit whitelist of trusted implementation contracts.",
        'require(trustedImpls[impl], "Untrusted impl");\nimpl.delegatecall(data);',
    ),
    "integer-overflow": (
        "Arithmetic can overflow, corrupting balance or counter values.",
        "Upgrade to Solidity 0.8+ where overflow reverts automatically. For legacy code, wrap arithmetic with OpenZeppelin SafeMath.",
        "// Solidity ^0.8.0: overflow reverts automatically\n// Legacy: balances[msg.sender] = balances[msg.sender].add(amount);",
    ),
    "access-control": (
        "Privileged function lacks access restriction and is callable by anyone.",
        "Add onlyOwner or role-based modifier to all admin functions. Use OpenZeppelin AccessControl for granular role management.",
        'bytes32 public constant ADMIN = keccak256("ADMIN");\nfunction setPrice(uint p) external onlyRole(ADMIN) { price = p; }',
    ),
    "unchecked-call": (
        "Return value of low-level call() is ignored, allowing silent failure.",
        "Always capture and check the bool return value. Prefer OpenZeppelin Address.sendValue() which reverts on failure automatically.",
        '(bool ok,) = to.call{value: amt}("");\nrequire(ok, "Transfer failed");',
    ),
    "arbitrary-send": (
        "ETH is pushed to an attacker-controlled address without validation.",
        "Adopt pull-payment pattern — let users withdraw their own funds instead of pushing to arbitrary addresses.",
        "// OpenZeppelin PullPayment:\n_asyncTransfer(msg.sender, balances[msg.sender]);\nbalances[msg.sender] = 0;",
    ),
    "timestamp-dependence": (
        "block.timestamp is used for randomness or time-gating, manipulable by miners.",
        "Never use block.timestamp as randomness source. Use Chainlink VRF v2 for verifiable randomness. Allow ±15-minute tolerance for time locks.",
        "// Chainlink VRF v2:\n// inherit VRFConsumerBaseV2, call requestRandomWords()",
    ),
    "denial-of-service": (
        "Unbounded loop over user-controlled array causes out-of-gas, bricking the function.",
        "Replace push loops with pull-payment: let each user claim their own reward. If iteration is required, add pagination with a batch size cap.",
        "// OpenZeppelin PullPayment:\nfunction claimReward() external { _asyncTransfer(msg.sender, reward); }",
    ),
    "flash-loan-attack": (
        "Spot price oracle can be manipulated via flash loan in a single transaction.",
        "Use TWAP (time-weighted average price) oracles instead of spot price. Add cooldown periods and reentrancy guards on price-sensitive paths.",
        "// Uniswap v3 TWAP:\nuint32[] memory ago = new uint32[](2); ago[0] = 300;\n(int56[] memory ticks,) = pool.observe(ago);",
    ),
    "front-running": (
        "Pending transaction is visible in mempool, allowing front-run for profit.",
        "Use commit-reveal scheme for sensitive operations. Add slippage tolerance and a deadline parameter to prevent stale execution.",
        "require(block.timestamp <= deadline, \"Tx expired\");\nrequire(amountOut >= minOut, \"Slippage\");",
    ),
}
# Aliases for Slither's native type names which differ from the normalized keys above
_DEFENSE_FALLBACK_EN["tx.origin"]    = _DEFENSE_FALLBACK_EN["tx-origin"]
_DEFENSE_FALLBACK_EN["overflow"]     = _DEFENSE_FALLBACK_EN["integer-overflow"]
_DEFENSE_FALLBACK_EN["selfdestruct"] = _DEFENSE_FALLBACK_EN["unprotected-selfdestruct"]


async def generate_defense_recommendations(vulnerabilities: List[Any], language: str = "en") -> List[Any]:
    if len(vulnerabilities) == 0:
        if language == "zh":
            return [{"issue": "無", "strategy": "繼續遵循安全最佳實踐。", "codeExample": "// 安全"}]
        return [{"issue": "None", "strategy": "Continue following security best practices.", "codeExample": "// Safe"}]

    # Deduplicate by type, preserving order, no artificial cap
    seen_types: set = set()
    unique: List[Any] = []
    for v in vulnerabilities:
        if v["type"] not in seen_types:
            seen_types.add(v["type"])
            unique.append(v)

    # Build type-specific fallback (English) or generic (Chinese — AI handles real zh)
    if language == "zh":
        fallback = [
            {
                "issue": f"{v['type']} 漏洞位於 {v['function']}()",
                "strategy": "套用針對此漏洞類型的安全模式並使用 OpenZeppelin 標準庫。",
                "codeExample": f"// 修復 {v['function']}() 中的 {v['type']} 問題",
            }
            for v in unique
        ]
    else:
        fallback = []
        for v in unique:
            normalized = v["type"].lower().replace(" ", "-")
            fb = _DEFENSE_FALLBACK_EN.get(normalized)
            if fb:
                fallback.append({"issue": fb[0], "strategy": fb[1], "codeExample": fb[2]})
            else:
                fallback.append({
                    "issue": f"{v['type']} vulnerability in {v['function']}()",
                    "strategy": "Review the function for missing access controls, unsafe patterns, or unvalidated inputs.",
                    "codeExample": f"// Audit {v['function']}() — add appropriate guards",
                })

    numbered = "\n".join(
        f"[{i + 1}] {v['type']} (severity: {v['severity']}) in {v['function']}()"
        for i, v in enumerate(unique)
    )

    try:
        raw = await ask_groq(
            f"""You are a smart contract security expert.
Generate specific defense recommendations for EACH vulnerability below.
Each recommendation must be tailored to the specific vulnerability type.
Do NOT give the same recommendation for different vulnerability types.

VULNERABILITIES TO ADDRESS:
{numbered}

For EACH vulnerability, provide a JSON object with:
- issue: the specific problem in this vulnerability (1 sentence)
- strategy: the specific fix for THIS vulnerability type (2-3 sentences)
- codeExample: a short Solidity snippet showing the fix

Return a JSON array with exactly {len(unique)} elements, one per vulnerability above, in the same order.

Rules:
- reentrancy → CEI pattern (state update BEFORE external call) + nonReentrant modifier
- tx-origin → replace with msg.sender, use OpenZeppelin Ownable
- unprotected-selfdestruct → add onlyOwner modifier, consider removing selfdestruct
- access-control → add role-based modifier, use OpenZeppelin AccessControl
- integer-overflow → upgrade to Solidity 0.8+ or use SafeMath
- unsafe-delegatecall → whitelist trusted implementations only, never accept user-supplied address
- unchecked-call → check bool return value, use Address.sendValue()
- Each entry must be DIFFERENT and specific to its vulnerability type.

Return ONLY a valid JSON array — no markdown fences, no explanation text.

{_lang_system(language)}""",
            max_tokens=min(200 * len(unique) + 200, 1400),
            temperature=0.1,
        )
        result = _parse_json(raw, fallback)
        if not isinstance(result, list) or len(result) == 0:
            return fallback
        return result
    except Exception:
        return fallback


async def generate_score_explanation(score: int, vulnerabilities: List[Any], language: str = "en") -> str:
    try:
        breakdown = ", ".join(f"{v['severity']}: {v['type']}" for v in vulnerabilities)
        return await ask_groq(
            f"{_lang_system(language)}\n\nExplain the security score {score}/100 in 2 sentences. Vulnerabilities found: {breakdown}",
            200,
        )
    except Exception:
        if language == "zh":
            return (
                f"安全評分 {score}/100，基於偵測到的 {len(vulnerabilities)} 個漏洞。"
                "分數主要受 Critical 和 High 級別風險影響。"
            )
        return (
            f"Security score: {score}/100 based on {len(vulnerabilities)} detected vulnerabilities. "
            "Score is primarily impacted by Critical and High severity findings."
        )


async def generate_copilot_answer(
    question: str,
    vulnerabilities: List[Any],
    score: float,
    language: str = "en",
) -> str:
    try:
        return await ask_groq(
            f"{_lang_system(language)}\n\nAnswer this security question: \"{question}\". Contract score: {score}/100. Vulnerability count: {len(vulnerabilities)}.",
            800,
        )
    except Exception:
        if language == "zh":
            return "AI 助手暫時無法使用。請優先檢視 Critical 漏洞並依照修復建議進行調整。"
        return "The AI assistant is temporarily unavailable. Based on static analysis, prioritize reviewing Critical vulnerabilities and follow the remediation recommendations."
