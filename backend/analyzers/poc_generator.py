import re
import logging
from typing import Any, Awaitable, Callable, List

from groq_client import ask_groq

logger = logging.getLogger(__name__)


async def generate_poc_script(
    contract_name: str,
    vulnerabilities: List[Any],
    contract_code: str,
    call_groq: Callable[[str], Awaitable[str]],
    language: str = "en",
) -> str:
    target_vulns = "\n".join(
        f"- [{v['severity'].upper()}] {v['type']} in {v['function']}() "
        f"at line {v.get('lineNumber', '?')}: {v['description']}"
        for v in vulnerabilities
        if v.get("severity") in ("critical", "high", "medium")
    )

    if not target_vulns:
        return (
            "// Vultron 安全驗證\n"
            "// 未偵測到可利用的 Critical、High 或 Medium 級別漏洞。\n"
            "// 此合約目前在自動化測試中表現為【安全】。\n"
            "// 建議定期進行人工審計以確保邏輯正確性。"
        )

    prompt = f"""You are a smart contract security researcher.
Given this Solidity contract named "{contract_name}":

{contract_code[:2000]}

With these vulnerabilities detected:
{target_vulns}

Generate a complete, runnable Hardhat test file that demonstrates the attack exploitation. The script should:
1. Deploy the vulnerable contract
2. Set up the attacker contract if needed
3. Execute the attack step by step
4. Assert that the attack succeeded (e.g. funds drained)

Return ONLY the JavaScript code, no explanation, no markdown fences.
Use ethers.js v6 syntax (ethers.deployContract, await contract.waitForDeployment).
Include comments explaining each attack step.
Contract name in the test must match: {contract_name}

IMPORTANT OUTPUT CONSTRAINTS:
- Generate ONLY the core attack logic
- Do NOT include full test suite setup (describe/before/after hooks)
- Do NOT include import statements
- Do NOT include contract deployment boilerplate
- DO include: attack contract snippet (10-20 lines) + exploit function (10-15 lines)
- DO include: 3-5 inline comments explaining attack steps
- Keep total output under 500 tokens
{"- 攻擊步驟的行內註解請用繁體中文" if language == "zh" else "- Use English for all inline comments"}

{"[SYSTEM: 攻擊腳本的行內註解請用繁體中文。程式碼本身保持 JavaScript。]" if language == "zh" else "[SYSTEM: You must respond in English only. Never use Chinese, Traditional Chinese, or any non-English language. English-only responses are mandatory.]"}"""

    try:
        raw = await ask_groq(prompt, 1200)
        # Strip markdown fences if the model wraps the output
        clean = re.sub(r"```javascript\s*", "", raw)
        clean = re.sub(r"```js\s*", "", clean)
        clean = re.sub(r"```\s*", "", clean)
        return clean.strip()
    except Exception as e:
        logger.warning(f"PoC generation failed: {e}")
        return ""
