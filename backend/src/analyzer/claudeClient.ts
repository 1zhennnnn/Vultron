import { Vulnerability, AttackStrategy, DefenseRecommendation } from '../types';

// Use a smaller, faster model to avoid Rate Limits (llama-3.1-8b-instant is much cheaper in TPD)
const GROQ_MODEL = 'llama-3.1-8b-instant';

async function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function askGroq(prompt: string, maxTokens = 800): Promise<string> {
  const maxRetries = 3;
  let lastError: any;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.GROQ_API_KEY ?? ''}`,
        },
        body: JSON.stringify({
          model: GROQ_MODEL,
          max_tokens: maxTokens,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.2,
        }),
      });

      if (res.status === 429) {
        const wait = Math.pow(2, attempt) * 1000;
        console.warn(`Groq Rate Limit (429). Retrying in ${wait}ms... (Attempt ${attempt + 1}/${maxRetries})`);
        await delay(wait);
        continue;
      }

      if (!res.ok) {
        const errText = await res.text();
        console.warn(`Groq API error ${res.status}: ${errText}. Falling back to mock response.`);
        throw new Error(`API_ERROR_${res.status}`);
      }

      const data = await res.json() as any;
      return data.choices[0].message.content as string;
    } catch (err: any) {
      lastError = err;
      if (err.message?.includes('API_ERROR')) throw err;
      // For network errors, we might want to retry too
      const wait = Math.pow(2, attempt) * 500;
      await delay(wait);
    }
  }

  throw lastError || new Error('Max retries reached for Groq API');
}

function parseJson<T>(raw: string, fallback: T): T {
  try {
    const clean = raw.replace(/```(?:json)?\s*/g, '').replace(/```\s*/g, '').trim();
    return JSON.parse(clean) as T;
  } catch {
    return fallback;
  }
}

export async function analyzeContractWithAI(
  code: string
): Promise<Vulnerability[]> {
  try {
    const raw = await askGroq(
      `你是一位智能合約資安審計專家。請分析以下 Solidity 代碼並找出潛在漏洞（如：Reentrancy, tx.origin, Unprotected Selfdestruct, Access Control, Overflow 等）。
請只回傳 JSON 格式的陣列，不要有任何解釋文字。
格式如下：
[
  {
    "id": "AI-001",
    "type": "vulnerability-type",
    "function": "functionName",
    "severity": "critical|high|medium|low",
    "description": "簡短的繁體中文描述",
    "lineNumber": 10
  }
]

代碼內容：
\`\`\`solidity
${code.slice(0, 3000)}
\`\`\``,
      1000
    );

    return parseJson<Vulnerability[]>(raw, []);
  } catch {
    return [];
  }
}

export async function generateSecuritySummary(
  code: string,
  vulnerabilities: Vulnerability[]
): Promise<string> {
  try {
    if (vulnerabilities.length === 0) {
      return await askGroq(
        `你是一位智能合約資安專家。此 Solidity 合約通過了自動化分析，未偵測到漏洞。請用繁體中文為開發者撰寫簡潔的 2-3 句安全摘要。語氣正面，但提醒自動化工具無法提供完整保證。

合約內容：
\`\`\`solidity
${code.slice(0, 1000)}
\`\`\``,
        300
      );
    }

    const vulnList = vulnerabilities
      .map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}(): ${v.description.slice(0, 100)}`)
      .join('\n');

    return await askGroq(
      `你是一位智能合約資安專家。分析以下漏洞並撰寫 2-3 句繁體中文摘要。聚焦最嚴重風險。
  ${vulnList}`,
      300
    );
  } catch {
    return "Vultron 已完成分析。合約中偵測到多個潛在風險，請檢閱下方的詳細清單與攻擊路徑。建議優先修復 Critical 與 High 級別的漏洞以確保資金安全。";
  }
}

export async function generateAttackStrategy(
  vulnerabilities: Vulnerability[]
): Promise<AttackStrategy> {
  const fallback: AttackStrategy = {
    exploitType: 'Automated Security Risk',
    riskLevel: 'High',
    steps: [
      '攻擊者識別合約中的邏輯缺陷',
      '攻擊者構造惡意交易數據',
      '透過外部調用或權限繞過執行攻擊',
      '合約資金被提取或狀態遭破壞'
    ],
  };

  if (vulnerabilities.length === 0) {
    return {
      exploitType: 'Secure',
      riskLevel: 'Safe',
      steps: ['No vulnerabilities detected.'],
    };
  }

  try {
    const priority = ['critical', 'high', 'medium', 'low', 'info'];
    const primary = [...vulnerabilities].sort(
      (a, b) => priority.indexOf(a.severity) - priority.indexOf(b.severity)
    )[0];

    const raw = await askGroq(
      `針對以下漏洞產生 JSON 攻擊步驟 (繁體中文)：
  類型：${primary.type}
  函數：${primary.function}()
  
  {"exploitType": "...", "riskLevel": "Critical", "steps": ["步驟1", "步驟2", "步驟3"]}`,
      400
    );
    return parseJson<AttackStrategy>(raw, fallback);
  } catch {
    return fallback;
  }
}

export async function generateDefenseRecommendations(
  vulnerabilities: Vulnerability[]
): Promise<DefenseRecommendation[]> {
  const fallback = vulnerabilities.slice(0, 3).map(v => ({
    issue: `${v.type} (${v.function})`,
    strategy: '套用 Checks-Effects-Interactions 模式並使用 ReentrancyGuard。',
    codeExample: '// 建議使用 OpenZeppelin 的標準庫',
  }));

  if (vulnerabilities.length === 0) {
    return [{
      issue: 'None',
      strategy: 'Continue following best practices.',
      codeExample: '// Safe',
    }];
  }

  try {
    const unique = vulnerabilities
      .filter((v, i, arr) => arr.findIndex(x => x.type === v.type) === i)
      .slice(0, 3);

    const raw = await askGroq(
      `針對以下漏洞提供繁體中文修復建議：${unique.map(v => v.type).join(', ')}
  回傳 JSON 陣列 [{"issue": "...", "strategy": "...", "codeExample": "..."}]`,
      800
    );
    return parseJson<DefenseRecommendation[]>(raw, fallback);
  } catch {
    return fallback;
  }
}

export async function generateScoreExplanation(
  score: number,
  vulnerabilities: Vulnerability[]
): Promise<string> {
  try {
    const breakdown = vulnerabilities.map(v => `${v.severity}: ${v.type}`).join(', ');
    return await askGroq(
      `解釋分數 ${score}/100。漏洞：${breakdown} (繁體中文, 2句)`,
      200
    );
  } catch {
    return `基於偵測到的 ${vulnerabilities.length} 個漏洞，該合約的安全評分為 ${score}。分數主要受到 Critical 與 High 級別風險的影響。`;
  }
}

export async function generateCopilotAnswer(
  question: string,
  vulnerabilities: Vulnerability[],
  score: number
): Promise<string> {
  try {
    return await askGroq(
      `回答安全問題：「${question}」。分數：${score}。漏洞數：${vulnerabilities.length}。 (繁體中文, 簡短)`,
      400
    );
  } catch {
    return "抱歉，目前 AI 助手服務負載過高。根據目前的靜態分析結果，建議您優先查看漏洞列表中的 Critical 項目，並根據修復建議進行調整。";
  }
}
