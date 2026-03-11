import { Vulnerability, AttackStrategy, DefenseRecommendation } from '../types';

export async function askGroq(prompt: string, maxTokens = 800): Promise<string> {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.GROQ_API_KEY ?? ''}`,
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      max_tokens: maxTokens,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Groq API error ${res.status}: ${errText}`);
  }
  const data = await res.json() as any;
  return data.choices[0].message.content as string;
}

function parseJson<T>(raw: string, fallback: T): T {
  try {
    const clean = raw.replace(/```(?:json)?\s*/g, '').replace(/```\s*/g, '').trim();
    return JSON.parse(clean) as T;
  } catch {
    return fallback;
  }
}

export async function generateSecuritySummary(
  code: string,
  vulnerabilities: Vulnerability[]
): Promise<string> {
  if (vulnerabilities.length === 0) {
    return await askGroq(
      `你是一位智能合約資安專家。此 Solidity 合約通過了自動化分析，未偵測到漏洞。請用繁體中文為開發者撰寫簡潔的 2-3 句安全摘要。語氣正面，但提醒自動化工具無法提供完整保證。請完全使用繁體中文回答。

合約內容：
\`\`\`solidity
${code.slice(0, 2000)}
\`\`\``,
      300
    );
  }

  const vulnList = vulnerabilities
    .map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}(): ${v.description.slice(0, 120)}`)
    .join('\n');

  return await askGroq(
    `你是一位智能合約資安專家。請分析以下漏洞，並用繁體中文為開發者撰寫簡潔的 2-3 句安全摘要。聚焦於最嚴重的風險及其實際影響。不要使用條列符號。請完全使用繁體中文回答。

偵測到的漏洞：
${vulnList}

合約內容（前 2000 字元）：
\`\`\`solidity
${code.slice(0, 2000)}
\`\`\``,
    400
  );
}

export async function generateAttackStrategy(
  vulnerabilities: Vulnerability[]
): Promise<AttackStrategy> {
  if (vulnerabilities.length === 0) {
    return {
      exploitType: 'No Exploitable Vulnerabilities',
      riskLevel: 'Safe',
      steps: [
        'No significant vulnerabilities detected by Slither analysis',
        'Contract follows secure coding patterns',
        'Recommend additional manual audit for business logic flaws',
        'Monitor on-chain activity after deployment',
      ],
    };
  }

  const priority = ['critical', 'high', 'medium', 'low', 'info'];
  const primary = [...vulnerabilities].sort(
    (a, b) => priority.indexOf(a.severity) - priority.indexOf(b.severity)
  )[0];

  const raw = await askGroq(
    `你是一位區塊鏈安全研究員。請針對以下漏洞，產生真實的逐步攻擊策略。所有文字欄位必須使用繁體中文。

漏洞類型：${primary.type}
受影響函數：${primary.function}()
描述：${primary.description.slice(0, 300)}

只回傳有效 JSON 物件，不要 markdown，不要說明文字：
{
  "exploitType": "攻擊類型名稱（繁體中文）",
  "riskLevel": "Critical",
  "steps": ["步驟1（繁體中文）", "步驟2", "步驟3", "步驟4", "步驟5", "步驟6"]
}`,
    500
  );

  return parseJson<AttackStrategy>(raw, {
    exploitType: primary.type.replace(/-/g, ' '),
    riskLevel: primary.severity === 'critical' ? 'Critical' : 'High',
    steps: [
      `攻擊者識別 ${primary.function}() 中的 ${primary.type} 漏洞`,
      '攻擊者構造針對漏洞的惡意交易',
      '攻擊者執行漏洞利用，提取資金或破壞合約狀態',
      '攻擊成功，合約遭入侵',
    ],
  });
}

export async function generateDefenseRecommendations(
  vulnerabilities: Vulnerability[]
): Promise<DefenseRecommendation[]> {
  if (vulnerabilities.length === 0) {
    return [{
      issue: 'No critical vulnerabilities detected',
      strategy: 'Continue following secure development practices and conduct regular audits.',
      codeExample: '// Best practices maintained:\n// ✅ Checks-Effects-Interactions\n// ✅ ReentrancyGuard where needed\n// ✅ msg.sender for authentication\n// ✅ Solidity 0.8+ overflow protection',
    }];
  }

  const unique = vulnerabilities
    .filter((v, i, arr) => arr.findIndex(x => x.type === v.type) === i)
    .slice(0, 4);

  const vulnSummary = unique.map(v => `${v.type} in ${v.function}()`).join(', ');

  const raw = await askGroq(
    `你是一位 Solidity 資安專家。請針對以下漏洞提供修復建議：${vulnSummary}

只回傳有效 JSON 陣列，不要 markdown，不要多餘文字。issue 和 strategy 欄位必須使用繁體中文，codeExample 使用 Solidity 程式碼：
[
  {
    "issue": "漏洞類型與函數名稱（繁體中文）",
    "strategy": "一句話描述修復方式（繁體中文）",
    "codeExample": "3-8 行展示安全模式的 Solidity 程式碼"
  }
]`,
    1200
  );

  return parseJson<DefenseRecommendation[]>(raw, unique.map(v => ({
    issue: `${v.type} 位於 ${v.function}()`,
    strategy: '請檢視並套用此漏洞類型的安全最佳實務。',
    codeExample: '// 套用 OpenZeppelin 安全模式',
  })));
}

export async function generateScoreExplanation(
  score: number,
  vulnerabilities: Vulnerability[]
): Promise<string> {
  const breakdown = vulnerabilities.length > 0
    ? vulnerabilities.map(v => `${v.severity}: ${v.type}`).join(', ')
    : 'none';

  return await askGroq(
    `請用繁體中文為開發者解釋此智能合約的安全分數，2-3 句話說明為何是這個分數。請說明具體原因。不要使用條列符號，語氣直接且具可操作性。請完全使用繁體中文回答。

分數：${score}/100
發現的漏洞：${breakdown}`,
    300
  );
}

export async function generateCopilotAnswer(
  question: string,
  vulnerabilities: Vulnerability[],
  score: number
): Promise<string> {
  const context = vulnerabilities.length > 0
    ? vulnerabilities.map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}(): ${v.description.slice(0, 150)}`).join('\n')
    : 'No vulnerabilities detected. Score: ' + score + '/100';

  return await askGroq(
    `你是 Vultron Copilot，一位智能合約資安專家助理。請根據已分析合約的漏洞回答開發者的問題。請完全使用繁體中文回答，無論問題是什麼語言。

資安背景：
${context}
安全分數：${score}/100

開發者問題：「${question}」

請提供具體、有幫助的回答，並引用實際偵測到的漏洞。若問題與資安無關，請引導回資安主題。回答限 3-6 句話，使用純文字，不要 markdown 標題。請完全使用繁體中文回答。`,
    400
  );
}
