import { GoogleGenerativeAI } from '@google/generative-ai';
import { Vulnerability, AttackStrategy, DefenseRecommendation } from '../types';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY ?? '');

async function askGemini(prompt: string, maxTokens = 800): Promise<string> {
  const model = genAI.getGenerativeModel({
    model: 'gemini-1.5-flash',
    generationConfig: { maxOutputTokens: maxTokens },
  });
  const result = await model.generateContent(prompt);
  return result.response.text();
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
    return await askGemini(
      `You are a smart contract security expert. This Solidity contract passed automated analysis with no vulnerabilities detected. Write a concise 2-3 sentence security summary for the developer. Be encouraging but remind them that automated tools are not a complete guarantee.

Contract:
\`\`\`solidity
${code.slice(0, 2000)}
\`\`\``,
      300
    );
  }

  const vulnList = vulnerabilities
    .map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}(): ${v.description.slice(0, 120)}`)
    .join('\n');

  return await askGemini(
    `You are a smart contract security expert. Analyze these vulnerabilities and write a concise 2-3 sentence security summary for the developer. Focus on the most critical risk and its real-world impact. Do not use bullet points.

Detected vulnerabilities:
${vulnList}

Contract (first 2000 chars):
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

  const raw = await askGemini(
    `You are a blockchain security researcher. Generate a realistic step-by-step attack strategy for this vulnerability.

Vulnerability type: ${primary.type}
Affected function: ${primary.function}()
Description: ${primary.description.slice(0, 300)}

Respond ONLY with a valid JSON object, no markdown, no explanation:
{
  "exploitType": "string — name of the attack type",
  "riskLevel": "Critical",
  "steps": ["step 1", "step 2", "step 3", "step 4", "step 5", "step 6"]
}`,
    500
  );

  return parseJson<AttackStrategy>(raw, {
    exploitType: primary.type.replace(/-/g, ' '),
    riskLevel: primary.severity === 'critical' ? 'Critical' : 'High',
    steps: [
      `Attacker identifies ${primary.type} in ${primary.function}()`,
      'Attacker crafts exploit transaction targeting the vulnerability',
      'Attacker executes exploit to drain funds or corrupt state',
      'Attack succeeds — contract compromised',
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

  const raw = await askGemini(
    `You are a Solidity security expert. Provide fix recommendations for these vulnerabilities: ${vulnSummary}

Respond ONLY with a valid JSON array, no markdown, no extra text:
[
  {
    "issue": "vulnerability type and function name",
    "strategy": "one clear sentence describing the fix approach",
    "codeExample": "3-8 lines of corrected Solidity code showing the secure pattern"
  }
]`,
    1200
  );

  return parseJson<DefenseRecommendation[]>(raw, unique.map(v => ({
    issue: `${v.type} in ${v.function}()`,
    strategy: 'Review and apply security best practices for this vulnerability type.',
    codeExample: '// Apply OpenZeppelin security patterns',
  })));
}

export async function generateScoreExplanation(
  score: number,
  vulnerabilities: Vulnerability[]
): Promise<string> {
  const breakdown = vulnerabilities.length > 0
    ? vulnerabilities.map(v => `${v.severity}: ${v.type}`).join(', ')
    : 'none';

  return await askGemini(
    `Explain this smart contract security score in 2-3 sentences for a developer. Be specific about why the score is this value.

Score: ${score}/100
Vulnerabilities found: ${breakdown}

Do not use bullet points. Be direct and actionable.`,
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

  return await askGemini(
    `You are Vultron Copilot, an expert smart contract security assistant. Answer the developer's question based on the analyzed contract's vulnerabilities.

Security context:
${context}
Security score: ${score}/100

Developer question: "${question}"

Provide a helpful, specific answer referencing the actual vulnerabilities found. If the question is not security-related, redirect to security topics. Keep the answer concise (3-6 sentences max). Use plain text, no markdown headers.`,
    400
  );
}
