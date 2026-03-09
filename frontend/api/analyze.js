import { GoogleGenerativeAI } from '@google/generative-ai';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY ?? '');

async function ask(prompt, maxTokens = 800) {
  const model = genAI.getGenerativeModel({
    model: 'gemini-2.0-flash',
    generationConfig: { maxOutputTokens: maxTokens },
  });
  const result = await model.generateContent(prompt);
  return result.response.text();
}

function parseJson(raw, fallback) {
  try {
    const clean = raw.replace(/```(?:json)?\s*/g, '').replace(/```\s*/g, '').trim();
    return JSON.parse(clean);
  } catch {
    return fallback;
  }
}

function extractContractName(code) {
  const match = code.match(/contract\s+(\w+)/);
  return match?.[1] ?? 'UnknownContract';
}

// Simple keyword-based vulnerability detection (no Slither needed)
function detectVulnerabilities(code) {
  const vulns = [];
  const lines = code.split('\n');

  lines.forEach((line, i) => {
    const lineNum = i + 1;
    const trimmed = line.trim();

    if (/\.call\{value:/.test(trimmed) && !/nonReentrant/.test(code)) {
      if (!vulns.find(v => v.type === 'reentrancy')) {
        vulns.push({
          id: 'SWC-107',
          type: 'reentrancy',
          function: extractFunctionName(lines, i),
          severity: 'critical',
          description: 'External call made before state update may allow reentrancy attack.',
          lineNumber: lineNum,
        });
      }
    }

    if (/tx\.origin/.test(trimmed)) {
      vulns.push({
        id: 'SWC-115',
        type: 'tx-origin',
        function: extractFunctionName(lines, i),
        severity: 'high',
        description: 'tx.origin used for authentication is vulnerable to phishing attacks.',
        lineNumber: lineNum,
      });
    }

    if (/selfdestruct|suicide/.test(trimmed)) {
      vulns.push({
        id: 'SWC-106',
        type: 'unprotected-selfdestruct',
        function: extractFunctionName(lines, i),
        severity: 'critical',
        description: 'selfdestruct() can permanently destroy the contract and steal ETH.',
        lineNumber: lineNum,
      });
    }

    if (/delegatecall/.test(trimmed)) {
      vulns.push({
        id: 'SWC-112',
        type: 'delegatecall',
        function: extractFunctionName(lines, i),
        severity: 'high',
        description: 'delegatecall to untrusted contract can lead to storage corruption.',
        lineNumber: lineNum,
      });
    }
  });

  // Check for integer overflow (Solidity < 0.8)
  if (/pragma solidity\s+\^?0\.[0-7]/.test(code)) {
    vulns.push({
      id: 'SWC-101',
      type: 'integer-overflow',
      function: 'multiple',
      severity: 'medium',
      description: 'Solidity < 0.8 has no built-in overflow protection. Use SafeMath or upgrade.',
      lineNumber: 1,
    });
  }

  return vulns;
}

function extractFunctionName(lines, lineIndex) {
  for (let i = lineIndex; i >= 0; i--) {
    const match = lines[i].match(/function\s+(\w+)/);
    if (match) return match[1];
  }
  return 'unknown';
}

function calculateScore(vulns) {
  const penalties = { critical: 40, high: 25, medium: 10, low: 5, info: 0 };
  const total = vulns.reduce((sum, v) => sum + (penalties[v.severity] ?? 0), 0);
  return Math.max(0, 100 - total);
}

function getRiskLevel(score) {
  if (score < 20) return 'Critical Risk';
  if (score < 45) return 'High Risk';
  if (score < 70) return 'Medium Risk';
  if (score < 90) return 'Low Risk';
  return 'Safe';
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { code } = req.body;
  if (!code || typeof code !== 'string' || code.trim().length < 10) {
    return res.status(400).json({ error: 'Invalid contract code.' });
  }

  try {
    const vulnerabilities = detectVulnerabilities(code);
    const securityScore = calculateScore(vulnerabilities);
    const riskLevel = getRiskLevel(securityScore);
    const vulnList = vulnerabilities.map(v =>
      `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}(): ${v.description}`
    ).join('\n') || 'none detected';

    const [summary, attackRaw, defenseRaw, scoreExplanation] = await Promise.all([
      ask(`You are a smart contract security expert. Write a concise 2-3 sentence security summary.
Vulnerabilities: ${vulnList}
Contract: ${code.slice(0, 1500)}`, 300),

      ask(`You are a blockchain security researcher. Generate attack strategy JSON.
Primary vulnerability: ${vulnerabilities[0]?.type ?? 'none'}
Respond ONLY with valid JSON:
{"exploitType":"string","riskLevel":"Critical","steps":["step1","step2","step3","step4","step5"]}`, 400),

      ask(`You are a Solidity security expert. Provide fix recommendations JSON for: ${vulnerabilities.map(v => v.type).join(', ') || 'no issues'}
Respond ONLY with valid JSON array:
[{"issue":"string","strategy":"string","codeExample":"string"}]`, 1000),

      ask(`Explain this smart contract security score in 2-3 sentences.
Score: ${securityScore}/100
Vulnerabilities: ${vulnerabilities.map(v => v.severity + ': ' + v.type).join(', ') || 'none'}`, 250),
    ]);

    const attackStrategy = parseJson(attackRaw, {
      exploitType: vulnerabilities[0]?.type ?? 'No Exploit',
      riskLevel: securityScore < 50 ? 'Critical' : 'Low',
      steps: ['No significant vulnerabilities detected', 'Contract appears secure', 'Recommend manual audit'],
    });

    const defenseRecommendations = parseJson(defenseRaw, vulnerabilities.map(v => ({
      issue: v.type,
      strategy: 'Apply security best practices.',
      codeExample: '// Follow OpenZeppelin patterns',
    })));

    return res.status(200).json({
      contractName: extractContractName(code),
      securityScore,
      riskLevel,
      vulnerabilities,
      summary,
      attackStrategy,
      defenseRecommendations,
      scoreExplanation,
      analyzedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Analyze error:', err);
    return res.status(500).json({ error: 'Analysis failed. Check GEMINI_API_KEY.' });
  }
}
