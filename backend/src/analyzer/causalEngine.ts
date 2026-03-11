import { Vulnerability } from '../types';

interface CausalNode {
  id: string;
  type: 'root-cause' | 'trigger' | 'exploit-action' | 'cascade-effect' | 'final-impact';
  label: string;
  description: string;
}

interface CausalEdge {
  from: string;
  to: string;
  relation: string;
}

interface CausalPath {
  id: string;
  from: string;
  to: string;
  mechanism: string;
  edge?: string;
  compound?: boolean;
  title?: string;
  severity?: string;
  // AI-enriched fields (present when generateAICausalPaths succeeds)
  summary?: string;
  nodes?: CausalNode[];
  edges?: CausalEdge[];
}

interface CausalPathResult {
  paths: CausalPath[];
  criticalPathId: string | null;
}

// Severity ordering for criticalPathId selection
const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// ── Single-vulnerability causal rules ──────────────────────────────────────
const CAUSAL_RULES: Array<{
  trigger: string;
  enables: string;
  mechanism: string;
  edge: string;
}> = [
  {
    trigger: 'tx-origin',
    enables: 'unprotected-selfdestruct',
    mechanism: 'tx.origin auth bypass allows unauthorized selfdestruct call',
    edge: 'enables',
  },
  {
    trigger: 'tx-origin',
    enables: 'arbitrary-send',
    mechanism: 'tx.origin auth bypass grants unauthorized fund transfer access',
    edge: 'enables',
  },
  {
    trigger: 'unsafe-delegatecall',
    enables: 'arbitrary-send',
    mechanism: 'delegatecall storage corruption overwrites owner → enables theft',
    edge: 'enables',
  },
  {
    trigger: 'reentrancy',
    enables: 'integer-overflow',
    mechanism: 'repeated reentrant calls can amplify overflow conditions',
    edge: 'amplifies',
  },
];

// ── Compound path rules (two vulnerabilities merge into one chain) ─────────
const COMPOUND_RULES: Array<{
  typeA: string;
  typeB: string;
  title: string;
  mechanism: string;
  edge: string;
}> = [
  {
    typeA: 'integer-overflow',
    typeB: 'unchecked-call',
    title: 'Silent Overflow + Transfer Chain',
    mechanism: 'integer-overflow corrupts balance value, unchecked-call silently transfers inflated amount without revert',
    edge: 'amplifies',
  },
  {
    typeA: 'access-control',
    typeB: 'unprotected-selfdestruct',
    title: 'Privilege Escalation → Contract Destruction',
    mechanism: 'missing access control lets attacker claim ownership, enabling immediate selfdestruct and fund theft',
    edge: 'enables',
  },
  {
    typeA: 'flash-loan-attack',
    typeB: 'reentrancy',
    title: 'Flash Loan Reentrancy Combo',
    mechanism: 'flash loan provides capital to trigger reentrancy, amplifying drain amount within a single atomic transaction',
    edge: 'amplifies',
  },
];

// ── Narrative templates — one entry per vulnerability type ─────────────────
// Each template.steps() receives the matched Vulnerability for function-name interpolation.
const NARRATIVE_TEMPLATES: Array<{
  type: string;
  title: string;
  steps: (v: Vulnerability) => string[];
}> = [
  {
    type: 'reentrancy',
    title: 'Reentrancy → Drain ETH Balance',
    steps: (v) => [
      'Attacker deploys malicious contract with reentrant fallback/receive function',
      'Attacker calls deposit() to establish valid balance',
      `Attacker calls ${v.function}() — ETH sent before state update`,
      'Malicious fallback re-enters before balance is decremented',
      'Loop repeats until contract ETH balance is zero',
    ],
  },
  {
    type: 'tx-origin',
    title: 'tx.origin Auth Bypass → Phishing Takeover',
    steps: () => [
      'Attacker deploys phishing contract disguised as legitimate service',
      'Victim (owner) interacts with phishing contract',
      'Phishing contract calls privileged target function — tx.origin == owner passes',
      'Attacker gains owner-level access and executes malicious action',
    ],
  },
  {
    type: 'unprotected-selfdestruct',
    title: 'Unprotected Selfdestruct → Permanent Fund Loss',
    steps: (v) => [
      `Attacker calls ${v.function}() containing selfdestruct`,
      'selfdestruct transfers all ETH to attacker address',
      'Contract bytecode permanently deleted from blockchain',
      'All user funds permanently lost — no recovery possible',
    ],
  },
  {
    type: 'unsafe-delegatecall',
    title: 'Unsafe Delegatecall → Storage Hijack',
    steps: () => [
      'Attacker provides malicious implementation contract address',
      'delegatecall executes attacker code in victim contract storage context',
      'Attacker overwrites storage slot 0 (owner variable) with their address',
      'Attacker is now owner — drains all funds via privileged functions',
    ],
  },
  {
    type: 'integer-overflow',
    title: 'Integer Overflow → Inflated Balance Withdrawal',
    steps: (v) => [
      'Attacker crafts input value near uint256 maximum boundary',
      `Arithmetic in ${v.function}() wraps from MAX back to 0 or attacker-controlled value`,
      'Balance or counter holds incorrect inflated value due to overflow',
      'Attacker withdraws far more than originally deposited',
    ],
  },
  {
    type: 'access-control',
    title: 'Access Control → Contract Takeover',
    steps: (v) => [
      `Privileged function ${v.function}() lacks onlyOwner or role check`,
      'Any external address calls the unprotected admin function directly',
      'Attacker reassigns ownership or modifies critical contract parameters',
      'Contract now fully controlled by attacker — funds drained or contract destroyed',
    ],
  },
  {
    type: 'flash-loan-attack',
    title: 'Flash Loan → Oracle Manipulation → Reserve Drain',
    steps: () => [
      'Attacker identifies protocol reads price from manipulable on-chain AMM spot',
      'Attacker borrows large capital amount via flash loan in single transaction',
      'Attacker executes large swap to artificially move oracle price',
      'Protocol calculates collateral or exchange rate using manipulated price',
      'Attacker extracts protocol reserves then repays flash loan atomically',
    ],
  },
  {
    type: 'front-running',
    title: 'Front-Running → MEV Profit Extraction',
    steps: (v) => [
      'Attacker monitors mempool for high-value pending transactions',
      `Attacker detects profitable pending call to ${v.function}()`,
      'Attacker submits identical or interfering transaction with higher gas price',
      'Miner prioritizes attacker transaction — it executes first',
      'Victim receives worse price, loses opportunity, or transaction fails',
    ],
  },
  {
    type: 'timestamp-dependence',
    title: 'Timestamp Manipulation → Miner-Controlled Outcome',
    steps: (v) => [
      `${v.function}() uses block.timestamp for time-sensitive or randomness logic`,
      'Miner identifies 15-second timestamp manipulation window',
      'Miner adjusts block timestamp to trigger the desired contract condition',
      'Time-locked or randomness-dependent function executes ahead of schedule',
      'Attacker wins lottery, auction, or time-gated reward unfairly',
    ],
  },
  {
    type: 'denial-of-service',
    title: 'Denial of Service → Function Permanently Bricked',
    steps: (v) => [
      `${v.function}() iterates over user-controlled or unbounded array`,
      'Attacker repeatedly adds entries to inflate array size and gas cost',
      'Array grows until single iteration exceeds block gas limit',
      'Every subsequent call to the function reverts due to out-of-gas',
      'Critical function permanently uncallable — contract funds locked forever',
    ],
  },
];

function buildPathFromTemplate(
  template: typeof NARRATIVE_TEMPLATES[number],
  match: Vulnerability,
): CausalPath {
  const path: CausalPath = {
    id: `path_${template.type}`,
    from: 'attacker',
    to: match.type,
    mechanism: template.steps(match)[0],
    edge: 'exploits',
    title: template.title,
    severity: match.severity,
  };
  console.log('path object title:', path.title);
  return path;
}

export function buildCausalPaths(vulnerabilities: Vulnerability[]): CausalPathResult {
  console.log('causalEngine input:', vulnerabilities.map(v => v.type));

  const types = new Set(vulnerabilities.map(v => v.type));
  const paths: CausalPath[] = [];

  // Per-vulnerability template paths (one entry node per detected vuln type)
  for (const template of NARRATIVE_TEMPLATES) {
    const match = vulnerabilities.find(v => v.type === template.type);
    console.log('checking template:', template.type, '→ match:', !!match);
    if (match) {
      const path = buildPathFromTemplate(template, match);
      paths.push(path);
      console.log('pushed path:', path.title, '| total paths:', paths.length);
    }
  }

  // Single-vuln causal rules (trigger → enables edges)
  for (const rule of CAUSAL_RULES) {
    const triggerFound = types.has(rule.trigger);
    const enablesFound = types.has(rule.enables);
    console.log(`checking rule: ${rule.trigger} → ${rule.enables} | trigger: ${triggerFound}, enables: ${enablesFound}`);
    if (triggerFound && enablesFound) {
      paths.push({
        id: `rule_${rule.trigger}_to_${rule.enables}`,
        from: rule.trigger,
        to: rule.enables,
        mechanism: rule.mechanism,
        edge: rule.edge,
      });
    }
  }

  // Compound rules (typeA + typeB → combined chain)
  for (const rule of COMPOUND_RULES) {
    const aFound = types.has(rule.typeA);
    const bFound = types.has(rule.typeB);
    console.log(`checking compound: ${rule.typeA} + ${rule.typeB} | A: ${aFound}, B: ${bFound}`);
    if (aFound && bFound) {
      paths.push({
        id: `compound_${rule.typeA}_${rule.typeB}`,
        from: rule.typeA,
        to: rule.typeB,
        mechanism: rule.mechanism,
        edge: rule.edge,
        compound: true,
        title: rule.title,
      });
    }
  }

  const criticalPath = paths.reduce((best, p) => {
    return (SEVERITY_RANK[p.severity ?? ''] ?? 0) > (SEVERITY_RANK[best?.severity ?? ''] ?? -1) ? p : best;
  }, null as CausalPath | null);

  console.log('causalEngine RETURNING paths count:', paths.length);
  return {
    paths,
    criticalPathId: criticalPath?.id ?? null,
  };
}

export function buildAttackNarrative(vulnerabilities: Vulnerability[], prebuiltPaths?: CausalPath[] | CausalPathResult): string[] {
  const priority = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...vulnerabilities].sort(
    (a, b) => priority.indexOf(a.severity) - priority.indexOf(b.severity)
  );

  if (sorted.length === 0) {
    return [
      'No exploitable vulnerabilities detected',
      'Contract follows secure coding patterns',
      'Recommend formal audit for business logic edge cases',
    ];
  }

  // Reuse pre-built paths from the controller to avoid a second buildCausalPaths call
  const rawPaths = prebuiltPaths ?? buildCausalPaths(vulnerabilities);
  const causalPaths: CausalPath[] = Array.isArray(rawPaths) ? rawPaths : rawPaths.paths;
  const steps: string[] = [];
  const primary = sorted[0];

  // Entry point
  steps.push(`Attacker identifies ${primary.type.replace(/-/g, ' ')} in ${primary.function}() via on-chain analysis`);

  // Compound path steps
  for (const path of causalPaths.filter(p => p.compound)) {
    steps.push(`Compound attack chain detected: ${path.title}`);
    steps.push(path.mechanism);
  }

  // Single-vuln causal chain steps
  for (const path of causalPaths.filter(p => !p.compound)) {
    steps.push(path.mechanism);
  }

  // Type-specific exploitation steps via NARRATIVE_TEMPLATES
  const template = NARRATIVE_TEMPLATES.find(t => t.type === primary.type);
  console.log('checking template:', primary.type, '→ match:', !!template);
  if (template) {
    steps.push(...template.steps(primary));
  } else {
    steps.push(`Attacker crafts transaction targeting ${primary.function}()`);
    steps.push('Vulnerability exploited to bypass security checks');
    steps.push('Attacker extracts value or corrupts contract state');
    steps.push('Protocol damage complete');
  }

  // Final drain step (skip if already described as terminal)
  if (!steps.some(s => s.includes('permanently') || s.includes('zero') || s.includes('atomically') || s.includes('forever'))) {
    steps.push('Attacker withdraws stolen funds to external wallet');
  }

  return steps;
}

// ── AI-powered causal path generation (with static fallback) ───────────────
export async function generateAICausalPaths(
  vulnerabilities: Vulnerability[],
  callGroq: (prompt: string) => Promise<string>,
): Promise<CausalPathResult> {
  console.log('non-info vulns:', vulnerabilities.filter(v => v.severity !== 'info').map(v => ({ type: v.type, severity: v.severity })));

  const actionable = vulnerabilities.filter(v => v.severity !== 'info');

  if (actionable.length === 0) {
    console.log('generateAICausalPaths: no actionable vulns — total input length:', vulnerabilities.length);
    return { paths: [], criticalPathId: null };
  }

  const vulnSummary = actionable
    .map(v => `- ${v.type} (${v.severity}) in ${v.function}() at line ${v.lineNumber ?? '?'}`)
    .join('\n');

  const prompt = `You are a smart contract security expert.
Given these vulnerabilities detected by Slither static analysis:
${vulnSummary}

Generate a JSON causal attack path analysis. Return ONLY valid JSON, no markdown.

{
  "paths": [
    {
      "id": "path_0",
      "title": "Short attack title",
      "severity": "critical|high|medium|low",
      "summary": "2-3 sentence explanation of how attacker exploits this",
      "from": "attacker",
      "to": "vulnerability-type",
      "mechanism": "one sentence causal link",
      "nodes": [
        { "id": "n0", "type": "root-cause", "label": "short label", "description": "detail under 20 words" },
        { "id": "n1", "type": "trigger", "label": "short label", "description": "detail under 20 words" },
        { "id": "n2", "type": "exploit-action", "label": "short label", "description": "detail under 20 words" },
        { "id": "n3", "type": "cascade-effect", "label": "short label", "description": "detail under 20 words" },
        { "id": "n4", "type": "final-impact", "label": "short label", "description": "detail under 20 words" }
      ],
      "edges": [
        { "from": "n0", "to": "n1", "relation": "enables" },
        { "from": "n1", "to": "n2", "relation": "triggers" },
        { "from": "n2", "to": "n3", "relation": "causes" },
        { "from": "n3", "to": "n4", "relation": "results in" }
      ]
    }
  ],
  "criticalPathId": "path_0"
}

Rules:
- Generate 1 path per unique high/critical vulnerability
- If multiple vulnerabilities chain together, add 1 compound path
- Maximum 4 paths total
- Node types must be: root-cause, trigger, exploit-action, cascade-effect, final-impact
- severity must match the vulnerability severity
- Keep labels under 6 words, descriptions under 20 words`;

  try {
    const raw = await callGroq(prompt);

    // Step 1: Extract the outermost JSON object
    let clean = raw;
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (jsonMatch) clean = jsonMatch[0];

    // Step 2: Remove markdown fences
    clean = clean.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();

    // Step 3: Remove JavaScript-style comments
    clean = clean.replace(/\/\/[^\n]*/g, '');
    clean = clean.replace(/\/\*[\s\S]*?\*\//g, '');

    // Step 4: Normalize unquoted or single-quoted property names to double-quoted
    clean = clean.replace(/(['"])?([a-zA-Z0-9_\-]+)(['"])?\s*:/g, '"$2":');

    // Step 5: Remove trailing commas before } or ]
    clean = clean.replace(/,\s*([}\]])/g, '$1');

    // Step 6: Parse with error context on failure
    let parsed: { paths: CausalPath[]; criticalPathId: string | null };
    try {
      parsed = JSON.parse(clean);
    } catch (e) {
      console.error('JSON parse failed. First 500 chars of cleaned response:', clean.substring(0, 500));
      throw e;
    }

    if (!Array.isArray(parsed.paths) || parsed.paths.length === 0) {
      throw new Error('AI returned empty paths array');
    }

    console.log('AI causal paths generated:', parsed.paths.length);
    return {
      paths: parsed.paths,
      criticalPathId: parsed.criticalPathId ?? null,
    };
  } catch (err) {
    console.warn('AI causal path generation failed, falling back to static:', err);
    return buildCausalPaths(vulnerabilities);
  }
}
