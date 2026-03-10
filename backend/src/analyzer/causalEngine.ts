import { Vulnerability } from '../types';

interface CausalPath {
  from: string;
  to: string;
  mechanism: string;
  edge?: string;
  compound?: boolean;
  title?: string;
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
// Original 4 rules (unchanged)
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

export function buildCausalPaths(vulnerabilities: Vulnerability[]): CausalPath[] {
  const types = new Set(vulnerabilities.map(v => v.type));
  const paths: CausalPath[] = [];

  // Single-vuln rules
  for (const rule of CAUSAL_RULES) {
    if (types.has(rule.trigger) && types.has(rule.enables)) {
      paths.push({
        from: rule.trigger,
        to: rule.enables,
        mechanism: rule.mechanism,
        edge: rule.edge,
      });
    }
  }

  // Compound rules
  for (const rule of COMPOUND_RULES) {
    if (types.has(rule.typeA) && types.has(rule.typeB)) {
      paths.push({
        from: rule.typeA,
        to: rule.typeB,
        mechanism: rule.mechanism,
        edge: rule.edge,
        compound: true,
        title: rule.title,
      });
    }
  }

  return paths;
}

export function buildAttackNarrative(vulnerabilities: Vulnerability[]): string[] {
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

  const causalPaths = buildCausalPaths(vulnerabilities);
  const steps: string[] = [];
  const primary = sorted[0];

  // Entry point
  steps.push(`Attacker identifies ${primary.type.replace(/-/g, ' ')} in ${primary.function}() via on-chain analysis`);

  // Compound path steps (show title if present)
  for (const path of causalPaths.filter(p => p.compound)) {
    steps.push(`Compound attack chain detected: ${path.title}`);
    steps.push(`${path.mechanism}`);
  }

  // Single-vuln causal chain steps
  for (const path of causalPaths.filter(p => !p.compound)) {
    steps.push(path.mechanism);
  }

  // Type-specific exploitation steps
  if (primary.type === 'reentrancy') {
    steps.push('Attacker deploys malicious contract with reentrant fallback/receive function');
    steps.push('Attacker calls deposit() to establish valid balance');
    steps.push(`Attacker calls ${primary.function}() — ETH sent before state update`);
    steps.push('Malicious fallback re-enters before balance is decremented');
    steps.push('Loop repeats until contract ETH balance is zero');
  } else if (primary.type === 'tx-origin') {
    steps.push('Attacker deploys phishing contract disguised as legitimate service');
    steps.push('Victim (owner) interacts with phishing contract');
    steps.push('Phishing contract calls privileged target function — tx.origin == owner passes');
    steps.push('Attacker gains owner-level access and executes malicious action');
  } else if (primary.type === 'unprotected-selfdestruct') {
    steps.push(`Attacker calls ${primary.function}() containing selfdestruct`);
    steps.push('selfdestruct transfers all ETH to attacker address');
    steps.push('Contract bytecode permanently deleted from blockchain');
    steps.push('All user funds permanently lost — no recovery possible');
  } else if (primary.type === 'unsafe-delegatecall') {
    steps.push('Attacker provides malicious implementation contract address');
    steps.push('delegatecall executes attacker code in victim contract storage context');
    steps.push('Attacker overwrites storage slot 0 (owner variable) with their address');
    steps.push('Attacker is now owner — drains all funds via privileged functions');
  } else if (primary.type === 'integer-overflow') {
    steps.push('Attacker crafts input value near uint256 maximum boundary');
    steps.push(`Arithmetic in ${primary.function}() wraps from MAX back to 0 or attacker-controlled value`);
    steps.push('Balance or counter holds incorrect inflated value due to overflow');
    steps.push('Attacker withdraws far more than originally deposited');
  } else if (primary.type === 'access-control') {
    steps.push(`Privileged function ${primary.function}() lacks onlyOwner or role check`);
    steps.push('Any external address calls the unprotected admin function directly');
    steps.push('Attacker reassigns ownership or modifies critical contract parameters');
    steps.push('Contract now fully controlled by attacker — funds drained or contract destroyed');
  } else if (primary.type === 'flash-loan-attack') {
    steps.push('Attacker identifies protocol reads price from manipulable on-chain AMM spot');
    steps.push('Attacker borrows large capital amount via flash loan in single transaction');
    steps.push('Attacker executes large swap to artificially move oracle price');
    steps.push('Protocol calculates collateral or exchange rate using manipulated price');
    steps.push('Attacker extracts protocol reserves then repays flash loan atomically');
  } else if (primary.type === 'front-running') {
    steps.push('Attacker monitors mempool for high-value pending transactions');
    steps.push(`Attacker detects profitable pending call to ${primary.function}()`);
    steps.push('Attacker submits identical or interfering transaction with higher gas price');
    steps.push('Miner prioritizes attacker transaction — it executes first');
    steps.push('Victim receives worse price, loses opportunity, or transaction fails');
  } else if (primary.type === 'timestamp-dependence') {
    steps.push(`${primary.function}() uses block.timestamp for time-sensitive or randomness logic`);
    steps.push('Miner identifies 15-second timestamp manipulation window');
    steps.push('Miner adjusts block timestamp to trigger the desired contract condition');
    steps.push('Time-locked or randomness-dependent function executes ahead of schedule');
    steps.push('Attacker wins lottery, auction, or time-gated reward unfairly');
  } else if (primary.type === 'denial-of-service') {
    steps.push(`${primary.function}() iterates over user-controlled or unbounded array`);
    steps.push('Attacker repeatedly adds entries to inflate array size and gas cost');
    steps.push('Array grows until single iteration exceeds block gas limit');
    steps.push('Every subsequent call to the function reverts due to out-of-gas');
    steps.push('Critical function permanently uncallable — contract funds locked forever');
  } else {
    steps.push(`Attacker crafts transaction targeting ${primary.function}()`);
    steps.push('Vulnerability exploited to bypass security checks');
    steps.push('Attacker extracts value or corrupts contract state');
    steps.push('Protocol damage complete');
  }

  // Final drain step (skip if already described as permanent)
  if (!steps.some(s => s.includes('permanently') || s.includes('zero') || s.includes('atomically') || s.includes('forever'))) {
    steps.push('Attacker withdraws stolen funds to external wallet');
  }

  return steps;
}
