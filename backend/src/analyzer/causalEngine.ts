import { Vulnerability } from '../types';

interface CausalPath {
  from: string;
  to: string;
  mechanism: string;
}

// Builds a causal chain: how one vulnerability enables another
const CAUSAL_RULES: Array<{
  trigger: string;
  enables: string;
  mechanism: string;
}> = [
  {
    trigger: 'tx-origin',
    enables: 'unprotected-selfdestruct',
    mechanism: 'tx.origin auth bypass allows unauthorized selfdestruct call',
  },
  {
    trigger: 'tx-origin',
    enables: 'arbitrary-send',
    mechanism: 'tx.origin auth bypass grants unauthorized fund transfer access',
  },
  {
    trigger: 'unsafe-delegatecall',
    enables: 'arbitrary-send',
    mechanism: 'delegatecall storage corruption overwrites owner → enables theft',
  },
  {
    trigger: 'reentrancy',
    enables: 'integer-overflow',
    mechanism: 'repeated reentrant calls can amplify overflow conditions',
  },
];

export function buildCausalPaths(vulnerabilities: Vulnerability[]): CausalPath[] {
  const types = new Set(vulnerabilities.map(v => v.type));
  const paths: CausalPath[] = [];

  for (const rule of CAUSAL_RULES) {
    if (types.has(rule.trigger) && types.has(rule.enables)) {
      paths.push({
        from: rule.trigger,
        to: rule.enables,
        mechanism: rule.mechanism,
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

  // Causal chain steps
  for (const path of causalPaths) {
    steps.push(`${path.mechanism}`);
  }

  // Generic exploitation steps based on type
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
  } else {
    steps.push(`Attacker crafts transaction targeting ${primary.function}()`);
    steps.push('Vulnerability exploited to bypass security checks');
    steps.push('Attacker extracts value or corrupts contract state');
    steps.push('Protocol damage complete');
  }

  // Final drain step
  if (!steps.some(s => s.includes('permanently') || s.includes('zero'))) {
    steps.push('Attacker withdraws stolen funds to external wallet');
  }

  return steps;
}
