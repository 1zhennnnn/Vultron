import { AttackStrategy, Vulnerability } from '../types';

interface AttackTemplate {
  exploitType: string;
  riskLevel: string;
  steps: string[];
}

const templates: Record<string, AttackTemplate> = {
  reentrancy: {
    exploitType: 'Reentrancy Attack',
    riskLevel: 'Critical',
    steps: [
      'Attacker writes a malicious contract with a receive()/fallback() function that calls target.withdraw()',
      'Attacker deploys malicious contract to the network',
      'Attacker calls target.deposit() with a small amount of ETH (e.g. 0.1 ETH) to register a balance',
      'Attacker calls target.withdraw(0.1 ETH) — target passes the require() balance check',
      'Target contract executes msg.sender.call{value: amount}("") — ETH is sent to attacker contract',
      "Attacker's fallback/receive() is triggered automatically upon receiving ETH",
      'Fallback function immediately calls target.withdraw() again — balance has NOT been updated yet',
      'Target passes require() check again since balances[attacker] still shows original amount',
      'This recursive loop repeats until target contract ETH balance hits 0',
      'Attacker contract calls a collect() function to forward all drained ETH to attacker EOA',
    ],
  },
  'tx-origin': {
    exploitType: 'Tx.Origin Phishing Attack',
    riskLevel: 'High',
    steps: [
      'Attacker deploys a phishing contract disguised as a legitimate DeFi protocol or NFT mint',
      'Attacker social-engineers the legitimate contract owner into interacting with the phishing contract',
      'Owner calls a function on the phishing contract (e.g. "Claim Airdrop")',
      'Phishing contract silently calls target.emergencyWithdraw() or owner-restricted functions',
      'Target evaluates: require(tx.origin == owner) — tx.origin is still the owner\'s EOA, so check PASSES',
      'Attacker gains owner-level privileges in the target contract via the phishing proxy',
      'Attacker executes privileged operations: drain funds, change ownership, disable security controls',
      'Attack is complete — owner is unaware until funds are missing',
    ],
  },
  'unprotected-selfdestruct': {
    exploitType: 'Forced Selfdestruct',
    riskLevel: 'Critical',
    steps: [
      'Attacker identifies the selfdestruct() call and which authentication guards it',
      'If guarded by tx.origin: attacker chains a phishing attack to satisfy tx.origin check (see tx.origin attack)',
      'If unguarded: attacker directly calls the function containing selfdestruct()',
      'selfdestruct(payable(attacker)) sends all contract ETH to attacker address',
      'Contract bytecode is deleted from the blockchain — all future calls will silently fail',
      'Users who had funds locked in the contract permanently lose access',
      'Protocol is permanently bricked — no upgrade path exists',
    ],
  },
  'unsafe-delegatecall': {
    exploitType: 'Delegatecall Storage Hijack',
    riskLevel: 'High',
    steps: [
      'Attacker identifies a delegatecall to a potentially controllable target address',
      'Attacker deploys a malicious logic contract that overwrites storage slot 0 (owner variable)',
      'Attacker provides the malicious contract address as the delegatecall target',
      'Target contract executes malicious code in its own storage context via delegatecall',
      'Storage slot 0 (owner) is overwritten with attacker\'s address',
      'Attacker is now the owner of the victim contract',
      'Attacker drains all funds and transfers ownership permanently',
    ],
  },
  'integer-overflow': {
    exploitType: 'Integer Overflow / Underflow',
    riskLevel: 'Medium',
    steps: [
      'Attacker identifies uint arithmetic operations without SafeMath protection',
      'Attacker crafts a transaction with extreme values (e.g. 2^256 - 1)',
      'Balance addition wraps around: 2^256 - 1 + 1 = 0 (overflow)',
      'Attacker can set their balance to 0 while appearing to have deposited maximum uint',
      'Alternatively, subtraction underflow: balances[msg.sender] - amount wraps to 2^256 - 1',
      'Attacker now has practically unlimited withdrawal capability',
      'Attacker withdraws all contract funds in a single transaction',
    ],
  },
  default: {
    exploitType: 'Generic Smart Contract Exploit',
    riskLevel: 'Medium',
    steps: [
      'Attacker performs reconnaissance: reads contract ABI, transaction history, and bytecode',
      'Attacker identifies publicly callable state-changing functions',
      'Attacker analyzes function logic for unchecked inputs or missing access controls',
      'Attacker crafts exploit payload targeting identified weakness',
      'Attacker submits exploit transaction with high gas priority to minimize MEV risk',
      'Vulnerability is triggered — attacker extracts value or disrupts protocol operation',
    ],
  },
};

export function generateAttackStrategy(vulnerabilities: Vulnerability[]): AttackStrategy {
  if (vulnerabilities.length === 0) {
    return {
      exploitType: 'No Exploitable Vulnerabilities',
      riskLevel: 'Safe',
      steps: [
        'No significant vulnerabilities detected by Vultron analysis',
        'Contract follows secure coding patterns',
        'Recommend additional manual audit for business logic flaws',
        'Monitor contract activity post-deployment for anomalies',
      ],
    };
  }

  const priority = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...vulnerabilities].sort(
    (a, b) => priority.indexOf(a.severity) - priority.indexOf(b.severity)
  );

  const primary = sorted[0];
  const template = templates[primary.type] || templates['default'];

  return {
    exploitType: template.exploitType,
    riskLevel: template.riskLevel,
    steps: template.steps,
  };
}
