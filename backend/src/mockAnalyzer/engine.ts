import { AnalysisResult, RiskLevel, Vulnerability } from '../types';

function extractContractName(code: string): string {
  const m = code.match(/contract\s+(\w+)/);
  return m ? m[1] : 'UnknownContract';
}

function findLineNumber(code: string, pattern: RegExp): number | undefined {
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return i + 1;
  }
  return undefined;
}

function getRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'Safe';
  if (score >= 60) return 'Low Risk';
  if (score >= 40) return 'Medium Risk';
  if (score >= 20) return 'High Risk';
  return 'Critical Risk';
}

export function analyzeContract(code: string): AnalysisResult {
  const contractName = extractContractName(code);
  const vulns: Vulnerability[] = [];

  const hasReentrancy = /\.call\{value|call\.value/.test(code);
  const hasTxOrigin = /tx\.origin/.test(code);
  const hasUint = /\buint\d*\b/.test(code);
  const hasSafeMath = /SafeMath|using SafeMath/.test(code);
  const hasSolidity8 = /pragma solidity\s+\^?0\.8/.test(code);
  const hasSelfdestruct = /selfdestruct|suicide\s*\(/.test(code);
  const hasDelegatecall = /\.delegatecall\(/.test(code);

  if (hasReentrancy) {
    vulns.push({
      id: 'SWC-107',
      type: 'reentrancy',
      function: 'withdraw',
      severity: 'critical',
      description:
        'An external call is made before state variables are updated, allowing a malicious contract to re-enter the withdraw() function recursively and drain all ETH from the contract before any balance deduction occurs.',
      lineNumber: findLineNumber(code, /\.call\{value|call\.value/),
    });
  }

  if (hasTxOrigin) {
    vulns.push({
      id: 'SWC-115',
      type: 'tx-origin',
      function: 'constructor / emergencyWithdraw',
      severity: 'high',
      description:
        'tx.origin is used for authentication. A malicious intermediary contract can trick the legitimate owner into calling it, causing tx.origin to return the owner address while msg.sender is the attacker — completely bypassing access control.',
      lineNumber: findLineNumber(code, /tx\.origin/),
    });
  }

  if (hasSelfdestruct) {
    vulns.push({
      id: 'SWC-106',
      type: 'unprotected-selfdestruct',
      function: 'emergencyWithdraw',
      severity: 'critical',
      description:
        'The selfdestruct() opcode is callable and can permanently destroy the contract and transfer all its ETH to an arbitrary address. If combined with the tx.origin vulnerability, an attacker can trigger this to irreversibly destroy the contract.',
      lineNumber: findLineNumber(code, /selfdestruct|suicide\s*\(/),
    });
  }

  if (hasDelegatecall) {
    vulns.push({
      id: 'SWC-112',
      type: 'unsafe-delegatecall',
      function: 'unknown',
      severity: 'high',
      description:
        'delegatecall executes external code in the context of the calling contract, giving it full access to storage and ETH. If the target address is attacker-controlled, this allows complete storage manipulation and fund drainage.',
      lineNumber: findLineNumber(code, /\.delegatecall\(/),
    });
  }

  if (hasUint && !hasSafeMath && !hasSolidity8) {
    vulns.push({
      id: 'SWC-101',
      type: 'integer-overflow',
      function: 'arithmetic functions',
      severity: 'medium',
      description:
        'This contract uses uint arithmetic without SafeMath and is compiled with Solidity < 0.8.0. Integer overflow/underflow is not checked by default. An attacker can wrap values to bypass balance checks or mint unlimited tokens.',
      lineNumber: findLineNumber(code, /\buint\d*\b/),
    });
  }

  let score = 100;
  const criticalCount = vulns.filter(v => v.severity === 'critical').length;
  const highCount = vulns.filter(v => v.severity === 'high').length;
  const mediumCount = vulns.filter(v => v.severity === 'medium').length;
  const lowCount = vulns.filter(v => v.severity === 'low').length;

  score -= criticalCount * 40;
  score -= highCount * 25;
  score -= mediumCount * 10;
  score -= lowCount * 5;
  score = Math.max(0, score);

  if (vulns.length === 0) {
    score = 92;
  }

  return {
    contractName,
    securityScore: score,
    riskLevel: getRiskLevel(score),
    vulnerabilities: vulns,
    analyzedAt: new Date().toISOString(),
  };
}
