import { Vulnerability } from '../types';

interface ChatInput {
  question: string;
  vulnerabilities: Vulnerability[];
  score: number;
}

function normalize(q: string): string {
  return q.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
}

function findVuln(type: string, vulns: Vulnerability[]): Vulnerability | undefined {
  return vulns.find(v => v.type === type);
}

export function generateCopilotAnswer(input: ChatInput): string {
  const { question, vulnerabilities, score } = input;
  const q = normalize(question);
  const hasCritical = vulnerabilities.some(v => v.severity === 'critical');
  const hasReentrancy = vulnerabilities.some(v => v.type === 'reentrancy');
  const hasTxOrigin = vulnerabilities.some(v => v.type === 'tx-origin');
  const hasSelfdestruct = vulnerabilities.some(v => v.type === 'unprotected-selfdestruct');
  const hasDelegatecall = vulnerabilities.some(v => v.type === 'unsafe-delegatecall');
  const primaryVuln = vulnerabilities.find(v => v.severity === 'critical') || vulnerabilities[0];

  const greetings = ['hello', 'hi', 'hey', 'greetings', 'what can you do', 'help'];
  if (greetings.some(g => q.includes(g))) {
    return `I'm Vultron Copilot, your AI smart contract security assistant. I've analyzed your contract and found ${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'} with a security score of ${score}/100. Ask me anything — "Why is this dangerous?", "How would a hacker exploit this?", or "How can I fix it?"`;
  }

  if (q.includes('score') || q.includes('increase') || q.includes('improve') || q.includes('better') || q.includes('提升') || q.includes('分數')) {
    if (score === 100) {
      return `Your contract has a perfect score of 100/100. To maintain this: use OpenZeppelin libraries, emit events for all state changes, and conduct regular professional audits before mainnet deployment.`;
    }
    const critical = vulnerabilities.filter(v => v.severity === 'critical');
    const high = vulnerabilities.filter(v => v.severity === 'high');
    let answer = `Your contract scores ${score}/100. To improve:\n\n`;
    if (critical.length > 0) {
      answer += `• Fix ${critical.length} critical issue${critical.length > 1 ? 's' : ''} to recover up to ${critical.length * 40} points:\n`;
      critical.forEach(v => { answer += `  → ${v.type.replace(/-/g, ' ')} in ${v.function}()\n`; });
    }
    if (high.length > 0) {
      answer += `• Fix ${high.length} high severity issue${high.length > 1 ? 's' : ''} to recover up to ${high.length * 25} points:\n`;
      high.forEach(v => { answer += `  → ${v.type.replace(/-/g, ' ')} in ${v.function}()\n`; });
    }
    answer += `\nAddressing all findings would bring your score to 100/100.`;
    return answer;
  }

  if (q.includes('dangerous') || q.includes('risk') || q.includes('bad') || q.includes('severity') || q.includes('impact') || q.includes('consequence') || q.includes('危險') || q.includes('風險')) {
    if (hasReentrancy) {
      return `The reentrancy vulnerability in ${findVuln('reentrancy', vulnerabilities)?.function || 'withdraw'}() is extremely dangerous. It mirrors the 2016 DAO hack — $60M stolen. The attacker can drain 100% of contract funds in a single transaction. Because the external call happens before the balance update, the attacker re-enters withdraw() dozens of times before any state change records the deduction.`;
    }
    if (hasSelfdestruct) {
      return `The unprotected selfdestruct is catastrophic: it permanently deletes the contract bytecode and sends all ETH to an attacker address. This is irreversible — no upgrade path, no recovery, all user funds gone forever. Combined with the tx.origin vulnerability here, an attacker can trigger this via a phishing attack without the owner directly approving it.`;
    }
    if (hasTxOrigin) {
      return `Using tx.origin for authentication is dangerous because it captures the original transaction initiator, not the immediate caller. A malicious contract can sit between the user and this contract: when the user interacts with the phishing contract, tx.origin still returns the user's address — completely bypassing the owner check. This enables privilege escalation through social engineering.`;
    }
    if (hasDelegatecall) {
      return `Unsafe delegatecall executes external contract code in the calling contract's own storage context. If the target address is attacker-controlled, they can overwrite any storage slot — including the owner variable at slot 0. This allows complete contract takeover in a single transaction.`;
    }
    if (vulnerabilities.length === 0) {
      return `No high-risk vulnerabilities were detected. The security score of ${score}/100 reflects a well-written contract. Consider a professional audit before mainnet deployment.`;
    }
    return `This contract has ${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'} with score ${score}/100. ${hasCritical ? 'Critical issues represent immediate risk of fund loss.' : 'The issues are significant but addressable before deployment.'}`;
  }

  if (q.includes('exploit') || q.includes('attack') || q.includes('hack') || q.includes('steal') || q.includes('drain') || q.includes('hacker') || q.includes('攻擊') || q.includes('利用')) {
    if (hasReentrancy) {
      return `Reentrancy exploit steps:\n\n1. Deploy a malicious contract with a receive() fallback that calls target.withdraw()\n2. Call deposit() with a small ETH amount to register a balance\n3. Call withdraw() — target sends ETH via .call{value:...}()\n4. The malicious receive() triggers immediately, calling withdraw() again\n5. Since balances[msg.sender] hasn't updated yet, the require() passes again\n6. This loop continues until the contract is empty — all in one atomic transaction`;
    }
    if (hasTxOrigin) {
      return `tx.origin phishing attack:\n\n1. Deploy a phishing contract disguised as a legitimate service\n2. Social-engineer the contract owner into calling the phishing contract\n3. The phishing contract calls the target's privileged functions\n4. tx.origin == owner passes (the real owner initiated the tx chain)\n5. Attacker gains owner-level access — drains funds, changes ownership`;
    }
    if (hasSelfdestruct) {
      return `Selfdestruct exploit: attacker first bypasses the tx.origin authentication via phishing, then calls emergencyWithdraw(). selfdestruct(payable(attacker)) destroys the contract and transfers all ETH. Irreversible in one transaction.`;
    }
    return `With ${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'} detected, an attacker would target the highest-severity issue first. ${primaryVuln ? `Primary target: ${primaryVuln.type.replace(/-/g, ' ')} in ${primaryVuln.function}().` : ''} Check the Attack Generator for a full simulation.`;
  }

  if (q.includes('fix') || q.includes('remediat') || q.includes('patch') || q.includes('resolve') || q.includes('secure') || q.includes('prevent') || q.includes('solv') || q.includes('修復') || q.includes('解決')) {
    if (hasReentrancy) {
      return `Fix the reentrancy with Checks-Effects-Interactions (CEI) pattern:\n\n// VULNERABLE:\n(bool success,) = msg.sender.call{value: amount}("");\nbalances[msg.sender] -= amount; // state AFTER call ❌\n\n// SECURE:\nbalances[msg.sender] -= amount; // state BEFORE call ✅\n(bool success,) = msg.sender.call{value: amount}("");\n\nAlso add OpenZeppelin ReentrancyGuard:\nfunction withdraw(uint256 amount) public nonReentrant { ... }`;
    }
    if (hasTxOrigin) {
      return `Replace tx.origin with msg.sender:\n\n// VULNERABLE:\nrequire(tx.origin == owner);\n\n// SECURE:\nimport "@openzeppelin/contracts/access/Ownable.sol";\ncontract MyContract is Ownable {\n  constructor() Ownable(msg.sender) {}\n  function privileged() public onlyOwner { ... }\n}`;
    }
    if (hasSelfdestruct) {
      return `Remove selfdestruct (deprecated in EIP-6049). Use emergency pause pattern instead:\n\nbool public paused;\nfunction emergencyPause() public onlyOwner { paused = true; }\n\n// Withdraw without destroying:\nfunction emergencyWithdraw() public onlyOwner {\n  payable(owner()).transfer(address(this).balance);\n}`;
    }
    return `See the Defense Recommendations panel for complete code examples. Key principles: Checks-Effects-Interactions, OpenZeppelin libraries, msg.sender over tx.origin, Solidity 0.8+ for arithmetic safety.`;
  }

  if (q.includes('reentrancy') || q.includes('reentrant') || q.includes('重入')) {
    if (hasReentrancy) {
      return `Reentrancy: the contract calls msg.sender.call{value: amount}("") before updating balances[msg.sender]. An attacker's fallback function triggers on ETH receipt and immediately calls withdraw() again. The balance hasn't been deducted yet so require() passes again. This loop runs until the contract is drained. Fix: update state before external calls (CEI pattern) + ReentrancyGuard.`;
    }
    return `No reentrancy vulnerability detected in this contract.`;
  }

  if (q.includes('selfdestruct') || q.includes('destroy') || q.includes('kill') || q.includes('銷毀')) {
    if (hasSelfdestruct) {
      return `selfdestruct(recipient) deletes the contract bytecode from the EVM and forcibly sends all ETH to the recipient. Irreversible. In this contract, emergencyWithdraw() contains selfdestruct guarded by a tx.origin check — which is exploitable. Chained attack: phishing bypass → selfdestruct → contract destroyed, funds stolen.`;
    }
    return `No unprotected selfdestruct detected in this contract.`;
  }

  if (vulnerabilities.length === 0) {
    return `Your contract appears secure with a score of ${score}/100. Ask me: "How can I improve the score?", "What security patterns should I follow?", or "What should I test?"`;
  }

  return `Based on your contract analysis (score: ${score}/100, ${vulnerabilities.length} issue${vulnerabilities.length !== 1 ? 's' : ''} found), ask me:\n• "Why is this dangerous?"\n• "How would a hacker exploit this?"\n• "How can I fix it?"\n• "What would increase the score?"`;
}
