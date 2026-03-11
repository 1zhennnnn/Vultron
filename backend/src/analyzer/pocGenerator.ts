import { Vulnerability } from '../types';

export async function generatePoCScript(
  contractName: string,
  vulnerabilities: Vulnerability[],
  contractCode: string,
  callGroq: (prompt: string) => Promise<string>,
): Promise<string> {
  const criticalVulns = vulnerabilities
    .filter(v => v.severity === 'critical' || v.severity === 'high')
    .map(v => `- ${v.type} in ${v.function}() at line ${v.lineNumber ?? '?'}: ${v.description}`)
    .join('\n');

  if (!criticalVulns) return '';

  const prompt = `You are a smart contract security researcher.
Given this Solidity contract named "${contractName}":

${contractCode.substring(0, 2000)}

With these vulnerabilities detected:
${criticalVulns}

Generate a complete, runnable Hardhat test file that demonstrates the attack exploitation. The script should:
1. Deploy the vulnerable contract
2. Set up the attacker contract if needed
3. Execute the attack step by step
4. Assert that the attack succeeded (e.g. funds drained)

Return ONLY the JavaScript code, no explanation, no markdown fences.
Use ethers.js v6 syntax (ethers.deployContract, await contract.waitForDeployment).
Include comments explaining each attack step.
Contract name in the test must match: ${contractName}`;

  try {
    const raw = await callGroq(prompt);
    // Strip markdown fences if the model wraps the output
    return raw.replace(/```javascript\s*/g, '').replace(/```js\s*/g, '').replace(/```\s*/g, '').trim();
  } catch (err) {
    console.warn('PoC generation failed:', err);
    return '';
  }
}
