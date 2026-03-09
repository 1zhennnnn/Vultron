import { Vulnerability } from '../types';

export function generateScoreExplanation(score: number, vulnerabilities: Vulnerability[]): string {
  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
  const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;

  const deductions: string[] = [];
  if (criticalCount > 0) deductions.push(`${criticalCount} critical vulnerabilit${criticalCount > 1 ? 'ies' : 'y'} (−${criticalCount * 40} pts)`);
  if (highCount > 0) deductions.push(`${highCount} high severity issue${highCount > 1 ? 's' : ''} (−${highCount * 25} pts)`);
  if (mediumCount > 0) deductions.push(`${mediumCount} medium severity issue${mediumCount > 1 ? 's' : ''} (−${mediumCount * 10} pts)`);
  if (lowCount > 0) deductions.push(`${lowCount} low severity issue${lowCount > 1 ? 's' : ''} (−${lowCount * 5} pts)`);

  let riskStatement = '';
  if (score <= 19) {
    riskStatement = 'This contract is in CRITICAL condition and should never be deployed to mainnet. Exploitation by automated bots scanning the blockchain is near-certain within hours of deployment.';
  } else if (score <= 39) {
    riskStatement = 'This contract carries HIGH risk. Sophisticated attackers actively monitoring the mempool would likely exploit these vulnerabilities within days of deployment.';
  } else if (score <= 59) {
    riskStatement = 'This contract carries MEDIUM risk. While not immediately catastrophic, the identified vulnerabilities could be exploited over time. Remediation should occur before production deployment.';
  } else if (score <= 79) {
    riskStatement = 'This contract carries LOW risk. The vulnerabilities found are minor and unlikely to result in direct financial loss, but should be addressed to maintain security best practices.';
  } else {
    riskStatement = 'This contract is considered SAFE by Vultron\'s analysis engine. No significant vulnerabilities were detected. The contract follows secure development patterns.';
  }

  if (vulnerabilities.length === 0) {
    return `Vultron assigned this contract a security score of ${score}/100.\n\nNo vulnerabilities were detected. The starting score of 100 was maintained, with a baseline score of ${score} reflecting conservative best-practice assessment.\n\n${riskStatement}\n\nNote: Automated analysis cannot guarantee complete coverage. Business logic vulnerabilities, economic exploits, and oracle manipulation attacks require manual review by domain experts.`;
  }

  const deductionText = deductions.length > 0
    ? `The score was penalized by: ${deductions.join(', ')}.`
    : '';

  const primaryVuln = vulnerabilities.find(v => v.severity === 'critical') || vulnerabilities[0];
  const primaryContext = primaryVuln
    ? `\n\nThe most severe finding is a ${primaryVuln.severity} ${primaryVuln.type.replace(/-/g, ' ')} vulnerability in ${primaryVuln.function}(). ${primaryVuln.description}`
    : '';

  return `Vultron assigned this contract a security score of ${score}/100.\n\n${deductionText}${primaryContext}\n\n${riskStatement}\n\nScore breakdown:\n  Starting score: 100\n${criticalCount > 0 ? `  Critical (×${criticalCount}): −${criticalCount * 40} pts\n` : ''}${highCount > 0 ? `  High (×${highCount}): −${highCount * 25} pts\n` : ''}${mediumCount > 0 ? `  Medium (×${mediumCount}): −${mediumCount * 10} pts\n` : ''}${lowCount > 0 ? `  Low (×${lowCount}): −${lowCount * 5} pts\n` : ''}  Final score: ${score}/100`;
}
