import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Download, Copy, ArrowLeft, Bot, Shield, Zap, Check } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import Sidebar from '../components/Sidebar';
import SecurityScoreCard from '../components/SecurityScoreCard';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';
import { FullAnalysisResult, AttackStrategy, DefenseRecommendation } from '../types';

const mockReport: Omit<FullAnalysisResult, 'summary' | 'attackStrategy' | 'defenseRecommendations' | 'scoreExplanation'> = {
  contractName: 'VulnerableBank',
  securityScore: 0,
  riskLevel: 'Critical Risk',
  vulnerabilities: [
    { id: 'SWC-107', type: 'reentrancy', function: 'withdraw', severity: 'critical', description: 'External call made before state update allows recursive re-entry. Attacker can drain all funds before balance is decremented.', lineNumber: 16 },
    { id: 'SWC-115', type: 'tx-origin', function: 'constructor / emergencyWithdraw', severity: 'high', description: 'tx.origin used for authentication is vulnerable to phishing proxy attacks.', lineNumber: 8 },
    { id: 'SWC-106', type: 'unprotected-selfdestruct', function: 'emergencyWithdraw', severity: 'critical', description: 'selfdestruct() callable, allowing permanent contract destruction and ETH theft.', lineNumber: 28 },
  ],
  analyzedAt: new Date().toISOString(),
};

const mockAttack: AttackStrategy = {
  exploitType: 'Reentrancy + Selfdestruct Chain',
  riskLevel: 'Critical',
  steps: [
    'Attacker deploys malicious contract with reentrancy fallback',
    'Attacker deposits 0.1 ETH to register balance',
    'Attacker calls withdraw() — ETH sent before state update',
    'Fallback re-enters withdraw() recursively',
    'Contract fully drained via reentrancy loop',
    'Attacker triggers selfdestruct via tx.origin phishing',
    'Contract permanently destroyed — all user funds lost',
  ],
};

const mockDefense: DefenseRecommendation[] = [
  {
    issue: 'Reentrancy in withdraw()',
    strategy: 'Apply Checks-Effects-Interactions pattern. Update state before external calls. Use OpenZeppelin ReentrancyGuard.',
    codeExample: '// SECURE:\nbalances[msg.sender] -= amount;\n(bool success,) = msg.sender.call{value: amount}("");\nrequire(success);',
  },
  {
    issue: 'tx.origin in constructor/emergencyWithdraw()',
    strategy: 'Replace tx.origin with msg.sender. Use OpenZeppelin Ownable.',
    codeExample: 'import "@openzeppelin/contracts/access/Ownable.sol";\ncontract Secure is Ownable {\n  constructor() Ownable(msg.sender) {}\n}',
  },
];

const mockSummary = 'This contract contains 3 critical/high severity vulnerabilities including a reentrancy attack vector in withdraw() and an unprotected selfdestruct in emergencyWithdraw(). The security score of 0/100 indicates this contract must not be deployed. An attacker could drain all funds via reentrancy and permanently destroy the contract using tx.origin phishing. Immediate remediation is required.';

export default function ReportPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [wasCopied, setWasCopied] = React.useState(false);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({ ...mockReport, attack: mockAttack, defense: mockDefense, summary: mockSummary }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vultron-report-${mockReport.contractName}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    const md = `# Vultron Security Report: ${mockReport.contractName}\nScore: ${mockReport.securityScore}/100 | Risk: ${mockReport.riskLevel}\n\n## Vulnerabilities\n${mockReport.vulnerabilities.map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}() (${v.id})\n  ${v.description}`).join('\n')}\n\n## Summary\n${mockSummary}`;
    navigator.clipboard.writeText(md);
    setWasCopied(true);
    setTimeout(() => setWasCopied(false), 2000);
  };

  return (
    <div className="flex h-screen bg-[#080810] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-5">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate(-1)} className="w-8 h-8 rounded-lg bg-[#1e1e30] hover:bg-[#2a2a40] flex items-center justify-center transition-colors">
              <ArrowLeft size={15} className="text-slate-400" />
            </button>
            <div>
              <h1 className="text-lg font-bold text-white">{t('report.title')}</h1>
              <p className="text-xs text-slate-500">{t('report.subtitle')} {new Date(mockReport.analyzedAt).toLocaleString()}</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={copyMarkdown} className="btn btn-outline text-xs">
              {wasCopied ? <><Check size={12} className="text-green-400" />{t('report.copied')}</> : <><Copy size={12} />{t('report.copyButton')}</>}
            </button>
            <button onClick={exportJson} className="btn btn-primary text-xs">
              <Download size={12} /> {t('report.exportButton')}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 mb-5">
          <div className="card p-5 flex justify-center">
            <SecurityScoreCard score={mockReport.securityScore} riskLevel={mockReport.riskLevel} />
          </div>
          <div className="card p-5 col-span-2">
            <h2 className="text-base font-bold text-white font-mono mb-4">{mockReport.contractName}</h2>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: t('report.totalVulns'), value: mockReport.vulnerabilities.length, color: 'text-white' },
                { label: t('report.criticalIssues'), value: mockReport.vulnerabilities.filter(v => v.severity === 'critical').length, color: 'text-red-400' },
                { label: t('report.highIssues'), value: mockReport.vulnerabilities.filter(v => v.severity === 'high').length, color: 'text-orange-400' },
              ].map(({ label, value, color }) => (
                <div key={label}>
                  <p className="text-xs text-slate-500 mb-1">{label}</p>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="card p-5 mb-5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Shield size={12} className="text-violet-400" /> {t('report.vulnDetails')}
          </h2>
          <table className="w-full">
            <thead>
              <tr className="text-[10px] text-slate-600 uppercase tracking-wider border-b border-[#1e1e30]">
                {(['id','type','function','severity','line','description'] as const).map(h => (
                  <th key={h} className="text-left pb-2.5 pr-4 font-medium">{t(`report.tableHeaders.${h}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {mockReport.vulnerabilities.map(v => (
                <tr key={v.id} className="border-b border-[#1e1e30]/40">
                  <td className="py-3 pr-4 text-xs font-mono text-slate-500">{v.id}</td>
                  <td className="py-3 pr-4 text-xs font-semibold text-white">{v.type.replace(/-/g, ' ')}</td>
                  <td className="py-3 pr-4 text-xs font-mono text-violet-400">{v.function}()</td>
                  <td className="py-3 pr-4"><RiskIndicatorBadge severity={v.severity} size="sm" /></td>
                  <td className="py-3 pr-4 text-xs font-mono text-slate-500">{v.lineNumber ? `L${v.lineNumber}` : '—'}</td>
                  <td className="py-3 text-xs text-slate-400 max-w-xs leading-relaxed">{v.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card p-5 mb-5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Zap size={12} className="text-orange-400" /> {t('report.attackVector')}: {mockAttack.exploitType}
          </h2>
          <div className="flex flex-col gap-2">
            {mockAttack.steps.map((step, i) => (
              <div key={i} className={`flex items-start gap-2.5 p-3 rounded-lg ${i === 0 || i === mockAttack.steps.length - 1 ? 'bg-red-500/8 border border-red-500/20' : 'bg-[#0f0f1a] border border-[#1e1e30]'}`}>
                <span className={`flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold ${i === 0 || i === mockAttack.steps.length - 1 ? 'bg-red-500 text-white' : 'bg-violet-500/20 text-violet-400'}`}>{i + 1}</span>
                <p className={`text-xs leading-relaxed ${i === 0 || i === mockAttack.steps.length - 1 ? 'text-red-300' : 'text-slate-300'}`}>{step}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5 mb-5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Shield size={12} className="text-green-400" /> {t('report.defenseRec')}
          </h2>
          <div className="flex flex-col gap-4">
            {mockDefense.map((d, i) => (
              <div key={i} className="p-4 rounded-xl bg-green-500/4 border border-green-500/15">
                <p className="text-sm font-semibold text-white mb-1">{d.issue}</p>
                <p className="text-xs text-slate-400 mb-2 leading-relaxed">{d.strategy}</p>
                <pre className="text-xs font-mono text-green-300 bg-[#080810] rounded-lg p-3 overflow-x-auto border border-[#1e1e30]">{d.codeExample}</pre>
              </div>
            ))}
          </div>
        </div>

        <div className="card-glow p-5 mb-5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Bot size={12} className="text-violet-400" /> {t('report.aiSummary')}
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">{mockSummary}</p>
        </div>
      </main>
    </div>
  );
}
