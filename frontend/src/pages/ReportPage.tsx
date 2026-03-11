import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Download, Copy, ArrowLeft, Bot, Shield, Check, ScanSearch } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import Sidebar from '../components/Sidebar';
import SecurityScoreCard from '../components/SecurityScoreCard';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';
import { FullAnalysisResult } from '../types';

export default function ReportPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [wasCopied, setWasCopied] = useState(false);
  const [report, setReport] = useState<FullAnalysisResult | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem('vultron_last_report');
    if (saved) {
      try {
        setReport(JSON.parse(saved));
      } catch {
        // corrupted data — treat as missing
      }
    }
  }, []);

  if (!report) {
    return (
      <div className="flex h-screen bg-[#080810] overflow-hidden">
        <Sidebar />
        <main className="flex-1 flex flex-col items-center justify-center gap-4 text-slate-500">
          <div className="w-16 h-16 rounded-2xl bg-violet-500/8 border border-violet-500/15 flex items-center justify-center">
            <ScanSearch size={28} className="text-violet-500/60" />
          </div>
          <p className="text-sm">尚無分析結果，請先在分析器頁面分析合約</p>
          <button onClick={() => navigate('/analyzer')} className="btn btn-primary text-xs">
            前往分析器
          </button>
        </main>
      </div>
    );
  }

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vultron-report-${report.contractName}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    const md = `# Vultron Security Report: ${report.contractName}\nScore: ${report.securityScore}/100 | Risk: ${report.riskLevel}\n\n## Vulnerabilities\n${report.vulnerabilities.map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}() (${v.id})\n  ${v.description}`).join('\n')}\n\n## Summary\n${report.summary}`;
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
              <p className="text-xs text-slate-500">{t('report.subtitle')} {new Date(report.analyzedAt).toLocaleString()}</p>
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
            <SecurityScoreCard score={report.securityScore} riskLevel={report.riskLevel} />
          </div>
          <div className="card p-5 col-span-2">
            <h2 className="text-base font-bold text-white font-mono mb-4">{report.contractName}</h2>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: t('report.totalVulns'), value: report.vulnerabilities.length, color: 'text-white' },
                { label: t('report.criticalIssues'), value: report.vulnerabilities.filter(v => v.severity === 'critical').length, color: 'text-red-400' },
                { label: t('report.highIssues'), value: report.vulnerabilities.filter(v => v.severity === 'high').length, color: 'text-orange-400' },
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
              {report.vulnerabilities.map(v => (
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

        {report.defenseRecommendations?.length > 0 && (
          <div className="card p-5 mb-5">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Shield size={12} className="text-green-400" /> {t('report.defenseRec')}
            </h2>
            <div className="flex flex-col gap-4">
              {report.defenseRecommendations.map((d, i) => (
                <div key={i} className="p-4 rounded-xl bg-green-500/4 border border-green-500/15">
                  <p className="text-sm font-semibold text-white mb-1">{d.issue}</p>
                  <p className="text-xs text-slate-400 mb-2 leading-relaxed">{d.strategy}</p>
                  <pre className="text-xs font-mono text-green-300 bg-[#080810] rounded-lg p-3 overflow-x-auto border border-[#1e1e30]">{d.codeExample}</pre>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="card-glow p-5 mb-5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Bot size={12} className="text-violet-400" /> {t('report.aiSummary')}
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">{report.summary}</p>
        </div>
      </main>
    </div>
  );
}
