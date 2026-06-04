import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Download, Copy, Check, Clock, Brain, AlertTriangle } from 'lucide-react';
import Sidebar from '../components/Sidebar';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';
import { FullAnalysisResult } from '../types';
import { getFixTemplate } from '../data/fixTemplates';
import { getContractHistory, getAnalysisById } from '../services/api';
import { cleanSlitherDescription } from '../utils/formatters';

function scoreColor(s: number) {
  if (s >= 80) return '#00ff41';
  if (s >= 50) return '#ffaa00';
  return '#ff4444';
}

function ScoreBar({ score }: { score: number }) {
  const filled = Math.round(score / 10);
  const empty  = 10 - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  return (
    <span style={{ fontFamily: "'Courier New', monospace", letterSpacing: '0.05em', color: scoreColor(score) }}>
      {bar} {score}%
    </span>
  );
}

function VulnRow({ v }: { v: FullAnalysisResult['vulnerabilities'][number] }) {
  const [open, setOpen] = useState(false);
  const sevColor =
    v.severity === 'critical' ? '#ff4444' :
    v.severity === 'high'     ? '#ffaa00' :
    v.severity === 'medium'   ? '#00ff41' :
    v.severity === 'low'      ? '#555555' : '#333333';

  return (
    <>
      <tr
        onClick={() => setOpen(o => !o)}
        style={{ cursor: 'pointer', borderLeft: `3px solid ${sevColor}` }}
        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,255,65,0.02)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        <td style={{ padding: '8px 10px' }}>
          <span style={{ color: sevColor, fontFamily: "'Courier New', monospace", fontSize: 10, fontWeight: 700, letterSpacing: '0.08em' }}>
            [{v.severity.toUpperCase()}]
          </span>
        </td>
        <td style={{ padding: '8px 10px' }}>
          <span style={{ color: '#cccccc', fontFamily: "'Courier New', monospace", fontSize: 11, fontWeight: 700 }}>
            {v.type.replace(/-/g, ' ')}
          </span>
        </td>
        <td style={{ padding: '8px 10px' }}>
          <span style={{ color: '#555555', fontFamily: "'Courier New', monospace", fontSize: 10 }}>
            {v.function}()
          </span>
        </td>
        <td style={{ padding: '8px 10px' }}>
          <span style={{ color: '#444444', fontFamily: "'Courier New', monospace", fontSize: 10 }}>
            {v.lineNumber ? `L${v.lineNumber}` : '—'}
          </span>
        </td>
        <td style={{ padding: '8px 10px', maxWidth: 280 }}>
          <span style={{ color: '#555555', fontFamily: "'Courier New', monospace", fontSize: 10, lineHeight: 1.5 }}>
            → {cleanSlitherDescription(v.description)}
          </span>
        </td>
        <td style={{ padding: '8px 10px', width: 80, whiteSpace: 'nowrap' }}>
          <span style={{ fontSize: 9, fontFamily: "'Courier New', monospace", fontWeight: 700, color: open ? '#00ff41' : '#555555' }}>
            {open ? '▼ COLLAPSE' : '▶ EXPAND'}
          </span>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} style={{ padding: '0 10px 10px 10px', background: '#0a0a0a' }}>
            <div style={{ borderLeft: `1px solid ${sevColor}`, paddingLeft: 12, marginLeft: 2 }}>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', marginBottom: 6, fontFamily: "'Courier New', monospace" }}>
                &gt; ROOT_CAUSE
              </p>
              <p style={{ fontSize: 11, color: '#888888', fontFamily: "'Courier New', monospace", lineHeight: 1.6 }}>
                {cleanSlitherDescription(v.description)}
              </p>
              {v.recommendation && (
                <>
                  <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', marginTop: 10, marginBottom: 6, fontFamily: "'Courier New', monospace" }}>
                    &gt; RECOMMENDATION
                  </p>
                  <p style={{ fontSize: 11, color: '#00ff41', fontFamily: "'Courier New', monospace", lineHeight: 1.6 }}>
                    {v.recommendation}
                  </p>
                </>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function ReportPage() {
  const navigate  = useNavigate();
  const location  = useLocation();
  const { i18n }  = useTranslation();
  const [wasCopied, setWasCopied] = useState(false);
  const [report, setReport]       = useState<FullAnalysisResult | null>(null);
  const [history, setHistory]     = useState<any | null>(null);

  useEffect(() => {
    const params     = new URLSearchParams(location.search);
    const analysisId = params.get('id');

    if (analysisId) {
      // Load from DB — no localStorage dependency
      getAnalysisById(analysisId)
        .then(data => setReport(data))
        .catch(() => {
          // fallback to localStorage if API fails
          const saved = localStorage.getItem('vultron_last_report');
          if (saved) { try { setReport(JSON.parse(saved)); } catch { /* corrupted */ } }
        });
    } else {
      const saved = localStorage.getItem('vultron_last_report');
      if (saved) { try { setReport(JSON.parse(saved)); } catch { /* corrupted */ } }
    }
  }, [location.search]);

  useEffect(() => {
    if (report?.contractName) {
      getContractHistory(report.contractName)
        .then(setHistory)
        .catch(() => {});
    }
  }, [report?.contractName]);

  const exportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vultron-report-${report.contractName}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    if (!report) return;
    const md = `# Vultron Security Report: ${report.contractName}\nScore: ${report.securityScore}/100 | Risk: ${report.riskLevel}\n\n## Vulnerabilities\n${report.vulnerabilities.map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}() (${v.id})\n  ${v.description}`).join('\n')}\n\n## Summary\n${report.summary}`;
    navigator.clipboard.writeText(md);
    setWasCopied(true);
    setTimeout(() => setWasCopied(false), 2000);
  };

  if (!report) {
    return (
      <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
        <Sidebar />
        <main className="flex-1 flex flex-col items-center justify-center gap-2">
          <p style={{ color: '#00ff41', fontSize: 13, fontWeight: 700, letterSpacing: '0.1em', marginBottom: 8 }}>
            &gt; NO_REPORT_AVAILABLE
          </p>
          {[
            "// You haven't analyzed any contracts yet.",
            "//",
            "// HOW TO START:",
            "// [01] Go to the Analyzer page",
            "// [02] Paste your Solidity contract",
            "// [03] Click ANALYZE CONTRACT",
            "// [04] Come back here to view results",
          ].map((line, i) => (
            <p key={i} style={{ color: '#555555', fontSize: 11, fontFamily: "'Courier New', monospace" }}>{line}</p>
          ))}
          <button
            onClick={() => navigate('/analyzer')}
            className="btn btn-primary text-[11px] mt-4"
          >
            [[ GO TO ANALYZER ]]
          </button>
        </main>
      </div>
    );
  }

  const criticalCount = report.vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount     = report.vulnerabilities.filter(v => v.severity === 'high').length;
  const mediumCount   = report.vulnerabilities.filter(v => v.severity === 'medium').length;

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">

        {/* Header */}
        <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: '#222222' }}>
          <div>
            <p style={{ color: '#00ff41', fontSize: 13, fontWeight: 700, letterSpacing: '0.1em' }}>&gt; SECURITY_REPORT</p>
            <p style={{ color: '#555555', fontSize: 11, marginTop: 2 }}>
              // {report.contractName} &nbsp;·&nbsp; {new Date(report.analyzedAt).toLocaleString()}
            </p>
            <p style={{ color: '#444444', fontSize: 10, marginTop: 3, fontFamily: "'Courier New', monospace" }}>
              // TIP: Press Ctrl+P to print or save as PDF
            </p>
          </div>
          <div className="flex gap-2">
            <button onClick={copyMarkdown} className="btn btn-outline text-[11px] flex items-center gap-1.5">
              {wasCopied ? <><Check size={11} style={{ color: '#00ff41' }} /> COPIED</> : <><Copy size={11} /> COPY_MD</>}
            </button>
            <button onClick={exportJson} className="btn btn-primary text-[11px] flex items-center gap-1.5">
              <Download size={11} /> EXPORT_JSON
            </button>
          </div>
        </div>

        {/* Solidity version */}
        {report.solidity_version && report.solidity_version !== 'unknown' && (
          <div className="font-mono text-xs px-3 py-1.5" style={{ background: '#0d0d0d', border: '1px solid #222222', color: '#555555' }}>
            {'// Solidity: '}
            <span style={{ color: '#00ff41' }}>{report.solidity_version}</span>
          </div>
        )}

        {/* Score + KPIs */}
        <div className="grid grid-cols-3 gap-3">
          {/* Final score */}
          <div className="p-4 col-span-2 flex flex-col gap-3" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; FINAL_SCORE</p>
            <div className="flex items-baseline gap-3">
              <span style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 48, color: scoreColor(report.securityScore), lineHeight: 1 }}>
                {report.securityScore}
              </span>
              <span style={{ color: '#333333', fontSize: 20, fontWeight: 700 }}>/&nbsp;100</span>
            </div>
            <ScoreBar score={report.securityScore} />
            <div className="mt-1">
              <RiskIndicatorBadge severity={
                report.riskLevel === 'Critical Risk' ? 'critical' :
                report.riskLevel === 'High Risk'     ? 'high'     :
                report.riskLevel === 'Medium Risk'   ? 'medium'   :
                report.riskLevel === 'Low Risk'      ? 'low'      :
                report.riskLevel === 'Safe'          ? 'safe'     : 'info'
              } size="sm" />
            </div>
          </div>

          {/* Vuln counts */}
          <div className="p-4 flex flex-col gap-3" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; VULN_SUMMARY</p>
            {[
              { label: '> CRITICAL', value: criticalCount, color: '#ff4444' },
              { label: '> HIGH',     value: highCount,     color: '#ffaa00' },
              { label: '> MEDIUM',   value: mediumCount,   color: '#00ff41' },
              { label: '> TOTAL',    value: report.vulnerabilities.length, color: '#cccccc' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex items-center justify-between">
                <span style={{ fontSize: 10, color: '#444444', letterSpacing: '0.08em' }}>{label}</span>
                <span style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 18, color }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability table */}
        <div style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
          <div className="flex items-center gap-2 px-4 py-2.5" style={{ borderBottom: '1px solid #222222' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; VULNERABILITY_DETAILS</p>
            <span style={{ fontSize: 10, color: '#333333' }}>// click row to expand</span>
          </div>
          <table className="w-full" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#0a0a0a' }}>
                {['SEVERITY', 'TYPE', 'FUNCTION', 'LINE', 'DESCRIPTION', ''].map(h => (
                  <th key={h} style={{
                    fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#444444',
                    padding: '7px 10px', borderBottom: '1px solid #222222', textAlign: 'left',
                    textTransform: 'uppercase', fontFamily: "'Courier New', monospace"
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {report.vulnerabilities.map(v => <VulnRow key={v.id} v={v} />)}
            </tbody>
          </table>
        </div>

        {/* Hallucination warning */}
        {report.hallucination && !report.hallucination.validation_passed && (
          <div className="flex items-start gap-3 p-3" style={{ border: '1px solid rgba(245,158,11,0.4)', background: 'rgba(245,158,11,0.05)' }}>
            <AlertTriangle size={13} style={{ color: '#f59e0b', flexShrink: 0, marginTop: 2 }} />
            <div>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#f59e0b', textTransform: 'uppercase' }}>
                HALLUCINATION_WARNING — {Math.round(report.hallucination.hallucination_rate * 100)}% unverified nodes
              </p>
              <p style={{ fontSize: 11, color: '#888888', marginTop: 3, fontFamily: "'Courier New', monospace" }}>
                // {report.hallucination.hallucination_count} causal path node(s) could not be anchored to Slither findings.
                Nodes marked ⚠ UNVERIFIED in the attack path graph.
              </p>
            </div>
          </div>
        )}

        {/* Contract Complexity */}
        {report.complexity && (
          <div className="font-mono text-xs" style={{ border: '1px solid #222222', padding: 12, background: '#0d0d0d', marginBottom: 0 }}>
            <div style={{ color: '#00ff41', marginBottom: 8, letterSpacing: '0.08em' }}>{'> CONTRACT_COMPLEXITY'}</div>
            <div style={{ color: '#888888', marginBottom: 8 }}>
              {'  Level:    '}
              <span style={{
                color: report.complexity.complexity_level === 'HIGH'
                  ? '#ff4444'
                  : report.complexity.complexity_level === 'MEDIUM'
                  ? '#ffaa00' : '#00ff41',
                fontWeight: 700,
              }}>
                [{report.complexity.complexity_level}]
              </span>
              {'  '}{report.complexity.complexity_note}
            </div>
            <div style={{ color: '#555555', marginBottom: 4, letterSpacing: '0.05em' }}>{'  ── METRICS ──────────────────'}</div>
            {Object.entries(report.complexity.metrics).map(([key, val]) => (
              <div key={key} style={{ color: '#666666' }}>
                {'  '}{key.padEnd(25, ' ')}{val}
              </div>
            ))}
          </div>
        )}

        {/* AI Summary */}
        {report.summary && (
          <div className="p-4" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase', marginBottom: 10 }}>&gt; AI_SUMMARY</p>
            <p style={{ fontSize: 12, color: '#888888', fontFamily: "'Courier New', monospace", lineHeight: 1.7 }}>{report.summary}</p>
          </div>
        )}

        {/* Exploitability breakdown */}
        {report.vulnerabilities.some(v => v.exploitability_score !== undefined) && (
          <div style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #222222' }}>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; EXPLOITABILITY_ANALYSIS</p>
            </div>
            <div className="p-4 flex flex-col gap-3">
              {report.vulnerabilities.filter(v => v.exploitability_score !== undefined).map((v) => {
                const score = v.exploitability_score ?? 50;
                const barColor = score >= 80 ? '#ff4444' : score >= 50 ? '#ffaa00' : '#00ff41';
                const filled = Math.round(score / 10);
                const bar = '█'.repeat(filled) + '░'.repeat(10 - filled);
                return (
                  <div key={v.id} style={{ borderLeft: `2px solid ${barColor}`, paddingLeft: 10 }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span style={{ fontSize: 10, fontWeight: 700, color: barColor, fontFamily: "'Courier New', monospace" }}>
                        [{v.exploitability_level ?? 'MEDIUM'}]
                      </span>
                      <span style={{ fontSize: 11, color: '#cccccc', fontFamily: "'Courier New', monospace" }}>
                        {v.type.replace(/-/g, ' ')} — {v.function}()
                      </span>
                      <span style={{ fontSize: 11, color: barColor, fontFamily: "'Courier New', monospace", marginLeft: 'auto' }}>
                        {bar} {score}
                      </span>
                    </div>
                    {v.exploitability_summary && (
                      <p style={{ fontSize: 10, color: '#555555', fontFamily: "'Courier New', monospace", lineHeight: 1.5 }}>
                        {v.exploitability_summary}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Defense recommendations + fix templates */}
        {report.defenseRecommendations?.length > 0 && (
          <div style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #222222' }}>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; DEFENSE_RECOMMENDATIONS</p>
            </div>
            <div className="p-4 flex flex-col gap-4">
              {report.defenseRecommendations.map((d, i) => {
                const matchVuln = report.vulnerabilities[i];
                const fixTpl = matchVuln ? getFixTemplate(matchVuln.type) : undefined;
                return (
                  <div key={i} style={{ borderLeft: '2px solid #00ff41', paddingLeft: 12 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: '#cccccc', marginBottom: 4, fontFamily: "'Courier New', monospace" }}>{d.issue}</p>
                    <p style={{ fontSize: 11, color: '#666666', marginBottom: 8, fontFamily: "'Courier New', monospace", lineHeight: 1.6 }}>{d.strategy}</p>
                    {fixTpl && (
                      <div style={{ marginBottom: 8 }}>
                        <p style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', color: '#444444', marginBottom: 4, fontFamily: "'Courier New', monospace" }}>&gt; FIX_STEPS</p>
                        {fixTpl.steps.map((step, si) => (
                          <p key={si} style={{ fontSize: 10, color: '#555555', fontFamily: "'Courier New', monospace", lineHeight: 1.6 }}>
                            {si + 1}. {step}
                          </p>
                        ))}
                        <p style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', color: '#444444', marginTop: 6, marginBottom: 4, fontFamily: "'Courier New', monospace" }}>&gt; FIXED_PATTERN</p>
                        <pre style={{
                          fontSize: 10, fontFamily: "'Courier New', monospace", color: '#00ff41',
                          background: '#000000', border: '1px solid #1a1a1a', padding: '10px 12px',
                          overflowX: 'auto', lineHeight: 1.5, marginBottom: 4
                        }}>{fixTpl.fixed_pattern}</pre>
                        <a href={fixTpl.oz_link} target="_blank" rel="noopener noreferrer"
                          style={{ fontSize: 10, color: '#00ff41', fontFamily: "'Courier New', monospace" }}
                          onMouseEnter={e => (e.currentTarget.style.color = '#00cc33')}
                          onMouseLeave={e => (e.currentTarget.style.color = '#00ff41')}
                        >
                          → OZ_REF: {fixTpl.oz_import}
                        </a>
                      </div>
                    )}
                    {!fixTpl && d.codeExample && (
                      <pre style={{
                        fontSize: 11, fontFamily: "'Courier New', monospace", color: '#00ff41',
                        background: '#000000', border: '1px solid #1a1a1a', padding: '10px 12px',
                        overflowX: 'auto', lineHeight: 1.5
                      }}>{d.codeExample}</pre>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Performance metrics */}
        {report.performance && (
          <div style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #222222' }}>
              <div className="flex items-center gap-2">
                <Clock size={10} style={{ color: '#00ff41' }} />
                <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; PERFORMANCE_METRICS</p>
              </div>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-5 gap-3">
                {[
                  { label: 'TOTAL', value: `${report.performance.total_ms}ms` },
                  { label: 'SLITHER', value: `${report.performance.slither_ms}ms` },
                  { label: 'GROQ_AI', value: `${report.performance.groq_ms}ms` },
                  { label: 'EXPLOIT', value: `${report.performance.exploitability_ms}ms` },
                  { label: 'VALIDATION', value: `${report.performance.validation_ms}ms` },
                ].map(({ label, value }) => (
                  <div key={label} style={{ borderLeft: '1px solid #222222', paddingLeft: 8 }}>
                    <p style={{ fontSize: 9, color: '#444444', letterSpacing: '0.08em', marginBottom: 2, fontFamily: "'Courier New', monospace" }}>{label}</p>
                    <p style={{ fontSize: 13, fontWeight: 700, color: '#00ff41', fontFamily: "'Courier New', monospace" }}>{value}</p>
                  </div>
                ))}
              </div>
              {report.hallucination && (
                <div style={{ marginTop: 12, borderTop: '1px solid #1a1a1a', paddingTop: 8 }}>
                  <div className="flex items-center gap-2">
                    <Brain size={10} style={{ color: report.hallucination.validation_passed ? '#00ff41' : '#f59e0b' }} />
                    <span style={{ fontSize: 10, color: '#444444', fontFamily: "'Courier New', monospace" }}>
                      HALLUCINATION_RATE: &nbsp;
                      <span style={{ color: report.hallucination.validation_passed ? '#00ff41' : '#f59e0b', fontWeight: 700 }}>
                        {(report.hallucination.hallucination_rate * 100).toFixed(1)}%
                      </span>
                      &nbsp;({report.hallucination.hallucination_count} unanchored nodes) — validation {report.hallucination.validation_passed ? 'PASSED ✓' : 'WARNING ⚠'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Analysis History */}
        {history && history.total_analyses > 1 && (
          <div className="font-mono text-xs" style={{ border: '1px solid #222222', padding: 12, background: '#0d0d0d' }}>
            <div style={{ color: '#00ff41', marginBottom: 8, letterSpacing: '0.08em' }}>
              {'> ANALYSIS_HISTORY — '}{history.contract_name}
            </div>

            {history.trend && (
              <div style={{ color: '#888888', marginBottom: 8 }}>
                {'  Latest score: '}
                <span style={{ color: '#ffffff' }}>{history.trend.latest}/100</span>
                {'  vs previous: '}
                <span style={{ color: '#ffffff' }}>{history.trend.previous}/100</span>
                {'  '}
                <span style={{
                  color: history.trend.direction === 'up'
                    ? '#00ff41'
                    : history.trend.direction === 'down'
                    ? '#ff4444' : '#888888',
                }}>
                  {history.trend.direction === 'up'
                    ? `↑ +${history.trend.change}`
                    : history.trend.direction === 'down'
                    ? `↓ ${history.trend.change}`
                    : '→ no change'}
                </span>
              </div>
            )}

            <div style={{ color: '#555555', marginBottom: 4, letterSpacing: '0.05em' }}>{'  ── SCORE TREND ──────────────'}</div>
            {history.history.map((h: any) => {
              const filled = Math.round(h.score / 10);
              const bar = '█'.repeat(filled) + '░'.repeat(10 - filled);
              return (
                <div key={h.id} style={{ display: 'flex', gap: 12, color: '#666666', marginBottom: 2 }}>
                  <span style={{ minWidth: 70 }}>{new Date(h.created_at).toLocaleDateString(i18n.language)}</span>
                  <span style={{
                    color: h.score >= 80 ? '#00ff41' : h.score >= 50 ? '#ffaa00' : '#ff4444',
                  }}>{bar}</span>
                  <span style={{ color: '#888888' }}>{h.score}/100</span>
                </div>
              );
            })}
          </div>
        )}

      </main>
    </div>
  );
}
