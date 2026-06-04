import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
} from 'recharts';
import { ScanSearch, TrendingUp, AlertTriangle, Shield, Clock, Brain } from 'lucide-react';
import Sidebar from '../components/Sidebar';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';
import SecurityScoreCard from '../components/SecurityScoreCard';
import { fetchStats } from '../services/api';
import { ScanHistoryItem } from '../types';

function LoadingIndicator({ label = 'LOADING' }: { label?: string }) {
  const [dots, setDots] = useState('_');
  useEffect(() => {
    const frames = ['_', '..', '...'];
    let i = 0;
    const id = setInterval(() => { i = (i + 1) % frames.length; setDots(frames[i]); }, 400);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="w-2 h-2 bg-[#00ff41] animate-ping" />
      <p style={{ color: '#00ff41', fontSize: 11, letterSpacing: '0.1em', fontFamily: "'Courier New', monospace" }}>
        &gt; {label}{dots}
      </p>
    </div>
  );
}

interface StatsData {
  totalScans: number;
  avgScore: number;
  criticalRisk: number;
  recentScans: ScanHistoryItem[];
  trendData: Array<{ date: string; score: number }>;
  topVulns: Array<{ type: string; count: number }>;
  performanceMetrics?: {
    avgTotalMs: number;
    avgHallucinationRate: number;
  };
}

function scoreColor(s: number) {
  if (s >= 80) return '#00ff41';
  if (s >= 50) return '#ffaa00';
  return '#ff4444';
}

const TOOLTIP_STYLE = {
  background: '#0d0d0d',
  border: '1px solid #222222',
  borderRadius: 0,
  fontSize: 11,
  color: '#00ff41',
  fontFamily: "'Courier New', monospace",
};

const TICK = { fill: '#666666', fontSize: 10, fontFamily: "'Courier New', monospace" };
const GRID = '#1a1a1a';

const VULN_COLORS: Record<string, string> = {
  reentrancy: '#ff4444',
  'tx-origin': '#ffaa00',
  'integer-overflow': '#ffaa00',
  'unprotected-selfdestruct': '#ff4444',
  'unsafe-delegatecall': '#ff4444',
  'access-control': '#ffaa00',
  'unchecked-call': '#00ff41',
  'arbitrary-send': '#ff4444',
};

function getVulnColor(type: string): string {
  return VULN_COLORS[type] ?? '#555555';
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { i18n } = useTranslation();
  const [stats, setStats] = useState<StatsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchStats()
      .then(data => { setStats(data as StatsData); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  }, []);

  const avgScore = stats?.avgScore ?? 0;
  const topVulnData = (stats?.topVulns ?? []).map(v => ({
    name: v.type.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()).slice(0, 14),
    count: v.count,
    fill: getVulnColor(v.type),
  }));

  if (loading) {
    return (
      <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
        <Sidebar />
        <main className="flex-1 flex items-center justify-center">
          <LoadingIndicator label="LOADING_DASHBOARD" />
        </main>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
        <Sidebar />
        <main className="flex-1 flex flex-col items-center justify-center gap-2">
          <p style={{ color: '#ff4444', fontSize: 11, letterSpacing: '0.1em', fontFamily: "'Courier New', monospace" }}>
            [ERROR] {error ?? 'No scan data found'}
          </p>
          <p style={{ color: '#555555', fontSize: 11, fontFamily: "'Courier New', monospace" }}>
            // Run an analysis first to populate the dashboard
          </p>
          <button onClick={() => navigate('/analyzer')} className="btn btn-primary text-[11px] mt-3">
            [[ GO TO ANALYZER ]]
          </button>
        </main>
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">

        {/* Header */}
        <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: '#222222' }}>
          <div>
            <p style={{ color: '#00ff41', fontSize: 13, fontWeight: 700, letterSpacing: '0.1em' }}>&gt; SECURITY_DASHBOARD</p>
            <p style={{ color: '#777777', fontSize: 11, marginTop: 2 }}>// Smart contract security overview — live data</p>
          </div>
          <button
            onClick={() => navigate('/analyzer')}
            className="btn btn-primary text-[11px] flex items-center gap-1.5"
          >
            <ScanSearch size={11} /> [[ NEW SCAN ]]
          </button>
        </div>

        {/* KPI row */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { icon: ScanSearch,    label: '> TOTAL_SCANS',    value: `${stats.totalScans}`,  sub: 'Historical records',  color: '#00ff41',  border: 'rgba(0,255,65,0.25)',  bg: 'rgba(0,255,65,0.03)'  },
            { icon: TrendingUp,    label: '> AVG_SCORE',      value: `${avgScore}`,          sub: 'All contracts',       color: scoreColor(avgScore), border: '#222222', bg: '#0d0d0d' },
            { icon: AlertTriangle, label: '> CRITICAL_RISKS', value: `${stats.criticalRisk}`, sub: 'Score below 20',     color: '#ff4444',  border: 'rgba(255,68,68,0.25)', bg: 'rgba(255,68,68,0.03)' },
          ].map(({ icon: Icon, label, value, sub, color, border, bg }) => (
            <div key={label} className="p-4" style={{
              border: `1px solid ${border}`, background: bg,
              borderBottom: `2px solid ${color}`,
            }}>
              <div className="flex items-start justify-between">
                <div>
                  <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase', marginBottom: 8 }}>{label}</p>
                  <p style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 36, color, lineHeight: 1 }}>{value}</p>
                  <p style={{ fontSize: 11, color: '#666666', marginTop: 4 }}>{sub}</p>
                </div>
                <div className="w-7 h-7 flex items-center justify-center flex-shrink-0" style={{ border: `1px solid ${border}`, background: bg }}>
                  <Icon size={12} style={{ color }} />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Intelligence row */}
        <div className="grid grid-cols-3 gap-3">
          {/* Avg score gauge */}
          <div className="p-4 flex flex-col items-center gap-2" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase', alignSelf: 'flex-start' }}>&gt; AVG_SECURITY_SCORE</p>
            <SecurityScoreCard
              score={avgScore}
              riskLevel={avgScore >= 80 ? 'Safe' : avgScore >= 60 ? 'Low Risk' : avgScore >= 40 ? 'Medium Risk' : avgScore >= 20 ? 'High Risk' : 'Critical Risk'}
            />
          </div>

          {/* Score distribution */}
          <div className="p-4" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase', marginBottom: 12 }}>&gt; SCORE_HISTORY</p>
            {stats.trendData.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-8">
                <p style={{ fontSize: 11, color: '#555555', fontFamily: 'monospace' }}>// No data yet</p>
                <p style={{ fontSize: 10, color: '#444444', fontFamily: 'monospace' }}>// Run your first analysis to see results</p>
                <button onClick={() => navigate('/analyzer')} className="btn btn-primary text-[10px] mt-1">
                  [[ GO TO ANALYZER ]]
                </button>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={170}>
                <LineChart data={stats.trendData}>
                  <CartesianGrid strokeDasharray="2 4" stroke={GRID} />
                  <XAxis dataKey="date" stroke={GRID} tick={TICK} />
                  <YAxis domain={[0, 100]} stroke={GRID} tick={TICK} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Line type="monotone" dataKey="score" stroke="#00ff41" strokeWidth={2}
                    dot={{ fill: '#00ff41', r: 3, strokeWidth: 0 }}
                    activeDot={{ r: 4, fill: '#00cc33', strokeWidth: 0 }} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Top vuln types */}
          <div className="p-4" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase', marginBottom: 12 }}>&gt; VULN_FREQUENCY</p>
            {topVulnData.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-8">
                <p style={{ fontSize: 11, color: '#555555', fontFamily: 'monospace' }}>// No vulnerability data yet</p>
                <p style={{ fontSize: 10, color: '#444444', fontFamily: 'monospace' }}>// Analyze a contract to populate this chart</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={170}>
                <BarChart data={topVulnData} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }} barSize={10}>
                  <CartesianGrid strokeDasharray="2 4" stroke={GRID} horizontal={false} />
                  <XAxis type="number" stroke={GRID} tick={TICK} />
                  <YAxis type="category" dataKey="name" stroke={GRID} tick={TICK} width={80} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" radius={0}>
                    {topVulnData.map((entry, i) => <Cell key={i} fill={entry.fill} fillOpacity={0.85} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Score trend */}
        {stats.trendData.length > 0 && (
          <div className="p-4" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp size={11} style={{ color: '#00ff41' }} />
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; SCORE_TREND</p>
            </div>
            <ResponsiveContainer width="100%" height={150}>
              <LineChart data={stats.trendData}>
                <CartesianGrid strokeDasharray="2 4" stroke={GRID} />
                <XAxis dataKey="date" stroke={GRID} tick={TICK} />
                <YAxis domain={[0, 100]} stroke={GRID} tick={TICK} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Line type="monotone" dataKey="score" stroke="#00ff41" strokeWidth={2}
                  dot={{ fill: '#00ff41', r: 3, strokeWidth: 0 }}
                  activeDot={{ r: 4, fill: '#00cc33', strokeWidth: 0 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Performance metrics */}
        {stats.performanceMetrics && (
          <div className="grid grid-cols-2 gap-3">
            {[
              { icon: Clock, label: '> AVG_ANALYSIS_TIME', value: `${stats.performanceMetrics.avgTotalMs}ms`, sub: 'Per contract scan', color: '#00ff41' },
              { icon: Brain, label: '> AVG_HALLUCINATION_RATE', value: `${(stats.performanceMetrics.avgHallucinationRate * 100).toFixed(1)}%`, sub: 'AI causal path accuracy', color: stats.performanceMetrics.avgHallucinationRate < 0.3 ? '#00ff41' : '#ffaa00' },
            ].map(({ icon: Icon, label, value, sub, color }) => (
              <div key={label} className="p-4" style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
                <div className="flex items-center gap-2 mb-2">
                  <Icon size={10} style={{ color }} />
                  <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>{label}</p>
                </div>
                <p style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 24, color, lineHeight: 1 }}>{value}</p>
                <p style={{ fontSize: 10, color: '#666666', marginTop: 4 }}>{sub}</p>
              </div>
            ))}
          </div>
        )}

        {/* Recent scans table */}
        <div style={{ border: '1px solid #222222', background: '#0d0d0d' }}>
          <div className="flex items-center gap-2 px-4 py-2.5" style={{ borderBottom: '1px solid #222222' }}>
            <Shield size={11} style={{ color: '#00ff41' }} />
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase' }}>&gt; RECENT_SCANS</p>
          </div>
          {stats.recentScans.length === 0 ? (
            <div className="px-4 py-6">
              <p style={{ fontSize: 11, color: '#666666' }}>// No scans recorded yet — run your first analysis</p>
            </div>
          ) : (
            <table className="data-table w-full">
              <thead>
                <tr>
                  {['CONTRACT', 'SCORE', 'RISK', 'VULNS', 'DATE', ''].map(h => (
                    <th key={h} className="text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {stats.recentScans.map(item => (
                  <tr key={item.id}
                    onClick={() => navigate(`/report?id=${item.id}`)}
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,255,65,0.04)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = ''; }}
                  >
                    <td><span style={{ fontFamily: "'Courier New', monospace", color: '#cccccc', fontSize: 11 }}>{item.contractName}</span></td>
                    <td><span style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 13, color: scoreColor(item.securityScore) }}>{item.securityScore}</span></td>
                    <td>
                      <RiskIndicatorBadge severity={
                        item.riskLevel === 'Critical Risk' ? 'critical' :
                        item.riskLevel === 'High Risk'     ? 'high' :
                        item.riskLevel === 'Medium Risk'   ? 'medium' :
                        item.riskLevel === 'Low Risk'      ? 'low' :
                        item.riskLevel === 'Safe'          ? 'safe' : 'info'
                      } size="sm" />
                    </td>
                    <td><span style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 11, color: '#888888' }}>{item.vulnerabilityCount}</span></td>
                    <td><span style={{ fontSize: 10, color: '#777777', fontFamily: "'Courier New', monospace" }}>{new Date(item.analyzedAt).toLocaleDateString(i18n.language)}</span></td>
                    <td>
                      <button
                        onClick={(e) => { e.stopPropagation(); navigate(`/report?id=${item.id}`); }}
                        style={{ fontSize: 10, color: '#00ff41', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', background: 'none', border: 'none', cursor: 'pointer', fontFamily: "'Courier New', monospace" }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#00cc33')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#00ff41')}
                      >
                        REPORT →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

      </main>
    </div>
  );
}
