import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, BarChart, Bar,
} from 'recharts';
import { ScanSearch, TrendingUp, AlertTriangle, Shield } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import Sidebar from '../components/Sidebar';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';
import SecurityScoreCard from '../components/SecurityScoreCard';
import { ScanHistoryItem } from '../types';

const mockHistory: ScanHistoryItem[] = [
  { id: '1', contractName: 'VulnerableBank',  securityScore: 0,  riskLevel: 'Critical Risk', vulnerabilityCount: 3, analyzedAt: '2025-01-20T10:30:00Z' },
  { id: '2', contractName: 'TokenSwap',        securityScore: 50, riskLevel: 'Medium Risk',   vulnerabilityCount: 2, analyzedAt: '2025-01-19T15:22:00Z' },
  { id: '3', contractName: 'NFTMarketplace',   securityScore: 75, riskLevel: 'Low Risk',      vulnerabilityCount: 1, analyzedAt: '2025-01-18T09:10:00Z' },
  { id: '4', contractName: 'YieldFarm',        securityScore: 25, riskLevel: 'High Risk',     vulnerabilityCount: 4, analyzedAt: '2025-01-17T14:45:00Z' },
  { id: '5', contractName: 'MultiSigWallet',   securityScore: 92, riskLevel: 'Safe',          vulnerabilityCount: 0, analyzedAt: '2025-01-16T11:00:00Z' },
];

const trendData = [
  { d: 'Jan 14', score: 92 },
  { d: 'Jan 15', score: 25 },
  { d: 'Jan 16', score: 75 },
  { d: 'Jan 17', score: 50 },
  { d: 'Jan 18', score: 0  },
  { d: 'Jan 19', score: 67 },
  { d: 'Jan 20', score: 88 },
];

const distData = [
  { name: 'Safe',          value: 1, color: '#22c55e' },
  { name: 'Low Risk',      value: 1, color: '#3b82f6' },
  { name: 'Medium Risk',   value: 1, color: '#eab308' },
  { name: 'High Risk',     value: 1, color: '#f97316' },
  { name: 'Critical Risk', value: 1, color: '#ef4444' },
];

const topVulnData = [
  { name: 'Reentrancy',      count: 3, fill: '#ef4444' },
  { name: 'Tx.Origin',       count: 2, fill: '#f97316' },
  { name: 'Overflow',        count: 2, fill: '#eab308' },
  { name: 'Selfdestruct',    count: 1, fill: '#8b5cf6' },
  { name: 'Delegatecall',    count: 1, fill: '#3b82f6' },
];

const avgScore = Math.round(mockHistory.reduce((s, i) => s + i.securityScore, 0) / mockHistory.length);
const criticalCount = mockHistory.filter(i => i.riskLevel === 'Critical Risk').length;

function scoreColor(s: number) {
  if (s >= 80) return 'text-green-400';
  if (s >= 50) return 'text-orange-400';
  return 'text-red-400';
}

const RADIAN = Math.PI / 180;
function renderCustomLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }: any) {
  if (percent < 0.08) return null;
  const r = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + r * Math.cos(-midAngle * RADIAN);
  const y = cy + r * Math.sin(-midAngle * RADIAN);
  return <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={600}>{`${(percent * 100).toFixed(0)}%`}</text>;
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();

  return (
    <div className="flex h-screen bg-[#080810] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">{t('dashboard.title')}</h1>
            <p className="text-xs text-slate-500 mt-0.5">{t('dashboard.subtitle')}</p>
          </div>
          <button onClick={() => navigate('/analyzer')} className="btn btn-primary text-sm">
            <ScanSearch size={14} /> {t('dashboard.newScan')}
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { icon: ScanSearch, label: t('dashboard.totalScans'), value: `${mockHistory.length}`, sub: t('dashboard.totalScansSub'), color: 'text-violet-400', border: 'border-violet-500/20', bg: 'bg-violet-500/8' },
            { icon: TrendingUp, label: t('dashboard.avgScore'), value: `${avgScore}`, sub: t('dashboard.avgScoreSub'), color: avgScore >= 80 ? 'text-green-400' : avgScore >= 50 ? 'text-orange-400' : 'text-red-400', border: 'border-slate-700/40', bg: 'bg-slate-700/8' },
            { icon: AlertTriangle, label: t('dashboard.criticalRisk'), value: `${criticalCount}`, sub: t('dashboard.criticalRiskSub'), color: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-500/8' },
          ].map(({ icon: Icon, label, value, sub, color, border, bg }) => (
            <div key={label} className={`card p-4 border ${border} ${bg}`}>
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs text-slate-500 mb-1">{label}</p>
                  <p className={`text-3xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-slate-600 mt-0.5">{sub}</p>
                </div>
                <div className={`w-9 h-9 rounded-xl ${bg} border ${border} flex items-center justify-center`}>
                  <Icon size={16} className={color} />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Intelligence row: Avg Gauge + Score Distribution + Top Vulns */}
        <div className="grid grid-cols-3 gap-4">
          {/* Avg Score Gauge */}
          <div className="card p-4 flex flex-col items-center gap-2">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider self-start">{t('dashboard.avgGaugeTitle')}</p>
            <SecurityScoreCard score={avgScore} riskLevel={avgScore >= 80 ? 'Safe' : avgScore >= 60 ? 'Low Risk' : avgScore >= 40 ? 'Medium Risk' : avgScore >= 20 ? 'High Risk' : 'Critical Risk'} />
          </div>

          {/* Score Distribution Pie */}
          <div className="card p-4">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">{t('dashboard.scoreDistTitle')}</p>
            <ResponsiveContainer width="100%" height={190}>
              <PieChart>
                <Pie
                  data={distData}
                  cx="50%"
                  cy="40%"
                  outerRadius={46}
                  dataKey="value"
                  labelLine={false}
                  label={renderCustomLabel}
                >
                  {distData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Legend
                  iconSize={7}
                  iconType="circle"
                  wrapperStyle={{ fontSize: 10, paddingTop: 2 }}
                  formatter={(value: string) => <span style={{ color: '#94a3b8', fontSize: 10 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Top Vuln Types Bar */}
          <div className="card p-4">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">{t('dashboard.topVulnTitle')}</p>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={topVulnData} layout="vertical" margin={{ top: 0, right: 8, left: 4, bottom: 0 }} barSize={12}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e1e30" horizontal={false} />
                <XAxis type="number" stroke="#334155" tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis type="category" dataKey="name" stroke="#334155" tick={{ fill: '#94a3b8', fontSize: 10 }} width={72} />
                <Tooltip contentStyle={{ background: '#13131f', border: '1px solid #1e1e30', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {topVulnData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Score Trend */}
        <div className="card p-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <TrendingUp size={12} className="text-violet-400" /> {t('dashboard.scoreTrend')}
          </h2>
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e1e30" />
              <XAxis dataKey="d" stroke="#334155" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis domain={[0, 100]} stroke="#334155" tick={{ fill: '#64748b', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#13131f', border: '1px solid #1e1e30', borderRadius: 8, color: '#e2e8f0', fontSize: 12 }} />
              <Line type="monotone" dataKey="score" stroke="#7c3aed" strokeWidth={2.5} dot={{ fill: '#7c3aed', r: 3, strokeWidth: 0 }} activeDot={{ r: 5, fill: '#a78bfa' }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Scans Table */}
        <div className="card p-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Shield size={12} className="text-violet-400" /> {t('dashboard.recentScans')}
          </h2>
          <table className="w-full">
            <thead>
              <tr className="text-[10px] text-slate-600 uppercase tracking-wider border-b border-[#1e1e30]">
                {['contract','score','risk','vulns','date'].map(h => (
                  <th key={h} className="text-left pb-2.5 pr-4 font-medium">{t(`dashboard.table.${h}`)}</th>
                ))}
                <th className="text-left pb-2.5 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {mockHistory.map(item => (
                <tr key={item.id} className="border-b border-[#1e1e30]/40 hover:bg-[#1a1a28]/40 transition-colors">
                  <td className="py-2.5 pr-4"><span className="text-sm font-medium text-white font-mono">{item.contractName}</span></td>
                  <td className="py-2.5 pr-4"><span className={`text-sm font-bold ${scoreColor(item.securityScore)}`}>{item.securityScore}</span></td>
                  <td className="py-2.5 pr-4">
                    <RiskIndicatorBadge severity={
                      item.riskLevel === 'Critical Risk' ? 'critical' :
                      item.riskLevel === 'High Risk' ? 'high' :
                      item.riskLevel === 'Medium Risk' ? 'medium' :
                      item.riskLevel === 'Low Risk' ? 'low' : 'info'
                    } size="sm" />
                  </td>
                  <td className="py-2.5 pr-4"><span className="text-sm text-slate-400">{item.vulnerabilityCount}</span></td>
                  <td className="py-2.5 pr-4"><span className="text-xs text-slate-600">{new Date(item.analyzedAt).toLocaleDateString()}</span></td>
                  <td className="py-2.5">
                    <button onClick={() => navigate('/report')} className="text-xs text-violet-400 hover:text-violet-300 transition-colors font-medium">{t('dashboard.reportBtn')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
