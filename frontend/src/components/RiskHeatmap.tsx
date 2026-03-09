import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts';
import { useTranslation } from 'react-i18next';
import { Vulnerability, Severity } from '../types';

const severityScore: Record<Severity, number> = {
  critical: 100, high: 75, medium: 40, low: 15, info: 5,
};

const severityColor: Record<Severity, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280',
};

interface Props { vulnerabilities: Vulnerability[]; }

export default function RiskHeatmap({ vulnerabilities }: Props) {
  const { t } = useTranslation();

  if (!vulnerabilities.length) {
    return (
      <div className="flex items-center justify-center py-6 text-sm text-slate-500">
        {t('heatmap.noVulns')}
      </div>
    );
  }

  const fnMap = new Map<string, { severity: Severity; score: number }>();
  vulnerabilities.forEach(v => {
    const score = severityScore[v.severity];
    const existing = fnMap.get(v.function);
    if (!existing || score > existing.score) {
      fnMap.set(v.function, { severity: v.severity, score });
    }
  });

  const data = Array.from(fnMap.entries())
    .map(([fn, info]) => ({
      fn: fn.length > 22 ? fn.slice(0, 20) + '…' : fn,
      score: info.score,
      severity: info.severity,
    }))
    .sort((a, b) => b.score - a.score);

  const chartH = Math.max(80, data.length * 52);

  return (
    <div>
      <ResponsiveContainer width="100%" height={chartH}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 20, left: 4, bottom: 0 }}
          barSize={16}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1e1e30" horizontal={false} />
          <XAxis
            type="number"
            domain={[0, 100]}
            stroke="#334155"
            tick={{ fill: '#64748b', fontSize: 10 }}
          />
          <YAxis
            type="category"
            dataKey="fn"
            stroke="#334155"
            tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
            width={108}
            tickFormatter={(v: string) => `${v}()`}
          />
          <Tooltip
            contentStyle={{ background: '#13131f', border: '1px solid #1e1e30', borderRadius: 8, fontSize: 12, color: '#e2e8f0' }}
            formatter={(value: number, _: string, props: any) => [
              `${props.payload.severity.toUpperCase()} · ${value}/100`,
              t('heatmap.xLabel'),
            ]}
            labelFormatter={(label: string) => `${label}()`}
          />
          <Bar dataKey="score" radius={[0, 4, 4, 0]}>
            {data.map((entry, i) => (
              <Cell key={i} fill={severityColor[entry.severity]} fillOpacity={0.85} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <div className="flex gap-3 flex-wrap mt-2.5">
        {(['critical', 'high', 'medium', 'low'] as Severity[])
          .filter(s => data.some(d => d.severity === s))
          .map(s => (
            <div key={s} className="flex items-center gap-1.5 text-xs text-slate-400">
              <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ background: severityColor[s] }} />
              <span className="capitalize">{s}</span>
            </div>
          ))}
      </div>
    </div>
  );
}
