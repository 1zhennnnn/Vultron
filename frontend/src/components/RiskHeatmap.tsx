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
  critical: '#ef4444', high: '#f59e0b', medium: '#3b82f6', low: '#64748b', info: '#374151',
};

interface Props { vulnerabilities: Vulnerability[]; }

export default function RiskHeatmap({ vulnerabilities }: Props) {
  const { t } = useTranslation();

  if (!vulnerabilities.length) {
    return (
      <div className="flex items-center justify-center py-6 text-[11px] text-[#374151] font-mono uppercase tracking-wider">
        {t('heatmap.noVulns')}
      </div>
    );
  }

  const fnMap = new Map<string, { severity: Severity; score: number }>();
  vulnerabilities.forEach(v => {
    const score = severityScore[v.severity];
    const ex = fnMap.get(v.function);
    if (!ex || score > ex.score) fnMap.set(v.function, { severity: v.severity, score });
  });

  const data = Array.from(fnMap.entries())
    .map(([fn, info]) => ({
      fn: fn.length > 20 ? fn.slice(0, 18) + '…' : fn,
      score: info.score,
      severity: info.severity,
    }))
    .sort((a, b) => b.score - a.score);

  const chartH = Math.max(60, data.length * 44);

  return (
    <div>
      <ResponsiveContainer width="100%" height={chartH}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 16, left: 0, bottom: 0 }}
          barSize={12}
        >
          <CartesianGrid strokeDasharray="2 4" stroke="#1f2937" horizontal={false} />
          <XAxis
            type="number" domain={[0, 100]}
            stroke="#1f2937"
            tick={{ fill: '#374151', fontSize: 9, fontFamily: 'Inter, sans-serif' }}
          />
          <YAxis
            type="category" dataKey="fn"
            stroke="#1f2937"
            tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}
            width={100}
            tickFormatter={(v: string) => `${v}()`}
          />
          <Tooltip
            contentStyle={{
              background: '#161b27', border: '1px solid #1f2937',
              borderRadius: 0, fontSize: 11, color: '#e2e8f0',
              fontFamily: 'JetBrains Mono, monospace',
            }}
            formatter={(value: number, _: string, props: any) => [
              `${(props.payload.severity || 'low').toUpperCase()} · ${value}/100`,
              t('heatmap.xLabel'),
            ]}
            labelFormatter={(label: string) => `${label}()`}
          />
          <Bar dataKey="score" radius={0}>
            {data.map((entry, i) => (
              <Cell key={i} fill={severityColor[entry.severity]} fillOpacity={0.8} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Legend */}
      <div className="flex gap-4 flex-wrap mt-2 pt-2 border-t border-[#1f2937]">
        {(['critical', 'high', 'medium', 'low'] as Severity[])
          .filter(s => data.some(d => d.severity === s))
          .map(s => (
            <div key={s} className="flex items-center gap-1.5">
              <span className="w-2 h-2 flex-shrink-0" style={{ background: severityColor[s] }} />
              <span className="text-[9px] font-bold tracking-widest text-[#64748b] uppercase">{s}</span>
            </div>
          ))}
      </div>
    </div>
  );
}
