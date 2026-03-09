import React from 'react';
import { Severity } from '../types';

const config: Record<Severity, { dot: string; pill: string; label: string }> = {
  critical: { dot: '#ef4444', pill: 'bg-red-500/10 border-red-500/30 text-red-400', label: 'Critical' },
  high:     { dot: '#f97316', pill: 'bg-orange-500/10 border-orange-500/30 text-orange-400', label: 'High' },
  medium:   { dot: '#eab308', pill: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400', label: 'Medium' },
  low:      { dot: '#3b82f6', pill: 'bg-blue-500/10 border-blue-500/30 text-blue-400', label: 'Low' },
  info:     { dot: '#6b7280', pill: 'bg-gray-500/10 border-gray-500/30 text-gray-400', label: 'Info' },
};

interface Props {
  severity: Severity;
  size?: 'sm' | 'md';
}

export default function RiskIndicatorBadge({ severity, size = 'md' }: Props) {
  const c = config[severity];
  const px = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-semibold ${px} ${c.pill}`}>
      <span
        className="rounded-full animate-pulse flex-shrink-0"
        style={{ width: 6, height: 6, background: c.dot }}
      />
      {c.label}
    </span>
  );
}
