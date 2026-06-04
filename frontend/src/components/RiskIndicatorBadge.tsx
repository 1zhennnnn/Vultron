import React from 'react';
import { Severity } from '../types';

// Square severity badges — industrial dashboard style (no rounded pills)
const config: Record<string, {
  bg: string; border: string; text: string; dot: string; label: string; short: string;
}> = {
  critical: { bg: 'bg-[rgba(239,68,68,0.12)]',   border: 'border-[#ef4444]',  text: 'text-[#ef4444]',  dot: '#ef4444', label: 'CRITICAL', short: 'CRIT' },
  high:     { bg: 'bg-[rgba(245,158,11,0.12)]',   border: 'border-[#f59e0b]',  text: 'text-[#f59e0b]',  dot: '#f59e0b', label: 'HIGH',     short: 'HIGH' },
  medium:   { bg: 'bg-[rgba(59,130,246,0.12)]',   border: 'border-[#3b82f6]',  text: 'text-[#3b82f6]',  dot: '#3b82f6', label: 'MEDIUM',   short: 'MED'  },
  low:      { bg: 'bg-[rgba(100,116,139,0.12)]',  border: 'border-[#64748b]',  text: 'text-[#64748b]',  dot: '#64748b', label: 'LOW',      short: 'LOW'  },
  info:     { bg: 'bg-[rgba(55,65,81,0.5)]',      border: 'border-[#374151]',  text: 'text-[#475569]',  dot: '#475569', label: 'INFO',     short: 'INFO' },
  safe:     { bg: 'bg-[rgba(16,185,129,0.12)]',   border: 'border-[#10b981]',  text: 'text-[#10b981]',  dot: '#10b981', label: 'SAFE',     short: 'SAFE' },
};

interface Props {
  severity: Severity | 'safe';
  size?: 'xs' | 'sm' | 'md';
}

export default function RiskIndicatorBadge({ severity, size = 'md' }: Props) {
  const c = config[severity] ?? config.info;

  if (size === 'xs') {
    // Minimal inline tag for table cells
    return (
      <span
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 border text-[9px] font-bold tracking-widest font-mono ${c.bg} ${c.border} ${c.text}`}
        style={{ borderRadius: 0 }}
      >
        {c.short}
      </span>
    );
  }

  const pad = size === 'sm' ? 'px-2 py-0.5' : 'px-2.5 py-1';
  const fs  = size === 'sm' ? 'text-[10px]' : 'text-[11px]';

  return (
    <span
      className={`inline-flex items-center gap-1.5 border font-bold tracking-widest ${pad} ${fs} ${c.bg} ${c.border} ${c.text}`}
      style={{ borderRadius: 0 }}
    >
      <span className="w-1.5 h-1.5 flex-shrink-0" style={{ background: c.dot }} />
      {c.label}
    </span>
  );
}
