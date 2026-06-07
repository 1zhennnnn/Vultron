import React from 'react';
import { RiskLevel } from '../types';

interface Props {
  score: number;
  riskLevel: RiskLevel;
  compact?: boolean;
}

function getColors(score: number) {
  if (score >= 80) return { stroke: '#10b981', textClass: 'text-[#10b981]' };
  if (score >= 50) return { stroke: '#f97316', textClass: 'text-[#f97316]' };
  return { stroke: '#ef4444', textClass: 'text-[#ef4444]' };
}

export default function SecurityScoreCard({ score, riskLevel, compact = false }: Props) {
  const { stroke, textClass } = getColors(score);
  const radius = 40;
  const circ   = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;

  if (compact) {
    // Horizontal KPI layout for the top metrics bar
    return (
      <div className="flex items-center gap-3">
        <svg width="56" height="56" viewBox="0 0 56 56">
          <circle cx="28" cy="28" r={radius * 0.6} fill="none" stroke="#1f2937" strokeWidth="6" />
          <circle
            cx="28" cy="28" r={radius * 0.6}
            fill="none" stroke={stroke} strokeWidth="6"
            strokeLinecap="butt"
            strokeDasharray={circ * 0.6}
            strokeDashoffset={(circ * 0.6) - (score / 100) * (circ * 0.6)}
            transform="rotate(-90 28 28)"
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
          <text x="28" y="29" textAnchor="middle" dominantBaseline="middle"
            fill="#e2e8f0" fontSize="13" fontWeight="700" fontFamily="JetBrains Mono, monospace">
            {score}
          </text>
        </svg>
        <div>
          <p className="text-[9px] font-bold tracking-widest text-[#64748b] uppercase">Security Score</p>
          <p className={`text-xs font-bold mt-0.5 ${textClass}`}>{riskLevel}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-3">
      {/* Ring gauge */}
      <div className="relative">
        <svg width="120" height="120" viewBox="-6 -6 132 132" overflow="visible">
          {/* Track */}
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#1f2937" strokeWidth="8" />
          {/* Tick marks */}
          {[0, 20, 40, 60, 80].map(pct => {
            const angle = ((pct / 100) * 2 * Math.PI) - (Math.PI / 2);
            const x1 = 60 + (radius - 5) * Math.cos(angle);
            const y1 = 60 + (radius - 5) * Math.sin(angle);
            const x2 = 60 + (radius + 5) * Math.cos(angle);
            const y2 = 60 + (radius + 5) * Math.sin(angle);
            return <line key={pct} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#374151" strokeWidth="1" />;
          })}
          {/* Progress */}
          <circle
            cx="60" cy="60" r={radius}
            fill="none" stroke={stroke} strokeWidth="8"
            strokeLinecap="butt"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            transform="rotate(-90 60 60)"
            style={{ transition: 'stroke-dashoffset 1.1s cubic-bezier(.4,0,.2,1)' }}
          />
          {/* Score number */}
          <text x="60" y="56" textAnchor="middle" dominantBaseline="middle"
            fill="#e2e8f0" fontSize="26" fontWeight="700" fontFamily="JetBrains Mono, monospace">
            {score}
          </text>
          <text x="60" y="74" textAnchor="middle" dominantBaseline="middle"
            fill="#64748b" fontSize="10" fontFamily="Inter, sans-serif" letterSpacing="2">
            / 100
          </text>
        </svg>
      </div>

      {/* Labels */}
      <div className="text-center">
        <p className="text-[9px] font-bold tracking-widest text-[#64748b] uppercase">Security Score</p>
        <p className={`text-sm font-bold tracking-wide mt-0.5 ${textClass}`}>{riskLevel}</p>
      </div>
    </div>
  );
}
