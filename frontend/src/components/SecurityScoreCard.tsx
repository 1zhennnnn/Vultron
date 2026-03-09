import React from 'react';
import { RiskLevel } from '../types';

interface Props {
  score: number;
  riskLevel: RiskLevel;
}

function getColors(score: number) {
  if (score >= 80) return { stroke: '#22c55e', text: 'text-green-400', glow: '#22c55e' };
  if (score >= 50) return { stroke: '#f97316', text: 'text-orange-400', glow: '#f97316' };
  return { stroke: '#ef4444', text: 'text-red-400', glow: '#ef4444' };
}

export default function SecurityScoreCard({ score, riskLevel }: Props) {
  const { stroke, text, glow } = getColors(score);
  const radius = 52;
  const circ = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative">
        <svg width="136" height="136" viewBox="0 0 136 136">
          <circle cx="68" cy="68" r={radius} fill="none" stroke="#1e1e30" strokeWidth="10" />
          <circle
            cx="68" cy="68" r={radius}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            transform="rotate(-90 68 68)"
            style={{
              transition: 'stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)',
              filter: `drop-shadow(0 0 8px ${glow})`,
            }}
          />
          <text x="68" y="63" textAnchor="middle" dominantBaseline="middle" fill="white" fontSize="30" fontWeight="700" fontFamily="Sora, sans-serif">{score}</text>
          <text x="68" y="84" textAnchor="middle" dominantBaseline="middle" fill="#64748b" fontSize="11" fontFamily="Sora, sans-serif">/ 100</text>
        </svg>
      </div>
      <div className="text-center">
        <p className="text-xs text-slate-500">Security Score</p>
        <p className={`text-sm font-semibold mt-0.5 ${text}`}>{riskLevel}</p>
      </div>
    </div>
  );
}
