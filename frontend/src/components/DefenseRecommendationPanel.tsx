import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Shield, ChevronRight } from 'lucide-react';
import { DefenseRecommendation } from '../types';

interface Props {
  recommendations: DefenseRecommendation[];
  isLoading: boolean;
}

export default function DefenseRecommendationPanel({ recommendations, isLoading }: Props) {
  const [active, setActive] = useState(0);

  if (isLoading) {
    return (
      <div className="space-y-2">
        <div className="flex gap-1">
          {[1, 2, 3].map(i => <div key={i} className="skeleton h-7 w-20" />)}
        </div>
        <div className="skeleton h-28" />
        <div className="skeleton h-28" />
      </div>
    );
  }

  if (!recommendations.length) {
    return (
      <div className="flex flex-col items-center py-8 gap-2">
        <div className="w-8 h-8 border border-[#10b981] flex items-center justify-center">
          <Shield size={14} className="text-[#10b981]" />
        </div>
        <p className="text-[11px] text-[#10b981] font-bold uppercase tracking-widest">No Remediation Required</p>
      </div>
    );
  }

  const current = recommendations[Math.min(active, recommendations.length - 1)];

  return (
    <div className="flex flex-col gap-3">
      {/* Tab selectors */}
      <div className="flex gap-1 flex-wrap">
        {recommendations.map((r, i) => (
          <button
            key={i}
            onClick={() => setActive(i)}
            className={`px-3 py-1 text-[10px] font-bold tracking-widest uppercase border transition-all ${
              active === i
                ? 'border-[#f97316] bg-[rgba(249,115,22,0.1)] text-[#f97316]'
                : 'border-[#1f2937] text-[#64748b] hover:border-[#374151] hover:text-[#94a3b8]'
            }`}
          >
            FIX #{i + 1}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="animate-fade-in" key={active}>
        <div className="border border-[#1f2937] p-3 mb-3 bg-[#0f1117]">
          <div className="flex items-start gap-2">
            <ChevronRight size={12} className="text-[#f97316] mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-xs font-semibold text-[#e2e8f0]">{current.issue}</p>
              <p className="text-[11px] text-[#94a3b8] mt-1 leading-relaxed">{current.strategy}</p>
            </div>
          </div>
        </div>

        <div className="border border-[#1f2937] overflow-hidden">
          <div className="px-3 py-1.5 bg-[#0f1117] border-b border-[#1f2937] flex items-center gap-2">
            <span className="text-[9px] font-bold tracking-widest text-[#64748b] uppercase">Secure Implementation</span>
          </div>
          <Editor
            height="160px"
            defaultLanguage="sol"
            value={current.codeExample}
            theme="vs-dark"
            options={{
              readOnly: true,
              fontSize: 11,
              fontFamily: "'JetBrains Mono', monospace",
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              lineNumbers: 'off',
              padding: { top: 8 },
              wordWrap: 'on',
              folding: false,
              contextmenu: false,
            }}
          />
        </div>
      </div>
    </div>
  );
}
