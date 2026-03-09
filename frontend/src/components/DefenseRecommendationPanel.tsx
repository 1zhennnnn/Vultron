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
      <div className="space-y-3">
        <div className="flex gap-2">
          {[1, 2, 3].map(i => <div key={i} className="skeleton h-8 w-28 rounded-lg" />)}
        </div>
        <div className="skeleton h-32 rounded-xl" />
        <div className="skeleton h-32 rounded-xl" />
      </div>
    );
  }

  if (!recommendations.length) {
    return (
      <div className="flex flex-col items-center py-8 gap-2 text-slate-500">
        <Shield size={28} className="text-green-500" />
        <p className="text-sm">No critical defense actions required</p>
      </div>
    );
  }

  const current = recommendations[Math.min(active, recommendations.length - 1)];

  return (
    <div className="flex flex-col gap-4">
      {/* Tabs */}
      <div className="flex gap-2 flex-wrap">
        {recommendations.map((r, i) => (
          <button
            key={i}
            onClick={() => setActive(i)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
              active === i
                ? 'bg-violet-600 text-white'
                : 'bg-[#1e1e30] text-slate-400 hover:text-white hover:bg-[#2a2a40]'
            }`}
          >
            Fix #{i + 1}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="space-y-3 animate-fade-in" key={active}>
        <div className="flex items-start gap-2">
          <ChevronRight size={14} className="text-violet-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold text-white">{current.issue}</p>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">{current.strategy}</p>
          </div>
        </div>

        <div className="rounded-xl overflow-hidden border border-[#1e1e30]">
          <div className="px-3 py-2 bg-[#0f0f1a] border-b border-[#1e1e30] flex items-center gap-2">
            <span className="text-xs text-slate-500 font-mono">Secure Implementation</span>
          </div>
          <Editor
            height="160px"
            defaultLanguage="sol"
            value={current.codeExample}
            theme="vs-dark"
            options={{
              readOnly: true,
              fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              lineNumbers: 'off',
              padding: { top: 10 },
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
