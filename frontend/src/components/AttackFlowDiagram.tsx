import React from 'react';
import { AlertTriangle, ArrowDown } from 'lucide-react';

interface Props {
  steps: string[];
}

export default function AttackFlowDiagram({ steps }: Props) {
  if (!steps || steps.length === 0) return null;

  return (
    <div className="flex flex-col items-center gap-0 w-full">
      {steps.map((step, index) => {
        const isFirst = index === 0;
        const isLast = index === steps.length - 1;
        const isDanger = isFirst || isLast;

        return (
          <React.Fragment key={index}>
            <div
              className={`w-full rounded-lg p-3 border transition-all duration-200 ${
                isDanger
                  ? 'bg-red-500/10 border-red-500/40 shadow-[0_0_12px_rgba(239,68,68,0.15)]'
                  : 'bg-[#1e1e2e] border-[#2a2a3e]'
              }`}
            >
              <div className="flex items-start gap-2">
                <span
                  className={`mt-0.5 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                    isDanger ? 'bg-red-500 text-white' : 'bg-violet-500/20 text-violet-400'
                  }`}
                >
                  {isDanger ? <AlertTriangle size={10} /> : index + 1}
                </span>
                <p className={`text-sm leading-relaxed ${isDanger ? 'text-red-300' : 'text-slate-300'}`}>
                  {step}
                </p>
              </div>
            </div>
            {index < steps.length - 1 && (
              <div className="flex flex-col items-center py-1">
                <div className="w-px h-3 bg-violet-500/40" />
                <ArrowDown size={14} className="text-violet-500/60" />
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
