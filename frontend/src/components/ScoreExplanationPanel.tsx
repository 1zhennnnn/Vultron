import React from 'react';
import { Terminal } from 'lucide-react';

interface Props {
  explanation: string;
  isLoading: boolean;
}

export default function ScoreExplanationPanel({ explanation, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        <div className="skeleton h-3.5 w-full" />
        <div className="skeleton h-3.5 w-5/6" />
        <div className="skeleton h-3.5 w-4/5" />
        <div className="skeleton h-3.5 w-full" />
        <div className="skeleton h-3.5 w-3/4" />
      </div>
    );
  }

  if (!explanation) {
    return (
      <div className="text-xs text-slate-600 italic font-mono">
        {'> '}Score explanation will appear after analysis...
      </div>
    );
  }

  return (
    <div
      className="text-xs font-mono text-slate-300 leading-relaxed whitespace-pre-wrap bg-[#080810] rounded-xl p-4 border border-[#1e1e30] max-h-64 overflow-y-auto animate-fade-in"
      style={{ fontFamily: '"JetBrains Mono", "Fira Code", monospace' }}
    >
      <span className="text-violet-400">{'> '}</span>
      {explanation}
    </div>
  );
}
