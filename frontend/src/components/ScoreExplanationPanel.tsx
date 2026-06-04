import React from 'react';

interface Props {
  explanation: string;
  isLoading: boolean;
}

export default function ScoreExplanationPanel({ explanation, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="space-y-1.5 p-3 border border-[#1f2937] bg-[#0f1117]">
        {[100, 90, 80, 95, 70].map((w, i) => (
          <div key={i} className="skeleton h-3" style={{ width: `${w}%` }} />
        ))}
      </div>
    );
  }

  if (!explanation) {
    return (
      <div className="terminal">
        <span className="text-[#374151]">{'>'} </span>
        <span className="text-[#374151] italic">Score explanation will appear after analysis...</span>
      </div>
    );
  }

  return (
    <div className="terminal whitespace-pre-wrap animate-fade-in max-h-48 overflow-y-auto">
      <span className="text-[#f97316]">{'>'} </span>
      {explanation}
    </div>
  );
}
