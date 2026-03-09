import React from 'react';
import { Shield, Zap, GitBranch, Bot } from 'lucide-react';
import { AnalysisResult } from '../types';
import SecurityScoreCard from './SecurityScoreCard';
import VulnerabilityList from './VulnerabilityList';
import AttackFlowDiagram from './AttackFlowDiagram';

interface Props {
  result: AnalysisResult | null;
  isLoading: boolean;
}

function SkeletonLoader() {
  return (
    <div className="h-full flex flex-col gap-4 p-4 animate-pulse">
      <div className="flex items-center justify-center py-8">
        <div className="w-32 h-32 rounded-full bg-[#1e1e2e]" />
      </div>
      <div className="h-4 bg-[#1e1e2e] rounded w-3/4" />
      <div className="h-4 bg-[#1e1e2e] rounded w-1/2" />
      <div className="h-20 bg-[#1e1e2e] rounded" />
      <div className="h-20 bg-[#1e1e2e] rounded" />
      <div className="h-20 bg-[#1e1e2e] rounded" />
      <div className="mt-4 flex flex-col gap-2">
        <div className="h-12 bg-[#1e1e2e] rounded" />
        <div className="h-6 w-4 bg-[#1e1e2e] rounded mx-auto" />
        <div className="h-12 bg-[#1e1e2e] rounded" />
      </div>
    </div>
  );
}

function Placeholder() {
  return (
    <div className="h-full flex flex-col items-center justify-center gap-6 px-8 text-center">
      <div className="w-20 h-20 rounded-full bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
        <Shield size={36} className="text-violet-400" />
      </div>
      <div>
        <h3 className="text-lg font-semibold text-white mb-2">Ready to Analyze</h3>
        <p className="text-sm text-slate-400 leading-relaxed">
          Paste your Solidity contract in the editor and click{' '}
          <span className="text-violet-400 font-medium">"Analyze Contract"</span> to detect
          vulnerabilities and generate a security report.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 w-full max-w-xs">
        {[
          { icon: Shield, label: 'Vulnerability Detection' },
          { icon: Zap, label: 'Attack Simulation' },
          { icon: Bot, label: 'AI Explanation' },
          { icon: GitBranch, label: 'Risk Scoring' },
        ].map(({ icon: Icon, label }) => (
          <div
            key={label}
            className="flex flex-col items-center gap-1.5 p-3 rounded-lg bg-[#1e1e2e] border border-[#2a2a3e]"
          >
            <Icon size={16} className="text-violet-400" />
            <span className="text-xs text-slate-400 text-center">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AnalysisResultPanel({ result, isLoading }: Props) {
  if (isLoading) return <SkeletonLoader />;
  if (!result) return <Placeholder />;

  const criticalCount = result.vulnerabilities.filter(v => v.severity === 'Critical').length;

  return (
    <div className="h-full overflow-y-auto p-4 flex flex-col gap-6 animate-slide-up">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">{result.contractName}</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Analyzed {new Date(result.analyzedAt).toLocaleString()}
          </p>
        </div>
        {criticalCount > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-red-500/10 border border-red-500/30 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
            <span className="text-xs text-red-400 font-semibold">{criticalCount} Critical</span>
          </div>
        )}
      </div>

      {/* Score */}
      <div className="card p-6 flex justify-center">
        <SecurityScoreCard score={result.securityScore} />
      </div>

      {/* Vulnerabilities */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
          <Shield size={14} className="text-violet-400" />
          Vulnerabilities ({result.vulnerabilities.length})
        </h3>
        <VulnerabilityList vulnerabilities={result.vulnerabilities} />
      </div>

      {/* AI Explanation */}
      <div className="card p-4">
        <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
          <Bot size={14} className="text-violet-400" />
          AI Analysis
        </h3>
        <div className="text-xs text-slate-400 leading-relaxed whitespace-pre-line font-mono bg-[#0a0a0f] rounded-lg p-3 border border-[#1e1e2e] max-h-48 overflow-y-auto">
          {result.aiExplanation}
        </div>
      </div>

      {/* Attack Flow */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
          <Zap size={14} className="text-orange-400" />
          Attack Path
        </h3>
        <AttackFlowDiagram steps={result.attackPath} />
      </div>
    </div>
  );
}
