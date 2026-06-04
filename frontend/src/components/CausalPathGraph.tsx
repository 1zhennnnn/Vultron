import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowDown, AlertTriangle } from 'lucide-react';
import { CausalPath, CausalNode } from '../types';

interface ConsensusInfo {
  runs: number;
  successful_runs: number;
  high_confidence_paths: number;
  low_confidence_paths: number;
  consensus_rate: number;
  note: string;
}

interface Props {
  paths: CausalPath[];
  criticalPathId: string | null;
  onNodeClick?: (payload: { lineNumber?: number; line?: number; label: string }) => void;
  consensus?: ConsensusInfo;
}

// Industrial node styles — square, border-coded by node type
const NODE_STYLES: Record<CausalNode['type'], {
  border: string; bg: string; text: string; tag: string; tagText: string;
}> = {
  'root-cause':     { border: 'border-[#ef4444]', bg: 'bg-[rgba(239,68,68,0.07)]',   text: 'text-[#fca5a5]', tag: 'bg-[rgba(239,68,68,0.15)] text-[#ef4444]',   tagText: 'ROOT CAUSE'     },
  'trigger':        { border: 'border-[#f59e0b]', bg: 'bg-[rgba(245,158,11,0.07)]',   text: 'text-[#fcd34d]', tag: 'bg-[rgba(245,158,11,0.15)] text-[#f59e0b]',   tagText: 'TRIGGER'        },
  'exploit-action': { border: 'border-[#f97316]', bg: 'bg-[rgba(249,115,22,0.07)]',   text: 'text-[#fdba74]', tag: 'bg-[rgba(249,115,22,0.15)] text-[#f97316]',   tagText: 'EXPLOIT ACTION' },
  'cascade-effect': { border: 'border-[#3b82f6]', bg: 'bg-[rgba(59,130,246,0.07)]',   text: 'text-[#93c5fd]', tag: 'bg-[rgba(59,130,246,0.15)] text-[#3b82f6]',   tagText: 'CASCADE'        },
  'final-impact':   { border: 'border-[#ef4444]', bg: 'bg-[rgba(127,29,29,0.25)]',    text: 'text-[#fca5a5]', tag: 'bg-[rgba(239,68,68,0.25)] text-[#ef4444]',   tagText: 'FINAL IMPACT'   },
};

function parseLineNumber(text: string): number | null {
  const m = text.match(/(?:line|L)\s?(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}

function PathGraph({ path, onNodeClick }: { path: CausalPath; onNodeClick?: Props['onNodeClick'] }) {
  const { t } = useTranslation();

  if (!path.nodes?.length) {
    return (
      <div className="border border-[#1f2937] p-4 bg-[#161b27]">
        <p className="text-[11px] text-[#94a3b8] leading-relaxed font-mono">{path.mechanism}</p>
        {path.summary && (
          <p className="mt-3 text-[10px] text-[#64748b] italic border-t border-[#1f2937] pt-3">{path.summary}</p>
        )}
      </div>
    );
  }

  const edgeMap = new Map<string, string>();
  (path.edges ?? []).forEach(e => edgeMap.set(e.from, e.relation));

  return (
    <div className="flex flex-col items-center gap-0">
      {path.nodes.map((node, i) => {
        const style = NODE_STYLES[node.type] ?? NODE_STYLES['exploit-action'];
        const relation = edgeMap.get(node.id);
        const isLast = i === path.nodes!.length - 1;

        return (
          <div key={node.id} className="flex flex-col items-center w-full max-w-md">
            <div
              onClick={() => {
                if (!onNodeClick) return;
                const line = node.lineNumber || parseLineNumber(node.description) || parseLineNumber(node.label);
                onNodeClick({ line: line || undefined, label: node.label });
              }}
              className={`w-full border p-3 transition-all ${style.border} ${style.bg} ${onNodeClick ? 'cursor-pointer hover:brightness-110' : ''}`}
            >
              <div className="flex items-start gap-2">
                <span className={`text-[8px] font-bold tracking-widest px-1.5 py-0.5 flex-shrink-0 mt-0.5 ${style.tag}`}>
                  {t(`analyzer.causalGraph.nodeTypes.${node.type}`, style.tagText)}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <p className={`text-xs font-semibold leading-snug ${style.text}`}>{node.label}</p>
                    {node.hallucination_risk && (
                      <span className="text-[8px] font-bold px-1 py-0.5 border border-[#f59e0b] text-[#f59e0b] bg-[rgba(245,158,11,0.08)] flex-shrink-0">
                        ⚠ UNVERIFIED
                      </span>
                    )}
                  </div>
                  <p className="text-[10px] text-[#94a3b8] mt-0.5 leading-relaxed">{node.description}</p>
                  {node.lineNumber && (
                    <p className="text-[9px] text-[#6b7280] font-mono mt-1">L{node.lineNumber}</p>
                  )}
                </div>
              </div>
            </div>

            {!isLast && (
              <div className="flex flex-col items-center py-1 gap-0.5">
                <div className="w-px h-2 bg-[#1f2937]" />
                <span className="text-[9px] text-[#6b7280] font-mono px-2 py-0.5 border border-[#2a2a2a] bg-[#0f1117] tracking-widest uppercase">
                  {relation ?? '→'}
                </span>
                <div className="w-px h-1 bg-[#2a2a2a]" />
                <ArrowDown size={10} className="text-[#6b7280]" />
              </div>
            )}
          </div>
        );
      })}

      {path.summary && (
        <p className="mt-4 text-[10px] text-[#64748b] italic text-center max-w-md border-t border-[#1f2937] pt-3 w-full">
          {path.summary}
        </p>
      )}
    </div>
  );
}

export default function CausalPathGraph({ paths, criticalPathId, onNodeClick, consensus }: Props) {
  const { t } = useTranslation();
  const [activeId, setActiveId] = useState<string>(criticalPathId ?? paths[0]?.id ?? '');

  const activePath = paths.find(p => p.id === activeId) ?? paths[0];
  if (!activePath) return null;

  const sevColor: Record<string, string> = {
    critical: 'text-[#ef4444]', high: 'text-[#f59e0b]',
    medium: 'text-[#3b82f6]',   low: 'text-[#64748b]',
  };

  return (
    <div>
      {/* Section label */}
      <div className="flex items-center gap-2 mb-3">
        <AlertTriangle size={11} className="text-[#f59e0b]" />
        <p className="section-label">{t('analyzer.causalGraph.title')}</p>
      </div>

      {/* Consensus status */}
      {consensus && (
        <div className="font-mono text-xs mb-3 border border-[#222222] p-3" style={{ background: '#060606' }}>
          <div style={{ color: '#00ff41', marginBottom: 4, letterSpacing: '0.08em' }}>
            {'> MULTI_RUN_CONSENSUS_ANALYSIS'}
          </div>
          <div style={{ color: '#888888' }}>
            {'  Runs completed:   '}{consensus.successful_runs}/{consensus.runs}
          </div>
          <div style={{ color: '#888888' }}>
            {'  High confidence:  '}
            <span style={{ color: '#00ff41' }}>{consensus.high_confidence_paths} paths</span>
          </div>
          <div style={{ color: '#888888' }}>
            {'  Low confidence:   '}
            <span style={{ color: '#ffaa00' }}>{consensus.low_confidence_paths} paths</span>
          </div>
          <div style={{ color: '#888888' }}>
            {'  Consensus rate:   '}
            <span style={{
              color: consensus.consensus_rate >= 0.7 ? '#00ff41'
                : consensus.consensus_rate >= 0.4 ? '#ffaa00'
                : '#ff4444',
            }}>
              {Math.round(consensus.consensus_rate * 100)}%
            </span>
          </div>
          {consensus.note && (
            <div style={{ color: '#555555', marginTop: 4 }}>{'  // '}{consensus.note}</div>
          )}
        </div>
      )}

      {/* Path selector tabs */}
      {paths.length > 1 && (
        <div className="flex flex-wrap gap-1 mb-4 border-b border-[#1f2937] pb-3">
          {paths.map(p => {
            const isCritical = p.id === criticalPathId;
            const isActive   = p.id === activeId;
            return (
              <button
                key={p.id}
                onClick={() => setActiveId(p.id)}
                className={`flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-bold tracking-wide border transition-all uppercase ${
                  isActive
                    ? 'border-[#f97316] bg-[rgba(249,115,22,0.1)] text-[#f97316]'
                    : 'border-[#1f2937] text-[#64748b] hover:border-[#374151] hover:text-[#94a3b8]'
                }`}
              >
                {p.title ?? p.id}
                {isCritical && (
                  <span className="text-[8px] font-bold px-1 py-0.5 bg-[rgba(239,68,68,0.2)] text-[#ef4444] border border-[#ef4444] animate-pulse">
                    {t('analyzer.causalGraph.criticalLabel')}
                  </span>
                )}
                {p.low_confidence && (
                  <span className="text-[8px] font-bold px-1 py-0.5 bg-[rgba(255,170,0,0.15)] text-[#ffaa00] border border-[#ffaa00]">
                    ~
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}

      {/* Active path header */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <h3 className="text-xs font-bold text-[#e2e8f0] tracking-wide">{activePath.title ?? activePath.id}</h3>
        {activePath.severity && (
          <span className={`text-[9px] font-bold uppercase tracking-widest border border-[#1f2937] px-1.5 py-0.5 ${sevColor[activePath.severity] ?? 'text-[#64748b]'}`}>
            {activePath.severity}
          </span>
        )}
        {activePath.low_confidence && (
          <span className="text-[9px] font-mono text-[#ffaa00]">
            ⚠ [SINGLE_RUN — VERIFY MANUALLY]
          </span>
        )}
      </div>

      <PathGraph path={activePath} onNodeClick={onNodeClick} />
    </div>
  );
}
