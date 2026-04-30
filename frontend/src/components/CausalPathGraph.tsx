import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Zap, ArrowDown } from 'lucide-react';
import { CausalPath, CausalNode } from '../types';

interface Props {
  paths: CausalPath[];
  criticalPathId: string | null;
  onNodeClick: (payload: { lineNumber?: number; line?: number; label: string }) => void;
}

const NODE_STYLES: Record<CausalNode['type'], { bg: string; border: string; text: string; dot: string }> = {
  'root-cause':     { bg: 'bg-red-500/10',    border: 'border-red-500/40',    text: 'text-red-300',    dot: 'bg-red-500' },
  'trigger':        { bg: 'bg-orange-500/10', border: 'border-orange-500/40', text: 'text-orange-300', dot: 'bg-orange-500' },
  'exploit-action': { bg: 'bg-amber-500/10',  border: 'border-amber-500/40',  text: 'text-amber-300',  dot: 'bg-amber-500' },
  'cascade-effect': { bg: 'bg-violet-500/10', border: 'border-violet-500/40', text: 'text-violet-300', dot: 'bg-violet-500' },
  'final-impact':   { bg: 'bg-red-900/30',    border: 'border-red-700/60',    text: 'text-red-200',    dot: 'bg-red-700' },
};

function parseLineNumber(text: string): number | null {
  const match = text.match(/(?:line|L)\s?(\d+)/i);
  return match ? parseInt(match[1], 10) : null;
}

function PathGraph({ path, onNodeClick }: { path: CausalPath; onNodeClick: Props['onNodeClick'] }) {
  const { t } = useTranslation();
  
  if (!path.nodes || path.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center gap-0">
        <div className="w-full max-w-lg rounded-xl border border-[#2a2a40] bg-[#1e1e30] p-4 text-center">
          <p className="text-xs text-slate-400 leading-relaxed">{path.mechanism}</p>
        </div>
        {path.summary && (
          <p className="mt-4 text-xs text-slate-500 italic text-center max-w-lg">{path.summary}</p>
        )}
      </div>
    );
  }

  const edgeMap = new Map<string, string>();
  (path.edges ?? []).forEach(e => edgeMap.set(e.from, e.relation));

  const handleNodeClick = (node: CausalNode) => {
    const line = node.lineNumber || parseLineNumber(node.description) || parseLineNumber(node.label);
    onNodeClick({ line: line || undefined, label: node.label });
  };

  return (
    <div className="flex flex-col items-center gap-0">
      {path.nodes.map((node, i) => {
        const style = NODE_STYLES[node.type] ?? NODE_STYLES['exploit-action'];
        const relation = edgeMap.get(node.id);
        const isLast = i === path.nodes!.length - 1;

        return (
          <div key={node.id} className="flex flex-col items-center w-full max-w-lg">
            <div 
              onClick={() => handleNodeClick(node)}
              className={`w-full rounded-xl border p-4 cursor-pointer transition-all hover:scale-[1.02] active:scale-[0.98] ${style.bg} ${style.border} shadow-sm hover:shadow-violet-500/20`}
            >
              <div className="flex items-start gap-3">
                <div className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${style.dot}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold uppercase tracking-widest ${style.text}`}>
                      {t(`analyzer.causalGraph.nodeTypes.${node.type}`, node.type.replace(/-/g, ' '))}
                    </span>
                  </div>
                  <p className="text-sm font-semibold text-white leading-snug">{node.label}</p>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{node.description}</p>
                </div>
              </div>
            </div>

            {!isLast && (
              <div className="flex flex-col items-center py-1.5 gap-0.5">
                <div className="w-px h-3 bg-violet-500/30" />
                <span className="text-[10px] text-slate-600 font-mono px-2 py-0.5 rounded bg-[#13131f] border border-[#1e1e30]">
                  {relation ?? '→'}
                </span>
                <div className="w-px h-2 bg-violet-500/30" />
                <ArrowDown size={12} className="text-violet-500/50" />
              </div>
            )}
          </div>
        );
      })}

      {path.summary && (
        <p className="mt-5 text-xs text-slate-500 italic text-center max-w-lg leading-relaxed border-t border-[#1e1e30] pt-4 w-full">
          {path.summary}
        </p>
      )}
    </div>
  );
}

export default function CausalPathGraph({ paths, criticalPathId, onNodeClick }: Props) {
  const { t } = useTranslation();
  const [activeId, setActiveId] = useState<string>(
    criticalPathId ?? paths[0]?.id ?? ''
  );

  const activePath = paths.find(p => p.id === activeId) ?? paths[0];
  if (!activePath) return null;

  const severityColor: Record<string, string> = {
    critical: 'text-red-400',
    high:     'text-orange-400',
    medium:   'text-amber-400',
    low:      'text-blue-400',
    info:     'text-slate-400',
  };

  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-4">
        <Zap size={13} className="text-amber-400" />
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          {t('analyzer.causalGraph.title')}
        </p>
      </div>

      {paths.length > 1 && (
        <div className="flex flex-wrap gap-2 mb-5">
          {paths.map(p => {
            const isCritical = p.id === criticalPathId;
            const isActive = p.id === activeId;
            return (
              <button
                key={p.id}
                onClick={() => setActiveId(p.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all duration-150 ${
                  isActive
                    ? 'bg-violet-600 text-white border-violet-500'
                    : 'bg-[#1e1e30] text-slate-400 border-[#2a2a40] hover:text-white hover:bg-[#2a2a40]'
                }`}
              >
                {p.title ?? p.id}
                {isCritical && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                    {t('analyzer.causalGraph.criticalLabel')}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}

      <div className="flex items-center gap-2 mb-4">
        <h3 className="text-sm font-bold text-white">{activePath.title ?? activePath.id}</h3>
        {activePath.severity && (
          <span className={`text-xs font-bold uppercase ${severityColor[activePath.severity] ?? 'text-slate-400'}`}>
            {activePath.severity}
          </span>
        )}
      </div>

      <PathGraph path={activePath} onNodeClick={onNodeClick} />
    </div>
  );
}
