import React, { useEffect, useState, useRef, useMemo } from 'react';
import { Terminal, Send, User, Bot } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Vulnerability } from '../types';
import { copilotChat } from '../services/api';

interface ChatMessage { role: 'user' | 'ai'; text: string; id: number; }

interface Props {
  summary: string;
  isLoading: boolean;
  vulnerabilities: Vulnerability[];
  score: number;
  selectedVulnerability?: { lineNumber?: number; line?: number; label: string } | null;
}

export default function SecurityCopilotPanel({ summary, isLoading, vulnerabilities, score, selectedVulnerability }: Props) {
  const { t, i18n } = useTranslation();
  const [displayedSummary, setDisplayedSummary]     = useState('');
  const [summaryTyping,    setSummaryTyping]         = useState(false);
  const [messages,         setMessages]             = useState<ChatMessage[]>([]);
  const [input,            setInput]                = useState('');
  const [isSending,        setIsSending]            = useState(false);
  const [streamedAnswer,   setStreamedAnswer]       = useState('');
  const [isStreamTyping,   setIsStreamTyping]       = useState(false);
  const summaryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const streamTimerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const chatEndRef      = useRef<HTMLDivElement>(null);
  const nextId          = useRef(0);

  const selectedLine  = selectedVulnerability?.lineNumber || selectedVulnerability?.line;
  const selectedLabel = selectedVulnerability?.label;

  const quickPrompts = useMemo(() => {
    if (selectedLine) return [
      { label: `Explain L${selectedLine}`,   query: `Can you explain why "${selectedLabel}" at line ${selectedLine} is a risk?` },
      { label: `Fix L${selectedLine}`,        query: `Provide a specific code fix for the issue at line ${selectedLine}.` },
      { label: 'Attack Vector',               query: `How would an attacker exploit the vulnerability at line ${selectedLine}?` },
    ];
    return [
      { label: 'Top Risks',       query: 'What are the top 3 critical risks in this contract?' },
      { label: 'Fix All',         query: 'Provide a general plan to fix these vulnerabilities.' },
      { label: 'Gas Optimization', query: 'Are there any gas optimization suggestions?' },
    ];
  }, [selectedLine, selectedLabel]);

  useEffect(() => {
    if (summaryTimerRef.current) clearInterval(summaryTimerRef.current);
    if (!summary) { setDisplayedSummary(''); return; }
    setDisplayedSummary(''); setSummaryTyping(true);
    let i = 0;
    summaryTimerRef.current = setInterval(() => {
      i++;
      setDisplayedSummary(summary.slice(0, i));
      if (i >= summary.length) { clearInterval(summaryTimerRef.current!); setSummaryTyping(false); }
    }, 12);
    return () => { if (summaryTimerRef.current) clearInterval(summaryTimerRef.current); };
  }, [summary]);

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, streamedAnswer]);

  const typeAnswer = (text: string, onDone: () => void) => {
    if (streamTimerRef.current) clearInterval(streamTimerRef.current);
    setStreamedAnswer(''); setIsStreamTyping(true);
    let i = 0;
    streamTimerRef.current = setInterval(() => {
      i++;
      setStreamedAnswer(text.slice(0, i));
      if (i >= text.length) { clearInterval(streamTimerRef.current!); setIsStreamTyping(false); onDone(); }
    }, 10);
  };

  const sendMessage = async (question: string) => {
    if (!question.trim() || isSending) return;
    setMessages(prev => [...prev, { role: 'user', text: question, id: nextId.current++ }]);
    setInput(''); setIsSending(true); setStreamedAnswer('');
    try {
      const res = await copilotChat(question, vulnerabilities, score, i18n.language);
      typeAnswer(res.answer, () => {
        setMessages(prev => [...prev, { role: 'ai', text: res.answer, id: nextId.current++ }]);
        setStreamedAnswer(''); setIsSending(false);
      });
    } catch {
      setMessages(prev => [...prev, {
        role: 'ai', text: 'Backend connection failed. Ensure the server is running.', id: nextId.current++,
      }]);
      setIsSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(input); }
  };

  const isActive = isLoading || summaryTyping || isSending || isStreamTyping;

  return (
    <div className="border border-[#1f2937] flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-2.5 px-3 py-2 bg-[#0f1117] border-b border-[#1f2937]">
        <div className="w-7 h-7 border border-[#3b82f6] flex items-center justify-center flex-shrink-0">
          <Bot size={13} className="text-[#3b82f6]" />
        </div>
        <div className="flex-1">
          <p className="text-[10px] font-bold tracking-widest text-[#e2e8f0] uppercase">
            {t('copilot.title')}
          </p>
          <p className="text-[9px] text-[#64748b]">{t('copilot.subtitle')}</p>
        </div>
        {isActive && (
          <div className="flex items-center gap-1">
            {[0, 120, 240].map(d => (
              <span key={d} className="w-1 h-1 bg-[#3b82f6] animate-bounce" style={{ animationDelay: `${d}ms` }} />
            ))}
          </div>
        )}
      </div>

      {/* AI Summary */}
      <div className="p-3 border-b border-[#1f2937]">
        <p className="section-label mb-2">{t('copilot.summaryLabel')}</p>
        {isLoading ? (
          <div className="space-y-1.5">
            {[1, 2, 3].map(i => <div key={i} className="skeleton h-3" style={{ width: `${90 - i * 8}%` }} />)}
          </div>
        ) : (
          <div className="text-[11px] text-[#94a3b8] leading-relaxed whitespace-pre-wrap min-h-[36px] font-mono">
            {displayedSummary}
            {summaryTyping && <span className="inline-block w-0.5 h-3.5 bg-[#3b82f6] ml-0.5 animate-pulse" />}
            {!displayedSummary && !summaryTyping && (
              <span className="text-[#374151] italic text-[10px]">{t('copilot.waitPrompt')}</span>
            )}
          </div>
        )}
      </div>

      {/* Chat thread */}
      {(messages.length > 0 || (isSending && !isStreamTyping)) && (
        <div className="flex flex-col gap-2 p-3 max-h-60 overflow-y-auto border-b border-[#1f2937]">
          <p className="section-label">{t('copilot.chatLabel')}</p>
          {messages.map(msg => (
            <div key={msg.id} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              {msg.role === 'ai' && (
                <div className="w-5 h-5 border border-[#3b82f6] flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Bot size={9} className="text-[#3b82f6]" />
                </div>
              )}
              <div className={`max-w-[85%] px-2.5 py-2 text-[11px] leading-relaxed whitespace-pre-wrap border ${
                msg.role === 'user'
                  ? 'border-[#f97316] bg-[rgba(249,115,22,0.08)] text-[#fdba74]'
                  : 'border-[#1f2937] bg-[#0f1117] text-[#94a3b8]'
              }`}>
                {msg.text}
              </div>
              {msg.role === 'user' && (
                <div className="w-5 h-5 border border-[#374151] flex items-center justify-center flex-shrink-0 mt-0.5">
                  <User size={9} className="text-[#64748b]" />
                </div>
              )}
            </div>
          ))}
          {isSending && (
            <div className="flex gap-2">
              <div className="w-5 h-5 border border-[#3b82f6] flex items-center justify-center flex-shrink-0 mt-0.5">
                <Bot size={9} className="text-[#3b82f6]" />
              </div>
              <div className="px-2.5 py-2 border border-[#1f2937] bg-[#0f1117] text-[11px] text-[#94a3b8] whitespace-pre-wrap">
                {streamedAnswer ? (
                  <>{streamedAnswer}{isStreamTyping && <span className="inline-block w-0.5 h-3 bg-[#3b82f6] ml-0.5 animate-pulse" />}</>
                ) : (
                  <span className="text-[#374151] flex items-center gap-1">
                    {t('copilot.thinking')}
                    {[0, 80, 160].map(d => (
                      <span key={d} className="w-1 h-1 bg-[#374151] animate-bounce inline-block" style={{ animationDelay: `${d}ms` }} />
                    ))}
                  </span>
                )}
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>
      )}

      {/* Quick prompts */}
      {!isLoading && displayedSummary && !isSending && (
        <div className="px-3 pt-2 pb-2 border-b border-[#1f2937]">
          <p className="text-[9px] text-[#374151] mb-2 uppercase tracking-widest font-bold">
            {selectedLine ? `CTX: Line ${selectedLine}` : t('copilot.suggestedLabel')}
          </p>
          <div className="flex gap-1.5 flex-wrap">
            {quickPrompts.map((p, i) => (
              <button
                key={i}
                onClick={() => sendMessage(p.query)}
                className={`text-[9px] px-2 py-1 border tracking-wider font-bold uppercase transition-all ${
                  selectedLine
                    ? 'border-[#f59e0b] text-[#f59e0b] bg-[rgba(245,158,11,0.08)] hover:bg-[rgba(245,158,11,0.15)]'
                    : 'border-[#1f2937] text-[#64748b] hover:border-[#374151] hover:text-[#94a3b8]'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      {!isLoading && displayedSummary && (
        <div className="p-2 flex gap-1.5">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isSending}
            placeholder={selectedLine ? `Query L${selectedLine}…` : t('copilot.chatPlaceholder')}
            className="flex-1 bg-[#0f1117] border border-[#1f2937] px-2.5 py-1.5 text-[11px] text-[#e2e8f0] placeholder-[#374151] focus:outline-none focus:border-[#3b82f6] transition-colors disabled:opacity-50 font-mono"
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={!input.trim() || isSending}
            className="btn btn-outline px-3 py-1.5 flex-shrink-0 disabled:opacity-30"
          >
            {isSending ? t('copilot.sendingButton') : <Send size={11} />}
          </button>
        </div>
      )}
    </div>
  );
}
