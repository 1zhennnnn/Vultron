import React, { useEffect, useState, useRef } from 'react';
import { Bot, Sparkles, Send, User } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Vulnerability } from '../types';
import { copilotChat } from '../services/api';

interface ChatMessage {
  role: 'user' | 'ai';
  text: string;
  id: number;
}

interface Props {
  summary: string;
  isLoading: boolean;
  vulnerabilities: Vulnerability[];
  score: number;
}

export default function SecurityCopilotPanel({ summary, isLoading, vulnerabilities, score }: Props) {
  const { t } = useTranslation();
  const [displayedSummary, setDisplayedSummary] = useState('');
  const [summaryTyping, setSummaryTyping] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [streamedAnswer, setStreamedAnswer] = useState('');
  const [isStreamTyping, setIsStreamTyping] = useState(false);
  const summaryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const streamTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(0);

  useEffect(() => {
    if (summaryTimerRef.current) clearInterval(summaryTimerRef.current);
    if (!summary) { setDisplayedSummary(''); return; }
    setDisplayedSummary('');
    setSummaryTyping(true);
    let i = 0;
    summaryTimerRef.current = setInterval(() => {
      i++;
      setDisplayedSummary(summary.slice(0, i));
      if (i >= summary.length) {
        clearInterval(summaryTimerRef.current!);
        setSummaryTyping(false);
      }
    }, 12);
    return () => { if (summaryTimerRef.current) clearInterval(summaryTimerRef.current); };
  }, [summary]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, streamedAnswer]);

  const typeAnswer = (text: string, onDone: () => void) => {
    if (streamTimerRef.current) clearInterval(streamTimerRef.current);
    setStreamedAnswer('');
    setIsStreamTyping(true);
    let i = 0;
    streamTimerRef.current = setInterval(() => {
      i++;
      setStreamedAnswer(text.slice(0, i));
      if (i >= text.length) {
        clearInterval(streamTimerRef.current!);
        setIsStreamTyping(false);
        onDone();
      }
    }, 10);
  };

  const sendMessage = async (question: string) => {
    if (!question.trim() || isSending) return;
    const userMsg: ChatMessage = { role: 'user', text: question, id: nextId.current++ };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsSending(true);
    setStreamedAnswer('');
    try {
      const res = await copilotChat(question, vulnerabilities, score);
      typeAnswer(res.answer, () => {
        const aiMsg: ChatMessage = { role: 'ai', text: res.answer, id: nextId.current++ };
        setMessages(prev => [...prev, aiMsg]);
        setStreamedAnswer('');
        setIsSending(false);
      });
    } catch {
      const errMsg: ChatMessage = {
        role: 'ai',
        text: 'Sorry, I could not connect to the backend. Please ensure the server is running on port 3001.',
        id: nextId.current++,
      };
      setMessages(prev => [...prev, errMsg]);
      setIsSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(input); }
  };

  const suggestions = t('copilot.questions', { returnObjects: true }) as string[];
  const isActive = isLoading || summaryTyping || isSending || isStreamTyping;

  return (
    <div className="card-glow flex flex-col" style={{ animation: isActive ? 'glowPulse 2s ease-in-out infinite' : 'none' }}>
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-[#1e1e30]">
        <div className="w-9 h-9 rounded-xl bg-violet-600/20 border border-violet-500/30 flex items-center justify-center">
          <Bot size={18} className="text-violet-400" />
        </div>
        <div>
          <p className="text-sm font-bold text-white flex items-center gap-1.5">
            {t('copilot.title')} <Sparkles size={12} className="text-violet-400" />
          </p>
          <p className="text-xs text-slate-500">{t('copilot.subtitle')}</p>
        </div>
        {isActive && (
          <div className="ml-auto flex items-center gap-1">
            {[0, 150, 300].map(d => (
              <span key={d} className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-bounce" style={{ animationDelay: `${d}ms` }} />
            ))}
          </div>
        )}
      </div>

      {/* AI Summary */}
      <div className="p-4 border-b border-[#1e1e30]">
        <p className="text-[10px] font-semibold text-violet-400 uppercase tracking-wider mb-2">{t('copilot.summaryLabel')}</p>
        {isLoading ? (
          <div className="space-y-1.5">
            {[1, 2, 3].map(i => <div key={i} className="skeleton h-3.5 rounded" style={{ width: `${90 - i * 8}%` }} />)}
          </div>
        ) : (
          <div className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap min-h-[40px]">
            {displayedSummary}
            {summaryTyping && <span className="inline-block w-0.5 h-4 bg-violet-400 ml-0.5 animate-pulse" />}
            {!displayedSummary && !summaryTyping && (
              <span className="text-slate-600 italic text-xs">{t('copilot.waitPrompt')}</span>
            )}
          </div>
        )}
      </div>

      {/* Chat Thread */}
      {(messages.length > 0 || (isSending && streamedAnswer === '' && !isStreamTyping)) && (
        <div className="flex flex-col gap-3 p-4 max-h-72 overflow-y-auto border-b border-[#1e1e30]">
          <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">{t('copilot.chatLabel')}</p>
          {messages.map(msg => (
            <div key={msg.id} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              {msg.role === 'ai' && (
                <div className="w-6 h-6 rounded-full bg-violet-600/20 border border-violet-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Bot size={11} className="text-violet-400" />
                </div>
              )}
              <div className={`max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap ${
                msg.role === 'user'
                  ? 'bg-violet-600/20 border border-violet-500/25 text-violet-100'
                  : 'bg-[#1e1e30] border border-[#2a2a40] text-slate-300'
              }`}>
                {msg.text}
              </div>
              {msg.role === 'user' && (
                <div className="w-6 h-6 rounded-full bg-slate-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <User size={11} className="text-slate-400" />
                </div>
              )}
            </div>
          ))}
          {/* Streaming / thinking */}
          {(isSending) && (
            <div className="flex gap-2 justify-start">
              <div className="w-6 h-6 rounded-full bg-violet-600/20 border border-violet-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Bot size={11} className="text-violet-400" />
              </div>
              <div className="max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed bg-[#1e1e30] border border-[#2a2a40] text-slate-300 whitespace-pre-wrap">
                {streamedAnswer ? (
                  <>
                    {streamedAnswer}
                    {isStreamTyping && <span className="inline-block w-0.5 h-3.5 bg-violet-400 ml-0.5 animate-pulse" />}
                  </>
                ) : (
                  <span className="text-slate-500 flex items-center gap-1.5">
                    {t('copilot.thinking')}
                    <span className="inline-flex gap-0.5 ml-1">
                      {[0, 100, 200].map(d => <span key={d} className="w-1 h-1 rounded-full bg-slate-500 animate-bounce" style={{ animationDelay: `${d}ms` }} />)}
                    </span>
                  </span>
                )}
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>
      )}

      {/* Suggested Questions */}
      {!isLoading && displayedSummary && messages.length === 0 && !isSending && (
        <div className="px-4 pt-3 pb-2 border-b border-[#1e1e30]">
          <p className="text-[10px] text-slate-500 mb-2">{t('copilot.suggestedLabel')}</p>
          <div className="flex gap-1.5 flex-wrap">
            {suggestions.map((q: string, i: number) => (
              <button
                key={i}
                onClick={() => sendMessage(q)}
                className="text-[11px] px-2.5 py-1 rounded-full bg-violet-500/8 border border-violet-500/20 text-violet-400 hover:bg-violet-500/15 transition-colors"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      {!isLoading && displayedSummary && (
        <div className="p-3 flex gap-2 items-center">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isSending}
            placeholder={t('copilot.chatPlaceholder')}
            className="flex-1 bg-[#0f0f1a] border border-[#1e1e30] rounded-lg px-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-violet-500/50 transition-colors disabled:opacity-50"
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={!input.trim() || isSending}
            className="btn btn-primary text-xs px-3 py-2 flex-shrink-0 disabled:opacity-40"
          >
            {isSending ? t('copilot.sendingButton') : <><Send size={12} />{t('copilot.sendButton')}</>}
          </button>
        </div>
      )}
    </div>
  );
}
