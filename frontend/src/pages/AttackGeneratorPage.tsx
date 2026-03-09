import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Zap, Play, RotateCcw, AlertTriangle, ScanSearch, Loader2, Activity } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import Sidebar from '../components/Sidebar';
import CodeEditorPanel from '../components/CodeEditorPanel';
import ExploitGraph from '../components/ExploitGraph';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';
import { analyzeContract, generateAttack } from '../services/api';
import { AttackStrategy } from '../types';

const EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = tx.origin;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function emergencyWithdraw() public {
        require(tx.origin == owner, "Not authorized");
        selfdestruct(payable(owner));
    }
}`;

export default function AttackGeneratorPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [code, setCode] = useState(EXAMPLE);
  const [strategy, setStrategy] = useState<AttackStrategy | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState(-1);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simDone, setSimDone] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const generate = async () => {
    if (!code.trim() || code.trim().length < 10) { setError('Contract code too short.'); return; }
    setLoading(true);
    setError(null);
    setStrategy(null);
    setCurrentStep(-1);
    setSimDone(false);
    timers.current.forEach(clearTimeout);
    timers.current = [];
    try {
      const analysis = await analyzeContract(code);
      const atk = await generateAttack(analysis.vulnerabilities);
      setStrategy(atk);
    } catch {
      setError(t('analyzer.errorMessage'));
    } finally {
      setLoading(false);
    }
  };

  const simulate = () => {
    if (!strategy || isSimulating) return;
    setCurrentStep(-1);
    setSimDone(false);
    setIsSimulating(true);
    timers.current.forEach(clearTimeout);
    timers.current = [];

    strategy.steps.forEach((_, i) => {
      const t1 = setTimeout(() => {
        setCurrentStep(i);
        if (i === strategy.steps.length - 1) {
          const t2 = setTimeout(() => {
            setIsSimulating(false);
            setSimDone(true);
          }, 900);
          timers.current.push(t2);
        }
      }, i * 750);
      timers.current.push(t1);
    });
  };

  const reset = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setStrategy(null);
    setCurrentStep(-1);
    setIsSimulating(false);
    setSimDone(false);
    setError(null);
  };

  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);

  const progress = strategy
    ? currentStep < 0 ? 0 : Math.round(((currentStep + 1) / strategy.steps.length) * 100)
    : 0;

  const isFinalStep = (i: number) => strategy ? i === strategy.steps.length - 1 : false;
  const isFirstStep = (i: number) => i === 0;

  return (
    <div className="flex h-screen bg-[#080810] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Zap size={18} className="text-orange-400" /> {t('attackGenerator.title')}
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">{t('attackGenerator.subtitle')}</p>
          </div>
          <div className="flex items-center gap-2">
            {(strategy || currentStep >= 0) && (
              <button onClick={reset} className="btn btn-outline text-xs">
                <RotateCcw size={12} /> {t('attackGenerator.resetButton')}
              </button>
            )}
            {strategy && !isSimulating && !simDone && (
              <button onClick={simulate} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-red-600/15 border border-red-500/30 text-red-400 hover:bg-red-600/25 transition-all text-xs font-semibold">
                <Activity size={13} /> {t('attackGenerator.simulateButton')}
              </button>
            )}
            {isSimulating && (
              <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-red-600/10 border border-red-500/20 text-red-400 text-xs font-semibold">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                {t('attackGenerator.simulating')}
              </div>
            )}
            <button onClick={generate} disabled={loading} className="btn btn-primary text-sm">
              {loading
                ? <><Loader2 size={14} className="animate-spin" />{t('attackGenerator.generating')}</>
                : <><Play size={14} />{t('attackGenerator.generateButton')}</>
              }
            </button>
          </div>
        </div>

        {/* Editor */}
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-[#1e1e30] bg-[#0f0f1a]">
            <div className="flex gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
              <span className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
            </div>
            <span className="text-xs text-slate-500 font-mono">{t('attackGenerator.targetContract')}</span>
          </div>
          <CodeEditorPanel value={code} onChange={setCode} height="220px" />
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/8 border border-red-500/20 rounded-lg px-4 py-3">
            <AlertTriangle size={13} /> {error}
          </div>
        )}

        {/* Info banner */}
        {strategy && (
          <div className="p-3 rounded-xl bg-orange-500/5 border border-orange-500/20 flex items-start gap-2">
            <AlertTriangle size={14} className="text-orange-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-xs font-semibold text-orange-300">{t('attackGenerator.infoTitle')}</p>
              <p className="text-xs text-slate-400 mt-0.5">{t('attackGenerator.infoDesc')}</p>
            </div>
          </div>
        )}

        {strategy && (
          <div className="grid grid-cols-2 gap-5 animate-fade-in">
            {/* Steps + Progress */}
            <div className="card p-5 flex flex-col gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-white">{strategy.exploitType}</span>
                <RiskIndicatorBadge severity={
                  strategy.riskLevel.toLowerCase() === 'critical' ? 'critical' :
                  strategy.riskLevel.toLowerCase() === 'high' ? 'high' :
                  strategy.riskLevel.toLowerCase() === 'medium' ? 'medium' : 'low'
                } size="sm" />
              </div>

              {/* Progress bar */}
              {(isSimulating || simDone || currentStep >= 0) && (
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider">{t('attackGenerator.progressLabel')}</span>
                    <span className="text-[10px] text-slate-400 font-mono">{progress}%</span>
                  </div>
                  <div className="h-1.5 bg-[#1e1e30] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${progress}%`,
                        background: progress === 100
                          ? 'linear-gradient(90deg, #ef4444, #dc2626)'
                          : 'linear-gradient(90deg, #7c3aed, #a78bfa)',
                        boxShadow: progress === 100 ? '0 0 8px rgba(239,68,68,0.6)' : '0 0 8px rgba(124,58,237,0.5)',
                      }}
                    />
                  </div>
                </div>
              )}

              <div className="flex flex-col gap-2">
                {strategy.steps.map((step, i) => {
                  const isActive = i === currentStep;
                  const isPast = i < currentStep || simDone;
                  const isFinal = isFinalStep(i);
                  const isFirst = isFirstStep(i);
                  const shown = currentStep < 0 || i <= currentStep;

                  return (
                    <div
                      key={i}
                      className={`flex items-start gap-2.5 rounded-xl p-3 border transition-all duration-400 ${
                        !shown ? 'opacity-0 scale-95' :
                        isFinal && (isActive || simDone)
                          ? 'bg-red-500/15 border-red-500/50 shadow-[0_0_16px_rgba(239,68,68,0.2)]'
                          : isActive
                          ? 'bg-violet-500/15 border-violet-500/40 shadow-[0_0_12px_rgba(124,58,237,0.2)]'
                          : isPast
                          ? 'bg-[#1a1a28] border-[#2a2a40] opacity-70'
                          : 'bg-[#0f0f1a] border-[#1e1e30]'
                      }`}
                      style={{
                        animation: isFinal && simDone ? 'none' : undefined,
                        transition: 'all 0.4s ease',
                      }}
                    >
                      <span className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        isFinal && (isActive || simDone) ? 'bg-red-500 text-white' :
                        isFirst && isActive ? 'bg-orange-500 text-white' :
                        isActive ? 'bg-violet-500 text-white' :
                        isPast ? 'bg-green-500/20 text-green-400' :
                        'bg-[#1e1e30] text-slate-500'
                      }`}>
                        {isPast && !isActive ? '✓' : isFinal ? '💀' : isFirst ? '⚡' : i + 1}
                      </span>
                      <p className={`text-xs leading-relaxed pt-0.5 ${
                        isFinal && (isActive || simDone) ? 'text-red-300' :
                        isActive ? 'text-white' :
                        isPast ? 'text-slate-400' :
                        'text-slate-600'
                      }`}>
                        {step}
                      </p>
                      {isActive && isSimulating && (
                        <span className="ml-auto flex-shrink-0 w-2 h-2 rounded-full bg-violet-400 animate-ping" />
                      )}
                    </div>
                  );
                })}
              </div>

              {simDone && (
                <div className="pt-3 border-t border-[#1e1e30] text-center">
                  <p className="text-xs font-semibold text-white mb-1">{t('attackGenerator.attackComplete')}</p>
                  <p className="text-xs text-slate-400 mb-3">{t('attackGenerator.attackCompleteDesc')}</p>
                  <button onClick={() => navigate('/analyzer')} className="btn btn-primary text-xs">
                    <ScanSearch size={12} /> {t('attackGenerator.toAnalyzer')}
                  </button>
                </div>
              )}

              {!isSimulating && !simDone && currentStep < 0 && (
                <p className="text-xs text-slate-500 text-center pt-1">
                  Click <span className="text-red-400 font-semibold">"{t('attackGenerator.simulateButton')}"</span> to animate
                </p>
              )}
            </div>

            {/* Exploit Graph */}
            <div className="card p-5">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">{t('attackGenerator.exploitGraph')}</p>
              <ExploitGraph steps={strategy.steps} />
            </div>
          </div>
        )}

        {!strategy && !loading && (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Zap size={32} className="text-slate-700" />
            <p className="text-sm text-slate-500">{t('attackGenerator.noStrategy')}</p>
          </div>
        )}
      </main>
    </div>
  );
}
