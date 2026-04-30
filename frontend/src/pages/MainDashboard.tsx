import React, { useState, useCallback } from 'react';
import { 
  ScanSearch, Zap, ShieldCheck, Activity, Loader2, AlertCircle, 
  FileText, Copy, Check, Info, LayoutDashboard, Terminal
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import Sidebar from '../components/Sidebar';
import ErrorBoundary from '../components/ErrorBoundary';
import CodeEditorPanel from '../components/CodeEditorPanel';
import SecurityScoreCard from '../components/SecurityScoreCard';
import VulnerabilityList from '../components/VulnerabilityList';
import ExploitGraph from '../components/ExploitGraph';
import SecurityCopilotPanel from '../components/SecurityCopilotPanel';
import DefenseRecommendationPanel from '../components/DefenseRecommendationPanel';
import ScoreExplanationPanel from '../components/ScoreExplanationPanel';
import RiskHeatmap from '../components/RiskHeatmap';
import ExploitKnowledgePanel from '../components/ExploitKnowledgePanel';
import CausalPathGraph from '../components/CausalPathGraph';
import RiskIndicatorBadge from '../components/RiskIndicatorBadge';

import { useVultronAnalysis } from '../services/useVultronAnalysis';

const CONTRACTS = {
  vulnerable: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = tx.origin; // VULNERABILITY: tx.origin authentication
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update (Reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    function emergencyWithdraw() public {
        require(tx.origin == owner, "Not authorized"); // VULNERABILITY: tx.origin
        selfdestruct(payable(owner)); // VULNERABILITY: Unprotected selfdestruct
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}`,
  safe: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeBank is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;

    constructor() Ownable(msg.sender) {}

    function deposit() public payable {
        require(msg.value > 0, "Must deposit non-zero amount");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}`,
};

type ViewMode = 'insights' | 'simulation';

export default function MainDashboard() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [viewMode, setViewMode] = useState<ViewMode>('insights');
  const [activeDemo, setActiveDemo] = useState<keyof typeof CONTRACTS | null>('vulnerable');
  const [pocCopied, setPocCopied] = useState(false);

  const {
    code, setCode, results, loading, error, runAnalysis,
    currentStep, setCurrentStep, isSimulating, simDone, 
    simulateAttack, resetSimulation,
    selectedVulnerability, setSelectedVulnerability
  } = useVultronAnalysis(CONTRACTS.vulnerable);

  const handleAnalyze = () => runAnalysis(code);

  const handleDemoSelect = (key: keyof typeof CONTRACTS) => {
    setActiveDemo(key);
    setCode(CONTRACTS[key]);
    runAnalysis(CONTRACTS[key]);
  };

  const handleCopyPoC = () => {
    if (results?.pocScript) {
      navigator.clipboard.writeText(results.pocScript);
      setPocCopied(true);
      setTimeout(() => setPocCopied(false), 2000);
    }
  };

  return (
    <div className="flex h-screen bg-[#080810] overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        
        {/* Header/Toolbar */}
        <header className="flex items-center justify-between px-6 py-4 border-b border-[#1e1e30] bg-[#0a0a14] z-10">
          <div className="flex items-center gap-4">
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <LayoutDashboard size={20} className="text-violet-500" />
                Vultron <span className="text-violet-500">v4</span>
              </h1>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="flex h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" />
                <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">Engine Active: Groq Llama-3.1</p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* View Switcher */}
            <div className="flex p-1 bg-[#161625] rounded-xl border border-[#2a2a40]">
              <button 
                onClick={() => setViewMode('insights')}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                  viewMode === 'insights' ? 'bg-violet-600 text-white shadow-lg shadow-violet-500/20' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <ShieldCheck size={14} /> Security Insights
              </button>
              <button 
                onClick={() => setViewMode('simulation')}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                  viewMode === 'simulation' ? 'bg-red-600 text-white shadow-lg shadow-red-500/20' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <Activity size={14} /> Attack Simulation
              </button>
            </div>

            <div className="h-8 w-px bg-[#1e1e30] mx-1" />

            <button onClick={handleAnalyze} disabled={loading} className={`btn ${loading ? 'opacity-70' : 'btn-primary'}`}>
              {loading ? (
                <><Loader2 size={16} className="animate-spin" /> {t('analyzer.analyzing')}</>
              ) : (
                <><ScanSearch size={16} /> {t('analyzer.analyzeButton')}</>
              )}
            </button>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto">
          {/* Top Section: Editor + Score Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-0 border-b border-[#1e1e30]">
            {/* Left: Editor (8 cols) */}
            <div className="lg:col-span-8 border-r border-[#1e1e30]">
              <div className="flex items-center justify-between px-4 py-2 bg-[#0f0f1a] border-b border-[#1e1e30]">
                <div className="flex items-center gap-3">
                   <div className="flex gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/30" />
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/30" />
                    <span className="w-2.5 h-2.5 rounded-full bg-green-500/30" />
                  </div>
                  <span className="text-[11px] text-slate-500 font-mono uppercase tracking-wider italic">Vultron_Sandbox.sol</span>
                </div>
                <div className="flex gap-2">
                  {Object.keys(CONTRACTS).map(k => (
                    <button 
                      key={k}
                      onClick={() => handleDemoSelect(k as any)}
                      className={`text-[10px] px-2 py-0.5 rounded border transition-all ${
                        activeDemo === k ? 'border-violet-500/50 bg-violet-500/10 text-violet-400' : 'border-[#1e1e30] text-slate-600 hover:text-slate-400'
                      }`}
                    >
                      {k.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
              <div className="h-[450px]">
                <CodeEditorPanel 
                  value={code} 
                  onChange={setCode} 
                  selectedVulnerability={selectedVulnerability}
                />
              </div>
            </div>

            {/* Right: Score Summary (4 cols) */}
            <div className="lg:col-span-4 bg-[#080810] flex flex-col p-6 overflow-y-auto">
               <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-6">Security Posture</p>
               {results ? (
                 <div className="space-y-6">
                   <SecurityScoreCard score={results.securityScore} riskLevel={results.riskLevel} />
                   <div className="p-4 rounded-2xl bg-violet-500/5 border border-violet-500/10">
                     <p className="text-[10px] font-bold text-violet-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                       <Info size={12} /> Analysis Summary
                     </p>
                     <ScoreExplanationPanel explanation={results.scoreExplanation} isLoading={loading} />
                   </div>
                   {results.vulnerabilities.length > 0 && (
                     <VulnerabilityList 
                       vulnerabilities={results.vulnerabilities.slice(0, 3)} 
                       compact 
                     />
                   )}
                 </div>
               ) : loading ? (
                 <div className="space-y-4">
                   <div className="h-48 rounded-3xl bg-white/5 animate-pulse" />
                   <div className="h-24 rounded-2xl bg-white/5 animate-pulse" />
                 </div>
               ) : (
                 <div className="flex-1 flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#1e1e30] rounded-3xl">
                   <div className="w-12 h-12 rounded-2xl bg-[#161625] flex items-center justify-center mb-4">
                     <ScanSearch className="text-slate-700" size={24} />
                   </div>
                   <h3 className="text-sm font-bold text-slate-400">No Analysis Data</h3>
                   <p className="text-xs text-slate-600 mt-2">Upload or paste contract code and click 'Process Contract' to begin</p>
                 </div>
               )}
            </div>
          </div>

          {/* Dynamic Bottom Section based on ViewMode */}
          <div className="p-6 max-w-[1600px] mx-auto">
            {error && (
              <div className="mb-6 flex items-center gap-3 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                <AlertCircle size={18} /> {error}
              </div>
            )}

            {!results && !loading ? (
              <div className="py-20 text-center">
                <h2 className="text-xl font-bold text-slate-700">Ready for Security Inspection</h2>
                <p className="text-sm text-slate-600 mt-2">Vultron AI is standing by to perform deep causal analysis.</p>
              </div>
            ) : viewMode === 'insights' ? (
              /* Security Insights View */
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 animate-fade-in">
                <div className="space-y-6">
                  <div className="card p-6">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Vulnerability Matrix</p>
                    <VulnerabilityList vulnerabilities={results?.vulnerabilities ?? []} />
                  </div>
                  <div className="card p-6">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Causal Attack Vectors</p>
                    <CausalPathGraph 
                      paths={results?.causalPaths ?? []} 
                      criticalPathId={results?.criticalPathId ?? null}
                      onNodeClick={setSelectedVulnerability}
                    />
                  </div>
                </div>
                <div className="space-y-6">
                  <div className="card p-6">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">AI Security Copilot</p>
                    <SecurityCopilotPanel
                      summary={results?.summary ?? ''}
                      isLoading={loading}
                      vulnerabilities={results?.vulnerabilities ?? []}
                      score={results?.securityScore ?? 100}
                      selectedVulnerability={selectedVulnerability}
                    />
                  </div>
                  <div className="card p-6">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Risk Distribution</p>
                    <RiskHeatmap vulnerabilities={results?.vulnerabilities ?? []} />
                  </div>
                  <div className="card p-6">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Remediation Strategies</p>
                    <DefenseRecommendationPanel recommendations={results?.defenseRecommendations ?? []} isLoading={loading} />
                  </div>
                  {results?.pocScript && (
                    <div className="card p-6 border-red-500/20 shadow-lg shadow-red-500/5">
                      <div className="flex items-center justify-between mb-4">
                        <div>
                          <p className="text-[10px] font-bold text-red-400 uppercase tracking-widest flex items-center gap-2">
                            <Terminal size={14} /> PoC Hardhat Exploit Script
                          </p>
                          <p className="text-[10px] text-slate-600 mt-1 uppercase tracking-tighter italic">Precision Attack Proof-of-Concept · Ethical Use Only</p>
                        </div>
                        <button 
                          onClick={handleCopyPoC}
                          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#161625] border border-[#2a2a40] text-slate-400 text-xs hover:text-white hover:bg-[#1e1e30] transition-all"
                        >
                          {pocCopied ? <><Check size={14} className="text-green-500" /> Copied</> : <><Copy size={14} /> Copy Script</>}
                        </button>
                      </div>
                      <pre className="p-5 rounded-2xl bg-[#05050a] border border-[#1e1e30] text-[11px] text-slate-300 font-mono overflow-x-auto leading-relaxed max-h-[400px]">
                        {results.pocScript}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              /* Attack Simulation View */
              <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 animate-fade-in">
                {/* Left: Simulation Flow (5 cols) */}
                <div className="xl:col-span-5 space-y-6">
                  <div className="card p-6">
                    <div className="flex items-center justify-between mb-6">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Exploit Narrative</p>
                      <div className="flex gap-2">
                         {results?.attackStrategy && !isSimulating && !simDone && (
                           <button onClick={simulateAttack} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-600/10 border border-red-500/30 text-red-400 text-[10px] font-bold uppercase tracking-wider hover:bg-red-600/20 transition-all">
                             <Activity size={12} /> Run Simulation
                           </button>
                         )}
                         {(isSimulating || simDone) && (
                           <button onClick={resetSimulation} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#161625] border border-[#2a2a40] text-slate-400 text-[10px] font-bold uppercase tracking-wider hover:text-white transition-all">
                             Reset
                           </button>
                         )}
                      </div>
                    </div>

                    {results?.attackStrategy ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between px-4 py-2 bg-red-500/5 border border-red-500/10 rounded-xl mb-4">
                           <span className="text-xs font-bold text-red-400">{results.attackStrategy.exploitType}</span>
                           <RiskIndicatorBadge severity={
                             results.attackStrategy.riskLevel.toLowerCase() === 'safe' ? 'safe' :
                             results.attackStrategy.riskLevel.toLowerCase() === 'critical risk' ? 'critical' :
                             results.attackStrategy.riskLevel.toLowerCase() === 'high risk' ? 'high' :
                             results.attackStrategy.riskLevel.toLowerCase() === 'medium risk' ? 'medium' :
                             results.attackStrategy.riskLevel.toLowerCase() === 'low risk' ? 'low' :
                             results.attackStrategy.riskLevel.toLowerCase() as any
                           } size="sm" />
                        </div>
                        
                        <div className="flex flex-col gap-2">
                          {results.attackStrategy.steps.map((step, i) => {
                            const isActive = i === currentStep;
                            const isPast = i < currentStep || simDone;
                            const isShown = currentStep < 0 || i <= currentStep;
                            
                            return (
                              <div 
                                key={i}
                                className={`flex items-start gap-4 p-4 rounded-2xl border transition-all duration-500 ${
                                  !isShown ? 'opacity-0 translate-y-4' :
                                  isActive ? 'bg-red-500/10 border-red-500/40 shadow-lg shadow-red-500/10' :
                                  isPast ? 'bg-[#0f0f1a] border-[#1e1e30] opacity-60' :
                                  'bg-[#0a0a14] border-[#1e1e30]'
                                }`}
                              >
                                <span className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                                  isActive ? 'bg-red-500 text-white' : 'bg-[#1e1e30] text-slate-500'
                                }`}>
                                  {isPast && !isActive ? '✓' : i + 1}
                                </span>
                                <p className={`text-xs leading-relaxed ${isActive ? 'text-white font-medium' : 'text-slate-400'}`}>{step}</p>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ) : (
                       <div className="p-10 text-center border border-dashed border-[#1e1e30] rounded-3xl">
                         <p className="text-xs text-slate-600">No attack strategy generated for this contract.</p>
                       </div>
                    )}
                  </div>
                </div>

                {/* Right: Graph & PoC (7 cols) */}
                <div className="xl:col-span-7 space-y-6">
                  <div className="card p-6 h-[500px]">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Dynamic Exploit Graph</p>
                    <ExploitGraph 
                      steps={results?.attackStrategy?.steps || []} 
                      currentStep={currentStep}
                      setCurrentStep={setCurrentStep}
                      isPlaying={isSimulating}
                      setIsPlaying={() => {}} // Hooked to simulation state
                    />
                  </div>

                  {results?.pocScript && (
                    <div className="card p-6 border-red-500/20 shadow-lg shadow-red-500/5">
                      <div className="flex items-center justify-between mb-4">
                        <div>
                          <p className="text-[10px] font-bold text-red-400 uppercase tracking-widest flex items-center gap-2">
                            <Terminal size={14} /> PoC Hardhat Exploit Script
                          </p>
                          <p className="text-[10px] text-slate-600 mt-1 uppercase tracking-tighter italic">Precision Attack Proof-of-Concept · Ethical Use Only</p>
                        </div>
                        <button 
                          onClick={handleCopyPoC}
                          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#161625] border border-[#2a2a40] text-slate-400 text-xs hover:text-white hover:bg-[#1e1e30] transition-all"
                        >
                          {pocCopied ? <><Check size={14} className="text-green-500" /> Copied</> : <><Copy size={14} /> Copy Script</>}
                        </button>
                      </div>
                      <pre className="p-5 rounded-2xl bg-[#05050a] border border-[#1e1e30] text-[11px] text-slate-300 font-mono overflow-x-auto leading-relaxed max-h-[400px]">
                        {results.pocScript}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
