import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  ScanSearch, ShieldCheck, Loader2, AlertCircle,
  Copy, Check, Terminal, LayoutDashboard, ChevronDown, ChevronUp,
  AlertTriangle, Shield
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import Sidebar from '../components/Sidebar';
import CodeEditorPanel from '../components/CodeEditorPanel';
import SecurityScoreCard from '../components/SecurityScoreCard';
import VulnerabilityList from '../components/VulnerabilityList';
import SecurityCopilotPanel from '../components/SecurityCopilotPanel';
import DefenseRecommendationPanel from '../components/DefenseRecommendationPanel';
import ScoreExplanationPanel from '../components/ScoreExplanationPanel';
import RiskHeatmap from '../components/RiskHeatmap';
import CausalPathGraph from '../components/CausalPathGraph';

import { useVultronAnalysis } from '../services/useVultronAnalysis';
import { getFixTemplate } from '../data/fixTemplates';

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

contract SafeBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "SafeBank: caller is not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "SafeBank: reentrant call blocked");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        require(msg.value > 0, "SafeBank: deposit amount must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "SafeBank: insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "SafeBank: transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }

    function getContractBalance() public view onlyOwner returns (uint256) {
        return address(this).balance;
    }
}`,
};

type ViewMode = 'insights' | 'remediation';

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#3b82f6',
  low: '#64748b',
  info: '#374151',
};

function countBySeverity(vulns: any[], sev: string) {
  return vulns.filter(v => v.severity === sev).length;
}

export default function MainDashboard() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [viewMode, setViewMode]     = useState<ViewMode>('insights');
  const [activeDemo, setActiveDemo] = useState<keyof typeof CONTRACTS | null>('vulnerable');
  const [pocCopied, setPocCopied]   = useState(false);
  const [editorOpen, setEditorOpen] = useState(true);
  const [analyzeComplete, setAnalyzeComplete] = useState(false);
  const [spinnerFrame, setSpinnerFrame] = useState(0);
  const [pocExpanded, setPocExpanded] = useState(false);
  const prevLoading = useRef(false);
  const SPINNER = ['/', '-', '\\', '|'];

  // Remediation tab state
  const [activeRemediation, setActiveRemediation] = useState<string | null>(null);
  const [activeSubTabs, setActiveSubTabs] = useState<Record<string, 'description' | 'fix' | 'reference'>>({});

  const {
    code, setCode, results, loading, error, progress, runAnalysis,
    selectedVulnerability, setSelectedVulnerability,
  } = useVultronAnalysis(CONTRACTS.vulnerable);

  useEffect(() => {
    if (prevLoading.current && !loading && results) {
      setAnalyzeComplete(true);
      const t = setTimeout(() => setAnalyzeComplete(false), 2000);
      return () => clearTimeout(t);
    }
    prevLoading.current = loading;
  }, [loading, results]);

  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => setSpinnerFrame(f => (f + 1) % 4), 150);
    return () => clearInterval(id);
  }, [loading]);

  // Default active remediation to first critical/high vulnerability
  useEffect(() => {
    if (results?.vulnerabilities?.length) {
      const first =
        results.vulnerabilities.find(v => v.severity === 'critical') ??
        results.vulnerabilities.find(v => v.severity === 'high') ??
        results.vulnerabilities[0];
      setActiveRemediation(first.id);
      setActiveSubTabs({});
    }
  }, [results]);

  const handleCausalNodeClick = useCallback((payload: { line?: number; lineNumber?: number; label: string }) => {
    setSelectedVulnerability(payload);
    if (payload.line || payload.lineNumber) {
      setEditorOpen(true);
    }
  }, [setSelectedVulnerability]);

  const handleAnalyze    = () => runAnalysis(code);
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

  const criticalCount = results ? countBySeverity(results.vulnerabilities, 'critical') : 0;
  const highCount     = results ? countBySeverity(results.vulnerabilities, 'high')     : 0;
  const medCount      = results ? countBySeverity(results.vulnerabilities, 'medium')   : 0;

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">

        {/* ── Top toolbar ────────────────────────────────────────── */}
        <header className="flex items-center justify-between px-4 py-2.5 border-b border-[#222222] bg-[#0d0d0d] flex-shrink-0 z-10">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold tracking-widest uppercase" style={{ color: '#00ff41', fontFamily: "'Courier New', monospace" }}>
                VULTRON_ <span style={{ color: '#555555' }}>v4</span>
              </span>
            </div>

            {/* View mode tabs */}
            <div className="flex border border-[#222222] ml-4">
              <button
                onClick={() => setViewMode('insights')}
                className={`flex items-center gap-1.5 px-3 py-1.5 border-r border-[#222222] transition-all ${
                  viewMode === 'insights' ? 'border-b-2' : 'hover:opacity-80'
                }`}
                style={viewMode === 'insights' ? {
                  background: 'rgba(0,255,65,0.08)', color: '#00ff41',
                  borderBottomColor: '#00ff41', fontFamily: "'Courier New', monospace",
                } : { fontFamily: "'Courier New', monospace" }}
              >
                <ShieldCheck size={11} />
                <div className="flex flex-col items-start">
                  <span className="text-[10px] font-bold tracking-widest uppercase">[ SECURITY INSIGHTS ]</span>
                  <span style={{ fontSize: 8, letterSpacing: '0.05em', color: viewMode === 'insights' ? 'rgba(0,255,65,0.55)' : '#444444', textTransform: 'none', fontWeight: 400 }}>
                    // vulnerabilities &amp; score
                  </span>
                </div>
              </button>
              <button
                onClick={() => setViewMode('remediation')}
                className={`flex items-center gap-1.5 px-3 py-1.5 transition-all ${
                  viewMode === 'remediation' ? 'border-b-2' : 'hover:opacity-80'
                }`}
                style={viewMode === 'remediation' ? {
                  background: 'rgba(59,130,246,0.08)', color: '#3b82f6',
                  borderBottomColor: '#3b82f6', fontFamily: "'Courier New', monospace",
                } : { fontFamily: "'Courier New', monospace" }}
              >
                <Shield size={11} />
                <div className="flex flex-col items-start">
                  <span className="text-[10px] font-bold tracking-widest uppercase">[ REMEDIATION ]</span>
                  <span style={{ fontSize: 8, letterSpacing: '0.05em', color: viewMode === 'remediation' ? 'rgba(59,130,246,0.55)' : '#444444', textTransform: 'none', fontWeight: 400 }}>
                    // fix recommendations &amp; secure code
                  </span>
                </div>
              </button>
            </div>
          </div>

          <div className="flex flex-col items-end gap-1">
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="btn btn-primary"
              style={analyzeComplete ? { borderColor: '#00ff41', background: 'rgba(0,255,65,0.12)' } : {}}
            >
              {loading
                ? <span style={{ fontFamily: 'monospace', letterSpacing: '0.05em' }}>{SPINNER[spinnerFrame]} ANALYZING...</span>
                : analyzeComplete
                ? <span style={{ color: '#00ff41' }}>ANALYSIS COMPLETE ✓</span>
                : <><ScanSearch size={12} /> {t('analyzer.analyzeButton')}</>}
            </button>
            {loading && progress && (
              <div className="font-mono text-xs mt-1 border border-[#222] p-2 min-w-[260px]" style={{ background: '#0a0a0a' }}>
                <div style={{ color: '#00ff41', fontSize: 9, letterSpacing: '0.08em', marginBottom: 4 }}>
                  {'> ANALYZING_CONTRACT...'}
                </div>
                <div style={{ color: '#888', fontSize: 9, marginBottom: 4 }}>
                  {`  [${String(progress.step).padStart(2, '0')}/${progress.total}] ${progress.message}`}
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1" style={{ background: '#111', height: 2 }}>
                    <div
                      style={{
                        height: 2,
                        background: '#00ff41',
                        width: `${progress.percent}%`,
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>
                  <span style={{ color: '#00ff41', fontSize: 9, minWidth: 28, textAlign: 'right' }}>
                    {progress.percent}%
                  </span>
                </div>
              </div>
            )}
          </div>
        </header>

        {/* ── Scrollable main area ────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto flex flex-col">

          {/* ── Code editor section ─────────────────────────────── */}
          <div className="border-b border-[#222222] flex-shrink-0">
            <div className="flex items-center justify-between px-3 py-1.5 bg-[#0d0d0d] border-b border-[#222222]">
              <div className="flex items-center gap-3">
                <span className="text-[9px] font-bold tracking-widest uppercase" style={{ color: '#555555', fontFamily: "'Courier New', monospace" }}>
                  // CONTRACT_EDITOR
                </span>
                <span className="text-[9px]" style={{ color: '#555555', fontFamily: "'Courier New', monospace" }}>Vultron_Sandbox.sol</span>
                <div className="flex gap-1">
                  {Object.keys(CONTRACTS).map(k => (
                    <button
                      key={k}
                      onClick={() => handleDemoSelect(k as any)}
                      className="text-[9px] px-2 py-0.5 border transition-all uppercase tracking-widest font-bold"
                      style={{
                        fontFamily: "'Courier New', monospace",
                        borderColor: activeDemo === k ? '#00ff41' : '#333333',
                        background: activeDemo === k ? 'rgba(0,255,65,0.08)' : 'transparent',
                        color: activeDemo === k ? '#00ff41' : '#444444',
                        borderRadius: 0,
                      }}
                    >
                      {k}
                    </button>
                  ))}
                </div>
              </div>
              <button
                onClick={() => setEditorOpen(p => !p)}
                className="flex items-center gap-1 text-[10px] transition-colors uppercase tracking-widest font-bold"
                style={{ color: '#777777', fontFamily: "'Courier New', monospace" }}
              >
                {editorOpen ? <><ChevronUp size={11} /> Collapse</> : <><ChevronDown size={11} /> Expand</>}
              </button>
            </div>

            {editorOpen && (
              <div className="h-[260px]">
                <CodeEditorPanel
                  value={code}
                  onChange={setCode}
                  selectedVulnerability={selectedVulnerability}
                />
              </div>
            )}
          </div>

          {/* ── Status bar ──────────────────────────────────────── */}
          <div className="flex items-center gap-4 px-4 py-1.5 bg-[#0d0d0d] border-b border-[#222222] flex-shrink-0"
            style={{ fontFamily: "'Courier New', monospace" }}>
            {loading ? (
              <>
                <span className="flex h-1.5 w-1.5 animate-pulse" style={{ background: '#00ff41' }} />
                <span className="text-[10px] uppercase tracking-widest" style={{ color: '#00ff41' }}>
                  &gt; ANALYZING_CONTRACT...
                </span>
              </>
            ) : results ? (
              <>
                <span className="flex h-1.5 w-1.5" style={{ background: '#00ff41' }} />
                <span className="text-[10px] uppercase tracking-widest" style={{ color: '#00ff41' }}>
                  ANALYSIS_COMPLETE
                </span>
                <span style={{ color: '#555555' }}>·</span>
                <span className="text-[10px]" style={{ color: '#555555' }}>
                  {results.vulnerabilities.length} findings
                </span>
                <span style={{ color: '#555555' }}>·</span>
                <span className="text-[10px]" style={{ color: '#777777' }}>
                  {new Date(results.analyzedAt).toLocaleTimeString(i18n.language)}
                </span>
                <span style={{ color: '#555555' }}>·</span>
                <span className="text-[10px]" style={{ color: '#555555' }}>
                  {results.contractName}
                </span>
              </>
            ) : (
              <>
                <span className="flex h-1.5 w-1.5" style={{ background: '#333333' }} />
                <span className="text-[10px] uppercase tracking-widest" style={{ color: '#777777' }}>
                  &gt; AWAITING_INPUT_<span className="cursor-blink">_</span>
                </span>
              </>
            )}
          </div>

          {/* ── Language mismatch banner ─────────────────────────── */}
          {results && results.analysisLanguage && results.analysisLanguage !== i18n.language && (
            <div className="flex items-center gap-2 px-4 py-2 flex-shrink-0"
              style={{ fontFamily: "'Courier New', monospace", background: 'rgba(255,170,0,0.05)', borderBottom: '1px solid rgba(255,170,0,0.3)' }}>
              <span style={{ color: '#ffaa00', fontSize: 10 }}>⚠</span>
              <span style={{ color: '#ffaa00', fontSize: 10, letterSpacing: '0.04em' }}>
                {i18n.language === 'zh'
                  ? '目前顯示的分析結果為英文版本，重新分析以取得繁體中文結果。'
                  : 'Current results were generated in Chinese. Re-analyze to get English output.'}
              </span>
            </div>
          )}

          {/* ── Error banner ─────────────────────────────────────── */}
          {error && (
            <div className="flex items-center gap-2.5 px-4 py-2.5 bg-[rgba(239,68,68,0.08)] border-b border-[rgba(239,68,68,0.3)] flex-shrink-0">
              <AlertCircle size={13} className="text-[#ef4444] flex-shrink-0" />
              <p className="text-[11px] text-[#ef4444]">{error}</p>
            </div>
          )}

          {/* ── Analysis results banner ─────────────────────────── */}
          {results && (
            <div className="flex items-center gap-3 px-4 py-1.5 border-b border-[#222222] flex-shrink-0"
              style={{ background: 'rgba(0,255,65,0.025)' }}>
              <span style={{ color: '#00ff41', fontSize: 10, fontFamily: "'Courier New', monospace", fontWeight: 700, letterSpacing: '0.1em' }}>
                &gt; ANALYSIS_RESULTS
              </span>
              <span style={{ color: '#222222', fontSize: 11, flex: 1 }}>
                ─────────────────────────────────────
              </span>
              <span style={{ color: '#555555', fontSize: 10, fontFamily: "'Courier New', monospace" }}>
                {results.vulnerabilities.length} findings &nbsp;·&nbsp; {results.contractName} &nbsp;·&nbsp; score {results.securityScore}
                {results.solidity_version && results.solidity_version !== 'unknown' && (
                  <> &nbsp;·&nbsp; <span style={{ color: '#00ff41' }}>// Solidity: {results.solidity_version}</span></>
                )}
              </span>
            </div>
          )}

          {/* ── No results placeholder ───────────────────────────── */}
          {!results && !loading && (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center p-8">
              <div className="w-12 h-12 border border-[#222222] flex items-center justify-center">
                <ScanSearch size={20} className="text-[#374151]" />
              </div>
              <p className="text-xs font-bold text-[#374151] uppercase tracking-widest">Ready for Inspection</p>
              <p className="text-[11px] text-[#374151] max-w-xs">
                Select a demo contract or paste your own Solidity code, then click ANALYZE CONTRACT
              </p>
            </div>
          )}

          {/* ── Security Insights View ───────────────────────────── */}
          {(results || loading) && viewMode === 'insights' && (
            <div className="flex flex-col">

              {/* KPI row */}
              {results && (
                <div className="grid grid-cols-5 border-b border-[#222222] flex-shrink-0">
                  <div className="border-r border-[#222222] p-4 flex flex-col gap-1">
                    <p className="section-label">Security Score</p>
                    <SecurityScoreCard score={results.securityScore} riskLevel={results.riskLevel} compact />
                  </div>
                  <div className="border-r border-[#222222] p-4">
                    <p className="section-label">&gt; CRITICAL</p>
                    <p className="kpi-number text-3xl mt-1" style={{ color: criticalCount > 0 ? '#ff4444' : '#333333' }}>
                      {criticalCount}
                    </p>
                    <p className="text-[9px] mt-1 uppercase tracking-widest font-bold" style={{ color: '#777777', fontFamily: "'Courier New', monospace" }}>Vulnerabilities</p>
                    <p className="text-[10px] mt-1 font-mono" style={{ color: '#555555' }}>資金可能被盜</p>
                  </div>
                  <div className="border-r border-[#222222] p-4">
                    <p className="section-label">&gt; HIGH</p>
                    <p className="kpi-number text-3xl mt-1" style={{ color: highCount > 0 ? '#ffaa00' : '#333333' }}>
                      {highCount}
                    </p>
                    <p className="text-[9px] mt-1 uppercase tracking-widest font-bold" style={{ color: '#777777', fontFamily: "'Courier New', monospace" }}>Vulnerabilities</p>
                    <p className="text-[10px] mt-1 font-mono" style={{ color: '#555555' }}>合約功能可能故障</p>
                  </div>
                  <div className="border-r border-[#222222] p-4">
                    <p className="section-label">&gt; MEDIUM</p>
                    <p className="kpi-number text-3xl mt-1" style={{ color: medCount > 0 ? '#00ff41' : '#333333' }}>
                      {medCount}
                    </p>
                    <p className="text-[9px] mt-1 uppercase tracking-widest font-bold" style={{ color: '#777777', fontFamily: "'Courier New', monospace" }}>Vulnerabilities</p>
                    <p className="text-[10px] mt-1 font-mono" style={{ color: '#555555' }}>邊界情況會出問題</p>
                  </div>
                  <div className="p-4">
                    <p className="section-label">&gt; LAST_SCAN</p>
                    <p className="kpi-number text-lg mt-1" style={{ color: '#888888' }}>
                      {new Date(results.analyzedAt).toLocaleTimeString(i18n.language, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </p>
                    <p className="text-[9px] mt-1" style={{ color: '#777777', fontFamily: "'Courier New', monospace" }}>
                      {new Date(results.analyzedAt).toLocaleDateString(i18n.language)}
                    </p>
                  </div>
                </div>
              )}

              {/* Main 40 / 60 split */}
              <div className="flex">
                {/* Left 40% — Vulnerability Matrix */}
                <div className="w-[40%] border-r border-[#222222] flex flex-col">
                  <div className="flex items-center justify-between px-4 py-2 bg-[#0d0d0d] border-b border-[#222222] flex-shrink-0">
                    <div className="flex items-center gap-2">
                      <AlertTriangle size={11} style={{ color: '#00ff41' }} />
                      <p className="section-label">Vulnerability Matrix</p>
                    </div>
                    {results && (
                      <span className="text-[9px] text-[#64748b] font-mono border border-[#222222] px-1.5 py-0.5">
                        {results.vulnerabilities.length} findings
                      </span>
                    )}
                  </div>
                  <div className="flex-1">
                    {loading ? (
                      <div className="p-4 space-y-2">
                        {[1, 2, 3, 4].map(i => <div key={i} className="skeleton h-10" />)}
                      </div>
                    ) : (
                      <VulnerabilityList
                        vulnerabilities={results?.vulnerabilities ?? []}
                        causalPaths={results?.causalPaths ?? []}
                        defenseRecommendations={results?.defenseRecommendations ?? []}
                      />
                    )}
                  </div>
                  {results && (
                    <div className="border-t border-[#222222] p-4 flex-shrink-0">
                      <p className="section-label mb-2">Score Explanation</p>
                      <ScoreExplanationPanel explanation={results.scoreExplanation} isLoading={loading} />
                    </div>
                  )}
                </div>

                {/* Right 60% — Causal Path Graph */}
                <div className="flex-1 overflow-y-auto p-4">
                  {loading && (
                    <div className="space-y-2">
                      {[1, 2, 3].map(i => <div key={i} className="skeleton h-12" />)}
                    </div>
                  )}
                  {results && (
                    <CausalPathGraph
                      paths={results.causalPaths}
                      criticalPathId={results.criticalPathId}
                      onNodeClick={handleCausalNodeClick}
                      consensus={results.consensus}
                    />
                  )}
                </div>
              </div>

              {/* PoC Script — collapsible, full width */}
              {results?.pocScript && (
                <div className="border-t border-[#222222] flex-shrink-0">
                  <div className="px-4 py-2 bg-[#0d0d0d]">
                    <button
                      onClick={() => setPocExpanded(v => !v)}
                      className="font-mono text-xs border border-[#333333] px-3 py-2 transition-colors"
                      style={{ color: pocExpanded ? '#ef4444' : '#888888', borderColor: pocExpanded ? 'rgba(239,68,68,0.5)' : '#333333' }}
                    >
                      {pocExpanded ? '▼' : '▶'} ADVANCED: VIEW EXPLOIT SCRIPT
                    </button>
                  </div>

                  {pocExpanded && (
                    <div>
                      <div className="flex items-center justify-between px-4 py-2 bg-[rgba(239,68,68,0.04)] border-y border-[rgba(239,68,68,0.2)]">
                        <div className="flex items-center gap-2">
                          <Terminal size={11} className="text-[#ef4444]" />
                          <p className="section-label text-[#ef4444]">PoC Hardhat Exploit Script</p>
                        </div>
                        <button onClick={handleCopyPoC} className="btn btn-outline text-[10px]">
                          {pocCopied
                            ? <><Check size={11} className="text-[#10b981]" /> Copied</>
                            : <><Copy size={11} /> Copy Script</>}
                        </button>
                      </div>
                      <div className="px-4 py-2 border-b border-[rgba(239,68,68,0.2)]" style={{ background: 'rgba(255,170,0,0.04)' }}>
                        <p className="font-mono text-[10px]" style={{ color: '#ffaa00' }}>
                          ⚠ ETHICAL USE ONLY — For authorized testing environments only. Unauthorized use against contracts is illegal.
                        </p>
                      </div>
                      <pre className="p-4 text-[11px] text-[#94a3b8] font-mono overflow-x-auto leading-relaxed max-h-[280px] bg-[#0d0d0d]">
                        {results.pocScript}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Secondary panels */}
              {results && (
                <div className="border-t border-[#222222] grid grid-cols-2 flex-shrink-0">
                  <div className="border-r border-[#222222] p-4">
                    <SecurityCopilotPanel
                      summary={results.summary}
                      isLoading={loading}
                      vulnerabilities={results.vulnerabilities}
                      score={results.securityScore}
                      selectedVulnerability={selectedVulnerability}
                    />
                  </div>
                  <div className="divide-y divide-[#1f2937]">
                    <div className="p-4">
                      <p className="section-label mb-3">Risk Distribution</p>
                      <RiskHeatmap vulnerabilities={results.vulnerabilities} />
                    </div>
                    <div className="p-4">
                      <p className="section-label mb-3">Remediation Strategies</p>
                      <DefenseRecommendationPanel
                        recommendations={results.defenseRecommendations}
                        isLoading={loading}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── REMEDIATION View ─────────────────────────────────── */}
          {(results || loading) && viewMode === 'remediation' && (
            <div className="flex flex-col animate-fade-in">

              {/* Header bar */}
              <div className="flex items-center gap-3 px-4 py-2 bg-[#0d0d0d] border-b border-[#222222] flex-shrink-0"
                style={{ fontFamily: "'Courier New', monospace" }}>
                <span style={{ color: '#3b82f6', fontSize: 10, fontWeight: 700, letterSpacing: '0.1em' }}>
                  &gt; REMEDIATION_STRATEGIES
                </span>
                {results && (
                  <>
                    <span style={{ color: '#333333' }}>─</span>
                    <span style={{ color: '#555555', fontSize: 10 }}>
                      {results.vulnerabilities.filter(v => v.severity !== 'info').length} actionable findings
                    </span>
                  </>
                )}
              </div>

              {/* ── Upper: vulnerability cards ── */}
              {loading ? (
                <div className="p-4 space-y-3 flex-shrink-0">
                  {[1, 2, 3].map(i => <div key={i} className="skeleton h-24" />)}
                </div>
              ) : (
                <div className="flex-shrink-0 divide-y divide-[#161616]">
                  {(results?.vulnerabilities ?? []).map((vuln, index) => {
                    const template = getFixTemplate(vuln.type);
                    const defense = results?.defenseRecommendations?.[
                      Math.min(index, (results.defenseRecommendations?.length ?? 1) - 1)
                    ];
                    const subTab = activeSubTabs[vuln.id] ?? 'description';
                    const isSelected = activeRemediation === vuln.id;
                    const sevColor = SEV_COLOR[vuln.severity] ?? '#374151';

                    return (
                      <div
                        key={vuln.id}
                        className="transition-all"
                        style={{
                          borderLeft: `2px solid ${isSelected ? sevColor : 'transparent'}`,
                          background: isSelected ? 'rgba(255,255,255,0.012)' : undefined,
                        }}
                      >
                        {/* Card header — click to select for diff panel */}
                        <div
                          className="flex items-center gap-2.5 px-4 py-2.5 cursor-pointer hover:bg-[rgba(255,255,255,0.02)] transition-colors"
                          onClick={() => setActiveRemediation(vuln.id)}
                        >
                          <span
                            className="text-[9px] font-bold tracking-widest flex-shrink-0"
                            style={{
                              color: sevColor,
                              background: `${sevColor}20`,
                              padding: '2px 6px',
                              fontFamily: 'monospace',
                            }}
                          >
                            {vuln.severity.toUpperCase()}
                          </span>
                          <span className="text-[11px] font-mono text-[#e2e8f0]">{vuln.type}</span>
                          <span className="text-[10px] text-[#555555] font-mono">· {vuln.function}()</span>
                          {vuln.lineNumber && (
                            <span className="text-[9px] text-[#374151] font-mono ml-auto flex-shrink-0">
                              L{vuln.lineNumber}
                            </span>
                          )}
                        </div>

                        {/* Sub-tab bar */}
                        <div className="flex px-4 border-b border-[#1a1a1a]">
                          {(['description', 'fix', 'reference'] as const).map(tab => (
                            <button
                              key={tab}
                              onClick={() => setActiveSubTabs(prev => ({ ...prev, [vuln.id]: tab }))}
                              className="text-[9px] font-bold tracking-widest uppercase px-2.5 py-1.5 border-b-2 transition-colors"
                              style={{
                                fontFamily: "'Courier New', monospace",
                                borderBottomColor: subTab === tab ? '#3b82f6' : 'transparent',
                                color: subTab === tab ? '#3b82f6' : '#555555',
                              }}
                            >
                              {tab}
                            </button>
                          ))}
                        </div>

                        {/* Sub-tab content */}
                        <div className="px-4 py-3">
                          {subTab === 'description' && (
                            <div className="font-mono text-[11px] leading-relaxed">
                              <p className="text-[#94a3b8]">
                                {vuln.description || defense?.issue || 'No description available.'}
                              </p>
                              {defense?.strategy && (
                                <p className="text-[#64748b] mt-2 border-t border-[#1a1a1a] pt-2">
                                  Strategy: {defense.strategy}
                                </p>
                              )}
                            </div>
                          )}

                          {subTab === 'fix' && (
                            <div className="grid grid-cols-2 gap-2">
                              <div>
                                <p className="text-[8px] font-bold tracking-widest mb-1.5 font-mono" style={{ color: '#ff4444' }}>
                                  ❌ VULNERABLE
                                </p>
                                <pre className="font-mono text-[9px] text-[#ff4444] bg-[#1a0a0a] border border-[rgba(255,68,68,0.25)] p-2 overflow-auto max-h-[130px] leading-relaxed whitespace-pre-wrap">
                                  {template?.vulnerable_pattern ?? defense?.codeExample ?? '// No pattern on record'}
                                </pre>
                              </div>
                              <div>
                                <p className="text-[8px] font-bold tracking-widest mb-1.5 font-mono" style={{ color: '#00ff41' }}>
                                  ✅ FIXED
                                </p>
                                <pre className="font-mono text-[9px] text-[#00ff41] bg-[#0a1a0a] border border-[rgba(0,255,65,0.25)] p-2 overflow-auto max-h-[130px] leading-relaxed whitespace-pre-wrap">
                                  {template?.fixed_pattern ?? '// Refer to the strategy above'}
                                </pre>
                              </div>
                            </div>
                          )}

                          {subTab === 'reference' && (
                            template?.oz_link ? (
                              <a
                                href={template.oz_link}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[11px] font-mono underline break-all"
                                style={{ color: '#3b82f6' }}
                              >
                                → {template.oz_link}
                              </a>
                            ) : (
                              <p className="text-[11px] text-[#555555] font-mono">
                                No reference available for this vulnerability type.
                              </p>
                            )
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* ── Lower: code diff for selected vulnerability ── */}
              {results && activeRemediation && (() => {
                const idx = results.vulnerabilities.findIndex(v => v.id === activeRemediation);
                const vuln = results.vulnerabilities[idx];
                if (!vuln) return null;
                const template = getFixTemplate(vuln.type);
                const defense = results.defenseRecommendations?.[
                  Math.min(idx, (results.defenseRecommendations?.length ?? 1) - 1)
                ];
                const sevColor = SEV_COLOR[vuln.severity] ?? '#374151';

                return (
                  <div className="border-t-2 border-[#222222] flex-shrink-0">
                    {/* Diff header */}
                    <div
                      className="flex items-center gap-2 px-4 py-2 bg-[#0d0d0d] border-b border-[#222222]"
                      style={{ fontFamily: "'Courier New', monospace" }}
                    >
                      <span style={{ color: '#3b82f6', fontSize: 10, fontWeight: 700, letterSpacing: '0.08em' }}>
                        &gt; CODE_DIFF
                      </span>
                      <span style={{ color: '#333333' }}>·</span>
                      <span
                        className="text-[9px] font-bold tracking-widest"
                        style={{ color: sevColor, background: `${sevColor}20`, padding: '1px 5px', fontFamily: 'monospace' }}
                      >
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span style={{ color: '#e2e8f0', fontSize: 10 }}>{vuln.type}</span>
                      <span style={{ color: '#555555', fontSize: 10 }}>· {vuln.function}()</span>
                    </div>

                    {/* Vulnerable vs Fixed columns */}
                    <div className="grid grid-cols-2 border-b border-[#222222]">
                      <div className="border-r border-[#222222]">
                        <div className="px-3 py-1.5 bg-[#140a0a] border-b border-[rgba(255,68,68,0.2)]">
                          <span className="text-[9px] font-bold text-[#ff4444] tracking-widest" style={{ fontFamily: 'monospace' }}>
                            ❌ VULNERABLE
                          </span>
                        </div>
                        <pre className="font-mono text-xs text-[#ff4444] bg-[#1a0a0a] p-3 overflow-auto max-h-[200px] leading-relaxed whitespace-pre-wrap">
                          {template?.vulnerable_pattern ?? defense?.codeExample ?? '// No vulnerable pattern on record'}
                        </pre>
                      </div>
                      <div>
                        <div className="px-3 py-1.5 bg-[#0a140a] border-b border-[rgba(0,255,65,0.2)]">
                          <span className="text-[9px] font-bold text-[#00ff41] tracking-widest" style={{ fontFamily: 'monospace' }}>
                            ✅ FIXED
                          </span>
                        </div>
                        <pre className="font-mono text-xs text-[#00ff41] bg-[#0a1a0a] p-3 overflow-auto max-h-[200px] leading-relaxed whitespace-pre-wrap">
                          {template?.fixed_pattern
                            ?? (defense?.strategy ? `// ${defense.strategy}` : '// Apply strategy above')}
                        </pre>
                      </div>
                    </div>

                    {/* Fix steps */}
                    <div className="p-4 bg-[#060606]" style={{ fontFamily: "'Courier New', monospace" }}>
                      <div style={{ color: '#3b82f6', fontSize: 10, letterSpacing: '0.08em', marginBottom: 10, fontWeight: 700 }}>
                        &gt; FIX_STEPS
                      </div>
                      {template ? (
                        <>
                          <div className="space-y-2 mb-4">
                            {template.steps.map((step, i) => (
                              <div key={i} className="flex items-start gap-2">
                                <span style={{ color: '#555555', fontSize: 10, minWidth: 32, flexShrink: 0 }}>
                                  [{String(i + 1).padStart(2, '0')}]
                                </span>
                                <span style={{ color: '#94a3b8', fontSize: 10, lineHeight: 1.7 }}>{step}</span>
                              </div>
                            ))}
                          </div>
                          <a
                            href={template.oz_link}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ color: '#3b82f6', fontSize: 10, textDecoration: 'underline' }}
                          >
                            → {template.oz_link}
                          </a>
                        </>
                      ) : defense?.strategy ? (
                        <p style={{ color: '#94a3b8', fontSize: 10, lineHeight: 1.7 }}>{defense.strategy}</p>
                      ) : (
                        <p style={{ color: '#555555', fontSize: 10 }}>No fix steps available.</p>
                      )}
                    </div>
                  </div>
                );
              })()}

            </div>
          )}

        </main>
      </div>
    </div>
  );
}
