import React, { useState, useCallback } from 'react';
import { Loader2, ScanSearch, AlertCircle, Monitor, ChevronDown } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import Sidebar from '../components/Sidebar';
import CodeEditorPanel from '../components/CodeEditorPanel';
import SecurityScoreCard from '../components/SecurityScoreCard';
import VulnerabilityList from '../components/VulnerabilityList';
import ExploitGraph from '../components/ExploitGraph';
import SecurityCopilotPanel from '../components/SecurityCopilotPanel';
import DefenseRecommendationPanel from '../components/DefenseRecommendationPanel';
import ScoreExplanationPanel from '../components/ScoreExplanationPanel';
import RiskHeatmap from '../components/RiskHeatmap';
import ExploitKnowledgePanel from '../components/ExploitKnowledgePanel';
import { analyzeContract } from '../services/api';
import { FullAnalysisResult } from '../types';

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

// SECURE: Safe bank implementation following best practices
contract SafeBank is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() Ownable(msg.sender) {}

    function deposit() public payable {
        require(msg.value > 0, "Must deposit non-zero amount");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // SECURE: CEI pattern + ReentrancyGuard
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // Effects before Interactions
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}`,

  token: `// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

// WARNING: Solidity 0.6 - no built-in overflow protection
contract TokenContract {
    string public name = "VultronToken";
    string public symbol = "VLT";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 _initialSupply) public {
        owner = msg.sender;
        totalSupply = _initialSupply * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value, "Insufficient balance");
        balances[msg.sender] -= _value;
        balances[_to] += _value; // potential overflow without SafeMath
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function mint(uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        totalSupply += _amount; // potential overflow
        balances[owner] += _amount;
    }

    function burn(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient");
        balances[msg.sender] -= _amount;
        totalSupply -= _amount; // potential underflow
    }
}`,
};

export default function AnalyzerPage() {
  const { t } = useTranslation();
  const [code, setCode] = useState(CONTRACTS.vulnerable);
  const [results, setResults] = useState<FullAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [activeDemo, setActiveDemo] = useState<keyof typeof CONTRACTS | null>('vulnerable');

  const runAnalysis = useCallback(async (contractCode: string) => {
    if (!contractCode.trim() || contractCode.trim().length < 10) {
      setError(t('analyzer.errorMessage'));
      return;
    }
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const result = await analyzeContract(contractCode);
      setResults(result);
    } catch {
      setError(t('analyzer.errorMessage'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  const handleAnalyze = () => runAnalysis(code);

  const handleDemoSelect = (key: keyof typeof CONTRACTS) => {
    setActiveDemo(key);
    setCode(CONTRACTS[key]);
    runAnalysis(CONTRACTS[key]);
  };

  const demoKeys: (keyof typeof CONTRACTS)[] = ['vulnerable', 'safe', 'token'];

  return (
    <div className="flex h-screen bg-[#080810] overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e1e30] bg-[#080810] flex-shrink-0">
          <div>
            <h1 className="text-sm font-bold text-white">{t('analyzer.title')}</h1>
            <p className="text-xs text-slate-600">{t('analyzer.subtitle')}</p>
          </div>
          <div className="flex items-center gap-2">
            {/* Demo Mode Toggle */}
            <button
              onClick={() => setDemoMode(v => !v)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                demoMode
                  ? 'bg-violet-600/20 border-violet-500/40 text-violet-300'
                  : 'bg-[#1e1e30] border-[#2a2a40] text-slate-400 hover:text-white'
              }`}
            >
              <Monitor size={12} />
              {t('analyzer.demoMode')}
              <ChevronDown size={11} className={`transition-transform ${demoMode ? 'rotate-180' : ''}`} />
            </button>

            {error && (
              <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-500/8 border border-red-500/20 rounded-lg px-3 py-1.5 max-w-xs">
                <AlertCircle size={12} />
                <span className="truncate">{error}</span>
              </div>
            )}
            <button onClick={handleAnalyze} disabled={loading} className="btn btn-primary">
              {loading
                ? <><Loader2 size={14} className="animate-spin" />{t('analyzer.analyzing')}</>
                : <><ScanSearch size={14} />{t('analyzer.analyzeButton')}</>
              }
            </button>
          </div>
        </div>

        {/* Demo Mode Bar */}
        {demoMode && (
          <div className="flex items-center gap-2 px-5 py-2.5 bg-violet-600/5 border-b border-violet-500/20 flex-shrink-0">
            <span className="text-xs text-violet-400 font-semibold">{t('analyzer.demoLabel')}</span>
            {demoKeys.map(key => (
              <button
                key={key}
                onClick={() => handleDemoSelect(key)}
                disabled={loading}
                className={`text-xs px-3 py-1.5 rounded-lg font-medium border transition-all duration-150 ${
                  activeDemo === key
                    ? 'bg-violet-600 text-white border-violet-500'
                    : 'bg-[#1e1e30] text-slate-400 border-[#2a2a40] hover:text-white hover:bg-[#2a2a40]'
                }`}
              >
                {t(`analyzer.demoContracts.${key}`)}
              </button>
            ))}
          </div>
        )}

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto">
          {/* Editor */}
          <div className="border-b border-[#1e1e30]">
            <div className="flex items-center gap-2 px-4 py-2 bg-[#0f0f1a] border-b border-[#1e1e30]">
              <div className="flex gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
                <span className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
              </div>
              <span className="text-xs text-slate-500 font-mono">{t('analyzer.editorFile')}</span>
              {results && (
                <span className="ml-auto text-xs font-bold text-violet-400 bg-violet-500/10 border border-violet-500/20 px-2 py-0.5 rounded-full">
                  {t('analyzer.resultsBadge')}: {results.securityScore}/100 · {results.riskLevel}
                </span>
              )}
            </div>
            <div style={{ height: 300 }}>
              <CodeEditorPanel value={code} onChange={setCode} height="300px" />
            </div>
          </div>

          {/* Results */}
          {(results || loading) && (
            <div className="p-5 flex flex-col gap-5">
              {/* Row 1: Score + Explanation | Vulnerabilities + Heatmap */}
              <div className="grid grid-cols-2 gap-5">
                <div className="card p-5 flex flex-col gap-4">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{t('analyzer.scoreSection')}</p>
                  <div className="flex justify-center">
                    {loading ? (
                      <div className="skeleton w-32 h-32 rounded-full" />
                    ) : results && (
                      <SecurityScoreCard score={results.securityScore} riskLevel={results.riskLevel} />
                    )}
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">{t('analyzer.scoreExplanation')}</p>
                    <ScoreExplanationPanel explanation={results?.scoreExplanation ?? ''} isLoading={loading} />
                  </div>
                </div>

                <div className="card p-5 flex flex-col gap-4">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    {t('analyzer.vulnerabilities')} {results && `(${results.vulnerabilities.length})`}
                  </p>
                  {loading ? (
                    <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="skeleton h-14 rounded-xl" />)}</div>
                  ) : results && <VulnerabilityList vulnerabilities={results.vulnerabilities} />}

                  {(results || loading) && (
                    <>
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mt-2">{t('analyzer.riskHeatmap')}</p>
                      {loading ? (
                        <div className="skeleton h-24 rounded-xl" />
                      ) : results && <RiskHeatmap vulnerabilities={results.vulnerabilities} />}
                    </>
                  )}
                </div>
              </div>

              {/* Row 2: Exploit Graph | Defense */}
              <div className="grid grid-cols-2 gap-5">
                <div className="card p-5">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">{t('analyzer.exploitGraph')}</p>
                  {loading ? <div className="skeleton h-64 rounded-xl" /> : results && <ExploitGraph steps={results.attackStrategy.steps} />}
                </div>
                <div className="card p-5">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">{t('analyzer.defenseRec')}</p>
                  <DefenseRecommendationPanel recommendations={results?.defenseRecommendations ?? []} isLoading={loading} />
                </div>
              </div>

              {/* Row 3: Knowledge Base */}
              {results && results.vulnerabilities.length > 0 && (
                <div className="card p-5">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">{t('analyzer.knowledgeBase')}</p>
                  <ExploitKnowledgePanel vulnerabilities={results.vulnerabilities} />
                </div>
              )}

              {/* Row 4: Copilot */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">{t('analyzer.aiCopilot')}</p>
                <SecurityCopilotPanel
                  summary={results?.summary ?? ''}
                  isLoading={loading}
                  vulnerabilities={results?.vulnerabilities ?? []}
                  score={results?.securityScore ?? 100}
                />
              </div>
            </div>
          )}

          {/* Placeholder */}
          {!results && !loading && (
            <div className="flex flex-col items-center justify-center py-20 gap-4 text-slate-600">
              <div className="w-16 h-16 rounded-2xl bg-violet-500/8 border border-violet-500/15 flex items-center justify-center">
                <ScanSearch size={28} className="text-violet-500/60" />
              </div>
              <p className="text-sm text-slate-500">{t('analyzer.placeholder')}</p>
              <div className="flex gap-2 flex-wrap justify-center">
                {(t('analyzer.moduleList', { returnObjects: true }) as string[]).map((m: string) => (
                  <span key={m} className="text-xs px-2 py-1 bg-[#13131f] border border-[#1e1e30] rounded-lg text-slate-500">{m}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
