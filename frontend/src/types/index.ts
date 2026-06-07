export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskLevel = 'Critical Risk' | 'High Risk' | 'Medium Risk' | 'Low Risk' | 'Safe';

export interface Vulnerability {
  id: string;
  type: string;
  function: string;
  severity: Severity;
  description: string;
  lineNumber?: number;
  recommendation?: string;
  exploitability_score?: number;
  exploitability_level?: 'HIGH' | 'MEDIUM' | 'LOW';
  exploitability_conditions?: Array<{ condition: string; weight: number; met: boolean }>;
  exploitability_summary?: string;
  swc_id?: string;
  swc_title?: string;
  cwe_id?: string;
  source_check?: string;
}

export interface AttackStrategy {
  exploitType: string;
  riskLevel: string;
  steps: string[];
}

export interface DefenseRecommendation {
  issue: string;
  strategy: string;
  codeExample: string;
}

export interface CausalNode {
  id: string;
  type: 'root-cause' | 'trigger' | 'exploit-action' | 'cascade-effect' | 'final-impact';
  label: string;
  description: string;
  lineNumber?: number;
  hallucination_risk?: boolean;
  anchored_to_slither?: boolean;
}

export interface CausalEdge {
  from: string;
  to: string;
  relation: string;
}

export interface CausalPath {
  id: string;
  from: string;
  to: string;
  mechanism: string;
  edge?: string;
  compound?: boolean;
  title?: string;
  severity?: string;
  low_confidence?: boolean;
  evidence_score?: number;
  evidence_confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  // AI-enriched fields
  summary?: string;
  nodes?: CausalNode[];
  edges?: CausalEdge[];
}

export interface FullAnalysisResult {
  contractName: string;
  securityScore: number;
  riskLevel: RiskLevel;
  vulnerabilities: Vulnerability[];
  summary: string;
  attackStrategy: AttackStrategy;
  defenseRecommendations: DefenseRecommendation[];
  scoreExplanation: string;
  causalPaths: CausalPath[];
  criticalPathId: string | null;
  pocScript?: string;
  slitherSuccess: boolean;
  analyzedAt: string;
  analysisLanguage?: string;
  solidity_version?: string;
  solc_used?: string;
  complexity?: {
    complexity_score: number;
    complexity_level: 'HIGH' | 'MEDIUM' | 'LOW';
    complexity_note: string;
    metrics: {
      loc: number;
      function_count: number;
      public_function_count: number;
      state_variable_count: number;
      external_call_count: number;
      modifier_count: number;
      event_count: number;
      inheritance_depth: number;
    };
  };
  performance?: {
    total_ms: number;
    slither_ms: number;
    groq_ms: number;
    exploitability_ms: number;
    validation_ms: number;
  };
  hallucination?: {
    validation_passed: boolean;
    hallucination_count: number;
    hallucination_rate: number;
  };
  consensus?: {
    runs: number;
    successful_runs: number;
    high_confidence_paths: number;
    low_confidence_paths: number;
    consensus_rate: number;
    note: string;
  };
}

export interface ScanHistoryItem {
  id: string;
  contractName: string;
  securityScore: number;
  riskLevel: RiskLevel;
  vulnerabilityCount: number;
  analyzedAt: string;
}
