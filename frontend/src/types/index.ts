export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskLevel = 'Critical Risk' | 'High Risk' | 'Medium Risk' | 'Low Risk' | 'Safe';

export interface Vulnerability {
  id: string;
  type: string;
  function: string;
  severity: Severity;
  description: string;
  lineNumber?: number;
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
}

export interface ScanHistoryItem {
  id: string;
  contractName: string;
  securityScore: number;
  riskLevel: RiskLevel;
  vulnerabilityCount: number;
  analyzedAt: string;
}
