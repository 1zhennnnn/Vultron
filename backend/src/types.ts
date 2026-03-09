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

export interface FullAnalysisResult {
  contractName: string;
  securityScore: number;
  riskLevel: RiskLevel;
  vulnerabilities: Vulnerability[];
  summary: string;
  attackStrategy: AttackStrategy;
  defenseRecommendations: DefenseRecommendation[];
  scoreExplanation: string;
  analyzedAt: string;
}
