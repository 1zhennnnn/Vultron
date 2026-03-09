import { Vulnerability, Severity, RiskLevel } from '../types';

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 40,
  high:     25,
  medium:   10,
  low:       5,
  info:      0,
};

export function calculateScore(vulnerabilities: Vulnerability[]): number {
  const penalty = vulnerabilities.reduce(
    (sum, v) => sum + (SEVERITY_PENALTY[v.severity] ?? 0),
    0
  );
  return Math.max(0, 100 - penalty);
}

export function getRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'Safe';
  if (score >= 60) return 'Low Risk';
  if (score >= 40) return 'Medium Risk';
  if (score >= 20) return 'High Risk';
  return 'Critical Risk';
}
