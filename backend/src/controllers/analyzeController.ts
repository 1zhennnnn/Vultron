import { Request, Response } from 'express';
import { runSlither, mapSlitherToVulnerabilities } from '../analyzer/slitherRunner';
import { calculateScore, getRiskLevel } from '../analyzer/scoreCalculator';
import {
  generateSecuritySummary,
  generateAttackStrategy,
  generateDefenseRecommendations,
  generateScoreExplanation,
  generateCopilotAnswer,
} from '../analyzer/claudeClient';
import { buildAttackNarrative } from '../analyzer/causalEngine';
import { Vulnerability } from '../types';

function extractContractName(code: string): string {
  const match = code.match(/contract\s+(\w+)/);
  return match?.[1] ?? 'UnknownContract';
}

export async function handleAnalyze(req: Request, res: Response): Promise<void> {
  const { code } = req.body;

  if (!code || typeof code !== 'string' || code.trim().length < 10) {
    res.status(400).json({ error: 'Request body must include a non-empty "code" string (min 10 chars).' });
    return;
  }

  try {
    // Step 1: Real Slither static analysis
    const slitherResult = await runSlither(code);
    const vulnerabilities = mapSlitherToVulnerabilities(slitherResult.detectors);

    // Step 2: Score calculation (deterministic, instant)
    const securityScore = calculateScore(vulnerabilities);
    const riskLevel = getRiskLevel(securityScore);

    // Step 3: All Claude AI calls in parallel
    const [summary, attackStrategy, defenseRecommendations, scoreExplanation] =
      await Promise.all([
        generateSecuritySummary(code, vulnerabilities),
        generateAttackStrategy(vulnerabilities),
        generateDefenseRecommendations(vulnerabilities),
        generateScoreExplanation(securityScore, vulnerabilities),
      ]);

    // Step 4: Causal attack narrative (deterministic, no AI needed)
    const narrativeSteps = buildAttackNarrative(vulnerabilities);

    // Merge: prefer Claude attack steps, fallback to narrative
    const finalAttackStrategy = {
      ...attackStrategy,
      steps: attackStrategy.steps.length >= 4 ? attackStrategy.steps : narrativeSteps,
    };

    res.json({
      contractName: extractContractName(code),
      securityScore,
      riskLevel,
      vulnerabilities,
      summary,
      attackStrategy: finalAttackStrategy,
      defenseRecommendations,
      scoreExplanation,
      slitherSuccess: slitherResult.success,
      analyzedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    console.error('Analysis error:', err);
    res.status(500).json({
      error: 'Analysis failed. Ensure GEMINI_API_KEY is set and Slither is installed.',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }
}

export async function handleCopilotChat(req: Request, res: Response): Promise<void> {
  const { question, vulnerabilities, score } = req.body;

  if (!question || typeof question !== 'string' || question.trim().length === 0) {
    res.status(400).json({ error: 'Requires non-empty question string.' });
    return;
  }

  try {
    const answer = await generateCopilotAnswer(
      question.trim(),
      Array.isArray(vulnerabilities) ? (vulnerabilities as Vulnerability[]) : [],
      typeof score === 'number' ? score : 100
    );
    res.json({ answer });
  } catch (err: any) {
    console.error('Copilot error:', err);
    res.status(500).json({ error: 'Copilot failed. Check ANTHROPIC_API_KEY.' });
  }
}
