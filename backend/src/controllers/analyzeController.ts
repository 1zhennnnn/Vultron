import { Request, Response } from 'express';
import { runSlither, mapSlitherToVulnerabilities } from '../analyzer/slitherRunner';
import { calculateScore, getRiskLevel } from '../analyzer/scoreCalculator';
import {
  generateSecuritySummary,
  generateAttackStrategy,
  generateDefenseRecommendations,
  generateScoreExplanation,
  generateCopilotAnswer,
  askGroq,
} from '../analyzer/claudeClient';
import { buildAttackNarrative, generateAICausalPaths } from '../analyzer/causalEngine';
import { generatePoCScript } from '../analyzer/pocGenerator';
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
    // Step 1: Real Slither static analysis (graceful fallback if Slither fails)
    let vulnerabilities: Vulnerability[] = [];
    let slitherSuccess = false;
    try {
      const slitherResult = await runSlither(code);
      vulnerabilities = mapSlitherToVulnerabilities(slitherResult.detectors);
      slitherSuccess = slitherResult.success;
    } catch (slitherErr) {
      console.warn('Slither failed, continuing with Gemini-only analysis:', slitherErr);
    }

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

    console.log('remediations count:', defenseRecommendations?.length);

    // Step 4: AI causal attack paths (falls back to static rules on failure)
    console.log('Using AI causal paths');
    const causalResult = await generateAICausalPaths(
      vulnerabilities,
      (prompt) => askGroq(prompt, 2000),
    );
    console.log('controller causalPaths count:', causalResult.paths.length);
    const narrativeSteps = buildAttackNarrative(vulnerabilities, causalResult.paths);

    // Merge: prefer Claude attack steps, fallback to narrative
    const finalAttackStrategy = {
      ...attackStrategy,
      steps: attackStrategy.steps.length >= 4 ? attackStrategy.steps : narrativeSteps,
    };

    const contractName = extractContractName(code);

    // Step 5: AI-generated PoC Hardhat attack script
    const pocScript = await generatePoCScript(contractName, vulnerabilities, code, (prompt) => askGroq(prompt, 2000));
    console.log('PoC script generated:', pocScript.length, 'chars');

    res.json({
      contractName,
      securityScore,
      riskLevel,
      vulnerabilities,
      summary,
      attackStrategy: finalAttackStrategy,
      defenseRecommendations,
      scoreExplanation,
      causalPaths: causalResult.paths,
      criticalPathId: causalResult.criticalPathId,
      pocScript,
      slitherSuccess,
      analyzedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    console.error('Analysis error:', err);
    res.status(500).json({
      error: 'Analysis failed. Ensure GROQ_API_KEY is set.',
      details: err?.message ?? String(err),
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
    res.status(500).json({ error: 'Copilot failed. Check GROQ_API_KEY.' });
  }
}
