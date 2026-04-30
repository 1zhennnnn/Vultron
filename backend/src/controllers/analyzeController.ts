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
  analyzeContractWithAI,
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
    // Step 1: Real Slither static analysis
    let vulnerabilities: Vulnerability[] = [];
    let slitherSuccess = false;
    try {
      const slitherResult = await runSlither(code);
      vulnerabilities = mapSlitherToVulnerabilities(slitherResult.detectors);
      slitherSuccess = slitherResult.success;
      console.log(`Slither analysis complete. Found ${vulnerabilities.length} vulnerabilities.`);
    } catch (slitherErr) {
      console.warn('Slither execution error, will fallback to AI:', slitherErr);
    }

    // Step 2: AI Fallback if Slither finds nothing or fails
    // Slither is great but sometimes misses things or fails to compile
    if (vulnerabilities.length === 0) {
      console.log('Slither found no issues. Running AI security scan fallback...');
      const aiVulns = await analyzeContractWithAI(code);
      vulnerabilities = aiVulns;
      console.log(`AI scan complete. Found ${vulnerabilities.length} vulnerabilities.`);
    }

    // Step 3: Score calculation (deterministic, instant)
    const securityScore = calculateScore(vulnerabilities);
    const riskLevel = getRiskLevel(securityScore);

    // Step 3: Sequential AI calls to avoid Groq rate limits
    const summary = await generateSecuritySummary(code, vulnerabilities);
    const attackStrategy = await generateAttackStrategy(vulnerabilities);
    const defenseRecommendations = await generateDefenseRecommendations(vulnerabilities);
    const scoreExplanation = await generateScoreExplanation(securityScore, vulnerabilities);

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
