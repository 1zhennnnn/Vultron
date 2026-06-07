import { useState, useCallback, useRef, useEffect } from 'react';
import { analyzeContractWithProgress, ProgressData } from '../services/api';
import { FullAnalysisResult, AttackStrategy, Vulnerability } from '../types';
import i18n from '../i18n/i18n';

export function useVultronAnalysis(initialCode: string) {
  const [code, setCode] = useState(initialCode);
  const [results, setResults] = useState<FullAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressData | null>(null);
  
  // Animation/Simulation State
  const [currentStep, setCurrentStep] = useState(-1);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simDone, setSimDone] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  // Selection state (for highlighting code from graphs/lists)
  const [selectedVulnerability, setSelectedVulnerability] = useState<any | null>(null);

  const clearTimers = useCallback(() => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  }, []);

  const runAnalysis = useCallback(async (contractCode: string) => {
    if (!contractCode.trim() || contractCode.trim().length < 10) {
      setError('Contract code too short.');
      return;
    }
    
    setLoading(true);
    setError(null);
    setProgress(null);
    setCurrentStep(-1);
    setIsSimulating(false);
    setSimDone(false);
    clearTimers();

    try {
      const analysisLanguage = i18n.language;
      const result = await analyzeContractWithProgress(contractCode, setProgress, analysisLanguage);
      const resultWithLang: FullAnalysisResult = { ...result, analysisLanguage };
      setResults(resultWithLang);
    } catch (err) {
      setError('Analysis failed. Check your connection and GROQ_API_KEY.');
    } finally {
      setLoading(false);
      setProgress(null);
    }
  }, [clearTimers]);

  const simulateAttack = useCallback(() => {
    const strategy = results?.attackStrategy;
    if (!strategy || isSimulating) return;

    setCurrentStep(-1);
    setSimDone(false);
    setIsSimulating(true);
    clearTimers();

    strategy.steps.forEach((_, i) => {
      const t1 = setTimeout(() => {
        setCurrentStep(i);
        if (i === strategy.steps.length - 1) {
          const t2 = setTimeout(() => {
            setIsSimulating(false);
            setSimDone(true);
          }, 900);
          timers.current.push(t2);
        }
      }, i * 750);
      timers.current.push(t1);
    });
  }, [results, isSimulating, clearTimers]);

  const resetSimulation = useCallback(() => {
    clearTimers();
    setCurrentStep(-1);
    setIsSimulating(false);
    setSimDone(false);
  }, [clearTimers]);

  // Cleanup on unmount
  useEffect(() => {
    return () => clearTimers();
  }, [clearTimers]);

  return {
    code,
    setCode,
    results,
    loading,
    error,
    progress,
    runAnalysis,
    // Simulation
    currentStep,
    setCurrentStep,
    isSimulating,
    setIsSimulating,
    simDone,
    simulateAttack,
    resetSimulation,
    // UI Selection
    selectedVulnerability,
    setSelectedVulnerability,
  };
}
