import { AnalysisResult } from '../types';

const BASE_URL = 'http://localhost:3001/api';

export async function analyzeContract(code: string): Promise<AnalysisResult> {
  const res = await fetch(`${BASE_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new Error('Analysis failed');
  return res.json();
}
