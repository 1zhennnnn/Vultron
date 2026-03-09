import { FullAnalysisResult, Vulnerability } from '../types';

const BASE = (import.meta.env.VITE_API_URL ?? 'https://vultron.onrender.com') + '/api';

async function post<T>(path: string, body: object): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export const analyzeContract = (code: string) =>
  post<FullAnalysisResult>('/analyze', { code });

export const copilotChat = (question: string, vulnerabilities: Vulnerability[], score: number) =>
  post<{ answer: string }>('/copilot-chat', { question, vulnerabilities, score });
