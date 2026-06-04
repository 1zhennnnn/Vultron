import { FullAnalysisResult, Vulnerability } from '../types';

const BASE = (import.meta.env.VITE_API_URL ?? 'http://localhost:8000') + '/api';
const WS_BASE = (import.meta.env.VITE_API_URL ?? 'http://localhost:8000').replace(/^http/, 'ws');

async function post<T>(path: string, body: object): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => null);
    throw new Error(err?.message ?? `API error: ${res.status}`);
  }
  const json = await res.json();
  if (json.status === 'error') throw new Error(json.message ?? 'Unknown error');
  return json.data !== undefined ? json.data : json;
}

export async function fetchStats(): Promise<unknown> {
  const res = await fetch(`${BASE}/analyses/stats`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const json = await res.json();
  if (json.status === 'error') throw new Error(json.message ?? 'Unknown error');
  return json.data;
}

export const analyzeContract = (code: string) =>
  post<FullAnalysisResult>('/analyze', { code });

export interface ProgressData {
  step: number;
  total: number;
  message: string;
  status: string;
  percent: number;
}

export async function analyzeContractWithProgress(
  code: string,
  onProgress: (data: ProgressData) => void,
  language: string = 'en',
): Promise<FullAnalysisResult> {
  const jobId = crypto.randomUUID();
  const wsUrl = `${WS_BASE}/ws/analysis/${jobId}`;

  return new Promise((resolve, reject) => {
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(wsUrl);
    } catch {
      return analyzeContract(code).then(resolve).catch(reject);
    }

    ws.onopen = () => {
      fetch(`${BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, job_id: jobId, language }),
      })
        .then(r => r.json())
        .then(json => {
          if (json.status === 'success') {
            resolve(json.data);
          } else {
            reject(new Error(json.message ?? 'Analysis failed'));
          }
          ws?.close();
        })
        .catch(err => {
          reject(err);
          ws?.close();
        });
    };

    ws.onmessage = (event) => {
      try {
        onProgress(JSON.parse(event.data) as ProgressData);
      } catch { /* ignore parse errors */ }
    };

    ws.onerror = () => {
      analyzeContract(code).then(resolve).catch(reject);
    };
  });
}

export async function getAnalysisById(id: string | number): Promise<FullAnalysisResult> {
  const res = await fetch(`${BASE}/analyses/${id}`);
  const json = await res.json();
  if (json.status === 'error') throw new Error(json.message ?? 'Analysis not found');
  return json.data as FullAnalysisResult;
}

export async function getContractHistory(contractName: string) {
  const res = await fetch(`${BASE}/analyses/history/${encodeURIComponent(contractName)}`);
  const json = await res.json();
  if (json.status === 'error') throw new Error(json.message ?? 'History not found');
  return json.data;
}

export const copilotChat = (question: string, vulnerabilities: Vulnerability[], score: number, language = 'en') =>
  post<{ answer: string }>('/copilot-chat', { question, vulnerabilities, score, language });
