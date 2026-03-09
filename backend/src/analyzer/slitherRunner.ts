import { exec } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import { Vulnerability, Severity } from '../types';

const execAsync = promisify(exec);

export interface SlitherDetector {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements: Array<{
    type: string;
    name: string;
    source_mapping?: {
      start: number;
      length: number;
      lines: number[];
    };
  }>;
}

export interface SlitherRawResult {
  success: boolean;
  detectors: SlitherDetector[];
  error?: string;
}

const CHECK_TYPE_MAP: Record<string, string> = {
  'reentrancy-eth':           'reentrancy',
  'reentrancy-no-eth':        'reentrancy',
  'reentrancy-benign':        'reentrancy',
  'reentrancy-events':        'reentrancy',
  'tx-origin':                'tx-origin',
  'suicidal':                 'unprotected-selfdestruct',
  'controlled-delegatecall':  'unsafe-delegatecall',
  'delegatecall-loop':        'unsafe-delegatecall',
  'unchecked-lowlevel':       'unchecked-call',
  'unchecked-send':           'unchecked-call',
  'integer-overflow':         'integer-overflow',
  'tautology':                'logic-error',
  'shadowing-state':          'shadowing',
  'uninitialized-local':      'uninitialized',
  'locked-ether':             'locked-ether',
  'arbitrary-send-eth':       'arbitrary-send',
  'arbitrary-send-erc20':     'arbitrary-send',
  'weak-prng':                'weak-randomness',
  'timestamp':                'timestamp-dependence',
  'msg-value-loop':           'msg-value-loop',
  'calls-loop':               'gas-griefing',
};

const IMPACT_MAP: Record<string, Severity> = {
  High:          'critical',
  Medium:        'high',
  Low:           'medium',
  Informational: 'info',
  Optimization:  'info',
};

export async function runSlither(solidityCode: string): Promise<SlitherRawResult> {
  const id = uuidv4();
  const tmpFile = join(tmpdir(), `vultron_${id}.sol`);
  const outputFile = join(tmpdir(), `vultron_${id}_out.json`);

  try {
    writeFileSync(tmpFile, solidityCode, 'utf-8');

    const cmd = [
      'slither',
      tmpFile,
      '--json', outputFile,
      '--no-fail-pedantic',
      '--disable-color',
    ].join(' ');

    try {
      await execAsync(cmd, { timeout: 45000 });
    } catch {
      // Slither exits non-zero when findings exist — try reading output anyway
    }

    if (existsSync(outputFile)) {
      const raw = JSON.parse(readFileSync(outputFile, 'utf-8'));
      return {
        success: true,
        detectors: raw.results?.detectors ?? [],
      };
    }

    return { success: false, detectors: [], error: 'Slither produced no output file' };
  } catch (err: any) {
    return { success: false, detectors: [], error: String(err.message ?? err) };
  } finally {
    try { unlinkSync(tmpFile); } catch {}
    try { if (existsSync(outputFile)) unlinkSync(outputFile); } catch {}
  }
}

export function mapSlitherToVulnerabilities(detectors: SlitherDetector[]): Vulnerability[] {
  return detectors
    .filter(d => d.impact !== 'Optimization')
    .map((d, i) => {
      const fnEl = d.elements.find(e => e.type === 'function');
      const affectedFunction = fnEl?.name ?? d.elements[0]?.name ?? 'unknown';
      const lines = d.elements[0]?.source_mapping?.lines ?? [];

      return {
        id: `SL-${String(i).padStart(3, '0')}`,
        type: CHECK_TYPE_MAP[d.check] ?? d.check,
        function: affectedFunction,
        severity: IMPACT_MAP[d.impact] ?? 'info',
        description: d.description.replace(/\n/g, ' ').replace(/\s{2,}/g, ' ').trim(),
        lineNumber: lines[0],
      };
    });
}
