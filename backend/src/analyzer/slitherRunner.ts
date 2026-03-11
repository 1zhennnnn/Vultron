import { exec } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { platform } from 'os';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import { Vulnerability, Severity } from '../types';

const execAsync = promisify(exec);

// Use simple temp path to avoid Windows path parsing issues with crytic_compile
const tmpDir = platform() === 'win32' ? 'C:\\Temp' : require('os').tmpdir();
try { mkdirSync(tmpDir, { recursive: true }); } catch {}

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
  // Reentrancy
  'reentrancy-eth':           'reentrancy',
  'reentrancy-no-eth':        'reentrancy',
  'reentrancy-benign':        'reentrancy',
  'reentrancy-events':        'reentrancy',

  // Authentication
  'tx-origin':                'tx-origin',

  // Selfdestruct
  'suicidal':                 'unprotected-selfdestruct',

  // Delegatecall
  'controlled-delegatecall':  'unsafe-delegatecall',
  'delegatecall-loop':        'unsafe-delegatecall',

  // Unchecked calls
  'unchecked-lowlevel':       'unchecked-call',
  'unchecked-send':           'unchecked-call',
  'unchecked-transfer':       'unchecked-call',

  // Integer issues
  'integer-overflow':         'integer-overflow',
  'incorrect-exp':            'integer-overflow',
  'tautology':                'integer-overflow',

  // Access control
  'missing-zero-check':       'access-control',
  'unprotected-upgrade':      'access-control',
  'protected-vars':           'access-control',
  'arbitrary-send-eth':       'access-control',
  'arbitrary-send-erc20':     'access-control',

  // Timestamp / randomness
  'weak-prng':                'timestamp-dependence',
  'timestamp':                'timestamp-dependence',
  'block-timestamp':          'timestamp-dependence',

  // Denial of service
  'msg-value-loop':           'denial-of-service',
  'calls-loop':               'denial-of-service',
  'gas-griefing':             'denial-of-service',

  // Misc
  'shadowing-state':          'shadowing',
  'uninitialized-local':      'uninitialized',
  'locked-ether':             'locked-ether',
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
  const tmpFile = join(tmpDir, `vultron_${id}.sol`);
  const outputFile = join(tmpDir, `vultron_${id}_out.json`);
  const scriptFile = join(tmpDir, `vultron_${id}_run.py`);

  // Python wrapper: cd into the .sol directory and run slither with relative filename
  // This avoids crytic_compile misparse of absolute Windows backslash paths
  const pythonScript = `
import subprocess
import sys
import os

sol_file = sys.argv[1]
output_file = sys.argv[2]
solc_path = sys.argv[3]

work_dir = os.path.dirname(sol_file)
filename = os.path.basename(sol_file)

os.chdir(work_dir)

result = subprocess.run(
    ['python', '-m', 'slither', filename,
     '--json', output_file,
     '--no-fail-pedantic',
     '--disable-color',
     '--solc', solc_path],
    capture_output=True,
    text=True
)

print(result.stdout)
print(result.stderr, file=sys.stderr)
sys.exit(result.returncode)
`;

  try {
    writeFileSync(tmpFile, solidityCode, 'utf-8');
    writeFileSync(scriptFile, pythonScript, 'utf-8');

    // Use forward slashes for all paths passed to Python
    const solPath = tmpFile.replace(/\\/g, '/');
    const outPath = outputFile.replace(/\\/g, '/');
    const cmd = `python "${scriptFile.replace(/\\/g, '/')}" "${solPath}" "${outPath}" "C:/Users/zhenn/solc.exe"`;

    const env = {
      ...process.env,
      PATH: `${process.env.PATH};C:\\Users\\zhenn;C:\\Users\\zhenn\\AppData\\Roaming\\Python\\Python311\\Scripts`,
    };

    console.log('Running slither wrapper:', cmd);
    console.log('Temp sol file:', tmpFile);

    try {
      await execAsync(cmd, { timeout: 60000, env });
    } catch (slitherErr: any) {
      // Slither exits non-zero when findings exist — try reading output anyway
      console.error('Slither execution error:', slitherErr?.message ?? slitherErr);
      console.error('Slither stderr:', slitherErr?.stderr ?? '(none)');
      console.error('Command used:', cmd);
    }

    if (existsSync(outputFile)) {
      const raw = JSON.parse(readFileSync(outputFile, 'utf-8'));
      return {
        success: true,
        detectors: raw.results?.detectors ?? [],
      };
    }

    console.error('Slither produced no output file. Command was:', cmd);
    return { success: false, detectors: [], error: 'Slither produced no output file' };
  } catch (err: any) {
    console.error('Slither execution error:', err?.message ?? err);
    return { success: false, detectors: [], error: String(err.message ?? err) };
  } finally {
    try { unlinkSync(tmpFile); } catch {}
    try { unlinkSync(scriptFile); } catch {}
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
