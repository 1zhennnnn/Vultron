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
extra_args = sys.argv[4:] if len(sys.argv) > 4 else []

work_dir = os.path.dirname(sol_file)
filename = os.path.basename(sol_file)

os.chdir(work_dir)

slither_cmd = [
    sys.executable, '-m', 'slither', filename,
    '--json', output_file,
    '--no-fail-pedantic',
    '--disable-color',
    '--solc', solc_path
]
slither_cmd.extend(extra_args)

result = subprocess.run(
    slither_cmd,
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
    // Add OpenZeppelin remapping if exists in backend/node_modules
    // __dirname is backend/src/analyzer, so node_modules is 2 levels up
    const ozPath = join(__dirname, '..', '..', 'node_modules', '@openzeppelin', 'contracts').replace(/\\/g, '/');
    
    // Pass as separate arguments to avoid shell quoting issues in the Python wrapper
    const cmd = `python "${scriptFile.replace(/\\/g, '/')}" "${solPath}" "${outPath}" "C:/Users/zhenn/solc.exe" "--solc-remaps" "@openzeppelin/=${ozPath}/"`;

    const env = {
      ...process.env,
      PATH: `${process.env.PATH};C:\\Users\\zhenn;C:\\Users\\zhenn\\AppData\\Roaming\\Python\\Python311\\Scripts`,
    };

    console.log('Running slither wrapper:', cmd);
    console.log('process.cwd():', process.cwd());
    console.log('ozPath:', ozPath);

    try {
      const { stdout, stderr } = await execAsync(cmd, { timeout: 60000, env });
      console.log('Slither wrapper stdout:', stdout);
      if (stderr) console.warn('Slither wrapper stderr:', stderr);
    } catch (slitherErr: any) {
      // Slither exits non-zero (1) when findings are found, which is "normal"
      if (slitherErr?.stdout) console.log('Slither stdout:', slitherErr.stdout);
      if (slitherErr?.stderr) console.warn('Slither stderr:', slitherErr.stderr);
    }

    if (existsSync(outputFile)) {
      try {
        const content = readFileSync(outputFile, 'utf-8');
        if (!content.trim()) {
          console.error('Slither output file is empty');
          return { success: false, detectors: [], error: 'Empty output' };
        }
        const raw = JSON.parse(content);
        console.log('Slither parsed detectors count:', raw.results?.detectors?.length ?? 0);
        return {
          success: true,
          detectors: raw.results?.detectors ?? [],
        };
      } catch (parseErr: any) {
        console.error('Failed to parse Slither output JSON:', parseErr);
        return { success: false, detectors: [], error: 'Parse error' };
      }
    }

    console.error('Slither produced no output file at:', outputFile);
    return { success: false, detectors: [], error: 'No output file produced' };
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
