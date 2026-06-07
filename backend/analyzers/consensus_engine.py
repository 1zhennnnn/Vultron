import asyncio
from typing import Any, Callable, Awaitable, Dict, List


def get_path_key(path: dict) -> str:
    # Issue #4: match by vulnerability type only, not by AI-generated title prose.
    # Two AI runs almost always phrase the title differently even for the same vuln,
    # so using title in the key caused 0% consensus.  Type-only matching correctly
    # identifies when both runs detected the same underlying vulnerability.
    vuln_type = (
        path.get("vulnerability_type", "")
        or path.get("to", "")
        or path.get("from", "")
    )
    return vuln_type.lower().strip()


async def run_consensus_analysis(
    slither_result: dict,
    contract_code: str,
    generate_ai_paths_fn: Callable[[List[Dict]], Awaitable[Dict]],
    runs: int = 2,
) -> dict:
    """
    Run AI causal path generation twice on the same vulnerability list.
    Paths whose vulnerability type appears in both runs are high-confidence;
    type-only matching (not title matching) avoids false 0% consensus caused
    by AI phrasing variance between runs.
    """
    vulnerabilities = slither_result.get('vulnerabilities', [])

    if not vulnerabilities:
        return {
            'paths': [],
            'criticalPathId': None,
            'consensus': {
                'runs': runs,
                'successful_runs': 0,
                'high_confidence_paths': 0,
                'low_confidence_paths': 0,
                'consensus_rate': 0.0,
                'note': 'No vulnerabilities to analyse',
            },
        }

    async def run_with_delay(delay: float) -> Dict:
        if delay > 0:
            await asyncio.sleep(delay)
        return await generate_ai_paths_fn(vulnerabilities)

    raw = await asyncio.gather(
        run_with_delay(0),
        run_with_delay(1.5),
        return_exceptions=True,
    )

    valid: List[List[Dict]] = []
    for r in raw:
        if isinstance(r, Exception):
            continue
        paths = r.get('paths', []) if isinstance(r, dict) else []
        if paths:
            valid.append(paths)

    if len(valid) == 0:
        return {
            'paths': [],
            'criticalPathId': None,
            'consensus': {
                'runs': runs,
                'successful_runs': 0,
                'high_confidence_paths': 0,
                'low_confidence_paths': 0,
                'consensus_rate': 0.0,
                'note': 'All runs failed',
            },
        }

    if len(valid) == 1:
        paths = valid[0]
        return {
            'paths': paths,
            'criticalPathId': paths[0].get('id') if paths else None,
            'consensus': {
                'runs': runs,
                'successful_runs': 1,
                'high_confidence_paths': len(paths),
                'low_confidence_paths': 0,
                'consensus_rate': 0.5,
                'note': 'One run failed — using single-run result',
            },
        }

    paths_run1, paths_run2 = valid[0], valid[1]

    # Build type→path maps; last writer wins if a type appears twice in one run
    map1 = {get_path_key(p): p for p in paths_run1}
    map2 = {get_path_key(p): p for p in paths_run2}

    keys1, keys2 = set(map1), set(map2)
    consensus_keys = keys1 & keys2
    single_keys    = keys1 ^ keys2

    # Prefer the run-1 path for consensus entries (run 2 is just confirmation)
    high_conf = [map1[k] for k in consensus_keys]
    low_conf = []
    for k in single_keys:
        path_data = map1.get(k) or map2.get(k)
        if path_data:                        # skip if both maps returned nothing
            low_conf.append({**path_data, 'low_confidence': True})

    all_paths    = high_conf + low_conf
    total_unique = len(keys1 | keys2)
    consensus_rate = len(consensus_keys) / total_unique if total_unique > 0 else 0.0

    critical = next(
        (p for p in high_conf if p.get('severity') == 'critical'),
        high_conf[0] if high_conf else (all_paths[0] if all_paths else None),
    )

    return {
        'paths': all_paths,
        'criticalPathId': critical.get('id') if critical else None,
        'consensus': {
            'runs': runs,
            'successful_runs': 2,
            'high_confidence_paths': len(high_conf),
            'low_confidence_paths': len(low_conf),
            'consensus_rate': round(consensus_rate, 3),
            'note': f'{len(high_conf)} path(s) confirmed in both runs',
        },
    }
