import asyncio
from typing import Any, Callable, Awaitable, Dict, List


def get_path_key(path: dict) -> str:
    vuln_type = path.get('vulnerability_type', '') or path.get('to', '')
    title = path.get('title', '')
    return f"{vuln_type.lower()}:{title.lower()[:30]}"


async def run_consensus_analysis(
    slither_result: dict,
    contract_code: str,
    generate_ai_paths_fn: Callable[[List[Dict]], Awaitable[Dict]],
    runs: int = 2,
) -> dict:
    """
    Run AI causal path generation twice on the same vulnerability list.
    Return the intersection as high-confidence results.
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
                'note': 'One run failed, using single run result',
            },
        }

    paths_run1, paths_run2 = valid[0], valid[1]
    map1 = {get_path_key(p): p for p in paths_run1}
    map2 = {get_path_key(p): p for p in paths_run2}

    keys1, keys2 = set(map1), set(map2)
    consensus_keys = keys1 & keys2
    single_keys    = keys1 ^ keys2

    high_conf = [map1[k] for k in consensus_keys]
    low_conf  = [
        {**(map1.get(k) or map2.get(k) or {}), 'low_confidence': True}
        for k in single_keys
    ]

    all_paths = high_conf + low_conf
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
            'note': f'{len(high_conf)} paths confirmed in both runs',
        },
    }
