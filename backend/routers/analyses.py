import json as _json

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import AnalysisRecord, ContractRecord, VulnerabilityRecord, get_session
from models.schemas import APIResponse

router = APIRouter()


@router.get("/analyses")
async def list_analyses(limit: int = 20, session: AsyncSession = Depends(get_session)):
    try:
        result = await session.execute(
            select(AnalysisRecord, ContractRecord.name)
            .join(ContractRecord)
            .order_by(AnalysisRecord.analyzed_at.desc())
            .limit(limit)
        )
        analyses = [
            {
                "id": a.id,
                "contractName": name,
                "securityScore": a.security_score,
                "riskLevel": a.risk_level,
                "vulnerabilityCount": a.vuln_count,
                "analyzedAt": a.analyzed_at.isoformat(),
            }
            for a, name in result.all()
        ]
        return APIResponse.success(analyses)
    except Exception as e:
        return APIResponse.error("INTERNAL_ERROR", str(e))


@router.get("/analyses/stats")
async def get_stats(session: AsyncSession = Depends(get_session)):
    try:
        total_scans = (
            await session.execute(select(func.count(AnalysisRecord.id)))
        ).scalar() or 0

        avg_score = round(
            (await session.execute(select(func.avg(AnalysisRecord.security_score)))).scalar() or 0, 1
        )

        critical_risk = (
            await session.execute(
                select(func.count(AnalysisRecord.id)).where(AnalysisRecord.security_score < 20)
            )
        ).scalar() or 0

        avg_total_ms = round(
            (await session.execute(select(func.avg(AnalysisRecord.total_ms)))).scalar() or 0
        )

        avg_hallucination = round(
            (await session.execute(select(func.avg(AnalysisRecord.hallucination_rate)))).scalar() or 0.0, 3
        )

        recent_rows = (
            await session.execute(
                select(AnalysisRecord, ContractRecord.name)
                .join(ContractRecord)
                .order_by(AnalysisRecord.analyzed_at.desc())
                .limit(10)
            )
        ).all()
        recent_scans = [
            {
                "id": a.id,
                "contractName": name,
                "securityScore": a.security_score,
                "riskLevel": a.risk_level,
                "vulnerabilityCount": a.vuln_count,
                "analyzedAt": a.analyzed_at.isoformat(),
            }
            for a, name in recent_rows
        ]

        trend_rows = (
            await session.execute(
                select(AnalysisRecord.security_score, AnalysisRecord.analyzed_at)
                .order_by(AnalysisRecord.analyzed_at.asc())
                .limit(30)
            )
        ).all()
        trend_data = [
            {"date": row.analyzed_at.strftime("%m/%d"), "score": row.security_score}
            for row in trend_rows
        ]

        top_vuln_rows = (
            await session.execute(
                select(VulnerabilityRecord.type, func.count(VulnerabilityRecord.id).label("count"))
                .group_by(VulnerabilityRecord.type)
                .order_by(func.count(VulnerabilityRecord.id).desc())
                .limit(6)
            )
        ).all()
        top_vulns = [{"type": row.type, "count": row.count} for row in top_vuln_rows]

        return APIResponse.success({
            "totalScans": total_scans,
            "avgScore": avg_score,
            "criticalRisk": critical_risk,
            "recentScans": recent_scans,
            "trendData": trend_data,
            "topVulns": top_vulns,
            "performanceMetrics": {
                "avgTotalMs": avg_total_ms,
                "avgHallucinationRate": avg_hallucination,
            },
        })
    except Exception as e:
        return APIResponse.error("INTERNAL_ERROR", str(e))


@router.get("/analyses/history/{contract_name}")
async def get_contract_history(contract_name: str, session: AsyncSession = Depends(get_session)):
    try:
        stmt = (
            select(AnalysisRecord, ContractRecord.name.label("contract_name"))
            .join(ContractRecord, AnalysisRecord.contract_id == ContractRecord.id)
            .where(ContractRecord.name == contract_name)
            .order_by(AnalysisRecord.analyzed_at.asc())
        )
        rows = (await session.execute(stmt)).all()

        if not rows:
            return APIResponse.error("NOT_FOUND", f"No history for {contract_name}")

        history = [
            {
                "id": r.AnalysisRecord.id,
                "score": r.AnalysisRecord.security_score,
                "created_at": r.AnalysisRecord.analyzed_at.isoformat(),
                "duration_ms": r.AnalysisRecord.total_ms,
            }
            for r in rows
        ]

        scores = [h["score"] for h in history]
        trend = None
        if len(scores) >= 2:
            diff = scores[-1] - scores[-2]
            trend = {
                "direction": "up" if diff > 0 else "down" if diff < 0 else "flat",
                "change": diff,
                "latest": scores[-1],
                "previous": scores[-2],
            }

        return APIResponse.success({
            "contract_name": contract_name,
            "total_analyses": len(history),
            "history": history,
            "trend": trend,
        })
    except Exception as e:
        return APIResponse.error("INTERNAL_ERROR", str(e))


@router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: int, session: AsyncSession = Depends(get_session)):
    try:
        row = (
            await session.execute(
                select(AnalysisRecord, ContractRecord.name)
                .join(ContractRecord)
                .where(AnalysisRecord.id == analysis_id)
            )
        ).first()
        if not row:
            return APIResponse.error("NOT_FOUND", f"Analysis {analysis_id} not found")

        a, name = row

        # Fetch full vulnerability list for this analysis
        vuln_rows = (
            await session.execute(
                select(VulnerabilityRecord)
                .where(VulnerabilityRecord.analysis_id == analysis_id)
                .order_by(VulnerabilityRecord.id)
            )
        ).scalars().all()

        vulnerabilities = [
            {
                "id": v.vuln_id,
                "type": v.type,
                "function": v.function,
                "severity": v.severity,
                "description": v.description,
                "lineNumber": v.line_number,
                "exploitability_score": v.exploitability_score,
                "exploitability_level": v.exploitability_level,
            }
            for v in vuln_rows
        ]

        def _load(field): return _json.loads(field) if field else None

        complexity = None
        if a.complexity_score is not None:
            complexity = {
                "complexity_score": a.complexity_score,
                "complexity_level": a.complexity_level or "UNKNOWN",
                "complexity_note": "",
                "metrics": {},
            }

        attack_strategy = _load(a.attack_strategy_json) or {
            "exploitType": "", "riskLevel": a.risk_level, "steps": []
        }
        defense_recs = _load(a.defense_recs_json) or []

        return APIResponse.success({
            "id": a.id,
            "contractName": name,
            "analyzedAt": a.analyzed_at.isoformat(),
            "securityScore": a.security_score,
            "riskLevel": a.risk_level,
            "vulnerabilities": vulnerabilities,
            "slitherSuccess": a.slither_success,
            "complexity": complexity,
            "summary": a.summary or "",
            "scoreExplanation": a.score_explanation or "",
            "attackStrategy": attack_strategy,
            "defenseRecommendations": defense_recs,
            "performance": {
                "total_ms": a.total_ms,
                "slither_ms": 0,
                "groq_ms": 0,
                "exploitability_ms": 0,
                "validation_ms": 0,
            },
            "hallucination": {
                "validation_passed": a.hallucination_rate < 0.5,
                "hallucination_count": 0,
                "hallucination_rate": a.hallucination_rate,
            },
            "causalPaths": _load(a.causal_paths_json) or [],
            "criticalPathId": a.critical_path_id,
            "pocScript": a.poc_script,
            "consensus": None,
            # Legacy fields for DashboardPage
            "vulnerabilityCount": a.vuln_count,
            "criticalCount": a.critical_count,
            "highCount": a.high_count,
            "totalMs": a.total_ms,
            "hallucinationRate": a.hallucination_rate,
        })
    except Exception as e:
        return APIResponse.error("INTERNAL_ERROR", str(e))
