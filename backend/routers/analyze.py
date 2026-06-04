import asyncio
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from analyzers.slither_runner import run_slither, map_slither_to_vulnerabilities, detect_solidity_version
from analyzers.score_calculator import calculate_score, calculate_weighted_score, get_risk_level
from analyzers.causal_engine import build_attack_narrative, generate_ai_causal_paths
from analyzers.consensus_engine import run_consensus_analysis
from analyzers.exploitability_analyzer import run_exploitability_analysis
from analyzers.hallucination_validator import validate_hallucination
from analyzers.poc_generator import generate_poc_script
from analyzers.complexity_analyzer import analyze_complexity
from database import save_analysis
from ws_manager import send_progress, active_connections
from groq_client import (
    ask_groq,
    analyze_contract_with_ai,
    generate_security_summary,
    generate_attack_strategy,
    generate_defense_recommendations,
    generate_score_explanation,
    generate_copilot_answer,
)
from models.schemas import AnalyzeRequest, APIResponse

router = APIRouter()


class CopilotRequest(BaseModel):
    question: str
    vulnerabilities: Optional[List[Any]] = []
    score: Optional[float] = 100
    language: Optional[str] = "en"


def _extract_contract_name(code: str) -> str:
    match = re.search(r"contract\s+(\w+)", code)
    return match.group(1) if match else "UnknownContract"


@router.post("/analyze")
async def handle_analyze(req: AnalyzeRequest):
    t_total_start = time.time()
    code = req.code  # already validated and stripped by the Pydantic model
    job_id = req.job_id
    language = req.language or "en"
    TOTAL_STEPS = 6

    try:
        # ── Stage 1: Version detection ────────────────────────────────────
        await send_progress(job_id, 1, TOTAL_STEPS, "Detecting Solidity version...")
        detected_version = detect_solidity_version(code)
        print(f"Detected Solidity version: {detected_version}")

        # ── Stage 2: Slither static analysis ──────────────────────────────
        await send_progress(job_id, 2, TOTAL_STEPS, "Running Slither static analysis...")
        t_slither_start = time.time()
        vulnerabilities: List[Any] = []
        slither_success = False
        slither_result: dict = {"success": False, "detectors": [], "solidity_version": "unknown", "solc_used": ""}
        try:
            slither_result = await run_slither(code)
            vulnerabilities = map_slither_to_vulnerabilities(slither_result["detectors"])
            slither_success = slither_result["success"]
            print(f"Slither: {len(vulnerabilities)} findings")
        except Exception as e:
            print(f"Slither error, falling back to AI: {e}")
        slither_ms = round((time.time() - t_slither_start) * 1000)

        # AI fallback if Slither finds nothing
        if len(vulnerabilities) == 0:
            print("Slither found nothing — running AI fallback scan")
            vulnerabilities = await analyze_contract_with_ai(code, language=language)
            print(f"AI scan: {len(vulnerabilities)} findings")

        # ── Stage 3: Exploitability + complexity analysis ─────────────────
        await send_progress(job_id, 3, TOTAL_STEPS, "Analyzing exploitability...")
        t_exploit_start = time.time()
        vulnerabilities = run_exploitability_analysis(vulnerabilities)
        exploitability_ms = round((time.time() - t_exploit_start) * 1000)
        complexity_result = analyze_complexity(code, slither_result)

        # ── Stage 4: Score calculation + AI calls ─────────────────────────
        security_score = calculate_weighted_score(vulnerabilities)
        risk_level = get_risk_level(security_score)

        contract_name = _extract_contract_name(code)
        await send_progress(job_id, 4, TOTAL_STEPS, "AI consensus analysis run 1/2...")
        t_groq_start = time.time()
        (
            summary,
            attack_strategy,
            defense_recommendations,
            score_explanation,
            causal_result,
            poc_script,
        ) = await asyncio.gather(
            generate_security_summary(code, vulnerabilities, language=language),
            generate_attack_strategy(vulnerabilities, language=language),
            generate_defense_recommendations(vulnerabilities, language=language),
            generate_score_explanation(security_score, vulnerabilities, language=language),
            run_consensus_analysis(
                slither_result={'vulnerabilities': vulnerabilities},
                contract_code=code,
                generate_ai_paths_fn=lambda vulns: generate_ai_causal_paths(
                    vulns, lambda p: ask_groq(p, 2000), language=language
                ),
                runs=2,
            ),
            generate_poc_script(contract_name, vulnerabilities, code, lambda prompt: ask_groq(prompt, 2000), language=language),
        )
        groq_ms = round((time.time() - t_groq_start) * 1000)
        print(f"Causal paths: {len(causal_result['paths'])}")
        print(f"PoC: {len(poc_script)} chars")

        narrative_steps = build_attack_narrative(vulnerabilities, causal_result["paths"])
        ai_steps = attack_strategy.get("steps", [])
        final_attack_strategy = {
            **attack_strategy,
            "steps": ai_steps if len(ai_steps) >= 4 else narrative_steps,
        }

        # ── Stage 5: Hallucination validation (sync, fast) ────────────────
        await send_progress(job_id, 5, TOTAL_STEPS, "AI consensus analysis run 2/2...")
        t_validation_start = time.time()
        hall_result = validate_hallucination(causal_result["paths"], vulnerabilities)
        validation_ms = round((time.time() - t_validation_start) * 1000)

        total_ms = round((time.time() - t_total_start) * 1000)

        performance = {
            "total_ms": total_ms,
            "slither_ms": slither_ms,
            "groq_ms": groq_ms,
            "exploitability_ms": exploitability_ms,
            "validation_ms": validation_ms,
        }
        hallucination = {
            "validation_passed": hall_result["validation_passed"],
            "hallucination_count": hall_result["hallucination_count"],
            "hallucination_rate": hall_result["hallucination_rate"],
        }

        result = {
            "contractName": contract_name,
            "securityScore": security_score,
            "riskLevel": risk_level,
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "attackStrategy": final_attack_strategy,
            "defenseRecommendations": defense_recommendations,
            "scoreExplanation": score_explanation,
            "causalPaths": hall_result["validated_paths"],
            "criticalPathId": causal_result["criticalPathId"],
            "pocScript": poc_script,
            "slitherSuccess": slither_success,
            "analyzedAt": datetime.now(timezone.utc).isoformat(),
            "performance": performance,
            "hallucination": hallucination,
            "consensus": causal_result.get("consensus", {}),
            "solidity_version": slither_result.get("solidity_version", "unknown"),
            "solc_used": slither_result.get("solc_used", ""),
            "complexity": complexity_result,
        }

        # ── Stage 6: DB save ──────────────────────────────────────────────
        await send_progress(job_id, 6, TOTAL_STEPS, "Saving results...", status="done")
        await save_analysis(result, code)
        active_connections.pop(job_id, None)

        return APIResponse.success(result)

    except Exception as e:
        print(f"Analysis error: {e}")
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content=APIResponse.error("ANALYSIS_FAILED", str(e)),
        )


@router.post("/analyze/validate")
async def validate_input(req: AnalyzeRequest):
    return APIResponse.success({"valid": True, "length": len(req.code)})


@router.post("/copilot-chat")
async def handle_copilot_chat(req: CopilotRequest):
    question = req.question.strip()
    if not question:
        return JSONResponse(
            status_code=400,
            content=APIResponse.error("VALIDATION_ERROR", "Requires non-empty question string"),
        )

    try:
        answer = await generate_copilot_answer(
            question,
            req.vulnerabilities or [],
            req.score if isinstance(req.score, (int, float)) else 100,
            language=req.language or "en",
        )
        return APIResponse.success({"answer": answer})

    except Exception as e:
        print(f"Copilot error: {e}")
        return JSONResponse(
            status_code=500,
            content=APIResponse.error("INTERNAL_ERROR", "Copilot failed. Check GROQ_API_KEY."),
        )
