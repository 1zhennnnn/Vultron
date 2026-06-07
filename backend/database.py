import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, Optional, Tuple

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, select, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker


def _make_url() -> Tuple[Optional[str], Dict]:
    """Return (asyncpg-compatible URL, connect_args dict).

    asyncpg does not accept psycopg2-style query parameters like sslmode or
    channel_binding.  Strip them from the URL and translate sslmode=require
    into connect_args={"ssl": True} instead.
    """
    url = os.getenv("DATABASE_URL", "")
    if not url:
        return None, {}

    needs_ssl = bool(re.search(r"sslmode=(require|verify-full|verify-ca)", url))

    # Remove parameters asyncpg cannot handle
    url = re.sub(r"[?&]sslmode=[^&]*", "", url)
    url = re.sub(r"[?&]channel_binding=[^&]*", "", url)
    url = re.sub(r"\?$", "", url)  # drop dangling '?'

    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    connect_args: Dict = {"ssl": True} if needs_ssl else {}
    return url, connect_args


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    analyses = relationship("AnalysisRecord", back_populates="user")


class ContractRecord(Base):
    __tablename__ = "contracts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    code_hash = Column(String(64), unique=True, index=True)
    solidity_version = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    analyses = relationship("AnalysisRecord", back_populates="contract", cascade="all, delete-orphan")


class AnalysisRecord(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    contract_id = Column(Integer, ForeignKey("contracts.id"), nullable=False)
    security_score = Column(Integer, nullable=False)
    risk_level = Column(String(50), nullable=False)
    vuln_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    slither_success = Column(Boolean, default=False)
    total_ms = Column(Integer, default=0)
    hallucination_rate = Column(Float, default=0.0)
    consensus_rate     = Column(Float,   default=0.0)
    high_conf_paths    = Column(Integer, default=0)
    low_conf_paths     = Column(Integer, default=0)
    slither_ms         = Column(Integer, default=0)
    groq_ms            = Column(Integer, default=0)
    engine             = Column(String(50), nullable=True)
    complexity_score = Column(Integer, nullable=True)
    complexity_level = Column(String(10), nullable=True)
    summary = Column(Text, nullable=True)
    attack_strategy_json = Column(Text, nullable=True)
    defense_recs_json = Column(Text, nullable=True)
    score_explanation = Column(Text, nullable=True)
    causal_paths_json = Column(Text, nullable=True)
    critical_path_id = Column(Text, nullable=True)
    poc_script = Column(Text, nullable=True)
    analyzed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    contract = relationship("ContractRecord", back_populates="analyses")
    user     = relationship("User", back_populates="analyses")
    vulnerabilities = relationship(
        "VulnerabilityRecord", back_populates="analysis", cascade="all, delete-orphan"
    )


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    vuln_id = Column(String(50), nullable=False)
    type = Column(String(100), nullable=False)
    function = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=True)
    exploitability_score = Column(Integer, nullable=True)
    exploitability_level = Column(String(10), nullable=True)

    analysis = relationship("AnalysisRecord", back_populates="vulnerabilities")


_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        url, connect_args = _make_url()
        if url:
            _engine = create_async_engine(
                url, echo=False, pool_pre_ping=True, connect_args=connect_args
            )
    return _engine


def _get_factory():
    global _session_factory
    engine = _get_engine()
    if _session_factory is None and engine is not None:
        _session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return _session_factory


async def init_db():
    engine = _get_engine()
    if engine is None:
        print("WARNING: DATABASE_URL not set — skipping database initialization")
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables initialized")


_MIGRATIONS = [
    # contracts table
    "ALTER TABLE contracts ADD COLUMN IF NOT EXISTS solidity_version    VARCHAR(20)",
    # analyses table — new columns added across v4 rounds
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS user_id              INTEGER REFERENCES users(id) ON DELETE SET NULL",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS consensus_rate       FLOAT   DEFAULT 0.0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS high_conf_paths      INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS low_conf_paths       INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS slither_ms           INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS groq_ms              INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS engine               VARCHAR(50)",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS complexity_score     INTEGER",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS complexity_level     VARCHAR(10)",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS summary              TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS attack_strategy_json TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS defense_recs_json    TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS score_explanation    TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS causal_paths_json    TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS critical_path_id     TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS poc_script           TEXT",
]


async def run_migrations():
    from sqlalchemy import text
    engine = _get_engine()
    if engine is None:
        return
    try:
        async with engine.begin() as conn:
            for sql in _MIGRATIONS:
                await conn.execute(text(sql))
        print("Migrations applied")
    except Exception as e:
        print(f"Migration warning (non-fatal): {e}")


async def close_db():
    """Gracefully dispose the asyncpg connection pool.
    Call this from FastAPI lifespan shutdown to avoid abrupt disconnections on Neon.
    """
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        print("Database connection pool closed")


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    factory = _get_factory()
    if factory is None:
        raise RuntimeError("Database not configured — DATABASE_URL missing")
    async with factory() as session:
        yield session


async def save_analysis(result: dict, code: str, user_id: Optional[int] = None) -> Optional[int]:
    factory = _get_factory()
    if factory is None:
        return

    try:
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        async with factory() as session:
            stmt = select(ContractRecord).where(ContractRecord.code_hash == code_hash)
            contract = (await session.execute(stmt)).scalar_one_or_none()
            if contract is None:
                contract = ContractRecord(
                    name=result["contractName"],
                    code_hash=code_hash,
                    solidity_version=result.get("solidity_version"),
                )
                session.add(contract)
                await session.flush()
            else:
                contract.name = result["contractName"]  # allow rename on re-analysis

            vulns = result.get("vulnerabilities", [])
            perf = result.get("performance", {})
            hall = result.get("hallucination", {})

            complexity = result.get("complexity", {})
            attack_strategy  = result.get("attackStrategy")
            defense_recs     = result.get("defenseRecommendations")
            causal_paths     = result.get("causalPaths")
            poc_script       = result.get("pocScript")
            analysis = AnalysisRecord(
                contract_id=contract.id,
                user_id=user_id,
                security_score=result["securityScore"],
                risk_level=result["riskLevel"],
                vuln_count=len(vulns),
                critical_count=sum(1 for v in vulns if v.get("severity") == "critical"),
                high_count=sum(1 for v in vulns if v.get("severity") == "high"),
                slither_success=result.get("slitherSuccess", False),
                total_ms=perf.get("total_ms", 0),
                hallucination_rate=hall.get("hallucination_rate", 0.0),
                consensus_rate=result.get("consensus", {}).get("consensus_rate", 0.0),
                high_conf_paths=result.get("consensus", {}).get("high_confidence_paths", 0),
                low_conf_paths=result.get("consensus", {}).get("low_confidence_paths", 0),
                slither_ms=perf.get("slither_ms", 0),
                groq_ms=perf.get("groq_ms", 0),
                engine="groq/llama-3.1-8b-instant",
                complexity_score=complexity.get("complexity_score"),
                complexity_level=complexity.get("complexity_level"),
                summary=result.get("summary") or None,
                attack_strategy_json=json.dumps(attack_strategy) if attack_strategy else None,
                defense_recs_json=json.dumps(defense_recs) if defense_recs else None,
                score_explanation=result.get("scoreExplanation") or None,
                causal_paths_json=json.dumps(causal_paths) if causal_paths else None,
                critical_path_id=result.get("criticalPathId"),
                poc_script=poc_script or None,
            )
            session.add(analysis)
            await session.flush()

            for v in vulns:
                session.add(VulnerabilityRecord(
                    analysis_id=analysis.id,
                    vuln_id=v.get("id", ""),
                    type=v.get("type", ""),
                    function=v.get("function", ""),
                    severity=v.get("severity", ""),
                    description=v.get("description", ""),
                    line_number=v.get("lineNumber"),
                    exploitability_score=v.get("exploitability_score"),
                    exploitability_level=v.get("exploitability_level"),
                ))

            await session.commit()
            return analysis.id
    except Exception as e:
        print(f"DB save failed (non-fatal): {e}")
    return None
