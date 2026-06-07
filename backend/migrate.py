"""
One-shot migration: add columns that were added to AnalysisRecord after initial deployment.
Safe to run multiple times — uses ADD COLUMN IF NOT EXISTS.
"""
import asyncio
import os
import re
from dotenv import load_dotenv

load_dotenv()

MIGRATIONS = [
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS consensus_rate    FLOAT   DEFAULT 0.0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS high_conf_paths   INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS low_conf_paths    INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS slither_ms        INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS groq_ms           INTEGER DEFAULT 0",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS engine            VARCHAR(50)",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS complexity_score  INTEGER",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS complexity_level  VARCHAR(10)",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS summary           TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS attack_strategy_json TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS defense_recs_json TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS score_explanation TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS causal_paths_json TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS critical_path_id  TEXT",
    "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS poc_script        TEXT",
]


def _make_url() -> str:
    url = os.getenv("DATABASE_URL", "")
    url = re.sub(r"[?&]sslmode=[^&]*", "", url)
    url = re.sub(r"[?&]channel_binding=[^&]*", "", url)
    url = re.sub(r"\?$", "", url)
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def run():
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy import text

    url = _make_url()
    engine = create_async_engine(url, connect_args={"ssl": True})

    async with engine.begin() as conn:
        for sql in MIGRATIONS:
            print(f"  → {sql[:60]}...")
            await conn.execute(text(sql))

    await engine.dispose()
    print("Migration complete.")


if __name__ == "__main__":
    asyncio.run(run())
