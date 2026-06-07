import asyncio
import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from database import init_db, close_db, run_migrations
from routers import analyze, analyses
from routers.auth import router as auth_router
from ws_manager import active_connections


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await run_migrations()
    yield
    await close_db()


app = FastAPI(title="Vultron v4", lifespan=lifespan)

_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
]
if _frontend_url := os.getenv("FRONTEND_URL"):
    _origins.append(_frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=r"https://.*\.(vercel|netlify)\.app",
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api")
app.include_router(analyses.router, prefix="/api")
app.include_router(auth_router)


@app.websocket("/ws/analysis/{job_id}")
async def analysis_websocket(websocket: WebSocket, job_id: str):
    await websocket.accept()
    active_connections[job_id] = websocket
    try:
        while job_id in active_connections:
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    finally:
        active_connections.pop(job_id, None)


async def _ping_groq() -> bool:
    key = os.getenv("GROQ_API_KEY", "")
    if not key:
        return False
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            return r.status_code == 200
    except Exception:
        return False


@app.get("/api/health")
async def health():
    groq_ok = await _ping_groq()
    return {
        "status": "ok",
        "service": "Vultron v4",
        "groq": "ok" if groq_ok else "error",
        "db": "configured" if os.getenv("DATABASE_URL") else "missing",
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print(f"Vultron v4 backend running on port {port}")
    if not os.getenv("GROQ_API_KEY"):
        print("WARNING: GROQ_API_KEY is not set — AI features will fail")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
