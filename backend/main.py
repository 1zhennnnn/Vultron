import asyncio
import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from database import init_db
from routers import analyze, analyses
from ws_manager import active_connections


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Vultron v3", lifespan=lifespan)

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
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api")
app.include_router(analyses.router, prefix="/api")


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


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "Vultron v3",
        "groq": "configured" if os.getenv("GROQ_API_KEY") else "missing",
        "db": "configured" if os.getenv("DATABASE_URL") else "missing",
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print(f"Vultron v3 backend running on port {port}")
    if not os.getenv("GROQ_API_KEY"):
        print("WARNING: GROQ_API_KEY is not set — AI features will fail")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
