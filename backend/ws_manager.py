import logging
from typing import Dict, Optional

from fastapi import WebSocket

logger = logging.getLogger(__name__)

active_connections: Dict[str, WebSocket] = {}


async def send_progress(
    job_id: Optional[str],
    step: int,
    total: int,
    message: str,
    status: str = "running",
) -> None:
    if not job_id:
        return
    ws = active_connections.get(job_id)
    if ws:
        try:
            await ws.send_json({
                "step": step,
                "total": total,
                "message": message,
                "status": status,
                "percent": round(step / total * 100),
            })
        except Exception as _e:
            active_connections.pop(job_id, None)
            logger.debug(f"WebSocket {job_id} disconnected: {_e}")
