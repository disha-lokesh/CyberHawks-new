"""
Garudatva v3 — Per-analysis live event bus.

Stage-level progress (STATIC_TRIAGE done, DYNAMIC_ANALYSIS running, ...) is
already reported by AnalysisStatus/pipeline.py. This module carries the
finer-grained, real-time events produced *during* dynamic analysis — Frida
hook messages, MonkeyRunner UI actions, permission dialogs — from wherever
they're generated (often a non-asyncio thread, e.g. Frida's own callback
thread) to the SSE stream in api/analysis.py, without polling.

Usage:
    publish(analysis_id, {"type": "network_event", "data": {...}})   # any thread
    async for event in subscribe(analysis_id): ...                  # SSE handler
"""

from __future__ import annotations

import asyncio
import time
from typing import AsyncGenerator, Dict

from utils.logger import get_logger

logger = get_logger(__name__)

# One asyncio.Queue per in-flight analysis_id, plus the loop that owns it so
# publish() can hand events across from non-asyncio threads safely.
_queues: Dict[str, "asyncio.Queue"] = {}
_loops: Dict[str, asyncio.AbstractEventLoop] = {}


def open_stream(analysis_id: str) -> None:
    """
    Call once when a pipeline run starts, from within the event loop that
    will actually serve it. Uses get_running_loop() (not get_event_loop())
    deliberately — it raises immediately if there's no loop running yet,
    instead of silently capturing an unrelated loop that a later
    call_soon_threadsafe would schedule onto and never execute.
    """
    _queues[analysis_id] = asyncio.Queue(maxsize=2000)
    _loops[analysis_id] = asyncio.get_running_loop()


def close_stream(analysis_id: str) -> None:
    _queues.pop(analysis_id, None)
    _loops.pop(analysis_id, None)


def publish(analysis_id: str, event: dict) -> None:
    """
    Publish one event. Safe to call from any thread (e.g. Frida's own
    message-dispatch thread) — schedules the queue put on the owning loop.
    """
    queue = _queues.get(analysis_id)
    loop = _loops.get(analysis_id)
    if queue is None or loop is None:
        return  # no subscriber ever opened a stream for this job — drop
    event.setdefault("ts", time.time())

    def _put():
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning(f"Event queue full for {analysis_id}, dropping event")

    try:
        loop.call_soon_threadsafe(_put)
    except RuntimeError:
        pass  # loop already closed (job finished) — nothing to deliver to


async def subscribe(analysis_id: str) -> AsyncGenerator[dict, None]:
    """Yield events for analysis_id as they're published, until the stream closes."""
    queue = _queues.get(analysis_id)
    if queue is None:
        return
    while analysis_id in _queues:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=1.0)
            yield event
        except asyncio.TimeoutError:
            continue
