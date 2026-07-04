"""
Garudatva v3 — Ollama Client
Wrapper around local Ollama API.
Primary: qwen2.5:7b-instruct-q4_K_M
Fallback: mistral:7b-instruct-v0.3-q4_K_M
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import httpx

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


async def _call_ollama(prompt: str, system: str, model: str) -> str:
    """Raw Ollama API call. Returns generated text."""
    async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT) as client:
        response = await client.post(
            f"{settings.OLLAMA_BASE_URL}/api/chat",
            json={
                "model": model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
                "options": {
                    "temperature": 0.1,   # Low temp for factual court language
                    "num_ctx": 4096,
                },
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["message"]["content"]


async def generate_narrative(
    static=None,
    dynamic=None,
    cloud=None,
    graph=None,
    case=None,
) -> Dict[str, Any]:
    """
    Build prompt from verified artifacts and generate court narrative.
    Tries primary model, falls back to secondary.
    Validates output with narrative_validator.
    """
    from core.ai.prompt_builder import build_prompt
    from core.ai.narrative_validator import validate_narrative
    from core.ai.translation import generate_translation

    system_prompt, user_prompt = build_prompt(
        static=static, dynamic=dynamic,
        cloud=cloud, graph=graph, case=case,
    )

    text = ""
    for model in [settings.OLLAMA_MODEL, settings.OLLAMA_FALLBACK_MODEL]:
        try:
            logger.info(f"Generating narrative with {model}...")
            text = await _call_ollama(user_prompt, system_prompt, model)
            logger.info(f"Narrative generated: {len(text.split())} words")
            break
        except Exception as e:
            logger.warning(f"Ollama model {model} failed: {e}")

    if not text:
        text = _fallback_narrative(static, dynamic)
        logger.warning("All Ollama models failed — using fallback narrative")

    # Validate and regenerate up to 3 times if forbidden phrases found
    for attempt in range(3):
        violations = validate_narrative(text)
        if not violations:
            break
        logger.warning(f"Narrative attempt {attempt+1} has {len(violations)} violations: {violations[:3]}")
        stricter_prompt = user_prompt + (
            f"\n\nIMPORTANT: Remove these forbidden phrases from your response: "
            f"{', '.join(violations[:5])}. Use only verified facts."
        )
        try:
            text = await _call_ollama(stricter_prompt, system_prompt, settings.OLLAMA_MODEL)
        except Exception:
            break

    # Regional language summary
    translation = {}
    try:
        translation = await generate_translation(text)
    except Exception as e:
        logger.warning(f"Translation failed: {e}")

    return {
        "text": text,
        "word_count": len(text.split()),
        "translation": translation,
        "model_used": settings.OLLAMA_MODEL,
    }


def _fallback_narrative(static, dynamic) -> str:
    """Minimal factual narrative when LLM unavailable."""
    lines = ["FORENSIC ANALYSIS SUMMARY", ""]
    if static and static.risk_score:
        lines.append(
            f"Risk Score: {static.risk_score.total:.1f}/100 "
            f"({static.risk_score.tier})"
        )
    if static and static.manifest:
        lines.append(f"Package: {static.manifest.package_name}")
    if static and static.india_matches:
        lines.append(
            f"India Pattern Matches: "
            f"{', '.join(m.pattern_name for m in static.india_matches[:5])}"
        )
    lines.append("")
    lines.append("LLM narrative unavailable — see structured data in report sections.")
    return "\n".join(lines)
