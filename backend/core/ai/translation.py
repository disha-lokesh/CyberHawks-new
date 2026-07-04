"""
Garudatva v3 — Regional Language Translation
Generates Kannada and Hindi summaries of findings.
Appended to PDF for field officer use — officers may not read technical English.
Uses Ollama with translation prompt.
"""

from __future__ import annotations

from typing import Dict
from utils.logger import get_logger

logger = get_logger(__name__)

TRANSLATION_SYSTEM = """You are a forensic translator for Indian law enforcement.
Translate the provided English forensic summary into simple, clear Kannada and Hindi.
Use plain language suitable for a field police officer, not a technical expert.
Keep legal terms (FIR, APK, malware, OTP, UPI) in English as they are commonly understood.
Return ONLY the translations in this exact format:

KANNADA:
[Kannada translation here]

HINDI:
[Hindi translation here]"""


async def generate_translation(english_narrative: str) -> Dict[str, str]:
    """Generate Kannada and Hindi summaries from the English narrative."""
    from config import settings
    import httpx

    # Take first 500 words to keep within context limits
    summary_text = " ".join(english_narrative.split()[:500])

    prompt = f"Translate this forensic summary:\n\n{summary_text}"

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{settings.OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": TRANSLATION_SYSTEM},
                        {"role": "user",   "content": prompt},
                    ],
                    "options": {"temperature": 0.2},
                },
            )
            response.raise_for_status()
            text = response.json()["message"]["content"]

        # Parse Kannada and Hindi sections
        kannada, hindi = "", ""
        if "KANNADA:" in text:
            parts = text.split("KANNADA:")[1]
            if "HINDI:" in parts:
                kannada = parts.split("HINDI:")[0].strip()
                hindi = parts.split("HINDI:")[1].strip()
            else:
                kannada = parts.strip()

        return {"kannada": kannada, "hindi": hindi}

    except Exception as e:
        logger.warning(f"Translation failed: {e}")
        return {"kannada": "", "hindi": ""}
