"""
Garudatva v3 — MonkeyRunner
Sends pseudo-random UI events for 120 seconds to trigger obfuscated payloads.
Fills input fields with realistic Indian PII to force malware data harvest paths.
"""

from __future__ import annotations

import asyncio
import random
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Realistic Indian PII for input fields — forces banking trojan harvest paths
INDIAN_PHONE_NUMBERS = [
    "9876543210", "8765432109", "7654321098",
    "9123456789", "8234567890", "7345678901",
]
INDIAN_EMAILS = [
    "ramesh.kumar@gmail.com", "priya.sharma@yahoo.co.in",
    "arun.patel@hotmail.com", "deepa.reddy@outlook.com",
]
INDIAN_NAMES = ["Ramesh Kumar", "Priya Sharma", "Arun Patel", "Deepa Reddy"]

# Approximate screen coordinates for Pixel 3a (1080x2220)
SCREEN_W, SCREEN_H = 1080, 2220


async def run_monkeyrunner(
    adb_serial: str,
    package_name: str,
    duration_seconds: int = 120,
    on_event=None,
) -> dict:
    """
    Emulate real user interaction for duration_seconds.
    Returns event stats.

    on_event: optional callable(action: str, detail: dict), invoked as each
    real ADB input event is sent — for real-time UI streaming (e.g. touch
    ripple / text-typing animation) rather than only a post-hoc summary.
    """
    logger.info(f"MonkeyRunner starting: {package_name} for {duration_seconds}s")

    stats = {
        "taps": 0, "swipes": 0, "text_inputs": 0,
        "keypresses": 0, "duration_seconds": duration_seconds,
    }

    deadline = asyncio.get_event_loop().time() + duration_seconds

    async def adb_input(cmd: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", adb_serial, "shell", f"input {cmd}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=5)

    while asyncio.get_event_loop().time() < deadline:
        action = random.choices(
            ["tap", "swipe", "text", "keypress", "scroll"],
            weights=[40, 20, 20, 10, 10],
        )[0]

        try:
            if action == "tap":
                x = random.randint(50, SCREEN_W - 50)
                y = random.randint(200, SCREEN_H - 200)
                await adb_input(f"tap {x} {y}")
                stats["taps"] += 1
                if on_event:
                    on_event("tap", {"x": x, "y": y})

            elif action == "swipe":
                x1 = random.randint(100, SCREEN_W - 100)
                y1 = random.randint(400, SCREEN_H - 400)
                direction = random.choice(["up", "down"])
                y2 = y1 - 500 if direction == "up" else y1 + 500
                y2 = max(100, min(y2, SCREEN_H - 100))
                await adb_input(f"swipe {x1} {y1} {x1} {y2} 300")
                stats["swipes"] += 1
                if on_event:
                    on_event("swipe", {"x1": x1, "y1": y1, "x2": x1, "y2": y2})

            elif action == "text":
                # Rotate through realistic Indian PII
                text = random.choice(
                    INDIAN_PHONE_NUMBERS + INDIAN_EMAILS + INDIAN_NAMES
                )
                # Escape spaces for shell
                text_escaped = text.replace(" ", "%s")
                await adb_input(f"text '{text_escaped}'")
                stats["text_inputs"] += 1
                if on_event:
                    on_event("text", {"length": len(text)})

            elif action == "keypress":
                key = random.choice([
                    "KEYCODE_BACK", "KEYCODE_HOME",
                    "KEYCODE_VOLUME_DOWN", "KEYCODE_VOLUME_UP",
                    "KEYCODE_ENTER", "KEYCODE_TAB",
                ])
                await adb_input(f"keyevent {key}")
                stats["keypresses"] += 1
                if on_event:
                    on_event("keypress", {"key": key})

            elif action == "scroll":
                x = SCREEN_W // 2
                y1 = random.randint(SCREEN_H // 3, 2 * SCREEN_H // 3)
                await adb_input(f"swipe {x} {y1} {x} {y1 - 300} 200")
                stats["swipes"] += 1
                if on_event:
                    on_event("scroll", {"x": x, "y1": y1, "y2": y1 - 300})

        except asyncio.TimeoutError:
            pass   # Input command timed out — continue
        except Exception as e:
            logger.debug(f"MonkeyRunner event error: {e}")

        await asyncio.sleep(random.uniform(0.3, 1.2))

    logger.info(f"MonkeyRunner complete: {stats}")
    return stats
