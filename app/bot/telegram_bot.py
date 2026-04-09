"""
Telegram Bot
============
Commands:
    /start           - Welcome message
    /scan <domain>   - Trigger a scan
    /status <id>     - Scan status and stages
    /findings        - Recent findings
    /critical        - Critical open findings
    /help            - Show command list

The bot communicates with the platform API over HTTP.
All interactions are proxied through the API — the bot does not
directly access the database or execute tools.
"""
import os
import sys
import time
from typing import Optional

import telebot
import httpx

# Allow running as __main__
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from app.config import get_settings
from app.utils.logging import get_logger, setup_logging

setup_logging()
logger = get_logger(__name__)
settings = get_settings()

# Resolve API base URL — defaults to localhost when running outside Docker
API_BASE = os.environ.get("API_BASE_URL", "http://localhost:8000/api/v1")

bot = telebot.TeleBot(settings.telegram_bot_token, parse_mode="Markdown")


# ─── Auth guard ──────────────────────────────────────────────────────────────

def is_authorized(user_id: int) -> bool:
    """Check if user is in the allowed list. Empty list = allow all."""
    allowed = settings.allowed_telegram_users
    return not allowed or user_id in allowed


def authorized_only(func):
    """Decorator to reject unauthorized users."""
    def wrapper(message):
        if not is_authorized(message.from_user.id):
            bot.reply_to(message, "⛔ Unauthorized.")
            logger.warning("Unauthorized access attempt", user_id=message.from_user.id)
            return
        return func(message)
    return wrapper


# ─── API helpers ─────────────────────────────────────────────────────────────

def api_get(path: str) -> Optional[dict | list]:
    try:
        r = httpx.get(f"{API_BASE}{path}", timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error("API GET failed", path=path, error=str(e))
        return None


def api_post(path: str, data: dict) -> Optional[dict]:
    try:
        r = httpx.post(f"{API_BASE}{path}", json=data, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error("API POST failed", path=path, error=str(e))
        return None


def sev_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(sev, "⚪")


def status_emoji(status: str) -> str:
    return {"pending": "⏳", "running": "🔄", "completed": "✅", "failed": "❌", "cancelled": "🚫"}.get(status, "❓")


# ─── Commands ────────────────────────────────────────────────────────────────

@bot.message_handler(commands=["start", "help"])
@authorized_only
def cmd_help(message):
    text = (
        "🔍 *Bug Bounty Platform Bot*\n\n"
        "Available commands:\n\n"
        "`/scan <domain>` — Start a scan\n"
        "`/status <scan_id>` — Scan status and stages\n"
        "`/findings` — Recent findings\n"
        "`/critical` — Critical finding feed\n"
        "`/cancel <scan_id>` — Cancel a running scan\n"
        "`/help` — Show this message\n\n"
        "_All scans are analyst-assisted. No autonomous exploitation is performed._"
    )
    bot.reply_to(message, text)


@bot.message_handler(commands=["scan"])
@authorized_only
def cmd_scan(message):
    parts = message.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        bot.reply_to(message, "Usage: `/scan <domain>`\nExample: `/scan example.com`")
        return

    domain = parts[1].strip().lower()
    bot.reply_to(message, f"⏳ Starting scan for `{domain}`...")

    payload = {
        "domain": domain,
        "options": {
            "run_ffuf": False,
            "run_gowitness": True,
            "nuclei_severity": "medium,high,critical",
            "timeout": 3600,
        },
    }

    result = api_post("/scans", payload)
    if not result:
        bot.reply_to(message, "❌ Failed to start scan. Check API connectivity.")
        return

    scan_id = result["id"]
    text = (
        f"✅ *Scan triggered*\n\n"
        f"*Domain:* `{domain}`\n"
        f"*Scan ID:* `{scan_id}`\n"
        f"*Status:* {status_emoji('pending')} pending\n\n"
        f"Use `/report {scan_id}` once completed."
    )
    bot.reply_to(message, text)
    logger.info("Scan triggered via Telegram", domain=domain, scan_id=scan_id,
                user_id=message.from_user.id)


@bot.message_handler(commands=["status"])
@authorized_only
def cmd_status(message):
    parts = message.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Usage: `/status <scan_id>`")
        return
    scan_id = parts[1].strip()
    scan = api_get(f"/scans/{scan_id}")
    stages = api_get(f"/scans/{scan_id}/stages") or []
    if not scan:
        bot.reply_to(message, "❌ Scan not found.")
        return

    lines = [
        f"📋 *Scan Status*\n",
        f"ID: `{scan_id[:8]}...`",
        f"Status: {status_emoji(scan['status'])} {scan['status']}",
        f"Assets: {scan.get('assets_found', 0)} | Findings: {scan.get('findings_count', 0)}",
        "",
        "*Stages:*",
    ]
    for st in stages:
        lines.append(f"- `{st['stage_type']}`: {st['status']} (attempt {st['attempt']})")
    bot.reply_to(message, "\n".join(lines))


@bot.message_handler(commands=["findings"])
@authorized_only
def cmd_findings(message):
    findings = api_get("/findings?limit=20")
    if findings is None:
        bot.reply_to(message, "❌ Failed to fetch findings.")
        return
    if not findings:
        bot.reply_to(message, "No findings in this window.")
        return

    lines = [f"🔍 *Recent Findings* ({len(findings)} shown)\n"]
    for f in findings:
        emoji = sev_emoji(f["severity"])
        validated = "✅" if f.get("is_validated") else ""
        fp = "🚫FP" if f.get("false_positive") else ""
        lines.append(f"{emoji} {validated}{fp} `{f['category']}` — {f['title'][:50]}")

    bot.reply_to(message, "\n".join(lines))


@bot.message_handler(commands=["critical"])
@authorized_only
def cmd_critical(message):
    findings = api_get("/findings?severity=critical&limit=20")
    if findings is None:
        bot.reply_to(message, "❌ Failed to fetch critical findings.")
        return
    if not findings:
        bot.reply_to(message, "No critical findings.")
        return
    lines = ["🚨 *Critical Findings*\n"]
    for f in findings:
        lines.append(f"🔴 `{f['scan_id'][:8]}...` {f['title'][:70]}")
    bot.reply_to(message, "\n".join(lines))


@bot.message_handler(commands=["cancel"])
@authorized_only
def cmd_cancel(message):
    parts = message.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Usage: `/cancel <scan_id>`")
        return

    scan_id = parts[1].strip()
    try:
        r = httpx.delete(f"{API_BASE}/scans/{scan_id}", timeout=10)
        if r.status_code == 204:
            bot.reply_to(message, f"✅ Scan `{scan_id[:8]}...` cancelled.")
        elif r.status_code == 404:
            bot.reply_to(message, "❌ Scan not found.")
        else:
            bot.reply_to(message, f"❌ Failed to cancel: HTTP {r.status_code}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not settings.telegram_bot_token:
        logger.error("TELEGRAM_BOT_TOKEN is not set. Bot cannot start.")
        sys.exit(1)

    logger.info("Telegram bot starting", api_base=API_BASE)
    # Retry loop in case API isn't up yet
    for attempt in range(10):
        try:
            bot.infinity_polling(timeout=30, long_polling_timeout=20)
            break
        except Exception as e:
            logger.warning("Bot polling error, retrying", error=str(e), attempt=attempt)
            time.sleep(5)
