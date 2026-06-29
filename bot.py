"""
bot.py

Entry point for the platform's Telegram bot.
Currently implements:
  - /start command handler
  - /status command handler
  - global error handler (Phase 4.5)
Future phases will add: alert delivery, IOC lookup commands, etc.
"""

import logging
import os
import time

from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from collectors.rss_collector import collect_all_feeds
from collectors.threat_feed_collector import collect_threat_feeds

# Configure basic logging so we can see what the bot is doing as it runs.
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Silence verbose third-party HTTP libraries.
# These can log full request URLs, and Telegram's Bot API embeds the
# bot token directly in the URL path — so verbose logging here would
# leak the token into our logs/terminal. WARNING level only shows real
# problems, never routine request URLs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Load variables from .env into the process environment.
load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# Record when the bot process started, so /status can report uptime.
START_TIME = time.time()


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /start command sent by a user."""
    user = update.effective_user
    logger.info("Received /start from user_id=%s", user.id)

    await update.message.reply_text(
        f"Hello {user.first_name}! Your Ethical Hacking Intel bot is online."
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /status command — reports bot uptime."""
    user = update.effective_user
    logger.info("Received /status from user_id=%s", user.id)

    uptime_seconds = int(time.time() - START_TIME)
    minutes, seconds = divmod(uptime_seconds, 60)
    hours, minutes = divmod(minutes, 60)

    await update.message.reply_text(
        f"✅ Bot is online.\n"
        f"Uptime: {hours}h {minutes}m {seconds}s"
    )

async def feeds_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /feeds command — triggers a live RSS collection run."""
    user = update.effective_user
    logger.info("Received /feeds from user_id=%s", user.id)

    await update.message.reply_text("🔄 Collecting feeds, please wait...")

    entries = await collect_all_feeds()

    if not entries:
        await update.message.reply_text(
            "⚠️ No entries were collected. Check logs for feed errors."
        )
        return

    # Count entries per source for the summary.
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["source_url"]] = counts.get(entry["source_url"], 0) + 1

    summary_lines = [f"✅ Collected {len(entries)} total entries:\n"]
    for source_url, count in counts.items():
        summary_lines.append(f"• {source_url} — {count} entries")

    summary_lines.append("\n📰 Most recent headlines:")
    for entry in entries[:5]:
        summary_lines.append(f"- {entry['title']}")

    await update.message.reply_text("\n".join(summary_lines))

async def threats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /threats command — fetches structured threat intel (Phase 6.5)."""
    user = update.effective_user
    logger.info("Received /threats from user_id=%s", user.id)

    await update.message.reply_text("🔄 Fetching threat intelligence, please wait...")

    results = await collect_threat_feeds()
    threatfox_iocs = results["threatfox"]
    chainabuse_reports = results["chainabuse"]

    summary_lines = [
        f"✅ ThreatFox: {len(threatfox_iocs)} IOCs (last 24h)\n",
    ]

    if threatfox_iocs:
        summary_lines.append("Recent IOCs:")
        for ioc in threatfox_iocs[:5]:
            summary_lines.append(
                f"- [{ioc['ioc_type']}] {ioc['ioc']} ({ioc['malware']})"
            )

    summary_lines.append(
        f"\n✅ Chainabuse test screening: {len(chainabuse_reports)} report(s) found"
    )

    await update.message.reply_text("\n".join(summary_lines))

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Global error handler. PTB calls this automatically whenever any
    registered handler raises an unhandled exception.
    """
    logger.error(
        "Unhandled exception while processing update: %s",
        context.error,
        exc_info=context.error,
    )

    # Try to notify the user, but don't let a failure here crash anything —
    # 'update' might not always be a normal message update.
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(
            "⚠️ Something went wrong processing your request. "
            "This has been logged."
        )


def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN is not set. Check your .env file."
        )

    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("feeds", feeds_command))
    application.add_handler(CommandHandler("threats", threats_command))
    application.add_error_handler(error_handler)

    logger.info("Bot is starting polling...")
    application.run_polling()


if __name__ == "__main__":
    main()
