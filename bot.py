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
    application.add_error_handler(error_handler)

    logger.info("Bot is starting polling...")
    application.run_polling()


if __name__ == "__main__":
    main()
