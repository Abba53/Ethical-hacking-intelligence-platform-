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
from collectors.rss_collector import collect_all_feeds, save_entries_to_db
from collectors.threat_feed_collector import collect_threat_feeds, save_threatfox_to_db, save_chainabuse_to_db
from extractors.ioc_extractor import process_rss_entries
from extractors.ioc_lookup import lookup_ioc
from tools.blockchain_forensics import investigate_wallet

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
    """Handles /feeds — collects RSS feeds and saves new entries to database."""
    user = update.effective_user
    logger.info("Received /feeds from user_id=%s", user.id)

    await update.message.reply_text("🔄 Collecting feeds, please wait...")

    entries = await collect_all_feeds()

    if not entries:
        await update.message.reply_text(
            "⚠️ No entries collected. Check logs for feed errors."
        )
        return

    summary = save_entries_to_db(entries)

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["source_url"]] = counts.get(entry["source_url"], 0) + 1

    lines = [
        f"✅ Feeds collected: {len(entries)} total entries\n"
        f"💾 New to database: {summary['inserted']} | "
        f"Already seen: {summary['skipped']}\n"
    ]

    for source_url, count in counts.items():
        lines.append(f"• {source_url} — {count} entries")

    if summary["inserted"] > 0:
        lines.append("\n📰 Recent new headlines:")
        new_entries = [e for e in entries if e["link"] not in []]
        for entry in entries[:3]:
            lines.append(f"- {entry['title']}")

    await update.message.reply_text("\n".join(lines))

async def threats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /threats — fetches threat intel and saves to database."""
    user = update.effective_user
    logger.info("Received /threats from user_id=%s", user.id)

    await update.message.reply_text("🔄 Fetching threat intelligence, please wait...")

    results = await collect_threat_feeds()
    tf_summary = save_threatfox_to_db(results["threatfox"])
    ca_summary = save_chainabuse_to_db(results["chainabuse"])

    lines = [
        f"✅ ThreatFox: {len(results['threatfox'])} IOCs fetched\n"
        f"💾 New: {tf_summary['inserted']} | "
        f"Already seen: {tf_summary['skipped']}\n"
    ]

    if results["threatfox"]:
        lines.append("Recent IOCs:")
        for ioc in results["threatfox"][:5]:
            lines.append(f"- [{ioc['ioc_type']}] {ioc['ioc']} ({ioc['malware']})")

    lines.append(
        f"\n✅ Chainabuse: {len(results['chainabuse'])} report(s) | "
        f"New: {ca_summary['inserted']}"
    )

    await update.message.reply_text("\n".join(lines))

async def extract_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /extract — runs IOC extraction on unprocessed RSS entries."""
    user = update.effective_user
    logger.info("Received /extract from user_id=%s", user.id)

    await update.message.reply_text("🔍 Running IOC extraction on new articles...")

    import asyncio
    loop = asyncio.get_event_loop()
    summary = await loop.run_in_executor(None, process_rss_entries, 50)

    lines = [
        f"✅ IOC Extraction complete\n",
        f"📄 Articles processed: {summary['entries_processed']}",
        f"🎯 New IOCs extracted: {summary['extracted']}",
        f"⏭️ Duplicates skipped: {summary['skipped']}",
    ]

    if summary["extracted"] == 0 and summary["entries_processed"] == 0:
        lines.append("\n(No new unprocessed articles — run /feeds first)")

    await update.message.reply_text("\n".join(lines))

async def lookup_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /lookup <value> — universal IOC lookup across local DB and live APIs."""
    user = update.effective_user
    logger.info("Received /lookup from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /lookup <ioc_value>\n"
            "Examples:\n"
            "  /lookup 192.168.1.1\n"
            "  /lookup CVE-2026-12345\n"
            "  /lookup malware.example.com\n"
            "  /lookup 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        )
        return

    value = " ".join(context.args).strip()
    await update.message.reply_text(f"🔍 Looking up: {value}")

    result = await lookup_ioc(value)
    ioc_type = result["ioc_type"]
    local = result["local"]
    chainabuse = result["chainabuse"]

    lines = [f"📋 IOC Lookup Results\n"]
    lines.append(f"Value: {value}")
    lines.append(f"Type:  {ioc_type}\n")

    # ThreatFox local matches
    tf_hits = local["threatfox"]
    if tf_hits:
        lines.append(f"⚠️ ThreatFox: {len(tf_hits)} match(es)")
        for hit in tf_hits[:3]:
            lines.append(
                f"  • {hit['malware']} | {hit['threat_type']} | "
                f"confidence: {hit['confidence_level']}%"
            )
            lines.append(f"    first seen: {hit['first_seen']}")
    else:
        lines.append("✅ ThreatFox: not found in local DB")

    # Extracted IOCs local matches
    ex_hits = local["extracted"]
    if ex_hits:
        lines.append(f"\n⚠️ Found in {len(ex_hits)} collected article(s)")
        for hit in ex_hits[:3]:
            lines.append(f"  • entry_id={hit['source_entry_id']} | {hit['extracted_at'][:19]}")
    else:
        lines.append("\n✅ Not found in extracted IOCs")

    # Chainabuse (crypto addresses only)
    if ioc_type in ("eth_address", "sol_address"):
        if chainabuse:
            lines.append(f"\n🚨 Chainabuse: {len(chainabuse)} report(s)")
            for r in chainabuse[:3]:
                lines.append(f"  • [{r['category']}] {r['description'][:60]}")
        else:
            lines.append("\n✅ Chainabuse: no reports found")

    if ioc_type == "unknown":
        lines.append("\n⚠️ Could not detect IOC type — check the value format.")

    await update.message.reply_text("\n".join(lines))

async def walletinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /walletinfo <address> — blockchain forensics for EVM and Solana."""
    user = update.effective_user
    logger.info("Received /walletinfo from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /walletinfo <wallet_address>\n"
            "Examples:\n"
            "  /walletinfo 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n"
            "  /walletinfo GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ"
        )
        return

    address = " ".join(context.args).strip()
    await update.message.reply_text(f"🔍 Investigating wallet: {address[:20]}...")

    result = await investigate_wallet(address)

    if "error" in result:
        error = result["error"]
        if error == "unsupported_type":
            await update.message.reply_text(
                f"⚠️ {result['message']}"
            )
        elif error == "no_api_key":
            await update.message.reply_text(
                "⚠️ Helius API key not configured. Check .env file."
            )
        elif error == "timeout":
            await update.message.reply_text(
                "⚠️ Request timed out. Try again in a moment."
            )
        else:
            await update.message.reply_text(
                f"⚠️ Lookup failed: {error}"
            )
        return

    chain = result.get("chain", "unknown")
    lines = [f"🔗 Wallet Forensics ({chain.upper()})\n"]
    lines.append(f"Address: {address[:20]}...{address[-6:]}\n")

    if chain == "ethereum":
        lines.append(f"💰 ETH Balance: {result['eth_balance']:.6f} ETH")
        lines.append(f"🪙 Token Holdings: {result['token_count']}")
        if result["tokens"]:
            lines.append("\nTop tokens:")
            for token in result["tokens"][:3]:
                lines.append(f"  • {token['name']} ({token['symbol']})")

    elif chain == "solana":
        lines.append(f"📊 Recent transactions: {result['tx_count_returned']}")
        txs = result.get("recent_transactions", [])
        if txs:
            lines.append("\nRecent activity:")
            for tx in txs[:5]:
                tx_type = tx["type"]
                desc = tx["description"]
                if desc:
                    lines.append(f"  • {tx_type}: {desc[:50]}")
                else:
                    lines.append(f"  • {tx_type}")

    await update.message.reply_text("\n".join(lines))

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
    application.add_handler(CommandHandler("extract", extract_command))
    application.add_handler(CommandHandler("lookup", lookup_command))
    application.add_handler(CommandHandler("walletinfo", walletinfo_command))
    application.add_error_handler(error_handler)

    logger.info("Bot is starting polling...")
    application.run_polling()


if __name__ == "__main__":
    main()
