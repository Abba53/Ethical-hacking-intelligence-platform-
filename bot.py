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
from telegram.request import HTTPXRequest
from collectors.rss_collector import collect_all_feeds, save_entries_to_db
from collectors.threat_feed_collector import collect_threat_feeds, save_threatfox_to_db, save_chainabuse_to_db
from extractors.ioc_extractor import process_rss_entries
from extractors.ioc_lookup import lookup_ioc
from tools.blockchain_forensics import investigate_wallet
from tools.network_security import investigate_network
from services.active.auth import authorize_target, deauthorize_target, is_authorized
from services.active.recon_service import ReconService
from services.active.network_scan_service import NetworkScanService
from services.active.web_service import WebService
from services.active.webapp_service import WebAppService
from scoring.threat_scorer import process_unscored_iocs, get_top_threats
from workflows.ai_workflow import AIWorkflow
from analysis.formatting import format_list_item
from pathlib import Path
from workflows.report_workflow import ReportWorkflow

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
                    lines.append(f"  • {format_list_item(tx_type)}")

    await update.message.reply_text("\n".join(lines))

async def netinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /netinfo <ip_or_domain> — network security investigation."""
    user = update.effective_user
    logger.info("Received /netinfo from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /netinfo <ip_or_domain>\n"
            "Examples:\n"
            "  /netinfo 8.8.8.8\n"
            "  /netinfo malware.example.com"
        )
        return

    value = " ".join(context.args).strip()
    await update.message.reply_text(f"🔍 Investigating: {value}")

    result = await investigate_network(value)

    if "error" in result:
        await update.message.reply_text(f"⚠️ {result.get('message', result['error'])}")
        return

    ioc_type = result["ioc_type"]
    geo = result["geo"]
    abuse = result["abuseipdb"]
    vt = result["virustotal"]

    lines = [f"🌐 Network Investigation\n"]
    lines.append(f"Target: {value}")
    lines.append(f"Type: {ioc_type}\n")

    # Geolocation (IP only)
    if geo and not geo.get("error"):
        lines.append(
            f"📍 {geo.get('city', '')}, {geo.get('country', '')} "
            f"({geo.get('country_code', '')})"
        )
        lines.append(f"🏢 ISP: {geo.get('isp', 'unknown')}")
        lines.append(f"🔢 ASN: {geo.get('asn', 'unknown')}")
        flags = []
        if geo.get("is_proxy"):
            flags.append("⚠️ PROXY")
        if geo.get("is_hosting"):
            flags.append("🖥️ HOSTING")
        if flags:
            lines.append(f"Flags: {' | '.join(flags)}")

    # AbuseIPDB (IP only)
    if abuse and not abuse.get("error"):
        score = abuse.get("abuse_confidence_score", 0)
        reports = abuse.get("total_reports", 0)
        if score >= 75:
            verdict = "🚨 HIGH RISK"
        elif score >= 25:
            verdict = "⚠️ SUSPICIOUS"
        else:
            verdict = "✅ LOW RISK"
        lines.append(
            f"\nAbuseIPDB: {verdict} "
            f"(score: {score}%, reports: {reports})"
        )
        if abuse.get("last_reported_at"):
            lines.append(f"Last reported: {abuse['last_reported_at'][:10]}")

    # VirusTotal
    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        clean = vt.get("harmless", 0)
        if mal >= 5:
            vt_verdict = "🚨 MALICIOUS"
        elif mal >= 1 or sus >= 3:
            vt_verdict = "⚠️ SUSPICIOUS"
        else:
            vt_verdict = "✅ CLEAN"
        lines.append(
            f"VirusTotal: {vt_verdict} "
            f"({mal} malicious, {sus} suspicious, {clean} clean)"
        )
        if vt.get("categories"):
            lines.append(f"Categories: {', '.join(vt['categories'])}")

    await update.message.reply_text("\n".join(lines))

async def authorize_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /authorize <target> — pre-authorizes a target for active scanning."""
    user = update.effective_user
    logger.info("Received /authorize from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /authorize <target>\n"
            "Examples:\n"
            "  /authorize scanme.nmap.org\n"
            "  /authorize https://mysite.com\n\n"
            "⚠️ Only authorize targets you own or have explicit permission to test."
        )
        return

    target = context.args[0].strip()
    is_new = authorize_target(target, authorized_by=user.id)

    if is_new:
        await update.message.reply_text(
            f"✅ Target authorized for scanning: {target}\n"
            f"You can now use /scan against this target.\n"
            f"Authorization resets on bot restart."
        )
    else:
        await update.message.reply_text(
            f"ℹ️ Target already authorized: {target}"
        )


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles /scan <tool> <target> — runs an authorized active scan.

    Tools: subfinder, nmap, nuclei, ffuf
    """
    user = update.effective_user
    logger.info("Received /scan from user_id=%s", user.id)

    if not context.args or len(context.args) < 2:
        await update.message.reply_text(
            "Usage: /scan <tool> <target>\n\n"
            "Available tools:\n"
            "  subfinder — subdomain discovery\n"
            "  nmap      — port scanning\n"
            "  nuclei    — vulnerability scanning\n"
            "  ffuf      — directory/endpoint fuzzing\n\n"
            "Example: /scan nmap scanme.nmap.org\n"
            "Run /authorize <target> first."
        )
        return

    tool = context.args[0].lower().strip()
    target = " ".join(context.args[1:]).strip()

    authorized, reason = is_authorized(user.id, target)
    if not authorized:
        await update.message.reply_text(
            f"⛔ Not authorized: {reason}\n"
            f"Use /authorize {target} first."
        )
        return

    await update.message.reply_text(f"🔄 Running {tool} against {target}...")

    try:
        if tool == "subfinder":
            svc = ReconService()
            result = await svc.subfinder(target, user_id=user.id)
        elif tool == "nmap":
            svc = NetworkScanService()
            result = await svc.quick_scan(target, user_id=user.id)
        elif tool == "nuclei":
            svc = WebService()
            result = await svc.nuclei_scan(target, profile="safe", user_id=user.id)
        elif tool == "ffuf":
            svc = WebAppService()
            result = await svc.ffuf_scan(target, user_id=user.id)
        else:
            await update.message.reply_text(
                f"⚠️ Unknown tool: {tool}\n"
                "Available: subfinder, nmap, nuclei, ffuf"
            )
            return
    except Exception as exc:
        logger.error("Scan error: %s", exc, exc_info=True)
        await update.message.reply_text(f"⚠️ Scan error: {exc}")
        return

    if not result["success"]:
        await update.message.reply_text(f"⚠️ {result['error']}")
        return

    data = result["data"]
    lines = [f"✅ {tool.upper()} scan complete\n"]
    lines.append(f"Target: {target}")
    lines.append(f"Summary: {result['summary']}\n")

    if tool == "subfinder":
        subs = data.get("subdomains", [])
        if subs:
            lines.append(f"Subdomains ({len(subs)}):")
            for s in subs[:10]:
                lines.append(f"  • {format_list_item(s)}")
            if len(subs) > 10:
                lines.append(f"  ... and {len(subs)-10} more")
        else:
            lines.append("No subdomains found.")

    elif tool == "nmap":
        ports = data.get("ports", [])
        if ports:
            lines.append(f"Open ports ({data.get('open_count', 0)}):")
            for p in ports[:10]:
                lines.append(f"  • {p['port']}/{p['protocol']} {p['service']}")
        else:
            lines.append("No open ports found.")

    elif tool == "nuclei":
        findings = data.get("findings", [])
        by_sev = data.get("by_severity", {})
        if findings:
            lines.append(f"Findings by severity: {by_sev}")
            seen_names = set()
            for f in findings:
                if f["name"] not in seen_names:
                    lines.append(f"  [{f['severity']}] {f['name']}")
                    seen_names.add(f["name"])
                    if len(seen_names) >= 8:
                        break
        else:
            lines.append("No findings.")

    elif tool == "ffuf":
        results = data.get("results", [])
        if results:
            lines.append(f"Paths found ({len(results)}):")
            for r in results[:10]:
                lines.append(f"  • [{r['status']}] {r['input']}")
        else:
            lines.append("No paths found.")

    await update.message.reply_text("\n".join(lines))


async def auditlog_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /auditlog — shows recent security operation audit log."""
    user = update.effective_user
    logger.info("Received /auditlog from user_id=%s", user.id)

    from audit.audit_logger import read_recent_audit_logs
    logs = read_recent_audit_logs(limit=10)

    if not logs:
        await update.message.reply_text("No audit log entries yet.")
        return

    lines = ["📋 Recent Security Operations\n"]
    for entry in logs:
        ts = entry["timestamp"][:19].replace("T", " ")
        lines.append(
            f"• {ts}\n"
            f"  {entry['operation_type']} | {entry['tool_name']}\n"
            f"  target: {entry['target'][:40]}\n"
            f"  {entry['result_summary'][:60]}\n"
        )

    await update.message.reply_text("\n".join(lines))

async def score_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /score — runs threat scoring on unscored IOCs."""
    user = update.effective_user
    logger.info("Received /score from user_id=%s", user.id)

    await update.message.reply_text("🔄 Scoring unscored IOCs, please wait...")

    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, process_unscored_iocs, 200)

    lines = [
        f"✅ Threat Scoring Complete\n",
        f"🎯 Newly scored: {result['scored']}",
        f"🔄 Updated: {result['updated']}",
        f"⚠️ Errors: {result['errors']}",
    ]

    if result["scored"] == 0 and result["updated"] == 0:
        lines.append("\n(All IOCs already scored — run /threats first to collect new ones)")

    await update.message.reply_text("\n".join(lines))


async def topthreats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /topthreats — shows highest-scoring IOCs."""
    user = update.effective_user
    logger.info("Received /topthreats from user_id=%s", user.id)

    import asyncio
    loop = asyncio.get_event_loop()
    threats = await loop.run_in_executor(
        None, get_top_threats, 10, "HIGH"
    )

    if not threats:
        await update.message.reply_text(
            "No HIGH or CRITICAL threats found.\n"
            "Run /threats then /score first."
        )
        return

    lines = [f"🚨 Top Threats (HIGH+)\n"]
    for t in threats:
        sev_emoji = "🔴" if t["severity"] == "CRITICAL" else "🟠"
        lines.append(
            f"{sev_emoji} [{t['severity']}] Score: {t['score']}\n"
            f"   {t['ioc_value']} ({t['ioc_type']})\n"
            f"   {t['explanation']}"
        )

    await update.message.reply_text("\n".join(lines))

async def aithreat_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /aithreat <ioc_value> — runs AI-powered threat analysis on an IOC."""
    user = update.effective_user
    logger.info("Received /aithreat from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /aithreat <ioc_value>\n"
            "Examples:\n"
            "  /aithreat 192.168.1.1\n"
            "  /aithreat malware.example.com"
        )
        return

    value = " ".join(context.args).strip()
    await update.message.reply_text(f"🤖 Running AI threat analysis on: {value}")

    lookup_result = await lookup_ioc(value)
    ioc_type = lookup_result["ioc_type"]
    local = lookup_result["local"]

    signals = {
        "threatfox_matches": local["threatfox"],
        "extracted_article_matches": local["extracted"],
        "chainabuse_matches": lookup_result["chainabuse"],
    }

    workflow = AIWorkflow()
    wf_result = await workflow.analyze_threat(
        target=value,
        threat_score=0,
        severity="UNKNOWN",
        ioc_type=ioc_type,
        signals=signals,
    )

    if not wf_result.success:
        error_msg = wf_result.errors[0] if wf_result.errors else "Unknown error"
        await update.message.reply_text(f"⚠️ AI analysis failed: {error_msg}")
        return

    response = wf_result.data["response"]
    report = response.analysis

    lines = [f"🤖 AI Threat Analysis: {value}\n"]
    lines.append(f"Summary: {report.executive_summary}")
    lines.append(f"Assessment: {report.threat_assessment}")
    lines.append(f"Attack Stage: {report.attack_stage}")
    lines.append(f"Confidence: {report.confidence}")
    lines.append(f"Priority: {report.priority}")

    if report.malware:
        lines.append(f"Malware: {report.malware}")
    if report.threat_actor:
        lines.append(f"Threat Actor: {report.threat_actor}")
    if report.mitre_attack:
        lines.append(f"MITRE ATT&CK: {', '.join(format_list_item(x) for x in report.mitre_attack)}")

    if report.recommendations:
        lines.append("\nRecommendations:")
        for rec in report.recommendations[:5]:
            lines.append(f"  • {format_list_item(rec)}")

    if report.detection_opportunities:
        lines.append("\nDetection Opportunities:")
        for d in report.detection_opportunities[:5]:
            lines.append(f"  • {format_list_item(d)}")

    await update.message.reply_text("\n".join(lines))

async def aiscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /aiscan <tool> <target> — runs an authorized scan, then AI-interprets the results."""
    user = update.effective_user
    logger.info("Received /aiscan from user_id=%s", user.id)

    if not context.args or len(context.args) < 2:
        await update.message.reply_text(
            "Usage: /aiscan <tool> <target>\n\n"
            "Available tools:\n"
            "  subfinder — subdomain discovery\n"
            "  nmap      — port scanning\n"
            "  nuclei    — vulnerability scanning\n"
            "  ffuf      — directory/endpoint fuzzing\n\n"
            "Example: /aiscan nmap scanme.nmap.org\n"
            "Run /authorize <target> first."
        )
        return

    tool = context.args[0].lower().strip()
    target = " ".join(context.args[1:]).strip()

    authorized, reason = is_authorized(user.id, target)
    if not authorized:
        await update.message.reply_text(
            f"⛔ Not authorized: {reason}\n"
            f"Use /authorize {target} first."
        )
        return

    await update.message.reply_text(f"🔄 Running {tool} against {target}...")

    try:
        if tool == "subfinder":
            svc = ReconService()
            result = await svc.subfinder(target, user_id=user.id)
        elif tool == "nmap":
            svc = NetworkScanService()
            result = await svc.quick_scan(target, user_id=user.id)
        elif tool == "nuclei":
            svc = WebService()
            result = await svc.nuclei_scan(target, profile="safe", user_id=user.id)
        elif tool == "ffuf":
            svc = WebAppService()
            result = await svc.ffuf_scan(target, user_id=user.id)
        else:
            await update.message.reply_text(
                f"⚠️ Unknown tool: {tool}\n"
                "Available: subfinder, nmap, nuclei, ffuf"
            )
            return
    except Exception as exc:
        logger.error("Scan error: %s", exc, exc_info=True)
        await update.message.reply_text(f"⚠️ Scan error: {exc}")
        return

    if not result["success"]:
        await update.message.reply_text(f"⚠️ {result['error']}")
        return

    await update.message.reply_text("🤖 Running AI interpretation of scan results...")

    workflow = AIWorkflow()
    wf_result = await workflow.analyze_scan(
        tool=tool,
        target=target,
        results=result["data"],
    )

    if not wf_result.success:
        error_msg = wf_result.errors[0] if wf_result.errors else "Unknown error"
        await update.message.reply_text(f"⚠️ AI analysis failed: {error_msg}")
        return

    response = wf_result.data["response"]
    report = response.analysis

    lines = [f"🤖 AI Scan Analysis: {tool} on {target}\n"]
    lines.append(f"Summary: {report.executive_summary}")
    lines.append(f"Attack Surface: {report.attack_surface}")

    if report.exposed_assets:
        lines.append("\nExposed Assets:")
        for a in report.exposed_assets[:5]:
            lines.append(f"  • {format_list_item(a)}")

    if report.entry_points:
        lines.append("\nPossible Entry Points:")
        for e in report.entry_points[:5]:
            lines.append(f"  • {format_list_item(e)}")

    if report.false_positives:
        lines.append("\nFalse Positives:")
        for fp in report.false_positives[:5]:
            lines.append(f"  • {format_list_item(fp)}")

    if report.recommendations:
        lines.append("\nRecommendations:")
        for rec in report.recommendations[:5]:
            lines.append(f"  • {format_list_item(rec)}")

    await update.message.reply_text("\n".join(lines))


async def ainetwork_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /ainetwork <ip_or_domain> — runs AI-powered network intelligence analysis."""
    user = update.effective_user
    logger.info("Received /ainetwork from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /ainetwork <ip_or_domain>\n"
            "Examples:\n"
            "  /ainetwork 8.8.8.8\n"
            "  /ainetwork malware.example.com"
        )
        return

    value = " ".join(context.args).strip()
    await update.message.reply_text(f"🔍 Gathering network intelligence on: {value}")

    result = await investigate_network(value)

    if "error" in result:
        await update.message.reply_text(f"⚠️ {result.get('message', result['error'])}")
        return

    await update.message.reply_text("🤖 Running AI network analysis...")

    workflow = AIWorkflow()
    wf_result = await workflow.analyze_network(
        target=value,
        data=result,
    )

    if not wf_result.success:
        error_msg = wf_result.errors[0] if wf_result.errors else "Unknown error"
        await update.message.reply_text(f"⚠️ AI analysis failed: {error_msg}")
        return

    response = wf_result.data["response"]
    report = response.analysis

    lines = [f"🤖 AI Network Analysis: {value}\n"]
    lines.append(f"Reputation: {report.reputation}")
    lines.append(f"Risk: {report.risk}")
    lines.append(f"Infrastructure: {report.infrastructure}")
    lines.append(f"Abuse History: {report.abuse_history}")

    if report.observations:
        lines.append("\nObservations:")
        for o in report.observations[:5]:
            lines.append(f"  • {format_list_item(o)}")

    if report.recommendations:
        lines.append("\nRecommendations:")
        for rec in report.recommendations[:5]:
            lines.append(f"  • {format_list_item(rec)}")

    await update.message.reply_text("\n".join(lines))


async def aiweb_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /aiweb <target> — runs an authorized web scan, then AI-interprets the findings."""
    user = update.effective_user
    logger.info("Received /aiweb from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /aiweb <target>\n"
            "Example: /aiweb https://example.com\n"
            "Run /authorize <target> first."
        )
        return

    target = " ".join(context.args).strip()

    authorized, reason = is_authorized(user.id, target)
    if not authorized:
        await update.message.reply_text(
            f"⛔ Not authorized: {reason}\n"
            f"Use /authorize {target} first."
        )
        return

    await update.message.reply_text(f"🔄 Running web scan against {target}...")

    try:
        svc = WebService()
        result = await svc.nuclei_scan(target, profile="safe", user_id=user.id)
    except Exception as exc:
        logger.error("Web scan error: %s", exc, exc_info=True)
        await update.message.reply_text(f"⚠️ Scan error: {exc}")
        return

    if not result["success"]:
        await update.message.reply_text(f"⚠️ {result['error']}")
        return

    await update.message.reply_text("🤖 Running AI interpretation of web scan findings...")

    workflow = AIWorkflow()
    wf_result = await workflow.analyze_web(
        target=target,
        findings=result["data"],
    )

    if not wf_result.success:
        error_msg = wf_result.errors[0] if wf_result.errors else "Unknown error"
        await update.message.reply_text(f"⚠️ AI analysis failed: {error_msg}")
        return

    response = wf_result.data["response"]
    report = response.analysis

    lines = [f"🤖 AI Web Analysis: {target}\n"]
    lines.append(f"Summary: {report.executive_summary}")
    lines.append(f"Risk: {report.risk}")

    if report.findings:
        lines.append("\nFindings:")
        for f in report.findings[:5]:
            lines.append(f"  • {format_list_item(f)}")

    if report.vulnerabilities:
        lines.append("\nVulnerabilities:")
        for v in report.vulnerabilities[:5]:
            lines.append(f"  • {format_list_item(v)}")

    if report.misconfigurations:
        lines.append("\nMisconfigurations:")
        for m in report.misconfigurations[:5]:
            lines.append(f"  • {format_list_item(m)}")

    if report.recommendations:
        lines.append("\nRecommendations:")
        for rec in report.recommendations[:5]:
            lines.append(f"  • {format_list_item(rec)}")

    await update.message.reply_text("\n".join(lines))


async def aimalware_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /aimalware <evidence description> — runs AI-powered malware analysis on free-text evidence."""
    user = update.effective_user
    logger.info("Received /aimalware from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /aimalware <evidence description>\n"
            "Example: /aimalware Sample drops a DLL into %APPDATA%, "
            "establishes a beacon to 45.33.10.20 every 60s, and modifies "
            "the Run registry key for persistence."
        )
        return

    evidence_text = " ".join(context.args).strip()
    await update.message.reply_text("🤖 Running AI malware analysis...")

    workflow = AIWorkflow()
    wf_result = await workflow.analyze_malware(
        malware={"evidence": evidence_text},
    )

    if not wf_result.success:
        error_msg = wf_result.errors[0] if wf_result.errors else "Unknown error"
        await update.message.reply_text(f"⚠️ AI analysis failed: {error_msg}")
        return

    response = wf_result.data["response"]
    report = response.analysis

    lines = [f"🤖 AI Malware Analysis\n"]
    lines.append(f"Summary: {report.executive_summary}")
    if report.malware_name:
        lines.append(f"Name: {report.malware_name}")
    if report.malware_family:
        lines.append(f"Family: {report.malware_family}")
    if report.malware_type:
        lines.append(f"Type: {report.malware_type}")
    lines.append(f"Confidence: {report.confidence}")
    lines.append(f"Severity: {report.severity}")
    lines.append(f"Risk Score: {report.risk_score}")

    if report.capabilities:
        lines.append("\nCapabilities:")
        for c in report.capabilities[:5]:
            lines.append(f"  • {format_list_item(c)}")

    if report.indicators_of_compromise:
        lines.append("\nIndicators of Compromise:")
        for ioc in report.indicators_of_compromise[:5]:
            lines.append(f"  • {format_list_item(ioc)}")

    if report.mitre_attack:
        lines.append(f"\nMITRE ATT&CK: {', '.join(format_list_item(x) for x in report.mitre_attack)}")

    if report.recommendations:
        lines.append("\nRecommendations:")
        for rec in report.recommendations[:5]:
            lines.append(f"  • {format_list_item(rec)}")

    if report.detection_opportunities:
        lines.append("\nDetection Opportunities:")
        for d in report.detection_opportunities[:5]:
            lines.append(f"  • {format_list_item(d)}")

    await update.message.reply_text("\n".join(lines))


async def aiexecutive_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /aiexecutive <incident description> — produces an AI-powered executive summary."""
    user = update.effective_user
    logger.info("Received /aiexecutive from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /aiexecutive <incident description>\n"
            "Example: /aiexecutive Three endpoints in the finance "
            "department were compromised via a phishing email delivering "
            "a Cobalt Strike loader; lateral movement observed to two "
            "file servers before containment."
        )
        return

    incident_text = " ".join(context.args).strip()
    await update.message.reply_text("🤖 Generating executive summary...")

    workflow = AIWorkflow()
    wf_result = await workflow.executive_summary(
        report={"incident_description": incident_text},
    )

    if not wf_result.success:
        error_msg = wf_result.errors[0] if wf_result.errors else "Unknown error"
        await update.message.reply_text(f"⚠️ AI analysis failed: {error_msg}")
        return

    response = wf_result.data["response"]
    report = response.analysis

    lines = [f"🤖 Executive Summary\n"]
    lines.append(f"Summary: {report.summary}")
    lines.append(f"\nBusiness Impact: {report.business_impact}")
    lines.append(f"Technical Impact: {report.technical_impact}")
    lines.append(f"Overall Risk: {report.overall_risk}")

    if report.priorities:
        lines.append("\nPriorities:")
        for p in report.priorities[:5]:
            lines.append(f"  • {format_list_item(p)}")

    if report.next_actions:
        lines.append("\nNext Actions:")
        for a in report.next_actions[:5]:
            lines.append(f"  • {format_list_item(a)}")

    await update.message.reply_text("\n".join(lines))


async def fullreport_command(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Handles /fullreport <target> — runs a complete security assessment
    and returns the report as a PDF.
    """

    user = update.effective_user
    logger.info("Received /fullreport from user_id=%s", user.id)

    if not context.args:
        await update.message.reply_text(
            "Usage: /fullreport <target>\n"
            "Runs recon, network, web and threat analysis,\n"
            "then generates an AI executive report.\n\n"
            "Example:\n"
            "/fullreport scanme.nmap.org"
        )
        return

    target = " ".join(context.args).strip()

    await update.message.reply_text(
        f"🔄 Running full analysis on {target}...\n"
        "This may take one or two minutes."
    )

    try:
        workflow = ReportWorkflow()
        wf_result = await workflow.generate(
            target=target,
            user_id=user.id,
        )

        if not wf_result.success:
            error_msg = (
                wf_result.errors[0]
                if wf_result.errors
                else wf_result.message
            )

            await update.message.reply_text(
                f"⚠️ Report generation failed:\n{error_msg}"
            )
            return

        document = wf_result.data["document"]
        pdf_path = wf_result.data["pdf_path"]

        summary = "\n".join(document.splitlines()[:12])

        await update.message.reply_text(
            "✅ Security assessment completed.\n\n"
            "Executive Summary:\n\n"
            f"{summary}"
        )

        with open(pdf_path, "rb") as pdf_file:
            await update.message.reply_document(
                document=pdf_file,
                filename=Path(pdf_path).name,
                caption=(
                    "📄 Cyber Intelligence Security Assessment Report\n"
                    f"Target: {target}"
                ),
            )

    except Exception:
        logger.exception("Full report generation failed")

        await update.message.reply_text(
            "⚠️ Something went wrong while generating the report. "
            "Check the Termux logs for details."
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

    request = HTTPXRequest(
        connect_timeout=60.0,
        read_timeout=300.0,
        write_timeout=300.0,
        pool_timeout=60.0,
    )

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .request(request)
        .build()
    )

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("feeds", feeds_command))
    application.add_handler(CommandHandler("threats", threats_command))
    application.add_handler(CommandHandler("extract", extract_command))
    application.add_handler(CommandHandler("lookup", lookup_command))
    application.add_handler(CommandHandler("walletinfo", walletinfo_command))
    application.add_handler(CommandHandler("netinfo", netinfo_command))
    application.add_handler(CommandHandler("authorize", authorize_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("auditlog", auditlog_command))
    application.add_handler(CommandHandler("score", score_command))
    application.add_handler(CommandHandler("topthreats", topthreats_command))
    application.add_handler(CommandHandler("aithreat", aithreat_command))
    application.add_handler(CommandHandler("aiscan", aiscan_command))
    application.add_handler(CommandHandler("ainetwork", ainetwork_command))
    application.add_handler(CommandHandler("aiweb", aiweb_command))
    application.add_handler(CommandHandler("aimalware", aimalware_command))
    application.add_handler(CommandHandler("aiexecutive", aiexecutive_command))
    application.add_handler(CommandHandler("fullreport", fullreport_command))
    application.add_error_handler(error_handler)

    logger.info("Bot is starting polling...")
    application.run_polling()


if __name__ == "__main__":
    main()
