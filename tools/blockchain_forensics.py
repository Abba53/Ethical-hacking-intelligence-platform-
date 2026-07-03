"""
tools/blockchain_forensics.py

Blockchain forensics tools for EVM (Ethereum) and Solana address investigation.

Sources:
  - Ethplorer (EVM): free development API, no signup required
    Base: https://api.ethplorer.io/
    Key: 'freekey' (rate-limited: 2 req/s, 100 results/req, 1000/24h)
  - Helius (Solana): requires HELIUS_API_KEY from .env
    Base: https://api-mainnet.helius-rpc.com/v0/
    Wallet: https://api.helius.xyz/v1/wallet/{address}/

Used by the /walletinfo bot command (Phase 9.2).

Security note: these endpoints accept user-supplied addresses. We validate
address format (via detect_ioc_type) before sending to external APIs to
prevent SSRF-class misuse of this tool.
"""

import logging
import os

import httpx
from dotenv import load_dotenv

from extractors.ioc_lookup import detect_ioc_type

logger = logging.getLogger(__name__)
load_dotenv()

HELIUS_API_KEY = os.getenv("HELIUS_API_KEY")
ETHPLORER_API_KEY = "freekey"

ETHPLORER_BASE = "https://api.ethplorer.io"
HELIUS_WALLET_BASE = "https://api.helius.xyz/v1/wallet"
HELIUS_RPC_BASE = "https://api-mainnet.helius-rpc.com/v0/addresses"

REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# EVM (Ethereum) forensics via Ethplorer
# ---------------------------------------------------------------------------

async def get_eth_address_info(address: str) -> dict:
    """
    Fetches Ethereum address information from Ethplorer.

    Returns ETH balance, token holdings count, and transaction count.
    Uses the free development key — acceptable for forensic investigation
    at low volume, not for high-frequency production use.
    """
    url = f"{ETHPLORER_BASE}/getAddressInfo/{address}"
    params = {
        "apiKey": ETHPLORER_API_KEY,
        "showETHTotals": "true",
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url, params=params, timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        logger.warning("Timeout fetching Ethplorer data for %s", address)
        return {"error": "timeout"}
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "Ethplorer HTTP error for %s: status %s", address, exc.response.status_code
        )
        return {"error": f"http_{exc.response.status_code}"}
    except httpx.RequestError as exc:
        logger.warning("Ethplorer network error for %s: %s", address, exc)
        return {"error": "network_error"}

    if "error" in data:
        logger.warning("Ethplorer returned error for %s: %s", address, data["error"])
        return {"error": data["error"].get("message", "unknown")}

    eth = data.get("ETH", {})
    tokens = data.get("tokens", [])
    tx_count = data.get("countTxs", 0)

    return {
        "address": address,
        "chain": "ethereum",
        "eth_balance": eth.get("balance", 0),
        "eth_balance_usd": eth.get("totalIn", 0),
        "token_count": len(tokens),
        "tx_count": tx_count,
        "tokens": [
            {
                "name": t.get("tokenInfo", {}).get("name", "Unknown"),
                "symbol": t.get("tokenInfo", {}).get("symbol", "?"),
                "balance": t.get("balance", 0),
            }
            for t in tokens[:5]
        ],
    }


# ---------------------------------------------------------------------------
# Solana forensics via Helius
# ---------------------------------------------------------------------------

async def get_sol_address_info(address: str) -> dict:
    """
    Fetches Solana address information via Helius Enhanced Transactions API.

    Returns recent transaction history (up to 10 transactions), parsed
    into human-readable form by Helius's 100+ transaction parsers.
    """
    if not HELIUS_API_KEY:
        logger.error("HELIUS_API_KEY not set — cannot perform Solana lookup")
        return {"error": "no_api_key"}

    url = f"{HELIUS_RPC_BASE}/{address}/transactions"
    params = {
        "api-key": HELIUS_API_KEY,
        "limit": 10,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url, params=params, timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            transactions = response.json()
    except httpx.TimeoutException:
        logger.warning("Timeout fetching Helius data for %s", address)
        return {"error": "timeout"}
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "Helius HTTP error for %s: status %s", address, exc.response.status_code
        )
        return {"error": f"http_{exc.response.status_code}"}
    except httpx.RequestError as exc:
        logger.warning("Helius network error for %s: %s", address, exc)
        return {"error": "network_error"}

    if not isinstance(transactions, list):
        logger.warning(
            "Unexpected Helius response shape for %s: %s", address, type(transactions)
        )
        return {"error": "unexpected_response"}

    parsed_txs = []
    for tx in transactions:
        parsed_txs.append({
            "signature": tx.get("signature", "")[:20] + "...",
            "type": tx.get("type", "UNKNOWN"),
            "timestamp": tx.get("timestamp", 0),
            "fee": tx.get("fee", 0),
            "description": tx.get("description", ""),
        })

    return {
        "address": address,
        "chain": "solana",
        "tx_count_returned": len(parsed_txs),
        "recent_transactions": parsed_txs,
    }


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

async def investigate_wallet(address: str) -> dict:
    """
    Routes a wallet address to the correct chain's investigation function.

    Validates the address type first to prevent sending arbitrary input
    to external APIs (SSRF defense). Only proceeds if the address is
    detected as a known crypto address type.
    """
    ioc_type = detect_ioc_type(address)

    if ioc_type == "eth_address":
        result = await get_eth_address_info(address)
        result["ioc_type"] = "eth_address"
        return result

    elif ioc_type == "sol_address":
        result = await get_sol_address_info(address)
        result["ioc_type"] = "sol_address"
        return result

    else:
        return {
            "error": "unsupported_type",
            "ioc_type": ioc_type,
            "message": (
                f"Address type '{ioc_type}' is not a supported wallet type. "
                "Provide an Ethereum (0x...) or Solana (base58) address."
            ),
        }
