"""
services/passive/blockchain_service.py

Passive blockchain forensics service.

Wraps tools/blockchain_forensics.py with audit logging and
standard result envelope. Supports EVM (Ethereum) and Solana.

Interface contract:
    BlockchainService().investigate(address, user_id) -> dict
    BlockchainService().evm(address, user_id) -> dict
    BlockchainService().solana(address, user_id) -> dict
"""

from services.base_service import BaseService
from tools.blockchain_forensics import (
    get_eth_address_info,
    get_sol_address_info,
    investigate_wallet,
)


class BlockchainService(BaseService):
    service_name = "blockchain_service"
    operation_type = "passive_lookup"
    requires_authorization = False

    async def investigate(
        self, address: str, user_id: int | str = "system"
    ) -> dict:
        """Full wallet investigation — routes to EVM or Solana automatically."""
        with self.audit_timer(address, user_id) as t:
            raw = await investigate_wallet(address)
            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])
            chain = raw.get("chain", "unknown")
            ioc_type = raw.get("ioc_type", "unknown")
            t.result_summary = f"chain={chain} type={ioc_type}"
            t.metadata = {"chain": chain, "ioc_type": ioc_type}
        return self._ok(raw, summary=t.result_summary)

    async def evm(self, address: str, user_id: int | str = "system") -> dict:
        """Ethereum address investigation via Ethplorer."""
        with self.audit_timer(address, user_id) as t:
            raw = await get_eth_address_info(address)
            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])
            balance = raw.get("eth_balance", 0)
            tokens = raw.get("token_count", 0)
            t.result_summary = f"eth={balance:.4f} tokens={tokens}"
            t.metadata = {"eth_balance": balance, "token_count": tokens}
        return self._ok(raw, summary=t.result_summary)

    async def solana(self, address: str, user_id: int | str = "system") -> dict:
        """Solana address investigation via Helius."""
        with self.audit_timer(address, user_id) as t:
            raw = await get_sol_address_info(address)
            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])
            tx_count = raw.get("tx_count_returned", 0)
            t.result_summary = f"recent_txs={tx_count}"
            t.metadata = {"tx_count_returned": tx_count}
        return self._ok(raw, summary=t.result_summary)
