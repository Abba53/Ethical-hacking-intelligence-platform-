import asyncio

from workflows.base_workflow import BaseWorkflow, WorkflowResult

from collectors.threat_feed_collector import (
    collect_threat_feeds,
    save_threatfox_to_db,
    save_chainabuse_to_db,
)


class ThreatWorkflow(BaseWorkflow):

    workflow_name = "threat_feeds"

    async def execute(self) -> WorkflowResult:
        """
        Fetches ThreatFox IOCs and a Chainabuse test-address screening,
        then saves both to the database. Mirrors the exact sequence
        already used by bot.py's /threats command.
        """
        results = await collect_threat_feeds()

        loop = asyncio.get_event_loop()

        tf_summary = await loop.run_in_executor(
            None, save_threatfox_to_db, results["threatfox"]
        )
        ca_summary = await loop.run_in_executor(
            None, save_chainabuse_to_db, results["chainabuse"]
        )

        return WorkflowResult(
            success=True,
            workflow=self.workflow_name,
            message=(
                f"ThreatFox: {len(results['threatfox'])} fetched, "
                f"{tf_summary['inserted']} new. "
                f"Chainabuse: {len(results['chainabuse'])} fetched, "
                f"{ca_summary['inserted']} new."
            ),
            data={
                "threatfox": results["threatfox"],
                "chainabuse": results["chainabuse"],
                "threatfox_summary": tf_summary,
                "chainabuse_summary": ca_summary,
            },
        )

    async def collect(self) -> WorkflowResult:

        return await self.run()
