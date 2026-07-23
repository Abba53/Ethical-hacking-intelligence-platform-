import asyncio

from workflows.base_workflow import BaseWorkflow, WorkflowResult

from scoring.threat_scorer import process_unscored_iocs, get_top_threats


class ScoringWorkflow(BaseWorkflow):

    workflow_name = "scoring"

    async def execute(self, *, action: str, **kwargs) -> WorkflowResult:
        """
        Dispatches to either scoring unscored IOCs or fetching top
        threats, based on `action`. Both underlying functions are
        synchronous/blocking (direct DB queries), so they run in the
        default executor to avoid blocking the event loop.
        """
        loop = asyncio.get_event_loop()

        if action == "process_unscored":
            limit = kwargs.get("limit", 100)

            result = await loop.run_in_executor(
                None, process_unscored_iocs, limit
            )

            return WorkflowResult(
                success=True,
                workflow=self.workflow_name,
                message=(
                    f"Scored {result['scored']} new, "
                    f"updated {result['updated']}, "
                    f"{result['errors']} errors."
                ),
                data={"result": result},
            )

        elif action == "top_threats":
            limit = kwargs.get("limit", 10)
            min_severity = kwargs.get("min_severity", "MEDIUM")

            result = await loop.run_in_executor(
                None, get_top_threats, limit, min_severity
            )

            return WorkflowResult(
                success=True,
                workflow=self.workflow_name,
                message=f"Found {len(result)} threat(s).",
                data={"threats": result},
            )

        else:
            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=f"Unknown action: {action}",
                errors=[f"No handler for action={action!r}"],
            )

    async def process_unscored(self, limit: int = 100) -> WorkflowResult:

        return await self.run(action="process_unscored", limit=limit)

    async def top_threats(
        self, limit: int = 10, min_severity: str = "MEDIUM"
    ) -> WorkflowResult:

        return await self.run(
            action="top_threats", limit=limit, min_severity=min_severity
        )
