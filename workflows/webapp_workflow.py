from workflows.base_workflow import BaseWorkflow, WorkflowResult

from services.active.webapp_service import WebAppService


class WebAppWorkflow(BaseWorkflow):

    workflow_name = "webapp_scan"

    def __init__(self):

        super().__init__()

        self.service = WebAppService()

    async def execute(
        self,
        *,
        action: str,
        target: str,
        wordlist_path: str | None = None,
        user_id: int | str = "system",
    ) -> WorkflowResult:
        """
        Dispatches to ffuf_scan or sqli_scan on WebAppService,
        based on `action`.
        """
        if action == "ffuf_scan":
            result = await self.service.ffuf_scan(
                target, wordlist_path=wordlist_path, user_id=user_id
            )
        elif action == "sqli_scan":
            result = await self.service.sqli_scan(target, user_id=user_id)
        else:
            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=f"Unknown action: {action}",
                errors=[f"No handler for action={action!r}"],
            )

        return WorkflowResult(
            success=result["success"],
            workflow=self.workflow_name,
            message=result.get("summary") or result.get("error") or "",
            data=result.get("data", {}),
            errors=[result["error"]] if not result["success"] else [],
        )

    async def ffuf_scan(
        self,
        target: str,
        wordlist_path: str | None = None,
        user_id: int | str = "system",
    ) -> WorkflowResult:

        return await self.run(
            action="ffuf_scan",
            target=target,
            wordlist_path=wordlist_path,
            user_id=user_id,
        )

    async def sqli_scan(
        self, target_url: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(
            action="sqli_scan", target=target_url, user_id=user_id
        )
