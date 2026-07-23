from workflows.base_workflow import BaseWorkflow, WorkflowResult

from services.active.web_service import WebService


class WebWorkflow(BaseWorkflow):

    workflow_name = "web_scan"

    def __init__(self):

        super().__init__()

        self.service = WebService()

    async def execute(
        self,
        *,
        action: str,
        target: str,
        profile: str = "safe",
        user_id: int | str = "system",
    ) -> WorkflowResult:
        """
        Dispatches to nuclei_scan or header_check on WebService,
        based on `action`.
        """
        if action == "nuclei_scan":
            result = await self.service.nuclei_scan(
                target, profile=profile, user_id=user_id
            )
        elif action == "header_check":
            result = await self.service.header_check(target, user_id=user_id)
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

    async def nuclei_scan(
        self,
        target: str,
        profile: str = "safe",
        user_id: int | str = "system",
    ) -> WorkflowResult:

        return await self.run(
            action="nuclei_scan",
            target=target,
            profile=profile,
            user_id=user_id,
        )

    async def header_check(
        self, target: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(
            action="header_check", target=target, user_id=user_id
        )
