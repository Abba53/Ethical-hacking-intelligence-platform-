from workflows.base_workflow import BaseWorkflow, WorkflowResult

from services.active.recon_service import ReconService


class ReconWorkflow(BaseWorkflow):

    workflow_name = "recon"

    def __init__(self):

        super().__init__()

        self.service = ReconService()

    async def execute(
        self, *, action: str, domain: str, user_id: int | str = "system"
    ) -> WorkflowResult:
        """
        Dispatches to subfinder, amass, or full_recon on ReconService,
        based on `action`.
        """
        dispatch = {
            "subfinder": self.service.subfinder,
            "amass": self.service.amass,
            "full_recon": self.service.full_recon,
        }

        handler = dispatch.get(action)

        if handler is None:
            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=f"Unknown action: {action}",
                errors=[f"No handler for action={action!r}"],
            )

        result = await handler(domain, user_id)

        return WorkflowResult(
            success=result["success"],
            workflow=self.workflow_name,
            message=result.get("summary") or result.get("error") or "",
            data=result.get("data", {}),
            errors=[result["error"]] if not result["success"] else [],
        )

    async def subfinder(
        self, domain: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(action="subfinder", domain=domain, user_id=user_id)

    async def amass(
        self, domain: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(action="amass", domain=domain, user_id=user_id)

    async def full_recon(
        self, domain: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(action="full_recon", domain=domain, user_id=user_id)
