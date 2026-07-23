from workflows.base_workflow import BaseWorkflow, WorkflowResult

from services.active.network_scan_service import NetworkScanService


class NetworkWorkflow(BaseWorkflow):

    workflow_name = "network_scan"

    def __init__(self):

        super().__init__()

        self.service = NetworkScanService()

    async def execute(
        self,
        *,
        target: str,
        profile: str = "quick",
        user_id: int | str = "system",
    ) -> WorkflowResult:
        """
        Runs an Nmap scan against target using the given profile
        (quick, standard, full), via NetworkScanService.scan().
        """
        result = await self.service.scan(
            target, profile=profile, user_id=user_id
        )

        return WorkflowResult(
            success=result["success"],
            workflow=self.workflow_name,
            message=result.get("summary") or result.get("error") or "",
            data=result.get("data", {}),
            errors=[result["error"]] if not result["success"] else [],
        )

    async def quick_scan(
        self, target: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(target=target, profile="quick", user_id=user_id)

    async def service_scan(
        self, target: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(target=target, profile="standard", user_id=user_id)

    async def full_scan(
        self, target: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(target=target, profile="full", user_id=user_id)
