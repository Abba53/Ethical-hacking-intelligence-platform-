from workflows.base_workflow import BaseWorkflow, WorkflowResult

from extractors.ioc_lookup import lookup_ioc


class LookupWorkflow(BaseWorkflow):

    workflow_name = "lookup"

    async def execute(self, *, value: str) -> WorkflowResult:

        result = await lookup_ioc(value)

        return WorkflowResult(
            success=True,
            workflow=self.workflow_name,
            message=f"Lookup complete for {value}.",
            data={"result": result},
        )

    async def lookup(self, value: str) -> WorkflowResult:

        return await self.run(value=value)
