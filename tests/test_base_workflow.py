import asyncio

from workflows.base_workflow import BaseWorkflow, WorkflowResult


class FailingWorkflow(BaseWorkflow):
    workflow_name = "test_workflow"

    async def execute(self, *args, **kwargs) -> WorkflowResult:
        raise RuntimeError("api_key=base-workflow-test-secret")


def test_workflow_exception_does_not_expose_sensitive_error():
    result = asyncio.run(FailingWorkflow().run())

    assert result.success is False
    assert result.message == "Workflow failed."
    assert result.errors == ["Workflow execution failed."]
    assert "base-workflow-test-secret" not in str(result)
    assert result.started_at is not None
    assert result.finished_at is not None
    assert result.duration_ms is not None
    assert result.duration_ms >= 0
