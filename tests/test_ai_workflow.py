import asyncio
import logging
from types import SimpleNamespace

from workflows.ai_workflow import AIWorkflow


def make_workflow(handler):
    workflow = AIWorkflow.__new__(AIWorkflow)
    workflow.workflow_name = "ai_analysis"
    workflow.analyst = SimpleNamespace(
        analyze_threat=handler,
        analyze_scan=handler,
        analyze_network=handler,
        analyze_web=handler,
        analyze_malware=handler,
        executive_summary=handler,
    )
    return workflow


def test_ai_workflow_exception_does_not_expose_sensitive_error(caplog):
    secret = "api_key=workflow-test-secret"

    async def failing_handler(**kwargs):
        raise RuntimeError(secret)

    workflow = make_workflow(failing_handler)

    with caplog.at_level(logging.ERROR):
        result = asyncio.run(
            workflow.execute(report_type="scan")
        )

    assert result.success is False
    assert secret not in result.message
    assert all(secret not in error for error in result.errors)
    assert secret not in caplog.text


def test_ai_workflow_failed_response_does_not_expose_provider_error(caplog):
    secret = "authorization=workflow-test-secret"

    async def failing_handler(**kwargs):
        return SimpleNamespace(
            success=False,
            error=secret,
        )

    workflow = make_workflow(failing_handler)

    with caplog.at_level(logging.ERROR):
        result = asyncio.run(
            workflow.execute(report_type="scan")
        )

    assert result.success is False
    assert secret not in result.message
    assert all(secret not in error for error in result.errors)
    assert secret not in caplog.text
    assert "response" not in result.data
