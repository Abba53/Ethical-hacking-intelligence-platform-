import logging

from workflows.base_workflow import BaseWorkflow, WorkflowResult
from analysis.ai_analysis import AIAnalyst

logger = logging.getLogger(__name__)


class AIWorkflow(BaseWorkflow):
    """
    Orchestration layer for all AI analysis operations.

    Responsibilities:
    - Dispatch report types to AIAnalyst.
    - Capture provider/parser exceptions.
    - Return a consistent WorkflowResult.
    - Log enough information to diagnose failures without
      exposing API credentials.
    """

    workflow_name = "ai_analysis"

    def __init__(self):
        super().__init__()

        logger.info("Initializing AIWorkflow")

        try:
            self.analyst = AIAnalyst()

            provider_name = getattr(
                self.analyst.provider,
                "provider_name",
                self.analyst.provider.__class__.__name__,
            )

            logger.info(
                "AIWorkflow initialized successfully | provider=%s",
                provider_name,
            )

        except Exception:
            logger.exception("Failed to initialize AIAnalyst")
            raise

    async def execute(
        self,
        *,
        report_type: str,
        **kwargs,
    ) -> WorkflowResult:
        """
        Dispatches the requested report type to AIAnalyst.

        Any provider/parser exception is converted into a
        WorkflowResult instead of escaping into the Telegram handler.
        """

        logger.info(
            "AI workflow started | report_type=%s",
            report_type,
        )

        dispatch = {
            "threat": self.analyst.analyze_threat,
            "scan": self.analyst.analyze_scan,
            "network": self.analyst.analyze_network,
            "web": self.analyst.analyze_web,
            "malware": self.analyst.analyze_malware,
            "executive": self.analyst.executive_summary,
        }

        handler = dispatch.get(report_type)

        if handler is None:
            message = f"Unknown report_type: {report_type}"

            logger.error(
                "AI workflow dispatch failed | %s",
                message,
            )

            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=message,
                errors=[
                    f"No handler for report_type={report_type!r}"
                ],
            )

        try:
            response = await handler(**kwargs)

        except Exception as exc:
            logger.exception(
                "AI handler raised exception | report_type=%s | error=%s",
                report_type,
                exc,
            )

            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=f"AI analysis failed: {type(exc).__name__}: {exc}",
                errors=[
                    f"{type(exc).__name__}: {exc}"
                ],
            )

        if response is None:
            logger.error(
                "AI handler returned None | report_type=%s",
                report_type,
            )

            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message="AI provider returned no response.",
                errors=[
                    "AI handler returned None"
                ],
            )

        logger.info(
            "AI handler completed | report_type=%s | success=%s",
            report_type,
            response.success,
        )

        if not response.success:
            error = response.error or "Unknown AI provider error"

            logger.error(
                "AI analysis failed | report_type=%s | error=%s",
                report_type,
                error,
            )

            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=error,
                data={"response": response},
                errors=[error],
            )

        return WorkflowResult(
            success=True,
            workflow=self.workflow_name,
            message="AI analysis complete.",
            data={"response": response},
            errors=[],
        )

    async def analyze_threat(
        self,
        *,
        target: str,
        threat_score: int,
        severity: str,
        ioc_type: str,
        signals: dict,
    ) -> WorkflowResult:

        return await self.run(
            report_type="threat",
            target=target,
            threat_score=threat_score,
            severity=severity,
            ioc_type=ioc_type,
            signals=signals,
        )

    async def analyze_scan(
        self,
        *,
        tool: str,
        target: str,
        results: dict,
    ) -> WorkflowResult:

        return await self.run(
            report_type="scan",
            tool=tool,
            target=target,
            results=results,
        )

    async def analyze_network(
        self,
        *,
        target: str,
        data: dict,
    ) -> WorkflowResult:

        return await self.run(
            report_type="network",
            target=target,
            data=data,
        )

    async def analyze_web(
        self,
        *,
        target: str,
        findings: dict,
    ) -> WorkflowResult:

        return await self.run(
            report_type="web",
            target=target,
            findings=findings,
        )

    async def analyze_malware(
        self,
        *,
        malware: dict,
    ) -> WorkflowResult:

        return await self.run(
            report_type="malware",
            malware=malware,
        )

    async def executive_summary(
        self,
        *,
        report: dict,
    ) -> WorkflowResult:

        return await self.run(
            report_type="executive",
            report=report,
        )
