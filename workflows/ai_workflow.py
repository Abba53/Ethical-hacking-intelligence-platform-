from workflows.base_workflow import BaseWorkflow, WorkflowResult

from analysis.ai_analysis import AIAnalyst


class AIWorkflow(BaseWorkflow):

    workflow_name = "ai_analysis"

    def __init__(self):

        super().__init__()

        self.analyst = AIAnalyst()

    async def execute(self, *, report_type: str, **kwargs) -> WorkflowResult:
        """
        Dispatches to the matching AIAnalyst method based on
        report_type, then wraps the resulting AIResponse into a
        WorkflowResult.
        """
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
            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message=f"Unknown report_type: {report_type}",
                errors=[f"No handler for report_type={report_type!r}"],
            )

        response = await handler(**kwargs)

        return WorkflowResult(
            success=response.success,
            workflow=self.workflow_name,
            message=response.error or "AI analysis complete.",
            data={"response": response},
            errors=[response.error] if response.error else [],
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
