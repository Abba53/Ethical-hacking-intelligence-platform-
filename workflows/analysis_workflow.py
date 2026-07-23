from workflows.base_workflow import BaseWorkflow, WorkflowResult

from workflows.recon_workflow import ReconWorkflow
from workflows.network_workflow import NetworkWorkflow
from workflows.web_workflow import WebWorkflow
from workflows.lookup_workflow import LookupWorkflow
from workflows.ai_workflow import AIWorkflow


class AnalysisWorkflow(BaseWorkflow):
    """
    Orchestrates recon, network, and web scanning plus an IOC lookup
    against a target, then runs AI analysis over each result set.

    Deliberately does NOT call ReportWorkflow — that stays a separate,
    manually-triggered step that consumes this workflow's output.
    """

    workflow_name = "analysis"

    def __init__(self):

        super().__init__()

        self.recon = ReconWorkflow()
        self.network = NetworkWorkflow()
        self.web = WebWorkflow()
        self.lookup = LookupWorkflow()
        self.ai = AIWorkflow()

    async def execute(
        self,
        *,
        target: str,
        user_id: int | str = "system",
    ) -> WorkflowResult:

        errors: list[str] = []
        reports: dict = {}

        # Threat (IOC lookup-based, same pattern as /aithreat)
        lookup_result = await self.lookup.lookup(target)
        if lookup_result.success:
            lookup_data = lookup_result.data["result"]
            signals = {
                "threatfox_matches": lookup_data["local"]["threatfox"],
                "extracted_article_matches": lookup_data["local"]["extracted"],
                "chainabuse_matches": lookup_data["chainabuse"],
            }
            ai_threat = await self.ai.analyze_threat(
                target=target,
                threat_score=0,
                severity="UNKNOWN",
                ioc_type=lookup_data["ioc_type"],
                signals=signals,
            )
            if ai_threat.success:
                reports["threat"] = ai_threat.data["response"].analysis
            else:
                errors.append(f"threat AI analysis failed: {ai_threat.message}")
        else:
            errors.append(
                f"IOC lookup failed: {'; '.join(lookup_result.errors)}"
            )

        # Recon
        recon_result = await self.recon.subfinder(target, user_id=user_id)
        if recon_result.success:
            ai_recon = await self.ai.analyze_scan(
                tool="subfinder",
                target=target,
                results=recon_result.data,
            )
            if ai_recon.success:
                reports["recon"] = ai_recon.data["response"].analysis
            else:
                errors.append(f"recon AI analysis failed: {ai_recon.message}")
        else:
            errors.append(
                f"recon scan failed: {'; '.join(recon_result.errors)}"
            )

        # Network
        network_result = await self.network.quick_scan(target, user_id=user_id)
        if network_result.success:
            ai_network = await self.ai.analyze_network(
                target=target,
                data=network_result.data,
            )
            if ai_network.success:
                reports["network"] = ai_network.data["response"].analysis
            else:
                errors.append(f"network AI analysis failed: {ai_network.message}")
        else:
            errors.append(
                f"network scan failed: {'; '.join(network_result.errors)}"
            )

        # Web
        web_result = await self.web.nuclei_scan(target, user_id=user_id)
        if web_result.success:
            ai_web = await self.ai.analyze_web(
                target=target,
                findings=web_result.data,
            )
            if ai_web.success:
                reports["web"] = ai_web.data["response"].analysis
            else:
                errors.append(f"web AI analysis failed: {ai_web.message}")
        else:
            errors.append(
                f"web scan failed: {'; '.join(web_result.errors)}"
            )

        overall_success = len(reports) > 0

        return WorkflowResult(
            success=overall_success,
            workflow=self.workflow_name,
            message=f"Gathered {len(reports)}/4 AI report(s) for {target}.",
            data={"target": target, "reports": reports},
            errors=errors,
        )

    async def analyze(
        self, target: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(target=target, user_id=user_id)
