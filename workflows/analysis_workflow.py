from workflows.base_workflow import BaseWorkflow, WorkflowResult

from workflows.recon_workflow import ReconWorkflow
from workflows.network_workflow import NetworkWorkflow
from workflows.web_workflow import WebWorkflow
from workflows.lookup_workflow import LookupWorkflow
from workflows.ai_workflow import AIWorkflow

from services.active.target_utils import extract_hostname, ensure_scheme
from tools.network_security import investigate_network


class AnalysisWorkflow(BaseWorkflow):
    """
    Orchestrates recon, nmap port scanning, network reputation
    intelligence, web scanning, and an IOC lookup against a target,
    then runs AI analysis over each result set.

    "network_scan" (nmap open ports) and "network" (reputation/geo
    intelligence via investigate_network) are two genuinely different
    kinds of data, so they're kept as separate report keys rather
    than conflated — nmap's port data is analyzed via analyze_scan
    (ReconReport shape), matching how /aiscan already treats nmap
    results, while investigate_network's reputation data is analyzed
    via analyze_network (NetworkReport shape), matching /ainetwork.

    Deliberately does NOT call ReportWorkflow — that stays a separate,
    manually-triggered step that consumes this workflow's output.
    """

    workflow_name = "analysis"

    def __init__(self):

        super().__init__()

        self.recon = ReconWorkflow()
        self.network_scan = NetworkWorkflow()
        self.web = WebWorkflow()
        self.lookup = LookupWorkflow()
        self.ai = AIWorkflow()

    async def execute(
        self,
        *,
        target: str,
        user_id: int | str = "system",
    ) -> WorkflowResult:

        hostname = extract_hostname(target)
        web_target = ensure_scheme(target)

        errors: list[str] = []
        reports: dict = {}

        # Threat (IOC lookup-based, same pattern as /aithreat)
        lookup_result = await self.lookup.lookup(hostname)
        if lookup_result.success:
            lookup_data = lookup_result.data["result"]
            signals = {
                "threatfox_matches": lookup_data["local"]["threatfox"],
                "extracted_article_matches": lookup_data["local"]["extracted"],
                "chainabuse_matches": lookup_data["chainabuse"],
            }
            ai_threat = await self.ai.analyze_threat(
                target=hostname,
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

        # Recon (subfinder)
        recon_result = await self.recon.subfinder(hostname, user_id=user_id)
        if recon_result.success:
            ai_recon = await self.ai.analyze_scan(
                tool="subfinder",
                target=hostname,
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

        # Network scan (nmap port scan — analyzed via analyze_scan,
        # since it's recon-shaped data, not reputation data)
        netscan_result = await self.network_scan.quick_scan(
            hostname, user_id=user_id
        )
        if netscan_result.success:
            ai_netscan = await self.ai.analyze_scan(
                tool="nmap",
                target=hostname,
                results=netscan_result.data,
            )
            if ai_netscan.success:
                reports["network_scan"] = ai_netscan.data["response"].analysis
            else:
                errors.append(
                    f"network scan AI analysis failed: {ai_netscan.message}"
                )
        else:
            errors.append(
                f"network scan failed: {'; '.join(netscan_result.errors)}"
            )

        # Network intelligence (reputation/geo/abuse — the correct
        # data source for analyze_network / NetworkReport)
        network_intel = await investigate_network(hostname)
        if "error" not in network_intel:
            ai_network = await self.ai.analyze_network(
                target=hostname,
                data=network_intel,
            )
            if ai_network.success:
                reports["network"] = ai_network.data["response"].analysis
            else:
                errors.append(
                    f"network intelligence AI analysis failed: {ai_network.message}"
                )
        else:
            errors.append(
                f"network intelligence lookup failed: "
                f"{network_intel.get('message', network_intel.get('error'))}"
            )

        # Web
        web_result = await self.web.nuclei_scan(web_target, user_id=user_id)
        if web_result.success:
            ai_web = await self.ai.analyze_web(
                target=web_target,
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
            message=f"Gathered {len(reports)}/5 AI report(s) for {hostname}.",
            data={"target": hostname, "reports": reports},
            errors=errors,
        )

    async def analyze(
        self, target: str, user_id: int | str = "system"
    ) -> WorkflowResult:

        return await self.run(target=target, user_id=user_id)
