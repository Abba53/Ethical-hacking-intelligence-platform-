from workflows.base_workflow import BaseWorkflow, WorkflowResult

from workflows.analysis_workflow import AnalysisWorkflow
from workflows.ai_workflow import AIWorkflow

from analysis.formatting import format_list_item
from reports.pdf_generator import PDFGenerator


class ReportWorkflow(BaseWorkflow):
    """
    Runs a complete security assessment, requests an AI executive
    summary, assembles a human-readable report, then exports it
    as a PDF.
    """

    workflow_name = "report"

    def __init__(self):

        super().__init__()

        self.analysis = AnalysisWorkflow()
        self.ai = AIWorkflow()
        self.pdf = PDFGenerator()

    async def execute(
        self,
        *,
        target: str,
        user_id: int | str = "system",
    ) -> WorkflowResult:

        analysis_result = await self.analysis.analyze(
            target,
            user_id=user_id,
        )

        reports = analysis_result.data.get("reports", {})

        if not reports:
            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message="No analysis data was gathered — cannot build a report.",
                errors=analysis_result.errors,
            )

        incident_description = self._build_incident_description(
            target,
            reports,
        )

        exec_result = await self.ai.executive_summary(
            report={
                "incident_description": incident_description,
            }
        )

        document = self._format_document(
            target,
            reports,
            exec_result,
        )

        pdf_path = self.pdf.generate(
            target=target,
            document=document,
        )

        return WorkflowResult(
            success=exec_result.success,
            workflow=self.workflow_name,
            message=(
                "PDF report generated."
                if exec_result.success
                else exec_result.message
            ),
            data={
                "target": target,
                "reports": reports,
                "executive_summary": (
                    exec_result.data["response"].analysis
                    if exec_result.success
                    else None
                ),
                "document": document,
                "pdf_path": pdf_path,
            },
            errors=analysis_result.errors + exec_result.errors,
        )

    def _build_incident_description(
        self,
        target: str,
        reports: dict,
    ) -> str:

        parts = [f"Security assessment findings for {target}:"]

        if "threat" in reports:
            r = reports["threat"]
            parts.append(
                f"Threat analysis: {r.executive_summary or r.threat_assessment}"
            )

        if "recon" in reports:
            r = reports["recon"]
            parts.append(
                f"Reconnaissance: {r.executive_summary}"
            )

        if "network_scan" in reports:
            r = reports["network_scan"]
            parts.append(
                f"Network scan: {r.executive_summary}"
            )

        if "network" in reports:
            r = reports["network"]
            parts.append(
                f"Network intelligence: reputation={r.reputation}, risk={r.risk}"
            )

        if "web" in reports:
            r = reports["web"]
            parts.append(
                f"Web assessment: {r.executive_summary}"
            )

        return "\n".join(parts)

    def _format_document(
        self,
        target: str,
        reports: dict,
        exec_result: WorkflowResult,
    ) -> str:

        lines = [
            f"SECURITY ASSESSMENT REPORT: {target}",
            "=" * 70,
            "",
        ]

        if exec_result.success:

            exec_report = exec_result.data["response"].analysis

            lines.append("EXECUTIVE SUMMARY")
            lines.append("-" * 70)

            lines.append(exec_report.summary)
            lines.append("")

            lines.append(
                f"Business Impact: {exec_report.business_impact}"
            )

            lines.append(
                f"Technical Impact: {exec_report.technical_impact}"
            )

            lines.append(
                f"Overall Risk: {exec_report.overall_risk}"
            )

            if exec_report.priorities:
                lines.append("")
                lines.append("Priorities:")

                for item in exec_report.priorities:
                    lines.append(
                        f" • {format_list_item(item)}"
                    )

            if exec_report.next_actions:
                lines.append("")
                lines.append("Next Actions:")

                for item in exec_report.next_actions:
                    lines.append(
                        f" • {format_list_item(item)}"
                    )

            lines.append("")

        else:

            lines.append(
                f"EXECUTIVE SUMMARY UNAVAILABLE ({exec_result.message})"
            )

            lines.append("")

        if "threat" in reports:

            r = reports["threat"]

            lines.append("THREAT ANALYSIS")
            lines.append("-" * 70)
            lines.append(f"Assessment : {r.threat_assessment}")
            lines.append(f"Priority   : {r.priority}")
            lines.append("")

        if "recon" in reports:

            r = reports["recon"]

            lines.append("RECONNAISSANCE")
            lines.append("-" * 70)
            lines.append(f"Attack Surface : {r.attack_surface}")
            lines.append("")

        if "network_scan" in reports:

            r = reports["network_scan"]

            lines.append("NETWORK PORT SCAN")
            lines.append("-" * 70)
            lines.append(r.executive_summary)
            lines.append("")

        if "network" in reports:

            r = reports["network"]

            lines.append("NETWORK INTELLIGENCE")
            lines.append("-" * 70)
            lines.append(f"Reputation : {r.reputation}")
            lines.append(f"Risk       : {r.risk}")
            lines.append("")

        if "web" in reports:

            r = reports["web"]

            lines.append("WEB ASSESSMENT")
            lines.append("-" * 70)
            lines.append(f"Risk : {r.risk}")
            lines.append("")

        return "\n".join(lines)

    async def generate(
        self,
        target: str,
        user_id: int | str = "system",
    ) -> WorkflowResult:

        return await self.run(
            target=target,
            user_id=user_id,
        )
