from workflows.base_workflow import BaseWorkflow, WorkflowResult

from workflows.analysis_workflow import AnalysisWorkflow
from workflows.ai_workflow import AIWorkflow

from analysis.formatting import format_list_item
from reports.pdf_generator import PDFGenerator


RISK_LEVELS = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

RISK_NAMES = {
    0: "UNDETERMINED",
    1: "INFO",
    2: "LOW",
    3: "MEDIUM",
    4: "HIGH",
    5: "CRITICAL",
}


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

        # Preserve failed/incomplete assessment evidence for the
        # executive risk decision. A partial assessment must never
        # be presented as a complete assessment.
        assessment_status = "complete" if not analysis_result.errors else "incomplete"

        exec_result = await self.ai.executive_summary(
            report={
                "incident_description": incident_description,
                "assessment_status": assessment_status,
                "assessment_errors": analysis_result.errors,
            }
        )

        document = self._format_document(
            target,
            reports,
            exec_result,
            assessment_errors=analysis_result.errors,
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

    @staticmethod
    def _risk_level(value: str | None) -> int:
        """Return the highest recognized severity contained in a risk value."""
        if not value:
            return 0

        normalized = str(value).strip().lower()

        if "critical" in normalized:
            return RISK_LEVELS["critical"]
        if "high" in normalized:
            return RISK_LEVELS["high"]
        if "medium" in normalized or "moderate" in normalized:
            return RISK_LEVELS["medium"]
        if "low" in normalized:
            return RISK_LEVELS["low"]
        if "info" in normalized:
            return RISK_LEVELS["info"]

        return 0

    @classmethod
    def _enforce_overall_risk(
        cls,
        ai_risk: str | None,
        reports: dict,
    ) -> str:
        """
        Derive the authoritative overall risk from verified component risks.

        The executive AI may explain or contextualize risk, but it must not
        raise or lower the authoritative risk derived from observed evidence.
        """
        component_levels = []

        for report_name in ("network", "web"):
            report = reports.get(report_name)
            if report is None:
                continue

            level = cls._risk_level(getattr(report, "risk", ""))
            if level > 0:
                component_levels.append(level)

        if component_levels:
            return RISK_NAMES[max(component_levels)]

        # No verified component risk is available. Preserve the AI assessment
        # as a fallback rather than inventing a deterministic risk.
        ai_level = cls._risk_level(ai_risk)
        return RISK_NAMES[ai_level]

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
                f"Web assessment: risk={r.risk}, "
                f"findings={r.executive_summary}"
            )

        return "\n".join(parts)

    def _format_document(
        self,
        target: str,
        reports: dict,
        exec_result: WorkflowResult,
        *,
        assessment_errors: list[str] | None = None,
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

            all_assessment_errors = list(assessment_errors or [])
            all_assessment_errors.extend(exec_result.errors)

            if all_assessment_errors:
                lines.append("Assessment Status: INCOMPLETE")
                lines.append(
                    "Overall Risk: UNDETERMINED — assessment evidence is incomplete"
                )
                lines.append("")
                lines.append("Assessment Errors:")
                for error in all_assessment_errors:
                    lines.append(f" • {error}")
            else:
                overall_risk = self._enforce_overall_risk(
                    exec_report.overall_risk,
                    reports,
                )
                lines.append(f"Overall Risk: {overall_risk}")

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
