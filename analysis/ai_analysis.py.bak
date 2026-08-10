from analysis.providers.provider_factory import get_provider

from analysis.parsers.json_parser import JSONParser

from analysis.models.ai_response import AIResponse
from analysis.models.threat_report import ThreatReport
from analysis.models.recon_report import ReconReport
from analysis.models.network_report import NetworkReport
from analysis.models.web_report import WebReport
from analysis.models.executive_report import ExecutiveReport
from analysis.models.malware_report import MalwareReport

from analysis.schema.threat_schema import THREAT_SCHEMA
from analysis.schema.recon_schema import RECON_SCHEMA
from analysis.schema.network_schema import NETWORK_SCHEMA
from analysis.schema.web_schema import WEB_SCHEMA
from analysis.schema.executive_schema import EXECUTIVE_SCHEMA
from analysis.schema.malware_schema import MALWARE_SCHEMA

from analysis.prompts.threat_prompt import THREAT_PROMPT
from analysis.prompts.recon_prompt import RECON_PROMPT
from analysis.prompts.network_prompt import NETWORK_PROMPT
from analysis.prompts.web_prompt import WEB_PROMPT
from analysis.prompts.malware_prompt import MALWARE_PROMPT
from analysis.prompts.executive_prompt import EXECUTIVE_PROMPT


class AIAnalyst:
    """
    High-level AI analysis service.

    This class never talks directly to OpenAI, Gemini, DeepSeek,
    Anthropic, or a local LLM. It only communicates with the
    provider interface.
    """

    def __init__(self):
        self.provider = get_provider()

    async def _run_prompt(
        self,
        prompt_template: str,
        context: str,
        *,
        report_type: str,
        schema: dict,
        report_class: type,
    ) -> AIResponse:
        """
        Merges the prompt template with its context, sends it to the
        configured provider, and parses the provider's raw text into
        the matching structured *Report dataclass.
        """
        full_prompt = f"{prompt_template}\n\n{context}"

        response: AIResponse = await self.provider.analyze(full_prompt)
        response.report_type = report_type

        if not response.success:
            return response

        try:
            parsed = JSONParser.parse(
                response.analysis,
                required_keys=list(schema.keys()),
            )
        except ValueError as exc:
            response.success = False
            response.error = f"Failed to parse structured response: {exc}"
            return response

        response.analysis = report_class(
            **{key: parsed.get(key, default) for key, default in schema.items()}
        )

        return response

    async def analyze_threat(
        self,
        *,
        target: str,
        threat_score: int,
        severity: str,
        ioc_type: str,
        signals: dict,
    ) -> AIResponse:
        context = f"""
Target:
{target}

IOC Type:
{ioc_type}

Threat Score:
{threat_score}

Severity:
{severity}

Signals:
{signals}
"""

        return await self._run_prompt(
            THREAT_PROMPT,
            context,
            report_type="threat",
            schema=THREAT_SCHEMA,
            report_class=ThreatReport,
        )

    async def analyze_scan(
        self,
        *,
        tool: str,
        target: str,
        results: dict,
    ) -> AIResponse:
        context = f"""
Tool:
{tool}

Target:
{target}

Results:
{results}
"""

        return await self._run_prompt(
            RECON_PROMPT,
            context,
            report_type="recon",
            schema=RECON_SCHEMA,
            report_class=ReconReport,
        )

    async def analyze_network(
        self,
        *,
        target: str,
        data: dict,
    ) -> AIResponse:
        context = f"""
Target:
{target}

Network Intelligence:

{data}
"""

        return await self._run_prompt(
            NETWORK_PROMPT,
            context,
            report_type="network",
            schema=NETWORK_SCHEMA,
            report_class=NetworkReport,
        )

    async def analyze_web(
        self,
        *,
        target: str,
        findings: dict,
    ) -> AIResponse:
        context = f"""
Target:
{target}

Findings:

{findings}
"""

        return await self._run_prompt(
            WEB_PROMPT,
            context,
            report_type="web",
            schema=WEB_SCHEMA,
            report_class=WebReport,
        )

    async def analyze_malware(
        self,
        *,
        malware: dict,
    ) -> AIResponse:
        return await self._run_prompt(
            MALWARE_PROMPT,
            str(malware),
            report_type="malware",
            schema=MALWARE_SCHEMA,
            report_class=MalwareReport,
        )

    async def executive_summary(
        self,
        *,
        report: dict,
    ) -> AIResponse:
        return await self._run_prompt(
            EXECUTIVE_PROMPT,
            str(report),
            report_type="executive",
            schema=EXECUTIVE_SCHEMA,
            report_class=ExecutiveReport,
        )
