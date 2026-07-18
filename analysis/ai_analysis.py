from analysis.providers.provider_factory import get_provider

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

    async def _run_prompt(self, prompt_template: str, context: str):
        """
        Merges the prompt template with its context into a single
        prompt string and sends it to the configured provider.
        """
        full_prompt = f"{prompt_template}\n\n{context}"

        return await self.provider.analyze(full_prompt)

    async def analyze_threat(
        self,
        *,
        target: str,
        threat_score: int,
        severity: str,
        ioc_type: str,
        signals: dict,
    ):
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
        )

    async def analyze_scan(
        self,
        *,
        tool: str,
        target: str,
        results: dict,
    ):
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
        )

    async def analyze_network(
        self,
        *,
        target: str,
        data: dict,
    ):
        context = f"""
Target:
{target}

Network Intelligence:

{data}
"""

        return await self._run_prompt(
            NETWORK_PROMPT,
            context,
        )

    async def analyze_web(
        self,
        *,
        target: str,
        findings: dict,
    ):
        context = f"""
Target:
{target}

Findings:

{findings}
"""

        return await self._run_prompt(
            WEB_PROMPT,
            context,
        )

    async def analyze_malware(
        self,
        *,
        malware: dict,
    ):
        return await self._run_prompt(
            MALWARE_PROMPT,
            str(malware),
        )

    async def executive_summary(
        self,
        *,
        report: dict,
    ):
        return await self._run_prompt(
            EXECUTIVE_PROMPT,
            str(report),
        )
