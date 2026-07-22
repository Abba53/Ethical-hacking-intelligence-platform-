from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class LocalProvider(BaseAIProvider):
    """
    Stub pending a decision on which local LLM backend to target
    (Ollama, llama.cpp server, LM Studio, etc.).
    """

    provider_name = "local"

    async def analyze(self, prompt: str) -> AIResponse:
        return AIResponse(
            success=False,
            provider=self.provider_name,
            report_type="",
            analysis=None,
            error="Not implemented",
        )
