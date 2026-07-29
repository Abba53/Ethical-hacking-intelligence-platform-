import os

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class VLLMProvider(BaseAIProvider):
    """
    vLLM serves an OpenAI-compatible endpoint from wherever you
    deployed it — there is no universal default host/port or model,
    so both VLLM_BASE_URL and VLLM_MODEL must be set for this
    provider to work.
    """

    provider_name = "vllm"
    model_name = os.getenv("VLLM_MODEL", "")
    base_url = os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1")

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            if not self.model_name:
                raise RuntimeError(
                    "VLLM_MODEL environment variable is not set — "
                    "set it to the model name your vLLM server was "
                    "started with."
                )
            api_key = os.getenv("VLLM_API_KEY", "not-needed")
            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url=self.base_url,
            )
        return self._client

    async def analyze(self, prompt: str) -> AIResponse:
        try:
            client = self._get_client()
            response = await client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:
            return AIResponse(
                success=False,
                provider=self.provider_name,
                report_type="",
                analysis=None,
                error=f"{type(exc).__name__}: {exc}",
            )

        text = response.choices[0].message.content
        return AIResponse(
            success=True,
            provider=self.provider_name,
            report_type="",
            analysis=text,
            raw_response=text,
        )
