import os

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class TogetherProvider(BaseAIProvider):
    """
    Together AI's API is OpenAI-compatible.
    """

    provider_name = "together"
    model_name = os.getenv(
        "TOGETHER_MODEL", "meta-llama/Llama-3.3-70B-Instruct-Turbo"
    )

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("TOGETHER_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "TOGETHER_API_KEY environment variable is not set."
                )
            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://api.together.xyz/v1",
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
