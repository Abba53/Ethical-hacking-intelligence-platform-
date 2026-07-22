import os

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class DeepSeekProvider(BaseAIProvider):
    """
    DeepSeek's API is OpenAI-compatible, so this reuses the openai
    SDK's AsyncOpenAI client pointed at DeepSeek's base_url instead
    of pulling in a separate SDK.
    """

    provider_name = "deepseek"
    model_name = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("DEEPSEEK_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "DEEPSEEK_API_KEY environment variable is not set."
                )
            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com",
            )

        return self._client

    async def analyze(self, prompt: str) -> AIResponse:
        try:
            client = self._get_client()

            response = await client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "user", "content": prompt},
                ],
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
