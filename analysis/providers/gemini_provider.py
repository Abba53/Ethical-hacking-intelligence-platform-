import os

from google import genai

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class GeminiProvider(BaseAIProvider):

    provider_name = "gemini"
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "GEMINI_API_KEY environment variable is not set."
                )
            self._client = genai.Client(api_key=api_key)

        return self._client

    async def analyze(self, prompt: str) -> AIResponse:
        try:
            client = self._get_client()

            response = await client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
        except Exception as exc:
            return AIResponse(
                success=False,
                provider=self.provider_name,
                report_type="",
                analysis=None,
                error=f"{type(exc).__name__}: {exc}",
            )

        return AIResponse(
            success=True,
            provider=self.provider_name,
            report_type="",
            analysis=response.text,
            raw_response=response.text,
        )
