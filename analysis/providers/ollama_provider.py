import os
import time

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class OllamaProvider(BaseAIProvider):
    """
    Ollama runs locally and exposes an OpenAI-compatible endpoint.

    No real API key is required by Ollama itself; the AsyncOpenAI
    client still requires a non-empty string, so a placeholder is
    used unless OLLAMA_API_KEY is explicitly set (e.g. for a
    password-protected remote Ollama instance).
    """

    provider_name = "ollama"

    model_name = os.getenv(
        "OLLAMA_MODEL",
        "llama3.1",
    )

    base_url = os.getenv(
        "OLLAMA_BASE_URL",
        "http://localhost:11434/v1",
    )

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv(
                "OLLAMA_API_KEY",
                "ollama",
            )

            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url=self.base_url,
            )

        return self._client

    async def analyze(self, prompt: str) -> AIResponse:
        start_time = time.perf_counter()

        try:
            client = self._get_client()

            response = await client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            )

            execution_time_ms = int(
                (time.perf_counter() - start_time) * 1000
            )

        except Exception as exc:
            execution_time_ms = int(
                (time.perf_counter() - start_time) * 1000
            )

            return AIResponse(
                success=False,
                provider=self.provider_name,
                report_type="",
                analysis=None,
                raw_response="",
                error=f"{type(exc).__name__}: {exc}",
                execution_time_ms=execution_time_ms,
            )

        text = response.choices[0].message.content

        return AIResponse(
            success=True,
            provider=self.provider_name,
            report_type="",
            analysis=text,
            raw_response=text,
            error=None,
            execution_time_ms=execution_time_ms,
        )
