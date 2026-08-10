import os
import time

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class CerebrasProvider(BaseAIProvider):
    """
    Cerebras's API is OpenAI-compatible.

    Note:
    Cerebras rejects frequency_penalty, presence_penalty and logit_bias,
    so this provider intentionally sends only the model and messages.
    """

    provider_name = "cerebras"
    model_name = os.getenv(
        "CEREBRAS_MODEL",
        "llama3.1-8b",
    )

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("CEREBRAS_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "CEREBRAS_API_KEY environment variable is not set."
                )

            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://api.cerebras.ai/v1",
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
