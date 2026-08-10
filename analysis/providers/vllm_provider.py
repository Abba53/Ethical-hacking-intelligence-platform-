import os
import time

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class VLLMProvider(BaseAIProvider):
    """
    vLLM serves an OpenAI-compatible endpoint from wherever you
    deployed it.

    Both VLLM_BASE_URL and VLLM_MODEL should be configured.
    """

    provider_name = "vllm"

    model_name = os.getenv(
        "VLLM_MODEL",
        "",
    )

    base_url = os.getenv(
        "VLLM_BASE_URL",
        "http://localhost:8000/v1",
    )

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            if not self.model_name:
                raise RuntimeError(
                    "VLLM_MODEL environment variable is not set. "
                    "Set it to the model your vLLM server was started with."
                )

            api_key = os.getenv(
                "VLLM_API_KEY",
                "not-needed",
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
