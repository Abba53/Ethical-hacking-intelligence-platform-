import os
import time

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class NvidiaNimProvider(BaseAIProvider):
    """
    NVIDIA NIM's hosted API (integrate.api.nvidia.com) is
    OpenAI-compatible.
    """

    provider_name = "nvidia_nim"
    model_name = os.getenv(
        "NVIDIA_NIM_MODEL",
        "meta/llama-3.1-70b-instruct",
    )

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("NVIDIA_NIM_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "NVIDIA_NIM_API_KEY environment variable is not set."
                )

            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://integrate.api.nvidia.com/v1", timeout = 300.0
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
