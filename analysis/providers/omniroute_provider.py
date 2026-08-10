import os
import time

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class OmniRouteProvider(BaseAIProvider):
    """
    OmniRoute is a self-hosted, open-source AI gateway that exposes
    a single OpenAI-compatible endpoint and routes requests to
    whichever provider/model it is configured with.

    Default local endpoint:
        http://localhost:20128/v1
    """

    provider_name = "omniroute"

    model_name = os.getenv(
        "OMNIROUTE_MODEL",
        "auto",
    )

    base_url = os.getenv(
        "OMNIROUTE_BASE_URL",
        "http://localhost:20128/v1",
    )

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv(
                "OMNIROUTE_API_KEY",
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
