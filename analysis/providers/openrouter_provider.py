import os
import time

from openai import AsyncOpenAI

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class OpenRouterProvider(BaseAIProvider):
    """
    OpenRouter's API is OpenAI-compatible and routes requests to
    many underlying model providers based on the model name.
    """

    provider_name = "openrouter"

    model_name = os.getenv(
        "OPENROUTER_MODEL",
        "meta-llama/llama-3.3-70b-instruct",
    )

    # Hard cost/latency ceilings — added to close two gaps found during
    # Phase 12 API integration review:
    #   - no cap meant a single call had genuinely open-ended cost
    #   - no timeout meant a hung request had no cutoff at all
    # Both are overridable via env vars so they can be tuned without
    # another code change, matching this codebase's existing pattern
    # (see OPENROUTER_MODEL above, same style).
    MAX_TOKENS = int(os.getenv("OPENROUTER_MAX_TOKENS", "1000"))
    REQUEST_TIMEOUT_SECONDS = float(os.getenv("OPENROUTER_TIMEOUT_SECONDS", "30.0"))

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("OPENROUTER_API_KEY")

            if not api_key:
                raise RuntimeError(
                    "OPENROUTER_API_KEY environment variable is not set."
                )

            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://openrouter.ai/api/v1",
                timeout=self.REQUEST_TIMEOUT_SECONDS,          # <-- NEW
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
                max_tokens=self.MAX_TOKENS,                     # <-- NEW
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
