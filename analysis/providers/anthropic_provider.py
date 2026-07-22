import os

from anthropic import AsyncAnthropic

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class AnthropicProvider(BaseAIProvider):

    provider_name = "anthropic"
    model_name = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY environment variable is not set."
                )
            self._client = AsyncAnthropic(api_key=api_key)

        return self._client

    async def analyze(self, prompt: str) -> AIResponse:
        try:
            client = self._get_client()

            response = await client.messages.create(
                model=self.model_name,
                max_tokens=4096,
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

        text_blocks = [
            block.text for block in response.content if block.type == "text"
        ]
        text = "".join(text_blocks)

        return AIResponse(
            success=True,
            provider=self.provider_name,
            report_type="",
            analysis=text,
            raw_response=text,
        )
